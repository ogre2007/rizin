#include "il_avr.h"

#define AVR_REG_SIZE  8
#define AVR_SREG_SIZE 8
#define AVR_RAMP_SIZE 8
#define AVR_SP_SIZE   16

// SREG = I|T|H|S|V|N|Z|C
// bits   0|1|2|3|4|5|6|7
#define AVR_SREG_I 0
#define AVR_SREG_T 1
#define AVR_SREG_H 2
#define AVR_SREG_S 3
#define AVR_SREG_V 4
#define AVR_SREG_N 5
#define AVR_SREG_Z 6
#define AVR_SREG_C 7

#define AVR_SPL_ADDR  0x3d
#define AVR_SPH_ADDR  0x3e
#define AVR_SREG_ADDR 0x3f

#define avr_return_val_if_invalid_gpr(x, v) \
	if (x >= 32) { \
		RZ_LOG_ERROR("RzIL: AVR: invalid register R%u\n", x); \
		return v; \
	}

#define avr_il_cast_reg(name, dst, len, sh, src) \
	do { \
		RzILOp *var = rz_il_new_op(RZIL_OP_VAR); \
		var->op.var->v = (src); \
		RzILOp *cast = rz_il_new_op(RZIL_OP_CAST); \
		cast->op.cast->val = var; \
		cast->op.cast->length = (len); \
		cast->op.cast->shift = (sh); \
		RzILOp *set = rz_il_new_op(RZIL_OP_SET); \
		set->op.set->x = cast; \
		set->op.set->v = (dst); \
		(name) = rz_il_new_op(RZIL_OP_PERFORM); \
		(name)->op.perform->eff = set; \
	} while (0)

#define avr_il_assign_reg(name, dst, src) \
	do { \
		RzILOp *var = rz_il_new_op(RZIL_OP_VAR); \
		var->op.var->v = (src); \
		RzILOp *set = rz_il_new_op(RZIL_OP_SET); \
		set->op.set->x = var; \
		set->op.set->v = (dst); \
		(name) = rz_il_new_op(RZIL_OP_PERFORM); \
		(name)->op.perform->eff = set; \
	} while (0)

#define avr_il_assign_imm(name, reg, imm) \
	do { \
		RzILOp *n = rz_il_new_op(RZIL_OP_INT); \
		n->op.int_->value = (imm); \
		n->op.int_->length = AVR_REG_SIZE; \
		RzILOp *set = rz_il_new_op(RZIL_OP_SET); \
		set->op.set->x = n; \
		set->op.set->v = (reg); \
		(name) = rz_il_new_op(RZIL_OP_PERFORM); \
		(name)->op.perform->eff = set; \
	} while (0)

#define avr_il_store_reg(name, address, reg) \
	do { \
		RzILOp *var = rz_il_new_op(RZIL_OP_VAR); \
		var->op.var->v = (reg); \
		RzILOp *addr = rz_il_new_op(RZIL_OP_INT); \
		addr->op.int_->value = (address); \
		addr->op.int_->length = 32; \
		(name) = rz_il_new_op(RZIL_OP_STORE); \
		(name)->op.store->key = addr; \
		(name)->op.store->value = var; \
	} while (0)

#define avr_il_set_bit(name, reg, b, pos) \
	do { \
		ut16 bits = 1 << (pos); \
		if (!b) { \
			bits = ~bits; \
		} \
		RzILOp *var = rz_il_new_op(RZIL_OP_VAR); \
		var->op.var->v = reg; \
		RzILOp *n = rz_il_new_op(RZIL_OP_INT); \
		n->op.int_->value = bits; \
		n->op.int_->length = AVR_REG_SIZE; \
		RzILOp *lop = rz_il_new_op(b ? RZIL_OP_LOGOR : RZIL_OP_LOGAND); \
		lop->op.logor->x = var; \
		lop->op.logor->y = n; \
		RzILOp *set = rz_il_new_op(RZIL_OP_SET); \
		set->op.set->x = lop; \
		set->op.set->v = (reg); \
		(name) = rz_il_new_op(RZIL_OP_PERFORM); \
		(name)->op.perform->eff = set; \
	} while (0)

typedef RzPVector *(*avr_rzil_op)(AVROp *aop, RzAnalysis *analysis);

const char *avr_registers[32] = {
	"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9",
	"R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R18",
	"R19", "R20", "R21", "R22", "R23", "R24", "R25", "R26", "R27",
	"R28", "R29", "R30", "R31"
};

static RzPVector *avr_il_nop(AVROp *aop, RzAnalysis *analysis) {
	return NULL;
}

static RzPVector *avr_il_clr(AVROp *aop, RzAnalysis *analysis) {
	// Rd = Rd ^ Rd -> S=0, V=0, N=0, Z=1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *clr = NULL;
	RzILOp *S = NULL;
	RzILOp *V = NULL;
	RzILOp *N = NULL;
	RzILOp *Z = NULL;

	avr_il_assign_imm(clr, avr_registers[Rd], 0);
	avr_il_set_bit(S, "SREG", 0, AVR_SREG_S);
	avr_il_set_bit(V, "SREG", 0, AVR_SREG_V);
	avr_il_set_bit(N, "SREG", 0, AVR_SREG_N);
	avr_il_set_bit(Z, "SREG", 1, AVR_SREG_Z);

	return rz_il_make_oplist(5, clr, S, V, N, Z);
}

static RzPVector *avr_il_cpi(AVROp *aop, RzAnalysis *analysis) {
	// SREG = compare(Rd, K)
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *clr = NULL;
	RzILOp *H = NULL;
	RzILOp *S = NULL;
	RzILOp *V = NULL;
	RzILOp *N = NULL;
	RzILOp *Z = NULL;
	RzILOp *C = NULL;

	//avr_il_assign_imm(clr, avr_registers[Rd], 0);
	//avr_il_set_bit(S, "SREG", 0, AVR_SREG_S);
	//avr_il_set_bit(V, "SREG", 0, AVR_SREG_V);
	//avr_il_set_bit(N, "SREG", 0, AVR_SREG_N);
	//avr_il_set_bit(Z, "SREG", 1, AVR_SREG_Z);

	return rz_il_make_nop_list(); //rz_il_make_oplist(5, clr, S, V, N, Z);
}

static RzPVector *avr_il_ldi(AVROp *aop, RzAnalysis *analysis) {
	// Rd = K
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *ldi = NULL;
	avr_il_assign_imm(ldi, avr_registers[Rd], K);
	return rz_il_make_oplist(1, ldi);
}

static RzPVector *avr_il_out(AVROp *aop, RzAnalysis *analysis) {
	// I/O(A) = Rr -> None
	ut16 A = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rr, NULL);

	RzILOp *out = NULL;
	switch (A) {
	case AVR_SPL_ADDR:
		avr_il_cast_reg(out, "SP", AVR_SP_SIZE, 0, avr_registers[Rr]);
		break;
	case AVR_SPH_ADDR:
		avr_il_cast_reg(out, "SP", AVR_SP_SIZE, 8, avr_registers[Rr]);
		break;
	case AVR_SREG_ADDR:
		avr_il_assign_reg(out, "SREG", avr_registers[Rr]);
		break;
	default:
		avr_il_store_reg(out, A, avr_registers[Rr]);
		break;
	}
	return rz_il_make_oplist(1, out);
}

static RzPVector *avr_il_rjmp(AVROp *aop, RzAnalysis *analysis) {
	// PC = PC + k + 1
	ut16 k = aop->param[0];
	// op size is added by the VM so we can remove it from the original value
	rz_il_bv_set_from_ut64(analysis->rzil->vm->pc, k - aop->size);
	return rz_il_make_nop_list();
}

static RzPVector *avr_il_ser(AVROp *aop, RzAnalysis *analysis) {
	// Rd = $FF
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *ser = NULL;
	avr_il_assign_imm(ser, avr_registers[Rd], 0xFF);
	return rz_il_make_oplist(1, ser);
}

static avr_rzil_op avr_ops[AVR_OP_SIZE] = {
	avr_il_nop, /* AVR_OP_INVALID */
	avr_il_nop, /* AVR_OP_ADC */
	avr_il_nop, /* AVR_OP_ADD */
	avr_il_nop, /* AVR_OP_ADIW */
	avr_il_nop, /* AVR_OP_AND */
	avr_il_nop, /* AVR_OP_ANDI */
	avr_il_nop, /* AVR_OP_ASR */
	avr_il_nop, /* AVR_OP_BLD */
	avr_il_nop, /* AVR_OP_BRCC */
	avr_il_nop, /* AVR_OP_BRCS */
	avr_il_nop, /* AVR_OP_BREAK */
	avr_il_nop, /* AVR_OP_BREQ */
	avr_il_nop, /* AVR_OP_BRGE */
	avr_il_nop, /* AVR_OP_BRHC */
	avr_il_nop, /* AVR_OP_BRHS */
	avr_il_nop, /* AVR_OP_BRID */
	avr_il_nop, /* AVR_OP_BRIE */
	avr_il_nop, /* AVR_OP_BRLO */
	avr_il_nop, /* AVR_OP_BRLT */
	avr_il_nop, /* AVR_OP_BRMI */
	avr_il_nop, /* AVR_OP_BRNE */
	avr_il_nop, /* AVR_OP_BRPL */
	avr_il_nop, /* AVR_OP_BRSH */
	avr_il_nop, /* AVR_OP_BRTC */
	avr_il_nop, /* AVR_OP_BRTS */
	avr_il_nop, /* AVR_OP_BRVC */
	avr_il_nop, /* AVR_OP_BRVS */
	avr_il_nop, /* AVR_OP_BST */
	avr_il_nop, /* AVR_OP_CALL */
	avr_il_nop, /* AVR_OP_CBI */
	avr_il_nop, /* AVR_OP_CLC */
	avr_il_nop, /* AVR_OP_CLH */
	avr_il_nop, /* AVR_OP_CLI */
	avr_il_nop, /* AVR_OP_CLN */
	avr_il_clr,
	avr_il_nop, /* AVR_OP_CLS */
	avr_il_nop, /* AVR_OP_CLT */
	avr_il_nop, /* AVR_OP_CLV */
	avr_il_nop, /* AVR_OP_CLZ */
	avr_il_nop, /* AVR_OP_COM */
	avr_il_nop, /* AVR_OP_CP */
	avr_il_nop, /* AVR_OP_CPC */
	avr_il_cpi,
	avr_il_nop, /* AVR_OP_CPSE */
	avr_il_nop, /* AVR_OP_DEC */
	avr_il_nop, /* AVR_OP_DES */
	avr_il_nop, /* AVR_OP_EICALL */
	avr_il_nop, /* AVR_OP_EIJMP */
	avr_il_nop, /* AVR_OP_ELPM */
	avr_il_nop, /* AVR_OP_EOR */
	avr_il_nop, /* AVR_OP_FMUL */
	avr_il_nop, /* AVR_OP_FMULS */
	avr_il_nop, /* AVR_OP_FMULSU */
	avr_il_nop, /* AVR_OP_ICALL */
	avr_il_nop, /* AVR_OP_IJMP */
	avr_il_nop, /* AVR_OP_IN */
	avr_il_nop, /* AVR_OP_INC */
	avr_il_nop, /* AVR_OP_JMP */
	avr_il_nop, /* AVR_OP_LAC */
	avr_il_nop, /* AVR_OP_LAS */
	avr_il_nop, /* AVR_OP_LAT */
	avr_il_nop, /* AVR_OP_LD */
	avr_il_nop, /* AVR_OP_LDD */
	avr_il_ldi,
	avr_il_nop, /* AVR_OP_LDS */
	avr_il_nop, /* AVR_OP_LPM */
	avr_il_nop, /* AVR_OP_LSL */
	avr_il_nop, /* AVR_OP_LSR */
	avr_il_nop, /* AVR_OP_MOV */
	avr_il_nop, /* AVR_OP_MOVW */
	avr_il_nop, /* AVR_OP_MUL */
	avr_il_nop, /* AVR_OP_MULS */
	avr_il_nop, /* AVR_OP_MULSU */
	avr_il_nop, /* AVR_OP_NEG */
	avr_il_nop, /* AVR_OP_NOP */
	avr_il_nop, /* AVR_OP_OR */
	avr_il_nop, /* AVR_OP_ORI */
	avr_il_out,
	avr_il_nop, /* AVR_OP_POP */
	avr_il_nop, /* AVR_OP_PUSH */
	avr_il_nop, /* AVR_OP_RCALL */
	avr_il_nop, /* AVR_OP_RET */
	avr_il_nop, /* AVR_OP_RETI */
	avr_il_rjmp,
	avr_il_nop, /* AVR_OP_ROL */
	avr_il_nop, /* AVR_OP_ROR */
	avr_il_nop, /* AVR_OP_SBC */
	avr_il_nop, /* AVR_OP_SBCI */
	avr_il_nop, /* AVR_OP_SBI */
	avr_il_nop, /* AVR_OP_SBIC */
	avr_il_nop, /* AVR_OP_SBIS */
	avr_il_nop, /* AVR_OP_SBIW */
	avr_il_nop, /* AVR_OP_SBRC */
	avr_il_nop, /* AVR_OP_SBRS */
	avr_il_nop, /* AVR_OP_SEC */
	avr_il_nop, /* AVR_OP_SEH */
	avr_il_nop, /* AVR_OP_SEI */
	avr_il_nop, /* AVR_OP_SEN */
	avr_il_ser,
	avr_il_nop, /* AVR_OP_SES */
	avr_il_nop, /* AVR_OP_SET */
	avr_il_nop, /* AVR_OP_SEV */
	avr_il_nop, /* AVR_OP_SEZ */
	avr_il_nop, /* AVR_OP_SLEEP */
	avr_il_nop, /* AVR_OP_SPM */
	avr_il_nop, /* AVR_OP_ST */
	avr_il_nop, /* AVR_OP_STD */
	avr_il_nop, /* AVR_OP_STS */
	avr_il_nop, /* AVR_OP_SUB */
	avr_il_nop, /* AVR_OP_SUBI */
	avr_il_nop, /* AVR_OP_SWAP */
	avr_il_nop, /* AVR_OP_TST */
	avr_il_nop, /* AVR_OP_WDR */
	avr_il_nop, /* AVR_OP_XCH */
};

static const char *avr_ops_name[AVR_OP_SIZE] = {
	"AVR_OP_INVALID", "AVR_OP_ADC", "AVR_OP_ADD", "AVR_OP_ADIW", "AVR_OP_AND", "AVR_OP_ANDI", "AVR_OP_ASR",
	"AVR_OP_BLD", "AVR_OP_BRCC", "AVR_OP_BRCS", "AVR_OP_BREAK", "AVR_OP_BREQ", "AVR_OP_BRGE", "AVR_OP_BRHC",
	"AVR_OP_BRHS", "AVR_OP_BRID", "AVR_OP_BRIE", "AVR_OP_BRLO", "AVR_OP_BRLT", "AVR_OP_BRMI", "AVR_OP_BRNE",
	"AVR_OP_BRPL", "AVR_OP_BRSH", "AVR_OP_BRTC", "AVR_OP_BRTS", "AVR_OP_BRVC", "AVR_OP_BRVS", "AVR_OP_BST",
	"AVR_OP_CALL", "AVR_OP_CBI", "AVR_OP_CLC", "AVR_OP_CLH", "AVR_OP_CLI", "AVR_OP_CLN", "AVR_OP_CLR",
	"AVR_OP_CLS", "AVR_OP_CLT", "AVR_OP_CLV", "AVR_OP_CLZ", "AVR_OP_COM", "AVR_OP_CP", "AVR_OP_CPC",
	"AVR_OP_CPI", "AVR_OP_CPSE", "AVR_OP_DEC", "AVR_OP_DES", "AVR_OP_EICALL", "AVR_OP_EIJMP", "AVR_OP_ELPM",
	"AVR_OP_EOR", "AVR_OP_FMUL", "AVR_OP_FMULS", "AVR_OP_FMULSU", "AVR_OP_ICALL", "AVR_OP_IJMP", "AVR_OP_IN",
	"AVR_OP_INC", "AVR_OP_JMP", "AVR_OP_LAC", "AVR_OP_LAS", "AVR_OP_LAT", "AVR_OP_LD", "AVR_OP_LDD",
	"AVR_OP_LDI", "AVR_OP_LDS", "AVR_OP_LPM", "AVR_OP_LSL", "AVR_OP_LSR", "AVR_OP_MOV", "AVR_OP_MOVW",
	"AVR_OP_MUL", "AVR_OP_MULS", "AVR_OP_MULSU", "AVR_OP_NEG", "AVR_OP_NOP", "AVR_OP_OR", "AVR_OP_ORI",
	"AVR_OP_OUT", "AVR_OP_POP", "AVR_OP_PUSH", "AVR_OP_RCALL", "AVR_OP_RET", "AVR_OP_RETI", "AVR_OP_RJMP",
	"AVR_OP_ROL", "AVR_OP_ROR", "AVR_OP_SBC", "AVR_OP_SBCI", "AVR_OP_SBI", "AVR_OP_SBIC", "AVR_OP_SBIS",
	"AVR_OP_SBIW", "AVR_OP_SBRC", "AVR_OP_SBRS", "AVR_OP_SEC", "AVR_OP_SEH", "AVR_OP_SEI", "AVR_OP_SEN",
	"AVR_OP_SER", "AVR_OP_SES", "AVR_OP_SET", "AVR_OP_SEV", "AVR_OP_SEZ", "AVR_OP_SLEEP", "AVR_OP_SPM",
	"AVR_OP_ST", "AVR_OP_STD", "AVR_OP_STS", "AVR_OP_SUB", "AVR_OP_SUBI", "AVR_OP_SWAP", "AVR_OP_TST",
	"AVR_OP_WDR", "AVR_OP_XCH"
};

RZ_IPI bool avr_rzil_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, AVROp *aop) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);
	op->rzil_op = RZ_NEW0(RzAnalysisRzilOp);
	if (!op->rzil_op) {
		RZ_LOG_ERROR("RzIL: AVR: cannot allocate RzAnalysisRzilOp\n");
		return false;
	}

	if (aop->mnemonic >= AVR_OP_SIZE) {
		RZ_LOG_ERROR("RzIL: AVR: out of bounds op\n");
		return false;
	}

	avr_rzil_op create_op = avr_ops[aop->mnemonic];
	op->rzil_op->ops = create_op(aop, analysis);

	//if (create_op != avr_il_nop) {
	//	eprintf("0x%08llx -> op %s %d\n", pc, avr_ops_name[aop->mnemonic], create_op == avr_il_nop);
	//}
	return true;
}

RZ_IPI bool avr_rzil_fini(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);

	RzAnalysisRzil *rzil = analysis->rzil;

	if (rzil->vm) {
		rz_il_vm_fini(rzil->vm);
		rzil->vm = NULL;
	}

	rzil->inited = false;
	return true;
}

RZ_IPI bool avr_rzil_init(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);
	RzAnalysisRzil *rzil = analysis->rzil;

	if (rzil->inited) {
		RZ_LOG_ERROR("RzIL: AVR: VM is already configured\n");
		return true;
	}

	RzArchProfile *profile = analysis->arch_target ? analysis->arch_target->profile : NULL;

	ut32 addr_space = 22; // 22 bits address space
	ut64 pc_address = 0;

	if (profile && profile->rom_size < 0x10000) {
		addr_space = 16;
	}

	if (!rz_il_vm_init(rzil->vm, pc_address, addr_space, addr_space)) {
		RZ_LOG_ERROR("RzIL: AVR: failed to initialize VM\n");
		return false;
	}

	char reg[8] = { 0 };

	for (ut32 i = 0; i < 32; ++i) {
		rz_strf(reg, "R%d", i);
		rz_il_vm_add_reg(rzil->vm, reg, AVR_REG_SIZE);
	}

	rz_il_vm_add_reg(rzil->vm, "SP", AVR_SP_SIZE);
	// SREG = I|T|H|S|V|N|Z|C
	// bits   0|1|2|3|4|5|6|7
	rz_il_vm_add_reg(rzil->vm, "SREG", AVR_SREG_SIZE);

	if (addr_space > 16) {
		rz_il_vm_add_reg(rzil->vm, "RAMPX", AVR_RAMP_SIZE);
		rz_il_vm_add_reg(rzil->vm, "RAMPY", AVR_RAMP_SIZE);
		rz_il_vm_add_reg(rzil->vm, "RAMPZ", AVR_RAMP_SIZE);
		rz_il_vm_add_reg(rzil->vm, "RAMPD", AVR_RAMP_SIZE);
		rz_il_vm_add_reg(rzil->vm, "EIND", AVR_RAMP_SIZE);
	}

	rz_il_vm_add_mem(rzil->vm, 8);

	return true;
}

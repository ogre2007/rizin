#include "il_avr.h"

//RZ_IPI bool avr_opcode_rzil

RZ_IPI bool avr_rzil_fini(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);

	RzAnalysisRzil *rzil = analysis->rzil;
	if (rzil->user) {
		AVRILContext *ctx = rzil->user;
		//ht_up_free(ctx->label_names);
		//free(ctx->stack);
		free(ctx);
		rzil->user = NULL;
	}

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
	ut64 stackptr_size = 16;

	if (profile) {
		if (profile->rom_size < 0x10000) {
			addr_space = 16;
			stackptr_size = 8;
		}
		pc_address = profile->pc;
	}

	if (!rz_il_vm_init(rzil->vm, pc_address, addr_space, addr_space)) {
		RZ_LOG_ERROR("RzIL: AVR: failed to initialize VM\n");
		return false;
	}

	char reg[8] = { 0 };
	for (ut32 i = 0; i < 32; ++i) {
		rz_strf(reg, "R%d", i);
		rz_il_vm_add_reg(rzil->vm, reg, 8);
	}
	rz_il_vm_add_reg(rzil->vm, "SP", stackptr_size);
	rz_il_vm_add_reg(rzil->vm, "SREG", 8);
	if (addr_space > 16) {
		rz_il_vm_add_reg(rzil->vm, "RAMPX", 8);
		rz_il_vm_add_reg(rzil->vm, "RAMPY", 8);
		rz_il_vm_add_reg(rzil->vm, "RAMPZ", 8);
		rz_il_vm_add_reg(rzil->vm, "RAMPD", 8);
		rz_il_vm_add_reg(rzil->vm, "EIND", 8);
	}

	rz_il_vm_add_mem(rzil->vm, addr_space);

	AVRILContext *context = RZ_NEW0(AVRILContext);
	rzil->user = context;
	return true;
}

#include "il_avr.h"


RZ_IPI bool avr_fini_rzil(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);

	RzAnalysisRzil *rzil = analysis->rzil;
	if (rzil->user) {
		AvrILContext *ctx = rzil->user;
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

RZ_IPI bool avr_init_rzil(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);
	RzAnalysisRzil *rzil = analysis->rzil;

	if (rzil->inited) {
		RZ_LOG_ERROR("RzIL: AVR: VM is already configured\n");
		return true;
	}

	ut32 addr_space = 32;
	ut64 start_addr = 0x12345600; //rzil->pc_addr;

	if (!rz_il_vm_init(rzil->vm, start_addr, addr_space, addr_space)) {
		RZ_LOG_ERROR("RzIL: AVR: failed to initialize VM\n");
		return false;
	}

	//BfStack astack = (BfStack)calloc(1, sizeof(struct bf_stack_t));
	//HtUP *names = ht_up_new0();
	AvrILContext *context = RZ_NEW0(AvrILContext);
	//context->stack = astack;
	//context->op_count = 0;
	//context->label_names = names;
	rzil->user = context;

	return true;//bf_specific_init(rzil);
}

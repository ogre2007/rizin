#ifndef RZIL_ANALYSIS_AVR_H
#define RZIL_ANALYSIS_AVR_H

#include <rz_analysis.h>

typedef struct il_avr_context_t {
	ut32 foobar;
} AvrILContext;

RZ_IPI bool avr_fini_rzil(RZ_NONNULL RzAnalysis *analysis);
RZ_IPI bool avr_init_rzil(RZ_NONNULL RzAnalysis *analysis);

#endif /* RZIL_ANALYSIS_AVR_H */
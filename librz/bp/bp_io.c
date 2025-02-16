// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bp.h>
#include <config.h>

RZ_API void rz_bp_restore_one(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	if (set) {
		// eprintf ("Setting bp at 0x%08"PFMT64x"\n", b->addr);
		if (b->hw || !b->bbytes) {
			eprintf("hw breakpoints not yet supported\n");
		} else {
			bp->iob.write_at(bp->iob.io, b->addr, b->bbytes, b->size);
		}
	} else {
		// eprintf ("Clearing bp at 0x%08"PFMT64x"\n", b->addr);
		if (b->hw || !b->obytes) {
			eprintf("hw breakpoints not yet supported\n");
		} else {
			bp->iob.write_at(bp->iob.io, b->addr, b->obytes, b->size);
		}
	}
}

/**
 * reflect all rz_bp stuff in the process using dbg->bp_write or ->breakpoint
 */
RZ_API int rz_bp_restore(RzBreakpoint *bp, bool set) {
	return rz_bp_restore_except(bp, set, UT64_MAX);
}

/**
 * reflect all rz_bp stuff in the process using dbg->bp_write or ->breakpoint
 *
 * except the specified breakpoint...
 */
RZ_API bool rz_bp_restore_except(RzBreakpoint *bp, bool set, ut64 addr) {
	bool rc = true;
	RzListIter *iter;
	RzBreakpointItem *b;

	if (set && bp->bpinmaps && bp->ctx.maps_sync) {
		bp->ctx.maps_sync(bp->ctx.user);
	}

	rz_list_foreach (bp->bps, iter, b) {
		if (addr && b->addr == addr) {
			continue;
		}
		// Avoid restoring disabled breakpoints
		if (set && !b->enabled) {
			continue;
		}
		// Check if the breakpoint is in a valid map
		if (set && bp->bpinmaps && !rz_bp_is_valid(bp, b)) {
			continue;
		}
		if (bp->breakpoint && bp->breakpoint(bp, b, set)) {
			continue;
		}

		/* write (o|b)bytes from every breakpoint in rz_bp if not handled by plugin */
		rz_bp_restore_one(bp, b, set);
		rc = true;
	}
	return rc;
}

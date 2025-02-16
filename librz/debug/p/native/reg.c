// SPDX-FileCopyrightText: 2014 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

// included from p/debug_native.c
// split for better reading/cleaning up

static char *rz_debug_native_reg_profile(RzDebug *dbg) {
#if __WINDOWS__
/*_______
 |   |   |
 |___|___|
 |   |   |
 |___|___|
*/
#if defined(__arm64__)
#include "reg/windows-arm64.h"
#elif defined(__arm__)
#include "reg/windows-arm.h"
#elif defined(__x86_64__)
#include "reg/windows-x64.h"
#elif defined(__i386__)
#include "reg/windows-x86.h"
#endif
#elif (__OpenBSD__ || __NetBSD__)
/*                           __.--..__
       \-/-/-/    _ __  _.--'  _.--'
  _  \'       \   \\  ''      `------.__
  \\/      __)_)   \\      ____..---'
  //\       o  o    \\----'
     / <_/      3    \\
      \_,_,__,_/      \\
*/
#if __i386__
#include "reg/netbsd-x86.h"
#elif __x86_64__
#include "reg/netbsd-x64.h"
#else
#error "Unsupported BSD architecture"
#endif

#elif __KFBSD__ || __FreeBSD__
/*
    /(       ).
    \ \__   /|
    /  _ '-/ |
   (/\/ |    \
   / /  | \   )
   O O _/     |
  (__)  __   /
    \___/   /
      `----'
*/
#if __i386__ || __i386
#include "reg/kfbsd-x86.h"
#elif __x86_64__ || __amd64__
#include "reg/kfbsd-x64.h"
#elif __aarch64__
#include "reg/kfbsd-arm64.h"
#else
#error "Unsupported BSD architecture"
#endif

#else
#warning Unsupported Kernel
	return NULL;
#endif
}

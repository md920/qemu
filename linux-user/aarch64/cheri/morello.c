/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 John Baldwin
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* 
 * This file is a port of kernel functions from LINUX-MORELLO
*/

#include "qemu.h"

#include "cheri-archspecific.h"

#include "machine/cheri.h"
#include "cheri/cheri.h"
#include "cheri/cheric.h"

/* DDC_ELx reset value (low/high 64 bits), as defined in the Morello spec */
#define DDC_RESET_VAL_LOW_64	0x0
#define DDC_RESET_VAL_HIGH_64	0xffffc00000010005ULL
#define VA_BITS 52
#define TASK_SIZE_MAX		(1UL << VA_BITS)

#define CAP_OTYPE_FIELD_BITS	15

#define __build_cap(root, perms, length, ...)				\
({									\
	cap_register_t c = (root);						\
	size_t len = (length);						\
									\
	c = *cheri_andperm(&c, (perms));				\
	if (len)							\
		c = *cheri_setbounds(&c, len);				\
									\
	c;								\
})
#define build_cap(root, perms, ...) __build_cap((root), (perms), ##__VA_ARGS__, 0)

static void cap_lo_hi_tag(cap_register_t cap, uint64_t *lo_val, uint64_t *hi_val, uint8_t *tag)
{
    *lo_val = (uint64_t)cheri_uintptr((cap_register_t *)&cap).cursor;
    target_ulong *len;
    *len = cheri_getlen((cap_register_t *)&cap);
    *hi_val = cheri_uintptr(cheri_load(&cap, len)).cursor;
    *tag = cheri_gettag((cap_register_t *)&cap);
}

static void check_root_cap(cap_register_t cap)
{
    uint64_t lo_val, hi_val;
    uint8_t tag;

    cap_lo_hi_tag(cap, &lo_val, &hi_val, &tag);

	/*if (!(tag == 1 &&
	      lo_val == DDC_RESET_VAL_LOW_64 &&
	      hi_val == DDC_RESET_VAL_HIGH_64))
		warn_report("DDC does not have its reset value, this may be a firmware bug\n");*/
}

void morello_init_capabilities(CPUARMState *env)
{
    cap_register_t root_cap;
    uint32_t perms;

    root_cap = *cheri_get_ddc(env);
    check_root_cap(root_cap);
	
    /* Initialise standard CHERI root capabilities. */

	perms = CAP_PERMS_ROOTCAP |
		CAP_PERMS_READ | CAP_PERMS_WRITE | CAP_PERMS_EXEC |
		CAP_PERM_BRANCH_SEALED_PAIR |
		CAP_PERM_SEAL | CAP_PERM_UNSEAL |
		CAP_PERM_COMPARTMENT_ID;
	/* Same upper limit as for access_ok() and __uaccess_mask_ptr() */
	userspace_allpermscap = build_cap(root_cap, perms, TASK_SIZE_MAX);

	perms = CAP_PERMS_ROOTCAP |
		CAP_PERMS_READ | CAP_PERMS_WRITE | CAP_PERMS_EXEC |
		CAP_PERM_BRANCH_SEALED_PAIR;
	userspace_cap = build_cap(userspace_allpermscap, perms);

	perms = CAP_PERM_GLOBAL | CAP_PERM_SEAL | CAP_PERM_UNSEAL;
	/*
	 * Includes all object types, not a final decision - some of them may
	 * be later reserved to the kernel.
	 */
	userspace_sealcap = build_cap(userspace_allpermscap,
					     perms, 1u << CAP_OTYPE_FIELD_BITS);
}
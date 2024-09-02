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

static cap_register_t morello_sentry_unsealcap;

/* DDC_ELx reset value (low/high 64 bits), as defined in the Morello spec */
#define DDC_RESET_VAL_LOW_64	0x0
#define DDC_RESET_VAL_HIGH_64	0xffffc00000010005ULL
#define VA_BITS 52
#define TASK_SIZE_MAX		(1UL << VA_BITS)

#define CAP_OTYPE_FIELD_BITS	15

#define PSR_C64_BIT	0x04000000

static void cap_lo_hi_tag(cap_register_t cap, uint64_t *lo_val, uint64_t *hi_val, uint8_t *tag)
{
    *lo_val = (uint64_t)cheri_uintptr((cap_register_t *)&cap).cursor;
    target_ulong *len;
    *len = cheri_getlen((cap_register_t *)&cap);
    *hi_val = cheri_uintptr(cheri_load(&cap, len)).cursor;
    *tag = cheri_gettag((cap_register_t *)&cap);
}

static bool cap_has_executive(cap_register_t cap)
{
	return cheri_getperm(&cap) & CAP_PERMS_EXEC;
}

static void set_creg_user_ptr(struct target_pt_regs *regs, int r, cap_register_t *val)
{
	regs->regs[r] = *val;
}

static void update_regs_c64(struct target_pt_regs *regs, unsigned long pc)
{
	if (pc & 0x1) {
		regs->pstate |= PSR_C64_BIT;
		cheri_update_pcc(&regs->pc, (pc & ~0x1), false);
	}
}

int morello_thread_start(struct target_pt_regs *regs, unsigned long pc, struct image_info *bprm)
{
	int ret = 0;

	update_regs_c64(regs, pc);

	/*
	 * Note: there is no need to explicitly set the address of PCC/CSP as
	 * PC/SP are already set to the appropriate values in regs, and X/C
	 * register merging automatically happens during ret_to_user.
	 */
	regs->pc = bprm->pcuabi.pcc;
	regs->sp = bprm->pcuabi.csp;

	ret = bprm->argc; /* Set x0 */
	set_creg_user_ptr(regs, 1, &bprm->pcuabi.argv);
	set_creg_user_ptr(regs, 2, &bprm->pcuabi.envp);
	set_creg_user_ptr(regs, 3, &bprm->pcuabi.auxv);

	return ret;
}

void morello_thread_set_csp(struct target_pt_regs *regs, cap_register_t sp)
{
	cap_register_t *thread_sp = &regs->sp;
	*thread_sp = sp;
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
	
	perms = CAP_PERM_GLOBAL | CAP_PERM_COMPARTMENT_ID;
	/* Maximum userspace bounds for the time being. */
	userspace_cid_cap = build_cap(userspace_allpermscap, perms);

	/* Initialize a capability able to unseal sentry capabilities. */
	perms = CAP_PERM_GLOBAL | CAP_PERM_UNSEAL;
	morello_sentry_unsealcap = *cheri_setaddress(&root_cap, CAP_OTYPE_SENTRY);
	morello_sentry_unsealcap = build_cap(morello_sentry_unsealcap, perms, 1);
}
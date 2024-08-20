/*-
 * Copyright (c) 2011-2017 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
 * This file is a port of lib/cheri.c from LINUX-MORELLO
 */

#include "qemu.h"

#include "cheri/cheric.h"
#include "cheri/cheri.h"

cap_register_t userspace_cap;
cap_register_t userspace_sealcap;
cap_register_t userspace_cid_cap;
cap_register_t userspace_allpermscap;
/*
 * Build a new userspace capability derived from userspace_cap.
 * 
 */
static cap_register_t *
build_user_cap(cap_register_t *ret, unsigned long addr, size_t len, uint32_t perms)
{

    *ret = userspace_cap;
    uint32_t root_perms = cheri_getperm(ret);
    
    ret = cheri_andperm(ret, perms);
	ret = cheri_setaddress(ret, addr);
    ret = cheri_setbounds(ret, len);

    return ret;
}

/*
 * Create a userspace capability allowing bounds to be enlarged
 *
 */
cap_register_t *
cheri_build_user_cap_inexact_bounds(cap_register_t *cap, unsigned long addr, size_t len,
				    uint32_t perms)
{
	return build_user_cap(cap, addr, len, perms);
}

/*
 * Checks whether a capability gives access to a given range of addresses and has the
 * requested permissions.
 */
bool cheri_check_cap(const cap_register_t * cap, size_t len,
		     uint32_t perms)
{
	unsigned long addr = cheri_getaddress(cap);
	unsigned long base = cheri_getbase(cap);

	if (!cheri_gettag(cap) || cap_is_sealed_entry(cap))
		return false;

	if (addr < base || addr > base + cheri_getlen(cap) - len)
		return false;

	if (perms & ~cheri_getperm(cap))
		return false;

	return true;
}

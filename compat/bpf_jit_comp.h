/* bpf_jit_comp.h : BPF filter alloc/free routines
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */
#ifndef __BPF_JIT_COMP_H
#define __BPF_JIT_COMP_H

#include <linux/uaccess.h>
#include <asm/cacheflush.h>

struct bpf_binary_header {
	unsigned int	pages;
	/* Note : for security reasons, bpf code will follow a randomly
	 * sized amount of int3 instructions
	 */
	u8		image[];
};

static inline void bpf_flush_icache(void *start, void *end)
{
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	smp_wmb();
	flush_icache_range((unsigned long)start, (unsigned long)end);
	set_fs(old_fs);
}

struct bpf_binary_header *bpf_alloc_binary(unsigned int proglen,
					   u8 **image_ptr);

#endif

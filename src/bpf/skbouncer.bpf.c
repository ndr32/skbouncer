// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "skbouncer.h"

#define TC_ACT_OK 0

char LICENSE[] SEC("license") = "GPL";

/* Name must stay <= 15 chars: BPF_OBJ_NAME_LEN is 16 incl. NUL, and a
 * longer name shows truncated in bpftool. */
SEC("tc")
int skb_egress(struct __sk_buff *skb)
{
	return TC_ACT_OK;
}

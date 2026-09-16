// SPDX-License-Identifier: GPL-2.0
/*
 * skbouncer - M1
 *
 * Minimal tc egress classifier. It loads, passes every packet, and does
 * nothing else. Its only job is to prove the build/load path works end to
 * end before M2 starts looking at TLS record headers on this same hook.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0

char LICENSE[] SEC("license") = "GPL";

/* Name must stay <= 15 chars: BPF_OBJ_NAME_LEN is 16 including the NUL,
 * and a longer name is silently truncated in `bpftool prog list`. */
SEC("tc")
int skb_egress(struct __sk_buff *skb)
{
	return TC_ACT_OK;
}

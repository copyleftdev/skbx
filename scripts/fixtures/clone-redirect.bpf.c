// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include "bpf_helpers.h"

#ifndef TARGET_IFINDEX
#error "TARGET_IFINDEX must identify the veth egress device"
#endif

SEC("classifier")
int clone_redirect(struct __sk_buff *skb)
{
    bpf_clone_redirect(skb, TARGET_IFINDEX, 0);
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include "bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} packet_counts SEC(".maps");

SEC("classifier")
int helper_classifier(struct __sk_buff *skb)
{
    __u32 key = skb->protocol;
    __u64 initial = 1;
    __u64 *count = bpf_map_lookup_elem(&packet_counts, &key);

    if (count)
        __sync_fetch_and_add(count, 1);
    else
        bpf_map_update_elem(&packet_counts, &key, &initial, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

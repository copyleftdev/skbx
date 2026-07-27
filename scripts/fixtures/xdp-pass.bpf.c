// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include "bpf_helpers.h"

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    (void)ctx;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

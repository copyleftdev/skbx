/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SKBX_BPF_CORE_READ_H
#define __SKBX_BPF_CORE_READ_H

#define bpf_core_read(dst, size, src) \
    bpf_probe_read_kernel((dst), (size), (const void *)__builtin_preserve_access_index(src))

#endif

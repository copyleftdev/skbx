/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SKBX_BPF_CORE_READ_H
#define __SKBX_BPF_CORE_READ_H

#define bpf_core_read(dst, size, src) \
    bpf_probe_read_kernel((dst), (size), (const void *)__builtin_preserve_access_index(src))

enum bpf_type_id_kind {
    BPF_TYPE_ID_LOCAL = 0,
    BPF_TYPE_ID_TARGET = 1,
};

#define bpf_core_type_id_kernel(type) \
    __builtin_btf_type_id(*(typeof(type) *)0, BPF_TYPE_ID_TARGET)

#endif

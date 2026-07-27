/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SKBX_BPF_HELPERS_H
#define __SKBX_BPF_HELPERS_H

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) typeof(value) *name
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u32 (*bpf_get_smp_processor_id)(void) = (void *)8;
static long (*bpf_clone_redirect)(void *skb, __u32 ifindex, __u64 flags) = (void *)13;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_get_stackid)(void *ctx, void *map, __u64 flags) = (void *)27;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data,
                                  __u64 size, __u64 flags) = (void *)130;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static long (*bpf_snprintf_btf)(char *str, __u32 str_size,
                                struct btf_ptr *ptr, __u32 ptr_size,
                                __u64 flags) = (void *)149;

#endif

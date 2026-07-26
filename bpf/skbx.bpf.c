// SPDX-License-Identifier: GPL-2.0-only
//
// Generic SKB kprobes for the first five kernel ABI arguments. Userspace uses
// kernel BTF to select the matching program for each function.

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#if defined(__TARGET_ARCH_x86)
#define PT_REGS_PARM1(ctx) ((ctx)->di)
#define PT_REGS_PARM2(ctx) ((ctx)->si)
#define PT_REGS_PARM3(ctx) ((ctx)->dx)
#define PT_REGS_PARM4(ctx) ((ctx)->cx)
#define PT_REGS_PARM5(ctx) ((ctx)->r8)
#define PT_REGS_RC(ctx) ((ctx)->ax)
#define PT_REGS_IP(ctx) ((ctx)->ip)
#define PT_REGS_FP(ctx) ((ctx)->bp)
#elif defined(__TARGET_ARCH_arm64)
#define PT_REGS_PARM1(ctx) ((ctx)->regs[0])
#define PT_REGS_PARM2(ctx) ((ctx)->regs[1])
#define PT_REGS_PARM3(ctx) ((ctx)->regs[2])
#define PT_REGS_PARM4(ctx) ((ctx)->regs[3])
#define PT_REGS_PARM5(ctx) ((ctx)->regs[4])
#define PT_REGS_RC(ctx) ((ctx)->regs[0])
#define PT_REGS_IP(ctx) ((ctx)->pc)
#define PT_REGS_FP(ctx) ((ctx)->regs[29])
#else
#error "unsupported target architecture"
#endif

#define READ_LEN_FAILED      (1u << 0)
#define READ_PROTOCOL_FAILED (1u << 1)
#define READ_MARK_FAILED     (1u << 2)
#define READ_DEVICE_FAILED   (1u << 3)
#define READ_IFINDEX_FAILED  (1u << 4)
#define READ_MTU_FAILED      (1u << 5)
#define READ_NETNS_FAILED    (1u << 6)
#define READ_TUPLE_FAILED    (1u << 7)
#define READ_CB_FAILED       (1u << 8)
#define READ_CALLER_FAILED   (1u << 9)
#define READ_TUNNEL_TUPLE_FAILED (1u << 10)
#define ASSOCIATION_DIRECT 0
#define ASSOCIATION_STACK  1

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86dd
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_IPV6_HOPOPTS 0
#define IPPROTO_IPV6_ROUTING 43
#define IPPROTO_IPV6_FRAGMENT 44
#define IPPROTO_AH 51
#define IPPROTO_NONE 59
#define IPPROTO_IPV6_DSTOPTS 60
#define IPPROTO_ICMPV6 58
#define MAX_IPV6_EXTENSION_HEADERS 8
#define MAX_ASSOCIATION_STACK_DEPTH 50
#define MAX_CBPF_INSNS 4096
#define CBPF_MEMWORDS 16

#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_SIZE(code)  ((code) & 0x18)
#define BPF_MODE(code)  ((code) & 0xe0)
#define BPF_OP(code)    ((code) & 0xf0)
#define BPF_SRC(code)   ((code) & 0x08)

#define BPF_LD   0x00
#define BPF_LDX  0x01
#define BPF_ST   0x02
#define BPF_STX  0x03
#define BPF_ALU  0x04
#define BPF_JMP  0x05
#define BPF_RET  0x06
#define BPF_MISC 0x07

#define BPF_W   0x00
#define BPF_H   0x08
#define BPF_B   0x10
#define BPF_IMM 0x00
#define BPF_ABS 0x20
#define BPF_IND 0x40
#define BPF_MEM 0x60
#define BPF_LEN 0x80
#define BPF_MSH 0xa0

#define BPF_ADD 0x00
#define BPF_SUB 0x10
#define BPF_MUL 0x20
#define BPF_DIV 0x30
#define BPF_OR  0x40
#define BPF_AND 0x50
#define BPF_LSH 0x60
#define BPF_RSH 0x70
#define BPF_NEG 0x80
#define BPF_MOD 0x90
#define BPF_XOR 0xa0

#define BPF_JA   0x00
#define BPF_JEQ  0x10
#define BPF_JGT  0x20
#define BPF_JGE  0x30
#define BPF_JSET 0x40
#define BPF_K    0x00
#define BPF_X    0x08
#define BPF_A    0x10
#define BPF_TAX  0x00
#define BPF_TXA  0x80

struct cbpf_insn {
    __u16 code;
    __u8 jt;
    __u8 jf;
    __u32 k;
};

struct cbpf_program {
    __u32 len;
    struct cbpf_insn instructions[MAX_CBPF_INSNS];
};

struct skbx_packet_tuple {
    __u8 saddr[16];
    __u8 daddr[16];
    __u16 sport;
    __u16 dport;
    __u16 l3_protocol;
    __u8 l4_protocol;
    __u8 tcp_flags;
    __u8 icmp_type;
    __u8 icmp_code;
    __u16 _pad;
};

struct skbx_trace_event {
    __u64 timestamp_ns;
    __u64 skb_addr;
    __u64 function_ip;
    __u64 caller_ip;
    __u32 pid;
    __u32 cpu;
    __u32 len;
    __u32 mark;
    __u32 ifindex;
    __u32 netns;
    __u32 mtu;
    __u16 protocol;
    __u16 read_status;
    struct skbx_packet_tuple tuple;
    struct skbx_packet_tuple tunnel_tuple;
    __u32 control_buffer[5];
    char command[16];
    __u8 association;
    __u8 _pad0[3];
    __s64 stack_id;
    __u64 parameter_second;
    __u64 parameter_third;
};

struct kernel_stats {
    __u64 reserve_failures;
    __u64 read_failures;
    __u64 filtered_events;
};

struct skbx_config {
    __u32 filter_mark;
    __u32 filter_mark_mask;
    __u32 filter_ifindex;
    __u32 filter_netns;
    __u32 output_stack;
    __u32 track_skb;
    __u32 output_tunnel;
    __u32 track_stack;
    struct cbpf_program pcap_l2;
    struct cbpf_program pcap_l3;
    struct cbpf_program tunnel_pcap_l2;
    struct cbpf_program tunnel_pcap_l3;
};

const volatile struct skbx_config CONFIG = {};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kernel_stats);
} telemetry SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 50 * sizeof(__u64));
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} tracked_skbs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} pending_clones SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} stack_anchor_skb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} skb_stack_anchor SEC(".maps");

static __always_inline struct kernel_stats *stats(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&telemetry, &key);
}

static __always_inline int read_netns(struct sk_buff *skb, __u32 *netns_id)
{
    struct net_device *device = 0;
    struct sock *socket = 0;
    struct net *net = 0;

    *netns_id = 0;
    if (bpf_core_read(&device, sizeof(device), &skb->dev))
        return -1;
    if (device) {
        if (bpf_core_read(&net, sizeof(net), &device->nd_net.net))
            return -1;
        if (net) {
            if (bpf_core_read(netns_id, sizeof(*netns_id), &net->ns.inum))
                return -1;
            if (*netns_id)
                return 0;
        }
    }

    /* Match pwru's fallback for output-path SKBs whose dev is not set yet. */
    if (bpf_core_read(&socket, sizeof(socket), &skb->sk))
        return -1;
    if (!socket)
        return 0;
    if (bpf_core_read(&net, sizeof(net), &socket->__sk_common.skc_net.net))
        return -1;
    if (net &&
        bpf_core_read(netns_id, sizeof(*netns_id), &net->ns.inum))
        return -1;
    return 0;
}

static __always_inline int packet_read(const unsigned char *head, __u32 tail,
                                       __u32 offset, void *destination,
                                       __u32 size)
{
    if (offset > tail || size > tail - offset)
        return -1;
    return bpf_probe_read_kernel(destination, size, head + offset);
}

static __always_inline int read_tuple_at(const unsigned char *head, __u32 tail,
                                         __u32 network_header,
                                         struct skbx_packet_tuple *tuple)
{
    __u8 version_ihl = 0;
    __u32 l4_offset;

    if (packet_read(head, tail, network_header, &version_ihl,
                    sizeof(version_ihl)))
        return -1;

    if ((version_ihl >> 4) == 4) {
        __u8 ihl = (version_ihl & 0x0f) * 4;
        __u8 fragment[2] = {};

        if (ihl < 20)
            return -1;
        tuple->l3_protocol = ETH_P_IP;
        if (packet_read(head, tail, network_header + 9,
                        &tuple->l4_protocol, sizeof(tuple->l4_protocol)) ||
            packet_read(head, tail, network_header + 12, tuple->saddr, 4) ||
            packet_read(head, tail, network_header + 16, tuple->daddr, 4) ||
            packet_read(head, tail, network_header + 6, fragment,
                        sizeof(fragment)))
            return -1;
        l4_offset = network_header + ihl;
        /* Non-initial IPv4 fragments do not contain a transport header. */
        if ((((__u16)fragment[0] << 8) | fragment[1]) & 0x1fff)
            return 0;
    } else if ((version_ihl >> 4) == 6) {
        __u8 next_header = 0;

        tuple->l3_protocol = ETH_P_IPV6;
        if (packet_read(head, tail, network_header + 6, &next_header,
                        sizeof(next_header)) ||
            packet_read(head, tail, network_header + 8, tuple->saddr, 16) ||
            packet_read(head, tail, network_header + 24, tuple->daddr, 16))
            return -1;
        l4_offset = network_header + 40;

#pragma clang loop unroll(full)
        for (int index = 0; index < MAX_IPV6_EXTENSION_HEADERS; index++) {
            __u8 extension[4] = {};
            __u32 extension_len;

            if (next_header != IPPROTO_IPV6_HOPOPTS &&
                next_header != IPPROTO_IPV6_ROUTING &&
                next_header != IPPROTO_IPV6_DSTOPTS &&
                next_header != IPPROTO_IPV6_FRAGMENT &&
                next_header != IPPROTO_AH)
                break;
            if (packet_read(head, tail, l4_offset, extension,
                            sizeof(extension)))
                return -1;

            if (next_header == IPPROTO_IPV6_FRAGMENT) {
                extension_len = 8;
                next_header = extension[0];
                /* Do not interpret payload from non-initial fragments. */
                if ((((__u16)extension[2] << 8) | extension[3]) & 0xfff8) {
                    tuple->l4_protocol = next_header;
                    return 0;
                }
            } else if (next_header == IPPROTO_AH) {
                extension_len = ((__u32)extension[1] + 2) * 4;
                next_header = extension[0];
            } else {
                extension_len = ((__u32)extension[1] + 1) * 8;
                next_header = extension[0];
            }
            if (l4_offset > tail || extension_len > tail - l4_offset)
                return -1;
            l4_offset += extension_len;
        }
        /* Reject rather than mislabel chains beyond the declared bound. */
        if (next_header == IPPROTO_IPV6_HOPOPTS ||
            next_header == IPPROTO_IPV6_ROUTING ||
            next_header == IPPROTO_IPV6_DSTOPTS ||
            next_header == IPPROTO_IPV6_FRAGMENT ||
            next_header == IPPROTO_AH)
            return -1;
        tuple->l4_protocol = next_header;
        if (next_header == IPPROTO_NONE)
            return 0;
    } else {
        return 0;
    }

    if (tuple->l4_protocol == IPPROTO_TCP ||
        tuple->l4_protocol == IPPROTO_UDP) {
        if (packet_read(head, tail, l4_offset, &tuple->sport,
                        sizeof(tuple->sport)) ||
            packet_read(head, tail, l4_offset + 2, &tuple->dport,
                        sizeof(tuple->dport)))
            return -1;
        if (tuple->l4_protocol == IPPROTO_TCP &&
            packet_read(head, tail, l4_offset + 13, &tuple->tcp_flags,
                        sizeof(tuple->tcp_flags)))
            return -1;
        return 0;
    }

    if (tuple->l4_protocol == IPPROTO_ICMP ||
        tuple->l4_protocol == IPPROTO_ICMPV6) {
        if (packet_read(head, tail, l4_offset, &tuple->icmp_type,
                        sizeof(tuple->icmp_type)) ||
            packet_read(head, tail, l4_offset + 1, &tuple->icmp_code,
                        sizeof(tuple->icmp_code)))
            return -1;
    }
    return 0;
}

static __always_inline int read_tuples(struct sk_buff *skb,
                                       struct skbx_trace_event *event)
{
    unsigned char *head = 0;
    __u32 tail = 0;
    __u16 network_header = 0;
    __u16 inner_network_header = 0;

    if (bpf_core_read(&head, sizeof(head), &skb->head) || !head ||
        bpf_core_read(&tail, sizeof(tail), &skb->tail) ||
        bpf_core_read(&network_header, sizeof(network_header),
                      &skb->network_header))
        return -1;
    if (read_tuple_at(head, tail, network_header, &event->tuple))
        return -1;
    if (!CONFIG.output_tunnel)
        return 0;
    if (bpf_core_read(&inner_network_header, sizeof(inner_network_header),
                      &skb->inner_network_header))
        return -2;
    if (inner_network_header &&
        read_tuple_at(head, tail, inner_network_header,
                      &event->tunnel_tuple))
        return -2;
    return 0;
}

static __always_inline int cbpf_load(const unsigned char *data, __u32 len,
                                     __u32 offset, __u16 size, __u32 *value)
{
    __u8 bytes[4] = {};
    __u32 width;

    if (size == BPF_B)
        width = 1;
    else if (size == BPF_H)
        width = 2;
    else if (size == BPF_W)
        width = 4;
    else
        return 0;
    if (offset > len || width > len - offset)
        return 0;
    if (bpf_probe_read_kernel(bytes, width, data + offset))
        return 0;

    if (width == 1)
        *value = bytes[0];
    else if (width == 2)
        *value = ((__u32)bytes[0] << 8) | bytes[1];
    else
        *value = ((__u32)bytes[0] << 24) |
                 ((__u32)bytes[1] << 16) |
                 ((__u32)bytes[2] << 8) |
                 bytes[3];
    return 1;
}

static __always_inline int run_cbpf(const volatile struct cbpf_program *program,
                                    const unsigned char *data, __u32 len)
{
    __u32 a = 0;
    __u32 x = 0;
    __u32 mem[CBPF_MEMWORDS] = {};
    __u32 pc = 0;

#pragma clang loop unroll(disable)
    for (int steps = 0; steps < MAX_CBPF_INSNS; steps++) {
        struct cbpf_insn insn;
        __u32 value = 0;
        __u32 next;
        __u16 class;

        if (pc >= program->len || pc >= MAX_CBPF_INSNS)
            return 0;
        insn = program->instructions[pc];
        class = BPF_CLASS(insn.code);

        if (class == BPF_LD || class == BPF_LDX) {
            __u16 mode = BPF_MODE(insn.code);
            if (mode == BPF_IMM) {
                value = insn.k;
            } else if (mode == BPF_LEN) {
                value = len;
            } else if (mode == BPF_MEM) {
                if (insn.k >= CBPF_MEMWORDS)
                    return 0;
                value = mem[insn.k];
            } else if (mode == BPF_ABS || mode == BPF_IND ||
                       mode == BPF_MSH) {
                __u32 offset = insn.k;
                if (mode == BPF_IND) {
                    if (offset > 0xffffffffU - x)
                        return 0;
                    offset += x;
                }
                if (!cbpf_load(data, len, offset,
                               mode == BPF_MSH ? BPF_B :
                               BPF_SIZE(insn.code), &value))
                    return 0;
                if (mode == BPF_MSH)
                    value = (value & 0x0f) << 2;
            } else {
                return 0;
            }
            if (class == BPF_LD)
                a = value;
            else
                x = value;
            pc++;
            continue;
        }

        if (class == BPF_ST || class == BPF_STX) {
            if (insn.k >= CBPF_MEMWORDS)
                return 0;
            mem[insn.k] = class == BPF_ST ? a : x;
            pc++;
            continue;
        }

        if (class == BPF_ALU) {
            __u32 rhs = BPF_SRC(insn.code) == BPF_X ? x : insn.k;
            switch (BPF_OP(insn.code)) {
            case BPF_ADD: a += rhs; break;
            case BPF_SUB: a -= rhs; break;
            case BPF_MUL: a *= rhs; break;
            case BPF_DIV:
                if (!rhs) return 0;
                a /= rhs;
                break;
            case BPF_OR:  a |= rhs; break;
            case BPF_AND: a &= rhs; break;
            case BPF_LSH: a <<= rhs & 31; break;
            case BPF_RSH: a >>= rhs & 31; break;
            case BPF_NEG: a = -a; break;
            case BPF_MOD:
                if (!rhs) return 0;
                a %= rhs;
                break;
            case BPF_XOR: a ^= rhs; break;
            default: return 0;
            }
            pc++;
            continue;
        }

        if (class == BPF_JMP) {
            __u16 op = BPF_OP(insn.code);
            if (op == BPF_JA) {
                next = pc + 1 + insn.k;
            } else {
                __u32 rhs = BPF_SRC(insn.code) == BPF_X ? x : insn.k;
                int condition;
                if (op == BPF_JEQ)
                    condition = a == rhs;
                else if (op == BPF_JGT)
                    condition = a > rhs;
                else if (op == BPF_JGE)
                    condition = a >= rhs;
                else if (op == BPF_JSET)
                    condition = (a & rhs) != 0;
                else
                    return 0;
                next = pc + 1 + (condition ? insn.jt : insn.jf);
            }
            if (next <= pc || next >= program->len ||
                next >= MAX_CBPF_INSNS)
                return 0;
            pc = next;
            continue;
        }

        if (class == BPF_RET)
            return ((insn.code & 0x18) == BPF_A ? a : insn.k) != 0;

        if (class == BPF_MISC) {
            if ((insn.code & 0xf8) == BPF_TAX)
                x = a;
            else if ((insn.code & 0xf8) == BPF_TXA)
                a = x;
            else
                return 0;
            pc++;
            continue;
        }
        return 0;
    }
    return 0;
}

static __always_inline int pcap_filter_match(struct sk_buff *skb)
{
    unsigned char *head = 0;
    __u32 tail = 0;
    __u16 offset = 0;
    __u16 mac_len = 0;
    const volatile struct cbpf_program *program;

    if (!CONFIG.pcap_l2.len && !CONFIG.pcap_l3.len)
        return 1;
    if (!skb ||
        bpf_core_read(&head, sizeof(head), &skb->head) || !head ||
        bpf_core_read(&tail, sizeof(tail), &skb->tail) ||
        bpf_core_read(&mac_len, sizeof(mac_len), &skb->mac_len))
        return 0;

    if (mac_len) {
        if (bpf_core_read(&offset, sizeof(offset), &skb->mac_header))
            return 0;
        program = &CONFIG.pcap_l2;
    } else {
        if (bpf_core_read(&offset, sizeof(offset), &skb->network_header))
            return 0;
        program = &CONFIG.pcap_l3;
    }
    if (!program->len || offset > tail)
        return 0;
    return run_cbpf(program, head + offset, tail - offset);
}

static __always_inline int tunnel_pcap_filter_match(struct sk_buff *skb)
{
    unsigned char *head = 0;
    __u32 tail = 0;
    __u16 inner_mac_header = 0;
    __u16 inner_network_header = 0;

    if (!CONFIG.tunnel_pcap_l2.len && !CONFIG.tunnel_pcap_l3.len)
        return 1;
    if (!skb ||
        bpf_core_read(&head, sizeof(head), &skb->head) || !head ||
        bpf_core_read(&tail, sizeof(tail), &skb->tail) ||
        bpf_core_read(&inner_network_header, sizeof(inner_network_header),
                      &skb->inner_network_header))
        return 0;
    /* Match pwru: tunnel predicates do not reject non-encapsulated SKBs. */
    if (!inner_network_header)
        return 1;

    if (CONFIG.tunnel_pcap_l2.len) {
        if (bpf_core_read(&inner_mac_header, sizeof(inner_mac_header),
                          &skb->inner_mac_header) ||
            inner_mac_header > tail ||
            !run_cbpf(&CONFIG.tunnel_pcap_l2, head + inner_mac_header,
                      tail - inner_mac_header))
            return 0;
    }
    if (CONFIG.tunnel_pcap_l3.len &&
        (inner_network_header > tail ||
         !run_cbpf(&CONFIG.tunnel_pcap_l3, head + inner_network_header,
                   tail - inner_network_header)))
        return 0;
    return 1;
}

static __always_inline int configured_filter_match(struct sk_buff *skb)
{
    __u32 mark = 0;
    __u32 ifindex = 0;
    __u32 netns = 0;
    struct net_device *device = 0;

    if (!CONFIG.filter_mark_mask && !CONFIG.filter_ifindex &&
        !CONFIG.filter_netns && !CONFIG.pcap_l2.len &&
        !CONFIG.pcap_l3.len && !CONFIG.tunnel_pcap_l2.len &&
        !CONFIG.tunnel_pcap_l3.len)
        return 1;
    if (!skb)
        goto filtered;
    if (!pcap_filter_match(skb))
        goto filtered;
    if (!tunnel_pcap_filter_match(skb))
        goto filtered;

    if (CONFIG.filter_mark_mask) {
        if (bpf_core_read(&mark, sizeof(mark), &skb->mark))
            return -1;
        if ((mark & CONFIG.filter_mark_mask) != CONFIG.filter_mark)
            goto filtered;
    }

    if (CONFIG.filter_ifindex) {
        if (bpf_core_read(&device, sizeof(device), &skb->dev) || !device)
            goto filtered;
    }
    if (CONFIG.filter_ifindex) {
        if (bpf_core_read(&ifindex, sizeof(ifindex), &device->ifindex))
            return -1;
        if (ifindex != CONFIG.filter_ifindex)
            goto filtered;
    }
    if (CONFIG.filter_netns) {
        if (read_netns(skb, &netns))
            return -1;
        if (netns != CONFIG.filter_netns)
            goto filtered;
    }
    return 1;

filtered:
    return 0;
}

static __always_inline int should_trace(struct sk_buff *skb,
                                        struct kernel_stats *counters)
{
    int matched = configured_filter_match(skb);
    __u64 key = (__u64)skb;
    __u8 one = 1;

    if (matched < 0) {
        if (counters)
            counters->read_failures++;
        matched = 0;
    }

    if (CONFIG.track_skb && skb) {
        if (matched) {
            bpf_map_update_elem(&tracked_skbs, &key, &one, 0);
        } else if (bpf_map_lookup_elem(&tracked_skbs, &key)) {
            return 1;
        }
    }
    if (!matched && counters)
        counters->filtered_events++;
    return matched;
}

static __always_inline __u64 get_stack_anchor(struct pt_regs *ctx)
{
    __u64 frame = PT_REGS_FP(ctx);

#pragma clang loop unroll(full)
    for (int depth = 0; depth < MAX_ASSOCIATION_STACK_DEPTH; depth++) {
        __u64 caller = 0;

        if (!frame ||
            bpf_probe_read_kernel(&caller, sizeof(caller), (void *)frame) ||
            !caller || caller <= frame)
            break;
        frame = caller;
    }
    return frame;
}

static __always_inline void associate_stack(struct pt_regs *ctx,
                                            struct sk_buff *skb)
{
    __u64 skb_addr = (__u64)skb;
    __u64 anchor = get_stack_anchor(ctx);
    __u64 *old_anchor;

    if (!anchor || !skb_addr)
        return;
    old_anchor = bpf_map_lookup_elem(&skb_stack_anchor, &skb_addr);
    if (old_anchor && *old_anchor != anchor) {
        __u64 stale = *old_anchor;
        bpf_map_delete_elem(&stack_anchor_skb, &stale);
    }
    bpf_map_update_elem(&stack_anchor_skb, &anchor, &skb_addr, 0);
    bpf_map_update_elem(&skb_stack_anchor, &skb_addr, &anchor, 0);
}

static __always_inline int trace_skb_associated(struct pt_regs *ctx,
                                                struct sk_buff *skb,
                                                __u8 association)
{
    struct kernel_stats *counters = stats();
    if (association == ASSOCIATION_DIRECT &&
        !should_trace(skb, counters))
        return 0;
    if (association == ASSOCIATION_DIRECT && CONFIG.track_stack)
        associate_stack(ctx, skb);
    struct skbx_trace_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

    if (!event) {
        if (counters)
            counters->reserve_failures++;
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->stack_id = -1;
    event->association = association;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->skb_addr = (__u64)skb;
    event->function_ip = (__u64)PT_REGS_IP(ctx);
    event->parameter_second = (__u64)PT_REGS_PARM2(ctx);
    event->parameter_third = (__u64)PT_REGS_PARM3(ctx);
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(event->command, sizeof(event->command));
    if (CONFIG.output_stack)
        event->stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

#if defined(__TARGET_ARCH_x86)
    if (bpf_probe_read_kernel(&event->caller_ip, sizeof(event->caller_ip),
                              (void *)ctx->sp))
        event->read_status |= READ_CALLER_FAILED;
#elif defined(__TARGET_ARCH_arm64)
    event->caller_ip = ctx->regs[30];
#endif

    if (!skb) {
        event->read_status |= READ_LEN_FAILED | READ_PROTOCOL_FAILED |
                              READ_MARK_FAILED | READ_DEVICE_FAILED;
    } else {
        struct net_device *device = 0;
        if (bpf_core_read(&event->len, sizeof(event->len), &skb->len))
            event->read_status |= READ_LEN_FAILED;
        if (bpf_core_read(&event->protocol, sizeof(event->protocol), &skb->protocol))
            event->read_status |= READ_PROTOCOL_FAILED;
        if (bpf_core_read(&event->mark, sizeof(event->mark), &skb->mark))
            event->read_status |= READ_MARK_FAILED;
        if (bpf_core_read(&device, sizeof(device), &skb->dev)) {
            event->read_status |= READ_DEVICE_FAILED;
        } else if (device &&
                   bpf_core_read(&event->ifindex, sizeof(event->ifindex), &device->ifindex)) {
            event->read_status |= READ_IFINDEX_FAILED;
        }
        if (device) {
            if (bpf_core_read(&event->mtu, sizeof(event->mtu), &device->mtu))
                event->read_status |= READ_MTU_FAILED;
        }
        if (read_netns(skb, &event->netns))
            event->read_status |= READ_NETNS_FAILED;
        if (bpf_core_read(event->control_buffer,
                          sizeof(event->control_buffer), &skb->cb))
            event->read_status |= READ_CB_FAILED;
        int tuple_status = read_tuples(skb, event);
        if (tuple_status == -1)
            event->read_status |= READ_TUPLE_FAILED;
        else if (tuple_status == -2)
            event->read_status |= READ_TUNNEL_TUPLE_FAILED;
    }

    if (event->read_status && counters)
        counters->read_failures++;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int trace_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    return trace_skb_associated(ctx, skb, ASSOCIATION_DIRECT);
}

#define DEFINE_SKB_PROBE(position)                                      \
    SEC("kprobe")                                                       \
    int skbx_skb_arg##position(struct pt_regs *ctx)                     \
    {                                                                   \
        return trace_skb(                                               \
            ctx, (struct sk_buff *)PT_REGS_PARM##position(ctx));        \
    }

DEFINE_SKB_PROBE(1)
DEFINE_SKB_PROBE(2)
DEFINE_SKB_PROBE(3)
DEFINE_SKB_PROBE(4)
DEFINE_SKB_PROBE(5)

SEC("kprobe")
int skbx_stack_associated(struct pt_regs *ctx)
{
    __u64 anchor;
    __u64 *skb_addr;

    if (!CONFIG.track_stack)
        return 0;
    anchor = get_stack_anchor(ctx);
    if (!anchor)
        return 0;
    skb_addr = bpf_map_lookup_elem(&stack_anchor_skb, &anchor);
    if (!skb_addr || !*skb_addr)
        return 0;
    return trace_skb_associated(ctx, (struct sk_buff *)*skb_addr,
                               ASSOCIATION_STACK);
}

SEC("kprobe")
int skbx_skb_lifetime_end(struct pt_regs *ctx)
{
    __u64 skb_addr = PT_REGS_PARM1(ctx);
    __u64 *anchor;

    if ((!CONFIG.track_stack && !CONFIG.track_skb) || !skb_addr)
        return 0;
    if (CONFIG.track_skb)
        bpf_map_delete_elem(&tracked_skbs, &skb_addr);
    if (!CONFIG.track_stack)
        return 0;
    anchor = bpf_map_lookup_elem(&skb_stack_anchor, &skb_addr);
    if (anchor) {
        __u64 key = *anchor;
        bpf_map_delete_elem(&stack_anchor_skb, &key);
    }
    bpf_map_delete_elem(&skb_stack_anchor, &skb_addr);
    return 0;
}

SEC("kprobe")
int skbx_clone_entry(struct pt_regs *ctx)
{
    __u64 original = PT_REGS_PARM1(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u8 one = 1;

    if (CONFIG.track_skb &&
        bpf_map_lookup_elem(&tracked_skbs, &original))
        bpf_map_update_elem(&pending_clones, &pid_tgid, &one, 0);
    return 0;
}

SEC("kretprobe")
int skbx_clone_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 cloned = PT_REGS_RC(ctx);
    __u8 one = 1;

    if (!CONFIG.track_skb ||
        !bpf_map_lookup_elem(&pending_clones, &pid_tgid))
        return 0;
    if (cloned)
        bpf_map_update_elem(&tracked_skbs, &cloned, &one, 0);
    bpf_map_delete_elem(&pending_clones, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

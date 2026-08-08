# Validation guide

`make check` is the rootless repository gate:

```console
make check
```

It runs formatting, all workspace tests, and Clippy with warnings denied.
`make build` produces the optimized release binary.

Live gates require root, kernel BTF, tracefs, and the networking tools used by
the scenario. They create disposable resources and install cleanup traps, but
should still be run on a development host rather than a production node.

| Feature | Command |
|---|---|
| Tunnel filters and inner tuple evidence | `make live-tunnel` |
| Cross-namespace interface and socket fallback | `make live-netns` |
| Direct-to-stack association | `make live-stack` |
| Logical-free stack lifetime | `make live-stack-lifetime` |
| JIT helper discovery and map evidence | `make live-bpf-helper` |
| TC program identity, metadata, and BTF dumps | `make live-tc-program` |
| XDP entry/exit pairing and action evidence | `make live-xdp-program` |
| Clone/veth COW lineage | `make live-skb-replacement` |
| XDP_TX frame-to-SKB lineage | `make live-xdp-lineage` |
| SKB/XDP metadata projections | `make live-metadata` |
| BTF scalar filters | `make live-skb-filter` |
| Atomic `sk_buff` and shared-info dumps | `make live-btf-dump` |
| Human text controls | `make live-text-output` |
| Replay-safe rotation, compression, and retention | `make live-rotation` |

Each live script rejects missing readiness, asserts the relevant event
contract with `jq`, checks reliability telemetry, and cleans up namespaces,
links, qdiscs, and capture processes on exit.

When adding a live gate:

1. isolate names with a process-specific suffix;
2. use `mktemp -d` for artifacts;
3. install cleanup before creating resources;
4. wait for `--ready-file` before generating traffic;
5. assert positive evidence and relevant negative filtering;
6. require a complete footer with zero unexpected failures;
7. print the retained trace path for debugging.

"Zero unexpected failures" means every counter the gate can control. A gate
that traces the kernel machinery skbx itself uses may see counters move for
reasons that belong to the host rather than to the code, and must scope the
assertion to say which counter that is and why, instead of either demanding a
clean footer it cannot guarantee or dropping the check.

A gate whose capture is not scoped to its own traffic has the related
problem: system-wide events fill the event budget, the evidence it needs is
crowded out, and it passes or fails on host load. Scope the capture with a
filter so the assertion is deterministic, rather than widening the assertion
to tolerate the noise.

`make live-bpf-helper` and `make live-stack-lifetime` are the current
examples. Helper tracking attaches kprobes
to the map helpers the tracer calls, so any concurrent BPF hash activity on the
host re-enters the tracer and trips the kernel recursion guard. Those misses
are genuine missed observations and the footer is right to report them, but
they scale with what else is running: on an otherwise idle machine they are
zero, and on a workstation they are reliably in the thousands. `make live-stack-lifetime` kprobes `kmem_cache_free`, which the tracer's own
teardown path reaches, and had the same problem twice over: it also captured
`consume_skb` unfiltered, so on a busy host 1024 unrelated events filled the
budget before the lifetime triple it asserts on could appear.

Both gates therefore accept an incomplete footer only when
`kernel_recursion_misses` explains it, and keep every other reliability
counter at zero. `live-stack-lifetime` additionally scopes its capture to
`icmp`, which is the traffic it generates: measured under four concurrent
iperf3 streams that produced 30 events and 20 stack associations on every
run, against 1024 capped events and a 15-to-30 spread unfiltered.

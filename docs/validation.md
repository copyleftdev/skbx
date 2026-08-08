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

`make live-bpf-helper` is the current example. Helper tracking attaches kprobes
to the map helpers the tracer calls, so any concurrent BPF hash activity on the
host re-enters the tracer and trips the kernel recursion guard. Those misses
are genuine missed observations and the footer is right to report them, but
they scale with what else is running: on an otherwise idle machine they are
zero, and on a workstation they are reliably in the thousands. That gate
therefore accepts an incomplete footer only when `kernel_recursion_misses`
explains it, and keeps every other reliability counter at zero.

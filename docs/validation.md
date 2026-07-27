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

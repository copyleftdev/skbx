# skbx

**An agent-first packet-path instrument for Linux.**

`skbx` is a Rust/eBPF tracer inspired by `pwru`, designed around the
agent-first contracts proven by entropyx and WhatTheDiff:

- the deterministic engine is the source of truth;
- `skbx describe` teaches an agent how to use the tool;
- `skbx schema` publishes a versioned machine contract;
- live output is bounded JSONL with explicit start/end envelopes;
- every event has a stable evidence handle;
- kernel/user-space loss and decode failures are first-class telemetry;
- replay is deterministic and never needs root;
- replay assembles bounded per-SKB routes and emits consensus/outlier handles;
- caches and capture duration are bounded by default;
- AI may explain captured evidence, but never manufactures observations.

The working name is intentionally isolated to the CLI crate and can be
changed without rewriting the engine.

## Current vertical slice

The current implementation inspects kernel BTF and attaches one of five
CO-RE eBPF kprobe programs according to the position of the
`struct sk_buff *` argument. By default it discovers all matching attachable
kernel functions; exact names and whole-name regular expressions can narrow
the plan. Named or all loaded kernel modules can be included through their
split BTF. It records:

- monotonic kernel timestamp;
- observed SKB address plus a capture-local monotonic clone/COW lineage ID;
- probed instruction address and resolved symbol;
- PID, CPU and command;
- packet length, protocol, mark and interface index;
- IPv4/IPv6 addresses (including bounded IPv6 extension chains),
  TCP/UDP ports, ICMP type/code and TCP flags;
- optional inner tunnel tuples from kernel-maintained SKB header offsets;
- BTF-validated non-SKB functions associated through bounded frame-pointer
  anchors, including exact callees decoded from JIT-compiled BPF programs,
  with every event labeled `direct` or `stack`;
- typed lookup/update/delete map-operation evidence with map identity and
  explicitly bounded key/update-value bytes;
- up to four target-BTF-validated scalar `skb->…` metadata projections,
  including bounded pointer chains and typed per-field read errors;
- parenthesized `&&`/`||` target-BTF-validated scalar `skb->…` filters,
  normalized to at most four immutable comparisons;
- optional bounded BTF renderings of `struct sk_buff` and
  `struct skb_shared_info`, atomically correlated with their event and carrying
  explicit byte, truncation and helper-error evidence;
- exact entry observations for every currently loaded BTF-enabled TC
  classifier or XDP program, discovered through the kernel program API and
  attached with one shared-map fentry tracer per program;
- up to four target-BTF-validated `xdp->…` scalar projections alongside XDP
  packet length, interface, namespace, MTU, protocol and tuple evidence;
- parenthesized `&&`/`||` target-BTF-validated `xdp->…` scalar filters,
  normalized to at most four comparisons in a separate immutable XDP plan;
- matched XDP entry/exit pairs correlated through bounded shared state, with
  the exact numeric return code decoded as `XDP_ABORTED`, `XDP_DROP`,
  `XDP_PASS`, `XDP_TX` or `XDP_REDIRECT` while retaining unknown codes;
- caller, network namespace, MTU and the SKB control buffer;
- BTF-decoded SKB drop reasons on supported drop functions;
- kernel ring-buffer reserve failures.

Capture also supports in-kernel mark/interface/netns filters, outer and
independent inner-L2/inner-L3 libpcap expressions, optional kernel stacks,
bounded SKB clone/copy/COW tracking and an agent-safe `--ready-file`
synchronization point. Every event labels whether it matched the configured
filter, a tracked identity, or a stack association. Named interfaces are
resolved in the namespace selected by `--filter-netns`, and device-less
output SKBs fall back to their socket namespace.

The audited compatibility surface and its executable evidence are recorded in
[`docs/pwru-parity.md`](docs/pwru-parity.md). XDP-to-SKB lineage is proven for
the instrumented frame-transport paths; unobserved driver-private copying
paths remain an explicit evidence boundary rather than a silent claim.

## Commands

```console
skbx describe --format json
skbx schema
skbx doctor --json
skbx plan --json
skbx plan --filter-func 'ip.*'
sudo skbx capture --duration 10 --format jsonl --output trace.jsonl
sudo skbx capture --probe tcp_v4_do_rcv --output-stack \
  --timestamp absolute --output trace.jsonl tcp port 443
sudo skbx capture --probe tcp_v4_do_rcv --format text \
  --timestamp relative --output-caller --output-skb-cb \
  --output-tcp-flags --output-netns-names --output -
sudo skbx capture --probe ip_local_out --output-tunnel \
  --filter-tunnel-pcap-l2 'ether proto 0x0800' \
  --filter-tunnel-pcap-l3 'icmp' --output trace.jsonl udp port 4789
sudo skbx capture --probe ip_rcv \
  --output-skb-metadata 'skb->mark' \
  --output-skb-metadata 'skb->dev->ifindex' --output trace.jsonl
sudo skbx capture --probe ip_rcv \
  --filter-skb-expr 'skb->mark = 0b101010 && skb->protocol = 0x0800' \
  --output trace.jsonl
sudo skbx capture --probe ip_rcv --output-skb \
  --output-skb-shared-info --output trace.jsonl
sudo skbx capture --filter-trace-tc \
  --output-skb-metadata 'skb->mark' --output-skb \
  --output-skb-shared-info --output trace.jsonl
sudo skbx capture --filter-trace-xdp \
  --filter-xdp-expr '(xdp->frame_sz = 0 || xdp->frame_sz >= 0o1)' \
  --output-xdp-metadata 'xdp->frame_sz' \
  --output-xdp-metadata 'xdp->rxq->dev->ifindex' \
  --output trace.jsonl icmp
sudo skbx capture --probe ip_rcv --output trace.jsonl \
  --output-max-bytes 104857600 --output-max-backups 4 \
  --output-max-age-days 7 --output-compress
skbx replay trace.jsonl --format json
skbx explain trace.jsonl event:<handle>
```

Replay route patterns contain example `event:` handles, so an agent can move
from a consensus or outlier directly back to the raw observations with
`explain`.

`capture` is bounded to 10 seconds and 100,000 events unless explicitly
overridden. Exit codes are stable: `0` success, `1` runtime failure, `2`
usage error, `3` incomplete capture or reliability gate failure.

Rotated output is JSONL-only and uses exact byte and backup ceilings. The
active file is the newest segment; `.1`, `.2`, and so on are older, with
optional `.gz`. Every retained segment has matching capture envelopes and can
be replayed or explained on its own; input gzip is detected by magic bytes.

Text capture uses stable pwru-shaped core columns for SKB, CPU/process/PID,
timestamp, netns, mark, interface, protocol, MTU, length, tuple and function.
It supports pwru-compatible `--output-meta=false`, `--output-tuple=false`,
`--output-caller`, `--output-skb-cb`, `--output-tcp-flags`,
`--output-netns-names` and `--netns-names-max-length` presentation controls.
Agent provenance remains visible as `ASSOC`/`ORIGIN`; metadata, control buffer,
tunnel, map, stack and BTF evidence use deterministic indented records. JSON
always retains the complete evidence regardless of text presentation flags.

## Build

Prerequisites:

- Rust 1.85 or newer;
- Clang/LLVM with the BPF backend;
- `bpftool`;
- libelf development headers and library;
- libpcap development headers and library;
- a Linux kernel exposing `/sys/kernel/btf/vmlinux`.

```console
cargo build --release
cargo test --workspace
```

The build script generates `vmlinux.h` into Cargo's output directory, then
compiles and embeds the CO-RE eBPF object. Generated kernel headers never
dirty the source tree.

Use `make check` for the same formatting, test and strict-lint gates run by
CI. `make benchmark` executes the ignored 100,000-event replay throughput
test in release mode.

On a disposable Linux test host, `sudo scripts/live-tunnel-test.sh
target/debug/skbx` creates two temporary network namespaces, verifies VXLAN
outer/inner filtering and tuple evidence, then removes both namespaces.
`sudo scripts/live-netns-test.sh target/debug/skbx` similarly verifies
cross-namespace interface lookup and the socket namespace fallback.
`sudo scripts/live-stack-test.sh target/debug/skbx` verifies that a direct
`ip_rcv` observation and a requested non-SKB `fib_table_lookup` call retain
the same evidence-addressed SKB identity. `sudo
scripts/live-stack-lifetime-test.sh target/debug/skbx` verifies ordered
same-SKB evidence across the logical-free teardown path:
`consume_skb` → `dst_release` → `kmem_cache_free`. The association is removed
at `kfree_skbmem`, before the SKB allocation itself is returned. `sudo
scripts/live-bpf-helper-test.sh target/debug/skbx` loads an isolated TC
classifier and proves automatic JIT-callee discovery with ordered
`tcf_classify` → map-helper evidence. `sudo
scripts/live-skb-replacement-test.sh target/debug/skbx` forces clone and veth
XDP copy-on-write transitions, then proves that three observed SKB addresses
retain one canonical identity through replay and `explain`. `sudo
scripts/live-xdp-lineage-test.sh target/debug/skbx` proves that identity also
survives XDP_TX frame transport into a newly allocated SKB, labeled
`tracked_xdp`. `sudo scripts/live-skb-filter-test.sh target/debug/skbx`
proves that BTF-compiled scalar predicates reject unmarked traffic and retain
marked traffic with matching projected values. `sudo
scripts/live-btf-dump-test.sh target/debug/skbx` proves atomic `sk_buff` and
shared-info renderings alongside an existing metadata projection. `sudo
scripts/live-text-output-test.sh target/debug/skbx` proves named-namespace,
caller, control-buffer and TCP-flag presentation plus metadata/tuple
suppression in isolated expanded and compact text captures. `sudo
scripts/live-tc-program-test.sh target/debug/skbx` loads an isolated TC
classifier and proves BTF entry discovery, dynamic fentry attachment, exact
program identity, read-clean SKB metadata and atomic `sk_buff` plus
`skb_shared_info` renderings. `sudo
scripts/live-xdp-program-test.sh target/debug/skbx` proves dynamic-only XDP
attachment with exact paired entry/exit identity, decoded `XDP_PASS` action,
L2 pcap filtering, tuple decoding and target-BTF-checked `xdp_buff` filters and
metadata.

## Architecture

```text
kernel kprobes
    │ fixed-size records + exact reserve-failure counter
    ▼
BPF ring buffer
    ▼
skbx-sensor ── raw, validated events
    ▼
skbx-core ─── handles, bounded state, symbol evidence, summaries
    ▼
skbx-contract ── traceq/0.1.0 JSONL + schema
    ▼
CLI / agent / CI
```

See [docs/pwru-parity.md](docs/pwru-parity.md) for the auditable feature
matrix and [docs/architecture.md](docs/architecture.md) for design invariants.

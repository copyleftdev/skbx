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
- SKB address;
- probed instruction address and resolved symbol;
- PID, CPU and command;
- packet length, protocol, mark and interface index;
- IPv4/IPv6 addresses (including bounded IPv6 extension chains),
  TCP/UDP ports, ICMP type/code and TCP flags;
- optional inner tunnel tuples from kernel-maintained SKB header offsets;
- caller, network namespace, MTU and the SKB control buffer;
- BTF-decoded SKB drop reasons on supported drop functions;
- kernel ring-buffer reserve failures.

Capture also supports in-kernel mark/interface/netns filters, outer and
independent inner-L2/inner-L3 libpcap expressions, optional kernel stacks,
bounded SKB clone/copy tracking and an agent-safe `--ready-file`
synchronization point.

It does **not yet** claim full `pwru` parity. Packet-byte/BTF dumps, tunnel
encapsulation-specific formatting, TC/XDP tracing and helper/map argument
tracing remain explicit gaps.

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
sudo skbx capture --probe ip_local_out --output-tunnel \
  --filter-tunnel-pcap-l2 'ether proto 0x0800' \
  --filter-tunnel-pcap-l3 'icmp' --output trace.jsonl udp port 4789
skbx replay trace.jsonl --format json
skbx explain trace.jsonl event:<handle>
```

Replay route patterns contain example `event:` handles, so an agent can move
from a consensus or outlier directly back to the raw observations with
`explain`.

`capture` is bounded to 10 seconds and 100,000 events unless explicitly
overridden. Exit codes are stable: `0` success, `1` runtime failure, `2`
usage error, `3` incomplete capture or reliability gate failure.

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

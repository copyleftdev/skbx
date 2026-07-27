# pwru parity matrix

This matrix is the definition of parity. It is derived from the upstream
`pwru --help` surface and runtime orchestration, not from skbx's current
implementation. A feature only moves to **supported** after unit/contract
coverage and a relevant live-kernel check exist.

| pwru capability | skbx status | Evidence or required work |
|---|---|---|
| Kernel BTF loading | supported | `plan` parses system or `--kernel-btf`; capture passes custom BTF to libbpf CO-RE relocation |
| Discover SKB functions from BTF | supported | Arguments 1–5 are classified without a function-name allowlist |
| Exact function selection | supported | Repeated `--probe` |
| Whole-name regular-expression selection | supported | `--filter-func` with Rust `regex` |
| Individual kprobe backend | supported | libbpf-rs individual links and explicit `--backend kprobe` |
| kprobe-multi backend | supported | libbpf-rs multi links grouped by SKB argument position; explicit and auto modes live checked |
| Concurrent attach/detach batches | supported | Multi links attach/detach each signature group as one kernel operation |
| Named kernel modules / all modules | supported | `--kmods` and `--all-kmods` parse base/split BTF with module-qualified plan and capture provenance |
| pcap expression filter | supported | rust-pcap/libpcap compiler plus verifier-bounded in-kernel cBPF VM; validates and accepts up to pwru's 4096-instruction ceiling |
| Tunnel L2/L3 pcap filters | supported | Independent `--filter-tunnel-pcap-l2` and `--filter-tunnel-pcap-l3` validated cBPF predicates; both predicates are ANDed and non-tunnel SKBs retain pwru's pass-through semantics; isolated VXLAN live gate |
| Network namespace filter | supported | Absolute path/inode resolution and early BPF predicate; namespace identity falls back from `skb->dev` to `skb->sk`; isolated live gate covers device-less output SKBs |
| Interface filter | supported | Numeric ifindex plus current/selected-netns ifname resolution; cross-netns lookup uses `nix` `setns` with mandatory restoration and is covered by an isolated live gate |
| Mark/mask filter | supported | Decimal/hex `mark[/mask]`, immutable rodata configuration and early BPF predicate |
| Arbitrary SKB expression filter | partial | `--filter-skb-expr` parses parenthesized `&&`/`||` expressions over scalar `skb->…` comparisons (`==`, `!=`, `<`, `<=`, `>`, `>=`), normalizes them to bounded disjunctive form with at most four expanded comparisons, and target-BTF checks paths and literal widths before immutable in-kernel execution; unrestricted C syntax and expansions beyond the verifier-safe bound remain intentionally unsupported |
| Arbitrary XDP expression filter | partial | `--filter-xdp-expr` provides the same parenthesized, bounded typed language over target-BTF-validated `xdp->…` paths and executes from a separate immutable XDP access plan; dynamic-only live gates cover pointer chains and boolean groups; unrestricted C syntax and expansions beyond the verifier-safe bound remain intentionally unsupported |
| Track SKB across transformations | supported | Bounded LRU lineage maps assign capture-local monotonic IDs and propagate through clone/copy, current `skb_pp_cow_data`, older veth COW, and data-head correlation from XDP frames into newly allocated SKBs; explicit `filter`/`tracked_skb`/`tracked_xdp` provenance, lifetime deletion, replay/explain continuity, forced COW and XDP_TX live gates |
| Track logically freed SKB by stack ID | supported | Bidirectional bounded stack-anchor maps preserve identity through non-SKB teardown calls and delete both directions at `kfree_skbmem`; live gate requires ordered, read-clean `consume_skb` → `dst_release` → `kmem_cache_free` evidence on one SKB |
| Trace non-SKB functions | supported | `--filter-non-skb-funcs` validates function existence in BTF, attaches through either backend and emits explicit `association: stack`; live checked with `ip_rcv` → `fib_table_lookup` same-SKB evidence |
| Trace BPF helper calls | supported | `--filter-track-bpf-helpers` performs bounded x86_64 decoding of current JIT programs from `/proc/kcore`, resolves exact direct callees through kallsyms, classifies them with BTF and uses explicit stack association; isolated TC/map-helper live gate |
| Trace TC programs | supported | `--filter-trace-tc` enumerates currently loaded BTF-enabled `SCHED_CLS` programs through libbpf-rs, discovers each entry from program BTF, and loads one fentry tracer per target while reusing the base ring, telemetry, stack and lineage maps; events and capture headers carry exact program ID/name/entry/kind and replay routes use that identity; the isolated live gate combines metadata, `sk_buff` and `skb_shared_info` dumps in one atomic 8568-byte program record with zero-loss evidence |
| Trace XDP programs | supported | `--filter-trace-xdp` dynamically attaches paired fentry/fexit links to every currently loaded BTF-enabled XDP program; bounded shared state admits exits only for matched entries; events carry exact ID/name/entry/kind/phase, numeric/decoded return action, L2-filtered packet, tuple, interface, netns and MTU evidence; dynamic-only isolated live gate and replay prove ordered `entry → exit:XDP_PASS(2)` routes with zero observation loss |
| Base metadata | supported | PID, CPU, comm, length, mark, protocol, ifindex, netns and MTU are captured with per-field read telemetry |
| IPv4/IPv6 L4 tuple | supported | Verifier-bounded IPv4 plus IPv6 decoder with at most eight extension headers; TCP/UDP ports, TCP flags, ICMPv4/ICMPv6 type/code and non-initial fragment handling |
| TCP flags | supported | Captured from the TCP wire header |
| Tunnel tuple | supported | `--output-tunnel` decodes from the kernel-maintained `inner_network_header`; isolated VXLAN gate validates outer UDP and inner ICMP evidence with zero read/reserve failures |
| Full `sk_buff` / shared-info dump | supported | `--output-skb` and `--output-skb-shared-info` preflight target BTF/helper support, render into a per-CPU 4092-byte buffer per type, and atomically emit one 8576-byte probe record or 8568-byte TC-program record with required/captured byte counts, truncation and helper errors; compact records remain unchanged when disabled; isolated live gates combine both dumps with metadata evidence |
| SKB control buffer | supported | Fixed 20-byte CO-RE read |
| Custom SKB/XDP metadata expressions | supported | Each context independently supports at most four strict target-BTF-validated scalar paths with four access steps, typed values and per-field failures; `--output-skb-metadata` reads `sk_buff` and `--output-xdp-metadata` reads `xdp_buff`; isolated live gates cover both |
| Caller | supported | Return address capture and deterministic kallsyms enrichment |
| Kernel stack | supported | Optional 50-frame stack map with explicit enrichment-failure telemetry |
| SKB drop reason | supported | BTF enum decoding for both `kfree_skb_reason` and the older `sk_skb_reason_drop` signature; live checked with named reasons |
| BPF map operation arguments | supported | JIT-discovered lookup/update/delete implementations use operation-specific probes and 320-byte extended records while ordinary events remain 224 bytes; map ID/name/sizes plus at most 32 bytes each of key/value, explicit truncation/read telemetry, isolated TC hash-map live gate |
| Timestamp modes | supported | `none`, raw-monotonic `current`, per-SKB `relative` and RFC 3339 `absolute`; JSON always retains raw monotonic evidence |
| Text output | supported | Stable pwru-shaped core columns cover SKB, CPU/process/PID, timestamp, netns, mark, interface, protocol, MTU, length, tuple and function, with explicit association/origin provenance; pwru-compatible metadata/tuple suppression, caller, SKB control-buffer, TCP-flag and bounded netns-name controls are supported; requested metadata, tunnel, map, stack and BTF evidence render as deterministic indented records, while JSON deliberately retains complete evidence regardless of text presentation |
| JSON output | supported | Versioned append-only `traceq` JSONL |
| Output event limit | supported | `--max-events`, bounded by default |
| Rotating/compressed output files | supported | Maintained `file-rotate`/`flate2` sink with exact byte/backup bounds, optional gzip and transparent gzip replay/explain; skbx rotates only after a complete footer and starts the next file with a matching header, so every retained segment replays independently; unit and live gates force rotation |
| Ready file | supported | `--ready-file` removes stale state, then uses create-new only after links attach and the capture header is flushed |
| Loss/recursion reporting | supported | Ring reserve/read/filter/decode/enrichment/output telemetry is explicit; exact loaded tracer program IDs are retained and their kernel `bpf_prog_info.recursion_misses` counters are summed at segment and capture boundaries, with any miss making the reliability gate incomplete; base, TC and paired-XDP live gates cover the query path |
| Deterministic replay | supported | Rootless, byte-stable summary |
| Evidence-handle lookup | supported | `event:<digest>` plus bounded same-SKB context |
| Self-describing agent contract | supported | `describe`, JSON Schema and stable exit codes |

## Dependency policy

- **libbpf-rs** is the maintained Rust interface from the libbpf project and
  owns object loading, CO-RE relocation, maps, individual links and
  kprobe-multi links.
- **btf-rs** is the Retis project's focused BTF parser and provides public,
  typed function-prototype traversal including split BTF.
- **regex**, **serde**, **clap**, **thiserror**, **anyhow**, and **blake3** are
  mature ecosystem components used only for their narrow responsibilities.
- **nix** provides the typed `setns` wrapper used for a single startup-time
  interface lookup in a selected network namespace.
- **rust-pcap** binds the system libpcap compiler; skbx validates its cBPF
  output before copying it into immutable eBPF configuration.
- **iced-x86** is a focused MIT-licensed decoder used at startup to resolve
  direct call targets from bounded x86_64 BPF JIT byte ranges.
- **file-rotate** and **flate2** are focused MIT-family rolling/gzip
  components used for explicit segment moves, retention and streaming
  compression; skbx owns traceq envelope boundaries and never delegates JSON
  splitting to either crate.
- Kernel hot-path logic remains small GPL-2.0 C compiled by Clang. No parsing,
  allocation, JSON encoding, or agent logic runs inside eBPF.

New dependencies require a clear owner, active maintenance, compatible
licensing, and an advantage over a small auditable local implementation.

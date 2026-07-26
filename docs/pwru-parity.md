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
| Arbitrary SKB expression filter | missing | Needs a constrained BTF-checked expression compiler |
| Track SKB across transformations | partial | Bounded LRU identity map, clone/copy propagation and `kfree_skbmem` lifetime deletion supported; veth/XDP conversion remains |
| Track freed SKB by stack ID | partial | Bidirectional bounded stack-anchor maps and `kfree_skbmem` cleanup are implemented; direct-to-associated live gate passes, while an after-free bridge gate remains |
| Trace non-SKB functions | supported | `--filter-non-skb-funcs` validates function existence in BTF, attaches through either backend and emits explicit `association: stack`; live checked with `ip_rcv` → `fib_table_lookup` same-SKB evidence |
| Trace BPF helper calls | missing | Architecture-aware helper discovery and non-SKB association |
| Trace TC programs | missing | Enumerate programs and attach fentry dynamically |
| Trace XDP programs | missing | XDP metadata path and fentry/fexit correlation |
| Base metadata | supported | PID, CPU, comm, length, mark, protocol, ifindex, netns and MTU are captured with per-field read telemetry |
| IPv4/IPv6 L4 tuple | supported | Verifier-bounded IPv4 plus IPv6 decoder with at most eight extension headers; TCP/UDP ports, TCP flags, ICMPv4/ICMPv6 type/code and non-initial fragment handling |
| TCP flags | supported | Captured from the TCP wire header |
| Tunnel tuple | supported | `--output-tunnel` decodes from the kernel-maintained `inner_network_header`; isolated VXLAN gate validates outer UDP and inner ICMP evidence with zero read/reserve failures |
| Full `sk_buff` / shared-info dump | missing | Needs `bpf_snprintf_btf` buffers or a typed bounded field projection |
| SKB control buffer | supported | Fixed 20-byte CO-RE read |
| Custom SKB/XDP metadata expressions | missing | Needs constrained BTF-checked field projections |
| Caller | supported | Return address capture and deterministic kallsyms enrichment |
| Kernel stack | supported | Optional 50-frame stack map with explicit enrichment-failure telemetry |
| SKB drop reason | supported | BTF enum decoding for both `kfree_skb_reason` and the older `sk_skb_reason_drop` signature; live checked with named reasons |
| BPF map operation arguments | missing | Dedicated entry/return probes and typed evidence records |
| Timestamp modes | supported | `none`, raw-monotonic `current`, per-SKB `relative` and RFC 3339 `absolute`; JSON always retains raw monotonic evidence |
| Text output | partial | Stable text exists but does not mimic every pwru column |
| JSON output | supported | Versioned append-only `traceq` JSONL |
| Output event limit | supported | `--max-events`, bounded by default |
| Rotating/compressed output files | missing | Add a maintained rolling-file sink |
| Ready file | supported | `--ready-file` removes stale state, then uses create-new only after links attach and the capture header is flushed |
| Loss/recursion reporting | partial | Ring reserve/read/filter/decode/enrichment/output telemetry explicit; BPF recursion misses are not yet observable |
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
- Kernel hot-path logic remains small GPL-2.0 C compiled by Clang. No parsing,
  allocation, JSON encoding, or agent logic runs inside eBPF.

New dependencies require a clear owner, active maintenance, compatible
licensing, and an advantage over a small auditable local implementation.

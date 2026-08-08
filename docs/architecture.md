# Architecture

## Product contract

`skbx` answers two different questions without mixing them:

1. **Observation:** which kernel networking functions handled this SKB?
2. **Explanation:** what does the captured route imply?

Observation is native, deterministic for recorded input, and evidence-backed.
Explanation is downstream and optional. An agent can only explain events
present in a trace.

The protocol is `traceq/0.1.0`. A trace is append-only JSONL:

```text
capture_start
event
event
...
capture_end
```

The footer is mandatory. Missing footer means the artifact is incomplete.
The footer carries kernel loss, user-space decode failures, output failures
and the stop reason. This prevents a partial trace from silently looking
authoritative.

Kernel loss is reported as a total plus two independent breakdowns, not their
cross product. `kernel_loss_by_cpu` attributes a hole to the core it happened
on; the kernel keeps those counters in a per-CPU array, so that view costs
nothing to carry. `kernel_loss_by_probe` attributes it to the probe that could
not emit — the kernel function, or the TC/XDP program id — which is what names
the leg of the path a hole belongs to. Only CPUs and probes that lost something
appear, and an empty array positively states that none did.

The per-probe attribution is bounded by a fixed-size map. When a probe plan
overflows it, the surplus lands in `kernel_unattributed_reserve_failures`
rather than being misfiled against another probe. The breakdown is also a
separate map read from the totals, taken while probes are still firing, so
failures landing between the two reads are counted without being attributed.
The kernel bumps the total before the attribution and userspace reads them in
the opposite order, which keeps both effects pointing the same way:
`kernel_loss_by_probe` undercounts and never exceeds
`kernel_reserve_failures`, which remains the only authoritative total.

A rotated segment footer is the exception: it holds the difference between two
checkpoints of two separately sampled series, so a single segment's per-probe
breakdown can exceed that segment's own total by however far the earlier
checkpoint lagged. Measured values are reported rather than clamped, and the
undercount still holds across all segments summed together.

The per-CPU breakdown has no such gap — it comes from the same map read as the
totals, so it sums to `kernel_reserve_failures` exactly, in whole captures and
in segments alike.

A hole that is attributed to a probe still says only that this probe failed to
emit at least once. It does not identify which packet lost that observation, so
`complete: false` continues to downgrade every absence in the capture — the
attribution narrows where to look, it does not restore the absence as evidence.

## Pipeline

```text
capability probe
  → deterministic probe plan
  → attach
  → bounded ring-buffer drain
  → validate fixed-size record
  → resolve immutable evidence handle
  → stream event
  → finalize reliability footer
  → deterministic replay/summary
```

## Invariants

1. Same JSONL input produces byte-identical replay summaries.
2. Live capture is bounded by duration and event count by default.
3. Kernel loss and decoding loss are never folded into ordinary events.
4. Machine output on stdout is never mixed with diagnostics on stderr.
5. All write errors propagate.
6. State keyed by SKB or PID has a declared maximum size and eviction policy.
7. Source addresses are evidence; symbol names are enrichment and may be
   unavailable when `kptr_restrict` hides kernel addresses.
8. Unsupported capability is explicit, never approximated silently.

## Probe safety

The planner parses the running kernel's BTF with `btf-rs`, locates
`struct sk_buff *` in the first five ABI argument positions, intersects the
result with attachable symbols, and selects the corresponding eBPF program.
An exact request absent from BTF stays visible as unavailable. No function is
attached based only on its name.

## Performance model

- one fixed-size ring-buffer reservation per observed function call;
- no packet allocation in kernel space;
- no unbounded kernel map;
- buffered userspace writes;
- streaming aggregation with bounded maps;
- deterministic `BTreeMap` ordering only at summary boundaries.

The kernel hot path never performs JSON encoding, symbolization or process
filesystem reads.

## Delivered surface

The evidence-backed surface includes BTF-discovered SKB and non-SKB probes,
individual and kprobe-multi attachment, split-BTF modules, tuple and tunnel
decoding, lineage across clone/copy/COW and XDP frame transport, TC/XDP
program observation, helper/map evidence, typed metadata and filters, atomic
BTF dumps, loss telemetry, schema, doctor, plan, capture, replay, and explain.

The authoritative status is the executable
[pwru parity matrix](pwru-parity.md), not a prose roadmap. Future work starts
as an observation request and moves into the supported matrix only after
unit, contract, and relevant live-kernel evidence exist.

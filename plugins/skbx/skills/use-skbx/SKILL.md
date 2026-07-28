---
name: use-skbx
description: Install, validate, and operate skbx for evidence-first Linux packet-path investigations. Use when diagnosing packet drops, tracing website requests through a Linux host, inspecting kernel networking hooks, planning bounded eBPF captures, replaying or explaining traceq JSONL evidence, assessing capture reliability, or exploring the local Arc multi-host demo.
---

# Use skbx

Treat the native trace as the source of truth. Help the user collect the
smallest bounded dataset that can answer the question, then separate observed
facts from correlation, candidates, and unknowns.

## Choose the workflow

Classify the request before running commands:

- **Setup or first use:** inspect the host, install only with permission, then
  run `doctor` and a no-attach plan.
- **Live investigation:** define the owned host and traffic tuple, plan probes,
  obtain authorization for privileged capture, and use a short duration.
- **Existing evidence:** skip installation and privilege checks when `skbx`
  already exists; replay the supplied `traceq` file and inspect its footer.
- **Multi-host exploration:** use Arc's rootless demo only from an skbx source
  checkout. Do not present the lab service as a production control plane.

Read [recipes.md](references/recipes.md) only when an exact capture recipe or
Arc command is needed.

## Establish scope

Confirm or infer these facts before capture:

- the Linux host or namespace the user controls;
- the target protocol, address, and port;
- whether the question is local-host, transit, or target-host behavior;
- the permitted duration, output path, and privilege boundary.

Never imply that one local sensor observes an ISP or remote server. Local
route, curl timing, `tracepath`, and `mtr` are supporting evidence, not packet
receipts from uninstrumented infrastructure.

## Inspect before changing anything

Run read-only checks first:

```console
uname -s
uname -m
command -v skbx
skbx --version
```

Live capture requires Linux on x86_64 or arm64, kernel BTF, Clang/LLVM with
the BPF backend, `bpftool`, libelf, libpcap, and root or suitable BPF/perf
capabilities. Replay and evidence lookup do not require root.

If `skbx` is absent and the user asked to install it, explain that the official
source install downloads and compiles code, then request approval before:

```console
cargo install --git https://github.com/copyleftdev/skbx --locked skbx-cli
```

Do not silently install OS packages, alter capabilities, weaken kernel
security settings, or run a fetched script through a shell.

## Preflight and plan

Use the machine-readable surfaces before attachment:

```console
skbx doctor --json
skbx plan --probe ip_rcv --json
```

Treat a failed `doctor` prerequisite or unresolved planned probe as a blocker
for the corresponding observation. Prefer probes verified by `plan` on the
target kernel over a memorized list.

## Capture deliberately

Before a command containing `sudo`, explain exactly what will attach, what
traffic is filtered, how long it will run, and where evidence will be written.
Run it only with explicit authorization.

Keep live captures bounded:

- specify exact probes;
- use the narrowest valid packet filter;
- set `--duration`;
- write JSONL to a named file;
- use `--ready-file` when coordinating a reproducer;
- avoid capturing unrelated traffic.

Never capture a host, namespace, or traffic stream the user is not authorized
to observe.

## Validate evidence before explaining it

Inspect the last JSONL envelope and run deterministic replay:

```console
tail -n 1 trace.jsonl
skbx replay trace.jsonl --format json
```

Check that `capture_end` exists. Report the trace as partial when it is absent,
`complete` is false, or reliability counters report reserve, recursion, read,
decode, enrichment, or output loss. Do not turn missing evidence into a claim
that the packet did not traverse a hook.

Use stable handles to retrieve context:

```console
skbx explain trace.jsonl event:<handle>
```

State conclusions in four lanes:

1. **Observed:** emitted by a named sensor and trace.
2. **Correlated:** supported across observed records with an explicit basis.
3. **Candidate:** plausible but metadata or timing is insufficient.
4. **Unknown:** no authoritative observation covers the boundary.

## Present the result

Return:

- the investigation question and scope;
- commands actually run;
- authoritative observations with handles;
- reliability state and any loss;
- evidence boundaries;
- the smallest next capture that would reduce uncertainty.

AI may explain skbx evidence. It must never manufacture an event, route, drop
reason, cross-host relationship, or claim of completeness.

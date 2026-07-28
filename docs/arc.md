# skbx Arc

Arc is an experimental command center for one question:

> What did each Linux host observe during the same bounded packet-path
> investigation, and which cross-host relationships can the evidence actually
> support?

It does not merge several traces into a fictional global truth. Each sensor's
validated `traceq/0.1.0` artifact remains authoritative for that host. Arc adds
a separate `missionq/0.1.0` record containing the capture plan, assignments,
artifact manifests, and explicitly labelled cross-host relationships.

## Try the complete vertical slice

Run the seeded three-sensor mission:

```console
cargo run -p skbx-arc -- serve --demo
```

Open <http://127.0.0.1:7878>. The scenario follows one HTTPS flow from a
developer laptop through an edge gateway to an application host. The final host
observes `SKB_DROP_REASON_NETFILTER_DROP`; that artifact also reports 14
recursion misses, so the mission is deliberately labelled `partial`.

The console supports:

- a stable mission topology with correlated, candidate, and unknown paths;
- sensor selection and evidence filtering;
- a synchronized event timeline;
- per-event receipts and correlation bases;
- visible loss, clock uncertainty, and incomplete capture state;
- a 390 px investigation layout and reduced-motion behavior.

The demo is created through the same state transitions used by the HTTP API. It
does not use a separate presentation-only data model.

## Components and trust boundary

```text
                         outbound poll
  Linux sensor ─────────────────────────────────┐
  skbx-agent                                    │
      │ exact bounded plan                      ▼
      │                                 ┌───────────────┐
      ├── skbx capture (future)         │   skbx Arc    │
      │                                 │ control plane │
      └── traceq artifact ─────────────▶│ + correlator  │
                                        └───────┬───────┘
                                                │
                                                ▼
                                      Mission Constellation
```

The current agent is intentionally outbound-only. Its rootless
`fixture-once` mode can register, poll for one assignment, validate the plan
digest and artifact byte limit, and upload a pre-existing trace. It cannot
execute shell text or start privileged capture.

A future live backend must translate a validated `CapturePlan` into an exact
argument vector for the native `skbx capture` command. It must never accept a
command string from Arc. The contract currently bounds:

- mission duration to 300 seconds;
- mission size to 32 sensors;
- events to 1,000,000 per sensor artifact;
- artifact size to 64 MiB;
- correlation windows to 5 seconds;
- exact requested probes to 64 entries.

Arc validates the `traceq` stream before indexing it. It rejects artifacts
which exceed the mission's byte or event budget, accepts an identical retry
idempotently, and rejects a different second artifact for the same
mission/sensor pair.

## Mission lifecycle

```text
draft ──arm──▶ armed ──lease──▶ capturing
                                  │
                    all artifacts submitted
                                  │
                         ┌────────┴────────┐
                         ▼                 ▼
                      complete          partial
                    no reported loss   any incomplete trace
```

Assignment leases are retry-safe. Polling during an active lease returns the
same generation and plan. Polling at or after expiry issues a newer generation.
Artifact content uses a BLAKE3 digest for idempotency and provenance.

## Correlation algorithm

Arc correlates only adjacent sensors in the ordered mission topology.
Direction-independent flow keys partition observations before matching, which
keeps unrelated traffic out of the candidate graph. Candidate pairs must fit
the mission's bounded time window plus both sensors' clock uncertainty.

Within each flow partition Arc performs deterministic sparse min-cost maximum
bipartite matching:

1. maximize the number of one-to-one observation matches;
2. among maximum-cardinality solutions, minimize timestamp distance;
3. break equal costs with stable event-handle ordering.

Packet length and outer/tunnel tuple agreement contribute to the evidence
basis. A metadata mismatch is labelled `candidate`, not silently upgraded to
`correlated`. Missing artifacts or zero viable matches produce an `unknown`
edge.

This is a better fit than greedy nearest-neighbor matching: greedy selection
can consume an observation needed for the only valid downstream match. It also
avoids the dense cubic cost of applying the Hungarian algorithm to an entire
capture. Flow partitioning and the bounded time window keep the residual graph
sparse; the current shortest-augmenting-path implementation prioritizes
determinism and correctness for the 32-sensor MVP.

## HTTP surface

The lab API is versioned under `/api/v1`:

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/sensors` | Register or refresh a sensor |
| `POST` | `/missions` | Create a validated bounded mission |
| `POST` | `/missions/{id}/arm` | Create pending assignments |
| `GET` | `/sensors/{id}/assignments/next` | Lease or retry an assignment |
| `POST` | `/missions/{id}/artifacts/{sensor}` | Validate and ingest `traceq` |
| `GET` | `/missions/{id}` | Read the mission evidence record |
| `GET` | `/snapshot` | Read the console projection |

Errors are structured JSON with a stable category and an actionable message.
`/healthz` reports service readiness and the mission contract version.

## Deployment strategy

The current executable is appropriate for a single-machine lab only. It binds
to `127.0.0.1:7878` unless an operator deliberately chooses another address,
and all state disappears on restart.

Before any shared or production deployment, Arc needs these gates:

1. **Identity and transport:** mutual TLS for every sensor, operator
   authentication, short-lived mission authorization, and certificate
   rotation.
2. **Durable evidence:** transactional mission/lease state, content-addressed
   artifact storage, retention policy, and encryption at rest.
3. **Live capture adapter:** a capability-checked plan-to-argv translator,
   privilege separation, local operator policy, and signed assignment
   envelopes.
4. **Fleet resilience:** heartbeat expiry, lease reconciliation, backpressure,
   resumable uploads, audit logs, and explicit degraded/partitioned states.
5. **Operational gates:** multi-kernel integration tests, adversarial artifact
   tests, load tests at contract limits, restore drills, and a documented
   incident response path.

The intended topology after those gates is one regional Arc service, an object
store for immutable artifacts, a transactional database for mission state, and
outbound-only agents. Arc should not become a general-purpose remote shell.

## Validation

The vertical slice is covered by:

- contract and deterministic-correlation unit tests;
- mission lifecycle, lease, conflict, budget, and API integration tests;
- a partial-evidence demo assertion;
- workspace formatting, Clippy, and test gates;
- browser checks for interactive evidence inspection, console errors,
  responsive overflow, and reduced motion.

Run the Rust gates with:

```console
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

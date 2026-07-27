---
title: I Had a Lot of Fun Building a Linux Packet Flight Recorder
published: false
description: I built skbx to follow packets through the Linux kernel, preserve what it observed, and replay the evidence later without root.
tags: linux, ebpf, networking, rust
cover_image: https://raw.githubusercontent.com/copyleftdev/skbx/main/assets/skbx-dev-cover-1000x420.png
---

<!--
Suggested cover alt text:
An abstract packet path passing through translucent kernel layers, a tunnel,
and a sequence of saved evidence markers.
-->

Some projects begin with a roadmap. `skbx` began with me falling into a Linux
networking rabbit hole and enjoying it much more than I expected.

The question was simple:

> Where did this packet actually go?

The answer was not.

A packet can pass through network namespaces, routing decisions, Netfilter,
traffic control, XDP programs, tunnels, clones, copies, and drop paths. A
packet capture at one interface can be completely correct while still showing
only one part of that journey.

I wanted to see more of the journey. Then I wanted to save what I saw, replay
it later without root, and know whether the capture itself had lost
observations.

That became [skbx](https://github.com/copyleftdev/skbx).

## The short version

`skbx` is a Linux packet-path flight recorder built with Rust and CO-RE eBPF.

During a live capture, it observes kernel networking functions and writes an
append-only JSONL evidence stream. Afterward, that stream can be replayed and
inspected without loading another eBPF program.

```text
live traffic
    ↓
CO-RE eBPF observations
    ↓
bounded traceq JSONL
    ↓
replay → route patterns → explain an event
```

It can observe:

- kernel functions handling an `sk_buff`;
- packet clones, copies, copy-on-write, and XDP-to-SKB transitions;
- TC and XDP program entry and exit;
- tunnels and inner packet tuples;
- kernel-reported drop reasons;
- selected BPF helper and map activity;
- capture loss, decoding failures, and output failures.

This is not a replacement for tcpdump or Wireshark. Those tools are excellent
when the question is about packet bytes and protocols at a capture point.
`skbx` is for questions about the path through the local Linux kernel.

It is also not the first tool to follow packets through that path. The project
is explicitly inspired by
[pwru](https://github.com/cilium/pwru), which showed how useful broad eBPF
packet tracing can be.

The part I especially wanted to explore was the evidence after the live
terminal stopped scrolling.

## Why call it a flight recorder?

Live tracing is useful, but incident work often continues after the privileged
session has ended.

Someone else may need to inspect the capture. We may want to compare it with a
successful request. We may need to cite one exact event in a bug report. An
automation or AI system may need structured input, but it should not be allowed
to invent observations that were never captured.

So the native `skbx` stream, called `traceq`, has an envelope:

```text
capture_start
event
event
...
capture_end
```

Every event receives a stable handle:

```text
event:111111111111111111111111
```

Replay groups ordered events into bounded route patterns, which receive their
own handles:

```text
route:1c0201e74424e253f8363577
```

The footer matters as much as the events. It records the stop reason and
reliability counters for kernel reservation failures, tracer recursion misses,
read failures, userspace decoding and enrichment failures, and output
failures.

If the footer is absent, the artifact is incomplete. If the tracer lost
observations, that uncertainty stays attached to the result.

I like this property because tracing software is also software. It should not
silently act omniscient.

## Installing it

The live tracer currently supports Linux on x86_64 and arm64. It needs Rust
1.85 or newer, Clang/LLVM with the BPF backend, `bpftool`, libelf, libpcap, and
a kernel exposing `/sys/kernel/btf/vmlinux`.

On Ubuntu, the native packages are:

```bash
sudo apt-get install "linux-tools-$(uname -r)" \
  clang llvm libelf-dev libpcap-dev pkg-config
```

On Debian:

```bash
sudo apt-get install \
  bpftool clang llvm libelf-dev libpcap-dev pkg-config
```

Then install the CLI directly from GitHub:

```bash
cargo install --git https://github.com/copyleftdev/skbx --locked skbx-cli
```

Before attaching anything, `doctor` checks the host:

```bash
skbx doctor --json
```

`plan` goes one step further. It shows exactly which functions would be
attached without performing the attachment:

```bash
skbx plan --filter-func 'ip.*' --json
```

That separation turned out to be useful while building the project. A missing
kernel capability should be visible before a privileged capture begins, not
silently approximated afterward.

## Capturing a first packet

Here is a small ICMP capture:

```bash
sudo skbx capture --probe ip_rcv \
  --duration 10 \
  --output trace.jsonl \
  icmp
```

While it runs, create some traffic in another terminal:

```bash
ping -c 3 1.1.1.1
```

The capture is deliberately bounded. It has a finite duration and event limit
instead of assuming that an unbounded trace is safe.

After it finishes, replay does not require root:

```bash
skbx replay trace.jsonl
```

Replay summarizes the functions, processes, packet identities, route patterns,
consensus, outliers, and reliability state. Given the same valid JSONL input,
it produces a byte-identical summary.

If an event looks interesting, retrieve it with its surrounding same-packet
evidence:

```bash
skbx explain trace.jsonl event:<handle>
```

The repository includes a small contract fixture containing an `ip_rcv` event
followed by `kfree_skb_reason`. Replaying that fixture produces a route shaped
like this:

```json
{
  "handle": "route:1c0201e74424e253f8363577",
  "functions": [
    "ip_rcv",
    "kfree_skb_reason"
  ],
  "routes": 1,
  "truncated": false,
  "outlier": false
}
```

That output was generated by the current CLI from the checked-in test fixture;
it is not illustrative pseudodata.

## Use case: what happened to a website request?

This is the use case I keep returning to.

Suppose `curl` starts an HTTPS request and eventually times out. A capture on
the client can answer questions such as:

- Did the request enter the local TCP and IP output paths?
- Which interfaces and namespaces were associated with it?
- Was its mark changed?
- Did a TC or XDP program handle it?
- Was it transformed or placed into a tunnel?
- Did the local kernel report a drop?

That evidence can clear or implicate the client host.

It cannot prove what happened inside the ISP or on the target server. To prove
those parts, we need observations from those vantage points. That limitation
is important: the absence of a local drop is not proof that a remote host
received the packet.

The useful result is a smaller, evidence-backed search area:

```text
client host evidence
        ↓
observed departure boundary
        ↓
ISP / transit inference
        ↓
target-host evidence, if available
```

I would rather know exactly where my evidence ends than have a tool produce a
confident story about systems it could not observe.

## Use case: a packet disappears inside the host

“The network dropped it” can hide several very different failures.

A host may reject a packet through a normal kernel path. A TC classifier or
XDP program may return a drop action. A packet may be consumed during teardown.
A transformation may cause the packet we were following to continue under a
different kernel object.

For focused TCP drop questions, a small bpftrace program may be the fastest
answer. For packet contents, I still reach for tcpdump or Wireshark.

I reach for `skbx` when I do not yet know which local subsystem owns the
failure, or when I want to preserve the ordered path rather than one drop
event.

## Use case: follow transformations instead of losing the trail

Linux does not promise that one logical packet corresponds to one
`struct sk_buff` address for its entire lifetime.

Packets can be cloned, copied, or changed through copy-on-write. XDP frames can
later become SKBs. Tunnels introduce outer and inner packet identities.

`skbx` uses bounded, capture-local lineage state to connect those transitions.
The provenance remains explicit: an event records whether it matched the
original filter or was included because it belonged to a packet already being
tracked.

For example, a marked packet can be followed with:

```bash
sudo skbx capture \
  --filter-mark 0x2a \
  --filter-track-skb \
  --output trace.jsonl
```

The important word here is *capture-local*. A lineage identifier is not a
distributed trace ID, and it should not be presented as one.

## Use case: capture once, investigate without root

Loading and attaching eBPF programs is privileged work. Reading a JSONL file
does not need to be.

That makes a simple handoff possible:

1. An operator checks the plan and performs a bounded capture.
2. The capture ends and writes its reliability footer.
3. The artifact is copied to a normal development or analysis environment.
4. Another person replays it and cites exact `event:` or `route:` handles.

This is useful for incident handoffs and bug reports, but it is also useful for
learning. I can capture a small experiment once and inspect it repeatedly
without keeping probes attached while I try to understand the result.

## Use case: give an AI evidence instead of a mystery

One of my stranger motivations was making the CLI friendly to both operators
and software agents.

Before touching the host, an agent can ask the executable what it supports:

```bash
skbx describe --format json
skbx schema
skbx doctor --json
skbx plan --json
```

The native engine remains the source of truth. An AI system may summarize a
route or explain a captured event, but the event must already exist in the
trace. Machine output stays on standard output, diagnostics stay on standard
error, and unsupported capabilities remain explicit.

This does not make an AI explanation automatically correct. It gives the
explanation something concrete to cite and gives a human a way to check it.

## The engineering parts I enjoyed

The obvious fun was seeing packets move through functions I had previously
treated as boxes in a diagram.

The less obvious fun was designing the boundaries:

- discovering valid `struct sk_buff *` arguments from the target kernel's BTF
  instead of guessing from function names;
- keeping kernel-side state and work bounded;
- moving JSON encoding, symbolization, and filesystem work out of the eBPF hot
  path;
- making probe planning inspectable before attachment;
- separating raw observation from later explanation;
- treating partial output as incomplete instead of “probably good enough”;
- making replay deterministic enough to use in tests and automation.

Those constraints made the tool more interesting to build. They also gave me a
better mental model of what an observability tool can honestly claim.

## What it does not know

`skbx` only observes what the running kernel and selected probes expose.

It does not see inside an ISP. It does not see a remote host unless it runs
there too. It is not a packet-content replacement for Wireshark. Kernel
configuration, BTF availability, permissions, hidden addresses, unsupported
signatures, and capture loss can all limit the evidence.

Those limitations are part of the interface rather than footnotes.

I am still exploring where this project is most useful. The best next input is
not “looks cool,” although I will happily take that. It is a packet path the
tool cannot explain yet, together with the kernel version, exact command,
`doctor --json` output, and reliability footer.

The source, installation instructions, architecture notes, and field guides
are in the repository:

{% embed https://github.com/copyleftdev/skbx %}

If you try it, I would love to know which networking question you used it to
answer—and where its evidence stopped.

---

*AI-assistance disclosure: I built and tested `skbx`. I used OpenAI Codex to
research adjacent writing, challenge the article's positioning, edit this
draft, verify its commands and example output against the repository, and
generate the cover illustration. I reviewed the technical claims and remain
responsible for their accuracy.*

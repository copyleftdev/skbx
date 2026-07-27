# skbx contributor context

## Product contract

skbx is an agent-first Linux packet-path observer built with Rust and CO-RE
eBPF. Its native engine is the source of truth. AI may explain captured
evidence, but must never invent events, routes, capabilities, or reliability.

Preserve these invariants:

- deterministic, versioned machine-readable contracts;
- stable event and route handles;
- bounded kernel and userspace state;
- explicit reserve, recursion, read, decode, enrichment, and output loss;
- machine data on stdout and diagnostics on stderr;
- replay and evidence lookup without root;
- Rust 1.85 minimum supported version.

## Design context

The primary audience is Linux networking engineers, kernel/eBPF developers,
SREs, and platform engineers investigating packet-path failures. AI agents are
a secondary audience consuming deterministic commands and schemas.

The brand voice is forensic, kinetic, and kernel-native. Use exact vocabulary:
packet paths, kernel hooks, loss, replay, handles, bounded capture, schemas,
and verifier-safe behavior. Avoid generic AI marketing.

The website follows a “Packet Flight Recorder” direction. A packet is the
protagonist of a scroll-driven story through observation, capture, stable
handles, replay, and explanation. Motion must reveal causality, not decorate.
Use ink-dark tinted neutrals, phosphor chartreuse, and safety orange. Avoid
cyan/purple AI gradients, glassmorphism, generic card grids, gradient text, and
excessive rounded containers.

Honor reduced-motion preferences, preserve all content without JavaScript, and
keep mobile effects lightweight.

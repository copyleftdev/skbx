# Contributing to skbx

Thanks for helping make Linux packet paths easier to prove.

`skbx` sits on a sensitive boundary: kernel instrumentation on one side,
incident evidence on the other. We value small, reviewable changes; precise
claims; and tests that show what the kernel actually did.

## Start with evidence

Before opening a bug, collect:

```console
uname -a
skbx doctor --json
skbx describe --format json
skbx plan --json [the same selectors used for capture]
```

Include the exact command, the `capture_start` envelope, and the
`capture_end` reliability footer. If a trace is needed, prefer the smallest
reproduction and remove payload or endpoint data you cannot share. Do not
remove loss telemetry—it determines whether the observation is complete.

The structured issue forms will walk you through this.

## Ways to contribute

- reproduce an issue on another kernel or architecture;
- add a bounded live-kernel gate for a packet path;
- improve BTF compatibility without weakening preflight validation;
- make traceq evidence clearer for humans and agents;
- improve documentation, diagnostics, or community examples;
- propose a new observation surface with an explicit cost model.

For large features, open an observation request before investing in an
implementation. We can agree on the evidence contract, verifier bounds, and
kernel support window first.

## Development setup

You need Linux, Rust 1.85+, Clang/LLVM with the BPF backend, `bpftool`,
libelf, libpcap, and kernel BTF at `/sys/kernel/btf/vmlinux`.

On Ubuntu:

```console
sudo apt-get install "linux-tools-$(uname -r)" clang llvm libelf-dev libpcap-dev pkg-config
export PATH="/usr/lib/linux-tools/$(uname -r):$PATH"
```

On Debian:

```console
sudo apt-get install bpftool clang llvm libelf-dev libpcap-dev pkg-config
```

Then build:

```console
cargo build --locked
```

Run the repository gate before sending a change:

```console
make check
make build
```

The root-required tests under `scripts/live-*-test.sh` create isolated
network namespaces and remove them on exit. Run only the gates relevant to
your change on a disposable development host. The
[validation guide](docs/validation.md) maps features to live tests.

## Change design

Every observation feature should answer:

1. What exact kernel fact is captured?
2. How is the target validated before attachment?
3. What are the verifier and memory bounds?
4. How does a read, decode, reserve, or output failure become visible?
5. Which unit, contract, and live-kernel checks prove the behavior?
6. Does the traceq schema remain append-only and replay-compatible?

Please avoid unbounded maps, silent fallbacks, name-only attachment guesses,
and prose claims without executable evidence.

## Pull requests

- Keep commits focused and use an imperative subject.
- Explain the user-visible evidence change, not only the implementation.
- Link the issue or observation request.
- List the exact checks you ran.
- Call out kernel/version assumptions and any untested path.
- Update `docs/pwru-parity.md` only when the required evidence exists.

By contributing, you agree that your userspace contribution is licensed under
AGPL-3.0-or-later. Contributions to `bpf/` are GPL-2.0-only.

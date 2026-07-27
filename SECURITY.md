# Security policy

## Reporting a vulnerability

Please do not open a public issue for a vulnerability.

Use GitHub’s **Report a vulnerability** flow in the Security tab of
`copyleftdev/skbx`. Include:

- affected commit or version;
- kernel and architecture;
- required privileges and configuration;
- a minimal reproduction;
- expected and observed behavior;
- potential confidentiality, integrity, or availability impact;
- whether the issue affects capture, replay, trace parsing, or eBPF loading.

Avoid attaching sensitive production traces. A synthetic reproducer is
preferred.

You should receive an acknowledgment within seven days. We will coordinate
validation, remediation, and disclosure timing with the reporter.

## Scope

Security-sensitive areas include:

- privilege boundaries and file creation;
- probe target validation;
- eBPF verifier assumptions and bounded kernel reads;
- trace parsing and compressed/rotated input;
- path, namespace, and symbol handling;
- evidence integrity and loss reporting.

The current development branch is the supported line until tagged releases
are published. Historical snapshots are not maintained separately.

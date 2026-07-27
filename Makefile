.PHONY: check build benchmark live-tunnel live-netns live-stack live-stack-lifetime live-bpf-helper live-skb-replacement live-xdp-lineage

check:
	cargo fmt --all -- --check
	cargo test --workspace --all-features --locked --offline
	cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings

build:
	cargo build --release --locked --offline

benchmark:
	cargo test --release --locked --offline -p skbx-core replay_100k_events -- --ignored --nocapture

live-tunnel:
	cargo build --locked --offline
	sudo ./scripts/live-tunnel-test.sh target/debug/skbx

live-netns:
	cargo build --locked --offline
	sudo ./scripts/live-netns-test.sh target/debug/skbx

live-stack:
	cargo build --locked --offline
	sudo ./scripts/live-stack-test.sh target/debug/skbx

live-stack-lifetime:
	cargo build --locked --offline
	sudo ./scripts/live-stack-lifetime-test.sh target/debug/skbx

live-bpf-helper:
	cargo build --locked --offline
	sudo ./scripts/live-bpf-helper-test.sh target/debug/skbx

live-skb-replacement:
	cargo build --locked --offline
	sudo ./scripts/live-skb-replacement-test.sh target/debug/skbx

live-xdp-lineage:
	cargo build --locked --offline
	sudo ./scripts/live-xdp-lineage-test.sh target/debug/skbx

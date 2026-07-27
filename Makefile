.PHONY: check build benchmark live-tunnel live-netns live-stack live-stack-lifetime live-bpf-helper live-tc-program live-skb-replacement live-xdp-lineage live-metadata live-skb-filter live-btf-dump live-rotation

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

live-tc-program:
	cargo build --locked --offline
	sudo ./scripts/live-tc-program-test.sh target/debug/skbx

live-skb-replacement:
	cargo build --locked --offline
	sudo ./scripts/live-skb-replacement-test.sh target/debug/skbx

live-xdp-lineage:
	cargo build --locked --offline
	sudo ./scripts/live-xdp-lineage-test.sh target/debug/skbx

live-metadata:
	cargo build --locked --offline
	sudo ./scripts/live-metadata-test.sh target/debug/skbx

live-skb-filter:
	cargo build --locked --offline
	sudo ./scripts/live-skb-filter-test.sh target/debug/skbx

live-btf-dump:
	cargo build --locked --offline
	sudo ./scripts/live-btf-dump-test.sh target/debug/skbx

live-rotation:
	cargo build --locked --offline
	sudo ./scripts/live-rotation-test.sh target/debug/skbx

.PHONY: check build benchmark

check:
	cargo fmt --all -- --check
	cargo test --workspace --all-features --locked --offline
	cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings

build:
	cargo build --release --locked --offline

benchmark:
	cargo test --release --locked --offline -p skbx-core replay_100k_events -- --ignored --nocapture

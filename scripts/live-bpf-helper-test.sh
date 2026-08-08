#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-bpf-helper-test must run as root" >&2
    exit 2
fi
if [[ $(uname -m) != x86_64 ]]; then
    echo "live-bpf-helper-test requires x86_64 JIT decoding" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-bpf-helper.XXXXXX)
TRACE=${TEST_DIR}/trace.jsonl
READY=${TEST_DIR}/ready
OBJECT=${TEST_DIR}/helper-classifier.bpf.o
SUFFIX=$$
NS_A=skbxha${SUFFIX}
NS_B=skbxhb${SUFFIX}
DEV_A=shda${SUFFIX}
DEV_B=shdb${SUFFIX}
CAPTURE_PID=

cleanup() {
    if [[ -n ${CAPTURE_PID} ]] && kill -0 "${CAPTURE_PID}" 2>/dev/null; then
        kill "${CAPTURE_PID}" 2>/dev/null || true
        wait "${CAPTURE_PID}" 2>/dev/null || true
    fi
    ip netns del "${NS_A}" 2>/dev/null || true
    ip netns del "${NS_B}" 2>/dev/null || true
}
trap cleanup EXIT

clang -O2 -g -target bpf \
    -I crates/skbx-sensor/bpf/include \
    -I /usr/include/x86_64-linux-gnu \
    -c scripts/fixtures/helper-classifier.bpf.c \
    -o "${OBJECT}"

ip netns add "${NS_A}"
ip netns add "${NS_B}"
ip link add "${DEV_A}" type veth peer name "${DEV_B}"
ip link set "${DEV_A}" netns "${NS_A}"
ip link set "${DEV_B}" netns "${NS_B}"
ip -n "${NS_A}" addr add 10.244.1.1/24 dev "${DEV_A}"
ip -n "${NS_B}" addr add 10.244.1.2/24 dev "${DEV_B}"
ip -n "${NS_A}" link set lo up
ip -n "${NS_B}" link set lo up
ip -n "${NS_A}" link set "${DEV_A}" up
ip -n "${NS_B}" link set "${DEV_B}" up
ip netns exec "${NS_A}" tc qdisc add dev "${DEV_A}" clsact
ip netns exec "${NS_A}" tc filter add dev "${DEV_A}" egress \
    bpf direct-action object-file "${OBJECT}" section classifier

"${SKBX_BINARY}" capture \
    --probe tcf_classify \
    --filter-track-bpf-helpers \
    --output-skb-metadata 'skb->mark' \
    --output-skb-metadata 'skb->dev->ifindex' \
    --duration 4 \
    --max-events 512 \
    --ready-file "${READY}" \
    --output "${TRACE}" &
CAPTURE_PID=$!

for _ in $(seq 1 50); do
    [[ -e ${READY} ]] && break
    kill -0 "${CAPTURE_PID}" 2>/dev/null || break
    sleep 0.1
done
if [[ ! -e ${READY} ]]; then
    wait "${CAPTURE_PID}"
    echo "capture did not become ready" >&2
    exit 1
fi

ip netns exec "${NS_A}" ping -c 5 -W 1 10.244.1.2 >/dev/null
wait "${CAPTURE_PID}"
CAPTURE_PID=

jq -s -e '
    [.[] | select(.kind == "event")] as $events
    | any(
        range(0; ($events | length) - 1) as $i
        | ($events[$i]) as $direct
        | ($events[$i + 1]) as $helper
        | $direct.function.symbol == "tcf_classify"
        and $direct.association == "direct"
        and $helper.association == "stack"
        and ($helper.function.symbol | endswith("map_lookup_elem"))
        and $helper.bpf_map.operation == "lookup"
        and $helper.bpf_map.map_name == "packet_counts"
        and $helper.bpf_map.key_size == 4
        and $helper.bpf_map.value_size == 8
        and ($helper.bpf_map.key | startswith("0x"))
        and ($helper.bpf_map.read_errors | length) == 0
        and ($helper.metadata | length) == 2
        and ($helper.metadata | all(.read_error == null))
        and $helper.metadata[0].value.value == $helper.packet.mark
        and $helper.metadata[1].value.value == $helper.packet.ifindex
        and $direct.skb == $helper.skb
        and ($direct.packet.read_errors | length) == 0
        and ($helper.packet.read_errors | length) == 0
    )
' "${TRACE}" >/dev/null
jq -e '
    select(
        .kind == "event" and
        .bpf_map.operation == "update" and
        .bpf_map.map_name == "packet_counts" and
        .bpf_map.key_truncated == false and
        .bpf_map.value_truncated == false and
        (.bpf_map.value | startswith("0x")) and
        (.bpf_map.read_errors | length) == 0
    )
' "${TRACE}" >/dev/null
jq -e '
    select(
        .kind == "capture_end" and
        .events > 0 and
        .reliability.kernel_reserve_failures == 0 and
        .reliability.kernel_read_failures == 0 and
        .reliability.userspace_decode_failures == 0 and
        .reliability.userspace_enrichment_failures == 0 and
        .reliability.output_failures == 0 and
        # Helper tracking kprobes the map helpers that the tracer itself
        # calls, so any concurrent BPF hash activity anywhere on the host
        # re-enters the tracer and trips the kernel recursion guard. Those
        # misses are real missed observations and the footer is right to
        # report them, but they depend on what else is running rather than
        # on this code. They are the only incompleteness this gate accepts;
        # every other counter above stays strict.
        (.complete == true or .reliability.kernel_recursion_misses > 0)
    )
' "${TRACE}" >/dev/null

echo "live BPF-helper test passed: ${TRACE}"

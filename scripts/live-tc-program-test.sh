#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-tc-program-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-tc-program.XXXXXX)
TRACE=${TEST_DIR}/trace.jsonl
READY=${TEST_DIR}/ready
OBJECT=${TEST_DIR}/helper-classifier.bpf.o
SUFFIX=$$
NS_A=skbxta${SUFFIX}
NS_B=skbxtb${SUFFIX}
DEV_A=stda${SUFFIX}
DEV_B=stdb${SUFFIX}
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
    -I bpf/include \
    -I /usr/include/x86_64-linux-gnu \
    -c scripts/fixtures/helper-classifier.bpf.c \
    -o "${OBJECT}"

ip netns add "${NS_A}"
ip netns add "${NS_B}"
ip link add "${DEV_A}" type veth peer name "${DEV_B}"
ip link set "${DEV_A}" netns "${NS_A}"
ip link set "${DEV_B}" netns "${NS_B}"
ip -n "${NS_A}" addr add 10.249.1.1/24 dev "${DEV_A}"
ip -n "${NS_B}" addr add 10.249.1.2/24 dev "${DEV_B}"
ip -n "${NS_A}" link set lo up
ip -n "${NS_B}" link set lo up
ip -n "${NS_A}" link set "${DEV_A}" up
ip -n "${NS_B}" link set "${DEV_B}" up
ip netns exec "${NS_A}" tc qdisc add dev "${DEV_A}" clsact
ip netns exec "${NS_A}" tc filter add dev "${DEV_A}" egress \
    bpf direct-action object-file "${OBJECT}" section classifier

"${SKBX_BINARY}" capture \
    --probe tcf_classify \
    --filter-trace-tc \
    --output-skb-metadata 'skb->mark' \
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

ip netns exec "${NS_A}" ping -c 5 -W 1 10.249.1.2 >/dev/null
wait "${CAPTURE_PID}"
CAPTURE_PID=

jq -e '
    select(.kind == "capture_start") |
    (.bpf_programs | length) >= 1 and
    any(
        .bpf_programs[];
        .id > 0 and
        .kind == "tc" and
        .name == "helper_classifi" and
        .entry == "helper_classifier"
    )
' "${TRACE}" >/dev/null

jq -e '
    select(.kind == "event" and .bpf_program.kind == "tc") |
    .bpf_program.id > 0 and
    .bpf_program.name == "helper_classifi" and
    .bpf_program.entry == "helper_classifier" and
    .function.address == "0x0" and
    .association == "direct" and
    (.metadata | length) == 1 and
    .metadata[0].expression == "skb->mark" and
    .metadata[0].read_error == null and
    .metadata[0].value.value == .packet.mark and
    (.packet.read_errors | length) == 0
' "${TRACE}" >/dev/null

jq -e '
    select(
        .kind == "capture_end" and
        .complete == true and
        .events > 0 and
        .reliability.kernel_reserve_failures == 0 and
        .reliability.kernel_read_failures == 0 and
        .reliability.userspace_decode_failures == 0
    )
' "${TRACE}" >/dev/null

echo "live TC-program test passed: ${TRACE}"

#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-xdp-program-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-xdp-program.XXXXXX)
TRACE=${TEST_DIR}/trace.jsonl
READY=${TEST_DIR}/ready
OBJECT=${TEST_DIR}/xdp-pass.bpf.o
SUFFIX=$$
NS_A=skbxza${SUFFIX}
NS_B=skbxzb${SUFFIX}
DEV_A=szda${SUFFIX}
DEV_B=szdb${SUFFIX}
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

ARCH_INCLUDE=/usr/include/$(uname -m)-linux-gnu
clang -O2 -g -target bpf \
    -I bpf/include \
    -I "${ARCH_INCLUDE}" \
    -c scripts/fixtures/xdp-pass.bpf.c \
    -o "${OBJECT}"

ip netns add "${NS_A}"
ip netns add "${NS_B}"
ip link add "${DEV_A}" type veth peer name "${DEV_B}"
ip link set "${DEV_A}" netns "${NS_A}"
ip link set "${DEV_B}" netns "${NS_B}"
ip -n "${NS_A}" addr add 10.250.1.1/24 dev "${DEV_A}"
ip -n "${NS_B}" addr add 10.250.1.2/24 dev "${DEV_B}"
ip -n "${NS_A}" link set lo up
ip -n "${NS_B}" link set lo up
ip -n "${NS_A}" link set "${DEV_A}" up
ip -n "${NS_B}" link set "${DEV_B}" up
ip netns exec "${NS_B}" ip link set dev "${DEV_B}" \
    xdp object-file "${OBJECT}" section xdp

"${SKBX_BINARY}" capture \
    --filter-trace-xdp \
    --filter-netns "/var/run/netns/${NS_B}" \
    --filter-ifname "${DEV_B}" \
    --output-xdp-metadata 'xdp->frame_sz' \
    --output-xdp-metadata 'xdp->rxq->dev->ifindex' \
    --duration 4 \
    --max-events 512 \
    --ready-file "${READY}" \
    --output "${TRACE}" \
    icmp &
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

ip netns exec "${NS_A}" ping -c 5 -W 1 10.250.1.2 >/dev/null
wait "${CAPTURE_PID}"
CAPTURE_PID=

jq -e '
    select(.kind == "capture_start") |
    any(
        .bpf_programs[];
        .id > 0 and
        .kind == "xdp" and
        .name == "xdp_pass" and
        .entry == "xdp_pass"
    ) and
    [.metadata_projections[].expression] == [
        "xdp->frame_sz",
        "xdp->rxq->dev->ifindex"
    ]
' "${TRACE}" >/dev/null

jq -e '
    select(.kind == "event" and .bpf_program.kind == "xdp") |
    .bpf_program.id > 0 and
    .bpf_program.name == "xdp_pass" and
    .bpf_program.entry == "xdp_pass" and
    .bpf_program_phase == "entry" and
    .function.address == "0x0" and
    .association == "direct" and
    .packet.protocol == 2048 and
    .packet.ifindex > 0 and
    .packet.netns > 0 and
    .packet.mtu == 1500 and
    (.packet.read_errors | length) == 0 and
    .tuple.destination == "10.250.1.2" and
    .tuple.l4_protocol == 1 and
    (.metadata | length) == 2 and
    (.metadata | all(.read_error == null)) and
    .metadata[0].expression == "xdp->frame_sz" and
    .metadata[0].value.value > 0 and
    .metadata[1].expression == "xdp->rxq->dev->ifindex" and
    .metadata[1].value.value == .packet.ifindex
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

echo "live XDP-program test passed: ${TRACE}"

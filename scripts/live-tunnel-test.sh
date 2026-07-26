#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-tunnel-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
NS_A=skbx-vx-a
NS_B=skbx-vx-b
UNDER_A=skbx-under-a
UNDER_B=skbx-under-b
VXLAN=skbx-vxlan
TEST_DIR=$(mktemp -d /tmp/skbx-live-tunnel.XXXXXX)
TRACE=${TEST_DIR}/trace.jsonl
READY=${TEST_DIR}/ready
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

if ip netns list | awk '{print $1}' | grep -Fxq "${NS_A}" ||
   ip netns list | awk '{print $1}' | grep -Fxq "${NS_B}"; then
    echo "refusing to replace existing ${NS_A} or ${NS_B} namespace" >&2
    exit 2
fi

modprobe vxlan
ip netns add "${NS_A}"
ip netns add "${NS_B}"
ip link add "${UNDER_A}" type veth peer name "${UNDER_B}"
ip link set "${UNDER_A}" netns "${NS_A}"
ip link set "${UNDER_B}" netns "${NS_B}"

ip -n "${NS_A}" link set lo up
ip -n "${NS_B}" link set lo up
ip -n "${NS_A}" address add 192.0.2.1/24 dev "${UNDER_A}"
ip -n "${NS_B}" address add 192.0.2.2/24 dev "${UNDER_B}"
ip -n "${NS_A}" link set "${UNDER_A}" up
ip -n "${NS_B}" link set "${UNDER_B}" up

ip -n "${NS_A}" link add "${VXLAN}" type vxlan id 42 \
    local 192.0.2.1 remote 192.0.2.2 dstport 4789 dev "${UNDER_A}"
ip -n "${NS_B}" link add "${VXLAN}" type vxlan id 42 \
    local 192.0.2.2 remote 192.0.2.1 dstport 4789 dev "${UNDER_B}"
ip -n "${NS_A}" address add 10.42.0.1/24 dev "${VXLAN}"
ip -n "${NS_B}" address add 10.42.0.2/24 dev "${VXLAN}"
ip -n "${NS_A}" link set "${VXLAN}" up
ip -n "${NS_B}" link set "${VXLAN}" up

"${SKBX_BINARY}" capture \
    --probe ip_local_out \
    --duration 5 \
    --max-events 64 \
    --output-tunnel \
    --filter-tunnel-pcap-l2 "ether proto 0x0800" \
    --filter-tunnel-pcap-l3 "icmp and dst host 10.42.0.2" \
    --ready-file "${READY}" \
    --output "${TRACE}" \
    "udp port 4789" &
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

ip netns exec "${NS_A}" ping -c 2 -W 1 10.42.0.2
wait "${CAPTURE_PID}"
CAPTURE_PID=

jq -e '
    select(
        .kind == "event" and
        .tuple.source == "192.0.2.1" and
        .tuple.destination == "192.0.2.2" and
        .tuple.destination_port == 4789 and
        .tunnel_tuple.source == "10.42.0.1" and
        .tunnel_tuple.destination == "10.42.0.2" and
        .tunnel_tuple.l4_protocol == 1 and
        .tunnel_tuple.icmp_type == 8 and
        (.packet.read_errors | length) == 0
    )
' "${TRACE}" >/dev/null
jq -e '
    select(
        .kind == "capture_end" and
        .complete == true and
        .events > 0 and
        .reliability.kernel_read_failures == 0 and
        .reliability.kernel_reserve_failures == 0
    )
' "${TRACE}" >/dev/null

echo "live tunnel test passed: ${TRACE}"

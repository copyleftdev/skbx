#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-netns-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
NS_A=skbx-net-a
NS_B=skbx-net-b
LINK_A=skbx-link-a
LINK_B=skbx-link-b
TEST_DIR=$(mktemp -d /tmp/skbx-live-netns.XXXXXX)
TRACE_IFACE=${TEST_DIR}/interface.jsonl
TRACE_SOCKET=${TEST_DIR}/socket.jsonl
READY_IFACE=${TEST_DIR}/ready-interface
READY_SOCKET=${TEST_DIR}/ready-socket
READY=
CAPTURE_PID=
LISTENER_PID=

cleanup() {
    if [[ -n ${CAPTURE_PID} ]] && kill -0 "${CAPTURE_PID}" 2>/dev/null; then
        kill "${CAPTURE_PID}" 2>/dev/null || true
        wait "${CAPTURE_PID}" 2>/dev/null || true
    fi
    if [[ -n ${LISTENER_PID} ]] && kill -0 "${LISTENER_PID}" 2>/dev/null; then
        kill "${LISTENER_PID}" 2>/dev/null || true
        wait "${LISTENER_PID}" 2>/dev/null || true
    fi
    ip netns del "${NS_A}" 2>/dev/null || true
    ip netns del "${NS_B}" 2>/dev/null || true
}
trap cleanup EXIT

wait_ready() {
    for _ in $(seq 1 50); do
        [[ -e ${READY} ]] && return
        kill -0 "${CAPTURE_PID}" 2>/dev/null || break
        sleep 0.1
    done
    wait "${CAPTURE_PID}"
    echo "capture did not become ready" >&2
    exit 1
}

if ip netns list | awk '{print $1}' | grep -Fxq "${NS_A}" ||
   ip netns list | awk '{print $1}' | grep -Fxq "${NS_B}"; then
    echo "refusing to replace existing ${NS_A} or ${NS_B} namespace" >&2
    exit 2
fi

ip netns add "${NS_A}"
ip netns add "${NS_B}"
ip link add "${LINK_A}" type veth peer name "${LINK_B}"
ip link set "${LINK_A}" netns "${NS_A}"
ip link set "${LINK_B}" netns "${NS_B}"
ip -n "${NS_A}" link set lo up
ip -n "${NS_B}" link set lo up
ip -n "${NS_A}" address add 198.18.0.1/24 dev "${LINK_A}"
ip -n "${NS_B}" address add 198.18.0.2/24 dev "${LINK_B}"
ip -n "${NS_A}" link set "${LINK_A}" up
ip -n "${NS_B}" link set "${LINK_B}" up

NETNS_PATH=/run/netns/${NS_A}
NETNS_INODE=$(stat -Lc %i "${NETNS_PATH}")

"${SKBX_BINARY}" capture \
    --probe ip_rcv \
    --filter-netns "${NETNS_PATH}" \
    --filter-ifname "${LINK_A}" \
    --duration 3 \
    --max-events 32 \
    --ready-file "${READY_IFACE}" \
    --output "${TRACE_IFACE}" &
CAPTURE_PID=$!
READY=${READY_IFACE}
wait_ready
ip netns exec "${NS_B}" ping -c 2 -W 1 198.18.0.1
wait "${CAPTURE_PID}"
CAPTURE_PID=

jq -e --argjson netns "${NETNS_INODE}" '
    select(
        .kind == "event" and
        .packet.netns == $netns and
        .packet.ifindex > 0 and
        .tuple.destination == "198.18.0.1" and
        (.packet.read_errors | length) == 0
    )
' "${TRACE_IFACE}" >/dev/null
jq -e '
    select(
        .kind == "capture_end" and
        .complete == true and
        .events > 0 and
        .reliability.kernel_read_failures == 0
    )
' "${TRACE_IFACE}" >/dev/null

ip netns exec "${NS_A}" nc -l -p 18080 </dev/null &
LISTENER_PID=$!
"${SKBX_BINARY}" capture \
    --probe tcp_v4_send_check \
    --filter-netns "${NETNS_PATH}" \
    --duration 3 \
    --max-events 32 \
    --ready-file "${READY_SOCKET}" \
    --output "${TRACE_SOCKET}" &
CAPTURE_PID=$!
READY=${READY_SOCKET}
wait_ready
ip netns exec "${NS_B}" nc -z -w 1 198.18.0.1 18080
wait "${CAPTURE_PID}"
CAPTURE_PID=
wait "${LISTENER_PID}" || true
LISTENER_PID=

jq -e --argjson netns "${NETNS_INODE}" '
    select(
        .kind == "event" and
        .packet.netns == $netns and
        .packet.ifindex == 0 and
        (.packet.read_errors | length) == 0
    )
' "${TRACE_SOCKET}" >/dev/null
jq -e '
    select(
        .kind == "capture_end" and
        .complete == true and
        .events > 0 and
        .reliability.kernel_read_failures == 0
    )
' "${TRACE_SOCKET}" >/dev/null

echo "live namespace test passed: ${TEST_DIR}"

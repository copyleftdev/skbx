#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-skb-filter-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-skb-filter.XXXXXX)
TRACE=${TEST_DIR}/trace.jsonl
READY=${TEST_DIR}/ready
SUFFIX=$$
NS_A=skbxfa${SUFFIX}
NS_B=skbxfb${SUFFIX}
DEV_A=sfda${SUFFIX}
DEV_B=sfdb${SUFFIX}
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

ip netns add "${NS_A}"
ip netns add "${NS_B}"
ip link add "${DEV_A}" type veth peer name "${DEV_B}"
ip link set "${DEV_A}" netns "${NS_A}"
ip link set "${DEV_B}" netns "${NS_B}"
ip -n "${NS_A}" addr add 10.246.1.1/24 dev "${DEV_A}"
ip -n "${NS_B}" addr add 10.246.1.2/24 dev "${DEV_B}"
ip -n "${NS_A}" link set lo up
ip -n "${NS_B}" link set lo up
ip -n "${NS_A}" link set "${DEV_A}" up
ip -n "${NS_B}" link set "${DEV_B}" up
ip netns exec "${NS_A}" tc qdisc add dev "${DEV_A}" clsact

"${SKBX_BINARY}" capture \
    --probe ip_rcv \
    --duration 4 \
    --max-events 64 \
    --filter-netns "/var/run/netns/${NS_A}" \
    --filter-ifname "${DEV_A}" \
    --filter-skb-expr 'skb->mark = 0b101010 && skb->pkt_type = 0 && skb->protocol = 0x0800 && skb->dev->ifindex > 0' \
    --output-skb-metadata 'skb->mark' \
    --output-skb-metadata 'skb->pkt_type' \
    --output-skb-metadata 'skb->dev->ifindex' \
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

ip netns exec "${NS_B}" ping -c 2 -W 1 10.246.1.1 >/dev/null
ip netns exec "${NS_A}" tc filter add dev "${DEV_A}" ingress \
    protocol all pref 1 matchall action skbedit mark 42
ip netns exec "${NS_B}" ping -c 3 -W 1 10.246.1.1 >/dev/null
wait "${CAPTURE_PID}"
CAPTURE_PID=

jq -s -e '
    (map(select(.kind == "capture_start")) | length == 1) and
    (map(select(.kind == "capture_start"))[0].filters.skb_expression ==
        "skb->mark = 0b101010 && skb->pkt_type = 0 && skb->protocol = 0x0800 && skb->dev->ifindex > 0") and
    ([.[] | select(.kind == "event")] | length > 0) and
    ([.[] | select(.kind == "event")] | all(
        .packet.mark == 42 and (
            (.metadata | map({key: .expression, value: .}) | from_entries) as $metadata |
            ($metadata["skb->mark"].read_error == null) and
            ($metadata["skb->mark"].value.value == 42) and
            ($metadata["skb->pkt_type"].read_error == null) and
            ($metadata["skb->pkt_type"].value.value == 0) and
            ($metadata["skb->dev->ifindex"].read_error == null) and
            ($metadata["skb->dev->ifindex"].value.value > 0)
        )
    )) and
    (map(select(.kind == "capture_end"))[0] |
        .complete == true and
        .events > 0 and
        .reliability.kernel_filtered_events > 0 and
        .reliability.kernel_reserve_failures == 0 and
        .reliability.kernel_read_failures == 0 and
        .reliability.userspace_decode_failures == 0)
' "${TRACE}" >/dev/null

echo "live SKB filter test passed: ${TRACE}"

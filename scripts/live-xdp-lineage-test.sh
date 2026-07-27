#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-xdp-lineage-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-xdp-lineage.XXXXXX)
TRACE=${TEST_DIR}/trace.jsonl
READY=${TEST_DIR}/ready
PASS_OBJECT=${TEST_DIR}/xdp-pass.bpf.o
TX_OBJECT=${TEST_DIR}/xdp-tx.bpf.o
SUFFIX=$$
NS_A=skbxya${SUFFIX}
NS_B=skbyb${SUFFIX}
DEV_A=syva${SUFFIX}
DEV_B=syvb${SUFFIX}
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
ip -n "${NS_A}" addr add 10.247.1.1/24 dev "${DEV_A}"
ip -n "${NS_B}" addr add 10.247.1.2/24 dev "${DEV_B}"
ip -n "${NS_A}" link set lo up
ip -n "${NS_B}" link set lo up
ip -n "${NS_A}" link set "${DEV_A}" up
ip -n "${NS_B}" link set "${DEV_B}" up

DESTINATION_MAC=$(
    ip -n "${NS_B}" -o link show dev "${DEV_B}" |
        sed -n 's/.*link\/ether \([^ ]*\).*/\1/p'
)
ip -n "${NS_A}" neigh replace 10.247.1.2 lladdr "${DESTINATION_MAC}" \
    nud permanent dev "${DEV_A}"

ARCH_INCLUDE=/usr/include/$(uname -m)-linux-gnu
clang -O2 -g -target bpf \
    -I crates/skbx-sensor/bpf/include \
    -I "${ARCH_INCLUDE}" \
    -c scripts/fixtures/xdp-pass.bpf.c \
    -o "${PASS_OBJECT}"
clang -O2 -g -target bpf \
    -I crates/skbx-sensor/bpf/include \
    -I "${ARCH_INCLUDE}" \
    -c scripts/fixtures/xdp-tx.bpf.c \
    -o "${TX_OBJECT}"

# The far end transmits the XDP frame back; the near end passes it and veth
# allocates a new SKB around the same data head.
ip netns exec "${NS_A}" ip link set dev "${DEV_A}" \
    xdp object-file "${PASS_OBJECT}" section xdp
ip netns exec "${NS_B}" ip link set dev "${DEV_B}" \
    xdp object-file "${TX_OBJECT}" section xdp

"${SKBX_BINARY}" capture \
    --probe __dev_queue_xmit \
    --probe veth_xdp_rcv_skb \
    --probe dev_gro_receive \
    --kmods veth \
    --filter-netns "/var/run/netns/${NS_A}" \
    --filter-ifname "${DEV_A}" \
    --filter-track-skb \
    --duration 5 \
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

# XDP_TX reflects the request instead of answering it, so ping success is not
# required; the trace assertions below are the outcome gate.
ip netns exec "${NS_A}" ping -c 5 -W 1 10.247.1.2 >/dev/null 2>&1 || true
wait "${CAPTURE_PID}"
CAPTURE_PID=

jq -s -e '
    [.[] | select(.kind == "event")] as $events
    | any(
        range(0; ($events | length) - 2) as $i
        | ($events[$i]) as $original
        | ($events[$i + 1]) as $before_xdp
        | ($events[$i + 2]) as $after_xdp
        | $original.function.symbol == "__dev_queue_xmit"
        and $original.match_origin == "filter"
        and $before_xdp.function.symbol == "veth_xdp_rcv_skb"
        and $before_xdp.match_origin == "tracked_skb"
        and $after_xdp.function.symbol == "dev_gro_receive"
        and $after_xdp.match_origin == "tracked_xdp"
        and $original.identity == $before_xdp.identity
        and $original.identity == $after_xdp.identity
        and $before_xdp.skb != $after_xdp.skb
        and ($original.packet.read_errors | length) == 0
        and ($before_xdp.packet.read_errors | length) == 0
        and ($after_xdp.packet.read_errors | length) == 0
    )
' "${TRACE}" >/dev/null
jq -e '
    select(
        .kind == "capture_end" and
        .complete == true and
        .events > 0 and
        .reliability.kernel_reserve_failures == 0 and
        .reliability.userspace_decode_failures == 0
    )
' "${TRACE}" >/dev/null

echo "live XDP-lineage test passed: ${TRACE}"

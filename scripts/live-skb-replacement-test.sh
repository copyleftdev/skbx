#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-skb-replacement-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-skb-replacement.XXXXXX)
TRACE=${TEST_DIR}/trace.jsonl
READY=${TEST_DIR}/ready
XDP_OBJECT=${TEST_DIR}/xdp-pass.bpf.o
CLONE_OBJECT=${TEST_DIR}/clone-redirect.bpf.o
SUFFIX=$$
NS_A=skbxca${SUFFIX}
NS_B=skbxcb${SUFFIX}
DEV_A=scva${SUFFIX}
DEV_B=scvb${SUFFIX}
DUMMY=scd${SUFFIX}
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
ip -n "${NS_A}" link add "${DUMMY}" type dummy
ip -n "${NS_A}" addr add 10.246.1.1/24 dev "${DUMMY}"
ip -n "${NS_B}" addr add 10.246.1.2/24 dev "${DEV_B}"
ip -n "${NS_A}" link set lo up
ip -n "${NS_B}" link set lo up
ip -n "${NS_A}" link set "${DUMMY}" up
ip -n "${NS_A}" link set "${DEV_A}" up
ip -n "${NS_B}" link set "${DEV_B}" up

DESTINATION_MAC=$(
    ip -n "${NS_B}" -o link show dev "${DEV_B}" |
        sed -n 's/.*link\/ether \([^ ]*\).*/\1/p'
)
TARGET_IFINDEX=$(
    ip -n "${NS_A}" -o link show dev "${DEV_A}" |
        cut -d: -f1 |
        tr -d ' '
)
ip -n "${NS_A}" neigh add 10.246.1.2 lladdr "${DESTINATION_MAC}" \
    nud permanent dev "${DUMMY}"

ARCH_INCLUDE=/usr/include/$(uname -m)-linux-gnu
clang -O2 -g -target bpf \
    -I bpf/include \
    -I "${ARCH_INCLUDE}" \
    -c scripts/fixtures/xdp-pass.bpf.c \
    -o "${XDP_OBJECT}"
clang -O2 -g -target bpf \
    -I bpf/include \
    -I "${ARCH_INCLUDE}" \
    -DTARGET_IFINDEX="${TARGET_IFINDEX}" \
    -c scripts/fixtures/clone-redirect.bpf.c \
    -o "${CLONE_OBJECT}"

ip netns exec "${NS_B}" ip link set dev "${DEV_B}" \
    xdp object-file "${XDP_OBJECT}" section xdp
ip netns exec "${NS_A}" tc qdisc add dev "${DUMMY}" clsact
ip netns exec "${NS_A}" tc filter add dev "${DUMMY}" egress \
    bpf direct-action object-file "${CLONE_OBJECT}" section classifier

"${SKBX_BINARY}" capture \
    --probe __dev_queue_xmit \
    --probe veth_xdp_rcv_skb \
    --probe dev_gro_receive \
    --kmods veth \
    --filter-netns "/var/run/netns/${NS_A}" \
    --filter-ifname "${DUMMY}" \
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

# The classifier clones each packet to the veth and drops the original, so
# ping is expected to report a local send failure even though the clone is
# delivered and observed.
ip netns exec "${NS_A}" ping -c 5 -W 1 10.246.1.2 >/dev/null 2>&1 || true
wait "${CAPTURE_PID}"
CAPTURE_PID=

jq -e '
    select(
        .kind == "capture_start" and
        (.identity_hooks | index("skb_pp_cow_data")) != null
    )
' "${TRACE}" >/dev/null
jq -s -e '
    [.[] | select(.kind == "event")] as $events
    | any(
        range(0; ($events | length) - 3) as $i
        | ($events[$i]) as $original
        | ($events[$i + 1]) as $clone
        | ($events[$i + 2]) as $before_cow
        | ($events[$i + 3]) as $after_cow
        | $original.function.symbol == "__dev_queue_xmit"
        and $original.match_origin == "filter"
        and $clone.function.symbol == "__dev_queue_xmit"
        and $clone.match_origin == "tracked_skb"
        and $before_cow.function.symbol == "veth_xdp_rcv_skb"
        and $before_cow.match_origin == "tracked_skb"
        and $after_cow.function.symbol == "dev_gro_receive"
        and $after_cow.match_origin == "tracked_skb"
        and $original.identity == $clone.identity
        and $original.identity == $before_cow.identity
        and $original.identity == $after_cow.identity
        and $original.identity != $original.skb
        and $original.skb != $clone.skb
        and $before_cow.skb == $clone.skb
        and $after_cow.skb != $before_cow.skb
        and ($original.packet.read_errors | length) == 0
        and ($clone.packet.read_errors | length) == 0
        and ($before_cow.packet.read_errors | length) == 0
        and ($after_cow.packet.read_errors | length) == 0
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

echo "live SKB-replacement test passed: ${TRACE}"

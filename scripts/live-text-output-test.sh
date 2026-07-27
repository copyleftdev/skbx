#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-text-output-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-text-output.XXXXXX)
EXPANDED=${TEST_DIR}/expanded.txt
COMPACT=${TEST_DIR}/compact.txt
READY_EXPANDED=${TEST_DIR}/ready-expanded
READY_COMPACT=${TEST_DIR}/ready-compact
SUFFIX=$$
NS_A=skbxtxta${SUFFIX}
NS_B=skbxtxtb${SUFFIX}
DEV_A=stxta${SUFFIX}
DEV_B=stxtb${SUFFIX}
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
ip -n "${NS_A}" addr add 10.245.1.1/24 dev "${DEV_A}"
ip -n "${NS_B}" addr add 10.245.1.2/24 dev "${DEV_B}"
ip -n "${NS_A}" link set lo up
ip -n "${NS_B}" link set lo up
ip -n "${NS_A}" link set "${DEV_A}" up
ip -n "${NS_B}" link set "${DEV_B}" up

"${SKBX_BINARY}" capture \
    --probe ip_rcv \
    --filter-netns "/var/run/netns/${NS_A}" \
    --filter-ifname "${DEV_A}" \
    --format text \
    --output-caller \
    --output-skb-cb \
    --output-tcp-flags \
    --output-netns-names \
    --netns-names-max-length 16 \
    --duration 4 \
    --max-events 32 \
    --ready-file "${READY_EXPANDED}" \
    --output "${EXPANDED}" &
CAPTURE_PID=$!

for _ in $(seq 1 50); do
    [[ -e ${READY_EXPANDED} ]] && break
    kill -0 "${CAPTURE_PID}" 2>/dev/null || break
    sleep 0.1
done
if [[ ! -e ${READY_EXPANDED} ]]; then
    wait "${CAPTURE_PID}"
    echo "expanded text capture did not become ready" >&2
    exit 1
fi

ip netns exec "${NS_B}" ping -c 3 -W 1 10.245.1.1 >/dev/null
wait "${CAPTURE_PID}"
CAPTURE_PID=

EXPANDED_HEADER=$(sed -n '2p' "${EXPANDED}")
[[ ${EXPANDED_HEADER} == *"NETNS NAME"* ]]
[[ ${EXPANDED_HEADER} == *"TUPLE"* ]]
[[ ${EXPANDED_HEADER} == *"FUNCTION CALLER"* ]]
grep -Eq "${NS_A}.*icmp:8/0.*direct.*filter.*ip_rcv.*[[:alnum:]_]" "${EXPANDED}"
grep -Eq '^  CB \[0x[0-9a-f]{8},' "${EXPANDED}"
grep -Eq 'capture_end events=[1-9][0-9]* complete=true reserve_failures=0 recursion_misses=0 decode_failures=0' "${EXPANDED}"

"${SKBX_BINARY}" capture \
    --probe ip_rcv \
    --filter-netns "/var/run/netns/${NS_A}" \
    --filter-ifname "${DEV_A}" \
    --format text \
    --output-meta=false \
    --output-tuple=false \
    --duration 4 \
    --max-events 32 \
    --ready-file "${READY_COMPACT}" \
    --output "${COMPACT}" &
CAPTURE_PID=$!

for _ in $(seq 1 50); do
    [[ -e ${READY_COMPACT} ]] && break
    kill -0 "${CAPTURE_PID}" 2>/dev/null || break
    sleep 0.1
done
if [[ ! -e ${READY_COMPACT} ]]; then
    wait "${CAPTURE_PID}"
    echo "compact text capture did not become ready" >&2
    exit 1
fi

ip netns exec "${NS_B}" ping -c 3 -W 1 10.245.1.1 >/dev/null
wait "${CAPTURE_PID}"
CAPTURE_PID=

COMPACT_HEADER=$(sed -n '2p' "${COMPACT}")
[[ ${COMPACT_HEADER} == *"SKB"* ]]
[[ ${COMPACT_HEADER} == *"ASSOC"* ]]
[[ ${COMPACT_HEADER} != *"NETNS"* ]]
[[ ${COMPACT_HEADER} != *"TUPLE"* ]]
grep -Eq 'direct.*filter.*ip_rcv' "${COMPACT}"
grep -Eq 'capture_end events=[1-9][0-9]* complete=true reserve_failures=0 recursion_misses=0 decode_failures=0' "${COMPACT}"

echo "live text-output test passed: ${TEST_DIR}"

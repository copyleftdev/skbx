#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-btf-dump-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-btf-dump.XXXXXX)
TRACE=${TEST_DIR}/trace.jsonl
READY=${TEST_DIR}/ready
SUFFIX=$$
NS_A=skbxda${SUFFIX}
NS_B=skbxdb${SUFFIX}
DEV_A=sdda${SUFFIX}
DEV_B=sddb${SUFFIX}
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

"${SKBX_BINARY}" capture \
    --probe ip_rcv \
    --duration 3 \
    --max-events 16 \
    --filter-netns "/var/run/netns/${NS_A}" \
    --filter-ifname "${DEV_A}" \
    --output-skb \
    --output-skb-shared-info \
    --output-skb-metadata 'skb->mark' \
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

ip netns exec "${NS_B}" ping -c 3 -W 1 10.247.1.1 >/dev/null
wait "${CAPTURE_PID}"
CAPTURE_PID=

jq -s -e '
    (map(select(.kind == "capture_start"))[0] |
        .btf_dump_types == ["sk_buff", "skb_shared_info"]) and
    ([.[] | select(.kind == "event")] | length > 0) and
    ([.[] | select(.kind == "event")] | all(
        (.metadata | length) == 1 and
        (.btf_dumps | length) == 2 and
        (.btf_dumps | all(
            .rendered != null and
            (.rendered | length) > 0 and
            .bytes_required > 0 and
            .bytes_captured > 0 and
            .read_error == null
        ))
    )) and
    (map(select(.kind == "capture_end"))[0] |
        .complete == true and
        .events > 0 and
        .reliability.kernel_reserve_failures == 0 and
        .reliability.kernel_read_failures == 0 and
        .reliability.userspace_decode_failures == 0)
' "${TRACE}" >/dev/null

echo "live BTF dump test passed: ${TRACE}"

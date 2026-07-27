#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-rotation-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-rotation.XXXXXX)
TRACE=${TEST_DIR}/trace.jsonl
READY=${TEST_DIR}/ready
SUFFIX=$$
NS_A=skbxra${SUFFIX}
NS_B=skbxrb${SUFFIX}
DEV_A=srda${SUFFIX}
DEV_B=srdb${SUFFIX}
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

"${SKBX_BINARY}" capture \
    --probe ip_rcv \
    --duration 5 \
    --max-events 400 \
    --output-max-bytes 65536 \
    --output-max-backups 2 \
    --output-compress \
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

ip netns exec "${NS_B}" ping -c 220 -i 0.005 -W 1 10.246.1.1 >/dev/null
wait "${CAPTURE_PID}"
CAPTURE_PID=

[[ -f ${TRACE} ]]
[[ -f ${TRACE}.1.gz ]]
[[ -f ${TRACE}.2.gz ]]
[[ ! -e ${TRACE}.3 ]]
[[ ! -e ${TRACE}.3.gz ]]
[[ $(stat -Lc %s "${TRACE}") -le 65536 ]]

"${SKBX_BINARY}" replay "${TRACE}" --format json |
    jq -e '
        .complete == true and
        .events > 0 and
        .segment.index >= 2
    ' >/dev/null
for suffix in 1 2; do
    segment=${TEST_DIR}/segment-${suffix}.jsonl
    gzip -cd "${TRACE}.${suffix}.gz" >"${segment}"
    [[ $(stat -Lc %s "${segment}") -le 65536 ]]
    "${SKBX_BINARY}" replay "${TRACE}.${suffix}.gz" --format json |
        jq -e '
            .complete == true and
            .events > 0 and
            .segment.index >= 0 and
            .stop_reason == "rotation"
        ' >/dev/null
    handle=$(jq -s -r 'map(select(.kind == "event"))[0].handle' "${segment}")
    "${SKBX_BINARY}" explain "${TRACE}.${suffix}.gz" "${handle}" |
        jq -e --arg handle "${handle}" '
            .target.handle == $handle and
            (.same_skb_evidence | length) > 0
        ' >/dev/null
done

echo "live rotation test passed: ${TEST_DIR}"

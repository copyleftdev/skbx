#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-metadata-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-metadata.XXXXXX)
TRACE=${TEST_DIR}/trace.jsonl
READY=${TEST_DIR}/ready
SUFFIX=$$
NS_A=skbxma${SUFFIX}
NS_B=skbxmb${SUFFIX}
DEV_A=smda${SUFFIX}
DEV_B=smdb${SUFFIX}
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
    --duration 3 \
    --max-events 64 \
    --output-skb-metadata 'skb->mark' \
    --output-skb-metadata 'skb->hash' \
    --output-skb-metadata 'skb->dev->ifindex' \
    --output-skb-metadata 'skb->skb_iif' \
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

ip netns exec "${NS_B}" ping -c 3 -W 1 10.245.1.1 >/dev/null
wait "${CAPTURE_PID}"
CAPTURE_PID=

jq -e '
    select(.kind == "capture_start") |
    [.metadata_projections[].expression] == [
        "skb->mark",
        "skb->hash",
        "skb->dev->ifindex",
        "skb->skb_iif"
    ] and
    [.metadata_projections[].encoding] == [
        "unsigned",
        "unsigned",
        "signed",
        "signed"
    ] and
    ([.metadata_projections[].size] | all(. == 4)) and
    ([.metadata_projections[].type_name] | all(length > 0))
' "${TRACE}" >/dev/null

jq -e '
    select(.kind == "event" and .tuple.destination == "10.245.1.1") |
    (.metadata | map({key: .expression, value: .}) | from_entries) as $metadata |
    ($metadata["skb->mark"].read_error == null) and
    ($metadata["skb->mark"].value.kind == "unsigned") and
    ($metadata["skb->mark"].value.value == .packet.mark) and
    ($metadata["skb->hash"].read_error == null) and
    ($metadata["skb->hash"].value.kind == "unsigned") and
    ($metadata["skb->dev->ifindex"].read_error == null) and
    ($metadata["skb->dev->ifindex"].value.kind == "signed") and
    ($metadata["skb->dev->ifindex"].value.value == .packet.ifindex) and
    ($metadata["skb->skb_iif"].read_error == null) and
    ($metadata["skb->skb_iif"].value.value == .packet.ifindex)
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

echo "live metadata test passed: ${TRACE}"

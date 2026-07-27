#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-stack-lifetime-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-stack-lifetime.XXXXXX)
TRACE=${TEST_DIR}/trace.jsonl
READY=${TEST_DIR}/ready
CAPTURE_PID=

cleanup() {
    if [[ -n ${CAPTURE_PID} ]] && kill -0 "${CAPTURE_PID}" 2>/dev/null; then
        kill "${CAPTURE_PID}" 2>/dev/null || true
        wait "${CAPTURE_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

"${SKBX_BINARY}" capture \
    --probe consume_skb \
    --probe __kfree_skb \
    --filter-track-skb-by-stackid \
    --filter-non-skb-funcs dst_release,kmem_cache_free \
    --duration 4 \
    --max-events 1024 \
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

ping -c 5 -W 1 127.0.0.1 >/dev/null
wait "${CAPTURE_PID}"
CAPTURE_PID=

# consume_skb is the logical lifetime boundary. dst_release and the first
# kmem_cache_free execute deeper in that teardown call stack without an SKB
# argument. kfree_skbmem subsequently removes the association before the SKB
# allocation itself is returned to the slab.
jq -s -e '
    (map(select(.kind == "capture_start"))[0].filters.track_stack == true)
    and ([.[] | select(.kind == "event")] as $events
    | any(
        range(0; ($events | length) - 2) as $i
        | ($events[$i]) as $direct
        | ($events[$i + 1]) as $release
        | ($events[$i + 2]) as $free
        | $direct.function.symbol == "consume_skb"
        and $direct.association == "direct"
        and $release.function.symbol == "dst_release"
        and $release.association == "stack"
        and $free.function.symbol == "kmem_cache_free"
        and $free.association == "stack"
        and $direct.skb == $release.skb
        and $direct.skb == $free.skb
        and ($direct.packet.read_errors | length) == 0
        and ($release.packet.read_errors | length) == 0
        and ($free.packet.read_errors | length) == 0
    ))
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

echo "live stack-lifetime test passed: ${TRACE}"

#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "live-stack-test must run as root" >&2
    exit 2
fi

SKBX_BINARY=${1:-target/debug/skbx}
TEST_DIR=$(mktemp -d /tmp/skbx-live-stack.XXXXXX)
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
    --probe ip_rcv \
    --filter-non-skb-funcs fib_table_lookup \
    --duration 4 \
    --max-events 256 \
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

ping -c 3 -W 1 127.0.0.1
wait "${CAPTURE_PID}"
CAPTURE_PID=

jq -s -e '
    [.[] | select(.kind == "event")]
    | group_by(.skb)
    | any(
        (any(.[]; .association == "direct" and .function.symbol == "ip_rcv")) and
        (any(.[];
            .association == "stack" and
            .function.symbol == "fib_table_lookup" and
            (.packet.read_errors | length) == 0
        ))
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

echo "live stack-association test passed: ${TRACE}"

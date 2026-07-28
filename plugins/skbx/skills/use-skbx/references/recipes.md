# skbx recipes

Use these recipes only after confirming host ownership, traffic scope, and the
privilege boundary. Resolve each probe with `skbx plan` before live capture.

## First bounded packet

```console
skbx doctor --json
skbx plan --probe ip_rcv --json
sudo skbx capture --probe ip_rcv \
  --duration 10 \
  --output trace.jsonl \
  icmp
skbx replay trace.jsonl --format json
skbx explain trace.jsonl event:<handle>
```

The capture step requires explicit authorization because it attaches eBPF
programs with elevated privileges. Replay and explain are rootless.

## Controlled HTTPS request on the client

Resolve the target once and keep that address constant for both filtering and
the request:

```console
TARGET_HOST=example.com
TARGET_IP="$(getent ahostsv4 "$TARGET_HOST" | awk 'NR == 1 { print $1 }')"
ip route get "$TARGET_IP"

skbx doctor --json
skbx plan \
  --probe ip_local_out \
  --probe ip_output \
  --probe __dev_queue_xmit \
  --probe ip_rcv \
  --probe tcp_v4_rcv \
  --json
```

After approval, start the bounded capture:

```console
sudo skbx capture \
  --probe ip_local_out \
  --probe ip_output \
  --probe __dev_queue_xmit \
  --probe ip_rcv \
  --probe tcp_v4_rcv \
  --filter-track-skb \
  --duration 15 \
  --ready-file /tmp/skbx-web.ready \
  --output web-trace.jsonl \
  "host $TARGET_IP and tcp port 443"
```

When the ready file exists, reproduce one HTTP/1.1 request against the exact
address:

```console
test -e /tmp/skbx-web.ready && \
curl --http1.1 \
  --resolve "$TARGET_HOST:443:$TARGET_IP" \
  -sS -o /dev/null \
  -w $'remote_ip=%{remote_ip}\ndns=%{time_namelookup}s\nconnect=%{time_connect}s\ntls=%{time_appconnect}s\nttfb=%{time_starttransfer}s\ntotal=%{time_total}s\nhttp=%{http_code}\n' \
  "https://$TARGET_HOST/"

tail -n 1 web-trace.jsonl
skbx replay web-trace.jsonl --format json
```

Do not label all time before the first byte as ISP latency. A local trace can
prove local egress and ingress, while transit and target behavior remain
separate evidence boundaries unless those systems have their own sensors.

## Existing trace

Do not request privileges merely to analyze an artifact:

```console
tail -n 1 capture.traceq.jsonl
skbx replay capture.traceq.jsonl --format json
skbx explain capture.traceq.jsonl event:<handle>
```

If the final envelope is missing, the capture is incomplete.

## Arc rootless demo

Use this only from an skbx source checkout:

```console
cargo run -p skbx-arc -- serve --demo
```

Open `http://127.0.0.1:7878`. Describe it as a local, in-memory,
loopback-default lab vertical slice. It has no authentication, persistence, or
live remote-capture backend.

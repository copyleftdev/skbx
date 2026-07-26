use crate::{BoundedMap, route_handle};
use serde::{Deserialize, Serialize};
use skbx_contract::{
    CONTRACT_VERSION, CaptureEnd, CaptureStart, Envelope, Reliability, RouteConsensus,
    RoutePattern, TraceEvent, TraceSummary,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::BufRead;
use thiserror::Error;

const MAX_REPLAY_EVENTS: u64 = 1_000_000;
const MAX_EXPLAIN_NEIGHBORS: usize = 32;
const MAX_REPLAY_ROUTES: usize = 65_536;
const MAX_ROUTE_HOPS: usize = 256;
const MAX_ROUTE_EXAMPLES: usize = 4;

#[derive(Clone, Debug)]
struct RouteBuilder {
    functions: Vec<String>,
    first_seq: u64,
    last_seq: u64,
    first_event: String,
    last_event: String,
    truncated: bool,
}

impl RouteBuilder {
    fn new(event: &TraceEvent, function: String) -> Self {
        Self {
            functions: vec![function],
            first_seq: event.seq,
            last_seq: event.seq,
            first_event: event.handle.clone(),
            last_event: event.handle.clone(),
            truncated: false,
        }
    }

    fn observe(&mut self, event: &TraceEvent, function: String) {
        if self.functions.len() < MAX_ROUTE_HOPS {
            self.functions.push(function);
        } else {
            self.truncated = true;
        }
        self.last_seq = event.seq;
        self.last_event.clone_from(&event.handle);
    }
}

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("trace IO failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSONL at line {line}: {source}")]
    Json {
        line: usize,
        source: serde_json::Error,
    },
    #[error("trace contract error: {0}")]
    Contract(String),
}

pub fn replay<R: BufRead>(reader: R) -> Result<TraceSummary, ReplayError> {
    let mut start: Option<CaptureStart> = None;
    let mut end: Option<CaptureEnd> = None;
    let mut functions = BTreeMap::new();
    let mut processes = BTreeMap::new();
    let mut skbs = BTreeSet::new();
    let mut routes: Option<BoundedMap<String, RouteBuilder>> = None;
    let mut completed_routes = Vec::<(String, RouteBuilder)>::new();
    let mut observed_events = 0_u64;

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let envelope: Envelope =
            serde_json::from_str(&line).map_err(|source| ReplayError::Json {
                line: index + 1,
                source,
            })?;
        match envelope {
            Envelope::CaptureStart(value) => {
                let route_capacity = usize::try_from(value.limits.route_cache_entries)
                    .unwrap_or(MAX_REPLAY_ROUTES)
                    .clamp(1, MAX_REPLAY_ROUTES);
                if start.replace(value).is_some() {
                    return Err(ReplayError::Contract(
                        "more than one capture_start envelope".into(),
                    ));
                }
                routes = Some(BoundedMap::new(route_capacity));
            }
            Envelope::Event(event) => {
                if end.is_some() {
                    return Err(ReplayError::Contract(
                        "event appeared after capture_end".into(),
                    ));
                }
                let capture = start.as_ref().ok_or_else(|| {
                    ReplayError::Contract("event appeared before capture_start".into())
                })?;
                validate_event(&event, capture)?;
                if event.seq != observed_events {
                    return Err(ReplayError::Contract(format!(
                        "expected event seq {observed_events}, found {}",
                        event.seq
                    )));
                }
                observed_events += 1;
                if observed_events > MAX_REPLAY_EVENTS {
                    return Err(ReplayError::Contract(format!(
                        "replay exceeds bounded limit of {MAX_REPLAY_EVENTS} events"
                    )));
                }
                let function = event
                    .function
                    .symbol
                    .clone()
                    .unwrap_or_else(|| event.function.address.clone());
                *functions.entry(function.clone()).or_insert(0) += 1;
                *processes.entry(event.command.clone()).or_insert(0) += 1;
                skbs.insert(event.skb.clone());
                let route_map = routes
                    .as_mut()
                    .expect("route state is initialized with capture_start");
                let route = match route_map.remove(&event.skb) {
                    Some(route)
                        if route
                            .functions
                            .first()
                            .is_some_and(|first| first == &function) =>
                    {
                        completed_routes.push((event.skb.clone(), route));
                        RouteBuilder::new(&event, function)
                    }
                    Some(mut route) => {
                        route.observe(&event, function);
                        route
                    }
                    None => RouteBuilder::new(&event, function),
                };
                debug_assert_eq!(route.last_seq, event.seq);
                route_map.insert(event.skb.clone(), route);
            }
            Envelope::CaptureEnd(value) => {
                let capture = start.as_ref().ok_or_else(|| {
                    ReplayError::Contract("capture_end appeared before capture_start".into())
                })?;
                if value.schema != CONTRACT_VERSION {
                    return Err(ReplayError::Contract(format!(
                        "unsupported footer schema {}",
                        value.schema
                    )));
                }
                if value.capture_id != capture.capture_id {
                    return Err(ReplayError::Contract(
                        "capture_end capture_id does not match capture_start".into(),
                    ));
                }
                if value.complete && !value.reliability.complete() {
                    return Err(ReplayError::Contract(
                        "footer marks a lossy capture complete".into(),
                    ));
                }
                if end.replace(value).is_some() {
                    return Err(ReplayError::Contract(
                        "more than one capture_end envelope".into(),
                    ));
                }
            }
        }
    }

    let start =
        start.ok_or_else(|| ReplayError::Contract("missing capture_start envelope".into()))?;
    if start.schema != CONTRACT_VERSION {
        return Err(ReplayError::Contract(format!(
            "unsupported schema {}; expected {CONTRACT_VERSION}",
            start.schema
        )));
    }

    let (complete, reliability, stop_reason) = match end {
        Some(end) => {
            if end.capture_id != start.capture_id {
                return Err(ReplayError::Contract(
                    "capture_end capture_id does not match capture_start".into(),
                ));
            }
            if end.events != observed_events {
                return Err(ReplayError::Contract(format!(
                    "footer reports {} events but stream contains {observed_events}",
                    end.events
                )));
            }
            (end.complete, end.reliability, Some(end.stop_reason))
        }
        None => (false, Reliability::default(), None),
    };

    let routes = routes.expect("start and route state are initialized together");
    let route_evictions = routes.evictions();
    let (route_patterns, route_consensus) =
        summarize_routes(&start.capture_id, &completed_routes, &routes);

    Ok(TraceSummary {
        schema: format!("{CONTRACT_VERSION}/summary"),
        capture_id: start.capture_id,
        complete,
        events: observed_events,
        distinct_skbs: skbs.len(),
        functions,
        processes,
        route_patterns,
        route_consensus,
        route_evictions,
        reliability,
        stop_reason,
    })
}

fn summarize_routes(
    capture_id: &str,
    completed: &[(String, RouteBuilder)],
    routes: &BoundedMap<String, RouteBuilder>,
) -> (Vec<RoutePattern>, Option<RouteConsensus>) {
    let mut ordered: Vec<_> = completed
        .iter()
        .map(|(skb, route)| (skb, route))
        .chain(routes.iter())
        .collect();
    ordered.sort_by(|(skb_a, route_a), (skb_b, route_b)| {
        route_a
            .first_seq
            .cmp(&route_b.first_seq)
            .then_with(|| skb_a.cmp(skb_b))
    });

    let mut grouped =
        BTreeMap::<(Vec<String>, bool), (u64, Vec<String>, Vec<String>, u64, u64)>::new();
    for (skb, route) in ordered {
        let aggregate = grouped
            .entry((route.functions.clone(), route.truncated))
            .or_insert_with(|| (0, Vec::new(), Vec::new(), route.first_seq, route.last_seq));
        aggregate.0 += 1;
        aggregate.3 = aggregate.3.min(route.first_seq);
        aggregate.4 = aggregate.4.max(route.last_seq);
        if aggregate.1.len() < MAX_ROUTE_EXAMPLES && !aggregate.1.contains(skb) {
            aggregate.1.push(skb.clone());
        }
        if aggregate.2.len() < MAX_ROUTE_EXAMPLES {
            aggregate.2.push(route.first_event.clone());
            if route.last_event != route.first_event && aggregate.2.len() < MAX_ROUTE_EXAMPLES {
                aggregate.2.push(route.last_event.clone());
            }
        }
    }

    let mut patterns: Vec<RoutePattern> = grouped
        .into_iter()
        .map(
            |(
                (functions, truncated),
                (routes, example_skbs, example_events, first_seq, last_seq),
            )| {
                RoutePattern {
                    handle: route_handle(capture_id, &functions, truncated),
                    functions,
                    routes,
                    example_skbs,
                    example_events,
                    first_seq,
                    last_seq,
                    truncated,
                    outlier: false,
                }
            },
        )
        .collect();
    patterns.sort_by(|a, b| {
        b.routes
            .cmp(&a.routes)
            .then_with(|| a.handle.cmp(&b.handle))
    });

    let total_routes = patterns.iter().map(|pattern| pattern.routes).sum::<u64>();
    let Some(dominant) = patterns.first() else {
        return (patterns, None);
    };
    let dominant_handle = dominant.handle.clone();
    let dominant_routes = dominant.routes;
    let ambiguous = patterns
        .get(1)
        .is_some_and(|second| second.routes == dominant_routes);
    if !ambiguous {
        for pattern in &mut patterns {
            pattern.outlier = pattern.handle != dominant_handle;
        }
    }
    let confidence_basis_points = dominant_routes
        .saturating_mul(10_000)
        .checked_div(total_routes)
        .unwrap_or(0)
        .min(10_000) as u16;
    let consensus = RouteConsensus {
        handle: dominant_handle,
        routes: dominant_routes,
        total_routes,
        confidence_basis_points,
        outlier_routes: if ambiguous {
            0
        } else {
            total_routes.saturating_sub(dominant_routes)
        },
        ambiguous,
    };
    (patterns, Some(consensus))
}

fn validate_event(event: &TraceEvent, start: &CaptureStart) -> Result<(), ReplayError> {
    if event.schema != CONTRACT_VERSION {
        return Err(ReplayError::Contract(format!(
            "event {} uses schema {}",
            event.seq, event.schema
        )));
    }
    if event.capture_id != start.capture_id {
        return Err(ReplayError::Contract(format!(
            "event {} capture_id does not match stream",
            event.seq
        )));
    }
    if !event.handle.starts_with("event:")
        || event.handle.len() != "event:".len() + 24
        || !event.handle["event:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReplayError::Contract(format!(
            "event {} has invalid evidence handle {}",
            event.seq, event.handle
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    pub schema: String,
    pub handle: String,
    pub target: TraceEvent,
    pub same_skb_evidence: Vec<TraceEvent>,
    pub truncated: bool,
}

pub fn explain<R: BufRead>(reader: R, handle: &str) -> Result<Explanation, ReplayError> {
    let mut events = VecDeque::with_capacity(MAX_EXPLAIN_NEIGHBORS);
    let mut target: Option<TraceEvent> = None;
    let mut target_skb: Option<String> = None;
    let mut truncated = false;

    // First pass identifies the target. Keeping this streaming and reopening
    // the file in the CLI avoids loading a trace into memory.
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let envelope: Envelope =
            serde_json::from_str(&line).map_err(|source| ReplayError::Json {
                line: index + 1,
                source,
            })?;
        if let Envelope::Event(event) = envelope {
            if event.handle == handle {
                target_skb = Some(event.skb.clone());
                target = Some(event);
                break;
            }
        }
    }

    let target =
        target.ok_or_else(|| ReplayError::Contract(format!("unknown evidence handle {handle}")))?;
    let _target_skb = target_skb.expect("target and skb are set together");

    // The caller supplies a second reader in practice through explain_file;
    // this single-reader API can still provide the target itself.
    events.push_back(target.clone());
    if events.len() >= MAX_EXPLAIN_NEIGHBORS {
        truncated = true;
    }

    Ok(Explanation {
        schema: format!("{CONTRACT_VERSION}/explanation"),
        handle: handle.into(),
        target,
        same_skb_evidence: events.into(),
        truncated,
    })
}

/// Explain with a reopenable path, returning bounded same-SKB evidence.
pub fn explain_file(path: &std::path::Path, handle: &str) -> Result<Explanation, ReplayError> {
    let first = std::io::BufReader::new(std::fs::File::open(path)?);
    let mut explanation = explain(first, handle)?;
    let target_skb = explanation.target.skb.clone();
    let mut evidence = Vec::new();
    let mut matching = 0_usize;

    let second = std::io::BufReader::new(std::fs::File::open(path)?);
    for (index, line) in second.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let envelope: Envelope =
            serde_json::from_str(&line).map_err(|source| ReplayError::Json {
                line: index + 1,
                source,
            })?;
        if let Envelope::Event(event) = envelope
            && event.skb == target_skb
        {
            matching += 1;
            if evidence.len() < MAX_EXPLAIN_NEIGHBORS {
                evidence.push(event);
            }
        }
    }
    explanation.truncated = matching > evidence.len();
    explanation.same_skb_evidence = evidence;
    Ok(explanation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use skbx_contract::{CaptureLimits, FunctionRef, PacketMeta, StopReason};
    use std::io::Cursor;

    fn fixture(include_end: bool) -> String {
        let start = Envelope::CaptureStart(CaptureStart {
            schema: CONTRACT_VERSION.into(),
            capture_id: "c1".into(),
            started_unix_ns: 1,
            started_monotonic_ns: 1,
            kernel_release: "test".into(),
            probes: vec!["ip_rcv".into()],
            attachment_backend: "kprobe".into(),
            timestamp_mode: "none".into(),
            filters: Default::default(),
            limits: CaptureLimits {
                duration_seconds: 1,
                max_events: 2,
                route_cache_entries: 4,
            },
        });
        let event = Envelope::Event(TraceEvent {
            schema: CONTRACT_VERSION.into(),
            capture_id: "c1".into(),
            seq: 0,
            handle: "event:000000000000000000000000".into(),
            timestamp_ns: 2,
            presentation_timestamp: None,
            cpu: 0,
            pid: 1,
            command: "init".into(),
            skb: "0x1".into(),
            function: FunctionRef {
                address: "0x2".into(),
                symbol: Some("ip_rcv".into()),
            },
            caller: None,
            stack: Vec::new(),
            parameters: Default::default(),
            drop_reason: None,
            packet: PacketMeta {
                len: 64,
                protocol: 0x800,
                mark: 0,
                ifindex: 1,
                read_status: 0,
                ..PacketMeta::default()
            },
            tuple: None,
        });
        let mut lines = vec![
            serde_json::to_string(&start).unwrap(),
            serde_json::to_string(&event).unwrap(),
        ];
        if include_end {
            lines.push(
                serde_json::to_string(&Envelope::CaptureEnd(CaptureEnd {
                    schema: CONTRACT_VERSION.into(),
                    capture_id: "c1".into(),
                    events: 1,
                    reliability: Reliability::default(),
                    complete: true,
                    stop_reason: StopReason::Duration,
                }))
                .unwrap(),
            );
        }
        lines.join("\n")
    }

    #[test]
    fn replay_is_deterministic() {
        let input = fixture(true);
        let a = replay(Cursor::new(&input)).unwrap();
        let b = replay(Cursor::new(&input)).unwrap();
        assert_eq!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap()
        );
        assert!(a.complete);
        assert_eq!(a.functions["ip_rcv"], 1);
        assert_eq!(a.route_patterns.len(), 1);
        assert_eq!(a.route_patterns[0].functions, ["ip_rcv"]);
        assert_eq!(a.route_consensus.unwrap().confidence_basis_points, 10_000);
    }

    #[test]
    fn missing_footer_is_explicitly_incomplete() {
        let summary = replay(Cursor::new(fixture(false))).unwrap();
        assert!(!summary.complete);
        assert_eq!(summary.stop_reason, None);
    }

    #[test]
    fn route_consensus_marks_only_minor_patterns_as_outliers() {
        let route = |functions: &[&str], first_seq, event: &str| RouteBuilder {
            functions: functions.iter().map(|value| (*value).into()).collect(),
            first_seq,
            last_seq: first_seq + functions.len() as u64,
            first_event: event.into(),
            last_event: event.into(),
            truncated: false,
        };
        let mut routes = BoundedMap::new(8);
        routes.insert("0x1".into(), route(&["ip_rcv", "tcp_v4_rcv"], 1, "event:1"));
        routes.insert("0x2".into(), route(&["ip_rcv", "tcp_v4_rcv"], 3, "event:2"));
        routes.insert("0x3".into(), route(&["ip_rcv", "udp_rcv"], 5, "event:3"));

        let (patterns, consensus) = summarize_routes("capture", &[], &routes);
        let consensus = consensus.unwrap();
        assert_eq!(consensus.routes, 2);
        assert_eq!(consensus.total_routes, 3);
        assert_eq!(consensus.confidence_basis_points, 6666);
        assert_eq!(consensus.outlier_routes, 1);
        assert!(!consensus.ambiguous);
        assert_eq!(patterns.iter().filter(|pattern| pattern.outlier).count(), 1);
    }

    #[test]
    #[ignore = "manual throughput measurement"]
    fn replay_100k_events() {
        const EVENTS: u64 = 100_000;
        let start = Envelope::CaptureStart(CaptureStart {
            schema: CONTRACT_VERSION.into(),
            capture_id: "benchmark".into(),
            started_unix_ns: 1,
            started_monotonic_ns: 1,
            kernel_release: "benchmark".into(),
            probes: vec!["ip_rcv".into()],
            attachment_backend: "kprobe".into(),
            timestamp_mode: "none".into(),
            filters: Default::default(),
            limits: CaptureLimits {
                duration_seconds: 1,
                max_events: EVENTS,
                route_cache_entries: 65_536,
            },
        });
        let mut bytes = Vec::with_capacity(48 * 1024 * 1024);
        serde_json::to_writer(&mut bytes, &start).unwrap();
        bytes.push(b'\n');
        for seq in 0..EVENTS {
            let event = Envelope::Event(TraceEvent {
                schema: CONTRACT_VERSION.into(),
                capture_id: "benchmark".into(),
                seq,
                handle: format!("event:{seq:024x}"),
                timestamp_ns: seq,
                presentation_timestamp: None,
                cpu: (seq % 64) as u32,
                pid: (seq % 4096) as u32,
                command: format!("worker-{}", seq % 16),
                skb: format!("0x{:x}", seq % 10_000),
                function: FunctionRef {
                    address: "0x1000".into(),
                    symbol: Some("ip_rcv".into()),
                },
                caller: None,
                stack: Vec::new(),
                parameters: Default::default(),
                drop_reason: None,
                packet: PacketMeta {
                    len: 64,
                    protocol: 0x0800,
                    mark: 0,
                    ifindex: 1,
                    read_status: 0,
                    ..PacketMeta::default()
                },
                tuple: None,
            });
            serde_json::to_writer(&mut bytes, &event).unwrap();
            bytes.push(b'\n');
        }
        let end = Envelope::CaptureEnd(CaptureEnd {
            schema: CONTRACT_VERSION.into(),
            capture_id: "benchmark".into(),
            events: EVENTS,
            reliability: Reliability::default(),
            complete: true,
            stop_reason: StopReason::Duration,
        });
        serde_json::to_writer(&mut bytes, &end).unwrap();
        bytes.push(b'\n');

        let started = std::time::Instant::now();
        let summary = replay(Cursor::new(bytes)).unwrap();
        let elapsed = started.elapsed();
        let rate = EVENTS as f64 / elapsed.as_secs_f64();
        eprintln!("replayed {EVENTS} events in {elapsed:?} ({rate:.0} events/s)");
        assert_eq!(summary.events, EVENTS);
        assert_eq!(summary.distinct_skbs, 10_000);
    }
}

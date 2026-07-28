//! Distributed capture mission contracts and deterministic correlation.
//!
//! `traceq` remains the authoritative per-host evidence format. This crate
//! defines the separate `missionq` envelope that references complete traceq
//! artifacts and labels every cross-host relationship by evidence strength.

use serde::{Deserialize, Serialize};
use skbx_contract::{PacketTuple, Reliability, TraceEvent, TraceSummary};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const MISSION_CONTRACT_VERSION: &str = "missionq/0.1.0";
pub const MAX_MISSION_SENSORS: usize = 32;
pub const MAX_MISSION_DURATION_SECONDS: u64 = 300;
pub const MAX_MISSION_EVENTS: u64 = 1_000_000;
pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_CORRELATION_WINDOW_NS: u64 = 250_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturePlan {
    pub duration_seconds: u64,
    pub max_events: u64,
    pub max_artifact_bytes: u64,
    pub filter: String,
    #[serde(default)]
    pub probes: Vec<String>,
    #[serde(default)]
    pub track_skb: bool,
    #[serde(default)]
    pub trace_tc: bool,
    #[serde(default)]
    pub trace_xdp: bool,
    #[serde(default = "default_correlation_window_ns")]
    pub correlation_window_ns: u64,
}

const fn default_correlation_window_ns() -> u64 {
    DEFAULT_CORRELATION_WINDOW_NS
}

impl CapturePlan {
    pub fn validate(&self) -> Result<(), MissionError> {
        if self.duration_seconds == 0 || self.duration_seconds > MAX_MISSION_DURATION_SECONDS {
            return Err(MissionError::InvalidPlan(format!(
                "duration_seconds must be between 1 and {MAX_MISSION_DURATION_SECONDS}"
            )));
        }
        if self.max_events == 0 || self.max_events > MAX_MISSION_EVENTS {
            return Err(MissionError::InvalidPlan(format!(
                "max_events must be between 1 and {MAX_MISSION_EVENTS}"
            )));
        }
        if self.max_artifact_bytes == 0 || self.max_artifact_bytes > MAX_ARTIFACT_BYTES {
            return Err(MissionError::InvalidPlan(format!(
                "max_artifact_bytes must be between 1 and {MAX_ARTIFACT_BYTES}"
            )));
        }
        if self.filter.trim().is_empty() {
            return Err(MissionError::InvalidPlan(
                "filter must be explicit and non-empty".into(),
            ));
        }
        if self.correlation_window_ns == 0 || self.correlation_window_ns > 5_000_000_000 {
            return Err(MissionError::InvalidPlan(
                "correlation_window_ns must be between 1 and 5000000000".into(),
            ));
        }
        if self.probes.len() > 64 {
            return Err(MissionError::InvalidPlan(
                "a mission may request at most 64 exact probes".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        let encoded = serde_json::to_vec(self).expect("CapturePlan serialization is infallible");
        format!("plan:{}", &blake3::hash(&encoded).to_hex()[..24])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionRequest {
    pub mission_id: String,
    pub name: String,
    pub targets: Vec<String>,
    pub plan: CapturePlan,
}

impl MissionRequest {
    pub fn validate(&self) -> Result<(), MissionError> {
        validate_identifier("mission_id", &self.mission_id)?;
        if self.name.trim().is_empty() || self.name.len() > 120 {
            return Err(MissionError::InvalidMission(
                "name must contain between 1 and 120 bytes".into(),
            ));
        }
        if self.targets.is_empty() || self.targets.len() > MAX_MISSION_SENSORS {
            return Err(MissionError::InvalidMission(format!(
                "targets must contain between 1 and {MAX_MISSION_SENSORS} sensors"
            )));
        }
        let mut unique = BTreeSet::new();
        for target in &self.targets {
            validate_identifier("target sensor", target)?;
            if !unique.insert(target) {
                return Err(MissionError::InvalidMission(format!(
                    "target sensor {target} appears more than once"
                )));
            }
        }
        self.plan.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorRegistration {
    pub sensor_id: String,
    pub display_name: String,
    pub kernel_release: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub clock_uncertainty_ns: u64,
}

impl SensorRegistration {
    pub fn validate(&self) -> Result<(), MissionError> {
        validate_identifier("sensor_id", &self.sensor_id)?;
        if self.display_name.trim().is_empty() || self.display_name.len() > 80 {
            return Err(MissionError::InvalidSensor(
                "display_name must contain between 1 and 80 bytes".into(),
            ));
        }
        if self.kernel_release.trim().is_empty() || self.kernel_release.len() > 160 {
            return Err(MissionError::InvalidSensor(
                "kernel_release must contain between 1 and 160 bytes".into(),
            ));
        }
        if self.capabilities.len() > 128 {
            return Err(MissionError::InvalidSensor(
                "a sensor may advertise at most 128 capabilities".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionStatus {
    Draft,
    Armed,
    Capturing,
    Complete,
    Partial,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentStatus {
    Pending,
    Leased,
    Submitted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assignment {
    pub schema: String,
    pub mission_id: String,
    pub sensor_id: String,
    pub generation: u64,
    pub plan_digest: String,
    pub plan: CapturePlan,
    pub lease_expires_unix_ns: u64,
    pub status: AssignmentStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    pub schema: String,
    pub mission_id: String,
    pub sensor_id: String,
    pub capture_id: String,
    pub content_hash: String,
    pub bytes: u64,
    pub complete: bool,
    pub events: u64,
    pub reliability: Reliability,
    pub route_handles: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Observed,
    Correlated,
    Candidate,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationEdge {
    pub edge_id: String,
    pub from_sensor: String,
    pub to_sensor: String,
    pub level: EvidenceLevel,
    pub confidence_basis_points: u16,
    pub basis: Vec<String>,
    pub source_events: Vec<String>,
    pub target_events: Vec<String>,
    pub matches: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionRecord {
    pub schema: String,
    pub mission_id: String,
    pub name: String,
    pub targets: Vec<String>,
    pub status: MissionStatus,
    pub plan: CapturePlan,
    pub plan_digest: String,
    pub created_unix_ns: u64,
    pub assignments: BTreeMap<String, AssignmentStatus>,
    pub artifacts: BTreeMap<String, ArtifactManifest>,
    pub correlations: Vec<CorrelationEdge>,
}

#[derive(Clone, Debug)]
pub struct SensorTrace {
    pub sensor_id: String,
    pub started_unix_ns: u64,
    pub started_monotonic_ns: u64,
    pub clock_uncertainty_ns: u64,
    pub events: Vec<TraceEvent>,
}

impl SensorTrace {
    pub fn global_timestamp(&self, event: &TraceEvent) -> u64 {
        self.started_unix_ns
            .saturating_add(event.timestamp_ns.saturating_sub(self.started_monotonic_ns))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ComparableEvent {
    handle: String,
    timestamp_ns: u64,
    uncertainty_ns: u64,
    packet_len: u32,
    tuple: PacketTuple,
    tunnel_tuple: Option<PacketTuple>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FlowKey {
    low_address: String,
    low_port: u16,
    high_address: String,
    high_port: u16,
    l3_protocol: u16,
    l4_protocol: u8,
}

impl FlowKey {
    fn from_tuple(tuple: &PacketTuple) -> Self {
        let source = (&tuple.source, tuple.source_port);
        let destination = (&tuple.destination, tuple.destination_port);
        let (low, high) = if source <= destination {
            (source, destination)
        } else {
            (destination, source)
        };
        Self {
            low_address: low.0.clone(),
            low_port: low.1,
            high_address: high.0.clone(),
            high_port: high.1,
            l3_protocol: tuple.l3_protocol,
            l4_protocol: tuple.l4_protocol,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Candidate {
    left: usize,
    right: usize,
    cost: u64,
    strong: bool,
}

/// Correlate adjacent sensors in mission order.
///
/// Events are partitioned by a direction-independent flow key. Each partition
/// builds a sparse candidate graph bounded by the mission time window, then a
/// deterministic min-cost maximum matching prevents one observation from being
/// assigned to more than one peer.
pub fn correlate_adjacent(
    targets: &[String],
    traces: &BTreeMap<String, SensorTrace>,
    window_ns: u64,
) -> Vec<CorrelationEdge> {
    targets
        .windows(2)
        .map(|pair| {
            let from = &pair[0];
            let to = &pair[1];
            match (traces.get(from), traces.get(to)) {
                (Some(left), Some(right)) => correlate_pair(left, right, window_ns),
                _ => unknown_edge(from, to, "one or both capture artifacts are missing"),
            }
        })
        .collect()
}

fn correlate_pair(left: &SensorTrace, right: &SensorTrace, window_ns: u64) -> CorrelationEdge {
    let left_events = comparable_events(left);
    let right_events = comparable_events(right);
    let mut left_by_flow = BTreeMap::<FlowKey, Vec<ComparableEvent>>::new();
    let mut right_by_flow = BTreeMap::<FlowKey, Vec<ComparableEvent>>::new();

    for event in left_events {
        left_by_flow
            .entry(FlowKey::from_tuple(&event.tuple))
            .or_default()
            .push(event);
    }
    for event in right_events {
        right_by_flow
            .entry(FlowKey::from_tuple(&event.tuple))
            .or_default()
            .push(event);
    }

    let mut matched = Vec::<(ComparableEvent, ComparableEvent, bool)>::new();
    for (flow, mut left_flow) in left_by_flow {
        let Some(mut right_flow) = right_by_flow.remove(&flow) else {
            continue;
        };
        left_flow.sort_by_key(|event| (event.timestamp_ns, event.handle.clone()));
        right_flow.sort_by_key(|event| (event.timestamp_ns, event.handle.clone()));

        let candidates = correlation_candidates(&left_flow, &right_flow, window_ns);

        for candidate in sparse_min_cost_matching(left_flow.len(), right_flow.len(), &candidates) {
            matched.push((
                left_flow[candidate.left].clone(),
                right_flow[candidate.right].clone(),
                candidate.strong,
            ));
        }
    }

    if matched.is_empty() {
        return unknown_edge(
            &left.sensor_id,
            &right.sensor_id,
            "no compatible packet observations overlapped in time",
        );
    }

    matched.sort_by(|a, b| {
        a.0.timestamp_ns
            .cmp(&b.0.timestamp_ns)
            .then_with(|| a.0.handle.cmp(&b.0.handle))
    });
    let strong_matches = matched.iter().filter(|(_, _, strong)| *strong).count();
    let level = if strong_matches == matched.len() {
        EvidenceLevel::Correlated
    } else {
        EvidenceLevel::Candidate
    };
    let confidence = if level == EvidenceLevel::Correlated {
        9000
    } else {
        5500
    };

    CorrelationEdge {
        edge_id: edge_id(&left.sensor_id, &right.sensor_id, level),
        from_sensor: left.sensor_id.clone(),
        to_sensor: right.sensor_id.clone(),
        level,
        confidence_basis_points: confidence,
        basis: if level == EvidenceLevel::Correlated {
            vec![
                "compatible flow tuple".into(),
                "packet length".into(),
                "bounded clock interval".into(),
                "one-to-one minimum-cost assignment".into(),
            ]
        } else {
            vec![
                "compatible flow tuple".into(),
                "bounded clock interval".into(),
                "packet metadata differs".into(),
            ]
        },
        source_events: matched
            .iter()
            .take(8)
            .map(|(source, _, _)| source.handle.clone())
            .collect(),
        target_events: matched
            .iter()
            .take(8)
            .map(|(_, target, _)| target.handle.clone())
            .collect(),
        matches: u64::try_from(matched.len()).unwrap_or(u64::MAX),
    }
}

fn comparable_events(trace: &SensorTrace) -> Vec<ComparableEvent> {
    trace
        .events
        .iter()
        .filter_map(|event| {
            event.tuple.clone().map(|tuple| ComparableEvent {
                handle: event.handle.clone(),
                timestamp_ns: trace.global_timestamp(event),
                uncertainty_ns: trace.clock_uncertainty_ns,
                packet_len: event.packet.len,
                tuple,
                tunnel_tuple: event.tunnel_tuple.clone(),
            })
        })
        .collect()
}

/// Build only the time-window overlap rather than the Cartesian product.
///
/// Both sides are timestamp-sorted. The lower cursor moves monotonically, so
/// candidate discovery is O(left + right + viable_candidates).
fn correlation_candidates(
    left: &[ComparableEvent],
    right: &[ComparableEvent],
    window_ns: u64,
) -> Vec<Candidate> {
    let max_right_uncertainty = right
        .iter()
        .map(|event| event.uncertainty_ns)
        .max()
        .unwrap_or(0);
    let mut first_possible = 0;
    let mut candidates = Vec::new();

    for (left_index, left_event) in left.iter().enumerate() {
        let broad_window = left_event
            .uncertainty_ns
            .saturating_add(max_right_uncertainty)
            .saturating_add(window_ns);
        let lower = left_event.timestamp_ns.saturating_sub(broad_window);
        let upper = left_event.timestamp_ns.saturating_add(broad_window);
        while first_possible < right.len() && right[first_possible].timestamp_ns < lower {
            first_possible += 1;
        }

        for (right_index, right_event) in right.iter().enumerate().skip(first_possible) {
            if right_event.timestamp_ns > upper {
                break;
            }
            let uncertainty = left_event
                .uncertainty_ns
                .saturating_add(right_event.uncertainty_ns)
                .saturating_add(window_ns);
            let delta = left_event.timestamp_ns.abs_diff(right_event.timestamp_ns);
            if delta > uncertainty {
                continue;
            }
            let length_penalty = u64::from(left_event.packet_len.abs_diff(right_event.packet_len))
                .saturating_mul(1_000_000);
            let strong = left_event.packet_len == right_event.packet_len
                && tuples_compatible(left_event, right_event);
            let evidence_penalty = if strong { 0 } else { window_ns };
            candidates.push(Candidate {
                left: left_index,
                right: right_index,
                cost: delta
                    .saturating_add(length_penalty)
                    .saturating_add(evidence_penalty),
                strong,
            });
        }
    }
    candidates
}

fn tuples_compatible(left: &ComparableEvent, right: &ComparableEvent) -> bool {
    left.tuple == right.tuple
        || left.tunnel_tuple.as_ref() == Some(&right.tuple)
        || right.tunnel_tuple.as_ref() == Some(&left.tuple)
}

fn unknown_edge(from: &str, to: &str, reason: &str) -> CorrelationEdge {
    CorrelationEdge {
        edge_id: edge_id(from, to, EvidenceLevel::Unknown),
        from_sensor: from.into(),
        to_sensor: to.into(),
        level: EvidenceLevel::Unknown,
        confidence_basis_points: 0,
        basis: vec![reason.into()],
        source_events: Vec::new(),
        target_events: Vec::new(),
        matches: 0,
    }
}

fn edge_id(from: &str, to: &str, level: EvidenceLevel) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(MISSION_CONTRACT_VERSION.as_bytes());
    hash.update(from.as_bytes());
    hash.update(to.as_bytes());
    hash.update(format!("{level:?}").as_bytes());
    format!("edge:{}", &hash.finalize().to_hex()[..24])
}

/// Min-cost maximum matching for a sparse bipartite graph.
///
/// Successive shortest augmenting paths are found with Bellman-Ford over the
/// residual graph. Mission windows keep candidate graphs deliberately small,
/// favoring auditable determinism over a dense cubic assignment matrix.
fn sparse_min_cost_matching(
    left_count: usize,
    right_count: usize,
    candidates: &[Candidate],
) -> Vec<Candidate> {
    if left_count == 0 || right_count == 0 || candidates.is_empty() {
        return Vec::new();
    }

    let source = 0;
    let left_start = 1;
    let right_start = left_start + left_count;
    let sink = right_start + right_count;
    let nodes = sink + 1;
    let mut graph = vec![Vec::<ResidualEdge>::new(); nodes];

    for left in 0..left_count {
        add_residual_edge(&mut graph, source, left_start + left, 1, 0, None);
    }
    for (candidate_index, candidate) in candidates.iter().enumerate() {
        add_residual_edge(
            &mut graph,
            left_start + candidate.left,
            right_start + candidate.right,
            1,
            i128::from(candidate.cost),
            Some(candidate_index),
        );
    }
    for right in 0..right_count {
        add_residual_edge(&mut graph, right_start + right, sink, 1, 0, None);
    }

    loop {
        let mut distance = vec![i128::MAX; nodes];
        let mut previous = vec![None::<(usize, usize)>; nodes];
        distance[source] = 0;

        for _ in 0..nodes.saturating_sub(1) {
            let mut changed = false;
            for from in 0..nodes {
                if distance[from] == i128::MAX {
                    continue;
                }
                for (edge_index, edge) in graph[from].iter().enumerate() {
                    if edge.capacity == 0 {
                        continue;
                    }
                    let candidate_distance = distance[from].saturating_add(edge.cost);
                    if candidate_distance < distance[edge.to] {
                        distance[edge.to] = candidate_distance;
                        previous[edge.to] = Some((from, edge_index));
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }

        if previous[sink].is_none() {
            break;
        }

        let mut node = sink;
        while node != source {
            let (from, edge_index) = previous[node].expect("augmenting path is complete");
            let reverse_index = graph[from][edge_index].reverse;
            graph[from][edge_index].capacity -= 1;
            graph[node][reverse_index].capacity += 1;
            node = from;
        }
    }

    let mut selected = Vec::new();
    for left in 0..left_count {
        for edge in &graph[left_start + left] {
            if let Some(index) = edge.candidate_index
                && edge.capacity == 0
            {
                selected.push(candidates[index]);
            }
        }
    }
    selected.sort_by_key(|candidate| (candidate.left, candidate.right));
    selected
}

#[derive(Clone, Debug)]
struct ResidualEdge {
    to: usize,
    reverse: usize,
    capacity: u8,
    cost: i128,
    candidate_index: Option<usize>,
}

fn add_residual_edge(
    graph: &mut [Vec<ResidualEdge>],
    from: usize,
    to: usize,
    capacity: u8,
    cost: i128,
    candidate_index: Option<usize>,
) {
    let forward_reverse = graph[to].len();
    let reverse_reverse = graph[from].len();
    graph[from].push(ResidualEdge {
        to,
        reverse: forward_reverse,
        capacity,
        cost,
        candidate_index,
    });
    graph[to].push(ResidualEdge {
        to: from,
        reverse: reverse_reverse,
        capacity: 0,
        cost: -cost,
        candidate_index: None,
    });
}

pub fn artifact_manifest(
    mission_id: &str,
    sensor_id: &str,
    bytes: &[u8],
    summary: &TraceSummary,
) -> ArtifactManifest {
    ArtifactManifest {
        schema: MISSION_CONTRACT_VERSION.into(),
        mission_id: mission_id.into(),
        sensor_id: sensor_id.into(),
        capture_id: summary.capture_id.clone(),
        content_hash: format!("blake3:{}", blake3::hash(bytes).to_hex()),
        bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        complete: summary.complete,
        events: summary.events,
        reliability: summary.reliability.clone(),
        route_handles: summary
            .route_patterns
            .iter()
            .map(|route| route.handle.clone())
            .collect(),
    }
}

pub fn validate_identifier(field: &str, value: &str) -> Result<(), MissionError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(MissionError::InvalidIdentifier {
            field: field.into(),
            value: value.into(),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MissionError {
    #[error("invalid {field} {value:?}; use 1-64 ASCII letters, digits, '.', '_', ':', or '-'")]
    InvalidIdentifier { field: String, value: String },
    #[error("invalid sensor: {0}")]
    InvalidSensor(String),
    #[error("invalid mission: {0}")]
    InvalidMission(String),
    #[error("invalid capture plan: {0}")]
    InvalidPlan(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use skbx_contract::{FunctionRef, PacketMeta};

    fn plan() -> CapturePlan {
        CapturePlan {
            duration_seconds: 20,
            max_events: 50_000,
            max_artifact_bytes: 8 * 1024 * 1024,
            filter: "tcp port 443".into(),
            probes: vec!["ip_rcv".into()],
            track_skb: true,
            trace_tc: true,
            trace_xdp: false,
            correlation_window_ns: DEFAULT_CORRELATION_WINDOW_NS,
        }
    }

    fn tuple() -> PacketTuple {
        PacketTuple {
            source: "10.0.0.4".into(),
            destination: "203.0.113.8".into(),
            source_port: 51_522,
            destination_port: 443,
            l3_protocol: 0x0800,
            l4_protocol: 6,
            tcp_flags: 0x02,
            icmp_type: None,
            icmp_code: None,
        }
    }

    fn event(handle_digit: char, timestamp_ns: u64, packet_len: u32) -> TraceEvent {
        TraceEvent {
            schema: skbx_contract::CONTRACT_VERSION.into(),
            capture_id: "capture".into(),
            seq: 0,
            handle: format!("event:{}", handle_digit.to_string().repeat(24)),
            timestamp_ns,
            presentation_timestamp: None,
            cpu: 0,
            pid: 1,
            command: "curl".into(),
            skb: "0x1".into(),
            identity: String::new(),
            function: FunctionRef {
                address: "0x1".into(),
                symbol: Some("ip_rcv".into()),
            },
            association: Default::default(),
            match_origin: Default::default(),
            caller: None,
            stack: Vec::new(),
            parameters: Default::default(),
            drop_reason: None,
            bpf_map: None,
            metadata: Vec::new(),
            btf_dumps: Vec::new(),
            bpf_program: None,
            bpf_program_phase: None,
            bpf_program_action: None,
            packet: PacketMeta {
                len: packet_len,
                ..Default::default()
            },
            tuple: Some(tuple()),
            tunnel_tuple: None,
        }
    }

    fn comparable(index: usize, timestamp_ns: u64) -> ComparableEvent {
        ComparableEvent {
            handle: format!("event:{index:024}"),
            timestamp_ns,
            uncertainty_ns: 0,
            packet_len: 64,
            tuple: tuple(),
            tunnel_tuple: None,
        }
    }

    #[test]
    fn plan_is_bounded_and_digest_is_stable() {
        let plan = plan();
        plan.validate().unwrap();
        assert_eq!(plan.digest(), plan.digest());

        let mut invalid = plan;
        invalid.max_events = MAX_MISSION_EVENTS + 1;
        assert!(matches!(
            invalid.validate(),
            Err(MissionError::InvalidPlan(_))
        ));
    }

    #[test]
    fn mission_rejects_duplicate_targets() {
        let request = MissionRequest {
            mission_id: "mission:test".into(),
            name: "Test".into(),
            targets: vec!["edge".into(), "edge".into()],
            plan: plan(),
        };
        assert!(matches!(
            request.validate(),
            Err(MissionError::InvalidMission(_))
        ));
    }

    #[test]
    fn correlation_is_one_to_one_and_minimum_cost() {
        let left = SensorTrace {
            sensor_id: "left".into(),
            started_unix_ns: 1_000,
            started_monotonic_ns: 0,
            clock_uncertainty_ns: 5,
            events: vec![event('1', 100, 64), event('2', 200, 64)],
        };
        let right = SensorTrace {
            sensor_id: "right".into(),
            started_unix_ns: 1_000,
            started_monotonic_ns: 0,
            clock_uncertainty_ns: 5,
            events: vec![event('3', 110, 64), event('4', 205, 64)],
        };
        let edge = correlate_pair(&left, &right, 50);
        assert_eq!(edge.level, EvidenceLevel::Correlated);
        assert_eq!(edge.matches, 2);
        assert_eq!(
            edge.source_events,
            vec![
                "event:111111111111111111111111",
                "event:222222222222222222222222"
            ]
        );
        assert_eq!(
            edge.target_events,
            vec![
                "event:333333333333333333333333",
                "event:444444444444444444444444"
            ]
        );
    }

    #[test]
    fn correlation_marks_metadata_mismatch_as_candidate() {
        let left = SensorTrace {
            sensor_id: "left".into(),
            started_unix_ns: 0,
            started_monotonic_ns: 0,
            clock_uncertainty_ns: 0,
            events: vec![event('1', 100, 64)],
        };
        let right = SensorTrace {
            sensor_id: "right".into(),
            started_unix_ns: 0,
            started_monotonic_ns: 0,
            clock_uncertainty_ns: 0,
            events: vec![event('2', 105, 72)],
        };
        let edge = correlate_pair(&left, &right, 50);
        assert_eq!(edge.level, EvidenceLevel::Candidate);
        assert_eq!(edge.matches, 1);
    }

    #[test]
    fn missing_trace_produces_unknown_edge() {
        let targets = vec!["left".into(), "right".into()];
        let edges = correlate_adjacent(&targets, &BTreeMap::new(), 100);
        assert_eq!(edges[0].level, EvidenceLevel::Unknown);
        assert_eq!(edges[0].confidence_basis_points, 0);
    }

    #[test]
    fn matching_finds_maximum_cardinality_before_minimum_cost() {
        let candidates = vec![
            Candidate {
                left: 0,
                right: 0,
                cost: 1,
                strong: true,
            },
            Candidate {
                left: 0,
                right: 1,
                cost: 2,
                strong: true,
            },
            Candidate {
                left: 1,
                right: 0,
                cost: 2,
                strong: true,
            },
        ];
        let selected = sparse_min_cost_matching(2, 2, &candidates);
        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&candidates[1]));
        assert!(selected.contains(&candidates[2]));
    }

    #[test]
    fn candidate_sweep_scales_with_the_viable_time_overlap() {
        const EVENTS: usize = 10_000;
        let left = (0..EVENTS)
            .map(|index| comparable(index, u64::try_from(index).unwrap() * 1_000))
            .collect::<Vec<_>>();
        let right = (0..EVENTS)
            .map(|index| comparable(index, u64::try_from(index).unwrap() * 1_000 + 5))
            .collect::<Vec<_>>();

        let candidates = correlation_candidates(&left, &right, 10);
        assert_eq!(candidates.len(), EVENTS);
        assert!(
            candidates
                .iter()
                .enumerate()
                .all(|(index, candidate)| candidate.left == index && candidate.right == index)
        );
    }
}

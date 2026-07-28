//! Bounded route observation and deterministic per-hop evidence.
//!
//! `skbx-route` deliberately separates wire observations from enrichment and
//! inference. A non-responsive hop is unknown, not a drop verdict, and public
//! metadata never becomes proof of what a transit router did with a packet.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const ROUTE_CONTRACT_VERSION: &str = "routeq/0.1.0";
pub const DEFAULT_MAX_HOPS: u8 = 20;
pub const DEFAULT_PROBES_PER_HOP: u8 = 2;
pub const DEFAULT_TIMEOUT_MS: u64 = 500;
pub const DEFAULT_MAX_DURATION_MS: u64 = 30_000;
pub const DEFAULT_DESTINATION_PORT: u16 = 33_434;
pub const MAX_HOPS: u8 = 64;
pub const MAX_PROBES_PER_HOP: u8 = 5;
pub const MAX_TIMEOUT_MS: u64 = 5_000;
pub const MAX_DURATION_MS: u64 = 120_000;
pub const MAX_PACKETS: u16 = 256;

const UNKNOWN_DOSSIER_FIELDS: &[&str] = &[
    "reverse_dns",
    "network_prefix",
    "origin_asn",
    "organization",
    "rpki_state",
    "location_hint",
    "mpls_labels",
    "remote_forwarding_decision",
];

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("invalid plan: {0}")]
    InvalidPlan(String),
    #[error("could not resolve an IPv4 address for {0}")]
    NoIpv4Address(String),
    #[error("routeq stream is invalid: {0}")]
    InvalidStream(String),
    #[error("live UDP route observation requires Linux")]
    UnsupportedPlatform,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("socket error: {0}")]
    Socket(#[from] nix::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeProtocol {
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbePlan {
    pub schema: String,
    pub target: String,
    pub protocol: ProbeProtocol,
    pub destination_port: u16,
    pub max_hops: u8,
    pub probes_per_hop: u8,
    pub timeout_ms: u64,
    pub max_duration_ms: u64,
    pub max_packets: u16,
    pub flow_strategy: String,
    pub active_enrichment: bool,
}

impl ProbePlan {
    pub fn bounded_udp(
        target: impl Into<String>,
        destination_port: u16,
        max_hops: u8,
        probes_per_hop: u8,
        timeout_ms: u64,
        max_duration_ms: u64,
    ) -> Result<Self, RouteError> {
        let target = target.into();
        if target.trim().is_empty() || target.len() > 253 {
            return Err(RouteError::InvalidPlan(
                "target must contain between 1 and 253 bytes".into(),
            ));
        }
        if target.chars().any(char::is_whitespace) {
            return Err(RouteError::InvalidPlan(
                "target must not contain whitespace".into(),
            ));
        }
        if destination_port == 0 {
            return Err(RouteError::InvalidPlan(
                "destination_port must be non-zero".into(),
            ));
        }
        if max_hops == 0 || max_hops > MAX_HOPS {
            return Err(RouteError::InvalidPlan(format!(
                "max_hops must be between 1 and {MAX_HOPS}"
            )));
        }
        if probes_per_hop == 0 || probes_per_hop > MAX_PROBES_PER_HOP {
            return Err(RouteError::InvalidPlan(format!(
                "probes_per_hop must be between 1 and {MAX_PROBES_PER_HOP}"
            )));
        }
        if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
            return Err(RouteError::InvalidPlan(format!(
                "timeout_ms must be between 1 and {MAX_TIMEOUT_MS}"
            )));
        }
        if max_duration_ms == 0 || max_duration_ms > MAX_DURATION_MS {
            return Err(RouteError::InvalidPlan(format!(
                "max_duration_ms must be between 1 and {MAX_DURATION_MS}"
            )));
        }
        let max_packets = u16::from(max_hops) * u16::from(probes_per_hop);
        if max_packets > MAX_PACKETS {
            return Err(RouteError::InvalidPlan(format!(
                "max_hops × probes_per_hop must not exceed {MAX_PACKETS}"
            )));
        }

        Ok(Self {
            schema: ROUTE_CONTRACT_VERSION.into(),
            target,
            protocol: ProbeProtocol::Udp,
            destination_port,
            max_hops,
            probes_per_hop,
            timeout_ms,
            max_duration_ms,
            max_packets,
            flow_strategy: "fixed_five_tuple".into(),
            active_enrichment: false,
        })
    }

    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("ProbePlan serialization is infallible");
        short_handle("plan", &bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Observed,
    Enriched,
    Correlated,
    Candidate,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceClaim {
    pub field: String,
    pub value: String,
    pub level: EvidenceLevel,
    pub source: String,
    pub basis: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopDossier {
    #[serde(default)]
    pub claims: Vec<EvidenceClaim>,
    pub unresolved: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    TimeExceeded,
    DestinationReached,
    Unreachable,
    OtherIcmp,
    Timeout,
    LocalError,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeObservation {
    pub sequence: u32,
    pub outcome: ProbeOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopObservation {
    pub handle: String,
    pub ttl: u8,
    pub probes: Vec<ProbeObservation>,
    pub dossier: HopDossier,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibilityBoundary {
    pub local_probe: EvidenceLevel,
    pub transit_forwarding: EvidenceLevel,
    pub target_processing: EvidenceLevel,
    pub statement: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    DestinationReached,
    MaxHops,
    DurationBudget,
    DemoComplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReliability {
    pub planned_packets: u16,
    pub attempted_packets: u16,
    pub sent_packets: u16,
    pub replies: u16,
    pub timeouts: u16,
    pub local_errors: u16,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum RouteRecord {
    TraceStart {
        schema: String,
        trace_id: String,
        started_unix_ns: u64,
        target_ip: Ipv4Addr,
        plan: ProbePlan,
        visibility: VisibilityBoundary,
    },
    Hop {
        schema: String,
        trace_id: String,
        hop: HopObservation,
    },
    TraceEnd {
        schema: String,
        trace_id: String,
        ended_unix_ns: u64,
        destination_reached: bool,
        stop_reason: StopReason,
        reliability: ProbeReliability,
    },
}

impl RouteRecord {
    pub fn trace_id(&self) -> &str {
        match self {
            Self::TraceStart { trace_id, .. }
            | Self::Hop { trace_id, .. }
            | Self::TraceEnd { trace_id, .. } => trace_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySummary {
    pub schema: String,
    pub trace_id: String,
    pub target: String,
    pub target_ip: Ipv4Addr,
    pub hops: usize,
    pub responsive_hops: usize,
    pub destination_reached: bool,
    pub complete: bool,
    pub stop_reason: StopReason,
    pub reliability: ProbeReliability,
    pub route_handle: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopExplanation {
    pub schema: String,
    pub trace_id: String,
    pub target: String,
    pub target_ip: Ipv4Addr,
    pub hop: HopObservation,
    pub boundary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichmentReport {
    pub provider: String,
    pub eligible_addresses: u16,
    pub skipped_non_global_addresses: u16,
    pub lookups_attempted: u16,
    pub lookups_succeeded: u16,
    pub lookups_failed: u16,
    pub lookup_budget_exhausted: bool,
    pub duration_exhausted: bool,
}

pub fn describe(version: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "skbx-route",
        "version": version,
        "contract_version": ROUTE_CONTRACT_VERSION,
        "purpose": "bounded route observation with per-hop evidence dossiers",
        "commands": {
            "describe": "emit this machine-readable contract",
            "plan": "validate and print the complete probe budget without sending packets",
            "trace": "run a bounded rootless Linux UDP route observation",
            "enrich": "add sourced RIPEstat prefix, origin ASN, and RPKI claims without probing hops",
            "demo": "emit a deterministic documentation-range routeq stream",
            "replay": "summarize a routeq stream deterministically",
            "explain": "retrieve a hop dossier by stable handle"
        },
        "defaults": {
            "max_hops": DEFAULT_MAX_HOPS,
            "probes_per_hop": DEFAULT_PROBES_PER_HOP,
            "timeout_ms": DEFAULT_TIMEOUT_MS,
            "max_duration_ms": DEFAULT_MAX_DURATION_MS,
            "destination_port": DEFAULT_DESTINATION_PORT
        },
        "limits": {
            "max_hops": MAX_HOPS,
            "max_probes_per_hop": MAX_PROBES_PER_HOP,
            "max_packets": MAX_PACKETS,
            "max_timeout_ms": MAX_TIMEOUT_MS,
            "max_duration_ms": MAX_DURATION_MS
        },
        "evidence_levels": [
            "observed",
            "enriched",
            "correlated",
            "candidate",
            "unknown"
        ],
        "invariants": [
            "plan never sends a packet",
            "trace keeps one UDP five-tuple to reduce per-flow load-balancing artifacts",
            "every live run is packet-, hop-, timeout-, and duration-bounded",
            "a silent hop is unknown and is not labeled as a drop",
            "no port scanning or service enumeration is performed",
            "enrichment is opt-in, HTTPS-only, and bounded independently from route probing",
            "enrichment skips private and special-purpose responder addresses",
            "public metadata is enrichment, never transit forwarding evidence",
            "a trace_end footer is required for a complete stream"
        ],
        "platform": {
            "live_trace": "Linux IPv4 with IP_RECVERR",
            "plan_replay_explain_demo": "portable"
        }
    })
}

#[derive(Debug, Deserialize)]
struct RipeStatEnvelope<T> {
    status: String,
    data: T,
}

#[derive(Debug, Deserialize)]
struct NetworkInfoData {
    #[serde(default)]
    asns: Vec<String>,
    prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RpkiValidationData {
    status: String,
}

/// Add passive routing context from RIPEstat without sending traffic to any hop.
///
/// The lookup budget counts every HTTP request, including RPKI validation
/// requests, and the duration budget bounds the full operation.
pub async fn enrich_ripestat(
    records: &mut [RouteRecord],
    max_lookups: u16,
    request_timeout_ms: u64,
    max_duration_ms: u64,
) -> Result<EnrichmentReport, RouteError> {
    if max_lookups == 0 || max_lookups > 128 {
        return Err(RouteError::InvalidPlan(
            "max_lookups must be between 1 and 128".into(),
        ));
    }
    if request_timeout_ms == 0 || request_timeout_ms > 10_000 {
        return Err(RouteError::InvalidPlan(
            "request_timeout_ms must be between 1 and 10000".into(),
        ));
    }
    if max_duration_ms == 0 || max_duration_ms > MAX_DURATION_MS {
        return Err(RouteError::InvalidPlan(format!(
            "max_duration_ms must be between 1 and {MAX_DURATION_MS}"
        )));
    }

    let addresses = records
        .iter()
        .filter_map(|record| match record {
            RouteRecord::Hop { hop, .. } => Some(
                hop.probes
                    .iter()
                    .filter_map(|probe| probe.responder)
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect::<BTreeSet<_>>();
    let eligible = addresses
        .iter()
        .copied()
        .filter(|address| is_public_routable(*address))
        .collect::<Vec<_>>();
    let skipped = addresses.len().saturating_sub(eligible.len()) as u16;
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_millis(request_timeout_ms))
        .user_agent("skbx-route/0.1")
        .build()?;
    let started = Instant::now();
    let duration_budget = Duration::from_millis(max_duration_ms);
    let mut report = EnrichmentReport {
        provider: "RIPEstat".into(),
        eligible_addresses: eligible.len() as u16,
        skipped_non_global_addresses: skipped,
        lookups_attempted: 0,
        lookups_succeeded: 0,
        lookups_failed: 0,
        lookup_budget_exhausted: false,
        duration_exhausted: false,
    };
    let mut claims_by_address = BTreeMap::new();
    let mut rpki_by_origin = BTreeMap::<(String, String), Option<String>>::new();

    for address in eligible {
        if report.lookups_attempted >= max_lookups || started.elapsed() >= duration_budget {
            report.lookup_budget_exhausted = report.lookups_attempted >= max_lookups;
            report.duration_exhausted = started.elapsed() >= duration_budget;
            break;
        }
        report.lookups_attempted += 1;
        let remaining = duration_budget.saturating_sub(started.elapsed());
        let network_result = tokio::time::timeout(remaining, async {
            client
                .get("https://stat.ripe.net/data/network-info/data.json")
                .query(&[
                    ("resource", address.to_string()),
                    ("sourceapp", "skbx-route".into()),
                ])
                .send()
                .await?
                .error_for_status()?
                .json::<RipeStatEnvelope<NetworkInfoData>>()
                .await
        })
        .await;

        let mut claims = Vec::new();
        match network_result {
            Ok(Ok(envelope)) if envelope.status == "ok" => {
                report.lookups_succeeded += 1;
                if let Some(prefix) = envelope
                    .data
                    .prefix
                    .filter(|prefix| !prefix.trim().is_empty())
                {
                    claims.push(ripe_claim(
                        "network_prefix",
                        prefix.clone(),
                        "RIPEstat network-info v1.1",
                        "prefix and origin are based on RIPE RIS routing data",
                    ));
                    if !envelope.data.asns.is_empty() {
                        let asns = envelope
                            .data
                            .asns
                            .iter()
                            .map(|asn| format!("AS{asn}"))
                            .collect::<Vec<_>>()
                            .join(",");
                        claims.push(ripe_claim(
                            "origin_asn",
                            asns,
                            "RIPEstat network-info v1.1",
                            "origin ASNs are based on RIPE RIS routing data",
                        ));
                    }

                    for asn in envelope.data.asns {
                        let rpki_key = (asn.clone(), prefix.clone());
                        if let Some(status) = rpki_by_origin.get(&rpki_key) {
                            if let Some(status) = status {
                                claims.push(ripe_claim(
                                    "rpki_state",
                                    format!("AS{asn}:{status}"),
                                    "RIPEstat rpki-validation v0.3",
                                    "state validates this origin ASN and prefix pair",
                                ));
                            }
                            continue;
                        }
                        if report.lookups_attempted >= max_lookups
                            || started.elapsed() >= duration_budget
                        {
                            report.lookup_budget_exhausted =
                                report.lookups_attempted >= max_lookups;
                            report.duration_exhausted = started.elapsed() >= duration_budget;
                            break;
                        }
                        report.lookups_attempted += 1;
                        let remaining = duration_budget.saturating_sub(started.elapsed());
                        let rpki_result = tokio::time::timeout(remaining, async {
                            client
                                .get("https://stat.ripe.net/data/rpki-validation/data.json")
                                .query(&[
                                    ("resource", asn.clone()),
                                    ("prefix", prefix.clone()),
                                    ("sourceapp", "skbx-route".into()),
                                ])
                                .send()
                                .await?
                                .error_for_status()?
                                .json::<RipeStatEnvelope<RpkiValidationData>>()
                                .await
                        })
                        .await;
                        match rpki_result {
                            Ok(Ok(envelope)) if envelope.status == "ok" => {
                                report.lookups_succeeded += 1;
                                rpki_by_origin.insert(rpki_key, Some(envelope.data.status.clone()));
                                claims.push(ripe_claim(
                                    "rpki_state",
                                    format!("AS{}:{}", asn, envelope.data.status),
                                    "RIPEstat rpki-validation v0.3",
                                    "state validates this origin ASN and prefix pair",
                                ));
                            }
                            Ok(Ok(_)) | Ok(Err(_)) => {
                                report.lookups_failed += 1;
                                rpki_by_origin.insert(rpki_key, None);
                            }
                            Err(_) => {
                                report.lookups_failed += 1;
                                report.duration_exhausted = true;
                                rpki_by_origin.insert(rpki_key, None);
                                break;
                            }
                        }
                    }
                }
            }
            Ok(Ok(_)) | Ok(Err(_)) => {
                report.lookups_failed += 1;
            }
            Err(_) => {
                report.lookups_failed += 1;
                report.duration_exhausted = true;
            }
        }
        if claims.is_empty() {
            claims.push(EvidenceClaim {
                field: "routing_metadata".into(),
                value: "lookup returned no usable route claim".into(),
                level: EvidenceLevel::Unknown,
                source: "RIPEstat".into(),
                basis: "a failed or empty enrichment response says nothing about forwarding".into(),
            });
        }
        claims_by_address.insert(address, claims);
    }

    for record in records {
        let RouteRecord::Hop { hop, .. } = record else {
            continue;
        };
        let responders = hop
            .probes
            .iter()
            .filter_map(|probe| probe.responder)
            .collect::<BTreeSet<_>>();
        for responder in responders {
            if let Some(claims) = claims_by_address.get(&responder) {
                for claim in claims {
                    if !hop.dossier.claims.iter().any(|existing| {
                        existing.field == claim.field
                            && existing.value == claim.value
                            && existing.source == claim.source
                    }) {
                        hop.dossier.claims.push(claim.clone());
                    }
                }
            } else if !is_public_routable(responder)
                && !hop
                    .dossier
                    .claims
                    .iter()
                    .any(|claim| claim.field == "address_scope")
            {
                hop.dossier.claims.push(EvidenceClaim {
                    field: "address_scope".into(),
                    value: address_scope(responder).into(),
                    level: EvidenceLevel::Enriched,
                    source: "local_address_classifier".into(),
                    basis: "deterministic IPv4 special-purpose range classification".into(),
                });
            }
        }
        let resolved = hop
            .dossier
            .claims
            .iter()
            .map(|claim| claim.field.as_str())
            .collect::<BTreeSet<_>>();
        hop.dossier
            .unresolved
            .retain(|field| !resolved.contains(field.as_str()));
    }

    Ok(report)
}

fn ripe_claim(field: &str, value: String, source: &str, basis: &str) -> EvidenceClaim {
    EvidenceClaim {
        field: field.into(),
        value,
        level: EvidenceLevel::Enriched,
        source: source.into(),
        basis: basis.into(),
    }
}

fn is_public_routable(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_unspecified()
        || address.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240)
}

fn address_scope(address: Ipv4Addr) -> &'static str {
    if address.is_private() {
        "private"
    } else if address.is_loopback() {
        "loopback"
    } else if address.is_link_local() {
        "link_local"
    } else if address.is_documentation() {
        "documentation"
    } else if address.is_multicast() {
        "multicast"
    } else if address.is_unspecified() {
        "unspecified"
    } else {
        "special_purpose"
    }
}

pub fn read_records(reader: impl Read) -> Result<Vec<RouteRecord>, RouteError> {
    let mut records = Vec::new();
    for (index, line) in BufReader::new(reader).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str(&line)
            .map_err(|error| RouteError::InvalidStream(format!("line {}: {error}", index + 1)))?;
        records.push(record);
    }
    if records.is_empty() {
        return Err(RouteError::InvalidStream("stream is empty".into()));
    }
    Ok(records)
}

pub fn replay(records: &[RouteRecord]) -> Result<ReplaySummary, RouteError> {
    let (trace_id, target, target_ip, plan) = match records.first() {
        Some(RouteRecord::TraceStart {
            schema,
            trace_id,
            target_ip,
            plan,
            ..
        }) if schema == ROUTE_CONTRACT_VERSION => (
            trace_id.clone(),
            plan.target.clone(),
            *target_ip,
            plan.clone(),
        ),
        Some(RouteRecord::TraceStart { schema, .. }) => {
            return Err(RouteError::InvalidStream(format!(
                "unsupported contract {schema}"
            )));
        }
        _ => {
            return Err(RouteError::InvalidStream(
                "first record must be trace_start".into(),
            ));
        }
    };

    let mut hops = Vec::new();
    let mut previous_ttl = 0;
    for record in records.iter().skip(1).take(records.len().saturating_sub(2)) {
        if record.trace_id() != trace_id {
            return Err(RouteError::InvalidStream(
                "records contain more than one trace_id".into(),
            ));
        }
        let RouteRecord::Hop { schema, hop, .. } = record else {
            return Err(RouteError::InvalidStream(
                "only hop records may appear between trace_start and trace_end".into(),
            ));
        };
        if schema != ROUTE_CONTRACT_VERSION {
            return Err(RouteError::InvalidStream(format!(
                "unsupported contract {schema}"
            )));
        }
        if hop.ttl <= previous_ttl || hop.ttl > plan.max_hops {
            return Err(RouteError::InvalidStream(format!(
                "hop TTL {} is outside the strictly increasing plan",
                hop.ttl
            )));
        }
        if hop.probes.is_empty() || hop.probes.len() > usize::from(plan.probes_per_hop) {
            return Err(RouteError::InvalidStream(format!(
                "hop {} has an invalid probe count",
                hop.ttl
            )));
        }
        if hop.handle != hop_handle(&trace_id, hop.ttl, &hop.probes) {
            return Err(RouteError::InvalidStream(format!(
                "hop {} has an invalid handle",
                hop.ttl
            )));
        }
        previous_ttl = hop.ttl;
        hops.push(hop);
    }

    let (destination_reached, stop_reason, reliability) = match records.last() {
        Some(RouteRecord::TraceEnd {
            schema,
            trace_id: footer_trace_id,
            destination_reached,
            stop_reason,
            reliability,
            ..
        }) if schema == ROUTE_CONTRACT_VERSION && footer_trace_id == &trace_id => {
            (*destination_reached, *stop_reason, reliability.clone())
        }
        Some(RouteRecord::TraceEnd { schema, .. }) => {
            if schema == ROUTE_CONTRACT_VERSION {
                return Err(RouteError::InvalidStream(
                    "records contain more than one trace_id".into(),
                ));
            }
            return Err(RouteError::InvalidStream(format!(
                "unsupported contract {schema}"
            )));
        }
        _ => {
            return Err(RouteError::InvalidStream(
                "trace_end footer is missing".into(),
            ));
        }
    };

    let attempted_packets = hops.iter().map(|hop| hop.probes.len() as u16).sum::<u16>();
    let replies = hops
        .iter()
        .flat_map(|hop| &hop.probes)
        .filter(|probe| {
            !matches!(
                probe.outcome,
                ProbeOutcome::Timeout | ProbeOutcome::LocalError
            )
        })
        .count() as u16;
    let timeouts = hops
        .iter()
        .flat_map(|hop| &hop.probes)
        .filter(|probe| probe.outcome == ProbeOutcome::Timeout)
        .count() as u16;
    let local_errors = hops
        .iter()
        .flat_map(|hop| &hop.probes)
        .filter(|probe| probe.outcome == ProbeOutcome::LocalError)
        .count() as u16;
    let observed_destination = hops.iter().flat_map(|hop| &hop.probes).any(|probe| {
        probe.outcome == ProbeOutcome::DestinationReached && probe.responder == Some(target_ip)
    });
    if reliability.planned_packets != plan.max_packets
        || reliability.attempted_packets != attempted_packets
        || reliability.replies != replies
        || reliability.timeouts != timeouts
        || reliability.local_errors != local_errors
        || reliability.sent_packets > reliability.attempted_packets
        || destination_reached != observed_destination
    {
        return Err(RouteError::InvalidStream(
            "trace_end reliability counters do not match hop observations".into(),
        ));
    }

    let responsive_hops = hops
        .iter()
        .filter(|hop| {
            hop.probes
                .iter()
                .any(|probe| probe.outcome != ProbeOutcome::Timeout)
        })
        .count();
    let route_material = hops
        .iter()
        .map(|hop| hop.handle.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    Ok(ReplaySummary {
        schema: ROUTE_CONTRACT_VERSION.into(),
        trace_id,
        target,
        target_ip,
        hops: hops.len(),
        responsive_hops,
        destination_reached,
        complete: reliability.complete,
        stop_reason,
        reliability,
        route_handle: short_handle("route", route_material.as_bytes()),
    })
}

pub fn explain(records: &[RouteRecord], handle: &str) -> Result<HopExplanation, RouteError> {
    let (trace_id, target, target_ip) = match records.first() {
        Some(RouteRecord::TraceStart {
            trace_id,
            target_ip,
            plan,
            ..
        }) => (trace_id.clone(), plan.target.clone(), *target_ip),
        _ => {
            return Err(RouteError::InvalidStream(
                "first record must be trace_start".into(),
            ));
        }
    };
    let hop = records.iter().find_map(|record| match record {
        RouteRecord::Hop { hop, .. } if hop.handle == handle => Some(hop.clone()),
        _ => None,
    });
    let hop =
        hop.ok_or_else(|| RouteError::InvalidStream(format!("hop handle {handle} was not found")))?;

    Ok(HopExplanation {
        schema: ROUTE_CONTRACT_VERSION.into(),
        trace_id,
        target,
        target_ip,
        hop,
        boundary: "The dossier proves only returned probe evidence and named enrichment sources. It does not prove an uninstrumented router's forwarding decision.".into(),
    })
}

pub fn demo_records() -> Vec<RouteRecord> {
    let plan = ProbePlan::bounded_udp("example.net", 33_434, 4, 2, 500, 5_000)
        .expect("static demo plan is valid");
    let started_unix_ns = 1_700_000_000_000_000_000;
    let target_ip = Ipv4Addr::new(203, 0, 113, 80);
    let trace_id = trace_id(&plan, target_ip, started_unix_ns);
    let mut records = vec![RouteRecord::TraceStart {
        schema: ROUTE_CONTRACT_VERSION.into(),
        trace_id: trace_id.clone(),
        started_unix_ns,
        target_ip,
        plan: plan.clone(),
        visibility: visibility_boundary(),
    }];

    let hops = vec![
        demo_hop(
            &trace_id,
            1,
            Ipv4Addr::new(192, 0, 2, 1),
            &[1_100_000, 1_260_000],
            ProbeOutcome::TimeExceeded,
            vec![
                enriched_claim(
                    "reverse_dns",
                    "gateway.lab.invalid",
                    "fixture/local-inventory",
                ),
                enriched_claim("organization", "Example lab", "fixture/local-inventory"),
            ],
        ),
        demo_hop(
            &trace_id,
            2,
            Ipv4Addr::new(198, 51, 100, 14),
            &[8_900_000, 9_240_000],
            ProbeOutcome::TimeExceeded,
            vec![
                enriched_claim("network_prefix", "198.51.100.0/24", "fixture/route-table"),
                enriched_claim("origin_asn", "AS64500", "fixture/route-table"),
                EvidenceClaim {
                    field: "location_hint".into(),
                    value: "exchange-edge".into(),
                    level: EvidenceLevel::Candidate,
                    source: "fixture/router-label".into(),
                    basis: "router labels are hints, not authoritative geolocation".into(),
                },
            ],
        ),
        timeout_hop(&trace_id, 3, 2),
        demo_hop(
            &trace_id,
            4,
            target_ip,
            &[20_100_000, 20_420_000],
            ProbeOutcome::DestinationReached,
            vec![enriched_claim(
                "network_prefix",
                "203.0.113.0/24",
                "fixture/route-table",
            )],
        ),
    ];
    records.extend(hops.into_iter().map(|hop| RouteRecord::Hop {
        schema: ROUTE_CONTRACT_VERSION.into(),
        trace_id: trace_id.clone(),
        hop,
    }));
    records.push(RouteRecord::TraceEnd {
        schema: ROUTE_CONTRACT_VERSION.into(),
        trace_id,
        ended_unix_ns: started_unix_ns + 50_000_000,
        destination_reached: true,
        stop_reason: StopReason::DemoComplete,
        reliability: ProbeReliability {
            planned_packets: plan.max_packets,
            attempted_packets: 8,
            sent_packets: 8,
            replies: 6,
            timeouts: 2,
            local_errors: 0,
            complete: true,
        },
    });
    records
}

fn demo_hop(
    trace_id: &str,
    ttl: u8,
    responder: Ipv4Addr,
    rtts: &[u64],
    outcome: ProbeOutcome,
    mut claims: Vec<EvidenceClaim>,
) -> HopObservation {
    let icmp = match outcome {
        ProbeOutcome::TimeExceeded => (11, 0),
        ProbeOutcome::DestinationReached => (3, 3),
        _ => (3, 0),
    };
    let probes = rtts
        .iter()
        .enumerate()
        .map(|(index, rtt)| ProbeObservation {
            sequence: u32::from(ttl) * 10 + index as u32,
            outcome,
            responder: Some(responder),
            rtt_ns: Some(*rtt),
            icmp_type: Some(icmp.0),
            icmp_code: Some(icmp.1),
            errno: Some(if outcome == ProbeOutcome::DestinationReached {
                libc::ECONNREFUSED as u32
            } else {
                libc::EHOSTUNREACH as u32
            }),
        })
        .collect::<Vec<_>>();
    claims.insert(0, observed_responder_claim(responder));
    let handle = hop_handle(trace_id, ttl, &probes);
    let resolved = claims
        .iter()
        .map(|claim| claim.field.as_str())
        .collect::<BTreeSet<_>>();
    let unresolved = UNKNOWN_DOSSIER_FIELDS
        .iter()
        .filter(|field| !resolved.contains(**field))
        .map(|field| (*field).to_owned())
        .collect();
    HopObservation {
        handle,
        ttl,
        probes,
        dossier: HopDossier { claims, unresolved },
    }
}

fn timeout_hop(trace_id: &str, ttl: u8, probes_per_hop: u8) -> HopObservation {
    let probes = (0..probes_per_hop)
        .map(|index| ProbeObservation {
            sequence: u32::from(ttl) * 10 + u32::from(index),
            outcome: ProbeOutcome::Timeout,
            responder: None,
            rtt_ns: None,
            icmp_type: None,
            icmp_code: None,
            errno: None,
        })
        .collect::<Vec<_>>();
    HopObservation {
        handle: hop_handle(trace_id, ttl, &probes),
        ttl,
        probes,
        dossier: HopDossier {
            claims: vec![EvidenceClaim {
                field: "response".into(),
                value: "no ICMP error received within the bounded timeout".into(),
                level: EvidenceLevel::Unknown,
                source: "local_udp_probe".into(),
                basis: "silence does not identify filtering, forwarding, or loss".into(),
            }],
            unresolved: UNKNOWN_DOSSIER_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
        },
    }
}

fn enriched_claim(field: &str, value: &str, source: &str) -> EvidenceClaim {
    EvidenceClaim {
        field: field.into(),
        value: value.into(),
        level: EvidenceLevel::Enriched,
        source: source.into(),
        basis: "value supplied by the named metadata source".into(),
    }
}

fn observed_responder_claim(address: Ipv4Addr) -> EvidenceClaim {
    EvidenceClaim {
        field: "response_address".into(),
        value: address.to_string(),
        level: EvidenceLevel::Observed,
        source: "local_udp_probe".into(),
        basis: "Linux IP_RECVERR ICMP offender address".into(),
    }
}

fn visibility_boundary() -> VisibilityBoundary {
    VisibilityBoundary {
        local_probe: EvidenceLevel::Observed,
        transit_forwarding: EvidenceLevel::Unknown,
        target_processing: EvidenceLevel::Unknown,
        statement: "Replies prove what the local socket received. They do not expose an uninstrumented router's forwarding decision or the target application's processing.".into(),
    }
}

fn trace_id(plan: &ProbePlan, target_ip: Ipv4Addr, started_unix_ns: u64) -> String {
    let material = serde_json::to_vec(&(plan, target_ip, started_unix_ns))
        .expect("trace identity serialization is infallible");
    short_handle("trace", &material)
}

fn hop_handle(trace_id: &str, ttl: u8, probes: &[ProbeObservation]) -> String {
    let material = serde_json::to_vec(&(trace_id, ttl, probes))
        .expect("hop identity serialization is infallible");
    short_handle("hop", &material)
}

fn short_handle(kind: &str, material: &[u8]) -> String {
    format!("{kind}:{}", &blake3::hash(material).to_hex()[..24])
}

#[cfg(target_os = "linux")]
pub fn trace_udp(plan: &ProbePlan) -> Result<Vec<RouteRecord>, RouteError> {
    use nix::poll::{PollFd, PollFlags, poll};
    use nix::sys::socket::{
        ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, setsockopt, sockopt,
    };
    use std::io::IoSliceMut;
    use std::os::fd::{AsFd, AsRawFd};

    let target_ip = (plan.target.as_str(), plan.destination_port)
        .to_socket_addrs()?
        .find_map(|address| match address {
            SocketAddr::V4(address) => Some(*address.ip()),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| RouteError::NoIpv4Address(plan.target.clone()))?;
    let target = SocketAddr::from((target_ip, plan.destination_port));
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(target)?;
    setsockopt(&socket, sockopt::Ipv4RecvErr, &true)?;

    let started_unix_ns = unix_time_ns();
    let id = trace_id(plan, target_ip, started_unix_ns);
    let mut records = vec![RouteRecord::TraceStart {
        schema: ROUTE_CONTRACT_VERSION.into(),
        trace_id: id.clone(),
        started_unix_ns,
        target_ip,
        plan: plan.clone(),
        visibility: visibility_boundary(),
    }];
    let run_started = Instant::now();
    let duration_budget = Duration::from_millis(plan.max_duration_ms);
    let mut sent_packets = 0u16;
    let mut attempted_packets = 0u16;
    let mut replies = 0u16;
    let mut timeouts = 0u16;
    let mut local_errors = 0u16;
    let mut destination_reached = false;
    let mut duration_exhausted = false;
    let mut sequence = 0u32;

    'hops: for ttl in 1..=plan.max_hops {
        if run_started.elapsed() >= duration_budget {
            duration_exhausted = true;
            break;
        }
        socket.set_ttl(u32::from(ttl))?;
        let mut observations = Vec::with_capacity(usize::from(plan.probes_per_hop));
        for _ in 0..plan.probes_per_hop {
            if run_started.elapsed() >= duration_budget {
                duration_exhausted = true;
                break;
            }
            sequence += 1;
            attempted_packets += 1;
            let payload = sequence.to_be_bytes();
            let probe_started = Instant::now();
            let observation = match socket.send(&payload) {
                Ok(_) => {
                    sent_packets += 1;
                    let remaining = duration_budget.saturating_sub(run_started.elapsed());
                    let timeout = remaining.min(Duration::from_millis(plan.timeout_ms));
                    let timeout_ms = u16::try_from(timeout.as_millis().max(1)).unwrap_or(u16::MAX);
                    let mut descriptors = [PollFd::new(socket.as_fd(), PollFlags::POLLERR)];
                    if poll(&mut descriptors, timeout_ms)? == 0 {
                        timeouts += 1;
                        ProbeObservation {
                            sequence,
                            outcome: ProbeOutcome::Timeout,
                            responder: None,
                            rtt_ns: None,
                            icmp_type: None,
                            icmp_code: None,
                            errno: None,
                        }
                    } else {
                        let mut bytes = [0u8; 64];
                        let mut vectors = [IoSliceMut::new(&mut bytes)];
                        let mut control =
                            nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in);
                        let message = recvmsg::<SockaddrStorage>(
                            socket.as_raw_fd(),
                            &mut vectors,
                            Some(&mut control),
                            MsgFlags::MSG_ERRQUEUE,
                        )?;
                        let mut parsed = None;
                        for control_message in message.cmsgs()? {
                            if let ControlMessageOwned::Ipv4RecvErr(error, offender) =
                                control_message
                            {
                                let responder = offender.map(|address| {
                                    Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))
                                });
                                let outcome = classify_icmp(
                                    error.ee_origin,
                                    error.ee_type,
                                    error.ee_code,
                                    responder,
                                    target_ip,
                                );
                                parsed = Some(ProbeObservation {
                                    sequence,
                                    outcome,
                                    responder,
                                    rtt_ns: Some(
                                        probe_started.elapsed().as_nanos().min(u128::from(u64::MAX))
                                            as u64,
                                    ),
                                    icmp_type: Some(error.ee_type),
                                    icmp_code: Some(error.ee_code),
                                    errno: Some(error.ee_errno),
                                });
                                break;
                            }
                        }
                        match parsed {
                            Some(observation) => {
                                replies += 1;
                                if observation.outcome == ProbeOutcome::DestinationReached {
                                    destination_reached = true;
                                }
                                observation
                            }
                            None => {
                                local_errors += 1;
                                ProbeObservation {
                                    sequence,
                                    outcome: ProbeOutcome::LocalError,
                                    responder: None,
                                    rtt_ns: Some(
                                        probe_started.elapsed().as_nanos().min(u128::from(u64::MAX))
                                            as u64,
                                    ),
                                    icmp_type: None,
                                    icmp_code: None,
                                    errno: None,
                                }
                            }
                        }
                    }
                }
                Err(error) => {
                    local_errors += 1;
                    ProbeObservation {
                        sequence,
                        outcome: ProbeOutcome::LocalError,
                        responder: None,
                        rtt_ns: None,
                        icmp_type: None,
                        icmp_code: None,
                        errno: error.raw_os_error().map(|value| value as u32),
                    }
                }
            };
            observations.push(observation);
        }

        if observations.is_empty() {
            break 'hops;
        }
        let hop = live_hop(&id, ttl, observations);
        records.push(RouteRecord::Hop {
            schema: ROUTE_CONTRACT_VERSION.into(),
            trace_id: id.clone(),
            hop,
        });
        if destination_reached {
            break 'hops;
        }
    }

    let stop_reason = if destination_reached {
        StopReason::DestinationReached
    } else if duration_exhausted {
        StopReason::DurationBudget
    } else {
        StopReason::MaxHops
    };
    records.push(RouteRecord::TraceEnd {
        schema: ROUTE_CONTRACT_VERSION.into(),
        trace_id: id,
        ended_unix_ns: unix_time_ns(),
        destination_reached,
        stop_reason,
        reliability: ProbeReliability {
            planned_packets: plan.max_packets,
            attempted_packets,
            sent_packets,
            replies,
            timeouts,
            local_errors,
            complete: true,
        },
    });
    Ok(records)
}

#[cfg(not(target_os = "linux"))]
pub fn trace_udp(_plan: &ProbePlan) -> Result<Vec<RouteRecord>, RouteError> {
    Err(RouteError::UnsupportedPlatform)
}

fn live_hop(trace_id: &str, ttl: u8, probes: Vec<ProbeObservation>) -> HopObservation {
    let responders = probes
        .iter()
        .filter_map(|probe| probe.responder)
        .collect::<BTreeSet<_>>();
    let mut claims = responders
        .into_iter()
        .map(observed_responder_claim)
        .collect::<Vec<_>>();
    if claims.is_empty() {
        claims.push(EvidenceClaim {
            field: "response".into(),
            value: "no attributable ICMP offender address observed".into(),
            level: EvidenceLevel::Unknown,
            source: "local_udp_probe".into(),
            basis: "silence or a local socket error cannot identify remote behavior".into(),
        });
    }
    HopObservation {
        handle: hop_handle(trace_id, ttl, &probes),
        ttl,
        probes,
        dossier: HopDossier {
            claims,
            unresolved: UNKNOWN_DOSSIER_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
        },
    }
}

fn classify_icmp(
    origin: u8,
    icmp_type: u8,
    icmp_code: u8,
    responder: Option<Ipv4Addr>,
    target_ip: Ipv4Addr,
) -> ProbeOutcome {
    if origin != libc::SO_EE_ORIGIN_ICMP {
        return ProbeOutcome::LocalError;
    }
    match (icmp_type, icmp_code) {
        (11, _) => ProbeOutcome::TimeExceeded,
        (3, 3) if responder == Some(target_ip) => ProbeOutcome::DestinationReached,
        (3, _) => ProbeOutcome::Unreachable,
        _ => ProbeOutcome::OtherIcmp,
    }
}

fn unix_time_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_is_bounded_and_digest_is_stable() {
        let plan =
            ProbePlan::bounded_udp("example.com", 33_434, 20, 2, 500, 30_000).expect("valid plan");
        assert_eq!(plan.max_packets, 40);
        assert_eq!(plan.digest(), plan.digest());
        assert!(ProbePlan::bounded_udp("example.com", 33_434, 64, 5, 500, 30_000).is_err());
    }

    #[test]
    fn demo_replays_and_explains_deterministically() {
        let records = demo_records();
        let first = replay(&records).expect("replay demo");
        let second = replay(&records).expect("replay demo again");
        assert_eq!(first, second);
        assert_eq!(first.hops, 4);
        assert_eq!(first.responsive_hops, 3);
        assert!(first.destination_reached);
        assert!(first.complete);

        let handle = match &records[1] {
            RouteRecord::Hop { hop, .. } => hop.handle.clone(),
            _ => panic!("demo second record must be a hop"),
        };
        let explanation = explain(&records, &handle).expect("explain hop");
        assert_eq!(explanation.hop.ttl, 1);
        assert_eq!(
            explanation.hop.dossier.claims[0].level,
            EvidenceLevel::Observed
        );
    }

    #[test]
    fn missing_footer_is_explicitly_invalid() {
        let mut records = demo_records();
        records.pop();
        assert!(matches!(
            replay(&records),
            Err(RouteError::InvalidStream(message)) if message.contains("trace_end")
        ));
    }

    #[test]
    fn replay_rejects_record_order_and_counter_drift() {
        let mut reordered = demo_records();
        reordered.insert(2, reordered[0].clone());
        assert!(matches!(
            replay(&reordered),
            Err(RouteError::InvalidStream(message)) if message.contains("only hop records")
        ));

        let mut drifted = demo_records();
        if let Some(RouteRecord::TraceEnd { reliability, .. }) = drifted.last_mut() {
            reliability.replies += 1;
        }
        assert!(matches!(
            replay(&drifted),
            Err(RouteError::InvalidStream(message)) if message.contains("reliability counters")
        ));
    }

    #[test]
    fn destination_requires_the_target_as_offender() {
        let target = Ipv4Addr::new(203, 0, 113, 8);
        assert_eq!(
            classify_icmp(
                libc::SO_EE_ORIGIN_ICMP,
                3,
                3,
                Some(Ipv4Addr::new(192, 0, 2, 1)),
                target
            ),
            ProbeOutcome::Unreachable
        );
        assert_eq!(
            classify_icmp(libc::SO_EE_ORIGIN_ICMP, 3, 3, Some(target), target),
            ProbeOutcome::DestinationReached
        );
    }

    #[tokio::test]
    async fn enrichment_classifies_special_ranges_without_http() {
        let mut records = demo_records();
        let report = enrich_ripestat(&mut records, 8, 100, 1_000)
            .await
            .expect("classify documentation ranges");
        assert_eq!(report.eligible_addresses, 0);
        assert_eq!(report.lookups_attempted, 0);
        assert_eq!(report.skipped_non_global_addresses, 3);
        replay(&records).expect("enrichment preserves the route evidence stream");
        let first_hop = match &records[1] {
            RouteRecord::Hop { hop, .. } => hop,
            _ => panic!("demo second record must be a hop"),
        };
        assert!(
            first_hop
                .dossier
                .claims
                .iter()
                .any(|claim| claim.field == "address_scope")
        );
    }

    #[test]
    fn ripestat_supported_shapes_decode_without_coercion() {
        let network: RipeStatEnvelope<NetworkInfoData> = serde_json::from_str(
            r#"{"status":"ok","data":{"asns":["13335"],"prefix":"1.1.1.0/24"}}"#,
        )
        .expect("network-info response");
        assert_eq!(network.data.asns, ["13335"]);
        assert_eq!(network.data.prefix.as_deref(), Some("1.1.1.0/24"));

        let rpki: RipeStatEnvelope<RpkiValidationData> =
            serde_json::from_str(r#"{"status":"ok","data":{"status":"valid"}}"#)
                .expect("RPKI response");
        assert_eq!(rpki.data.status, "valid");
    }
}

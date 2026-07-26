//! Versioned contracts shared by the CLI, sensor and replay engine.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CONTRACT_VERSION: &str = "traceq/0.1.0";
pub const EVENT_SCHEMA: &str = "https://copyleftdev.github.io/skbx/schema/traceq-0.1.0.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Supported,
    Partial,
    Planned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub name: &'static str,
    pub status: CapabilityStatus,
    pub requires: &'static str,
    pub cost: &'static str,
    pub description: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Describe {
    pub name: &'static str,
    pub version: &'static str,
    pub contract_version: &'static str,
    pub purpose: &'static str,
    pub capabilities: Vec<Capability>,
    pub commands: BTreeMap<&'static str, &'static str>,
    pub output_formats: Vec<&'static str>,
    pub defaults: Defaults,
    pub exit_codes: BTreeMap<u8, &'static str>,
    pub invariants: Vec<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Defaults {
    pub duration_seconds: u64,
    pub max_events: u64,
    pub ring_bytes: u64,
    pub machine_stream: &'static str,
}

impl Describe {
    pub fn current(version: &'static str) -> Self {
        let supported = CapabilityStatus::Supported;
        let partial = CapabilityStatus::Partial;
        let planned = CapabilityStatus::Planned;
        Self {
            name: "skbx",
            version,
            contract_version: CONTRACT_VERSION,
            purpose: "agent-first Linux packet-path observation with explicit evidence and reliability",
            capabilities: vec![
                Capability {
                    name: "self-describe",
                    status: supported.clone(),
                    requires: "none",
                    cost: "constant",
                    description: "emit commands, capabilities, defaults and invariants as JSON",
                },
                Capability {
                    name: "capability-doctor",
                    status: supported.clone(),
                    requires: "linux",
                    cost: "low_io",
                    description: "inspect BTF, tracefs, privileges and symbol visibility",
                },
                Capability {
                    name: "deterministic-probe-plan",
                    status: supported.clone(),
                    requires: "/proc/kallsyms",
                    cost: "low_io",
                    description: "resolve a curated or caller-supplied probe set before attachment",
                },
                Capability {
                    name: "live-skb-kprobe-capture",
                    status: supported.clone(),
                    requires: "root|CAP_BPF+CAP_PERFMON, kernel BTF, tracefs",
                    cost: "one fixed-size ring record per observed call",
                    description: "capture metadata at BTF-validated functions with an SKB in arguments 1-5",
                },
                Capability {
                    name: "kprobe-multi-backend",
                    status: supported.clone(),
                    requires: "Linux 5.18+ with BPF_TRACE_KPROBE_MULTI",
                    cost: "one link per active SKB argument position",
                    description: "attach signature-grouped probes atomically, with an explicit individual-link fallback",
                },
                Capability {
                    name: "loss-telemetry",
                    status: supported.clone(),
                    requires: "live capture",
                    cost: "one per-cpu increment on reserve failure",
                    description: "report kernel reserve failures and userspace decode failures",
                },
                Capability {
                    name: "deterministic-replay",
                    status: supported.clone(),
                    requires: "traceq JSONL",
                    cost: "streaming_io",
                    description: "rebuild byte-stable summaries without root or network",
                },
                Capability {
                    name: "handle-addressed-explain",
                    status: supported.clone(),
                    requires: "traceq JSONL and event handle",
                    cost: "streaming_io",
                    description: "return an event and same-SKB neighboring evidence",
                },
                Capability {
                    name: "btf-signature-discovery",
                    status: supported.clone(),
                    requires: "kernel BTF",
                    cost: "startup_cpu",
                    description: "discover arbitrary functions and the position of SKB arguments",
                },
                Capability {
                    name: "split-btf-modules",
                    status: supported.clone(),
                    requires: "module BTF under /sys/kernel/btf",
                    cost: "startup_cpu proportional to selected modules",
                    description: "discover named or all kernel modules while retaining module provenance",
                },
                Capability {
                    name: "pcap-filter",
                    status: partial.clone(),
                    requires: "libpcap-compatible compiler",
                    cost: "up to 128 bounded cBPF steps per observed call",
                    description: "compile libpcap syntax and execute validated cBPF in kernel space",
                },
                Capability {
                    name: "packet-tuple-decoding",
                    status: supported.clone(),
                    requires: "packet header access",
                    cost: "bounded_kernel_reads",
                    description: "decode IPv4/IPv6, TCP/UDP tuples and TCP flags",
                },
                Capability {
                    name: "kernel-stack-and-caller",
                    status: supported.clone(),
                    requires: "BPF stack trace map",
                    cost: "optional stack capture plus userspace symbolization",
                    description: "capture caller and up to 50 evidence-addressed kernel frames",
                },
                Capability {
                    name: "timestamp-presentations",
                    status: supported.clone(),
                    requires: "live capture",
                    cost: "constant userspace formatting per event",
                    description: "present current, per-SKB relative or RFC 3339 absolute time while retaining raw monotonic evidence",
                },
                Capability {
                    name: "skb-identity-tracking",
                    status: partial,
                    requires: "bounded LRU maps",
                    cost: "one bounded lookup/update per observed call",
                    description: "continue matching an SKB and propagate identity through clone/copy",
                },
                Capability {
                    name: "skb-drop-reason",
                    status: supported.clone(),
                    requires: "kernel BTF enum and a supported drop function",
                    cost: "constant_userspace_lookup",
                    description: "decode named reasons for kfree_skb_reason and sk_skb_reason_drop",
                },
                Capability {
                    name: "capture-ready-file",
                    status: supported.clone(),
                    requires: "writable local path",
                    cost: "one startup file operation",
                    description: "create an empty synchronization file only after every requested probe is attached",
                },
                Capability {
                    name: "tunnel-and-tc-xdp-observation",
                    status: planned,
                    requires: "bounded inner-header parsing and dynamic BPF program links",
                    cost: "bounded_kernel_reads",
                    description: "correlate tunnel, TC and XDP paths without inventing missing evidence",
                },
                Capability {
                    name: "route-consensus-and-outliers",
                    status: supported.clone(),
                    requires: "traceq JSONL",
                    cost: "streaming_memory",
                    description: "assemble bounded per-SKB paths and identify consensus/outlier routes with evidence handles",
                },
            ],
            commands: BTreeMap::from([
                ("describe", "emit this protocol root"),
                ("schema", "emit the traceq JSON Schema"),
                ("doctor", "inspect host capture prerequisites"),
                ("plan", "resolve probes without attaching"),
                ("capture", "run a bounded live capture"),
                (
                    "replay",
                    "summarize an existing JSONL trace deterministically",
                ),
                ("explain", "retrieve evidence by event handle"),
            ]),
            output_formats: vec!["json", "jsonl", "text"],
            defaults: Defaults {
                duration_seconds: 10,
                max_events: 100_000,
                ring_bytes: 8 * 1024 * 1024,
                machine_stream: "jsonl",
            },
            exit_codes: BTreeMap::from([
                (0, "success"),
                (1, "runtime or IO failure"),
                (2, "usage or contract error"),
                (3, "capture incomplete or reliability gate failed"),
            ]),
            invariants: vec![
                "deterministic replay: same traceq input -> byte-identical summary",
                "local-first: capture and replay require no network",
                "bounded-by-default: duration, events and state have explicit limits",
                "evidence-addressed: every event has a stable content-derived handle",
                "honest-loss: incomplete streams and dropped events are explicit",
                "stdout-pure: machine output never mixes with diagnostics",
                "AI explains evidence; AI never creates observations",
            ],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeSpec {
    pub function: String,
    #[serde(default)]
    pub module: Option<String>,
    pub source: ProbeSource,
    pub available: bool,
    pub skb_argument: Option<u8>,
    pub assumption: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeSource {
    KernelBtf,
    KernelModuleBtf,
    Curated,
    CallerAsserted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbePlan {
    pub schema: String,
    pub kernel_release: String,
    pub probes: Vec<ProbeSpec>,
    pub attachable: usize,
    pub unavailable: usize,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketMeta {
    pub len: u32,
    pub protocol: u16,
    pub mark: u32,
    pub ifindex: u32,
    #[serde(default)]
    pub netns: u32,
    #[serde(default)]
    pub mtu: u32,
    #[serde(default)]
    pub control_buffer: [u32; 5],
    pub read_status: u16,
    #[serde(default)]
    pub read_errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketTuple {
    pub source: String,
    pub destination: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub l3_protocol: u16,
    pub l4_protocol: u8,
    pub tcp_flags: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRef {
    pub address: String,
    pub symbol: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub schema: String,
    pub capture_id: String,
    pub seq: u64,
    pub handle: String,
    pub timestamp_ns: u64,
    #[serde(default)]
    pub presentation_timestamp: Option<PresentedTimestamp>,
    pub cpu: u32,
    pub pid: u32,
    pub command: String,
    pub skb: String,
    pub function: FunctionRef,
    #[serde(default)]
    pub caller: Option<FunctionRef>,
    #[serde(default)]
    pub stack: Vec<FunctionRef>,
    #[serde(default)]
    pub parameters: [String; 2],
    #[serde(default)]
    pub drop_reason: Option<String>,
    pub packet: PacketMeta,
    #[serde(default)]
    pub tuple: Option<PacketTuple>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampMode {
    Current,
    Relative,
    Absolute,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresentedTimestamp {
    pub mode: TimestampMode,
    pub value_ns: u64,
    pub display: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureStart {
    pub schema: String,
    pub capture_id: String,
    pub started_unix_ns: u64,
    #[serde(default)]
    pub started_monotonic_ns: u64,
    pub kernel_release: String,
    pub probes: Vec<String>,
    #[serde(default)]
    pub attachment_backend: String,
    #[serde(default)]
    pub timestamp_mode: String,
    #[serde(default)]
    pub filters: CaptureFilters,
    pub limits: CaptureLimits,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureFilters {
    pub mark: u32,
    pub mark_mask: u32,
    pub ifindex: u32,
    pub netns: u32,
    pub track_skb: bool,
    pub pcap: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureLimits {
    pub duration_seconds: u64,
    pub max_events: u64,
    pub route_cache_entries: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reliability {
    pub kernel_reserve_failures: u64,
    pub kernel_read_failures: u64,
    #[serde(default)]
    pub kernel_filtered_events: u64,
    pub userspace_decode_failures: u64,
    #[serde(default)]
    pub userspace_enrichment_failures: u64,
    pub output_failures: u64,
}

impl Reliability {
    pub fn complete(&self) -> bool {
        self.kernel_reserve_failures == 0
            && self.userspace_decode_failures == 0
            && self.userspace_enrichment_failures == 0
            && self.output_failures == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Duration,
    EventLimit,
    Signal,
    SourceEnded,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureEnd {
    pub schema: String,
    pub capture_id: String,
    pub events: u64,
    pub reliability: Reliability,
    pub complete: bool,
    pub stop_reason: StopReason,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
// Event is the hot variant. Boxing it would add one allocation and pointer
// chase to every live record solely to shrink the cold enum representation.
#[allow(clippy::large_enum_variant)]
pub enum Envelope {
    CaptureStart(CaptureStart),
    Event(TraceEvent),
    CaptureEnd(CaptureEnd),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSummary {
    pub schema: String,
    pub capture_id: String,
    pub complete: bool,
    pub events: u64,
    pub distinct_skbs: usize,
    pub functions: BTreeMap<String, u64>,
    pub processes: BTreeMap<String, u64>,
    #[serde(default)]
    pub route_patterns: Vec<RoutePattern>,
    #[serde(default)]
    pub route_consensus: Option<RouteConsensus>,
    #[serde(default)]
    pub route_evictions: u64,
    pub reliability: Reliability,
    pub stop_reason: Option<StopReason>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePattern {
    pub handle: String,
    pub functions: Vec<String>,
    pub routes: u64,
    pub example_skbs: Vec<String>,
    pub example_events: Vec<String>,
    pub first_seq: u64,
    pub last_seq: u64,
    pub truncated: bool,
    pub outlier: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteConsensus {
    pub handle: String,
    pub routes: u64,
    pub total_routes: u64,
    pub confidence_basis_points: u16,
    pub outlier_routes: u64,
    pub ambiguous: bool,
}

pub fn json_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": EVENT_SCHEMA,
        "title": "skbx traceq JSONL envelope",
        "description": "One JSON object per line; discriminator is kind. A complete stream starts with capture_start and ends with capture_end.",
        "oneOf": [
            {"$ref": "#/$defs/CaptureStartEnvelope"},
            {"$ref": "#/$defs/EventEnvelope"},
            {"$ref": "#/$defs/CaptureEndEnvelope"}
        ],
        "$defs": {
            "CaptureStartEnvelope": {
                "type": "object",
                "required": ["kind", "schema", "capture_id", "started_unix_ns", "started_monotonic_ns", "kernel_release", "probes", "attachment_backend", "timestamp_mode", "filters", "limits"],
                "properties": {
                    "kind": {"const": "capture_start"},
                    "schema": {"const": CONTRACT_VERSION},
                    "capture_id": {"type": "string"},
                    "started_unix_ns": {"type": "integer", "minimum": 0},
                    "started_monotonic_ns": {"type": "integer", "minimum": 0},
                    "kernel_release": {"type": "string"},
                    "probes": {"type": "array", "items": {"type": "string"}},
                    "attachment_backend": {"enum": ["kprobe", "kprobe-multi"]},
                    "timestamp_mode": {"enum": ["none", "current", "relative", "absolute"]},
                    "filters": {"$ref": "#/$defs/CaptureFilters"},
                    "limits": {"$ref": "#/$defs/CaptureLimits"}
                },
                "additionalProperties": false
            },
            "EventEnvelope": {
                "type": "object",
                "required": ["kind", "schema", "capture_id", "seq", "handle", "timestamp_ns", "presentation_timestamp", "cpu", "pid", "command", "skb", "function", "caller", "stack", "parameters", "drop_reason", "packet", "tuple"],
                "properties": {
                    "kind": {"const": "event"},
                    "schema": {"const": CONTRACT_VERSION},
                    "capture_id": {"type": "string"},
                    "seq": {"type": "integer", "minimum": 0},
                    "handle": {"type": "string", "pattern": "^event:[0-9a-f]{24}$"},
                    "timestamp_ns": {"type": "integer", "minimum": 0},
                    "presentation_timestamp": {
                        "oneOf": [
                            {"$ref": "#/$defs/PresentedTimestamp"},
                            {"type": "null"}
                        ]
                    },
                    "cpu": {"type": "integer", "minimum": 0},
                    "pid": {"type": "integer", "minimum": 0},
                    "command": {"type": "string"},
                    "skb": {"type": "string"},
                    "function": {"$ref": "#/$defs/FunctionRef"},
                    "caller": {
                        "oneOf": [
                            {"$ref": "#/$defs/FunctionRef"},
                            {"type": "null"}
                        ]
                    },
                    "stack": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/FunctionRef"},
                        "maxItems": 50
                    },
                    "parameters": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "items": {"type": "string", "pattern": "^0x[0-9a-f]+$"}
                    },
                    "drop_reason": {"type": ["string", "null"]},
                    "packet": {"$ref": "#/$defs/PacketMeta"},
                    "tuple": {
                        "oneOf": [
                            {"$ref": "#/$defs/PacketTuple"},
                            {"type": "null"}
                        ]
                    }
                },
                "additionalProperties": false
            },
            "CaptureEndEnvelope": {
                "type": "object",
                "required": ["kind", "schema", "capture_id", "events", "reliability", "complete", "stop_reason"],
                "properties": {
                    "kind": {"const": "capture_end"},
                    "schema": {"const": CONTRACT_VERSION},
                    "capture_id": {"type": "string"},
                    "events": {"type": "integer", "minimum": 0},
                    "reliability": {"$ref": "#/$defs/Reliability"},
                    "complete": {"type": "boolean"},
                    "stop_reason": {"enum": ["duration", "event_limit", "signal", "source_ended", "error"]}
                },
                "additionalProperties": false
            },
            "CaptureLimits": {
                "type": "object",
                "required": ["duration_seconds", "max_events", "route_cache_entries"],
                "properties": {
                    "duration_seconds": {"type": "integer", "minimum": 1},
                    "max_events": {"type": "integer", "minimum": 1},
                    "route_cache_entries": {"type": "integer", "minimum": 1}
                },
                "additionalProperties": false
            },
            "CaptureFilters": {
                "type": "object",
                "required": ["mark", "mark_mask", "ifindex", "netns", "track_skb", "pcap"],
                "properties": {
                    "mark": {"type": "integer", "minimum": 0, "maximum": 4294967295_u64},
                    "mark_mask": {"type": "integer", "minimum": 0, "maximum": 4294967295_u64},
                    "ifindex": {"type": "integer", "minimum": 0, "maximum": 4294967295_u64},
                    "netns": {"type": "integer", "minimum": 0, "maximum": 4294967295_u64},
                    "track_skb": {"type": "boolean"},
                    "pcap": {"type": ["string", "null"]}
                },
                "additionalProperties": false
            },
            "FunctionRef": {
                "type": "object",
                "required": ["address", "symbol"],
                "properties": {
                    "address": {"type": "string", "pattern": "^0x[0-9a-f]+$"},
                    "symbol": {"type": ["string", "null"]}
                },
                "additionalProperties": false
            },
            "PresentedTimestamp": {
                "type": "object",
                "required": ["mode", "value_ns", "display"],
                "properties": {
                    "mode": {"enum": ["current", "relative", "absolute"]},
                    "value_ns": {"type": "integer", "minimum": 0},
                    "display": {"type": "string"}
                },
                "additionalProperties": false
            },
            "PacketMeta": {
                "type": "object",
                "required": ["len", "protocol", "mark", "ifindex", "netns", "mtu", "control_buffer", "read_status", "read_errors"],
                "properties": {
                    "len": {"type": "integer", "minimum": 0, "maximum": 4294967295_u64},
                    "protocol": {"type": "integer", "minimum": 0, "maximum": 65535},
                    "mark": {"type": "integer", "minimum": 0, "maximum": 4294967295_u64},
                    "ifindex": {"type": "integer", "minimum": 0, "maximum": 4294967295_u64},
                    "netns": {"type": "integer", "minimum": 0, "maximum": 4294967295_u64},
                    "mtu": {"type": "integer", "minimum": 0, "maximum": 4294967295_u64},
                    "control_buffer": {
                        "type": "array",
                        "minItems": 5,
                        "maxItems": 5,
                        "items": {"type": "integer", "minimum": 0, "maximum": 4294967295_u64}
                    },
                    "read_status": {"type": "integer", "minimum": 0, "maximum": 65535},
                    "read_errors": {
                        "type": "array",
                        "items": {"type": "string"},
                        "uniqueItems": true
                    }
                },
                "additionalProperties": false
            },
            "PacketTuple": {
                "type": "object",
                "required": ["source", "destination", "source_port", "destination_port", "l3_protocol", "l4_protocol", "tcp_flags"],
                "properties": {
                    "source": {"type": "string"},
                    "destination": {"type": "string"},
                    "source_port": {"type": "integer", "minimum": 0, "maximum": 65535},
                    "destination_port": {"type": "integer", "minimum": 0, "maximum": 65535},
                    "l3_protocol": {"type": "integer", "minimum": 0, "maximum": 65535},
                    "l4_protocol": {"type": "integer", "minimum": 0, "maximum": 255},
                    "tcp_flags": {"type": "integer", "minimum": 0, "maximum": 255}
                },
                "additionalProperties": false
            },
            "Reliability": {
                "type": "object",
                "required": [
                    "kernel_reserve_failures",
                    "kernel_read_failures",
                    "kernel_filtered_events",
                    "userspace_decode_failures",
                    "userspace_enrichment_failures",
                    "output_failures"
                ],
                "properties": {
                    "kernel_reserve_failures": {"type": "integer", "minimum": 0},
                    "kernel_read_failures": {"type": "integer", "minimum": 0},
                    "kernel_filtered_events": {"type": "integer", "minimum": 0},
                    "userspace_decode_failures": {"type": "integer", "minimum": 0},
                    "userspace_enrichment_failures": {"type": "integer", "minimum": 0},
                    "output_failures": {"type": "integer", "minimum": 0}
                },
                "additionalProperties": false
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_distinguishes_supported_and_planned_capabilities() {
        let describe = Describe::current("0.1.0");
        assert!(describe.capabilities.iter().any(|c| {
            c.name == "btf-signature-discovery" && c.status == CapabilityStatus::Supported
        }));
        assert!(describe.capabilities.iter().any(|c| {
            c.name == "route-consensus-and-outliers" && c.status == CapabilityStatus::Supported
        }));
        assert!(describe.capabilities.iter().any(|c| {
            c.name == "tunnel-and-tc-xdp-observation" && c.status == CapabilityStatus::Planned
        }));
        assert_eq!(describe.defaults.max_events, 100_000);
    }

    #[test]
    fn reliability_is_strict_about_observation_loss() {
        assert!(Reliability::default().complete());
        assert!(
            !Reliability {
                kernel_reserve_failures: 1,
                ..Reliability::default()
            }
            .complete()
        );
    }

    #[test]
    fn schema_is_version_pinned() {
        assert_eq!(json_schema()["$id"], EVENT_SCHEMA);
    }
}

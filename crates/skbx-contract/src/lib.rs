#![recursion_limit = "256"]
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
                    status: supported.clone(),
                    requires: "libpcap-compatible compiler",
                    cost: "up to 4096 bounded cBPF steps per configured predicate",
                    description: "compile libpcap syntax and execute validated cBPF in kernel space",
                },
                Capability {
                    name: "namespace-interface-filter",
                    status: supported.clone(),
                    requires: "network namespace path for cross-namespace names",
                    cost: "one startup setns round trip plus bounded kernel reads",
                    description: "resolve interface names in the selected namespace and recover namespace identity from skb device or socket",
                },
                Capability {
                    name: "packet-tuple-decoding",
                    status: supported.clone(),
                    requires: "packet header access",
                    cost: "bounded_kernel_reads",
                    description: "decode IPv4/IPv6 extension chains, TCP/UDP/ICMP tuples and TCP flags",
                },
                Capability {
                    name: "tunnel-packet-observation",
                    status: supported.clone(),
                    requires: "SKB inner header offsets",
                    cost: "optional bounded inner-header reads and cBPF predicates",
                    description: "apply independent inner L2/L3 pcap predicates and emit an inner packet tuple",
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
                    status: supported.clone(),
                    requires: "bounded LRU maps",
                    cost: "one bounded lookup/update per observed call",
                    description: "continue a monotonic lineage through clone/copy, veth copy-on-write and XDP-frame-to-SKB conversion",
                },
                Capability {
                    name: "stack-associated-functions",
                    status: supported.clone(),
                    requires: "kernel frame pointers and bounded LRU maps",
                    cost: "up to 50 frame-pointer reads on selected probes",
                    description: "associate explicitly requested non-SKB functions with packet evidence while labeling the inference source",
                },
                Capability {
                    name: "bpf-helper-tracing",
                    status: supported.clone(),
                    requires: "x86_64, readable /proc/kcore and BPF JIT symbols",
                    cost: "bounded startup disassembly plus selected stack-associated probes",
                    description: "decode exact direct callees from current JIT programs, validate them with BTF and retain same-SKB evidence",
                },
                Capability {
                    name: "bpf-map-operation-evidence",
                    status: supported.clone(),
                    requires: "BPF helper tracing and map BTF metadata",
                    cost: "320-byte records only for selected map operations",
                    description: "emit typed map identity, bounded key and update-value bytes with explicit truncation and read errors",
                },
                Capability {
                    name: "btf-checked-skb-metadata-projections",
                    status: supported.clone(),
                    requires: "target kernel BTF",
                    cost: "up to four scalar reads and an extended record only when requested",
                    description: "resolve bounded skb field paths before attach and emit typed values with per-projection read errors",
                },
                Capability {
                    name: "btf-checked-skb-scalar-filter",
                    status: supported.clone(),
                    requires: "target kernel BTF",
                    cost: "up to four bounded scalar reads per observed call",
                    description: "compile up to four &&-joined typed scalar comparisons into immutable access plans with explicit read-failure telemetry",
                },
                Capability {
                    name: "atomic-btf-structure-dumps",
                    status: supported.clone(),
                    requires: "target kernel BTF and BPF_FUNC_snprintf_btf",
                    cost: "one 8576-byte atomic record per event only when requested",
                    description: "render bounded sk_buff and skb_shared_info evidence with required/captured byte counts, truncation and helper errors",
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
                    name: "replay-safe-rolling-output",
                    status: supported.clone(),
                    requires: "JSONL file output",
                    cost: "one bounded serialization per event plus optional rotation-time gzip",
                    description: "rotate only between envelopes, retain a bounded backup count and make every segment independently replayable",
                },
                Capability {
                    name: "tc-xdp-observation",
                    status: partial,
                    requires: "BPF program enumeration, program BTF and fentry",
                    cost: "one shared-map fentry link per eligible TC program",
                    description: "emit exact TC program identity at entry; XDP and TC BTF structure dumps remain planned",
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
    #[serde(default)]
    pub icmp_type: Option<u8>,
    #[serde(default)]
    pub icmp_code: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRef {
    pub address: String,
    pub symbol: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BpfMapOperationKind {
    Lookup,
    Update,
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfMapOperation {
    pub operation: BpfMapOperationKind,
    pub map_id: u32,
    pub map_name: String,
    pub key_size: u32,
    pub value_size: u32,
    pub key: Option<String>,
    pub value: Option<String>,
    pub key_truncated: bool,
    pub value_truncated: bool,
    pub read_errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataEncoding {
    Unsigned,
    Signed,
    Boolean,
    Pointer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataProjection {
    pub expression: String,
    pub type_name: String,
    pub encoding: MetadataEncoding,
    pub size: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MetadataScalar {
    Unsigned { value: u64 },
    Signed { value: i64 },
    Boolean { value: bool },
    Pointer { address: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataValue {
    pub expression: String,
    pub type_name: String,
    pub encoding: MetadataEncoding,
    pub value: Option<MetadataScalar>,
    pub read_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtfDump {
    pub type_name: String,
    pub rendered: Option<String>,
    pub bytes_required: u64,
    pub bytes_captured: u32,
    pub truncated: bool,
    pub read_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BpfProgramKind {
    Tc,
    Xdp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfProgramRef {
    pub id: u32,
    pub name: String,
    pub entry: String,
    pub kind: BpfProgramKind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventAssociation {
    #[default]
    Direct,
    Stack,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOrigin {
    #[default]
    Filter,
    TrackedSkb,
    TrackedXdp,
    StackAssociation,
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identity: String,
    pub function: FunctionRef,
    #[serde(default)]
    pub association: EventAssociation,
    #[serde(default)]
    pub match_origin: MatchOrigin,
    #[serde(default)]
    pub caller: Option<FunctionRef>,
    #[serde(default)]
    pub stack: Vec<FunctionRef>,
    #[serde(default)]
    pub parameters: [String; 2],
    #[serde(default)]
    pub drop_reason: Option<String>,
    #[serde(default)]
    pub bpf_map: Option<BpfMapOperation>,
    #[serde(default)]
    pub metadata: Vec<MetadataValue>,
    #[serde(default)]
    pub btf_dumps: Vec<BtfDump>,
    #[serde(default)]
    pub bpf_program: Option<BpfProgramRef>,
    pub packet: PacketMeta,
    #[serde(default)]
    pub tuple: Option<PacketTuple>,
    #[serde(default)]
    pub tunnel_tuple: Option<PacketTuple>,
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
    pub identity_hooks: Vec<String>,
    #[serde(default)]
    pub attachment_backend: String,
    #[serde(default)]
    pub timestamp_mode: String,
    #[serde(default)]
    pub output_tunnel: bool,
    #[serde(default)]
    pub metadata_projections: Vec<MetadataProjection>,
    #[serde(default)]
    pub btf_dump_types: Vec<String>,
    #[serde(default)]
    pub bpf_programs: Vec<BpfProgramRef>,
    #[serde(default)]
    pub segment: Option<CaptureSegmentStart>,
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
    #[serde(default)]
    pub track_stack: bool,
    pub pcap: Option<String>,
    #[serde(default)]
    pub tunnel_pcap_l2: Option<String>,
    #[serde(default)]
    pub tunnel_pcap_l3: Option<String>,
    #[serde(default)]
    pub skb_expression: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureLimits {
    pub duration_seconds: u64,
    pub max_events: u64,
    pub route_cache_entries: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSegmentStart {
    pub index: u32,
    pub first_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSegmentEnd {
    pub index: u32,
    pub first_seq: u64,
    pub next_seq: Option<u64>,
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
    Rotation,
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
    #[serde(default)]
    pub segment: Option<CaptureSegmentEnd>,
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
    #[serde(default)]
    pub segment: Option<CaptureSegmentStart>,
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
                    "identity_hooks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "uniqueItems": true
                    },
                    "attachment_backend": {"enum": ["kprobe", "kprobe-multi"]},
                    "timestamp_mode": {"enum": ["none", "current", "relative", "absolute"]},
                    "output_tunnel": {"type": "boolean"},
                    "metadata_projections": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/MetadataProjection"},
                        "maxItems": 4
                    },
                    "btf_dump_types": {
                        "type": "array",
                        "items": {"enum": ["sk_buff", "skb_shared_info"]},
                        "maxItems": 2,
                        "uniqueItems": true
                    },
                    "bpf_programs": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/BpfProgramRef"}
                    },
                    "segment": {
                        "oneOf": [
                            {"$ref": "#/$defs/CaptureSegmentStart"},
                            {"type": "null"}
                        ]
                    },
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
                    "identity": {"type": "string", "pattern": "^0x[0-9a-f]+$"},
                    "function": {"$ref": "#/$defs/FunctionRef"},
                    "association": {"enum": ["direct", "stack"]},
                    "match_origin": {"enum": ["filter", "tracked_skb", "tracked_xdp", "stack_association"]},
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
                    "bpf_map": {
                        "oneOf": [
                            {"$ref": "#/$defs/BpfMapOperation"},
                            {"type": "null"}
                        ]
                    },
                    "metadata": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/MetadataValue"},
                        "maxItems": 4
                    },
                    "btf_dumps": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/BtfDump"},
                        "maxItems": 2
                    },
                    "bpf_program": {
                        "oneOf": [
                            {"$ref": "#/$defs/BpfProgramRef"},
                            {"type": "null"}
                        ]
                    },
                    "packet": {"$ref": "#/$defs/PacketMeta"},
                    "tuple": {
                        "oneOf": [
                            {"$ref": "#/$defs/PacketTuple"},
                            {"type": "null"}
                        ]
                    },
                    "tunnel_tuple": {
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
                    "stop_reason": {"enum": ["duration", "event_limit", "signal", "source_ended", "rotation", "error"]},
                    "segment": {
                        "oneOf": [
                            {"$ref": "#/$defs/CaptureSegmentEnd"},
                            {"type": "null"}
                        ]
                    }
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
            "CaptureSegmentStart": {
                "type": "object",
                "required": ["index", "first_seq"],
                "properties": {
                    "index": {"type": "integer", "minimum": 0},
                    "first_seq": {"type": "integer", "minimum": 0}
                },
                "additionalProperties": false
            },
            "CaptureSegmentEnd": {
                "type": "object",
                "required": ["index", "first_seq", "next_seq"],
                "properties": {
                    "index": {"type": "integer", "minimum": 0},
                    "first_seq": {"type": "integer", "minimum": 0},
                    "next_seq": {"type": ["integer", "null"], "minimum": 0}
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
                    "track_stack": {"type": "boolean"},
                    "pcap": {"type": ["string", "null"]},
                    "tunnel_pcap_l2": {"type": ["string", "null"]},
                    "tunnel_pcap_l3": {"type": ["string", "null"]},
                    "skb_expression": {"type": ["string", "null"]}
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
            "BpfMapOperation": {
                "type": "object",
                "required": ["operation", "map_id", "map_name", "key_size", "value_size", "key", "value", "key_truncated", "value_truncated", "read_errors"],
                "properties": {
                    "operation": {"enum": ["lookup", "update", "delete"]},
                    "map_id": {"type": "integer", "minimum": 0},
                    "map_name": {"type": "string"},
                    "key_size": {"type": "integer", "minimum": 0},
                    "value_size": {"type": "integer", "minimum": 0},
                    "key": {"type": ["string", "null"], "pattern": "^0x[0-9a-f]*$"},
                    "value": {"type": ["string", "null"], "pattern": "^0x[0-9a-f]*$"},
                    "key_truncated": {"type": "boolean"},
                    "value_truncated": {"type": "boolean"},
                    "read_errors": {
                        "type": "array",
                        "items": {"enum": ["metadata", "key", "value"]},
                        "uniqueItems": true
                    }
                },
                "additionalProperties": false
            },
            "MetadataProjection": {
                "type": "object",
                "required": ["expression", "type_name", "encoding", "size"],
                "properties": {
                    "expression": {"type": "string", "pattern": "^skb->"},
                    "type_name": {"type": "string"},
                    "encoding": {"enum": ["unsigned", "signed", "boolean", "pointer"]},
                    "size": {"enum": [1, 2, 4, 8]}
                },
                "additionalProperties": false
            },
            "MetadataValue": {
                "type": "object",
                "required": ["expression", "type_name", "encoding", "value", "read_error"],
                "properties": {
                    "expression": {"type": "string", "pattern": "^skb->"},
                    "type_name": {"type": "string"},
                    "encoding": {"enum": ["unsigned", "signed", "boolean", "pointer"]},
                    "value": {
                        "oneOf": [
                            {"$ref": "#/$defs/MetadataUnsigned"},
                            {"$ref": "#/$defs/MetadataSigned"},
                            {"$ref": "#/$defs/MetadataBoolean"},
                            {"$ref": "#/$defs/MetadataPointer"},
                            {"type": "null"}
                        ]
                    },
                    "read_error": {"enum": ["kernel_read", "record_missing", null]}
                },
                "additionalProperties": false
            },
            "BtfDump": {
                "type": "object",
                "required": ["type_name", "rendered", "bytes_required", "bytes_captured", "truncated", "read_error"],
                "properties": {
                    "type_name": {"enum": ["sk_buff", "skb_shared_info"]},
                    "rendered": {"type": ["string", "null"]},
                    "bytes_required": {"type": "integer", "minimum": 0},
                    "bytes_captured": {"type": "integer", "minimum": 0, "maximum": 4092},
                    "truncated": {"type": "boolean"},
                    "read_error": {"type": ["string", "null"]}
                },
                "additionalProperties": false
            },
            "BpfProgramRef": {
                "type": "object",
                "required": ["id", "name", "entry", "kind"],
                "properties": {
                    "id": {"type": "integer", "minimum": 1},
                    "name": {"type": "string"},
                    "entry": {"type": "string"},
                    "kind": {"enum": ["tc", "xdp"]}
                },
                "additionalProperties": false
            },
            "MetadataUnsigned": {
                "type": "object",
                "required": ["kind", "value"],
                "properties": {
                    "kind": {"const": "unsigned"},
                    "value": {"type": "integer", "minimum": 0}
                },
                "additionalProperties": false
            },
            "MetadataSigned": {
                "type": "object",
                "required": ["kind", "value"],
                "properties": {
                    "kind": {"const": "signed"},
                    "value": {"type": "integer"}
                },
                "additionalProperties": false
            },
            "MetadataBoolean": {
                "type": "object",
                "required": ["kind", "value"],
                "properties": {
                    "kind": {"const": "boolean"},
                    "value": {"type": "boolean"}
                },
                "additionalProperties": false
            },
            "MetadataPointer": {
                "type": "object",
                "required": ["kind", "address"],
                "properties": {
                    "kind": {"const": "pointer"},
                    "address": {"type": "string", "pattern": "^0x[0-9a-f]+$"}
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
                    "tcp_flags": {"type": "integer", "minimum": 0, "maximum": 255},
                    "icmp_type": {"type": ["integer", "null"], "minimum": 0, "maximum": 255},
                    "icmp_code": {"type": ["integer", "null"], "minimum": 0, "maximum": 255}
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
            c.name == "btf-checked-skb-scalar-filter" && c.status == CapabilityStatus::Supported
        }));
        assert!(describe.capabilities.iter().any(|c| {
            c.name == "atomic-btf-structure-dumps" && c.status == CapabilityStatus::Supported
        }));
        assert!(
            describe.capabilities.iter().any(|c| {
                c.name == "tc-xdp-observation" && c.status == CapabilityStatus::Partial
            })
        );
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

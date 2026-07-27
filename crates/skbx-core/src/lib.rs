//! Deterministic planning, evidence handles, bounded state and replay.

mod bounded;
mod bpf_helpers;
mod doctor;
mod drop_reason;
mod evidence;
mod metadata;
mod plan;
mod replay;
mod symbols;

pub use bounded::BoundedMap;
pub use bpf_helpers::{BpfHelperDiscovery, BpfHelperError, discover_bpf_helpers};
pub use doctor::{DoctorCheck, DoctorReport, doctor};
pub use drop_reason::DropReasonTable;
pub use evidence::{capture_id, event_handle, route_handle};
pub use metadata::{
    MAX_METADATA_ACCESS_STEPS, MAX_METADATA_PROJECTIONS, MetadataAccessPlan, MetadataError,
    ResolvedMetadataProjection, resolve_skb_metadata,
};
pub use plan::{
    DEFAULT_BTF_PATH, PlanError, build_probe_plan, build_probe_plan_with_bpf_helpers,
    build_probe_plan_with_non_skb,
};
pub use replay::{Explanation, ReplayError, explain, explain_file, replay};
pub use symbols::SymbolTable;

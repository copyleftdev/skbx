//! Raw event sources. Live eBPF is feature-gated; replay never needs it.

mod raw;

pub use raw::{
    ASSOCIATION_DIRECT, ASSOCIATION_STACK, KernelStats, MAP_OPERATION_DELETE, MAP_OPERATION_LOOKUP,
    MAP_OPERATION_UPDATE, MAP_READ_KEY_FAILED, MAP_READ_METADATA_FAILED, MAP_READ_VALUE_FAILED,
    MATCH_FILTER, MATCH_STACK_ASSOCIATION, MATCH_TRACKED_SKB, MATCH_TRACKED_XDP,
    MAX_MAP_CAPTURE_BYTES, READ_CALLER_FAILED, READ_CB_FAILED, READ_DEVICE_FAILED,
    READ_IFINDEX_FAILED, READ_LEN_FAILED, READ_MARK_FAILED, READ_MTU_FAILED, READ_NETNS_FAILED,
    READ_PROTOCOL_FAILED, READ_TUNNEL_TUPLE_FAILED, READ_TUPLE_FAILED, RawMapTraceEvent,
    RawObservation, RawPacketTuple, RawTraceEvent,
};

#[cfg(feature = "ebpf")]
mod live;
#[cfg(feature = "ebpf")]
pub use live::{
    AttachmentMode, CbpfInsn, CbpfProgram, LiveError, LiveSensor, MAX_CBPF_INSNS, SensorConfig,
};

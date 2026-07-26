//! Raw event sources. Live eBPF is feature-gated; replay never needs it.

mod raw;

pub use raw::{
    KernelStats, READ_CALLER_FAILED, READ_CB_FAILED, READ_DEVICE_FAILED, READ_IFINDEX_FAILED,
    READ_LEN_FAILED, READ_MARK_FAILED, READ_MTU_FAILED, READ_NETNS_FAILED, READ_PROTOCOL_FAILED,
    READ_TUPLE_FAILED, RawTraceEvent,
};

#[cfg(feature = "ebpf")]
mod live;
#[cfg(feature = "ebpf")]
pub use live::{
    AttachmentMode, CbpfInsn, CbpfProgram, LiveError, LiveSensor, MAX_CBPF_INSNS, SensorConfig,
};

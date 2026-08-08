use skbx_contract::{KernelCpuLoss, KernelProbeLoss, Reliability};

pub const READ_LEN_FAILED: u16 = 1 << 0;
pub const READ_PROTOCOL_FAILED: u16 = 1 << 1;
pub const READ_MARK_FAILED: u16 = 1 << 2;
pub const READ_DEVICE_FAILED: u16 = 1 << 3;
pub const READ_IFINDEX_FAILED: u16 = 1 << 4;
pub const READ_MTU_FAILED: u16 = 1 << 5;
pub const READ_NETNS_FAILED: u16 = 1 << 6;
pub const READ_TUPLE_FAILED: u16 = 1 << 7;
pub const READ_CB_FAILED: u16 = 1 << 8;
pub const READ_CALLER_FAILED: u16 = 1 << 9;
pub const READ_TUNNEL_TUPLE_FAILED: u16 = 1 << 10;
pub const ASSOCIATION_DIRECT: u8 = 0;
pub const ASSOCIATION_STACK: u8 = 1;
pub const MATCH_FILTER: u8 = 0;
pub const MATCH_TRACKED_SKB: u8 = 1;
pub const MATCH_STACK_ASSOCIATION: u8 = 2;
pub const MATCH_TRACKED_XDP: u8 = 3;
pub const MAP_OPERATION_LOOKUP: u8 = 1;
pub const MAP_OPERATION_UPDATE: u8 = 2;
pub const MAP_OPERATION_DELETE: u8 = 3;
pub const MAP_READ_METADATA_FAILED: u8 = 1 << 0;
pub const MAP_READ_KEY_FAILED: u8 = 1 << 1;
pub const MAP_READ_VALUE_FAILED: u8 = 1 << 2;
pub const MAX_MAP_CAPTURE_BYTES: usize = 32;
pub const MAX_METADATA_PROJECTIONS: usize = 4;
pub const BTF_DUMP_SK_BUFF: u8 = 1 << 0;
pub const BTF_DUMP_SHARED_INFO: u8 = 1 << 1;
pub const BTF_RECORD_COMPONENT_MAP: u8 = 1 << 0;
pub const BTF_RECORD_COMPONENT_METADATA: u8 = 1 << 1;
pub const MAX_BTF_DUMP_BYTES: usize = 4092;
pub const BPF_PROGRAM_TC: u8 = 1;
pub const BPF_PROGRAM_XDP: u8 = 2;
pub const BPF_PROGRAM_PHASE_ENTRY: u8 = 1;
pub const BPF_PROGRAM_PHASE_EXIT: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawPacketTuple {
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub l3_protocol: u16,
    pub l4_protocol: u8,
    pub tcp_flags: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawTraceEvent {
    pub timestamp_ns: u64,
    pub skb_addr: u64,
    pub identity: u64,
    pub function_ip: u64,
    pub caller_ip: u64,
    pub pid: u32,
    pub cpu: u32,
    pub len: u32,
    pub mark: u32,
    pub ifindex: u32,
    pub netns: u32,
    pub mtu: u32,
    pub protocol: u16,
    pub read_status: u16,
    pub tuple: RawPacketTuple,
    pub tunnel_tuple: RawPacketTuple,
    pub control_buffer: [u32; 5],
    pub command: [u8; 16],
    pub association: u8,
    pub match_origin: u8,
    pub _pad0: [u8; 2],
    pub stack_id: i64,
    pub parameter_second: u64,
    pub parameter_third: u64,
}

impl RawTraceEvent {
    pub const BYTE_LEN: usize = std::mem::size_of::<Self>();

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::BYTE_LEN {
            return None;
        }
        let mut event = Self::default();
        // SAFETY: destination is a valid initialized byte-addressable struct,
        // lengths match exactly, and source/destination cannot overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (&mut event as *mut Self).cast::<u8>(),
                Self::BYTE_LEN,
            );
        }
        Some(event)
    }

    pub fn command_string(&self) -> String {
        let end = self
            .command
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.command.len());
        String::from_utf8_lossy(&self.command[..end]).into_owned()
    }

    pub fn read_failures(&self) -> Vec<&'static str> {
        [
            (READ_LEN_FAILED, "len"),
            (READ_PROTOCOL_FAILED, "protocol"),
            (READ_MARK_FAILED, "mark"),
            (READ_DEVICE_FAILED, "device"),
            (READ_IFINDEX_FAILED, "ifindex"),
            (READ_MTU_FAILED, "mtu"),
            (READ_NETNS_FAILED, "netns"),
            (READ_TUPLE_FAILED, "tuple"),
            (READ_CB_FAILED, "control_buffer"),
            (READ_CALLER_FAILED, "caller"),
            (READ_TUNNEL_TUPLE_FAILED, "tunnel_tuple"),
        ]
        .into_iter()
        .filter_map(|(mask, name)| (self.read_status & mask != 0).then_some(name))
        .collect()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawMapTraceEvent {
    pub event: RawTraceEvent,
    pub map_id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub operation: u8,
    pub key_captured: u8,
    pub value_captured: u8,
    pub read_status: u8,
    pub map_name: [u8; 16],
    pub key: [u8; MAX_MAP_CAPTURE_BYTES],
    pub value: [u8; MAX_MAP_CAPTURE_BYTES],
}

impl RawMapTraceEvent {
    pub const BYTE_LEN: usize = std::mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::BYTE_LEN {
            return None;
        }
        let mut event = Self::default();
        // SAFETY: destination is initialized and byte-addressable, lengths
        // match, and the ring sample cannot overlap this stack value.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (&mut event as *mut Self).cast::<u8>(),
                Self::BYTE_LEN,
            );
        }
        Some(event)
    }

    pub fn map_name_string(&self) -> String {
        let end = self
            .map_name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.map_name.len());
        String::from_utf8_lossy(&self.map_name[..end]).into_owned()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawMetadata {
    pub values: [u64; MAX_METADATA_PROJECTIONS],
    pub read_status: u8,
    pub count: u8,
    pub _pad: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawMetadataTraceEvent {
    pub event: RawTraceEvent,
    pub metadata: RawMetadata,
}

impl RawMetadataTraceEvent {
    pub const BYTE_LEN: usize = std::mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        copy_record(bytes)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawMapMetadataTraceEvent {
    pub map: RawMapTraceEvent,
    pub metadata: RawMetadata,
}

impl RawMapMetadataTraceEvent {
    pub const BYTE_LEN: usize = std::mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        copy_record(bytes)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawBtfDumps {
    pub skb_result: i64,
    pub shared_info_result: i64,
    pub requested: u8,
    pub _pad: [u8; 7],
    pub skb: [u8; MAX_BTF_DUMP_BYTES],
    pub shared_info: [u8; MAX_BTF_DUMP_BYTES],
}

impl Default for RawBtfDumps {
    fn default() -> Self {
        Self {
            skb_result: 0,
            shared_info_result: 0,
            requested: 0,
            _pad: [0; 7],
            skb: [0; MAX_BTF_DUMP_BYTES],
            shared_info: [0; MAX_BTF_DUMP_BYTES],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawBtfTraceEvent {
    pub record: RawMapMetadataTraceEvent,
    pub dumps: RawBtfDumps,
    pub components: u8,
    pub _pad: [u8; 7],
}

impl RawBtfTraceEvent {
    pub const BYTE_LEN: usize = std::mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Option<Box<Self>> {
        if bytes.len() != Self::BYTE_LEN {
            return None;
        }
        let mut record = Box::<Self>::new_uninit();
        // SAFETY: the allocation is exactly Self::BYTE_LEN bytes, every byte
        // is initialized from the ring sample, and Self is plain C-layout
        // data with no invalid bit patterns or drop-bearing fields.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                record.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
            Some(record.assume_init())
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawBpfProgram {
    pub id: u32,
    pub kind: u8,
    pub phase: u8,
    pub _pad: [u8; 2],
    pub name: [u8; 16],
    pub entry: [u8; 64],
}

impl Default for RawBpfProgram {
    fn default() -> Self {
        Self {
            id: 0,
            kind: 0,
            phase: 0,
            _pad: [0; 2],
            name: [0; 16],
            entry: [0; 64],
        }
    }
}

impl RawBpfProgram {
    pub fn name_string(&self) -> String {
        nul_terminated(&self.name)
    }

    pub fn entry_string(&self) -> String {
        nul_terminated(&self.entry)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawProgramTraceEvent {
    pub event: RawTraceEvent,
    pub program: RawBpfProgram,
}

impl RawProgramTraceEvent {
    pub const BYTE_LEN: usize = std::mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        copy_record(bytes)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawProgramMetadataTraceEvent {
    pub program: RawProgramTraceEvent,
    pub metadata: RawMetadata,
}

impl RawProgramMetadataTraceEvent {
    pub const BYTE_LEN: usize = std::mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        copy_record(bytes)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawProgramBtfTraceEvent {
    pub record: RawProgramMetadataTraceEvent,
    pub dumps: RawBtfDumps,
    pub components: u8,
    pub _pad: [u8; 7],
}

impl RawProgramBtfTraceEvent {
    pub const BYTE_LEN: usize = std::mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Option<Box<Self>> {
        if bytes.len() != Self::BYTE_LEN {
            return None;
        }
        let mut record = Box::<Self>::new_uninit();
        // SAFETY: the allocation is exactly Self::BYTE_LEN bytes, every byte
        // is initialized from the ring sample, and Self is plain C-layout
        // data with no invalid bit patterns or drop-bearing fields.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                record.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
            Some(record.assume_init())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawObservation {
    Trace(RawTraceEvent),
    Metadata(RawMetadataTraceEvent),
    Map(RawMapTraceEvent),
    MapMetadata(RawMapMetadataTraceEvent),
    Btf(Box<RawBtfTraceEvent>),
    Program(RawProgramTraceEvent),
    ProgramMetadata(RawProgramMetadataTraceEvent),
    ProgramBtf(Box<RawProgramBtfTraceEvent>),
}

impl RawObservation {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == RawTraceEvent::BYTE_LEN {
            RawTraceEvent::from_bytes(bytes).map(Self::Trace)
        } else if bytes.len() == RawMetadataTraceEvent::BYTE_LEN {
            RawMetadataTraceEvent::from_bytes(bytes).map(Self::Metadata)
        } else if bytes.len() == RawMapTraceEvent::BYTE_LEN {
            RawMapTraceEvent::from_bytes(bytes).map(Self::Map)
        } else if bytes.len() == RawMapMetadataTraceEvent::BYTE_LEN {
            RawMapMetadataTraceEvent::from_bytes(bytes).map(Self::MapMetadata)
        } else if bytes.len() == RawBtfTraceEvent::BYTE_LEN {
            RawBtfTraceEvent::from_bytes(bytes).map(Self::Btf)
        } else if bytes.len() == RawProgramTraceEvent::BYTE_LEN {
            RawProgramTraceEvent::from_bytes(bytes).map(Self::Program)
        } else if bytes.len() == RawProgramMetadataTraceEvent::BYTE_LEN {
            RawProgramMetadataTraceEvent::from_bytes(bytes).map(Self::ProgramMetadata)
        } else if bytes.len() == RawProgramBtfTraceEvent::BYTE_LEN {
            RawProgramBtfTraceEvent::from_bytes(bytes).map(Self::ProgramBtf)
        } else {
            None
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        RawTraceEvent,
        Option<RawMapTraceEvent>,
        Option<RawMetadata>,
        Option<RawBtfDumps>,
        Option<RawBpfProgram>,
    ) {
        match self {
            Self::Trace(event) => (event, None, None, None, None),
            Self::Metadata(record) => (record.event, None, Some(record.metadata), None, None),
            Self::Map(map) => (map.event, Some(map), None, None, None),
            Self::MapMetadata(record) => (
                record.map.event,
                Some(record.map),
                Some(record.metadata),
                None,
                None,
            ),
            Self::Btf(record) => {
                let map = (record.components & BTF_RECORD_COMPONENT_MAP != 0)
                    .then_some(record.record.map);
                let metadata = (record.components & BTF_RECORD_COMPONENT_METADATA != 0)
                    .then_some(record.record.metadata);
                (
                    record.record.map.event,
                    map,
                    metadata,
                    Some(record.dumps),
                    None,
                )
            }
            Self::Program(record) => (record.event, None, None, None, Some(record.program)),
            Self::ProgramMetadata(record) => (
                record.program.event,
                None,
                Some(record.metadata),
                None,
                Some(record.program.program),
            ),
            Self::ProgramBtf(record) => {
                let metadata = (record.components & BTF_RECORD_COMPONENT_METADATA != 0)
                    .then_some(record.record.metadata);
                (
                    record.record.program.event,
                    None,
                    metadata,
                    Some(record.dumps),
                    Some(record.record.program.program),
                )
            }
        }
    }
}

fn nul_terminated(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn copy_record<T: Copy + Default>(bytes: &[u8]) -> Option<T> {
    if bytes.len() != std::mem::size_of::<T>() {
        return None;
    }
    let mut record = T::default();
    // SAFETY: destination is initialized and byte-addressable, lengths
    // match, and the ring sample cannot overlap this stack value.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut record as *mut T).cast::<u8>(),
            bytes.len(),
        );
    }
    Some(record)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelStats {
    pub reserve_failures: u64,
    pub read_failures: u64,
    pub filtered_events: u64,
    /// Reserve failures the kernel could not file against a probe because the
    /// probe-site map was full. Counted here rather than dropped so the
    /// per-probe breakdown never has to be read as exhaustive.
    pub unattributed_reserve_failures: u64,
}

/// Identifies the probe that failed to emit, mirroring `struct probe_site_key`
/// in the BPF object. Exactly one of the two fields is set: a kernel-function
/// probe carries its instruction pointer, a TC/XDP program probe its program id.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProbeSiteKey {
    pub function_ip: u64,
    pub program_id: u32,
    pub _pad: u32,
}

impl ProbeSiteKey {
    pub const BYTE_LEN: usize = std::mem::size_of::<Self>();

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::BYTE_LEN {
            return None;
        }
        Some(Self {
            function_ip: u64::from_ne_bytes(bytes[0..8].try_into().ok()?),
            program_id: u32::from_ne_bytes(bytes[8..12].try_into().ok()?),
            _pad: 0,
        })
    }
}

/// Reserve failures attributed to one probe, summed across CPUs.
///
/// The kernel keeps this per-CPU as well, but the emitted contract reports
/// probe and CPU as two independent projections rather than their cross
/// product: a probe-by-core matrix grows with both and answers a question
/// nobody asked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProbeSiteLoss {
    pub site: ProbeSiteKey,
    pub reserve_failures: u64,
}

/// Kernel counters as the per-CPU array actually holds them, indexed by CPU id.
///
/// The counters live in a `BPF_MAP_TYPE_PERCPU_ARRAY`, so the breakdown is free
/// to carry — it is what the lookup already returns. Totalling it at readout
/// threw away the only attribution the kernel side has for a lost observation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KernelStatsByCpu {
    per_cpu: Vec<KernelStats>,
}

impl KernelStatsByCpu {
    /// `per_cpu` is ordered by CPU id, one entry per possible CPU.
    pub fn new(per_cpu: Vec<KernelStats>) -> Self {
        Self { per_cpu }
    }

    pub fn per_cpu(&self) -> &[KernelStats] {
        &self.per_cpu
    }

    pub fn total(&self) -> KernelStats {
        self.per_cpu
            .iter()
            .fold(KernelStats::default(), |mut total, stats| {
                total.reserve_failures = total
                    .reserve_failures
                    .saturating_add(stats.reserve_failures);
                total.read_failures = total.read_failures.saturating_add(stats.read_failures);
                total.filtered_events = total.filtered_events.saturating_add(stats.filtered_events);
                total.unattributed_reserve_failures = total
                    .unattributed_reserve_failures
                    .saturating_add(stats.unattributed_reserve_failures);
                total
            })
    }

    /// Only CPUs that lost something. A CPU that filtered events but lost none
    /// is not loss, so it is omitted rather than reported as a hole.
    pub fn loss_by_cpu(&self) -> Vec<KernelCpuLoss> {
        self.per_cpu
            .iter()
            .enumerate()
            .filter(|(_, stats)| stats.reserve_failures != 0 || stats.read_failures != 0)
            .map(|(cpu, stats)| KernelCpuLoss {
                cpu: u32::try_from(cpu).unwrap_or(u32::MAX),
                reserve_failures: stats.reserve_failures,
                read_failures: stats.read_failures,
            })
            .collect()
    }

    /// `loss_by_probe` is a parameter rather than a field the caller patches in
    /// afterwards: leaving it to the caller means a future third call site can
    /// drop the attribution silently, and a dropped breakdown reads exactly
    /// like a capture that lost nothing per probe.
    pub fn into_reliability(
        self,
        recursion_misses: u64,
        decode_failures: u64,
        enrichment_failures: u64,
        loss_by_probe: Vec<KernelProbeLoss>,
    ) -> Reliability {
        let total = self.total();
        Reliability {
            kernel_reserve_failures: total.reserve_failures,
            kernel_read_failures: total.read_failures,
            kernel_filtered_events: total.filtered_events,
            kernel_recursion_misses: recursion_misses,
            userspace_decode_failures: decode_failures,
            userspace_enrichment_failures: enrichment_failures,
            output_failures: 0,
            kernel_loss_by_cpu: self.loss_by_cpu(),
            kernel_unattributed_reserve_failures: total.unattributed_reserve_failures,
            // Resolved by the caller, which owns the symbol table needed to turn
            // a probe site address into a function name.
            kernel_loss_by_probe: loss_by_probe,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_event_has_fixed_224_byte_contract() {
        assert_eq!(std::mem::size_of::<RawPacketTuple>(), 44);
        assert_eq!(RawTraceEvent::BYTE_LEN, 224);
    }

    #[test]
    fn rejects_wrong_record_size() {
        assert!(RawTraceEvent::from_bytes(&[0; 223]).is_none());
        assert!(RawTraceEvent::from_bytes(&[0; 224]).is_some());
    }

    #[test]
    fn decodes_base_and_extended_map_records_by_size() {
        assert_eq!(RawMapTraceEvent::BYTE_LEN, 320);
        assert_eq!(std::mem::size_of::<RawMetadata>(), 40);
        assert_eq!(RawMetadataTraceEvent::BYTE_LEN, 264);
        assert_eq!(RawMapMetadataTraceEvent::BYTE_LEN, 360);
        assert_eq!(std::mem::size_of::<RawBtfDumps>(), 8208);
        assert_eq!(RawBtfTraceEvent::BYTE_LEN, 8576);
        assert_eq!(std::mem::size_of::<RawBpfProgram>(), 88);
        assert_eq!(RawProgramTraceEvent::BYTE_LEN, 312);
        assert_eq!(RawProgramMetadataTraceEvent::BYTE_LEN, 352);
        assert_eq!(RawProgramBtfTraceEvent::BYTE_LEN, 8568);
        assert!(
            std::mem::size_of::<RawObservation>() <= 368,
            "optional BTF dumps must not inflate compact queued observations"
        );
        assert!(matches!(
            RawObservation::from_bytes(&[0; 224]),
            Some(RawObservation::Trace(_))
        ));
        assert!(matches!(
            RawObservation::from_bytes(&[0; 264]),
            Some(RawObservation::Metadata(_))
        ));
        assert!(matches!(
            RawObservation::from_bytes(&[0; 320]),
            Some(RawObservation::Map(_))
        ));
        assert!(matches!(
            RawObservation::from_bytes(&[0; 360]),
            Some(RawObservation::MapMetadata(_))
        ));
        assert!(matches!(
            RawObservation::from_bytes(&[0; 8576]),
            Some(RawObservation::Btf(_))
        ));
        assert!(matches!(
            RawObservation::from_bytes(&[0; 312]),
            Some(RawObservation::Program(_))
        ));
        assert!(matches!(
            RawObservation::from_bytes(&[0; 352]),
            Some(RawObservation::ProgramMetadata(_))
        ));
        assert!(matches!(
            RawObservation::from_bytes(&[0; 8568]),
            Some(RawObservation::ProgramBtf(_))
        ));
        let record = RawBtfTraceEvent {
            components: BTF_RECORD_COMPONENT_MAP | BTF_RECORD_COMPONENT_METADATA,
            ..Default::default()
        };
        let (_, map, metadata, dumps, program) = RawObservation::Btf(Box::new(record)).into_parts();
        assert!(map.is_some());
        assert!(metadata.is_some());
        assert!(dumps.is_some());
        assert!(program.is_none());
        assert!(RawObservation::from_bytes(&[0; 319]).is_none());
    }

    #[test]
    fn read_failure_names_are_stable_and_ordered() {
        let event = RawTraceEvent {
            read_status: READ_TUPLE_FAILED | READ_CALLER_FAILED | READ_TUNNEL_TUPLE_FAILED,
            ..RawTraceEvent::default()
        };
        assert_eq!(
            event.read_failures(),
            vec!["tuple", "caller", "tunnel_tuple"]
        );
    }

    #[test]
    fn program_record_preserves_identity_and_metadata() {
        let mut program = RawBpfProgram {
            id: 42,
            kind: BPF_PROGRAM_TC,
            phase: BPF_PROGRAM_PHASE_ENTRY,
            ..Default::default()
        };
        program.name[..8].copy_from_slice(b"cls_test");
        program.entry[..15].copy_from_slice(b"classify_packet");
        let record = RawProgramMetadataTraceEvent {
            program: RawProgramTraceEvent {
                event: RawTraceEvent {
                    skb_addr: 0xfeed,
                    ..Default::default()
                },
                program,
            },
            metadata: RawMetadata {
                count: 1,
                values: [7, 0, 0, 0],
                ..Default::default()
            },
        };

        let (event, map, metadata, dumps, program) =
            RawObservation::ProgramMetadata(record).into_parts();
        assert_eq!(event.skb_addr, 0xfeed);
        assert!(map.is_none());
        assert_eq!(metadata.expect("metadata").values[0], 7);
        assert!(dumps.is_none());
        let program = program.expect("program");
        assert_eq!(program.id, 42);
        assert_eq!(program.phase, BPF_PROGRAM_PHASE_ENTRY);
        assert_eq!(program.name_string(), "cls_test");
        assert_eq!(program.entry_string(), "classify_packet");
    }

    #[test]
    fn program_btf_record_preserves_atomic_components() {
        let record = RawProgramBtfTraceEvent {
            record: RawProgramMetadataTraceEvent {
                program: RawProgramTraceEvent {
                    event: RawTraceEvent {
                        skb_addr: 0xbeef,
                        ..Default::default()
                    },
                    program: RawBpfProgram {
                        id: 43,
                        kind: BPF_PROGRAM_TC,
                        phase: BPF_PROGRAM_PHASE_ENTRY,
                        ..Default::default()
                    },
                },
                metadata: RawMetadata {
                    count: 1,
                    values: [9, 0, 0, 0],
                    ..Default::default()
                },
            },
            components: BTF_RECORD_COMPONENT_METADATA,
            ..Default::default()
        };

        let (event, map, metadata, dumps, program) =
            RawObservation::ProgramBtf(Box::new(record)).into_parts();
        assert_eq!(event.skb_addr, 0xbeef);
        assert!(map.is_none());
        assert_eq!(metadata.expect("metadata").values[0], 9);
        assert!(dumps.is_some());
        assert_eq!(program.expect("program").id, 43);
    }

    fn stats_by_cpu(per_cpu: &[(u64, u64, u64)]) -> KernelStatsByCpu {
        KernelStatsByCpu::new(
            per_cpu
                .iter()
                .map(
                    |&(reserve_failures, read_failures, filtered_events)| KernelStats {
                        reserve_failures,
                        read_failures,
                        filtered_events,
                        unattributed_reserve_failures: 0,
                    },
                )
                .collect(),
        )
    }

    #[test]
    fn reliability_totals_still_match_the_per_cpu_breakdown() {
        let stats = stats_by_cpu(&[(2, 0, 10), (0, 0, 40), (3, 1, 0)]);
        let reliability = stats.into_reliability(0, 0, 0);

        assert_eq!(reliability.kernel_reserve_failures, 5);
        assert_eq!(reliability.kernel_read_failures, 1);
        assert_eq!(reliability.kernel_filtered_events, 50);
        assert_eq!(
            reliability
                .kernel_loss_by_cpu
                .iter()
                .map(|loss| loss.reserve_failures)
                .sum::<u64>(),
            reliability.kernel_reserve_failures
        );
    }

    #[test]
    fn loss_is_attributed_to_the_cpu_that_could_not_emit() {
        let stats = stats_by_cpu(&[(0, 0, 0), (0, 0, 0), (7, 2, 0)]);

        assert_eq!(
            stats.loss_by_cpu(),
            vec![KernelCpuLoss {
                cpu: 2,
                reserve_failures: 7,
                read_failures: 2,
            }]
        );
    }

    #[test]
    fn a_cpu_that_only_filtered_is_not_reported_as_loss() {
        // Filtering is the probe declining to emit, not a hole in the capture.
        let stats = stats_by_cpu(&[(0, 0, 900), (0, 0, 12)]);

        assert!(stats.loss_by_cpu().is_empty());
        assert_eq!(stats.into_reliability(0, 0, 0).kernel_filtered_events, 912);
    }

    #[test]
    fn unattributed_reserve_failures_total_across_cpus() {
        let stats = KernelStatsByCpu::new(vec![
            KernelStats {
                reserve_failures: 5,
                unattributed_reserve_failures: 2,
                ..KernelStats::default()
            },
            KernelStats {
                reserve_failures: 4,
                unattributed_reserve_failures: 4,
                ..KernelStats::default()
            },
        ]);

        let reliability = stats.into_reliability(0, 0, 0);

        assert_eq!(reliability.kernel_reserve_failures, 9);
        assert_eq!(reliability.kernel_unattributed_reserve_failures, 6);
        // The total is authoritative; attribution is only ever a subset of it.
        assert!(
            reliability.kernel_unattributed_reserve_failures <= reliability.kernel_reserve_failures
        );
    }

    #[test]
    fn probe_site_keys_decode_to_exactly_one_kind_of_site() {
        let mut kernel = [0_u8; ProbeSiteKey::BYTE_LEN];
        kernel[0..8].copy_from_slice(&0xffff_ffff_8123_4560_u64.to_ne_bytes());
        let kernel = ProbeSiteKey::from_bytes(&kernel).expect("kernel site decodes");
        assert_eq!(kernel.function_ip, 0xffff_ffff_8123_4560);
        assert_eq!(kernel.program_id, 0);

        let mut program = [0_u8; ProbeSiteKey::BYTE_LEN];
        program[8..12].copy_from_slice(&77_u32.to_ne_bytes());
        let program = ProbeSiteKey::from_bytes(&program).expect("program site decodes");
        assert_eq!(program.function_ip, 0);
        assert_eq!(program.program_id, 77);
    }

    #[test]
    fn probe_site_key_rejects_a_wrong_sized_key() {
        assert_eq!(ProbeSiteKey::BYTE_LEN, 16);
        assert!(ProbeSiteKey::from_bytes(&[0_u8; 12]).is_none());
    }

    #[test]
    fn a_lossless_capture_reports_an_empty_breakdown_not_a_missing_one() {
        let reliability = stats_by_cpu(&[(0, 0, 0), (0, 0, 0)]).into_reliability(0, 0, 0);

        assert!(reliability.complete());
        assert!(reliability.kernel_loss_by_cpu.is_empty());
    }
}

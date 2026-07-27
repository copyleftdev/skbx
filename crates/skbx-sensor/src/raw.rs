use skbx_contract::Reliability;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawObservation {
    Trace(RawTraceEvent),
    Metadata(RawMetadataTraceEvent),
    Map(RawMapTraceEvent),
    MapMetadata(RawMapMetadataTraceEvent),
    Btf(Box<RawBtfTraceEvent>),
    Program(RawProgramTraceEvent),
    ProgramMetadata(RawProgramMetadataTraceEvent),
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
}

impl KernelStats {
    pub fn into_reliability(self, decode_failures: u64, enrichment_failures: u64) -> Reliability {
        Reliability {
            kernel_reserve_failures: self.reserve_failures,
            kernel_read_failures: self.read_failures,
            kernel_filtered_events: self.filtered_events,
            userspace_decode_failures: decode_failures,
            userspace_enrichment_failures: enrichment_failures,
            output_failures: 0,
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
}

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
}

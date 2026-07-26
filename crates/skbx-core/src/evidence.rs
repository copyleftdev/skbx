pub fn capture_id(started_unix_ns: u64, kernel_release: &str, probes: &[String]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"skbx.capture\0");
    hash.update(&started_unix_ns.to_le_bytes());
    hash.update(kernel_release.as_bytes());
    for probe in probes {
        hash.update(b"\0");
        hash.update(probe.as_bytes());
    }
    hash.finalize().to_hex()[..24].to_owned()
}

pub fn event_handle(
    capture_id: &str,
    seq: u64,
    timestamp_ns: u64,
    skb: u64,
    function_address: u64,
) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"skbx.event\0");
    hash.update(capture_id.as_bytes());
    hash.update(&seq.to_le_bytes());
    hash.update(&timestamp_ns.to_le_bytes());
    hash.update(&skb.to_le_bytes());
    hash.update(&function_address.to_le_bytes());
    format!("event:{}", &hash.finalize().to_hex()[..24])
}

pub fn route_handle(capture_id: &str, functions: &[String], truncated: bool) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"skbx.route\0");
    hash.update(capture_id.as_bytes());
    hash.update(&[u8::from(truncated)]);
    for function in functions {
        hash.update(b"\0");
        hash.update(function.as_bytes());
    }
    format!("route:{}", &hash.finalize().to_hex()[..24])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_stable_and_input_sensitive() {
        let a = event_handle("capture", 1, 2, 3, 4);
        assert_eq!(a, event_handle("capture", 1, 2, 3, 4));
        assert_ne!(a, event_handle("capture", 2, 2, 3, 4));
        assert!(a.starts_with("event:"));
    }

    #[test]
    fn route_handles_encode_order_and_truncation() {
        let functions = vec!["ip_rcv".into(), "tcp_v4_rcv".into()];
        let handle = route_handle("capture", &functions, false);
        assert_eq!(handle, route_handle("capture", &functions, false));
        assert_ne!(handle, route_handle("capture", &functions, true));
        assert_ne!(
            handle,
            route_handle("capture", &["tcp_v4_rcv".into(), "ip_rcv".into()], false)
        );
        assert!(handle.starts_with("route:"));
    }
}

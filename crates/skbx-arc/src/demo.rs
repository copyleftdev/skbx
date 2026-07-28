use crate::state::ControlPlane;
use skbx_contract::{
    CONTRACT_VERSION, CaptureEnd, CaptureFilters, CaptureLimits, CaptureStart, Envelope,
    FunctionRef, PacketMeta, PacketTuple, Reliability, StopReason, TraceEvent,
};
use skbx_mission::{
    CapturePlan, DEFAULT_CORRELATION_WINDOW_NS, MissionRequest, SensorRegistration,
};

const DEMO_START_NS: u64 = 1_774_560_000_000_000_000;

pub fn demo_control_plane() -> ControlPlane {
    let mut control = ControlPlane::default();
    let sensors = [
        ("client-7", "Developer laptop", "6.12.18-arch1-1", 1_100_000),
        ("edge-2", "Edge gateway", "6.8.0-63-generic", 800_000),
        ("api-4", "Application host", "6.8.0-63-generic", 1_900_000),
    ];
    for (sensor_id, display_name, kernel, uncertainty) in sensors {
        control
            .register_sensor(
                SensorRegistration {
                    sensor_id: sensor_id.into(),
                    display_name: display_name.into(),
                    kernel_release: kernel.into(),
                    capabilities: vec![
                        "live-skb-kprobe-capture".into(),
                        "loss-telemetry".into(),
                        "deterministic-replay".into(),
                    ],
                    clock_uncertainty_ns: uncertainty,
                },
                DEMO_START_NS,
            )
            .expect("demo sensor is valid");
    }

    control
        .create_mission(
            MissionRequest {
                mission_id: "mission:web-timeout".into(),
                name: "Website request / timeout".into(),
                targets: vec!["client-7".into(), "edge-2".into(), "api-4".into()],
                plan: CapturePlan {
                    duration_seconds: 20,
                    max_events: 50_000,
                    max_artifact_bytes: 8 * 1024 * 1024,
                    filter: "tcp port 443".into(),
                    probes: vec![
                        "ip_local_out".into(),
                        "dev_queue_xmit".into(),
                        "ip_rcv".into(),
                        "kfree_skb_reason".into(),
                    ],
                    track_skb: true,
                    trace_tc: true,
                    trace_xdp: true,
                    correlation_window_ns: DEFAULT_CORRELATION_WINDOW_NS,
                },
            },
            DEMO_START_NS,
        )
        .expect("demo mission is valid");
    control
        .arm_mission("mission:web-timeout")
        .expect("demo mission arms");

    let client = trace(
        "client",
        &[
            DemoEvent::new('1', 80_000_000, "ip_local_out"),
            DemoEvent::new('2', 96_000_000, "dev_queue_xmit"),
        ],
        true,
    );
    let edge = trace(
        "edge",
        &[
            DemoEvent::new('3', 112_000_000, "netif_receive_skb"),
            DemoEvent::new('4', 127_000_000, "ip_forward"),
            DemoEvent::new('5', 141_000_000, "dev_queue_xmit"),
        ],
        true,
    );
    let api = trace(
        "api",
        &[
            DemoEvent::new('6', 165_000_000, "ip_rcv"),
            DemoEvent::new('7', 179_000_000, "tcp_v4_rcv"),
            DemoEvent::new('8', 191_000_000, "kfree_skb_reason")
                .with_drop("SKB_DROP_REASON_NETFILTER_DROP"),
        ],
        false,
    );

    for (sensor_id, bytes, now) in [
        ("client-7", client, DEMO_START_NS + 1_000_000_000),
        ("edge-2", edge, DEMO_START_NS + 1_100_000_000),
        ("api-4", api, DEMO_START_NS + 1_200_000_000),
    ] {
        control
            .next_assignment(sensor_id, now)
            .expect("demo assignment exists")
            .expect("demo target has assignment");
        control
            .submit_artifact("mission:web-timeout", sensor_id, &bytes, now)
            .expect("demo artifact is valid");
    }
    control
}

#[derive(Clone, Copy)]
struct DemoEvent {
    handle_digit: char,
    timestamp_ns: u64,
    function: &'static str,
    drop_reason: Option<&'static str>,
}

impl DemoEvent {
    const fn new(handle_digit: char, timestamp_ns: u64, function: &'static str) -> Self {
        Self {
            handle_digit,
            timestamp_ns,
            function,
            drop_reason: None,
        }
    }

    const fn with_drop(mut self, drop_reason: &'static str) -> Self {
        self.drop_reason = Some(drop_reason);
        self
    }
}

fn trace(capture_id: &str, events: &[DemoEvent], complete: bool) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push(
        serde_json::to_string(&Envelope::CaptureStart(CaptureStart {
            schema: CONTRACT_VERSION.into(),
            capture_id: capture_id.into(),
            started_unix_ns: DEMO_START_NS,
            started_monotonic_ns: 0,
            kernel_release: "demo".into(),
            probes: events.iter().map(|event| event.function.into()).collect(),
            identity_hooks: Vec::new(),
            attachment_backend: "fixture".into(),
            timestamp_mode: "current".into(),
            output_tunnel: false,
            metadata_projections: Vec::new(),
            btf_dump_types: Vec::new(),
            bpf_programs: Vec::new(),
            segment: None,
            filters: CaptureFilters {
                pcap: Some("tcp port 443".into()),
                track_skb: true,
                ..Default::default()
            },
            limits: CaptureLimits {
                duration_seconds: 20,
                max_events: 50_000,
                route_cache_entries: 128,
            },
        }))
        .expect("demo header serializes"),
    );
    for (index, event) in events.iter().enumerate() {
        lines.push(
            serde_json::to_string(&Envelope::Event(TraceEvent {
                schema: CONTRACT_VERSION.into(),
                capture_id: capture_id.into(),
                seq: u64::try_from(index).expect("demo event count fits u64"),
                handle: format!("event:{}", event.handle_digit.to_string().repeat(24)),
                timestamp_ns: event.timestamp_ns,
                presentation_timestamp: None,
                cpu: u32::try_from(index % 2).expect("demo cpu fits u32"),
                pid: 4_201,
                command: "curl".into(),
                skb: format!("0x{index:04x}"),
                identity: "lineage:demo".into(),
                function: FunctionRef {
                    address: format!("0x{:x}", 0x1000 + index),
                    symbol: Some(event.function.into()),
                },
                association: Default::default(),
                match_origin: Default::default(),
                caller: None,
                stack: Vec::new(),
                parameters: Default::default(),
                drop_reason: event.drop_reason.map(str::to_owned),
                bpf_map: None,
                metadata: Vec::new(),
                btf_dumps: Vec::new(),
                bpf_program: None,
                bpf_program_phase: None,
                bpf_program_action: None,
                packet: PacketMeta {
                    len: 74,
                    protocol: 0x0800,
                    ifindex: 2,
                    ..Default::default()
                },
                tuple: Some(PacketTuple {
                    source: "10.0.0.4".into(),
                    destination: "203.0.113.8".into(),
                    source_port: 51_522,
                    destination_port: 443,
                    l3_protocol: 0x0800,
                    l4_protocol: 6,
                    tcp_flags: 0x02,
                    icmp_type: None,
                    icmp_code: None,
                }),
                tunnel_tuple: None,
            }))
            .expect("demo event serializes"),
        );
    }
    let reliability = Reliability {
        kernel_recursion_misses: if complete { 0 } else { 14 },
        ..Default::default()
    };
    lines.push(
        serde_json::to_string(&Envelope::CaptureEnd(CaptureEnd {
            schema: CONTRACT_VERSION.into(),
            capture_id: capture_id.into(),
            events: u64::try_from(events.len()).expect("demo event count fits u64"),
            reliability,
            complete,
            stop_reason: StopReason::Duration,
            segment: None,
        }))
        .expect("demo footer serializes"),
    );
    let mut output = lines.join("\n").into_bytes();
    output.push(b'\n');
    output
}

#[cfg(test)]
pub(crate) fn test_trace(capture_id: &str, timestamp_offset_ns: u64, complete: bool) -> Vec<u8> {
    trace(
        capture_id,
        &[
            DemoEvent::new('a', timestamp_offset_ns, "ip_rcv"),
            DemoEvent::new('b', timestamp_offset_ns + 10, "tcp_v4_rcv"),
        ],
        complete,
    )
}

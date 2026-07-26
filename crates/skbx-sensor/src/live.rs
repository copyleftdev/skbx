use crate::{KernelStats, RawTraceEvent};
use libbpf_rs::{Link, MapCore, MapFlags, MapHandle, Object, ObjectBuilder, ProgramAttachType};
use skbx_contract::ProbeSpec;
use std::collections::{BTreeSet, VecDeque};
use std::ffi::{OsStr, c_void};
use std::mem;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::ptr::NonNull;
use std::slice;
use std::time::Duration;
use thiserror::Error;

#[repr(C, align(8))]
struct Align8<const N: usize>([u8; N]);

static BPF_OBJECT: &Align8<{ include_bytes!(env!("SKBX_BPF_OBJ")).len() }> =
    &Align8(*include_bytes!(env!("SKBX_BPF_OBJ")));

pub const MAX_CBPF_INSNS: usize = 128;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CbpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CbpfProgram {
    pub len: u32,
    pub instructions: [CbpfInsn; MAX_CBPF_INSNS],
}

impl Default for CbpfProgram {
    fn default() -> Self {
        Self {
            len: 0,
            instructions: [CbpfInsn::default(); MAX_CBPF_INSNS],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SensorConfig {
    pub filter_mark: u32,
    pub filter_mark_mask: u32,
    pub filter_ifindex: u32,
    pub filter_netns: u32,
    pub output_stack: u32,
    pub track_skb: u32,
    pub output_tunnel: u32,
    pub pcap_l2: CbpfProgram,
    pub pcap_l3: CbpfProgram,
    pub tunnel_pcap_l2: CbpfProgram,
    pub tunnel_pcap_l3: CbpfProgram,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttachmentMode {
    #[default]
    Auto,
    Kprobe,
    KprobeMulti,
}

impl AttachmentMode {
    fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Kprobe => "kprobe",
            Self::KprobeMulti => "kprobe-multi",
        }
    }
}

#[derive(Debug, Error)]
pub enum LiveError {
    #[error("load eBPF object: {0}")]
    Load(String),
    #[error("configure eBPF program: {0}")]
    Program(String),
    #[error("configure eBPF map: {0}")]
    Map(String),
    #[error("poll ring buffer: {0}")]
    Poll(#[from] std::io::Error),
}

#[derive(Default)]
struct RingState {
    events: VecDeque<RawTraceEvent>,
    decode_failures: u64,
}

pub struct LiveSensor {
    ring: NonNull<libbpf_rs::libbpf_sys::ring_buffer>,
    ring_state: Box<RingState>,
    telemetry: MapHandle,
    stack_traces: MapHandle,
    _links: Vec<Link>,
    _object: Object,
    attachment_backend: &'static str,
    enrichment_failures: u64,
}

impl LiveSensor {
    pub fn attach(
        probes: &[ProbeSpec],
        btf_path: Option<&Path>,
        config: &SensorConfig,
        route_cache_entries: u32,
        attachment_mode: AttachmentMode,
    ) -> Result<Self, LiveError> {
        if probes.is_empty() {
            return Err(LiveError::Program("probe list is empty".into()));
        }
        match attachment_mode {
            AttachmentMode::Auto => match Self::attach_once(
                probes,
                btf_path,
                config,
                route_cache_entries,
                AttachmentMode::KprobeMulti,
            ) {
                Ok(sensor) => Ok(sensor),
                Err(multi_error) => Self::attach_once(
                    probes,
                    btf_path,
                    config,
                    route_cache_entries,
                    AttachmentMode::Kprobe,
                )
                .map_err(|fallback_error| {
                    LiveError::Program(format!(
                        "automatic kprobe-multi failed ({multi_error}); individual fallback failed ({fallback_error})"
                    ))
                }),
            },
            mode => Self::attach_once(probes, btf_path, config, route_cache_entries, mode),
        }
    }

    fn attach_once(
        probes: &[ProbeSpec],
        btf_path: Option<&Path>,
        config: &SensorConfig,
        route_cache_entries: u32,
        mode: AttachmentMode,
    ) -> Result<Self, LiveError> {
        debug_assert_ne!(mode, AttachmentMode::Auto);
        let active_arguments: BTreeSet<u8> = probes
            .iter()
            .filter_map(|probe| probe.skb_argument)
            .collect();
        let mut builder = ObjectBuilder::default();
        if let Some(path) = btf_path {
            builder
                .btf_custom_path(path)
                .map_err(|error| LiveError::Load(format!("set custom BTF: {error}")))?;
        }
        let mut open = builder
            .open_memory(&BPF_OBJECT.0)
            .map_err(|error| LiveError::Load(error.to_string()))?;

        configure_maps(&mut open, config, route_cache_entries)?;
        for mut program in open.progs_mut() {
            let name = program.name().to_string_lossy();
            let argument = name
                .strip_prefix("skbx_skb_arg")
                .and_then(|value| value.parse::<u8>().ok());
            let active = argument.is_some_and(|value| active_arguments.contains(&value))
                || (config.track_skb != 0
                    && matches!(name.as_ref(), "skbx_clone_entry" | "skbx_clone_exit"));
            program.set_autoload(active);
            if active && argument.is_some() && mode == AttachmentMode::KprobeMulti {
                program.set_attach_type(ProgramAttachType::KprobeMulti);
            }
        }

        let object = open
            .load()
            .map_err(|error| LiveError::Load(error.to_string()))?;
        let mut links = Vec::new();
        for argument in active_arguments {
            let selected: Vec<String> = probes
                .iter()
                .filter(|probe| probe.skb_argument == Some(argument))
                .map(|probe| probe.function.clone())
                .collect();
            let program_name = format!("skbx_skb_arg{argument}");
            let program = object
                .progs_mut()
                .find(|program| program.name() == OsStr::new(&program_name))
                .ok_or_else(|| LiveError::Program(format!("program {program_name} not found")))?;
            match mode {
                AttachmentMode::KprobeMulti => {
                    links.push(
                        program
                            .attach_kprobe_multi(false, selected)
                            .map_err(|error| {
                                LiveError::Program(format!(
                                    "attach argument-{argument} kprobe-multi group: {error}"
                                ))
                            })?,
                    );
                }
                AttachmentMode::Kprobe => {
                    for function in selected {
                        links.push(program.attach_kprobe(false, &function).map_err(|error| {
                            LiveError::Program(format!(
                                "attach argument-{argument} probe to {function}: {error}"
                            ))
                        })?);
                    }
                }
                AttachmentMode::Auto => unreachable!("resolved before attach_once"),
            }
        }
        if config.track_skb != 0 {
            for (program_name, retprobe) in [("skbx_clone_entry", false), ("skbx_clone_exit", true)]
            {
                let program = object
                    .progs_mut()
                    .find(|program| program.name() == OsStr::new(program_name))
                    .ok_or_else(|| {
                        LiveError::Program(format!("program {program_name} not found"))
                    })?;
                for function in ["skb_clone", "skb_copy"] {
                    links.push(program.attach_kprobe(retprobe, function).map_err(|error| {
                        LiveError::Program(format!("attach {program_name} to {function}: {error}"))
                    })?);
                }
            }
        }

        let events = map_handle(&object, "events")?;
        let telemetry = map_handle(&object, "telemetry")?;
        let stack_traces = map_handle(&object, "stack_traces")?;
        let mut ring_state = Box::<RingState>::default();
        let ring = create_ring(&events, ring_state.as_mut())?;

        Ok(Self {
            ring,
            ring_state,
            telemetry,
            stack_traces,
            _links: links,
            _object: object,
            attachment_backend: mode.label(),
            enrichment_failures: 0,
        })
    }

    pub fn poll(&mut self, timeout: Duration) -> Result<Vec<RawTraceEvent>, LiveError> {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: ring is a live libbpf ring manager owned by this sensor.
        let result =
            unsafe { libbpf_rs::libbpf_sys::ring_buffer__poll(self.ring.as_ptr(), timeout_ms) };
        if result < 0 {
            return Err(LiveError::Poll(std::io::Error::from_raw_os_error(-result)));
        }
        Ok(self.ring_state.events.drain(..).collect())
    }

    pub fn stats(&self) -> Result<KernelStats, LiveError> {
        let key = 0_u32.to_ne_bytes();
        let values = self
            .telemetry
            .lookup_percpu(&key, MapFlags::ANY)
            .map_err(|error| LiveError::Map(error.to_string()))?
            .ok_or_else(|| LiveError::Map("telemetry key 0 not found".into()))?;
        let mut total = KernelStats::default();
        for value in values {
            let Some(stats) = kernel_stats_from_bytes(&value) else {
                return Err(LiveError::Map(format!(
                    "telemetry value has unexpected size {}",
                    value.len()
                )));
            };
            total.reserve_failures = total
                .reserve_failures
                .saturating_add(stats.reserve_failures);
            total.read_failures = total.read_failures.saturating_add(stats.read_failures);
            total.filtered_events = total.filtered_events.saturating_add(stats.filtered_events);
        }
        Ok(total)
    }

    pub fn decode_failures(&self) -> u64 {
        self.ring_state.decode_failures
    }

    pub fn stack_frames(&mut self, stack_id: i64) -> Vec<u64> {
        let Ok(stack_id) = u32::try_from(stack_id) else {
            return Vec::new();
        };
        let key = stack_id.to_ne_bytes();
        match self.stack_traces.lookup(&key, MapFlags::ANY) {
            Ok(Some(value)) => value
                .chunks_exact(mem::size_of::<u64>())
                .map(|bytes| u64::from_ne_bytes(bytes.try_into().expect("8-byte stack frame")))
                .take_while(|address| *address != 0)
                .collect(),
            Ok(None) | Err(_) => {
                self.enrichment_failures += 1;
                Vec::new()
            }
        }
    }

    pub fn enrichment_failures(&self) -> u64 {
        self.enrichment_failures
    }

    pub fn attachment_backend(&self) -> &'static str {
        self.attachment_backend
    }
}

impl Drop for LiveSensor {
    fn drop(&mut self) {
        // SAFETY: ring was returned by ring_buffer__new and is freed once.
        unsafe { libbpf_rs::libbpf_sys::ring_buffer__free(self.ring.as_ptr()) };
    }
}

fn configure_maps(
    object: &mut libbpf_rs::OpenObject,
    config: &SensorConfig,
    route_cache_entries: u32,
) -> Result<(), LiveError> {
    let config_bytes = unsafe {
        slice::from_raw_parts(
            (config as *const SensorConfig).cast::<u8>(),
            mem::size_of::<SensorConfig>(),
        )
    };
    let mut configured = false;
    let mut resized = false;
    for mut map in object.maps_mut() {
        let name = map.name().to_string_lossy();
        if name.ends_with(".rodata") {
            let initial = map
                .initial_value_mut()
                .ok_or_else(|| LiveError::Map("rodata has no initial value".into()))?;
            if initial.len() != config_bytes.len() {
                return Err(LiveError::Map(format!(
                    "CONFIG size {} does not match rodata size {}",
                    config_bytes.len(),
                    initial.len()
                )));
            }
            initial.copy_from_slice(config_bytes);
            configured = true;
        } else if name == "tracked_skbs" {
            map.set_max_entries(route_cache_entries)
                .map_err(|error| LiveError::Map(error.to_string()))?;
            resized = true;
        }
    }
    if !configured {
        return Err(LiveError::Map("CONFIG rodata map not found".into()));
    }
    if !resized {
        return Err(LiveError::Map("tracked_skbs map not found".into()));
    }
    Ok(())
}

fn map_handle(object: &Object, name: &str) -> Result<MapHandle, LiveError> {
    let map = object
        .maps()
        .find(|map| map.name() == OsStr::new(name))
        .ok_or_else(|| LiveError::Map(format!("{name} map not found")))?;
    MapHandle::try_from(&map).map_err(|error| LiveError::Map(error.to_string()))
}

fn create_ring(
    events: &MapHandle,
    state: &mut RingState,
) -> Result<NonNull<libbpf_rs::libbpf_sys::ring_buffer>, LiveError> {
    // SAFETY: events is a ring-buffer map and state has a stable Box address
    // for the full lifetime of the returned ring manager.
    let pointer = unsafe {
        libbpf_rs::libbpf_sys::ring_buffer__new(
            events.as_fd().as_raw_fd(),
            Some(on_ring_sample),
            (state as *mut RingState).cast::<c_void>(),
            std::ptr::null(),
        )
    };
    NonNull::new(pointer).ok_or_else(|| {
        LiveError::Map(format!(
            "create events ring buffer: {}",
            std::io::Error::last_os_error()
        ))
    })
}

unsafe extern "C" fn on_ring_sample(
    context: *mut c_void,
    data: *mut c_void,
    size: libc::c_ulong,
) -> i32 {
    let state = unsafe { &mut *context.cast::<RingState>() };
    let bytes = unsafe { slice::from_raw_parts(data.cast::<u8>(), size as usize) };
    match RawTraceEvent::from_bytes(bytes) {
        Some(event) => state.events.push_back(event),
        None => state.decode_failures = state.decode_failures.saturating_add(1),
    }
    0
}

fn kernel_stats_from_bytes(bytes: &[u8]) -> Option<KernelStats> {
    if bytes.len() != mem::size_of::<KernelStats>() {
        return None;
    }
    Some(KernelStats {
        reserve_failures: u64::from_ne_bytes(bytes[0..8].try_into().ok()?),
        read_failures: u64::from_ne_bytes(bytes[8..16].try_into().ok()?),
        filtered_events: u64::from_ne_bytes(bytes[16..24].try_into().ok()?),
    })
}

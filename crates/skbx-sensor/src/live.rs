use crate::{KernelStats, RawObservation};
use libbpf_rs::btf::{Btf, BtfType, TypeId};
use libbpf_rs::query::{ProgInfoIter, ProgInfoQueryOptions, ProgramInfo};
use libbpf_rs::{
    Link, MapCore, MapFlags, MapHandle, Object, ObjectBuilder, Program, ProgramAttachType,
    ProgramType,
};
use skbx_contract::{BpfProgramKind, BpfProgramRef, ProbeSpec};
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

pub const MAX_CBPF_INSNS: usize = 4096;
pub const MAX_METADATA_ACCESS_STEPS: usize = 4;
pub const FILTER_COMPARE_EQUAL: u8 = 1;
pub const FILTER_COMPARE_NOT_EQUAL: u8 = 2;
pub const FILTER_COMPARE_LESS: u8 = 3;
pub const FILTER_COMPARE_LESS_OR_EQUAL: u8 = 4;
pub const FILTER_COMPARE_GREATER: u8 = 5;
pub const FILTER_COMPARE_GREATER_OR_EQUAL: u8 = 6;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetadataAccess {
    pub offsets: [u32; MAX_METADATA_ACCESS_STEPS],
    pub dereference_mask: u8,
    pub steps: u8,
    pub size: u8,
    pub bitfield_size: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScalarFilterCondition {
    pub access: MetadataAccess,
    pub _pad0: [u8; 4],
    pub value: u64,
    pub comparison: u8,
    pub signed: u8,
    pub group: u8,
    pub _pad1: [u8; 5],
}

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SensorConfig {
    pub filter_mark: u32,
    pub filter_mark_mask: u32,
    pub filter_ifindex: u32,
    pub filter_netns: u32,
    pub output_stack: u32,
    pub track_skb: u32,
    pub output_tunnel: u32,
    pub track_stack: u32,
    pub pcap_l2: CbpfProgram,
    pub pcap_l3: CbpfProgram,
    pub tunnel_pcap_l2: CbpfProgram,
    pub tunnel_pcap_l3: CbpfProgram,
    pub metadata_count: u32,
    pub metadata: [MetadataAccess; crate::MAX_METADATA_PROJECTIONS],
    pub xdp_metadata_count: u32,
    pub xdp_metadata: [MetadataAccess; crate::MAX_METADATA_PROJECTIONS],
    pub scalar_filter_count: u32,
    pub scalar_filters: [ScalarFilterCondition; crate::MAX_METADATA_PROJECTIONS],
    pub xdp_scalar_filter_count: u32,
    pub xdp_scalar_filters: [ScalarFilterCondition; crate::MAX_METADATA_PROJECTIONS],
    pub output_skb_dump: u32,
    pub output_shared_info_dump: u32,
    pub dynamic_program_id: u32,
    pub dynamic_program_kind: u8,
    pub _pad0: [u8; 3],
    pub dynamic_program_name: [u8; 16],
    pub dynamic_program_entry: [u8; 64],
}

#[cfg(test)]
mod abi_tests {
    use super::*;

    #[test]
    fn scalar_filter_layout_matches_bpf() {
        assert_eq!(mem::size_of::<MetadataAccess>(), 20);
        assert_eq!(mem::size_of::<ScalarFilterCondition>(), 40);
    }
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
    events: VecDeque<RawObservation>,
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
    identity_hooks: Vec<String>,
    bpf_programs: Vec<BpfProgramRef>,
    tracer_program_ids: Vec<u32>,
    enrichment_failures: u64,
}

impl LiveSensor {
    pub fn attach(
        probes: &[ProbeSpec],
        btf_path: Option<&Path>,
        config: &SensorConfig,
        route_cache_entries: u32,
        attachment_mode: AttachmentMode,
        trace_tc: bool,
        trace_xdp: bool,
    ) -> Result<Self, LiveError> {
        if probes.is_empty() && !trace_tc && !trace_xdp {
            return Err(LiveError::Program("probe list is empty".into()));
        }
        match attachment_mode {
            AttachmentMode::Auto => match Self::attach_once(
                probes,
                btf_path,
                config,
                route_cache_entries,
                AttachmentMode::KprobeMulti,
                trace_tc,
                trace_xdp,
            ) {
                Ok(sensor) => Ok(sensor),
                Err(multi_error) => Self::attach_once(
                    probes,
                    btf_path,
                    config,
                    route_cache_entries,
                    AttachmentMode::Kprobe,
                    trace_tc,
                    trace_xdp,
                )
                .map_err(|fallback_error| {
                    LiveError::Program(format!(
                        "automatic kprobe-multi failed ({multi_error}); individual fallback failed ({fallback_error})"
                    ))
                }),
            },
            mode => Self::attach_once(
                probes,
                btf_path,
                config,
                route_cache_entries,
                mode,
                trace_tc,
                trace_xdp,
            ),
        }
    }

    fn attach_once(
        probes: &[ProbeSpec],
        btf_path: Option<&Path>,
        config: &SensorConfig,
        route_cache_entries: u32,
        mode: AttachmentMode,
        trace_tc: bool,
        trace_xdp: bool,
    ) -> Result<Self, LiveError> {
        debug_assert_ne!(mode, AttachmentMode::Auto);
        let active_arguments: BTreeSet<u8> = probes
            .iter()
            .filter_map(|probe| probe.skb_argument)
            .collect();
        let all_non_skb_functions: Vec<String> = probes
            .iter()
            .filter(|probe| probe.available && probe.skb_argument.is_none())
            .map(|probe| probe.function.clone())
            .collect();
        let map_lookup_functions: Vec<String> = all_non_skb_functions
            .iter()
            .filter(|function| function.ends_with("_lookup_elem"))
            .cloned()
            .collect();
        let map_update_functions: Vec<String> = all_non_skb_functions
            .iter()
            .filter(|function| function.ends_with("_update_elem"))
            .cloned()
            .collect();
        let map_delete_functions: Vec<String> = all_non_skb_functions
            .iter()
            .filter(|function| function.ends_with("_delete_elem"))
            .cloned()
            .collect();
        let non_skb_functions: Vec<String> = all_non_skb_functions
            .into_iter()
            .filter(|function| {
                !function.ends_with("_lookup_elem")
                    && !function.ends_with("_update_elem")
                    && !function.ends_with("_delete_elem")
            })
            .collect();
        let available_functions = available_kprobe_functions();
        let identity_targets: Vec<(&str, &str)> = if config.track_skb != 0 {
            [
                ("skb_pp_cow_data", "skbx_replacement_arg2_entry"),
                (
                    "veth_convert_skb_to_xdp_buff",
                    "skbx_replacement_arg3_entry",
                ),
            ]
            .into_iter()
            .filter(|(function, _)| available_functions.contains(*function))
            .collect()
        } else {
            Vec::new()
        };
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
                    && matches!(name.as_ref(), "skbx_clone_entry" | "skbx_clone_exit"))
                || ((config.track_skb != 0 || config.track_stack != 0)
                    && name == "skbx_skb_lifetime_end")
                || (config.track_stack != 0
                    && !non_skb_functions.is_empty()
                    && name == "skbx_stack_associated")
                || (config.track_stack != 0
                    && !map_lookup_functions.is_empty()
                    && name == "skbx_map_lookup")
                || (config.track_stack != 0
                    && !map_update_functions.is_empty()
                    && name == "skbx_map_update")
                || (config.track_stack != 0
                    && !map_delete_functions.is_empty()
                    && name == "skbx_map_delete")
                || (name == "skbx_replacement_arg2_entry"
                    && identity_targets
                        .iter()
                        .any(|(_, program)| *program == "skbx_replacement_arg2_entry"))
                || (name == "skbx_replacement_arg3_entry"
                    && identity_targets
                        .iter()
                        .any(|(_, program)| *program == "skbx_replacement_arg3_entry"))
                || (name == "skbx_replacement_exit" && !identity_targets.is_empty());
            program.set_autoload(active);
            if active
                && (argument.is_some()
                    || matches!(
                        name.as_ref(),
                        "skbx_stack_associated"
                            | "skbx_map_lookup"
                            | "skbx_map_update"
                            | "skbx_map_delete"
                    ))
                && mode == AttachmentMode::KprobeMulti
            {
                program.set_attach_type(ProgramAttachType::KprobeMulti);
            }
        }

        let object = open
            .load()
            .map_err(|error| LiveError::Load(error.to_string()))?;
        let mut tracer_program_ids = object
            .progs()
            .filter(|program| program.autoload())
            .map(|program| {
                Program::id_from_fd(program.as_fd()).map_err(|error| {
                    LiveError::Program(format!("query tracer program ID: {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
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
        if config.track_stack != 0 && !non_skb_functions.is_empty() {
            let program = object
                .progs_mut()
                .find(|program| program.name() == OsStr::new("skbx_stack_associated"))
                .ok_or_else(|| {
                    LiveError::Program("program skbx_stack_associated not found".into())
                })?;
            match mode {
                AttachmentMode::KprobeMulti => {
                    links.push(
                        program
                            .attach_kprobe_multi(false, non_skb_functions.clone())
                            .map_err(|error| {
                                LiveError::Program(format!(
                                    "attach stack-associated kprobe-multi group: {error}"
                                ))
                            })?,
                    );
                }
                AttachmentMode::Kprobe => {
                    for function in &non_skb_functions {
                        links.push(program.attach_kprobe(false, function).map_err(|error| {
                            LiveError::Program(format!(
                                "attach stack-associated probe to {function}: {error}"
                            ))
                        })?);
                    }
                }
                AttachmentMode::Auto => unreachable!("resolved before attach_once"),
            }
        }
        if config.track_stack != 0 {
            for (program_name, functions) in [
                ("skbx_map_lookup", &map_lookup_functions),
                ("skbx_map_update", &map_update_functions),
                ("skbx_map_delete", &map_delete_functions),
            ] {
                if functions.is_empty() {
                    continue;
                }
                let program = object
                    .progs_mut()
                    .find(|program| program.name() == OsStr::new(program_name))
                    .ok_or_else(|| {
                        LiveError::Program(format!("program {program_name} not found"))
                    })?;
                match mode {
                    AttachmentMode::KprobeMulti => {
                        links.push(
                            program
                                .attach_kprobe_multi(false, functions.clone())
                                .map_err(|error| {
                                    LiveError::Program(format!(
                                        "attach {program_name} kprobe-multi group: {error}"
                                    ))
                                })?,
                        );
                    }
                    AttachmentMode::Kprobe => {
                        for function in functions {
                            links.push(program.attach_kprobe(false, function).map_err(
                                |error| {
                                    LiveError::Program(format!(
                                        "attach {program_name} to {function}: {error}"
                                    ))
                                },
                            )?);
                        }
                    }
                    AttachmentMode::Auto => unreachable!("resolved before attach_once"),
                }
            }
        }
        if config.track_skb != 0 || config.track_stack != 0 {
            let program = object
                .progs_mut()
                .find(|program| program.name() == OsStr::new("skbx_skb_lifetime_end"))
                .ok_or_else(|| {
                    LiveError::Program("program skbx_skb_lifetime_end not found".into())
                })?;
            links.push(
                program
                    .attach_kprobe(false, "kfree_skbmem")
                    .map_err(|error| {
                        LiveError::Program(format!(
                            "attach SKB lifetime probe to kfree_skbmem: {error}"
                        ))
                    })?,
            );
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
            for (function, entry_program) in &identity_targets {
                let program = object
                    .progs_mut()
                    .find(|program| program.name() == OsStr::new(entry_program))
                    .ok_or_else(|| {
                        LiveError::Program(format!("program {entry_program} not found"))
                    })?;
                links.push(program.attach_kprobe(false, function).map_err(|error| {
                    LiveError::Program(format!(
                        "attach SKB replacement entry to {function}: {error}"
                    ))
                })?);
                let program = object
                    .progs_mut()
                    .find(|program| program.name() == OsStr::new("skbx_replacement_exit"))
                    .ok_or_else(|| {
                        LiveError::Program("program skbx_replacement_exit not found".into())
                    })?;
                links.push(program.attach_kprobe(true, function).map_err(|error| {
                    LiveError::Program(format!(
                        "attach SKB replacement exit to {function}: {error}"
                    ))
                })?);
            }
        }

        let mut bpf_programs = Vec::new();
        if trace_tc {
            for (link, program, tracer_id) in attach_tc_programs(&object, btf_path, config)? {
                links.push(link);
                bpf_programs.push(program);
                tracer_program_ids.push(tracer_id);
            }
            if bpf_programs.is_empty() {
                return Err(LiveError::Program(
                    "--filter-trace-tc found no loaded BTF-enabled SCHED_CLS programs".into(),
                ));
            }
        }
        if trace_xdp {
            for (link, program, tracer_id) in attach_xdp_programs(&object, btf_path, config)? {
                links.push(link);
                tracer_program_ids.push(tracer_id);
                if !bpf_programs.contains(&program) {
                    bpf_programs.push(program);
                }
            }
            if !bpf_programs
                .iter()
                .any(|program| program.kind == BpfProgramKind::Xdp)
            {
                return Err(LiveError::Program(
                    "--filter-trace-xdp found no loaded BTF-enabled XDP programs".into(),
                ));
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
            identity_hooks: identity_targets
                .into_iter()
                .map(|(function, _)| function.to_owned())
                .collect(),
            bpf_programs,
            tracer_program_ids,
            enrichment_failures: 0,
        })
    }

    pub fn poll(&mut self, timeout: Duration) -> Result<Vec<RawObservation>, LiveError> {
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

    pub fn recursion_misses(&self) -> Result<u64, LiveError> {
        let wanted: BTreeSet<u32> = self.tracer_program_ids.iter().copied().collect();
        let mut found = BTreeSet::new();
        let mut total = 0_u64;

        for program in ProgInfoIter::default() {
            if wanted.contains(&program.id) {
                found.insert(program.id);
                total = total.saturating_add(program.recursion_misses);
            }
        }
        if found != wanted {
            let missing = wanted.difference(&found).copied().collect::<Vec<_>>();
            return Err(LiveError::Program(format!(
                "query recursion misses for tracer program IDs {missing:?}"
            )));
        }
        Ok(total)
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

    pub fn identity_hooks(&self) -> &[String] {
        &self.identity_hooks
    }

    pub fn bpf_programs(&self) -> &[BpfProgramRef] {
        &self.bpf_programs
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
    let mut tracked_resized = false;
    let mut data_resized = false;
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
            tracked_resized = true;
        } else if name == "skb_data_lineages" {
            map.set_max_entries(route_cache_entries)
                .map_err(|error| LiveError::Map(error.to_string()))?;
            data_resized = true;
        }
    }
    if !configured {
        return Err(LiveError::Map("CONFIG rodata map not found".into()));
    }
    if !tracked_resized {
        return Err(LiveError::Map("tracked_skbs map not found".into()));
    }
    if !data_resized {
        return Err(LiveError::Map("skb_data_lineages map not found".into()));
    }
    Ok(())
}

fn attach_tc_programs(
    base: &Object,
    btf_path: Option<&Path>,
    config: &SensorConfig,
) -> Result<Vec<(Link, BpfProgramRef, u32)>, LiveError> {
    attach_dynamic_programs(
        base,
        btf_path,
        config,
        ProgramType::SchedCls,
        "skbx_trace_tc",
        crate::BPF_PROGRAM_TC,
        BpfProgramKind::Tc,
        "TC",
    )
}

fn attach_xdp_programs(
    base: &Object,
    btf_path: Option<&Path>,
    config: &SensorConfig,
) -> Result<Vec<(Link, BpfProgramRef, u32)>, LiveError> {
    let mut attached = attach_dynamic_programs(
        base,
        btf_path,
        config,
        ProgramType::Xdp,
        "skbx_trace_xdp",
        crate::BPF_PROGRAM_XDP,
        BpfProgramKind::Xdp,
        "XDP",
    )?;
    attached.extend(attach_dynamic_programs(
        base,
        btf_path,
        config,
        ProgramType::Xdp,
        "skbx_trace_xdp_exit",
        crate::BPF_PROGRAM_XDP,
        BpfProgramKind::Xdp,
        "XDP exit",
    )?);
    Ok(attached)
}

#[allow(clippy::too_many_arguments)]
fn attach_dynamic_programs(
    base: &Object,
    btf_path: Option<&Path>,
    config: &SensorConfig,
    target_type: ProgramType,
    tracer_name: &str,
    raw_kind: u8,
    kind: BpfProgramKind,
    label: &str,
) -> Result<Vec<(Link, BpfProgramRef, u32)>, LiveError> {
    let options = ProgInfoQueryOptions::default().include_func_info(true);
    let targets: Vec<(ProgramInfo, String)> = ProgInfoIter::with_query_opts(options)
        .filter(|program| program.ty == target_type)
        .filter_map(|program| {
            let entry = bpf_program_entry(&program)?;
            Some((program, entry))
        })
        .collect();
    let mut attached = Vec::with_capacity(targets.len());

    for (target, entry) in targets {
        let target_fd = Program::fd_from_id(target.id).map_err(|error| {
            LiveError::Program(format!("open {label} BPF program {}: {error}", target.id))
        })?;
        let mut dynamic_config = *config;
        dynamic_config.dynamic_program_id = target.id;
        dynamic_config.dynamic_program_kind = raw_kind;
        dynamic_config.dynamic_program_name = fixed_bytes::<16>(target.name.as_c_str().to_bytes());
        dynamic_config.dynamic_program_entry = fixed_bytes::<64>(entry.as_bytes());

        let mut builder = ObjectBuilder::default();
        if let Some(path) = btf_path {
            builder
                .btf_custom_path(path)
                .map_err(|error| LiveError::Load(format!("set custom BTF: {error}")))?;
        }
        let mut open = builder
            .open_memory(&BPF_OBJECT.0)
            .map_err(|error| LiveError::Load(error.to_string()))?;
        configure_dynamic_maps(&mut open, base, &dynamic_config)?;
        for mut program in open.progs_mut() {
            let active = program.name() == OsStr::new(tracer_name);
            program.set_autoload(active);
            if active {
                program
                    .set_attach_target(target_fd.as_raw_fd(), Some(entry.clone()))
                    .map_err(|error| {
                        LiveError::Program(format!(
                            "target {label} BPF program {} entry {entry}: {error}",
                            target.id
                        ))
                    })?;
            }
        }
        let object = open.load().map_err(|error| {
            LiveError::Load(format!(
                "load {label} tracer for program {} entry {entry}: {error}",
                target.id
            ))
        })?;
        let tracer = object
            .progs_mut()
            .find(|program| program.name() == OsStr::new(tracer_name))
            .ok_or_else(|| LiveError::Program(format!("program {tracer_name} not found")))?;
        let tracer_id = Program::id_from_fd(tracer.as_fd()).map_err(|error| {
            LiveError::Program(format!(
                "query {label} tracer ID for program {}: {error}",
                target.id
            ))
        })?;
        let link = tracer.attach_trace().map_err(|error| {
            LiveError::Program(format!(
                "attach {label} tracer to program {} entry {entry}: {error}",
                target.id
            ))
        })?;
        attached.push((
            link,
            BpfProgramRef {
                id: target.id,
                name: target.name.to_string_lossy().into_owned(),
                entry,
                kind: kind.clone(),
            },
            tracer_id,
        ));
    }
    Ok(attached)
}

fn bpf_program_entry(program: &ProgramInfo) -> Option<String> {
    if program.btf_id == 0 {
        return None;
    }
    let function = program.func_info.iter().min_by_key(|info| info.insn_off)?;
    let btf = Btf::from_prog_id(program.id).ok()?;
    btf.type_by_id::<BtfType<'_>>(TypeId::from(function.type_id))
        .and_then(|function| function.name())
        .map(|name| name.to_string_lossy().into_owned())
}

fn configure_dynamic_maps(
    object: &mut libbpf_rs::OpenObject,
    base: &Object,
    config: &SensorConfig,
) -> Result<(), LiveError> {
    let config_bytes = unsafe {
        slice::from_raw_parts(
            (config as *const SensorConfig).cast::<u8>(),
            mem::size_of::<SensorConfig>(),
        )
    };
    for mut map in object.maps_mut() {
        let name = map.name().to_owned();
        if name.to_string_lossy().ends_with(".rodata") {
            let initial = map
                .initial_value_mut()
                .ok_or_else(|| LiveError::Map("dynamic rodata has no initial value".into()))?;
            if initial.len() != config_bytes.len() {
                return Err(LiveError::Map(format!(
                    "dynamic CONFIG size {} does not match rodata size {}",
                    config_bytes.len(),
                    initial.len()
                )));
            }
            initial.copy_from_slice(config_bytes);
            continue;
        }
        let base_map = base
            .maps()
            .find(|candidate| candidate.name() == name)
            .ok_or_else(|| {
                LiveError::Map(format!(
                    "base map {} not found for dynamic tracer",
                    name.to_string_lossy()
                ))
            })?;
        map.reuse_fd(base_map.as_fd())
            .map_err(|error| LiveError::Map(error.to_string()))?;
    }
    Ok(())
}

fn fixed_bytes<const N: usize>(value: &[u8]) -> [u8; N] {
    let mut output = [0; N];
    let length = value.len().min(N.saturating_sub(1));
    output[..length].copy_from_slice(&value[..length]);
    output
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
    match RawObservation::from_bytes(bytes) {
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

fn available_kprobe_functions() -> BTreeSet<String> {
    [
        "/sys/kernel/tracing/available_filter_functions",
        "/sys/kernel/debug/tracing/available_filter_functions",
    ]
    .into_iter()
    .find_map(|path| std::fs::read_to_string(path).ok())
    .map(|contents| {
        contents
            .lines()
            .filter_map(|line| line.split_ascii_whitespace().next())
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

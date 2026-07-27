use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use nix::sched::{CloneFlags, setns};
use skbx_contract::{
    BpfMapOperation, BpfMapOperationKind, BpfProgramKind, BpfProgramPhase, BpfProgramRef, BtfDump,
    CONTRACT_VERSION, CaptureEnd, CaptureFilters, CaptureLimits, CaptureStart, Describe, Envelope,
    EventAssociation, FunctionRef, MatchOrigin, MetadataEncoding, MetadataScalar, MetadataValue,
    PacketMeta, PacketTuple, PresentedTimestamp, Reliability, StopReason, TimestampMode,
    TraceEvent,
};
use skbx_core::{
    BoundedMap, DEFAULT_BTF_PATH, DropReasonTable, SymbolTable, build_dynamic_probe_plan,
    build_probe_plan_with_bpf_helpers, capture_id, discover_bpf_helpers, doctor,
    ensure_btf_dump_support, event_handle, explain_with_context, replay, resolve_skb_filter,
    resolve_skb_metadata, resolve_xdp_metadata,
};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(feature = "ebpf")]
mod pcap_filter;
mod segmented_output;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_DURATION_SECONDS: u64 = 10;
const DEFAULT_MAX_EVENTS: u64 = 100_000;
const DEFAULT_ROUTE_CACHE_ENTRIES: u32 = 65_536;

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Parser)]
#[command(
    name = "skbx",
    version,
    about = "Agent-first Linux packet-path observation",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
// Parsed exactly once at process startup. Indirection would complicate clap's
// declarative surface without reducing capture-path memory or work.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Emit the machine-readable tool contract.
    Describe {
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Emit the versioned traceq JSON Schema.
    Schema,
    /// Inspect host prerequisites without attaching probes.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Resolve a deterministic probe plan without attaching.
    Plan {
        #[arg(long = "probe")]
        probes: Vec<String>,
        /// Select BTF-discovered functions by a whole-name regular expression.
        #[arg(long)]
        filter_func: Option<String>,
        /// Trace these BTF-validated functions through bounded stack association.
        #[arg(long, value_delimiter = ',')]
        filter_non_skb_funcs: Vec<String>,
        /// Trace direct kernel callees discovered from JIT-compiled BPF programs.
        #[arg(long)]
        filter_track_bpf_helpers: bool,
        /// Read target kernel BTF from this path.
        #[arg(long)]
        kernel_btf: Option<PathBuf>,
        /// Include split BTF from these kernel modules.
        #[arg(long = "kmods", value_delimiter = ',', conflicts_with = "all_kmods")]
        kmods: Vec<String>,
        /// Include split BTF from every module under the BTF directory.
        #[arg(long, conflicts_with = "kmods")]
        all_kmods: bool,
        #[arg(long)]
        json: bool,
    },
    /// Run a bounded live eBPF capture.
    Capture {
        #[arg(long = "probe")]
        probes: Vec<String>,
        /// Select BTF-discovered functions by a whole-name regular expression.
        #[arg(long)]
        filter_func: Option<String>,
        /// Trace these BTF-validated functions through bounded stack association.
        #[arg(long, value_delimiter = ',')]
        filter_non_skb_funcs: Vec<String>,
        /// Trace direct kernel callees discovered from JIT-compiled BPF programs.
        #[arg(long)]
        filter_track_bpf_helpers: bool,
        /// Trace every currently loaded BTF-enabled TC classifier.
        #[arg(long)]
        filter_trace_tc: bool,
        /// Trace every currently loaded BTF-enabled XDP program.
        #[arg(long)]
        filter_trace_xdp: bool,
        /// Read target kernel BTF from this path.
        #[arg(long)]
        kernel_btf: Option<PathBuf>,
        /// Include split BTF from these kernel modules.
        #[arg(long = "kmods", value_delimiter = ',', conflicts_with = "all_kmods")]
        kmods: Vec<String>,
        /// Include split BTF from every module under the BTF directory.
        #[arg(long, conflicts_with = "kmods")]
        all_kmods: bool,
        /// Filter skb mark as mark[/mask], accepting decimal or 0x-prefixed values.
        #[arg(long)]
        filter_mark: Option<String>,
        /// Filter by numeric interface index.
        #[arg(long, conflicts_with = "filter_ifname")]
        filter_ifindex: Option<u32>,
        /// Filter by an interface in the current network namespace.
        #[arg(long, conflicts_with = "filter_ifindex")]
        filter_ifname: Option<String>,
        /// Filter by network namespace path or inode:<number>.
        #[arg(long)]
        filter_netns: Option<String>,
        /// Keep following matching SKBs and their clone/copy descendants.
        #[arg(long)]
        filter_track_skb: bool,
        /// Apply up to four BTF-checked scalar comparisons joined with &&.
        #[arg(long)]
        filter_skb_expr: Option<String>,
        /// Apply a libpcap expression to the inner Ethernet frame when present.
        #[arg(long)]
        filter_tunnel_pcap_l2: Option<String>,
        /// Apply a libpcap expression to the inner IP packet when present.
        #[arg(long)]
        filter_tunnel_pcap_l3: Option<String>,
        /// Capture up to 50 kernel stack frames per event.
        #[arg(long)]
        output_stack: bool,
        /// Decode the inner IP tuple from SKBs carrying tunnel header offsets.
        #[arg(long)]
        output_tunnel: bool,
        /// Emit up to four BTF-validated scalar paths such as skb->mark.
        #[arg(long = "output-skb-metadata")]
        output_skb_metadata: Vec<String>,
        /// Emit up to four BTF-validated scalar paths such as xdp->frame_sz.
        #[arg(long = "output-xdp-metadata")]
        output_xdp_metadata: Vec<String>,
        /// Emit a bounded BTF rendering of struct sk_buff with each event.
        #[arg(long)]
        output_skb: bool,
        /// Emit a bounded BTF rendering of struct skb_shared_info with each event.
        #[arg(long = "output-skb-shared-info")]
        output_skb_shared_info: bool,
        /// Probe attachment backend; auto falls back to individual kprobes.
        #[arg(long, value_enum, default_value_t = AttachmentBackend::Auto)]
        backend: AttachmentBackend,
        /// Timestamp presentation; raw monotonic timestamp_ns is always retained in JSON.
        #[arg(long, value_enum, default_value_t = TimestampOutput::None)]
        timestamp: TimestampOutput,
        #[arg(long, default_value_t = DEFAULT_DURATION_SECONDS)]
        duration: u64,
        #[arg(long, default_value_t = DEFAULT_MAX_EVENTS)]
        max_events: u64,
        #[arg(long, default_value_t = DEFAULT_ROUTE_CACHE_ENTRIES)]
        route_cache_entries: u32,
        #[arg(long, value_enum, default_value_t = OutputFormat::Jsonl)]
        format: OutputFormat,
        #[arg(long, default_value = "-")]
        output: PathBuf,
        /// Rotate JSONL between complete envelopes at this many bytes (minimum 65536).
        #[arg(long)]
        output_max_bytes: Option<u64>,
        /// Maximum rotated segments retained in addition to the active file.
        #[arg(long, default_value_t = 8)]
        output_max_backups: u32,
        /// Gzip rotated segments; the active segment remains plain JSONL.
        #[arg(long)]
        output_compress: bool,
        /// Atomically create this file after every requested probe is attached.
        #[arg(long)]
        ready_file: Option<PathBuf>,
        /// Exit 3 when the footer reports kernel or userspace event loss.
        #[arg(long)]
        fail_on_loss: bool,
        /// libpcap-compatible packet filter expression.
        #[arg(value_name = "PCAP_FILTER", trailing_var_arg = true)]
        pcap_filter: Vec<String>,
    },
    /// Deterministically summarize a recorded traceq JSONL stream.
    Replay {
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = SummaryFormat::Json)]
        format: SummaryFormat,
    },
    /// Retrieve an event and bounded same-SKB evidence by handle.
    Explain { input: PathBuf, handle: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Jsonl,
    Text,
}

enum CaptureWriter {
    Plain(BufWriter<Box<dyn Write>>),
    Segmented(Box<segmented_output::SegmentedTraceWriter>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum AttachmentBackend {
    Auto,
    Kprobe,
    KprobeMulti,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum TimestampOutput {
    None,
    Current,
    Relative,
    Absolute,
}

impl TimestampOutput {
    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Current => "current",
            Self::Relative => "relative",
            Self::Absolute => "absolute",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SummaryFormat {
    Json,
    Text,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("skbx: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    match cli.command {
        Command::Describe { format } => {
            if format != "json" {
                bail!("describe: unsupported format {format:?}; use json");
            }
            write_pretty_stdout(&Describe::current(VERSION))?;
            Ok(0)
        }
        Command::Schema => {
            write_pretty_stdout(&skbx_contract::json_schema())?;
            Ok(0)
        }
        Command::Doctor { json } => {
            let report = doctor();
            if json {
                write_pretty_stdout(&report)?;
            } else {
                println!(
                    "skbx doctor — kernel {} — {}",
                    report.kernel_release,
                    if report.ready { "READY" } else { "NOT READY" }
                );
                for check in &report.checks {
                    println!(
                        "  {:<5} {:<24} {}",
                        format!("{:?}", check.status).to_lowercase(),
                        check.name,
                        check.evidence
                    );
                }
            }
            Ok(if report.ready { 0 } else { 1 })
        }
        Command::Plan {
            probes,
            filter_func,
            filter_non_skb_funcs,
            filter_track_bpf_helpers,
            kernel_btf,
            kmods,
            all_kmods,
            json,
        } => {
            let bpf_helpers = resolve_bpf_helpers(filter_track_bpf_helpers)?;
            let plan = build_probe_plan_with_bpf_helpers(
                &probes,
                filter_func.as_deref(),
                &filter_non_skb_funcs,
                &bpf_helpers,
                kernel_btf.as_deref(),
                &kmods,
                all_kmods,
            )?;
            if json {
                write_pretty_stdout(&plan)?;
            } else {
                println!(
                    "skbx plan — kernel {} — {} attachable, {} unavailable",
                    plan.kernel_release, plan.attachable, plan.unavailable
                );
                for probe in &plan.probes {
                    let argument = probe
                        .skb_argument
                        .map_or_else(|| "?".into(), |argument| argument.to_string());
                    let target = match &probe.module {
                        Some(module) => format!("{} [{module}]", probe.function),
                        None => probe.function.clone(),
                    };
                    println!(
                        "  {:<11} {} arg={} ({})",
                        if probe.available {
                            "attach"
                        } else {
                            "unavailable"
                        },
                        target,
                        argument,
                        probe.assumption
                    );
                }
                for warning in &plan.warnings {
                    eprintln!("skbx plan: warning: {warning}");
                }
            }
            Ok(if plan.attachable > 0 { 0 } else { 1 })
        }
        Command::Capture {
            probes,
            filter_func,
            filter_non_skb_funcs,
            filter_track_bpf_helpers,
            filter_trace_tc,
            filter_trace_xdp,
            kernel_btf,
            kmods,
            all_kmods,
            filter_mark,
            filter_ifindex,
            filter_ifname,
            filter_netns,
            filter_track_skb,
            filter_skb_expr,
            filter_tunnel_pcap_l2,
            filter_tunnel_pcap_l3,
            output_stack,
            output_tunnel,
            output_skb_metadata,
            output_xdp_metadata,
            output_skb,
            output_skb_shared_info,
            backend,
            timestamp,
            duration,
            max_events,
            route_cache_entries,
            format,
            output,
            output_max_bytes,
            output_max_backups,
            output_compress,
            ready_file,
            fail_on_loss,
            pcap_filter,
        } => capture(
            &probes,
            filter_func.as_deref(),
            &filter_non_skb_funcs,
            filter_track_bpf_helpers,
            filter_trace_tc,
            filter_trace_xdp,
            kernel_btf.as_deref(),
            &kmods,
            all_kmods,
            filter_mark.as_deref(),
            filter_ifindex,
            filter_ifname.as_deref(),
            filter_netns.as_deref(),
            filter_track_skb,
            filter_skb_expr.as_deref(),
            filter_tunnel_pcap_l2.as_deref(),
            filter_tunnel_pcap_l3.as_deref(),
            output_stack,
            output_tunnel,
            &output_skb_metadata,
            &output_xdp_metadata,
            output_skb,
            output_skb_shared_info,
            backend,
            timestamp,
            duration,
            max_events,
            route_cache_entries,
            format,
            &output,
            output_max_bytes,
            output_max_backups,
            output_compress,
            ready_file.as_deref(),
            fail_on_loss,
            &pcap_filter,
        ),
        Command::Replay { input, format } => {
            let reader = open_trace(&input)?;
            let summary = replay(reader)?;
            match format {
                SummaryFormat::Json => write_pretty_stdout(&summary)?,
                SummaryFormat::Text => {
                    println!(
                        "skbx replay — capture {} — {} events — {} SKBs — {}",
                        summary.capture_id,
                        summary.events,
                        summary.distinct_skbs,
                        if summary.complete {
                            "complete"
                        } else {
                            "INCOMPLETE"
                        }
                    );
                    println!("Functions");
                    for (function, count) in &summary.functions {
                        println!("  {count:>10}  {function}");
                    }
                    if let Some(consensus) = &summary.route_consensus {
                        println!(
                            "Routes: patterns={} consensus={} support={}/{} confidence={}.{:02}% outliers={} ambiguous={} evictions={}",
                            summary.route_patterns.len(),
                            consensus.handle,
                            consensus.routes,
                            consensus.total_routes,
                            consensus.confidence_basis_points / 100,
                            consensus.confidence_basis_points % 100,
                            consensus.outlier_routes,
                            consensus.ambiguous,
                            summary.route_evictions
                        );
                    }
                    println!(
                        "Reliability: kernel_reserve_failures={} decode_failures={} output_failures={}",
                        summary.reliability.kernel_reserve_failures,
                        summary.reliability.userspace_decode_failures,
                        summary.reliability.output_failures
                    );
                }
            }
            Ok(if summary.complete { 0 } else { 3 })
        }
        Command::Explain { input, handle } => {
            if !handle.starts_with("event:") {
                bail!("explain handle must start with event:");
            }
            let explanation =
                explain_with_context(open_trace(&input)?, open_trace(&input)?, &handle)?;
            write_pretty_stdout(&explanation)?;
            Ok(0)
        }
    }
}

fn open_trace(path: &Path) -> Result<Box<dyn BufRead>> {
    let file = File::open(path).with_context(|| format!("open trace input {}", path.display()))?;
    let mut buffered = BufReader::new(file);
    let gzip = buffered
        .fill_buf()
        .with_context(|| format!("inspect trace input {}", path.display()))?
        .starts_with(&[0x1f, 0x8b]);
    if gzip {
        Ok(Box::new(BufReader::new(flate2::read::GzDecoder::new(
            buffered,
        ))))
    } else {
        Ok(Box::new(buffered))
    }
}

fn resolve_bpf_helpers(enabled: bool) -> Result<Vec<String>> {
    if !enabled {
        return Ok(Vec::new());
    }
    let discovery = discover_bpf_helpers().context("discover BPF JIT helper callees")?;
    eprintln!(
        "skbx: BPF helper discovery decoded {}/{} programs ({} bytes, {} read failures) and resolved {} exact callees",
        discovery.programs_decoded,
        discovery.programs_seen,
        discovery.decoded_bytes,
        discovery.program_read_failures,
        discovery.helpers.len()
    );
    if discovery.helpers.is_empty() {
        bail!(
            "--filter-track-bpf-helpers found no exact kernel callees in currently JIT-compiled BPF programs"
        );
    }
    Ok(discovery.helpers)
}

#[allow(clippy::too_many_arguments)]
fn capture(
    requested: &[String],
    filter_func: Option<&str>,
    non_skb_functions: &[String],
    filter_track_bpf_helpers: bool,
    filter_trace_tc: bool,
    filter_trace_xdp: bool,
    kernel_btf: Option<&Path>,
    modules: &[String],
    all_modules: bool,
    filter_mark: Option<&str>,
    filter_ifindex: Option<u32>,
    filter_ifname: Option<&str>,
    filter_netns: Option<&str>,
    filter_track_skb: bool,
    filter_skb_expr: Option<&str>,
    filter_tunnel_pcap_l2: Option<&str>,
    filter_tunnel_pcap_l3: Option<&str>,
    output_stack: bool,
    output_tunnel: bool,
    output_skb_metadata: &[String],
    output_xdp_metadata: &[String],
    output_skb: bool,
    output_skb_shared_info: bool,
    backend: AttachmentBackend,
    timestamp: TimestampOutput,
    duration_seconds: u64,
    max_events: u64,
    route_cache_entries: u32,
    format: OutputFormat,
    output_path: &Path,
    output_max_bytes: Option<u64>,
    output_max_backups: u32,
    output_compress: bool,
    ready_file: Option<&Path>,
    fail_on_loss: bool,
    pcap_filter: &[String],
) -> Result<u8> {
    if duration_seconds == 0 {
        bail!("capture --duration must be greater than zero");
    }
    if max_events == 0 {
        bail!("capture --max-events must be greater than zero");
    }
    if route_cache_entries == 0 {
        bail!("capture --route-cache-entries must be greater than zero");
    }
    if (filter_trace_tc || filter_trace_xdp) && (output_skb || output_skb_shared_info) {
        bail!("dynamic BPF program tracing does not yet support BTF structure dumps");
    }
    if !output_xdp_metadata.is_empty() && !filter_trace_xdp {
        bail!("--output-xdp-metadata requires --filter-trace-xdp");
    }
    if output_max_bytes.is_some() && output_path == Path::new("-") {
        bail!("--output-max-bytes requires a file --output path");
    }
    if output_max_bytes.is_some_and(|bytes| bytes < segmented_output::MIN_ROTATION_BYTES) {
        bail!(
            "--output-max-bytes must be at least {}",
            segmented_output::MIN_ROTATION_BYTES
        );
    }
    if output_max_bytes.is_some() && format != OutputFormat::Jsonl {
        bail!("--output-max-bytes currently requires --format jsonl");
    }
    if output_max_bytes.is_some() && output_max_backups == 0 {
        bail!("--output-max-backups must be greater than zero when rotation is enabled");
    }
    if output_compress && output_max_bytes.is_none() {
        bail!("--output-compress requires --output-max-bytes");
    }
    if let Some(path) = ready_file {
        prepare_ready_file(path)?;
    }
    let metadata_projections = resolve_skb_metadata(output_skb_metadata, kernel_btf)?;
    let xdp_metadata_projections = resolve_xdp_metadata(output_xdp_metadata, kernel_btf)?;
    let scalar_filter = resolve_skb_filter(filter_skb_expr, kernel_btf)?;
    if output_skb || output_skb_shared_info {
        ensure_btf_dump_support(kernel_btf.unwrap_or_else(|| Path::new(DEFAULT_BTF_PATH)))?;
    }
    let mut filters = resolve_filters(filter_mark, filter_ifindex, filter_ifname, filter_netns)?;
    filters.pcap = (!pcap_filter.is_empty()).then(|| pcap_filter.join(" "));
    filters.tunnel_pcap_l2 = filter_tunnel_pcap_l2.map(str::to_owned);
    filters.tunnel_pcap_l3 = filter_tunnel_pcap_l3.map(str::to_owned);
    filters.track_skb = filter_track_skb;
    filters.skb_expression = scalar_filter.as_ref().map(|filter| filter.source.clone());
    if filter_track_skb
        && filters.mark_mask == 0
        && filters.ifindex == 0
        && filters.netns == 0
        && filters.pcap.is_none()
        && filters.tunnel_pcap_l2.is_none()
        && filters.tunnel_pcap_l3.is_none()
        && filters.skb_expression.is_none()
    {
        bail!("--filter-track-skb requires at least one packet filter");
    }
    let bpf_helpers = resolve_bpf_helpers(filter_track_bpf_helpers)?;
    let dynamic_only = (filter_trace_tc || filter_trace_xdp)
        && requested.is_empty()
        && filter_func.is_none()
        && non_skb_functions.is_empty()
        && bpf_helpers.is_empty()
        && modules.is_empty()
        && !all_modules;
    let plan = if dynamic_only {
        build_dynamic_probe_plan()
    } else {
        build_probe_plan_with_bpf_helpers(
            requested,
            filter_func,
            non_skb_functions,
            &bpf_helpers,
            kernel_btf,
            modules,
            all_modules,
        )?
    };
    filters.track_stack = plan
        .probes
        .iter()
        .any(|probe| probe.available && probe.skb_argument.is_none());
    let attachments: Vec<_> = plan
        .probes
        .iter()
        .filter(|probe| probe.available)
        .cloned()
        .collect();
    if attachments.is_empty() && !filter_trace_tc && !filter_trace_xdp {
        bail!("capture has no attachable probes; run `skbx plan --json`");
    }
    let probes: Vec<String> = attachments
        .iter()
        .map(|probe| match &probe.module {
            Some(module) => format!("{} [{module}]", probe.function),
            None => probe.function.clone(),
        })
        .collect();
    for warning in &plan.warnings {
        eprintln!("skbx capture: warning: {warning}");
    }

    #[cfg(not(feature = "ebpf"))]
    {
        let _ = (
            duration_seconds,
            max_events,
            route_cache_entries,
            backend,
            timestamp,
            format,
            output_path,
            output_max_bytes,
            output_max_backups,
            output_compress,
            ready_file,
            fail_on_loss,
        );
        bail!("this skbx binary was built without the ebpf feature");
    }

    #[cfg(feature = "ebpf")]
    {
        install_signal_handlers();
        STOP_REQUESTED.store(false, Ordering::Relaxed);

        let started_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_nanos()
            .try_into()
            .context("Unix timestamp does not fit in traceq u64 nanoseconds")?;
        let started_monotonic_ns = monotonic_ns()?;
        let id = capture_id(started_unix_ns, &plan.kernel_release, &probes);
        let mut start = CaptureStart {
            schema: CONTRACT_VERSION.into(),
            capture_id: id.clone(),
            started_unix_ns,
            started_monotonic_ns,
            kernel_release: plan.kernel_release.clone(),
            probes: probes.clone(),
            identity_hooks: Vec::new(),
            attachment_backend: String::new(),
            timestamp_mode: timestamp.label().into(),
            output_tunnel,
            metadata_projections: metadata_projections
                .iter()
                .chain(xdp_metadata_projections.iter())
                .map(|projection| projection.descriptor.clone())
                .collect(),
            btf_dump_types: [
                output_skb.then_some("sk_buff"),
                output_skb_shared_info.then_some("skb_shared_info"),
            ]
            .into_iter()
            .flatten()
            .map(str::to_owned)
            .collect(),
            bpf_programs: Vec::new(),
            segment: None,
            filters: filters.clone(),
            limits: CaptureLimits {
                duration_seconds,
                max_events,
                route_cache_entries,
            },
        };

        // Attach before creating or writing the output artifact. If the host
        // cannot load BPF, callers get an error rather than a misleading
        // header-only trace.
        let (pcap_l2, pcap_l3) = pcap_filter::compile(filters.pcap.as_deref())?;
        let tunnel_pcap_l2 = pcap_filter::compile_l2(filters.tunnel_pcap_l2.as_deref())?;
        let tunnel_pcap_l3 = pcap_filter::compile_l3(filters.tunnel_pcap_l3.as_deref())?;
        let sensor_config = skbx_sensor::SensorConfig {
            filter_mark: filters.mark,
            filter_mark_mask: filters.mark_mask,
            filter_ifindex: filters.ifindex,
            filter_netns: filters.netns,
            output_stack: u32::from(output_stack),
            track_skb: u32::from(filter_track_skb),
            output_tunnel: u32::from(output_tunnel),
            track_stack: u32::from(filters.track_stack),
            pcap_l2,
            pcap_l3,
            tunnel_pcap_l2,
            tunnel_pcap_l3,
            metadata_count: metadata_projections.len() as u32,
            metadata: std::array::from_fn(|index| {
                metadata_projections.get(index).map_or_else(
                    skbx_sensor::MetadataAccess::default,
                    |projection| skbx_sensor::MetadataAccess {
                        offsets: projection.access.offsets,
                        dereference_mask: projection.access.dereference_mask,
                        steps: projection.access.steps,
                        size: projection.access.size,
                        _pad: 0,
                    },
                )
            }),
            xdp_metadata_count: xdp_metadata_projections.len() as u32,
            xdp_metadata: std::array::from_fn(|index| {
                xdp_metadata_projections.get(index).map_or_else(
                    skbx_sensor::MetadataAccess::default,
                    |projection| skbx_sensor::MetadataAccess {
                        offsets: projection.access.offsets,
                        dereference_mask: projection.access.dereference_mask,
                        steps: projection.access.steps,
                        size: projection.access.size,
                        _pad: 0,
                    },
                )
            }),
            scalar_filter_count: scalar_filter
                .as_ref()
                .map_or(0, |filter| filter.conditions.len() as u32),
            scalar_filters: std::array::from_fn(|index| {
                scalar_filter
                    .as_ref()
                    .and_then(|filter| filter.conditions.get(index))
                    .map_or_else(skbx_sensor::ScalarFilterCondition::default, |condition| {
                        skbx_sensor::ScalarFilterCondition {
                            access: skbx_sensor::MetadataAccess {
                                offsets: condition.access.offsets,
                                dereference_mask: condition.access.dereference_mask,
                                steps: condition.access.steps,
                                size: condition.access.size,
                                _pad: 0,
                            },
                            _pad0: [0; 4],
                            value: condition.value,
                            comparison: match condition.comparison {
                                skbx_core::ScalarComparison::Equal => {
                                    skbx_sensor::FILTER_COMPARE_EQUAL
                                }
                                skbx_core::ScalarComparison::NotEqual => {
                                    skbx_sensor::FILTER_COMPARE_NOT_EQUAL
                                }
                                skbx_core::ScalarComparison::Less => {
                                    skbx_sensor::FILTER_COMPARE_LESS
                                }
                                skbx_core::ScalarComparison::LessOrEqual => {
                                    skbx_sensor::FILTER_COMPARE_LESS_OR_EQUAL
                                }
                                skbx_core::ScalarComparison::Greater => {
                                    skbx_sensor::FILTER_COMPARE_GREATER
                                }
                                skbx_core::ScalarComparison::GreaterOrEqual => {
                                    skbx_sensor::FILTER_COMPARE_GREATER_OR_EQUAL
                                }
                            },
                            signed: u8::from(condition.signed),
                            _pad1: [0; 6],
                        }
                    })
            }),
            output_skb_dump: u32::from(output_skb),
            output_shared_info_dump: u32::from(output_skb_shared_info),
            dynamic_program_id: 0,
            dynamic_program_kind: 0,
            _pad0: [0; 3],
            dynamic_program_name: [0; 16],
            dynamic_program_entry: [0; 64],
        };
        let mut sensor = skbx_sensor::LiveSensor::attach(
            &attachments,
            kernel_btf,
            &sensor_config,
            route_cache_entries,
            match backend {
                AttachmentBackend::Auto => skbx_sensor::AttachmentMode::Auto,
                AttachmentBackend::Kprobe => skbx_sensor::AttachmentMode::Kprobe,
                AttachmentBackend::KprobeMulti => skbx_sensor::AttachmentMode::KprobeMulti,
            },
            filter_trace_tc,
            filter_trace_xdp,
        )?;
        start.attachment_backend = sensor.attachment_backend().into();
        start.identity_hooks = sensor.identity_hooks().to_vec();
        start.bpf_programs = sensor.bpf_programs().to_vec();
        let mut writer = if let Some(max_bytes) = output_max_bytes {
            CaptureWriter::Segmented(Box::new(segmented_output::SegmentedTraceWriter::new(
                output_path,
                &start,
                max_bytes,
                output_max_backups,
                output_compress,
            )?))
        } else {
            let output: Box<dyn Write> = if output_path == Path::new("-") {
                Box::new(std::io::stdout())
            } else {
                Box::new(
                    File::create(output_path)
                        .with_context(|| format!("create output {}", output_path.display()))?,
                )
            };
            let mut writer = BufWriter::with_capacity(256 * 1024, output);
            write_start(&mut writer, format, &start)?;
            writer
                .flush()
                .context("flush capture header before readiness signal")?;
            CaptureWriter::Plain(writer)
        };
        if let Some(path) = ready_file {
            signal_ready(path)?;
        }

        let symbols = SymbolTable::from_kallsyms();
        let drop_reasons =
            DropReasonTable::from_btf(kernel_btf.unwrap_or_else(|| Path::new(DEFAULT_BTF_PATH)));
        let deadline = Instant::now() + Duration::from_secs(duration_seconds);
        let mut last_skb_timestamps = BoundedMap::<String, u64>::new(route_cache_entries as usize);
        let mut reliability_checkpoint = Reliability::default();
        let mut seq = 0_u64;
        let mut stop_reason = StopReason::Duration;

        while Instant::now() < deadline {
            if STOP_REQUESTED.load(Ordering::Relaxed) {
                stop_reason = StopReason::Signal;
                break;
            }
            if seq >= max_events {
                stop_reason = StopReason::EventLimit;
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout = remaining.min(Duration::from_millis(100));
            for observation in sensor.poll(timeout)? {
                if seq >= max_events {
                    stop_reason = StopReason::EventLimit;
                    break;
                }
                let (raw, map, metadata, btf_dumps, bpf_program) = observation.into_parts();
                let stack = sensor.stack_frames(raw.stack_id);
                let mut event = convert_event(
                    &id,
                    seq,
                    raw,
                    RawEventComponents {
                        map,
                        metadata,
                        btf_dumps,
                        bpf_program,
                    },
                    EventEnrichment {
                        metadata_projections: &metadata_projections,
                        xdp_metadata_projections: &xdp_metadata_projections,
                        symbols: &symbols,
                        drop_reasons: &drop_reasons,
                        stack: &stack,
                    },
                );
                event.presentation_timestamp = present_timestamp(
                    timestamp,
                    &event,
                    started_unix_ns,
                    started_monotonic_ns,
                    &mut last_skb_timestamps,
                )?;
                match &mut writer {
                    CaptureWriter::Plain(writer) => write_event(writer, format, &event)?,
                    CaptureWriter::Segmented(writer) => {
                        writer.write_event(&event, || {
                            let current = sensor.stats()?.into_reliability(
                                sensor.decode_failures(),
                                sensor.enrichment_failures(),
                            );
                            let segment = reliability_delta(&current, &reliability_checkpoint);
                            reliability_checkpoint = current;
                            Ok(segment)
                        })?;
                    }
                }
                seq += 1;
            }
        }

        let stats = sensor.stats()?;
        let reliability =
            stats.into_reliability(sensor.decode_failures(), sensor.enrichment_failures());
        let complete = reliability.complete();
        let end = CaptureEnd {
            schema: CONTRACT_VERSION.into(),
            capture_id: id,
            events: seq,
            reliability,
            complete,
            stop_reason,
            segment: None,
        };
        let final_segment_reliability =
            reliability_delta(&end.reliability, &reliability_checkpoint);
        match writer {
            CaptureWriter::Plain(mut writer) => {
                write_end(&mut writer, format, &end)?;
                writer.flush().context("flush capture output")?;
            }
            CaptureWriter::Segmented(writer) => {
                writer.finish(&end, final_segment_reliability)?;
            }
        }

        if fail_on_loss && !end.complete {
            Ok(3)
        } else {
            Ok(0)
        }
    }
}

fn prepare_ready_file(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            bail!("ready file path is a directory: {}", path.display())
        }
        Ok(_) => std::fs::remove_file(path)
            .with_context(|| format!("remove stale ready file {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect ready file {}", path.display())),
    }
}

fn signal_ready(path: &Path) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create ready file {}", path.display()))?;
    Ok(())
}

fn monotonic_ns() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value points to an initialized timespec and CLOCK_MONOTONIC is
    // supported on the Linux hosts where live capture is available.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read monotonic clock");
    }
    let seconds = u64::try_from(value.tv_sec).context("negative monotonic seconds")?;
    let nanoseconds = u64::try_from(value.tv_nsec).context("negative monotonic nanoseconds")?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .context("monotonic timestamp overflow")
}

fn present_timestamp(
    mode: TimestampOutput,
    event: &TraceEvent,
    started_unix_ns: u64,
    started_monotonic_ns: u64,
    last_skb_timestamps: &mut BoundedMap<String, u64>,
) -> Result<Option<PresentedTimestamp>> {
    let (mode, value_ns, display) = match mode {
        TimestampOutput::None => return Ok(None),
        TimestampOutput::Current => (
            TimestampMode::Current,
            event.timestamp_ns,
            event.timestamp_ns.to_string(),
        ),
        TimestampOutput::Relative => {
            let previous = last_skb_timestamps
                .remove(&event.skb)
                .unwrap_or(event.timestamp_ns);
            last_skb_timestamps.insert(event.skb.clone(), event.timestamp_ns);
            let value = event.timestamp_ns.saturating_sub(previous);
            (TimestampMode::Relative, value, value.to_string())
        }
        TimestampOutput::Absolute => {
            let value = started_unix_ns
                .saturating_add(event.timestamp_ns.saturating_sub(started_monotonic_ns));
            let display = OffsetDateTime::from_unix_timestamp_nanos(i128::from(value))
                .context("absolute timestamp is outside supported range")?
                .format(&Rfc3339)
                .context("format absolute timestamp")?;
            (TimestampMode::Absolute, value, display)
        }
    };
    Ok(Some(PresentedTimestamp {
        mode,
        value_ns,
        display,
    }))
}

fn resolve_filters(
    mark_spec: Option<&str>,
    ifindex: Option<u32>,
    ifname: Option<&str>,
    netns_spec: Option<&str>,
) -> Result<CaptureFilters> {
    let (mark, mark_mask) = mark_spec.map(parse_mark).transpose()?.unwrap_or((0, 0));
    let explicit_netns = netns_spec.map(parse_netns).transpose()?;
    let resolved_ifindex = match (ifindex, ifname) {
        (Some(index), None) => index,
        (None, Some(name)) => {
            if netns_spec.is_some_and(|spec| spec.starts_with("inode:")) {
                bail!("inode network namespace cannot be used with --filter-ifname");
            }
            resolve_ifindex(name, netns_spec)?
        }
        (None, None) => 0,
        (Some(_), Some(_)) => unreachable!("clap rejects conflicting interface selectors"),
    };
    // Interface indexes are namespace-local. Match pwru by coupling a named
    // interface to the selected namespace, or to the current namespace when
    // --filter-netns was omitted.
    let netns = if ifname.is_some() {
        explicit_netns.unwrap_or(netns_inode("/proc/self/ns/net")?)
    } else {
        explicit_netns.unwrap_or(0)
    };
    Ok(CaptureFilters {
        mark,
        mark_mask,
        ifindex: resolved_ifindex,
        netns,
        track_skb: false,
        track_stack: false,
        pcap: None,
        tunnel_pcap_l2: None,
        tunnel_pcap_l3: None,
        skb_expression: None,
    })
}

fn resolve_ifindex(name: &str, netns_path: Option<&str>) -> Result<u32> {
    let resolve_current = || {
        let name = CString::new(name).context("interface name contains a NUL byte")?;
        // SAFETY: name is a valid NUL-terminated string for this call.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("resolve interface {name:?}"));
        }
        Ok(index)
    };
    let Some(netns_path) = netns_path else {
        return resolve_current();
    };
    if netns_inode(netns_path)? == netns_inode("/proc/self/ns/net")? {
        return resolve_current();
    }

    let current = File::open("/proc/self/ns/net").context("open current network namespace")?;
    let target = File::open(netns_path)
        .with_context(|| format!("open target network namespace {netns_path}"))?;
    setns(&target, CloneFlags::CLONE_NEWNET)
        .with_context(|| format!("enter target network namespace {netns_path}"))?;
    let resolved = resolve_current();
    setns(&current, CloneFlags::CLONE_NEWNET)
        .context("restore current network namespace after interface lookup")?;
    resolved
}

fn parse_mark(spec: &str) -> Result<(u32, u32)> {
    let mut parts = spec.split('/');
    let mark = parse_u32(parts.next().unwrap_or_default()).context("invalid mark")?;
    let mask = parts
        .next()
        .map(parse_u32)
        .transpose()
        .context("invalid mark mask")?
        .unwrap_or(u32::MAX);
    if parts.next().is_some() {
        bail!("mark filter must use mark[/mask]");
    }
    Ok((mark, mask))
}

fn parse_netns(spec: &str) -> Result<u32> {
    if let Some(inode) = spec.strip_prefix("inode:") {
        return parse_u32(inode).context("invalid network namespace inode");
    }
    if !spec.starts_with('/') {
        bail!("network namespace must be an absolute path or inode:<number>");
    }
    netns_inode(spec)
}

fn netns_inode(path: &str) -> Result<u32> {
    let inode = std::fs::metadata(path)
        .with_context(|| format!("stat network namespace {path}"))?
        .ino();
    inode
        .try_into()
        .context("network namespace inode does not fit u32")
}

fn parse_u32(value: &str) -> Result<u32> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |digits| (digits, 16));
    u32::from_str_radix(digits, radix).with_context(|| format!("parse {value:?} as u32"))
}

struct EventEnrichment<'a> {
    metadata_projections: &'a [skbx_core::ResolvedMetadataProjection],
    xdp_metadata_projections: &'a [skbx_core::ResolvedMetadataProjection],
    symbols: &'a SymbolTable,
    drop_reasons: &'a DropReasonTable,
    stack: &'a [u64],
}

#[derive(Default)]
struct RawEventComponents {
    map: Option<skbx_sensor::RawMapTraceEvent>,
    metadata: Option<skbx_sensor::RawMetadata>,
    btf_dumps: Option<skbx_sensor::RawBtfDumps>,
    bpf_program: Option<skbx_sensor::RawBpfProgram>,
}

fn convert_event(
    capture_id: &str,
    seq: u64,
    raw: skbx_sensor::RawTraceEvent,
    components: RawEventComponents,
    enrichment: EventEnrichment<'_>,
) -> TraceEvent {
    let metadata_projections = if components
        .bpf_program
        .is_some_and(|program| program.kind == skbx_sensor::BPF_PROGRAM_XDP)
    {
        enrichment.xdp_metadata_projections
    } else {
        enrichment.metadata_projections
    };
    let bpf_program_phase = components.bpf_program.map(|program| {
        if program.phase == skbx_sensor::BPF_PROGRAM_PHASE_EXIT {
            BpfProgramPhase::Exit
        } else {
            BpfProgramPhase::Entry
        }
    });
    let function_symbol = enrichment
        .symbols
        .resolve(raw.function_ip)
        .map(str::to_owned);
    let drop_reason = function_symbol
        .as_deref()
        .and_then(|function| drop_reason_parameter(function, &raw))
        .and_then(|reason| enrichment.drop_reasons.resolve(reason))
        .map(str::to_owned);
    TraceEvent {
        schema: CONTRACT_VERSION.into(),
        capture_id: capture_id.into(),
        seq,
        handle: event_handle(
            capture_id,
            seq,
            raw.timestamp_ns,
            raw.skb_addr,
            raw.function_ip,
        ),
        timestamp_ns: raw.timestamp_ns,
        presentation_timestamp: None,
        cpu: raw.cpu,
        pid: raw.pid,
        command: raw.command_string(),
        skb: format!("{:#x}", raw.skb_addr),
        identity: format!("{:#x}", raw.identity),
        function: FunctionRef {
            address: format!("{:#x}", raw.function_ip),
            symbol: function_symbol,
        },
        association: if raw.association == skbx_sensor::ASSOCIATION_STACK {
            EventAssociation::Stack
        } else {
            EventAssociation::Direct
        },
        match_origin: match raw.match_origin {
            skbx_sensor::MATCH_TRACKED_SKB => MatchOrigin::TrackedSkb,
            skbx_sensor::MATCH_TRACKED_XDP => MatchOrigin::TrackedXdp,
            skbx_sensor::MATCH_STACK_ASSOCIATION => MatchOrigin::StackAssociation,
            _ => MatchOrigin::Filter,
        },
        caller: (raw.caller_ip != 0).then(|| FunctionRef {
            address: format!("{:#x}", raw.caller_ip),
            symbol: enrichment.symbols.resolve(raw.caller_ip).map(str::to_owned),
        }),
        stack: enrichment
            .stack
            .iter()
            .map(|address| FunctionRef {
                address: format!("{address:#x}"),
                symbol: enrichment.symbols.resolve(*address).map(str::to_owned),
            })
            .collect(),
        parameters: [
            format!("{:#x}", raw.parameter_second),
            format!("{:#x}", raw.parameter_third),
        ],
        drop_reason,
        bpf_map: components.map.map(convert_bpf_map),
        metadata: convert_metadata(components.metadata, metadata_projections),
        btf_dumps: convert_btf_dumps(components.btf_dumps),
        bpf_program: components.bpf_program.map(convert_bpf_program),
        bpf_program_phase,
        packet: PacketMeta {
            len: raw.len,
            protocol: u16::from_be(raw.protocol),
            mark: raw.mark,
            ifindex: raw.ifindex,
            netns: raw.netns,
            mtu: raw.mtu,
            control_buffer: raw.control_buffer,
            read_status: raw.read_status,
            read_errors: raw.read_failures().into_iter().map(str::to_owned).collect(),
        },
        tuple: packet_tuple(&raw.tuple),
        tunnel_tuple: packet_tuple(&raw.tunnel_tuple),
    }
}

fn convert_bpf_program(raw: skbx_sensor::RawBpfProgram) -> BpfProgramRef {
    BpfProgramRef {
        id: raw.id,
        name: raw.name_string(),
        entry: raw.entry_string(),
        kind: match raw.kind {
            skbx_sensor::BPF_PROGRAM_XDP => BpfProgramKind::Xdp,
            _ => BpfProgramKind::Tc,
        },
    }
}

fn convert_btf_dumps(raw: Option<skbx_sensor::RawBtfDumps>) -> Vec<BtfDump> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    [
        (
            skbx_sensor::BTF_DUMP_SK_BUFF,
            "sk_buff",
            raw.skb_result,
            &raw.skb[..],
        ),
        (
            skbx_sensor::BTF_DUMP_SHARED_INFO,
            "skb_shared_info",
            raw.shared_info_result,
            &raw.shared_info[..],
        ),
    ]
    .into_iter()
    .filter(|(flag, _, _, _)| raw.requested & flag != 0)
    .map(|(_, type_name, result, bytes)| {
        if result < 0 {
            return BtfDump {
                type_name: type_name.into(),
                rendered: None,
                bytes_required: 0,
                bytes_captured: 0,
                truncated: false,
                read_error: Some(format!("kernel_error:{result}")),
            };
        }
        let captured = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        BtfDump {
            type_name: type_name.into(),
            rendered: Some(String::from_utf8_lossy(&bytes[..captured]).into_owned()),
            bytes_required: result as u64,
            bytes_captured: captured as u32,
            truncated: result as usize >= bytes.len(),
            read_error: None,
        }
    })
    .collect()
}

fn convert_metadata(
    raw: Option<skbx_sensor::RawMetadata>,
    projections: &[skbx_core::ResolvedMetadataProjection],
) -> Vec<MetadataValue> {
    projections
        .iter()
        .enumerate()
        .map(|(index, projection)| {
            let read_error = match raw {
                Some(raw)
                    if index < usize::from(raw.count) && raw.read_status & (1_u8 << index) == 0 =>
                {
                    None
                }
                Some(raw) if index < usize::from(raw.count) => Some("kernel_read".into()),
                _ => Some("record_missing".into()),
            };
            let value = read_error
                .is_none()
                .then(|| metadata_scalar(&projection.descriptor, raw.unwrap().values[index]));
            MetadataValue {
                expression: projection.descriptor.expression.clone(),
                type_name: projection.descriptor.type_name.clone(),
                encoding: projection.descriptor.encoding.clone(),
                value,
                read_error,
            }
        })
        .collect()
}

fn metadata_scalar(projection: &skbx_contract::MetadataProjection, raw: u64) -> MetadataScalar {
    let bits = u32::from(projection.size) * 8;
    let value = if bits < 64 {
        raw & ((1_u64 << bits) - 1)
    } else {
        raw
    };
    match projection.encoding {
        MetadataEncoding::Unsigned => MetadataScalar::Unsigned { value },
        MetadataEncoding::Signed => {
            let value = if bits == 64 {
                value as i64
            } else {
                ((value << (64 - bits)) as i64) >> (64 - bits)
            };
            MetadataScalar::Signed { value }
        }
        MetadataEncoding::Boolean => MetadataScalar::Boolean { value: value != 0 },
        MetadataEncoding::Pointer => MetadataScalar::Pointer {
            address: format!("{value:#x}"),
        },
    }
}

fn convert_bpf_map(raw: skbx_sensor::RawMapTraceEvent) -> BpfMapOperation {
    let operation = match raw.operation {
        skbx_sensor::MAP_OPERATION_UPDATE => BpfMapOperationKind::Update,
        skbx_sensor::MAP_OPERATION_DELETE => BpfMapOperationKind::Delete,
        _ => BpfMapOperationKind::Lookup,
    };
    let key_len = usize::from(raw.key_captured).min(raw.key.len());
    let value_len = usize::from(raw.value_captured).min(raw.value.len());
    let read_errors = [
        (skbx_sensor::MAP_READ_METADATA_FAILED, "metadata"),
        (skbx_sensor::MAP_READ_KEY_FAILED, "key"),
        (skbx_sensor::MAP_READ_VALUE_FAILED, "value"),
    ]
    .into_iter()
    .filter(|(mask, _)| raw.read_status & mask != 0)
    .map(|(_, name)| name.to_owned())
    .collect();
    BpfMapOperation {
        operation,
        map_id: raw.map_id,
        map_name: raw.map_name_string(),
        key_size: raw.key_size,
        value_size: raw.value_size,
        key: (raw.read_status & skbx_sensor::MAP_READ_KEY_FAILED == 0)
            .then(|| hex_bytes(&raw.key[..key_len])),
        value: (raw.operation == skbx_sensor::MAP_OPERATION_UPDATE
            && raw.read_status & skbx_sensor::MAP_READ_VALUE_FAILED == 0)
            .then(|| hex_bytes(&raw.value[..value_len])),
        key_truncated: raw.key_size > u32::from(raw.key_captured),
        value_truncated: raw.operation == skbx_sensor::MAP_OPERATION_UPDATE
            && raw.value_size > u32::from(raw.value_captured),
        read_errors,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(2 + bytes.len() * 2);
    output.push_str("0x");
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn drop_reason_parameter(function: &str, raw: &skbx_sensor::RawTraceEvent) -> Option<u64> {
    match function {
        "kfree_skb_reason" => Some(raw.parameter_second),
        "sk_skb_reason_drop" => Some(raw.parameter_third),
        _ => None,
    }
}

fn reliability_delta(current: &Reliability, previous: &Reliability) -> Reliability {
    Reliability {
        kernel_reserve_failures: current
            .kernel_reserve_failures
            .saturating_sub(previous.kernel_reserve_failures),
        kernel_read_failures: current
            .kernel_read_failures
            .saturating_sub(previous.kernel_read_failures),
        kernel_filtered_events: current
            .kernel_filtered_events
            .saturating_sub(previous.kernel_filtered_events),
        userspace_decode_failures: current
            .userspace_decode_failures
            .saturating_sub(previous.userspace_decode_failures),
        userspace_enrichment_failures: current
            .userspace_enrichment_failures
            .saturating_sub(previous.userspace_enrichment_failures),
        output_failures: current
            .output_failures
            .saturating_sub(previous.output_failures),
    }
}

fn packet_tuple(raw: &skbx_sensor::RawPacketTuple) -> Option<PacketTuple> {
    let (source, destination) = match raw.l3_protocol {
        0x0800 => (
            Ipv4Addr::new(raw.saddr[0], raw.saddr[1], raw.saddr[2], raw.saddr[3]).to_string(),
            Ipv4Addr::new(raw.daddr[0], raw.daddr[1], raw.daddr[2], raw.daddr[3]).to_string(),
        ),
        0x86dd => (
            Ipv6Addr::from(raw.saddr).to_string(),
            Ipv6Addr::from(raw.daddr).to_string(),
        ),
        _ => return None,
    };
    Some(PacketTuple {
        source,
        destination,
        source_port: u16::from_be(raw.sport),
        destination_port: u16::from_be(raw.dport),
        l3_protocol: raw.l3_protocol,
        l4_protocol: raw.l4_protocol,
        tcp_flags: raw.tcp_flags,
        icmp_type: matches!(raw.l4_protocol, 1 | 58).then_some(raw.icmp_type),
        icmp_code: matches!(raw.l4_protocol, 1 | 58).then_some(raw.icmp_code),
    })
}

fn write_start(writer: &mut impl Write, format: OutputFormat, start: &CaptureStart) -> Result<()> {
    match format {
        OutputFormat::Jsonl => write_envelope(writer, &Envelope::CaptureStart(start.clone())),
        OutputFormat::Text => {
            writeln!(
                writer,
                "skbx capture {} — kernel {} — probes: {}",
                start.capture_id,
                start.kernel_release,
                start.probes.join(",")
            )?;
            if start.timestamp_mode == "none" {
                writeln!(
                    writer,
                    "{:<5} {:<8} {:<18} {:<8} {:<7} {:<13} FUNCTION",
                    "CPU", "PID", "SKB", "LEN", "ASSOC", "ORIGIN"
                )?;
            } else {
                writeln!(
                    writer,
                    "{:<30} {:<5} {:<8} {:<18} {:<8} {:<7} {:<13} FUNCTION",
                    "TIME", "CPU", "PID", "SKB", "LEN", "ASSOC", "ORIGIN"
                )?;
            }
            Ok(())
        }
    }
}

fn write_event(writer: &mut impl Write, format: OutputFormat, event: &TraceEvent) -> Result<()> {
    match format {
        OutputFormat::Jsonl => write_envelope(writer, &Envelope::Event(event.clone())),
        OutputFormat::Text => {
            let function = event_display_name(event);
            let association = match event.association {
                EventAssociation::Direct => "direct",
                EventAssociation::Stack => "stack",
            };
            let origin = match event.match_origin {
                MatchOrigin::Filter => "filter",
                MatchOrigin::TrackedSkb => "tracked_skb",
                MatchOrigin::TrackedXdp => "tracked_xdp",
                MatchOrigin::StackAssociation => "stack",
            };
            if let Some(timestamp) = &event.presentation_timestamp {
                writeln!(
                    writer,
                    "{:<30} {:<5} {:<8} {:<18} {:<8} {:<7} {:<13} {}",
                    timestamp.display,
                    event.cpu,
                    event.pid,
                    event.skb,
                    event.packet.len,
                    association,
                    origin,
                    &function
                )?;
            } else {
                writeln!(
                    writer,
                    "{:<5} {:<8} {:<18} {:<8} {:<7} {:<13} {}",
                    event.cpu,
                    event.pid,
                    event.skb,
                    event.packet.len,
                    association,
                    origin,
                    &function
                )?;
            }
            for dump in &event.btf_dumps {
                writeln!(
                    writer,
                    "BTF {} captured={}/{} truncated={} error={}",
                    dump.type_name,
                    dump.bytes_captured,
                    dump.bytes_required,
                    dump.truncated,
                    dump.read_error.as_deref().unwrap_or("none")
                )?;
                if let Some(rendered) = &dump.rendered {
                    writeln!(writer, "{rendered}")?;
                }
            }
            Ok(())
        }
    }
}

fn event_display_name(event: &TraceEvent) -> String {
    event.bpf_program.as_ref().map_or_else(
        || {
            event
                .function
                .symbol
                .clone()
                .unwrap_or_else(|| event.function.address.clone())
        },
        |program| {
            let kind = match program.kind {
                BpfProgramKind::Tc => "tc",
                BpfProgramKind::Xdp => "xdp",
            };
            format!(
                "bpf:{kind}:{}:{}/{}",
                program.id, program.name, program.entry
            )
        },
    )
}

fn write_end(writer: &mut impl Write, format: OutputFormat, end: &CaptureEnd) -> Result<()> {
    match format {
        OutputFormat::Jsonl => write_envelope(writer, &Envelope::CaptureEnd(end.clone())),
        OutputFormat::Text => {
            writeln!(
                writer,
                "capture_end events={} complete={} reserve_failures={} decode_failures={} reason={:?}",
                end.events,
                end.complete,
                end.reliability.kernel_reserve_failures,
                end.reliability.userspace_decode_failures,
                end.stop_reason
            )?;
            Ok(())
        }
    }
}

fn write_envelope(writer: &mut impl Write, envelope: &Envelope) -> Result<()> {
    serde_json::to_writer(&mut *writer, envelope).context("encode traceq envelope")?;
    writer.write_all(b"\n").context("write traceq newline")
}

fn write_pretty_stdout(value: &impl serde::Serialize) -> Result<()> {
    let stdout = std::io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    serde_json::to_writer_pretty(&mut writer, value).context("encode JSON")?;
    writer.write_all(b"\n").context("write JSON newline")?;
    writer.flush().context("flush stdout")
}

extern "C" fn request_stop(_: i32) {
    STOP_REQUESTED.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    // SAFETY: request_stop is an async-signal-safe handler that only writes
    // an AtomicBool. The process owns these signal dispositions.
    unsafe {
        libc::signal(
            libc::SIGINT,
            request_stop as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            request_stop as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_program_identity_is_exact_in_events_and_text() {
        let mut name = [0; 16];
        name[..8].copy_from_slice(b"cls_test");
        let mut entry = [0; 64];
        entry[..15].copy_from_slice(b"classify_packet");
        let event = convert_event(
            "capture",
            0,
            skbx_sensor::RawTraceEvent {
                skb_addr: 1,
                ..Default::default()
            },
            RawEventComponents {
                bpf_program: Some(skbx_sensor::RawBpfProgram {
                    id: 42,
                    kind: skbx_sensor::BPF_PROGRAM_TC,
                    phase: skbx_sensor::BPF_PROGRAM_PHASE_ENTRY,
                    name,
                    entry,
                    ..Default::default()
                }),
                ..Default::default()
            },
            EventEnrichment {
                metadata_projections: &[],
                xdp_metadata_projections: &[],
                symbols: &SymbolTable::default(),
                drop_reasons: &DropReasonTable::default(),
                stack: &[],
            },
        );

        assert_eq!(
            event.bpf_program,
            Some(BpfProgramRef {
                id: 42,
                name: "cls_test".into(),
                entry: "classify_packet".into(),
                kind: BpfProgramKind::Tc,
            })
        );
        assert_eq!(
            event_display_name(&event),
            "bpf:tc:42:cls_test/classify_packet"
        );
        assert_eq!(event.bpf_program_phase, Some(BpfProgramPhase::Entry));
    }

    #[test]
    fn event_conversion_is_stable() {
        let raw = skbx_sensor::RawTraceEvent {
            timestamp_ns: 1,
            skb_addr: 2,
            function_ip: 0x1010,
            pid: 3,
            cpu: 4,
            len: 64,
            protocol: 8,
            caller_ip: 0x1005,
            tuple: skbx_sensor::RawPacketTuple {
                l3_protocol: 0x0800,
                l4_protocol: 6,
                saddr: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                daddr: [127, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                sport: 1234_u16.to_be(),
                dport: 443_u16.to_be(),
                tcp_flags: 0x12,
                ..Default::default()
            },
            tunnel_tuple: skbx_sensor::RawPacketTuple {
                l3_protocol: 0x0800,
                l4_protocol: 1,
                saddr: [10, 42, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                daddr: [10, 42, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                icmp_type: 8,
                ..Default::default()
            },
            command: {
                let mut command = [0; 16];
                command[..4].copy_from_slice(b"curl");
                command
            },
            ..Default::default()
        };
        let symbols = SymbolTable::parse("0000000000001000 T ip_rcv\n");
        let drop_reasons = DropReasonTable::default();
        let a = convert_event(
            "capture",
            0,
            raw,
            RawEventComponents::default(),
            EventEnrichment {
                metadata_projections: &[],
                xdp_metadata_projections: &[],
                symbols: &symbols,
                drop_reasons: &drop_reasons,
                stack: &[0x1010],
            },
        );
        let b = convert_event(
            "capture",
            0,
            raw,
            RawEventComponents::default(),
            EventEnrichment {
                metadata_projections: &[],
                xdp_metadata_projections: &[],
                symbols: &symbols,
                drop_reasons: &drop_reasons,
                stack: &[0x1010],
            },
        );
        assert_eq!(a, b);
        assert_eq!(a.function.symbol.as_deref(), Some("ip_rcv"));
        assert_eq!(a.caller.as_ref().unwrap().symbol.as_deref(), Some("ip_rcv"));
        assert_eq!(a.stack[0].symbol.as_deref(), Some("ip_rcv"));
        assert_eq!(a.packet.protocol, 0x0800);
        let tuple = a.tuple.unwrap();
        assert_eq!(tuple.source, "127.0.0.1");
        assert_eq!(tuple.destination_port, 443);
        assert_eq!(tuple.tcp_flags, 0x12);
        assert_eq!(tuple.icmp_type, None);
        let tunnel_tuple = a.tunnel_tuple.unwrap();
        assert_eq!(tunnel_tuple.source, "10.42.0.1");
        assert_eq!(tunnel_tuple.destination, "10.42.0.2");
        assert_eq!(tunnel_tuple.icmp_type, Some(8));
        assert_eq!(tunnel_tuple.icmp_code, Some(0));

        let associated = convert_event(
            "capture",
            1,
            skbx_sensor::RawTraceEvent {
                association: skbx_sensor::ASSOCIATION_STACK,
                ..raw
            },
            RawEventComponents::default(),
            EventEnrichment {
                metadata_projections: &[],
                xdp_metadata_projections: &[],
                symbols: &symbols,
                drop_reasons: &drop_reasons,
                stack: &[],
            },
        );
        assert_eq!(associated.association, EventAssociation::Stack);
    }

    #[test]
    fn map_operation_conversion_preserves_bounds_and_read_failures() {
        let mut raw = skbx_sensor::RawMapTraceEvent {
            operation: skbx_sensor::MAP_OPERATION_UPDATE,
            map_id: 7,
            key_size: 40,
            value_size: 8,
            key_captured: skbx_sensor::MAX_MAP_CAPTURE_BYTES as u8,
            value_captured: 8,
            read_status: skbx_sensor::MAP_READ_VALUE_FAILED,
            key: [0xab; skbx_sensor::MAX_MAP_CAPTURE_BYTES],
            ..Default::default()
        };
        raw.map_name[..3].copy_from_slice(b"map");

        let operation = convert_bpf_map(raw);
        assert_eq!(operation.operation, BpfMapOperationKind::Update);
        assert_eq!(operation.map_id, 7);
        assert_eq!(operation.map_name, "map");
        assert_eq!(
            operation.key.as_deref(),
            Some("0xabababababababababababababababababababababababababababababababab")
        );
        assert_eq!(operation.value, None);
        assert!(operation.key_truncated);
        assert!(!operation.value_truncated);
        assert_eq!(operation.read_errors, ["value"]);
    }

    #[test]
    fn metadata_conversion_is_typed_and_reports_individual_failures() {
        let projections = [
            skbx_core::ResolvedMetadataProjection {
                descriptor: skbx_contract::MetadataProjection {
                    expression: "skb->mark".into(),
                    type_name: "unsigned int".into(),
                    encoding: MetadataEncoding::Unsigned,
                    size: 4,
                },
                access: Default::default(),
            },
            skbx_core::ResolvedMetadataProjection {
                descriptor: skbx_contract::MetadataProjection {
                    expression: "skb->skb_iif".into(),
                    type_name: "int".into(),
                    encoding: MetadataEncoding::Signed,
                    size: 4,
                },
                access: Default::default(),
            },
        ];
        let metadata = convert_metadata(
            Some(skbx_sensor::RawMetadata {
                values: [7, u64::from(u32::MAX), 0, 0],
                count: 2,
                ..Default::default()
            }),
            &projections,
        );
        assert_eq!(
            metadata[0].value,
            Some(MetadataScalar::Unsigned { value: 7 })
        );
        assert_eq!(
            metadata[1].value,
            Some(MetadataScalar::Signed { value: -1 })
        );

        let failed = convert_metadata(
            Some(skbx_sensor::RawMetadata {
                count: 2,
                read_status: 1 << 1,
                ..Default::default()
            }),
            &projections,
        );
        assert_eq!(failed[0].read_error, None);
        assert_eq!(failed[1].value, None);
        assert_eq!(failed[1].read_error.as_deref(), Some("kernel_read"));
    }

    #[test]
    fn btf_dump_conversion_preserves_truncation_and_kernel_errors() {
        let mut raw = skbx_sensor::RawBtfDumps {
            skb_result: 5_000,
            shared_info_result: -14,
            requested: skbx_sensor::BTF_DUMP_SK_BUFF | skbx_sensor::BTF_DUMP_SHARED_INFO,
            ..Default::default()
        };
        raw.skb[..skbx_sensor::MAX_BTF_DUMP_BYTES - 1].fill(b'x');
        let dumps = convert_btf_dumps(Some(raw));

        assert_eq!(dumps.len(), 2);
        assert_eq!(dumps[0].type_name, "sk_buff");
        assert_eq!(
            dumps[0].bytes_captured,
            (skbx_sensor::MAX_BTF_DUMP_BYTES - 1) as u32
        );
        assert_eq!(dumps[0].bytes_required, 5_000);
        assert!(dumps[0].truncated);
        assert_eq!(
            dumps[0].rendered.as_ref().unwrap().len(),
            skbx_sensor::MAX_BTF_DUMP_BYTES - 1
        );
        assert_eq!(dumps[1].type_name, "skb_shared_info");
        assert_eq!(dumps[1].rendered, None);
        assert_eq!(dumps[1].read_error.as_deref(), Some("kernel_error:-14"));
    }

    #[test]
    fn filter_parsing_matches_pwru_mark_semantics() {
        assert_eq!(parse_mark("0xa00/0xf00").unwrap(), (0xa00, 0xf00));
        assert_eq!(parse_mark("12").unwrap(), (12, u32::MAX));
        assert!(parse_mark("1/2/3").is_err());
        assert_eq!(parse_netns("inode:42").unwrap(), 42);
        let current = resolve_filters(None, None, Some("lo"), None).unwrap();
        assert!(current.ifindex > 0);
        assert_eq!(current.netns, netns_inode("/proc/self/ns/net").unwrap());
        let explicit = resolve_filters(None, None, Some("lo"), Some("/proc/self/ns/net")).unwrap();
        assert_eq!(explicit.ifindex, current.ifindex);
        assert_eq!(explicit.netns, current.netns);
        assert!(resolve_filters(None, None, Some("lo"), Some("inode:42")).is_err());
    }

    #[test]
    fn drop_reason_parameter_matches_kernel_signature() {
        let raw = skbx_sensor::RawTraceEvent {
            parameter_second: 11,
            parameter_third: 22,
            ..Default::default()
        };
        assert_eq!(drop_reason_parameter("kfree_skb_reason", &raw), Some(11));
        assert_eq!(drop_reason_parameter("sk_skb_reason_drop", &raw), Some(22));
        assert_eq!(drop_reason_parameter("consume_skb", &raw), None);
    }

    #[test]
    fn readiness_replaces_stale_file_then_uses_create_new() {
        let path = std::env::temp_dir().join(format!(
            "skbx-ready-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"stale").unwrap();
        prepare_ready_file(&path).unwrap();
        assert!(!path.exists());

        signal_ready(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        assert!(signal_ready(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn timestamp_presentations_keep_raw_time_and_bound_relative_state() {
        let raw = skbx_sensor::RawTraceEvent {
            timestamp_ns: 100,
            skb_addr: 1,
            function_ip: 2,
            ..Default::default()
        };
        let event = convert_event(
            "capture",
            0,
            raw,
            RawEventComponents::default(),
            EventEnrichment {
                metadata_projections: &[],
                xdp_metadata_projections: &[],
                symbols: &SymbolTable::default(),
                drop_reasons: &DropReasonTable::default(),
                stack: &[],
            },
        );
        let mut last = BoundedMap::new(2);
        let first = present_timestamp(TimestampOutput::Relative, &event, 1_000, 100, &mut last)
            .unwrap()
            .unwrap();
        assert_eq!(first.value_ns, 0);

        let mut second_event = event.clone();
        second_event.timestamp_ns = 150;
        let second = present_timestamp(
            TimestampOutput::Relative,
            &second_event,
            1_000,
            100,
            &mut last,
        )
        .unwrap()
        .unwrap();
        assert_eq!(second.value_ns, 50);
        assert_eq!(second_event.timestamp_ns, 150);

        let absolute = present_timestamp(
            TimestampOutput::Absolute,
            &second_event,
            1_700_000_000_000_000_000,
            100,
            &mut last,
        )
        .unwrap()
        .unwrap();
        assert_eq!(absolute.value_ns, 1_700_000_000_000_000_050);
        assert!(absolute.display.ends_with('Z'));
    }
}

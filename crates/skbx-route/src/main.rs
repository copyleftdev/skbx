use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use skbx_route::{
    DEFAULT_DESTINATION_PORT, DEFAULT_MAX_DURATION_MS, DEFAULT_MAX_HOPS, DEFAULT_PROBES_PER_HOP,
    DEFAULT_TIMEOUT_MS, ProbePlan, RouteRecord, demo_records, describe, enrich_ripestat, explain,
    read_records, replay, trace_udp,
};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "skbx-route",
    version,
    about = "Bounded route observation with per-hop evidence dossiers",
    long_about = "Trace an IPv4 path with a fixed UDP flow, preserve each hop as replayable evidence, and keep unobserved transit behavior explicitly unknown."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Emit the machine-readable tool contract.
    Describe,
    /// Validate the complete probe budget without sending a packet.
    Plan {
        target: String,
        #[command(flatten)]
        limits: ProbeLimits,
        #[arg(long)]
        json: bool,
    },
    /// Run a bounded, rootless Linux UDP route observation.
    Trace {
        target: String,
        #[command(flatten)]
        limits: ProbeLimits,
        #[arg(long, value_enum, default_value_t = OutputFormat::Jsonl)]
        format: OutputFormat,
        #[arg(long, default_value = "-")]
        output: PathBuf,
    },
    /// Send public responder IPs to RIPEstat for passive routing evidence.
    Enrich {
        input: PathBuf,
        /// Maximum total RIPEstat HTTPS requests, including RPKI lookups.
        #[arg(long, default_value_t = 64)]
        max_lookups: u16,
        /// Per-request HTTPS timeout.
        #[arg(long, default_value_t = 3_000)]
        request_timeout_ms: u64,
        /// Hard wall-clock budget for all enrichment.
        #[arg(long, default_value_t = 30_000)]
        max_duration_ms: u64,
        #[arg(long, default_value = "-")]
        output: PathBuf,
    },
    /// Emit a deterministic documentation-range route for evaluation.
    Demo {
        #[arg(long, value_enum, default_value_t = OutputFormat::Jsonl)]
        format: OutputFormat,
        #[arg(long, default_value = "-")]
        output: PathBuf,
    },
    /// Deterministically summarize a routeq JSONL stream.
    Replay {
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = SummaryFormat::Json)]
        format: SummaryFormat,
    },
    /// Retrieve one hop and its evidence dossier by stable handle.
    Explain { input: PathBuf, handle: String },
}

#[derive(Clone, Debug, clap::Args)]
struct ProbeLimits {
    /// UDP destination port. One fixed five-tuple is retained across the run.
    #[arg(long, default_value_t = DEFAULT_DESTINATION_PORT)]
    port: u16,
    /// Largest IPv4 TTL to send.
    #[arg(long, default_value_t = DEFAULT_MAX_HOPS)]
    max_hops: u8,
    /// Number of observations attempted at each TTL.
    #[arg(long, default_value_t = DEFAULT_PROBES_PER_HOP)]
    probes: u8,
    /// Maximum wait for each probe response.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
    timeout_ms: u64,
    /// Hard wall-clock budget for the complete run.
    #[arg(long, default_value_t = DEFAULT_MAX_DURATION_MS)]
    max_duration_ms: u64,
}

impl ProbeLimits {
    fn plan(&self, target: String) -> Result<ProbePlan> {
        ProbePlan::bounded_udp(
            target,
            self.port,
            self.max_hops,
            self.probes,
            self.timeout_ms,
            self.max_duration_ms,
        )
        .map_err(Into::into)
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Jsonl,
    Text,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SummaryFormat {
    Json,
    Text,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Describe => {
            println!("{}", serde_json::to_string_pretty(&describe(VERSION))?);
        }
        Command::Plan {
            target,
            limits,
            json,
        } => {
            let plan = limits.plan(target)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                println!("PLAN {}", plan.digest());
                println!("target              {}", plan.target);
                println!("protocol            udp");
                println!("flow strategy       {}", plan.flow_strategy);
                println!("max hops            {}", plan.max_hops);
                println!("probes per hop      {}", plan.probes_per_hop);
                println!("max packets         {}", plan.max_packets);
                println!("per-probe timeout   {} ms", plan.timeout_ms);
                println!("wall-clock budget   {} ms", plan.max_duration_ms);
                println!("active enrichment   disabled");
            }
        }
        Command::Trace {
            target,
            limits,
            format,
            output,
        } => {
            let plan = limits.plan(target)?;
            eprintln!(
                "skbx-route: sending at most {} UDP probes over {} hops within {} ms",
                plan.max_packets, plan.max_hops, plan.max_duration_ms
            );
            let records = trace_udp(&plan)?;
            write_records(&records, format, &output)?;
        }
        Command::Enrich {
            input,
            max_lookups,
            request_timeout_ms,
            max_duration_ms,
            output,
        } => {
            let file = File::open(&input)
                .with_context(|| format!("open routeq input {}", input.display()))?;
            let mut records = read_records(file)?;
            replay(&records)?;
            let report = enrich_ripestat(
                &mut records,
                max_lookups,
                request_timeout_ms,
                max_duration_ms,
            )
            .await?;
            write_records(&records, OutputFormat::Jsonl, &output)?;
            eprintln!(
                "skbx-route: RIPEstat lookups={} succeeded={} failed={} skipped_non_global={} lookup_budget_exhausted={} duration_exhausted={}",
                report.lookups_attempted,
                report.lookups_succeeded,
                report.lookups_failed,
                report.skipped_non_global_addresses,
                report.lookup_budget_exhausted,
                report.duration_exhausted
            );
        }
        Command::Demo { format, output } => {
            write_records(&demo_records(), format, &output)?;
        }
        Command::Replay { input, format } => {
            let file = File::open(&input)
                .with_context(|| format!("open routeq input {}", input.display()))?;
            let summary = replay(&read_records(file)?)?;
            match format {
                SummaryFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                }
                SummaryFormat::Text => {
                    println!(
                        "{} {} → {} hops={} responsive={} reached={} complete={}",
                        summary.route_handle,
                        summary.target,
                        summary.target_ip,
                        summary.hops,
                        summary.responsive_hops,
                        summary.destination_reached,
                        summary.complete
                    );
                }
            }
        }
        Command::Explain { input, handle } => {
            let file = File::open(&input)
                .with_context(|| format!("open routeq input {}", input.display()))?;
            let explanation = explain(&read_records(file)?, &handle)?;
            println!("{}", serde_json::to_string_pretty(&explanation)?);
        }
    }
    Ok(())
}

fn write_records(records: &[RouteRecord], format: OutputFormat, output: &Path) -> Result<()> {
    let sink: Box<dyn Write> = if output == Path::new("-") {
        Box::new(std::io::stdout())
    } else {
        Box::new(
            File::create(output)
                .with_context(|| format!("create routeq output {}", output.display()))?,
        )
    };
    let mut writer = BufWriter::new(sink);
    match format {
        OutputFormat::Jsonl => {
            for record in records {
                serde_json::to_writer(&mut writer, record)?;
                writer.write_all(b"\n")?;
            }
        }
        OutputFormat::Text => write_text(records, &mut writer)?,
    }
    writer.flush()?;
    Ok(())
}

fn write_text(records: &[RouteRecord], writer: &mut dyn Write) -> Result<()> {
    for record in records {
        match record {
            RouteRecord::TraceStart {
                trace_id,
                target_ip,
                plan,
                ..
            } => {
                writeln!(
                    writer,
                    "{trace_id} {} ({target_ip}) udp/{}",
                    plan.target, plan.destination_port
                )?;
            }
            RouteRecord::Hop { hop, .. } => {
                write!(writer, "{:>2}  ", hop.ttl)?;
                for probe in &hop.probes {
                    match (probe.responder, probe.rtt_ns) {
                        (Some(address), Some(rtt)) => {
                            write!(
                                writer,
                                "{} {:.3}ms {:?}  ",
                                address,
                                rtt as f64 / 1_000_000.0,
                                probe.outcome
                            )?;
                        }
                        _ => write!(writer, "* {:?}  ", probe.outcome)?,
                    }
                }
                writeln!(writer, "{}", hop.handle)?;
            }
            RouteRecord::TraceEnd {
                destination_reached,
                stop_reason,
                reliability,
                ..
            } => {
                writeln!(
                    writer,
                    "END reached={} stop={:?} attempted={} sent={} replies={} timeouts={} local_errors={} complete={}",
                    destination_reached,
                    stop_reason,
                    reliability.attempted_packets,
                    reliability.sent_packets,
                    reliability.replies,
                    reliability.timeouts,
                    reliability.local_errors,
                    reliability.complete
                )?;
            }
        }
    }
    Ok(())
}

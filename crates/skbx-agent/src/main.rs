use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use skbx_agent::{AgentClient, run_fixture_once};
use skbx_mission::SensorRegistration;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "skbx-agent",
    version,
    about = "Outbound-only sensor agent for skbx Arc"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Poll once and submit a pre-existing traceq artifact.
    ///
    /// This rootless lab mode exercises the entire control-plane protocol
    /// without attaching probes or accepting remote shell commands.
    FixtureOnce {
        #[arg(long, default_value = "http://127.0.0.1:7878")]
        control: String,
        #[arg(long)]
        sensor_id: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        kernel_release: Option<String>,
        #[arg(long, default_value_t = 2_000_000)]
        clock_uncertainty_ns: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::FixtureOnce {
            control,
            sensor_id,
            display_name,
            artifact,
            kernel_release,
            clock_uncertainty_ns,
        } => {
            let kernel_release = kernel_release
                .map(Ok)
                .unwrap_or_else(read_kernel_release)
                .context("determine kernel release")?;
            let client = AgentClient::new(control)?;
            let report = run_fixture_once(
                &client,
                SensorRegistration {
                    sensor_id,
                    display_name,
                    kernel_release,
                    capabilities: vec![
                        "fixture-artifact-submit".into(),
                        "deterministic-replay".into(),
                    ],
                    clock_uncertainty_ns,
                },
                &artifact,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

fn read_kernel_release() -> Result<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_owned())
        .context("read /proc/sys/kernel/osrelease")
}

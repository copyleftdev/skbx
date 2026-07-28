use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use skbx_arc::{ControlPlane, app, demo_control_plane, shared};
use std::net::SocketAddr;

#[derive(Debug, Parser)]
#[command(
    name = "skbx-arc",
    version,
    about = "Evidence-first control plane for bounded skbx capture missions"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve the local Arc API and Mission Constellation console.
    Serve {
        /// Socket address to listen on. Arc stays loopback-only by default.
        #[arg(long, default_value = "127.0.0.1:7878")]
        bind: SocketAddr,

        /// Seed a complete three-sensor investigation for local evaluation.
        #[arg(long)]
        demo: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { bind, demo } => {
            let control = if demo {
                demo_control_plane()
            } else {
                ControlPlane::default()
            };
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .with_context(|| format!("bind Arc to {bind}"))?;
            eprintln!(
                "skbx Arc listening on http://{bind}{}",
                if demo { " (demo mission loaded)" } else { "" }
            );
            axum::serve(listener, app(shared(control)))
                .with_graceful_shutdown(shutdown_signal())
                .await
                .context("serve Arc")?;
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

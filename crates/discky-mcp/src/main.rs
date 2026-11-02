//! `discky-mcp`: Discky's MCP server over stdio. stdout carries only the protocol; logs go
//! to stderr.

mod params;
mod server;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use discky_core::index::snapshot::Actor;
use discky_core::{Engine, ScanStatus};
use rmcp::serve_server;

use crate::server::DisckyServer;

#[derive(Parser)]
#[command(version, about = "Discky MCP server (stdio)")]
struct Cli {
    /// Directory holding config.toml, snapshot.bin and removals.log (sets DISCKY_HOME).
    #[arg(long)]
    home: Option<PathBuf>,
    /// Log filter for stderr, e.g. `warn`, `info`, `discky_mcp=debug`.
    #[arg(long, default_value = "warn")]
    log_level: String,
    /// Run one scan of the configured roots, print node count, duration and max RSS, exit.
    #[arg(long, hide = true)]
    self_test_scan: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Some(home) = &cli.home {
        // SAFETY: no other thread exists yet (the runtime is built below).
        unsafe { std::env::set_var("DISCKY_HOME", home) };
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::new(&cli.log_level))
        .init();

    let engine = match Engine::open(Actor::Mcp) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            tracing::error!("cannot open Discky: {e}");
            eprintln!("discky-mcp: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(e) = engine.last_error() {
        tracing::warn!("{e}");
    }
    if cli.self_test_scan {
        return self_test_scan(&engine);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match runtime.block_on(serve(engine)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            eprintln!("discky-mcp: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(engine: Arc<Engine>) -> Result<(), Box<dyn std::error::Error>> {
    let service = serve_server(DisckyServer::new(engine), rmcp::transport::io::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// Scan the configured roots synchronously and print node count, duration and max RSS.
fn self_test_scan(engine: &Engine) -> ExitCode {
    let started = Instant::now();
    let id = engine.start_scan(None);
    let status = engine.wait_scan(&id, Duration::from_secs(24 * 3600));
    let elapsed = started.elapsed();
    // SAFETY: `usage` is a valid, writable rusage for the duration of the call.
    let max_rss = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage.ru_maxrss // bytes on macOS
    };
    match status {
        ScanStatus::Done { node_count, .. } => {
            println!("nodes: {node_count}");
            println!("duration_ms: {}", elapsed.as_millis());
            println!(
                "nodes_per_sec: {:.0}",
                f64::from(node_count) / elapsed.as_secs_f64()
            );
            println!("max_rss_bytes: {max_rss}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("discky-mcp: scan did not finish: {other:?}");
            ExitCode::FAILURE
        }
    }
}

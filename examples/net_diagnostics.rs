//! Network diagnostics example.
//!
//! Runs a full network diagnostics report from an iroh Endpoint — covering
//! UDP connectivity, relay latency, and port mapping protocol availability.
//!
//! Run with: cargo run --features=net_diagnostics --example net_diagnostics
//!
use anyhow::Result;
use iroh::Endpoint;
use iroh_n0des::net_diagnostics::diagnose;

#[tokio::main]
async fn main() -> Result<()> {
    let endpoint = Endpoint::bind().await?;

    println!("Running network diagnostics...\n");
    let report = diagnose(&endpoint).await?;
    println!("{report}");

    endpoint.close().await;
    Ok(())
}

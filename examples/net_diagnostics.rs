//! Network diagnostics example for iroh-powered applications.
//!
//! Demonstrates how to run a full network diagnostics report from an existing
//! iroh Endpoint — covering NAT type, UDP connectivity, relay latency, and
//! port mapping protocol availability.
//!
//! Run with: cargo run --features=net_diagnostics --example net_diagnostics
use anyhow::Result;
use iroh::Endpoint;
use iroh_n0des::Client;

#[tokio::main]
async fn main() -> Result<()> {
    // In your app you already have an Endpoint. Here we create one to demonstrate.
    let endpoint = Endpoint::bind().await?;

    let client = Client::builder(&endpoint)
        .api_secret_from_env()?
        .build()
        .await?;

    println!("Running network diagnostics...\n");
    // pass true to upload the results to n0des
    let report = client.net_diagnostics(false).await?;
    println!("{report}");

    endpoint.close().await;
    Ok(())
}

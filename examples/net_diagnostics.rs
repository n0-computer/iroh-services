//! Network diagnostics example with a ClientHost.
//!
//! Demonstrates how to set up a ClientHost that accepts incoming n0des RPC
//! requests, and run a full network diagnostics report from an existing iroh
//! Endpoint — covering NAT type, UDP connectivity, relay latency, and port
//! mapping protocol availability.
//!
//! The ClientHost registers on the n0des ALPN so that the remote n0des service
//! can dial back into this endpoint to request diagnostics on demand.
//!
//! Run with: cargo run --features=net_diagnostics,client_host --example net_diagnostics
use anyhow::Result;
use iroh::{Endpoint, protocol::Router};
use iroh_n0des::{ALPN, API_SECRET_ENV_VAR_NAME, ApiSecret, Client, ClientHost};

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Create an endpoint that will both dial n0des and accept incoming
    //    requests from the n0des service via a ClientHost.
    let endpoint = Endpoint::builder().bind().await?;

    // 2. Parse the ApiSecret separately so we can extract the remote
    //    EndpointID. Normally we'd pass it straight to the client builder.
    let secret = ApiSecret::from_env_var(API_SECRET_ENV_VAR_NAME)?;

    // 3. Build a Client that dials n0des (as in all other examples).
    let client = Client::builder(&endpoint)
        .api_secret(secret.clone())?
        .build()
        .await?;

    // 4. Set up a ClientHost so n0des can dial *back* into this endpoint.
    //    The allow-list restricts accepted connections to the n0des service
    //    endpoint extracted from the ApiSecret.
    let host = ClientHost::new(&endpoint, vec![secret.addr().id]);

    // 5. Register the ClientHost on the n0des ALPN and spawn the router.
    //    Once running, n0des can open connections to this endpoint and send
    //    RPC requests such as RunNetworkDiagnostics.
    let router = Router::builder(endpoint)
        .accept(ALPN.to_vec(), host)
        .spawn();

    // 6. Run diagnostics locally (pass true to also upload results to n0des).
    println!("Running network diagnostics...\n");
    let report = client.net_diagnostics(false).await?;
    println!("{report}");

    println!("waiting");
    tokio::signal::ctrl_c().await?;
    router.endpoint().close().await;
    Ok(())
}

//! Network diagnostics example with a ClientHost.
//!
//! Demonstrates how to set up a ClientHost that accepts incoming iroh-services RPC
//! requests, and run a full network diagnostics report from an existing iroh
//! Endpoint — covering NAT type, UDP connectivity, relay latency, and port
//! mapping protocol availability.
//!
//! The ClientHost registers on the [CLIENT_HOST_ALPN], so that the remote
//! iroh-services service can dial back into this endpoint to request diagnostics.
//!
//! Run with: cargo run --features=net_diagnostics,client_host --example net_diagnostics
use anyhow::Result;
use iroh::{Endpoint, protocol::Router};
use iroh_services::{
    API_SECRET_ENV_VAR_NAME, ApiSecret, CLIENT_HOST_ALPN, Client, ClientHost,
    caps::NetDiagnosticsCap,
};

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Create an endpoint that will both dial iroh-services and accept incoming
    //    requests from the iroh-services service via a ClientHost.
    let endpoint = Endpoint::builder().bind().await?;

    // 2. Parse the ApiSecret separately so we can extract the remote
    //    EndpointID. Normally we'd pass it straight to the client builder.
    let secret = ApiSecret::from_env_var(API_SECRET_ENV_VAR_NAME)?;

    // 3. Build a Client that dials iroh-services (as in all other examples).
    let client = Client::builder(&endpoint)
        .api_secret(secret.clone())?
        .build()
        .await?;

    // 4. grant the ability to get diagnostics to the remote EndpointID associated
    //    with our project on iroh-services. This will create a capability token, send it to
    //    the remote for storage & confirm receipt. We do this in a task to avoid
    //    blocking the local node startup in the rare case that remote endpoint is
    //    down when this process starts.
    let client2 = client.clone();
    let remote_id = secret.addr().id;
    let t = tokio::spawn(async move {
        if let Err(err) = client2
            .grant_capability(remote_id, vec![NetDiagnosticsCap::GetAny])
            .await
        {
            eprintln!("Failed to grant capability: {err:?}");
        }
    });

    // 5. Set up a ClientHost so iroh-services can dial *back* into this endpoint.
    //    Incoming connections must present an RCAN issued by this endpoint.
    let host = ClientHost::new(&endpoint);
    let router = Router::builder(endpoint)
        .accept(CLIENT_HOST_ALPN, host)
        .spawn();

    // 6. Run diagnostics locally (pass true to also upload results to iroh-services).
    println!("Running network diagnostics...\n");
    let report = client.net_diagnostics(false).await?;
    println!("{:?}", report);

    println!("waiting for remote diagnostics requests. ctrl+c to exit.");
    tokio::signal::ctrl_c().await?;
    router.endpoint().close().await;
    t.abort();

    Ok(())
}

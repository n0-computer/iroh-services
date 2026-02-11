//! Network diagnostics example with a ClientHost.
//!
//! Demonstrates how to set up a ClientHost that accepts incoming n0des RPC
//! requests, and run a full network diagnostics report from an existing iroh
//! Endpoint — covering NAT type, UDP connectivity, relay latency, and port
//! mapping protocol availability.
//!
//! The ClientHost registers on the n0des ALPN for general RPC, and a
//! DiagnosticsHost on a dedicated net-diagnostics ALPN so that the remote
//! n0des service can dial back into this endpoint to request diagnostics.
//!
//! Run with: cargo run --features=net_diagnostics,client_host --example net_diagnostics
use anyhow::Result;
use iroh::{Endpoint, protocol::Router};
use iroh_n0des::{
    ALPN, API_SECRET_ENV_VAR_NAME, ApiSecret, Client, ClientHost, DiagnosticsHost,
    NET_DIAGNOSTICS_ALPN, caps::NetDiagnosticsCap,
};

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

    // 4. grant the ability to get diagnostics to the remote EndpointID associated
    //    with our project on n0des. This will create a capability token, send it to
    //    the remote for storage & confirm receipt. We do this in a task to avoid
    //    blocking the local node startup in the rare case that remote endpoint is
    //    down when this process starts.
    let client2 = client.clone();
    let remote_id = secret.addr().id;
    tokio::spawn(async move {
        client2
            .grant_capability(remote_id, vec![NetDiagnosticsCap::GetAny])
            .await
            .unwrap();
    });

    // 5. Set up a ClientHost so n0des can dial *back* into this endpoint.
    //    Incoming connections must present an RCAN issued by this endpoint.
    let host = ClientHost::new(&endpoint);

    // 6. Register the ClientHost on the n0des ALPN and DiagnosticsHost on
    //    the dedicated net-diagnostics ALPN. Once running, n0des can open
    //    connections to request diagnostics via the dedicated protocol.
    let diag_host = DiagnosticsHost::new(&endpoint);
    let router = Router::builder(endpoint)
        .accept(ALPN, host)
        .accept(NET_DIAGNOSTICS_ALPN, diag_host)
        .spawn();

    // 6. Run diagnostics locally (pass true to also upload results to n0des).
    println!("Running network diagnostics...\n");
    let report = client.net_diagnostics(false).await?;
    println!("{:?}", report);

    println!("waiting for remote diagnostics requests. ctrl+c to exit.");
    tokio::signal::ctrl_c().await?;
    router.endpoint().close().await;
    Ok(())
}

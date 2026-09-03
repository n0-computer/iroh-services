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
//! Run with: cargo run --example net_diagnostics
use iroh::{Endpoint, protocol::Router};
use iroh_services::{CLIENT_HOST_ALPN, ClientHost, caps::Caps};
use n0_error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // 1. Create an endpoint that will both dial iroh-services and accept incoming
    //    requests from the iroh-services service via a ClientHost.
    //    Needs IROH_SERVICES_API_SECRET set as an environment variable.
    //    The preset is cloned so we can reuse its API secret below.
    let preset = iroh_services::preset().api_secret_from_env()?.build()?;

    let endpoint = Endpoint::bind(preset.clone()).await?;

    // optional: name the endpoint. Here we generate a name from the endpoint id
    // to keep name unique. in your app this would be used to connect with
    // something like a userId or machine name
    let id = endpoint.id().to_string();
    let name = format!("net-diagnostics-example-{}", &id[..8]);

    // 2. Build a Client that dials iroh-services (as in all other examples).
    //    client_builder reuses the preset's API secret, which also carries the
    //    address of the iroh-services endpoint to dial.
    let client = preset.client_builder(&endpoint).name(name)?.build().await?;

    // 3. grant the ability to get diagnostics to the remote EndpointID associated
    //    with our project on iroh-services. This will create a capability token, send it to
    //    the remote for storage & confirm receipt. We do this in a task to avoid
    //    blocking the local node startup in the rare case that remote endpoint is
    //    down when this process starts.
    let client2 = client.clone();
    let remote_id = preset.api_secret().addr().id;
    let t = tokio::spawn(async move {
        if let Err(err) = client2
            .grant_capability(remote_id, Caps::net_diagnostics_get_any())
            .await
        {
            eprintln!("Failed to grant capability: {err:?}");
        }
    });

    // 4. Set up a ClientHost so iroh-services can dial *back* into this endpoint.
    //    Incoming connections must present an RCAN issued by this endpoint.
    let host = ClientHost::new(&endpoint);
    let router = Router::builder(endpoint)
        .accept(CLIENT_HOST_ALPN, host)
        .spawn();

    // 5. Run diagnostics locally and upload the results to iroh-services
    //    (pass false to keep the report local).
    println!("Running network diagnostics...\n");
    let report = client.net_diagnostics(true).await?;
    println!("{:?}", report);

    println!("waiting for remote diagnostics requests. ctrl+c to exit.");
    tokio::signal::ctrl_c().await?;
    // push the metrics accumulated since the last interval tick
    client.shutdown().await;
    router.endpoint().close().await;
    t.abort();

    Ok(())
}

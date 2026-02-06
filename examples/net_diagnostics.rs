//! Network diagnostics example for iroh-powered applications.
//!
//! Demonstrates how to run a full network diagnostics report from an existing
//! iroh Endpoint — covering NAT type, UDP connectivity, relay latency, and
//! port mapping protocol availability.
//!
//! Run with: cargo run --features=net_diagnostics,client_host --example net_diagnostics
use anyhow::Result;
use iroh::{Endpoint, protocol::Router};
use iroh_n0des::{ALPN, API_SECRET_ENV_VAR_NAME, ApiSecret, Client, ClientHost};

#[tokio::main]
async fn main() -> Result<()> {
    // start by creating an endpoint, we're going to register a ClientHost to
    // this endpoint so n0des can request network diagnostic reports remotely
    // to do that we need to set up a ClientHost that only accepts connections
    // from the remote
    let endpoint = Endpoint::builder().bind().await?;

    // normally we would pass the ApiSecret directly to our client builder,
    // but in this case we parse it separately so we can extract the
    // EndpointID this n0des account belongs to.
    let secret = ApiSecret::from_env_var(API_SECRET_ENV_VAR_NAME)?;

    // create a client as we do in all other examples, passing in the parsed
    // secret.
    let client = Client::builder(&endpoint)
        .api_secret(secret.clone())?
        .build()
        .await?;

    // configure the client host, locking the set of endpoints it will accept
    // communication from to the endpoint within the API secret
    let host = ClientHost::new(&endpoint, vec![secret.addr().id]);

    // build a router & register our host on the n0des ALPN
    let router = Router::builder(endpoint)
        .accept(ALPN.to_vec(), host)
        .spawn();

    println!("Running network diagnostics...\n");
    // pass true to upload the results to n0des
    let report = client.net_diagnostics(false).await?;
    println!("{report}");

    println!("waiting");
    tokio::signal::ctrl_c().await?;
    router.endpoint().close().await;
    Ok(())
}

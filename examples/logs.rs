//! Log collection example.
//!
//! Demonstrates how to install the iroh-services log collector alongside the
//! standard `tracing-subscriber` `fmt` layer, ship records to the cloud over
//! the iroh-services RPC channel, and let the cloud override the local
//! filter at runtime via `SetLogLevel`.
//!
//! The level filter starts at `off`. The cloud pushes a level after this
//! endpoint is opted into log collection from the dashboard or REST API; both
//! the buffered cloud-shipping layer and the stderr fmt layer respect that
//! level. Anything emitted before the cloud responds is silently dropped.
//!
//! Run with: cargo run --example logs

use std::time::Duration;
use tracing_subscriber::prelude::*;

use anyhow::Result;
use iroh::{Endpoint, endpoint::presets, protocol::Router};
use iroh_services::{
    API_SECRET_ENV_VAR_NAME, ApiSecret, CLIENT_HOST_ALPN, Client, ClientHost, caps::LogsCap, logs,
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Build the buffer layer and compose it with a stderr fmt layer behind
    //    the same reloadable filter, so local console output mirrors what
    //    gets shipped. The cloud raises the filter from `off` after this
    //    endpoint is opted in via the dashboard.
    let (collector, log_layer) = logs::layer();
    tracing_subscriber::registry()
        .with(log_layer)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init()
        .map_err(|e| anyhow::anyhow!("failed to install tracing subscriber: {e}"))?;

    // 2. Create the endpoint and parse the API secret so we know which
    //    cloud endpoint to grant SetLevel to.
    let endpoint = Endpoint::bind(presets::N0).await?;
    let secret = ApiSecret::from_env_var(API_SECRET_ENV_VAR_NAME)?;
    let cloud_id = secret.addr().id;

    let name = format!("logs-example-{}", &endpoint.id().to_string()[..8]);

    // 3. Build the client. `with_log_collection(collector.clone())` starts a
    //    background task that drains the buffer every second and ships the
    //    batch as a `PutLogs` RPC.
    let client = Client::builder(&endpoint)
        .api_secret(secret)?
        .name(name)?
        .with_log_collection(collector.clone())
        .build()
        .await?;

    // 4. Grant `LogsCap::SetLevel` so the cloud can dial us back and apply a
    //    filter override. Spawned so a momentarily-down cloud does not block
    //    startup.
    let client_for_grant = client.clone();
    let grant_task = tokio::spawn(async move {
        if let Err(err) = client_for_grant
            .grant_capability(cloud_id, [LogsCap::SetLevel])
            .await
        {
            eprintln!("failed to grant LogsCap::SetLevel: {err:?}");
        }
    });

    // 5. Accept the cloud's callback connections on `CLIENT_HOST_ALPN`. The
    //    `ClientHost` needs the same collector so the `SetLogLevel` request
    //    can hot-reload the filter.
    let host = ClientHost::new(&endpoint).with_log_collector(collector);
    let router = Router::builder(endpoint)
        .accept(CLIENT_HOST_ALPN, host)
        .spawn();

    // 6. Emit an info log every other second forever. These will surface on
    //    the dashboard's Logs page (and on this process's stderr) once the
    //    endpoint is opted into log collection at `info` level or above.
    println!("emitting logs; ctrl+c to exit.");
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut counter: u64 = 0;
    loop {
        tokio::select! {
            _ = tick.tick() => {
                counter += 1;
                info!(counter, "logs example heartbeat");
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    grant_task.abort();
    router.endpoint().close().await;
    Ok(())
}

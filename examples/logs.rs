//! Log collection example.
//!
//! Demonstrates installing the iroh-services file logger and letting the
//! cloud override the local filter at runtime via `SetLogLevel`.
//!
//! The level filter starts at `off`. The cloud pushes a level after this
//! endpoint is opted into log collection from the dashboard or REST API.
//! Anything emitted before the cloud responds is silently dropped.
//!
//! Run with: cargo run --example logs

use std::time::Duration;

use anyhow::Result;
use iroh::{Endpoint, endpoint::presets, protocol::Router};
use iroh_services::{
    API_SECRET_ENV_VAR_NAME, ApiSecret, CLIENT_HOST_ALPN, Client, ClientHost,
    caps::LogsCap,
    logs::{self, FileLoggerConfig, Rotation},
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Install the cloud-controlled file logger. Records land under
    //    `./logs/` and roll over hourly with up to 24 files kept. The
    //    WorkerGuard must outlive the process; drop it in `main`'s tail
    //    so any buffered records flush on exit.
    let (collector, _guard) = logs::install(
        FileLoggerConfig::new("./logs")
            .with_rotation(Rotation::HOURLY)
            .with_max_files(Some(24)),
    )?;

    // 2. Create the endpoint and parse the API secret so we know which
    //    cloud endpoint to grant SetLevel to.
    let endpoint = Endpoint::bind(presets::N0).await?;
    let secret = ApiSecret::from_env_var(API_SECRET_ENV_VAR_NAME)?;
    let cloud_id = secret.addr().id;

    let name = format!("logs-example-{}", &endpoint.id().to_string()[..8]);

    // 3. Build the client.
    let client = Client::builder(&endpoint)
        .api_secret(secret)?
        .name(name)?
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
    //    `ClientHost` needs the collector so the `SetLogLevel` request can
    //    hot-reload the local filter.
    let host = ClientHost::new(&endpoint).with_log_collector(collector);
    let router = Router::builder(endpoint)
        .accept(CLIENT_HOST_ALPN, host)
        .spawn();

    // 6. Emit an info log every other second forever. Records are written
    //    to the local rolling file once the cloud raises the level above
    //    `off`.
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

use std::str::FromStr;

use iroh::{Endpoint, protocol::Router};
use iroh_services::{ApiSecret, Client, caps::NetDiagnosticsCap, preset};
use n0_error::{Result, StdResultExt};
#[cfg(not(wasm_browser))]
use tokio::test;
use tracing_subscriber::EnvFilter;
#[cfg(wasm_browser)]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[test]
async fn main_integration_test() -> Result {
    if let Some(env) = option_env!("RUST_LOG") {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_str(env).anyerr()?)
            .without_time()
            .init();
    }

    let Some(secret) = option_env!("IROH_SERVICES_API_SECRET") else {
        n0_error::bail_any!("Missing IROH_SERVICES_API_SECRET env var");
    };
    let secret = ApiSecret::from_str(secret)?;

    let preset = preset().api_secret(secret.clone()).build()?;
    let endpoint = Endpoint::bind(preset).await?;
    let services = Client::builder(&endpoint)
        .api_secret(secret.clone())?
        .name(format!("iroh-services integration-rs {}", env!("TARGET")))?
        .build()
        .await
        .std_context("failed building iroh-services client")?;

    services
        .grant_capability(secret.addr().id, vec![NetDiagnosticsCap::GetAny])
        .await
        .std_context("failed granting net diagnostics capability")?;

    let host = iroh_services::ClientHost::new(&endpoint);

    let router = Router::builder(endpoint.clone())
        .accept(iroh_services::CLIENT_HOST_ALPN, host)
        .spawn();

    endpoint.online().await;

    services
        .ping()
        .await
        .std_context("iroh-services ping failed")?;

    services
        .push_metrics()
        .await
        .std_context("iroh-services metrics upload failed")?;

    services
        .net_diagnostics(true)
        .await
        .std_context("iroh-services net diagnostics with upload failed")?;

    router
        .shutdown()
        .await
        .std_context("failed to shutdown endpoint")?; // will also shut down the endpoint

    Ok(())
}

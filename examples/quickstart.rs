use iroh::{Endpoint, endpoint::presets};
use iroh_services::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let endpoint = Endpoint::bind(presets::N0).await?;

    // Wait for the endpoint to be online
    endpoint.online().await;

    // needs IROH_SERVICES_API_SECRET set to an environment variable
    // client will now push endpoint metrics to iroh-services
    let client = Client::builder(&endpoint)
        .api_secret_from_env()?
        .name("quickstart-example")?
        .build()
        .await?;

    // we can also ping the service just to confirm everything is working
    client.ping().await?;

    // keep the endpoint running so it continues pushing metrics.
    // ctrl+c to exit.
    println!("endpoint running. ctrl+c to exit.");
    tokio::signal::ctrl_c().await?;
    endpoint.close().await;

    Ok(())
}

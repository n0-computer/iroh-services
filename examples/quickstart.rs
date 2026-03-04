use iroh::Endpoint;
use iroh_services::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let endpoint = Endpoint::bind().await?;

    // needs IROH_SERVICES_API_KEY set to an environment variable
    // client will now push endpoint metrics to services
    let client = Client::builder(&endpoint)
        .api_secret_from_env()?
        .build()
        .await?;

    // we can also ping the service just to confirm everything is working
    client.ping().await?;

    Ok(())
}

use iroh::Endpoint;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // needs IROH_SERVICES_API_SECRET set as an environment variable.
    // uses the public n0 relays; see the `relays` example for custom relays.
    let preset = iroh_services::preset().api_secret_from_env()?.build()?;

    let endpoint = Endpoint::bind(preset.clone()).await?;
    // Wait for the endpoint to be online
    endpoint.online().await;

    // client_builder reuses the preset's api secret, which also carries the
    // iroh-services endpoint address to dial.
    // client will now push endpoint metrics to iroh-services
    let client = preset
        .client_builder(&endpoint)
        .name("quickstart-example")?
        .build()
        .await?;

    // we can also ping the service just to confirm everything is working
    client.ping().await?;

    // keep the endpoint running so it continues pushing metrics.
    // ctrl+c to exit.
    println!("endpoint running. ctrl+c to exit.");
    tokio::signal::ctrl_c().await?;
    // push the metrics accumulated since the last interval tick
    client.shutdown().await;
    endpoint.close().await;

    Ok(())
}

//! This example shows common methods for configuring custom relays provided by iroh services.
//! All of these leverage the [`iroh_services::preset`] builder to configure the endpoint,
//! which itself builds an [`iroh::presets::Preset`] to pass to an [`iroh::Endpoint`] on
//! construction.
//!
//! To run these, set IROH_SERVICES_API_SECRET in your environment, using an API secret
//! from your iroh services project, and then run with `cargo run --example relays`.
//!
//! Your app will use only one of these methods, depending on your use case. As written,
//! this example runs against the public n0 relays. To use custom relays instead,
//! uncomment the `relays` preset at the bottom and paste in your own relay URLs.
use iroh::Endpoint;

#[tokio::main]
async fn main() -> n0_error::Result<()> {
    tracing_subscriber::fmt::init();

    // Public relays. This is the minimal preset, and works with a free iroh
    // services project. The preset already applies `iroh::endpoint::presets::N0`
    // (production crypto + n0 DNS lookup) and defaults to the public n0 relay
    // map, so leaving `relays` unset is the same as using `presets::N0`, plus an
    // access token for your project. That gives a bandwidth bump on the public
    // relays and surfaces your relay traffic on your project.
    let preset = iroh_services::preset().api_secret_from_env()?.build()?;

    // if you are using a secret key from disk, or generally want control over
    // the ID your endpoint uses, the secret key must be given to the preset
    // *before* passing it to the endpoint. The access token that the preset creates
    // to access relays is scoped only to the given key.
    //
    // If no key is provided, a random one is generated and passed to the
    // endpoint.
    // let secret_key = iroh::SecretKey::generate();
    // let preset = iroh_services::preset()
    //     .secret_key(secret_key)
    //     .api_secret_from_str("YOUR_API_SECRET_HERE")?
    //     .build()?;

    // pro & enterprise projects have access to custom relays, which are set
    // with the `relays` method on the builder.
    // You'll need to replace these strings with the relay urls for your project.
    // let preset = iroh_services::preset()
    //     .relays([
    //         // Replace these with your own relay urls!
    //         "https://use1-1.relay.n0.iroh-canary.iroh.link.",
    //         "https://usw1-1.relay.n0.iroh-canary.iroh.link.",
    //         "https://euc1-1.relay.n0.iroh-canary.iroh.link.",
    //         "https://aps1-1.relay.n0.iroh-canary.iroh.link.",
    //     ])?
    //     .api_secret_from_str("YOUR_API_SECRET_HERE")?
    //     .build()?;

    // once a preset is built, we'll pass it to the endpoint for binding.
    // we clone the preset so we can reuse to get a client builder below
    let endpoint = Endpoint::bind(preset.clone()).await?;

    // wait for the endpoint to be online, to prove we have an authorized
    // connection to a relay
    endpoint.online().await;

    // a client is not required to use, but the preset has a convenience method
    // for creating a client builder that uses the same access token as the
    // endpoint, so you don't need to pass the secret key separately:
    let client = preset.client_builder(&endpoint).build().await?;

    // we can also ping the service just to confirm everything is working
    client.ping().await?;

    // keep the connection alive
    println!("waiting for ctrl+c...");
    tokio::signal::ctrl_c().await?;

    endpoint.close().await;

    Ok(())
}

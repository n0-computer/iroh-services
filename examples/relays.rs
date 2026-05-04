//! This example shows using custom relays provided by iroh services.
use iroh::{Endpoint, SecretKey};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // minimal preset that works with a free iroh services project. This will
    // give a bandwidth bump when using the public relays, and surface your
    // relay traffic on your project:
    let _preset = iroh_services::preset().api_secret_from_env()?.build()?;

    // pro & enterprise projects have access to custom relays, which are set
    // with the `relays` method on the builder:
    let _preset = iroh_services::preset()
        .relays([
            "https://us-east1.project_username.iroh.link",
            "https://eu-west1.project_username.iroh.link",
            "https://eu-central1.project_username.iroh.link",
        ])?
        .api_secret_from_env()?
        .build()?;

    // if you are using a secret key from disk, or generally want control over
    // the ID your endpoint uses, the secret key must be given to the preset
    // before passing it to the endpoint (because the endpoint ID is the public
    // half of the secret keypair). The access token that's created by the
    // preset to access relays is scoped only to the given key.
    //
    // If no key is provided, a random one is generated and passed to the
    // endpoint.
    let secret_key = SecretKey::generate();
    let preset = iroh_services::preset()
        .secret_key(secret_key)
        .api_secret_from_env()?
        .build()?;

    // once a preset is built, we'll pass it to the endpoint for binding.
    // we clone the preset so we can reuse to get a client builder below
    let endpoint = Endpoint::bind(preset.clone()).await?;

    // a client is not required to use
    let client = preset.client_builder(&endpoint).build().await?;

    // we can also ping the service just to confirm everything is working
    client.ping().await?;

    Ok(())
}

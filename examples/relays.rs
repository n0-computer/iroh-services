//! This example shows common methods for configuring custom relays provided by iroh services.
//! All of these leverage the [`iroh_services::preset`] builder to configure the endpoint,
//! which itself builds an [`iroh::presets::Preset`] to pass to an [`iroh::Endpoint`] on
//! construction.
//!
//! To run these, set IROH_SERVICES_API_SECRET in your environment, using an API secret
//! from your iroh services project, and then run with `cargo run --example relays`.
//!
//! Your app will use only one of these methods, depending on your use case. To test this
//! example with custom relay URLS, you will need to comment out the secret key preset
//! example and use the `relays` method instead, pasting in your own relay URLs.
use std::str::FromStr;

use anyhow::Context;
use clap::Parser;
use data_encoding::HEXLOWER;
use iroh::{Endpoint, EndpointId, RelayMap, RelayUrl, SecretKey, protocol::Router};

fn relay_map_from_env() -> anyhow::Result<Option<RelayMap>> {
    match std::env::var("IROH_RELAYS") {
        Ok(value) if !value.is_empty() => {
            let parts = value.split(",");
            let mut urls = Vec::new();
            for url_string in parts {
                let url: RelayUrl = url_string
                    .trim()
                    .parse()
                    .with_context(|| "Failed to parse string as relay URL: {url_string}")?;
                urls.push(url);
            }
            Ok(Some(RelayMap::from_iter(urls)))
        }
        _ => Ok(None),
    }
}

#[derive(Debug, clap::Parser)]
struct Cli {
    targets: Vec<EndpointId>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Create secret key if not set.
    let secret_key = match std::env::var("IROH_SECRET") {
        Ok(s) => SecretKey::from_str(&s)
            .context("Failed to parse IROH_SECRET environment variable as iroh secret key")?,
        Err(_) => {
            let s = SecretKey::generate();
            println!(
                "Generated a new endpoint secret. To reuse, set\n\tIROH_SECRET={}",
                HEXLOWER.encode(&s.to_bytes())
            );
            s
        }
    };

    let relay_map = relay_map_from_env()?.context("Missing IROH_RELAYS environment variable")?;

    let preset = iroh_services::preset()
        .secret_key(secret_key)
        .relay_map(relay_map)
        .api_secret_from_env()?
        .build()?;

    // once a preset is built, we'll pass it to the endpoint for binding.
    // we clone the preset so we can reuse to get a client builder below
    let endpoint = Endpoint::builder(preset.clone()).bind().await?;

    // wait for the endpoint to be online, to prove we have an authorized
    // connection to a relay
    endpoint.online().await;

    // a client is not required to use, but the preset has a convenience method
    // for creating a client builder that uses the same access token as the
    // endpoint, so you don't need to pass the secret key separately:
    let client = preset.client_builder(&endpoint).build().await?;

    println!("endpoint id: {}", endpoint.id());
    let router = Router::builder(endpoint)
        .accept(iroh_ping::ALPN, iroh_ping::Ping::default())
        .spawn();

    // we can also ping the service just to confirm everything is working
    tokio::task::spawn(async move {
        let res = client.ping().await;
        println!("Pinged iroh services: {res:?}");
    });

    for target in cli.targets {
        println!("ping {target}...");
        let res = iroh_ping::Ping::new()
            .ping(router.endpoint(), target.into())
            .await;
        println!("ping {target}: {res:?}");
    }

    // keep the connection alive
    println!("waiting for ctrl+c...");
    tokio::signal::ctrl_c().await?;

    router.shutdown().await?;

    Ok(())
}

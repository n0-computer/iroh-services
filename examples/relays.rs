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
use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Parser;
use data_encoding::HEXLOWER;
use iroh::{Endpoint, EndpointId, RelayMap, RelayUrl, SecretKey, protocol::Router};

#[derive(Debug, clap::Parser)]
struct Cli {
    targets: Vec<EndpointId>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let preset = iroh_services::preset()
        // Read the endpoint secret key from IROH_SECRET, or create if unset.
        .secret_key(secret_key_from_env()?)
        // Read the relay map from IROH_RELAYS, or use default public relays if unset.
        .relay_map(relay_map_from_env()?)
        // Read the iroh-services API secret from IROH_SERVICES_API_SECRET.
        .api_secret_from_env()?
        .build()?;

    // Once the preset is built, we'll pass it to the endpoint for binding.
    // We clone the preset so we can reuse to get a client builder below.
    let endpoint = Endpoint::builder(preset.clone()).bind().await?;

    // Wait for the endpoint to be online, to prove we have an authorized
    // connection to a relay
    endpoint.online().await;
    println!("endpoint id: {}", endpoint.id());

    // We create a router to accept ping requests.
    let router = Router::builder(endpoint.clone())
        .accept(iroh_ping::ALPN, iroh_ping::Ping::default())
        .spawn();

    // A services client is not required to use, but the preset has a convenience method
    // for creating a client builder that uses the same access token as the
    // endpoint, so you don't need to pass the secret key separately:
    let client = preset.client_builder(&endpoint).build().await?;
    // We can also ping the service just to confirm everything is working
    tokio::task::spawn(async move {
        loop {
            let start = Instant::now();
            match client.ping().await {
                Ok(_) => println!("Pinged iroh services: OK, RTT {:?}", start.elapsed()),
                Err(err) => println!("Failed to ping iroh services: {err:#}"),
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Ping each target in a loop.
    for target in cli.targets {
        let endpoint = endpoint.clone();
        tokio::task::spawn(async move {
            loop {
                let start = Instant::now();
                match iroh_ping::Ping::new().ping(&endpoint, target.into()).await {
                    Ok(_) => println!(
                        "Pinged {}: OK, RTT {:?})",
                        target.fmt_short(),
                        start.elapsed()
                    ),
                    Err(err) => {
                        println!("Failed to ping {}: {err:#}", target.fmt_short());
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    println!("Waiting for Ctrl+C...");
    tokio::signal::ctrl_c().await?;

    router.shutdown().await?;

    Ok(())
}

fn relay_map_from_env() -> Result<RelayMap> {
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
            println!(
                "Using custom relay map:\n    - {}",
                urls.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n   - ")
            );
            Ok(RelayMap::from_iter(urls))
        }
        _ => {
            println!("Using default relay map");
            Ok(iroh::defaults::prod::default_relay_map())
        }
    }
}

fn secret_key_from_env() -> Result<SecretKey> {
    Ok(match std::env::var("IROH_SECRET") {
        Ok(s) => SecretKey::from_str(&s)
            .context("Failed to parse IROH_SECRET environment variable as iroh secret key")?,
        Err(_) => {
            let secret_key = SecretKey::generate();
            println!(
                "Generated a new endpoint secret. To reuse, set\n\tIROH_SECRET={}",
                HEXLOWER.encode(&secret_key.to_bytes())
            );
            secret_key
        }
    })
}

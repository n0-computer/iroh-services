//! Binds an iroh endpoint through the iroh services [`preset`], then keeps it online
//! by pinging the iroh services relay and any target endpoints passed on the command
//! line.
//!
//! The endpoint is configured entirely from the environment, so you can point it at
//! different relays, reuse an identity, or authorize against your project without
//! editing the source. The [`preset`] builder produces an [`IrohServicesPreset`]
//! that is passed to [`Endpoint::builder`] on construction.
//!
//! # Environment variables
//!
//! - `IROH_SERVICES_API_SECRET`: the API secret from your iroh services project. This
//!   authorizes the endpoint against the project's relays and is required. Read via
//!   [`api_secret_from_env`].
//! - `IROH_SECRET`: the endpoint secret key as a hex string, controlling the endpoint
//!   id. If unset, a fresh key is generated and its hex encoding is printed so you can
//!   set it to reuse the same id on the next run.
//! - `IROH_RELAYS`: a comma-separated list of relay URLs to use instead of the default
//!   public relay map. Custom relays require a pro or enterprise project. If unset, the
//!   default public relay map is used.
//!
//! # Examples
//!
//! Run against the default public relays with a generated identity:
//!
//! ```sh
//! export IROH_SERVICES_API_SECRET=your_api_secret_here
//! cargo run --example relays
//! ```
//!
//! Reuse an identity and point at your project's custom relays, while pinging a peer:
//!
//! ```sh
//! export IROH_SERVICES_API_SECRET=your_api_secret_here
//! export IROH_SECRET=your_hex_secret_key_here
//! export IROH_RELAYS=https://use1-1.relay.example,https://euc1-1.relay.example
//! cargo run --example relays -- <target-endpoint-id>
//! ```
//!
//! [`preset`]: iroh_services::preset
//! [`IrohServicesPreset`]: iroh_services::IrohServicesPreset
//! [`api_secret_from_env`]: iroh_services::PresetBuilder::api_secret_from_env
//! [`Endpoint::builder`]: iroh::Endpoint::builder
use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Parser;
use data_encoding::HEXLOWER;
use iroh::{Endpoint, EndpointId, RelayMap, RelayUrl, SecretKey, Watcher, protocol::Router};

/// Bind an iroh services endpoint and ping the given targets over iroh-ping.
#[derive(Debug, clap::Parser)]
struct Cli {
    /// Endpoint IDs to ping. Each is pinged every five seconds.
    targets: Vec<EndpointId>,
}

/// Binds the endpoint, starts the ping loops, and runs until Ctrl+C.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let preset = iroh_services::preset()
        // Read the iroh-services API secret from IROH_SERVICES_API_SECRET.
        .api_secret_from_env()?
        // Read the endpoint secret key from IROH_SECRET, or create if unset.
        .secret_key(secret_key_from_env()?)
        // Read the relay map from IROH_RELAYS, or use default public relays if unset.
        .relay_map(relay_map_from_env()?)
        .build()?;

    // Once the preset is built, we'll pass it to the endpoint for binding.
    // We clone the preset so we can reuse to get a client builder below.
    let endpoint = Endpoint::builder(preset.clone()).bind().await?;
    println!("Endpoint id: {}", endpoint.id());

    // Wait for the endpoint to be online, to prove we have an authorized
    // connection to a relay
    endpoint.online().await;
    println!(
        "Endpoint is online. Home relay: {}",
        endpoint.addr().relay_urls().next().expect("has relay")
    );

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

/// Reads the relay map from `IROH_RELAYS`, falling back to the default public relays.
fn relay_map_from_env() -> Result<RelayMap> {
    match std::env::var("IROH_RELAYS") {
        Ok(value) if !value.is_empty() => {
            let mut urls = Vec::new();
            for url_string in value.split(",") {
                let url: RelayUrl = url_string
                    .trim()
                    .parse()
                    .with_context(|| "Failed to parse string as relay URL: {url_string}")?;
                urls.push(url);
            }
            println!(
                "Using custom relay map:\n\t- {}",
                urls.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n\t- ")
            );
            Ok(RelayMap::from_iter(urls))
        }
        _ => {
            println!("Using default relay map");
            Ok(iroh::defaults::prod::default_relay_map())
        }
    }
}

/// Reads the endpoint secret key from `IROH_SECRET`, generating one if unset.
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

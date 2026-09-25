//! Endpoint metadata example.
//!
//! Demonstrates how to associate metadata with an endpoint via the iroh-services
//! Client: a human-readable `name`, a single `group`, and arbitrary key-value
//! `attributes`. Each can be set at build time via the [`ClientBuilder`], and
//! updated later through the `Client::set_*` methods.
//!
//! Run with: `IROH_SERVICES_API_SECRET=... cargo run --example endpoint_meta`
use std::time::Duration;

use iroh::{Endpoint, endpoint::presets};
use iroh_services::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let endpoint = Endpoint::bind(presets::N0).await?;

    //> Derive a unique name from the endpoint id so repeated runs don't collide
    // in dashboards. In a real app this is typically a user id, machine name,
    // or other stable identifier from your application.
    let id = endpoint.id().to_string();
    let name = format!("endpoint-meta-example-{}", &id[..8]);

    // Set name, group, and attributes at build time. The client sends these
    // immediately after authenticating with iroh-services. Validation errors
    // (e.g. name too long) surface here; transport errors during startup are
    // logged at `warn` level rather than failing the build.
    let mut attrs = vec![];
    for i in 0..25 {
        attrs.push((format!("my-thing: {i}"), i.to_string()));
    }
    let client = Client::builder(&endpoint)
        .api_secret_from_env()?
        .name(name)?
        .group("staging")?
        .attributes(attrs)?
        .build()
        .await?;

    client.ping().await?;
    println!("endpoint registered with initial metadata");

    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("updating endpoint metadata...");

    // Each metadata field can also be updated after construction. These calls
    // return explicit errors, unlike the builder which logs and continues.
    client.set_name("endpoint-meta-example-renamed").await?;
    client.set_group("production").await?;

    // set_attributes fully replaces the prior set on each call. Pass an empty
    // iterator to clear all attributes.
    client.set_attribute("version", "41.0.3").await?;

    println!("metadata updated");
    endpoint.close().await;

    Ok(())
}

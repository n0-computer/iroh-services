//! Endpoint metadata example.
//!
//! Demonstrates how to associate metadata with an endpoint via the iroh-services
//! Client: a human-readable `name`, a single `group`, and arbitrary key-value
//! `attributes`. Each can be set at build time via the [`ClientBuilder`], and
//! updated later through the `Client::set_*` methods.
//!
//! Run with: `IROH_SERVICES_API_SECRET=... cargo run --example endpoint_meta`
use iroh::{Endpoint, endpoint::presets};
use iroh_services::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let endpoint = Endpoint::bind(presets::N0).await?;

    // Derive a unique name from the endpoint id so repeated runs don't collide
    // in dashboards. In a real app this is typically a user id, machine name,
    // or other stable identifier from your application.
    let id = endpoint.id().to_string();
    let name = format!("endpoint-meta-example-{}", &id[..8]);

    // Set name, group, and attributes at build time. The client sends these
    // immediately after authenticating with iroh-services. Validation errors
    // (e.g. name too long) surface here; transport errors during startup are
    // logged at `warn` level rather than failing the build.
    let client = Client::builder(&endpoint)
        .api_secret_from_env()?
        .name(name)?
        .group("examples")?
        .attributes([
            ("env", "dev"),
            ("region", "us-west"),
            ("role", "endpoint-meta-example"),
        ])?
        .build()
        .await?;

    client.ping().await?;
    println!("endpoint registered with initial metadata");

    // Each metadata field can also be updated after construction. These calls
    // return explicit errors, unlike the builder which logs and continues.
    client.set_name("endpoint-meta-example-renamed").await?;
    client.set_group("staging").await?;

    // set_attributes fully replaces the prior set on each call. Pass an empty
    // iterator to clear all attributes.
    client
        .set_attributes([("env", "staging"), ("region", "eu-central")])
        .await?;

    println!("metadata updated");
    Ok(())
}

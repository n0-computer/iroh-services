//! iroh-services is the client side of interacting with [iroh-services]. iroh-services gives
//! visibility into a running iroh network by pushing metrics aggregations
//! from [iroh] endpoints into a central hub for monitoring.
//!
//! Typical setup looks something like this:
//! ```no_run
//! use iroh::{Endpoint, endpoint::presets};
//! use iroh_services::Client;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let endpoint = Endpoint::bind(presets::N0).await?;
//!
//!     // needs IROH_SERVICES_API_SECRET set to an environment variable
//!     // client will now push endpoint metrics to iroh-services.
//!     let client = Client::builder(&endpoint)
//!         .api_secret_from_env()?
//!         .build()
//!         .await?;
//!
//!     // we can also ping the service just to confirm everything is working
//!     client.ping().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! [iroh-services]: https://services.iroh.computer
//! [iroh]: https://iroh.computer

mod client;
mod client_host;
#[cfg(not(wasm_browser))]
mod openssh;

pub mod api_secret;
pub mod caps;
pub mod net_diagnostics;
mod preset;
pub mod protocol;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

/// Version of this crate.
pub const IROH_SERVICES_VERSION: &str = built_info::PKG_VERSION;

/// Version of iroh this crate was built against.
pub static IROH_VERSION: std::sync::LazyLock<&str> = std::sync::LazyLock::new(|| {
    built_info::DEPENDENCIES
        .iter()
        .find(|(name, _)| *name == "iroh")
        .expect("iroh dependency not found")
        .1
});

pub use anyhow;
pub use client_host::{CLIENT_HOST_ALPN, ClientHost, ClientHostClient};
pub use iroh_metrics::Registry;

pub use self::{
    api_secret::{API_SECRET_ENV_VAR_NAME, ApiSecret},
    client::{Client, ClientBuilder},
    net_diagnostics::{DiagnosticsReport, checks::run_diagnostics},
    preset::{IrohServicesPreset, PresetBuilder, preset},
    protocol::ALPN,
};

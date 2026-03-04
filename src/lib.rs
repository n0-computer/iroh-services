//! iroh-services is the client side of interacting with [services]. services gives
//! visibility into a running iroh network by pushing metrics aggregations
//! from [iroh] endpoints into a central hub for monitoring.
//!
//! Typical setup looks something like this:
//! ```no_run
//! use iroh::Endpoint;
//! use iroh_services::Client;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let endpoint = Endpoint::bind().await?;
//!
//!     // needs IROH_SERVICES_API_KEY set to an environment variable
//!     // client will now push endpoint metrics to services.
//!     let client = Client::builder(&endpoint)
//!         .api_key_from_env()?
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
//! [services]: https://services.iroh.computer
//! [iroh]: https://iroh.computer

mod client;
#[cfg(feature = "client_host")]
mod client_host;

pub mod api_key;
pub mod caps;
pub mod net_diagnostics;
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
#[cfg(feature = "client_host")]
pub use client_host::{CLIENT_HOST_ALPN, ClientHost, ClientHostClient};
pub use iroh_metrics::Registry;

#[cfg(feature = "net_diagnostics")]
pub use self::net_diagnostics::{DiagnosticsReport, checks::run_diagnostics};
pub use self::{
    api_key::ApiKey,
    client::{API_KEY_ENV_VAR_NAME, Client, ClientBuilder},
    protocol::ALPN,
};

//! iroh-n0des is the client side of interacting with [n0des]. n0des gives
//! visibility into a running iroh network by pushing metrics aggregations
//! from [iroh] endpoints into a central hub for monitoring.
//!
//! Typical setup looks something like this:
//! ```no_run
//! use iroh::Endpoint;
//! use iroh_n0des::Client;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let endpoint = Endpoint::bind().await?;
//!
//!     // needs N0DES_API_SECRET set to an environment variable
//!     // client will now push endpoint metrics to n0des.
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
//! [n0des]: https://n0des.iroh.computer
//! [iroh]: https://iroh.computer
mod client;

pub mod api_secret;
pub mod caps;
pub mod net_diagnostics;
pub mod protocol;

pub use anyhow;
pub use iroh_metrics::Registry;

#[cfg(feature = "client_host")]
pub use protocol::client_host::ClientHost;

#[cfg(feature = "tickets")]
pub use self::client::PublishedTicket;
pub use self::{
    api_secret::ApiSecret,
    client::{API_SECRET_ENV_VAR_NAME, Client, ClientBuilder},
    protocol::ALPN,
};

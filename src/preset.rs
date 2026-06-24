//! An [`iroh::endpoint`] preset tailored for use with iroh-services.
//!
//! [`IrohServicesPreset`] starts from the n0 stock preset (production crypto
//! provider + n0 DNS-based address lookup) and overlays the bits that
//! iroh-services callers usually want to configure together: the relay map
//! the endpoint should use, an optional explicit [`SecretKey`], and an
//! optional [`ApiSecret`] that downstream code can retrieve to wire up a
//! [`crate::Client`].
//!
//! # Example
//! ```no_run
//! use iroh::Endpoint;
//!
//! async fn run() -> anyhow::Result<()> {
//!     let preset = iroh_services::preset()
//!         .relays(["https://us-east1.project_username.iroh.link"])?
//!         .api_secret_from_env()?
//!         .build()?;
//!     let endpoint = Endpoint::builder(preset).bind().await?;
//!     Ok(())
//! }
//! ```
use std::{str::FromStr, time::Duration};

use anyhow::{Context, Result, anyhow};
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey, endpoint::presets::Preset};

use crate::{
    ClientBuilder,
    api_secret::{API_SECRET_ENV_VAR_NAME, ApiSecret},
    caps::{Cap, Caps, DEFAULT_CAP_EXPIRY},
};

/// An iroh endpoint preset configured for iroh-services. Build one with
/// [`preset`] or [`IrohServicesPreset::builder`], then pass it to
/// [`iroh::Endpoint::builder`].
#[derive(Debug, Clone)]
pub struct IrohServicesPreset {
    secret_key: SecretKey,
    relays: RelayMap,
    // not used by the preset, only for creating a client builder
    api_secret: ApiSecret,
}

impl IrohServicesPreset {
    /// Start a new builder seeded with iroh-services defaults. Equivalent to
    /// the free-standing [`preset`] function.
    pub fn builder() -> PresetBuilder {
        preset()
    }

    /// Returns the [`ApiSecret`] used to create this preset.
    /// Useful for handing the same secret to a [`crate::Client`] without
    /// plumbing it through twice.
    pub fn api_secret(&self) -> &ApiSecret {
        &self.api_secret
    }

    /// Returns a [`ClientBuilder`] pre-configured with this preset's API secret.
    pub fn client_builder(&self, endpoint: &Endpoint) -> ClientBuilder {
        // unwrap is ok here because the api_secret has been factored
        // to the point that it can no longer fail.
        ClientBuilder::new(endpoint)
            .api_secret(self.api_secret.clone())
            .unwrap()
    }
}

impl Preset for IrohServicesPreset {
    fn apply(self, builder: iroh::endpoint::Builder) -> iroh::endpoint::Builder {
        // Inherit n0 defaults (crypto provider + DNS address lookup), then
        // overlay our relay map and (optionally) an explicit secret key
        let mut builder = iroh::endpoint::presets::N0.apply(builder);
        builder = builder.relay_mode(RelayMode::Custom(self.relays));
        builder = builder.secret_key(self.secret_key);
        builder
    }
}

/// Fluent builder for [`IrohServicesPreset`]. Construct one through
/// [`preset`] or [`IrohServicesPreset::builder`].
#[derive(Debug, Clone)]
pub struct PresetBuilder {
    cap_expiry: Duration,
    secret_key: Option<SecretKey>,
    relays: RelayMap,
    api_secret: Option<ApiSecret>,
}

/// Start a new [`IrohServicesPreset`] builder seeded with iroh-services
/// defaults: the n0 production relay map and no explicit secret key (the
/// endpoint will generate one at bind time).
pub fn preset() -> PresetBuilder {
    PresetBuilder {
        cap_expiry: DEFAULT_CAP_EXPIRY,
        secret_key: None,
        relays: iroh::endpoint::default_relay_mode().relay_map(),
        api_secret: None,
    }
}

impl PresetBuilder {
    /// Set the endpoint's long-lived [`SecretKey`]. If left unset the
    /// endpoint will generate a fresh random key at bind time.
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Set relay URLs. This method accepts any iterator of &str, allowing the
    /// common pattern:
    /// ```no_run
    /// fn build() -> anyhow::Result<()> {
    ///     let _preset = iroh_services::preset()
    ///         .relays([
    ///             "https://us-east1.project_username.iroh.link",
    ///             "https://eu-west1.project_username.iroh.link",
    ///             "https://eu-central1.project_username.iroh.link",
    ///         ])?
    ///         .api_secret_from_env()?
    ///         .build()?;
    ///     Ok(())
    /// }
    /// ```
    pub fn relays<I, S>(mut self, relays: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let parsed = relays
            .into_iter()
            .map(|s| {
                let s = s.as_ref();
                s.parse::<RelayUrl>()
                    .with_context(|| format!("invalid relay url {s:?}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        self.relays = RelayMap::from_iter(parsed);
        Ok(self)
    }

    /// Pick relays via a [`RelayMode`] (e.g. `RelayMode::Staging` or a
    /// pre-built `RelayMode::Custom(RelayMap)`).
    pub fn relay_mode(mut self, mode: RelayMode) -> Self {
        self.relays = mode.relay_map();
        self
    }

    /// Pass in a [`RelayMap`] directly, bypassing URL parsing.
    pub fn relay_map(mut self, map: RelayMap) -> Self {
        self.relays = map;
        self
    }

    /// Check IROH_SERVICES_API_SECRET environment variable for a valid API secret
    pub fn api_secret_from_env(self) -> Result<Self> {
        let ticket = ApiSecret::from_env_var(API_SECRET_ENV_VAR_NAME)?;
        Ok(self.api_secret(ticket))
    }

    /// set client API secret from an encoded string
    pub fn api_secret_from_str(self, secret_key: &str) -> Result<Self> {
        let key = ApiSecret::from_str(secret_key).context("invalid iroh services api secret")?;
        Ok(self.api_secret(key))
    }

    /// Stash an [`ApiSecret`] on the preset so callers can retrieve it later
    /// via [`IrohServicesPreset::api_secret`] when constructing a client.
    pub fn api_secret(mut self, api_secret: ApiSecret) -> Self {
        self.api_secret = Some(api_secret);
        self
    }

    /// Finalize the configuration into an [`IrohServicesPreset`].
    pub fn build(self) -> Result<IrohServicesPreset> {
        let secret_key = self.secret_key.unwrap_or_else(SecretKey::generate);

        let Some(api_secret) = self.api_secret else {
            return Err(anyhow!(
                "api secret is required to use iroh_services relay preset"
            ));
        };

        // build our token to interact with relays. This is only scoped to relay use.
        let rcan = crate::caps::create_api_token_from_secret_key(
            api_secret.secret.clone(),
            secret_key.public(),
            self.cap_expiry,
            Caps::new([Cap::Relay(crate::caps::RelayCap::Use)]),
        )?;

        let mut token = data_encoding::BASE32_NOPAD.encode(&rcan.encode());
        token.make_ascii_lowercase();

        let relays = self.relays.with_auth_token(token);

        Ok(IrohServicesPreset {
            secret_key,
            relays,
            api_secret,
        })
    }
}

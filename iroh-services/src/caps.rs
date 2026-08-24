use std::{collections::BTreeSet, fmt, str::FromStr};

use anyhow::{Context, Result, bail};
use iroh::{EndpointId, SecretKey};
use n0_future::time::Duration;
use rcan::{Expires, Rcan};
use serde::{Deserialize, Serialize};

use crate::ApiToken;

macro_rules! cap_enum(
    ($enum:item) => {
        #[derive(
            Debug,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            Serialize,
            Deserialize,
            Clone,
            Copy,
            strum::Display,
            strum::EnumString,
        )]
        #[strum(serialize_all = "kebab-case")]
        #[serde(rename_all = "kebab-case")]
        $enum
    }
);

/// A set of iroh-services capabilities.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum Caps {
    V0(CapSet<Cap>),
}

impl Default for Caps {
    fn default() -> Self {
        Self::V0(CapSet::default())
    }
}

impl std::ops::Deref for Caps {
    type Target = CapSet<Cap>;

    fn deref(&self) -> &Self::Target {
        let Self::V0(slf) = self;
        slf
    }
}

/// A capability is the capacity to perform an operation in iroh-services.
#[derive(
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    derive_more::From,
    strum::Display,
)]
#[serde(rename_all = "kebab-case")]
pub enum Cap {
    #[strum(to_string = "all")]
    All,
    #[strum(to_string = "client")]
    Client,
    #[strum(to_string = "relay:{0}")]
    Relay(RelayCap),
    #[strum(to_string = "metrics:{0}")]
    Metrics(MetricsCap),
    #[strum(to_string = "net-diagnostics:{0}")]
    NetDiagnostics(NetDiagnosticsCap),
}

impl FromStr for Cap {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s == "all" {
            Ok(Self::All)
        } else if let Some((domain, inner)) = s.split_once(':') {
            Ok(match domain {
                "metrics" => Self::Metrics(MetricsCap::from_str(inner)?),
                "relay" => Self::Relay(RelayCap::from_str(inner)?),
                "net-diagnostics" => Self::NetDiagnostics(NetDiagnosticsCap::from_str(inner)?),
                _ => bail!("invalid cap domain"),
            })
        } else {
            Err(anyhow::anyhow!("invalid cap string"))
        }
    }
}

cap_enum!(
    /// A metrics capability.
    pub enum MetricsCap {
        PutAny,
    }
);

cap_enum!(
    /// A relay capability.
    pub enum RelayCap {
        Use,
    }
);

cap_enum!(
    /// A network-diagnostics capability.
    pub enum NetDiagnosticsCap {
        PutAny,
        GetAny,
    }
);

impl Caps {
    pub fn new(caps: impl IntoIterator<Item = impl Into<Cap>>) -> Self {
        Self::V0(CapSet::new(caps))
    }

    /// Returns the capabilities granted by a shared API secret.
    pub fn for_shared_secret() -> Self {
        Self::new([Cap::Client])
    }

    /// Returns the maximum set of capabilities.
    pub fn all() -> Self {
        Self::new([Cap::All])
    }

    pub fn extend(self, caps: impl IntoIterator<Item = impl Into<Cap>>) -> Self {
        let Self::V0(mut set) = self;
        set.extend(caps.into_iter().map(Into::into));
        Self::V0(set)
    }

    pub fn from_strs<'a>(strs: impl IntoIterator<Item = &'a str>) -> Result<Self> {
        Ok(Self::V0(CapSet::from_strs(strs)?))
    }

    pub fn to_strings(&self) -> Vec<String> {
        let Self::V0(set) = self;
        set.to_strings()
    }

    pub fn permits(&self, other: &Self) -> bool {
        let Self::V0(slf) = self;
        let Self::V0(other) = other;
        slf.permits(other)
    }

    pub(crate) fn into_proto(self) -> iroh_services_proto::caps::Caps {
        let Self::V0(set) = self;
        iroh_services_proto::caps::Caps::new(set.0.into_iter().map(Cap::into_proto))
    }

    pub(crate) fn from_proto(caps: iroh_services_proto::caps::Caps) -> Self {
        Self::new(caps.iter().copied().map(Cap::from_proto))
    }
}

impl From<Cap> for Caps {
    fn from(cap: Cap) -> Self {
        Self::new([cap])
    }
}

impl Cap {
    pub fn permits(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::All, _) => true,
            (Self::Client, other) => client_capabilities(other),
            (Self::Relay(slf), Self::Relay(other)) => slf.permits(other),
            (Self::Metrics(slf), Self::Metrics(other)) => slf.permits(other),
            (Self::NetDiagnostics(slf), Self::NetDiagnostics(other)) => slf.permits(other),
            (_, _) => false,
        }
    }

    fn into_proto(self) -> iroh_services_proto::caps::Cap {
        use iroh_services_proto::caps as proto;

        match self {
            Self::All => proto::Cap::All,
            Self::Client => proto::Cap::Client,
            Self::Relay(RelayCap::Use) => proto::Cap::Relay(proto::RelayCap::Use),
            Self::Metrics(MetricsCap::PutAny) => proto::Cap::Metrics(proto::MetricsCap::PutAny),
            Self::NetDiagnostics(NetDiagnosticsCap::PutAny) => {
                proto::Cap::NetDiagnostics(proto::NetDiagnosticsCap::PutAny)
            }
            Self::NetDiagnostics(NetDiagnosticsCap::GetAny) => {
                proto::Cap::NetDiagnostics(proto::NetDiagnosticsCap::GetAny)
            }
        }
    }

    fn from_proto(cap: iroh_services_proto::caps::Cap) -> Self {
        use iroh_services_proto::caps as proto;

        match cap {
            proto::Cap::All => Self::All,
            proto::Cap::Client => Self::Client,
            proto::Cap::Relay(proto::RelayCap::Use) => Self::Relay(RelayCap::Use),
            proto::Cap::Metrics(proto::MetricsCap::PutAny) => Self::Metrics(MetricsCap::PutAny),
            proto::Cap::NetDiagnostics(proto::NetDiagnosticsCap::PutAny) => {
                Self::NetDiagnostics(NetDiagnosticsCap::PutAny)
            }
            proto::Cap::NetDiagnostics(proto::NetDiagnosticsCap::GetAny) => {
                Self::NetDiagnostics(NetDiagnosticsCap::GetAny)
            }
        }
    }
}

fn client_capabilities(other: &Cap) -> bool {
    match other {
        Cap::All => false,
        Cap::Client => true,
        Cap::Relay(RelayCap::Use) => true,
        Cap::Metrics(MetricsCap::PutAny) => true,
        Cap::NetDiagnostics(NetDiagnosticsCap::PutAny) => true,
        Cap::NetDiagnostics(NetDiagnosticsCap::GetAny) => true,
    }
}

impl MetricsCap {
    pub fn permits(&self, other: &Self) -> bool {
        matches!((self, other), (Self::PutAny, Self::PutAny))
    }
}

impl RelayCap {
    pub fn permits(&self, other: &Self) -> bool {
        matches!((self, other), (Self::Use, Self::Use))
    }
}

impl NetDiagnosticsCap {
    pub fn permits(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::PutAny, Self::PutAny) | (Self::GetAny, Self::GetAny)
        )
    }
}

/// A set of capabilities.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Serialize, Deserialize)]
pub struct CapSet<C: Ord>(BTreeSet<C>);

impl<C: Ord> Default for CapSet<C> {
    fn default() -> Self {
        Self(BTreeSet::new())
    }
}

impl<C: Ord> CapSet<C> {
    pub fn new(set: impl IntoIterator<Item = impl Into<C>>) -> Self {
        Self(BTreeSet::from_iter(set.into_iter().map(Into::into)))
    }

    pub fn iter(&self) -> impl Iterator<Item = &'_ C> + '_ {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn contains(&self, cap: impl Into<C>) -> bool {
        self.0.contains(&cap.into())
    }

    pub fn extend(&mut self, caps: impl IntoIterator<Item = impl Into<C>>) {
        self.0.extend(caps.into_iter().map(Into::into));
    }

    pub fn insert(&mut self, cap: impl Into<C>) -> bool {
        self.0.insert(cap.into())
    }

    pub fn from_strs<'a, E>(strs: impl IntoIterator<Item = &'a str>) -> Result<Self>
    where
        C: FromStr<Err = E>,
        Result<C, E>: Context<C, E>,
    {
        let mut caps = Self::default();
        for s in strs {
            let cap = C::from_str(s).with_context(|| format!("Unknown capability: {s}"))?;
            caps.insert(cap);
        }
        Ok(caps)
    }

    pub fn to_strings(&self) -> Vec<String>
    where
        C: fmt::Display,
    {
        self.iter().map(ToString::to_string).collect()
    }
}

impl CapSet<Cap> {
    pub fn permits(&self, other: &Self) -> bool {
        other
            .iter()
            .all(|other_cap| self.iter().any(|self_cap| self_cap.permits(other_cap)))
    }
}

pub(crate) const DEFAULT_CAP_EXPIRY: Duration = Duration::from_hours(24 * 30); // 1 month

/// Create an rcan token for the api access from a PEM-encoded OpenSSH ed25519
/// private key.
#[cfg(not(wasm_browser))]
pub fn create_api_token_from_openssh_pem(
    pem: &str,
    local_id: EndpointId,
    max_age: Duration,
    capability: Caps,
) -> Result<ApiToken> {
    let seed = crate::openssh::parse_ed25519_private_key(pem)?;
    let issuer = ed25519_dalek::SigningKey::from_bytes(&seed);
    let audience = local_id.as_verifying_key();
    let can = Rcan::issuing_builder(&issuer, audience, capability.into_proto())
        .sign(Expires::valid_for(max_age));
    Ok(ApiToken::new(can))
}

/// Create an rcan token that grants capabilities to a remote endpoint.
/// The local endpoint is the issuer (granter), and the remote endpoint is the
/// audience (grantee).
pub fn create_grant_token(
    local_secret: SecretKey,
    remote_id: EndpointId,
    max_age: Duration,
    capability: Caps,
) -> Result<ApiToken> {
    let issuer = ed25519_dalek::SigningKey::from_bytes(&local_secret.to_bytes());
    let audience = remote_id.as_verifying_key();
    let can = Rcan::issuing_builder(&issuer, audience, capability.into_proto())
        .sign(Expires::valid_for(max_age));
    Ok(ApiToken::new(can))
}

/// Create an rcan token for the api access from an iroh secret key
pub fn create_api_token_from_secret_key(
    private_key: SecretKey,
    local_id: EndpointId,
    max_age: Duration,
    capability: Caps,
) -> Result<ApiToken> {
    let issuer = ed25519_dalek::SigningKey::from_bytes(&private_key.to_bytes());
    let audience = local_id.as_verifying_key();
    let can = Rcan::issuing_builder(&issuer, audience, capability.into_proto())
        .sign(Expires::valid_for(max_age));
    Ok(ApiToken::new(can))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_conversion_preserves_capabilities() {
        let caps = Caps::new([
            Cap::All,
            Cap::Client,
            Cap::Relay(RelayCap::Use),
            Cap::Metrics(MetricsCap::PutAny),
            Cap::NetDiagnostics(NetDiagnosticsCap::PutAny),
            Cap::NetDiagnostics(NetDiagnosticsCap::GetAny),
        ]);

        let proto = caps.clone().into_proto();
        assert_eq!(proto.to_strings(), caps.to_strings());
        assert_eq!(Caps::from_proto(proto), caps);
    }
}

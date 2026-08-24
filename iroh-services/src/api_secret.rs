use std::{collections::BTreeSet, env::VarError, fmt, str::FromStr};

use anyhow::{Context, anyhow};
use iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};
use iroh_tickets::{ParseError, Ticket};
use serde::{Deserialize, Serialize};

/// The environment variable name this crate checks in builders for an API secret.
pub const API_SECRET_ENV_VAR_NAME: &str = "IROH_SERVICES_API_SECRET";

/// The secret material used to connect your services.iroh.computer project. The
/// value of these should be treated like any other API key: guard them carefully.
#[derive(Debug, Clone)]
pub struct ApiSecret {
    /// ED25519 secret used to construct rcans from.
    pub secret: SecretKey,
    /// The iroh-services endpoint to direct requests to.
    pub remote: EndpointAddr,
}

impl fmt::Display for ApiSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode_string())
    }
}

#[derive(Serialize, Deserialize)]
struct Variant0EndpointAddr {
    endpoint_id: EndpointId,
    addrs: BTreeSet<TransportAddr>,
}

/// Wire format for [`Ticket`].
#[derive(Serialize, Deserialize)]
enum TicketWireFormat {
    Variant0(Variant0ServicesTicket),
}

#[derive(Serialize, Deserialize)]
struct Variant0ServicesTicket {
    secret: SecretKey,
    addr: Variant0EndpointAddr,
}

impl Ticket for ApiSecret {
    const KIND: &'static str = "services";

    fn encode_bytes(&self) -> Vec<u8> {
        let data = TicketWireFormat::Variant0(Variant0ServicesTicket {
            secret: self.secret.clone(),
            addr: Variant0EndpointAddr {
                endpoint_id: self.remote.id,
                addrs: self.remote.addrs.clone(),
            },
        });
        postcard::to_stdvec(&data).expect("postcard serialization failed")
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let TicketWireFormat::Variant0(Variant0ServicesTicket { secret, addr }) =
            postcard::from_bytes(bytes)?;
        Ok(Self {
            secret,
            remote: EndpointAddr {
                id: addr.endpoint_id,
                addrs: addr.addrs,
            },
        })
    }
}

impl FromStr for ApiSecret {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode_string(s)
    }
}

impl ApiSecret {
    /// Creates a new API secret.
    pub fn new(secret: SecretKey, remote: impl Into<EndpointAddr>) -> Self {
        Self {
            secret,
            remote: remote.into(),
        }
    }

    /// Reads an API secret from the given environment variable.
    pub fn from_env_var(env_var: &str) -> anyhow::Result<Self> {
        match std::env::var(env_var) {
            Ok(ticket_string) if ticket_string.is_empty() => {
                Err(anyhow!("{env_var} environment variable is set but empty"))
            }
            Ok(ticket_string) => Self::from_str(&ticket_string)
                .context(format!("invalid api secret at env var {env_var}")),
            Err(VarError::NotPresent) => Err(anyhow!("{env_var} environment variable is not set")),
            Err(VarError::NotUnicode(err)) => Err(anyhow!(
                "{env_var} environment variable is not valid unicode: {err:?}"
            )),
        }
    }

    /// Returns the [`EndpointAddr`] of the provider for this ticket.
    pub fn addr(&self) -> &EndpointAddr {
        &self.remote
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_roundtrips() {
        let secret = SecretKey::from_bytes(&[1; 32]);
        let facade = ApiSecret::new(secret, SecretKey::from_bytes(&[2; 32]).public());

        let decoded = ApiSecret::decode_bytes(&facade.encode_bytes()).unwrap();
        assert_eq!(decoded.secret.to_bytes(), facade.secret.to_bytes());
        assert_eq!(decoded.remote, facade.remote);
    }
}

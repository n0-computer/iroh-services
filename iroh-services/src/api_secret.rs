use std::{
    collections::BTreeSet,
    env::VarError,
    fmt::{self, Display},
    str::FromStr,
};

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
    /// ED25519 secret used to construct rcans from
    pub secret: SecretKey,
    /// The iroh-services endpoint to direct requests to
    pub remote: EndpointAddr,
}

impl Display for ApiSecret {
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
    // KIND is the constant that's added to the front of a serialized ticket
    // string. It should be a short, human readable string
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
        let res: TicketWireFormat = postcard::from_bytes(bytes)?;
        let TicketWireFormat::Variant0(Variant0ServicesTicket { secret, addr }) = res;
        Ok(Self {
            secret,
            remote: EndpointAddr {
                id: addr.endpoint_id,
                addrs: addr.addrs.clone(),
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
    /// Creates a new ticket.
    pub fn new(secret: SecretKey, remote: impl Into<EndpointAddr>) -> Self {
        Self {
            secret,
            remote: remote.into(),
        }
    }

    /// Read an Api Secret from a given environment variable
    pub fn from_env_var(env_var: &str) -> anyhow::Result<Self> {
        match std::env::var(env_var) {
            Ok(ticket_string) if ticket_string.is_empty() => {
                Err(anyhow!("{env_var} environment variable is set but empty"))
            }
            Ok(ticket_string) => Self::from_str(&ticket_string)
                .context(format!("invalid api secret at env var {env_var}")),
            Err(VarError::NotPresent) => Err(anyhow!("{env_var} environment variable is not set")),
            Err(VarError::NotUnicode(e)) => Err(anyhow!(
                "{env_var} environment variable is not valid unicode: {:?}",
                e
            )),
        }
    }

    /// The [`EndpointAddr`] of the provider for this ticket.
    pub fn addr(&self) -> &EndpointAddr {
        &self.remote
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ticket string is a credential users store outside the process, so
    /// its encoding has to survive across releases the same way the wire
    /// format does. This pins the format released as iroh-services 1.0.0.
    ///
    /// The cross-version wire encoding is covered separately, in
    /// `iroh-services-proto/tests/wire_compat.rs`.
    #[test]
    fn test_ticket_encoding_matches_v1() {
        const V1_TICKET: &str = "servicesaaqcukrkfivcukrkfivcukrkfivcukrkfivcukrkfivcukrkfivcuksfbcqhvkkbob7t5mw3steis6uawlars5dww3pccowcoppx3bwe74aa";

        let secret = SecretKey::from_bytes(&[42u8; 32]);
        let remote = SecretKey::from_bytes(&[43u8; 32]).public();
        let ticket = ApiSecret::new(secret.clone(), remote);
        assert_eq!(
            ticket.to_string(),
            V1_TICKET,
            "the api secret encoding changed since iroh-services 1.0.0, \
             which invalidates every secret already issued"
        );

        let parsed = ApiSecret::from_str(V1_TICKET).expect("a v1 ticket must still parse");
        assert_eq!(parsed.secret.to_bytes(), secret.to_bytes());
        assert_eq!(parsed.remote.id, remote);
    }
}

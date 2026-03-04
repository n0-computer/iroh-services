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

/// The secret material used to connect your services.iroh.computer project. The
/// value of these should be treated like any other API key: guard them carefully.
#[derive(Debug, Clone)]
pub struct ApiKey {
    /// ED25519 secret used to construct rcans from
    pub secret: SecretKey,
    /// the services endpoint to direct requests to
    pub remote: EndpointAddr,
}

impl Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Ticket::serialize(self))
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
    Variant0(Variant0servicesTicket),
}

#[derive(Serialize, Deserialize)]
struct Variant0servicesTicket {
    secret: SecretKey,
    addr: Variant0EndpointAddr,
}

impl Ticket for ApiKey {
    // KIND is the constant that's added to the front of a serialized ticket
    // string. It should be a short, human readable string
    const KIND: &'static str = "services";

    fn to_bytes(&self) -> Vec<u8> {
        let data = TicketWireFormat::Variant0(Variant0servicesTicket {
            secret: self.secret.clone(),
            addr: Variant0EndpointAddr {
                endpoint_id: self.remote.id,
                addrs: self.remote.addrs.clone(),
            },
        });
        postcard::to_stdvec(&data).expect("postcard serialization failed")
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let res: TicketWireFormat = postcard::from_bytes(bytes)?;
        let TicketWireFormat::Variant0(Variant0servicesTicket { secret, addr }) = res;
        Ok(Self {
            secret,
            remote: EndpointAddr {
                id: addr.endpoint_id,
                addrs: addr.addrs.clone(),
            },
        })
    }
}

impl FromStr for ApiKey {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        iroh_tickets::Ticket::deserialize(s)
    }
}

impl ApiKey {
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

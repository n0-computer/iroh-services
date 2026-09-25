use std::{
    collections::BTreeSet,
    env::VarError,
    fmt::{self, Display},
    str::FromStr,
};

use iroh::{EndpointAddr, EndpointId, SecretKey, TransportAddr};
use iroh_tickets::{ParseError, Ticket};
use n0_error::{e, stack_error};
use serde::{Deserialize, Serialize};

/// The environment variable name this crate checks in builders for an API secret.
pub const API_SECRET_ENV_VAR_NAME: &str = "IROH_SERVICES_API_SECRET";

/// Error returned by [`ApiSecret::from_env_var`].
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum FromEnvError {
    #[error("{env_var} environment variable is not set")]
    NotSet { env_var: String },
    #[error("{env_var} environment variable is set but empty")]
    Empty { env_var: String },
    #[error("{env_var} environment variable is not valid unicode")]
    NotUnicode { env_var: String },
    #[error("{env_var} environment variable is not a valid api secret")]
    Invalid { env_var: String, source: ParseError },
}

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
    pub fn from_env_var(env_var: &str) -> Result<Self, FromEnvError> {
        let env_var = env_var.to_string();
        match std::env::var(&env_var) {
            Ok(ticket_string) if ticket_string.is_empty() => {
                Err(e!(FromEnvError::Empty { env_var }))
            }
            Ok(ticket_string) => Self::from_str(&ticket_string)
                .map_err(|source| e!(FromEnvError::Invalid { env_var }, source)),
            Err(VarError::NotPresent) => Err(e!(FromEnvError::NotSet { env_var })),
            Err(VarError::NotUnicode(_)) => Err(e!(FromEnvError::NotUnicode { env_var })),
        }
    }

    /// The [`EndpointAddr`] of the provider for this ticket.
    pub fn addr(&self) -> &EndpointAddr {
        &self.remote
    }
}

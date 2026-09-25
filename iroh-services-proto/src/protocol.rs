use std::collections::BTreeMap;

use irpc::{channel::oneshot, rpc_requests};
use n0_error::stack_error;
use rcan::Rcan;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{caps::Caps, net_diagnostics::DiagnosticsReport};

/// The main ALPN for connecting from the client to the cloud node.
///
/// # Versioning
///
/// The wire protocol is append-only and does not bump this ALPN for additive
/// changes. postcard encodes enum variants by index, so as long as new
/// [`IrohServicesProtocol`] and [`RemoteError`] variants are only appended
/// (never inserted, reordered, or removed), older messages stay wire-compatible:
///
/// - An older client always works against a newer server: the server decodes
///   every request the client can send, and only replies with error variants the
///   client already knows.
/// - A newer client against an older server keeps working for the pre-existing
///   requests (auth, metrics, and so on); a request the old server does not know
///   fails as a per-request error rather than breaking the connection.
///
/// The cloud node is deployed at or ahead of the clients that talk to it, so the
/// second case is transient and limited to the new calls. A breaking change
/// (reordering or removing variants, or changing a message's shape) requires a
/// new ALPN.
pub const ALPN: &[u8] = b"/iroh/n0des/1";

/// The ALPN for sending messages from the cloud node to the client.
pub const CLIENT_HOST_ALPN: &[u8] = b"n0/n0des-client-host/1";

pub type IrohServicesClient = irpc::Client<IrohServicesProtocol>;

pub type ClientHostClient = irpc::Client<ClientHostProtocol>;

/// New request variants MUST be appended, never inserted or reordered. See the
/// versioning policy on [`ALPN`].
#[rpc_requests(message = ServicesMessage)]
#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
pub enum IrohServicesProtocol {
    #[rpc(tx=oneshot::Sender<()>)]
    Auth(Auth),
    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    PutMetrics(PutMetrics),
    #[rpc(tx=oneshot::Sender<Pong>)]
    Ping(Ping),

    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    PutNetworkDiagnostics(PutNetworkDiagnostics),

    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    GrantCap(GrantCap),

    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    NameEndpoint(NameEndpoint),

    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    SetGroup(SetGroup),

    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    SetAttributes(SetAttributes),
}

/// Dedicated protocol for cloud-to-endpoint net diagnostics connections.
#[rpc_requests(message = NetDiagnosticsMessage)]
#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ClientHostProtocol {
    #[rpc(tx=oneshot::Sender<()>)]
    Auth(Auth),
    #[rpc(tx=oneshot::Sender<RemoteResult<DiagnosticsReport>>)]
    RunNetworkDiagnostics(RunNetworkDiagnostics),
}

pub type RemoteResult<T> = Result<T, RemoteError>;

// No `add_meta` here: this is a wire type, and `n0_error::Meta` is not
// serializable.
#[stack_error(derive)]
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RemoteError {
    // The first three variants and their order are the v1 wire contract: postcard
    // encodes enum variants by index, so a v1 client only decodes these and at
    // their original positions. New variants MUST be appended after them, and the
    // server must only send new variants in response to new (v2+) requests.
    #[error("Missing capability: {}", _0.to_strings().join(", "))]
    MissingCapability(Caps),
    #[error("Unauthorized: {_0}")]
    AuthError(String),
    #[error("Internal server error")]
    InternalServerError,
    #[error("Invalid input: {_0}")]
    InvalidInput(String),
    #[error("Rate limit exceeded")]
    RateLimited,
}

/// Authentication on first request
#[derive(Debug, derive_more::Display, Serialize, Deserialize)]
#[display("Auth")]
pub struct Auth {
    pub caps: Rcan<Caps>,
}

/// Request to store the given metrics data
#[derive(Debug, derive_more::Display, Serialize, Deserialize)]
#[display("PutMetrics")]
pub struct PutMetrics {
    pub session_id: Uuid,
    pub update: iroh_metrics::encoding::Update,
}

/// Simple ping requests
#[derive(Debug, derive_more::Display, Serialize, Deserialize)]
#[display("Ping")]
pub struct Ping {
    pub req_id: [u8; 16],
}

/// Simple ping response
#[derive(Debug, Serialize, Deserialize)]
pub struct Pong {
    pub req_id: [u8; 16],
}

/// Publishing network diagnostics
#[derive(Debug, derive_more::Display, Serialize, Deserialize)]
#[display("PutNetworkDiagnostics")]
pub struct PutNetworkDiagnostics {
    pub report: DiagnosticsReport,
}

/// ask this node to run diagnostics & return the result.
/// present even without the net_diagnostics feature flag because the request
/// struct is empty in both cases
#[derive(Debug, derive_more::Display, Serialize, Deserialize)]
#[display("RunNetworkDiagnostics")]
pub struct RunNetworkDiagnostics;

/// Grant a capability token to the remote endpoint. The remote should store
/// the RCAN and use it when dialing back to authorize its requests.
#[derive(Debug, derive_more::Display, Serialize, Deserialize)]
#[display("GrantCap")]
pub struct GrantCap {
    pub cap: Rcan<Caps>,
}

/// Label the client endpoint cloud-side with a string identifier.
#[derive(Debug, derive_more::Display, Serialize, Deserialize)]
#[display("NameEndpoint")]
pub struct NameEndpoint {
    pub name: String,
}

/// Attach the client endpoint to a single named group cloud-side.
#[derive(Debug, derive_more::Display, Serialize, Deserialize)]
#[display("SetGroup")]
pub struct SetGroup {
    pub group: String,
}

/// Maximum length in bytes for an attribute value. Values may be empty.
pub const ATTRIBUTE_VALUE_MAX_LENGTH: usize = 128;

/// Maximum number of entries allowed in the attributes map.
pub const ATTRIBUTES_MAX_COUNT: usize = 128;

/// Replace the arbitrary key-value attributes on the client endpoint cloud-side.
#[derive(Debug, derive_more::Display, Serialize, Deserialize)]
#[display("SetAttributes")]
pub struct SetAttributes {
    pub attributes: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{ATTRIBUTE_VALUE_MAX_LENGTH, RemoteError, SetAttributes, SetGroup};

    #[test]
    fn test_remote_error_wire_compat() {
        // postcard encodes enum variants by their index. v1 clients only know
        // the first three RemoteError variants, so these indices are a frozen
        // wire contract; new variants must be appended after them.
        let idx = |e: &RemoteError| postcard::to_stdvec(e).expect("encode")[0];
        assert_eq!(idx(&RemoteError::AuthError(String::new())), 1);
        assert_eq!(idx(&RemoteError::InternalServerError), 2);
        // v2+ variants, appended after the v1 set.
        assert_eq!(idx(&RemoteError::InvalidInput(String::new())), 3);
        assert_eq!(idx(&RemoteError::RateLimited), 4);
    }

    // The wire format used by irpc is postcard. These round-trips pin the
    // on-the-wire contract these messages share with the server.

    #[test]
    fn test_set_group_serde_roundtrip() {
        // a normal group, plus a unicode group for good measure
        for group in ["staging", "my-group 👋"] {
            let msg = SetGroup {
                group: group.to_string(),
            };
            let bytes = postcard::to_stdvec(&msg).expect("postcard serialize");
            let decoded: SetGroup = postcard::from_bytes(&bytes).expect("postcard deserialize");
            assert_eq!(decoded.group, msg.group);
        }
    }

    #[test]
    fn test_set_attributes_serde_roundtrip() {
        // empty map: the documented "clear" case
        let empty = SetAttributes {
            attributes: BTreeMap::new(),
        };
        let bytes = postcard::to_stdvec(&empty).expect("postcard serialize");
        let decoded: SetAttributes = postcard::from_bytes(&bytes).expect("postcard deserialize");
        assert!(decoded.attributes.is_empty());
        assert_eq!(decoded.attributes, empty.attributes);

        // unicode key/value plus a value at exactly the documented max length
        let mut attributes = BTreeMap::new();
        attributes.insert("région 🌍".to_string(), "us-wëst 🚀".to_string());
        let max_value = "x".repeat(ATTRIBUTE_VALUE_MAX_LENGTH);
        assert_eq!(max_value.len(), ATTRIBUTE_VALUE_MAX_LENGTH);
        attributes.insert("max".to_string(), max_value);

        let msg = SetAttributes { attributes };
        let bytes = postcard::to_stdvec(&msg).expect("postcard serialize");
        let decoded: SetAttributes = postcard::from_bytes(&bytes).expect("postcard deserialize");
        assert_eq!(decoded.attributes, msg.attributes);
    }
}

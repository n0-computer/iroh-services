use std::collections::BTreeMap;

use anyhow::Result;
use irpc::{channel::oneshot, rpc_requests};
use rcan::Rcan;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{caps::Caps, net_diagnostics::DiagnosticsReport};

/// The main ALPN for connecting from the client to the cloud node.
pub const ALPN: &[u8] = b"/iroh/n0des/1";

pub type IrohServicesClient = irpc::Client<IrohServicesProtocol>;

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

#[derive(Clone, Serialize, Deserialize, thiserror::Error, Debug)]
#[non_exhaustive]
pub enum RemoteError {
    // The first three variants and their order are the v1 wire contract: postcard
    // encodes enum variants by index, so a v1 client only decodes these and at
    // their original positions. New variants MUST be appended after them, and the
    // server must only send new variants in response to new (v2+) requests.
    #[error("Missing capability: {}", _0.to_strings().join(", "))]
    MissingCapability(Caps),
    #[error("Unauthorized: {}", _0)]
    AuthError(String),
    #[error("Internal server error")]
    InternalServerError,
    #[error("Invalid input: {}", _0)]
    InvalidInput(String),
    #[error("Rate limit exceeded")]
    RateLimited,
}

/// Authentication on first request
#[derive(Debug, Serialize, Deserialize)]
pub struct Auth {
    pub caps: Rcan<Caps>,
}

/// Request to store the given metrics data
#[derive(Debug, Serialize, Deserialize)]
pub struct PutMetrics {
    pub session_id: Uuid,
    pub update: iroh_metrics::encoding::Update,
}

/// Simple ping requests
#[derive(Debug, Serialize, Deserialize)]
pub struct Ping {
    pub req_id: [u8; 16],
}

/// Simple ping response
#[derive(Debug, Serialize, Deserialize)]
pub struct Pong {
    pub req_id: [u8; 16],
}

/// Publishing network diagnostics
#[derive(Debug, Serialize, Deserialize)]
pub struct PutNetworkDiagnostics {
    pub report: crate::net_diagnostics::DiagnosticsReport,
}

/// ask this node to run diagnostics & return the result.
/// present even without the net_diagnostics feature flag because the request
/// struct is empty in both cases
#[derive(Debug, Serialize, Deserialize)]
pub struct RunNetworkDiagnostics;

/// Grant a capability token to the remote endpoint. The remote should store
/// the RCAN and use it when dialing back to authorize its requests.
#[derive(Debug, Serialize, Deserialize)]
pub struct GrantCap {
    pub cap: Rcan<Caps>,
}

/// Label the client endpoint cloud-side with a string identifier.
#[derive(Debug, Serialize, Deserialize)]
pub struct NameEndpoint {
    pub name: String,
}

/// Attach the client endpoint to a single named group cloud-side.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetGroup {
    pub group: String,
}

/// Replace the arbitrary key-value attributes on the client endpoint cloud-side.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetAttributes {
    pub attributes: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{RemoteError, SetAttributes, SetGroup};
    use crate::client::CLIENT_ATTRIBUTE_VALUE_MAX_LENGTH;

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

    // The wire format used by irpc (and elsewhere in this crate, see
    // `api_secret.rs`) is postcard. These round-trips pin the on-the-wire
    // contract these messages share with the server.

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
        let max_value = "x".repeat(CLIENT_ATTRIBUTE_VALUE_MAX_LENGTH);
        assert_eq!(max_value.len(), CLIENT_ATTRIBUTE_VALUE_MAX_LENGTH);
        attributes.insert("max".to_string(), max_value);

        let msg = SetAttributes { attributes };
        let bytes = postcard::to_stdvec(&msg).expect("postcard serialize");
        let decoded: SetAttributes = postcard::from_bytes(&bytes).expect("postcard deserialize");
        assert_eq!(decoded.attributes, msg.attributes);
    }
}

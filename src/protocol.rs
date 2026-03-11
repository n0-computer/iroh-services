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
pub enum RemoteError {
    #[error("Missing capability: {}", _0.to_strings().join(", "))]
    MissingCapability(Caps),
    #[error("Unauthorized: {}", _0)]
    AuthError(String),
    #[error("Internal server error")]
    InternalServerError,
}

/// Authentication on first request
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
pub struct Auth {
    pub caps: Rcan<Caps>,
    /// Optional human-readable label for this endpoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            caps: Default::default(),
            label: None,
        }
    }
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

#[cfg(test)]
mod tests {
    use iroh::SecretKey;
    use n0_future::time::Duration;
    use serde::{Deserialize, Serialize};

    use crate::caps::{Caps, create_api_token_from_secret_key};

    use super::Auth;

    fn make_auth(label: Option<&str>) -> Auth {
        let mut rng = rand::rng();
        let secret = SecretKey::generate(&mut rng);
        let id = SecretKey::generate(&mut rng).public();
        let caps =
            create_api_token_from_secret_key(secret, id, Duration::from_secs(60), Caps::default())
                .unwrap();
        Auth {
            caps,
            label: label.map(Into::into),
        }
    }

    /// Simulates an old server/client that has no label field.
    #[derive(Serialize, Deserialize)]
    struct LegacyAuth {
        caps: rcan::Rcan<Caps>,
    }

    #[test]
    fn auth_label_round_trip() {
        let auth = make_auth(Some("my-node"));
        let bytes = postcard::to_stdvec(&auth).unwrap();
        let decoded: Auth = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.label, Some("my-node".to_string()));
    }

    #[test]
    fn auth_label_new_client_old_server_compat() {
        // A new client sending Auth with label=None should produce bytes that an
        // old server (represented here by LegacyAuth) can still decode successfully.
        let auth = make_auth(None);
        let bytes = postcard::to_stdvec(&auth).unwrap();

        // Old server decodes the prefix it understands and ignores any trailing bytes
        // (such as those that might be introduced by the optional `label` field).
        let (_legacy, _remaining) = postcard::take_from_bytes::<LegacyAuth>(&bytes).unwrap();
    }
}

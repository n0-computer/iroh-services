use anyhow::Result;
use irpc::{
    channel::{mpsc, oneshot},
    rpc_requests,
};
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

    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    NameEndpoint(NameEndpoint),
    #[rpc(tx=oneshot::Sender<RemoteResult<Option<SetLogLevel>>>)]
    GetLogLevel(GetLogLevel),
}

/// Dedicated protocol for cloud-to-endpoint callbacks (net diagnostics, log
/// level overrides).
#[rpc_requests(message = ClientHostMessage)]
#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ClientHostProtocol {
    #[rpc(tx=oneshot::Sender<()>)]
    Auth(Auth),
    #[rpc(tx=oneshot::Sender<RemoteResult<DiagnosticsReport>>)]
    RunNetworkDiagnostics(RunNetworkDiagnostics),
    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    SetLogLevel(SetLogLevel),
    #[rpc(tx=mpsc::Sender<RemoteResult<Vec<u8>>>)]
    FetchLogs(FetchLogs),
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

/// Ask the client to stream the contents of its currently-active rolling
/// log file. The client picks the newest file under its configured
/// log directory matching the configured filename prefix.
#[derive(Debug, Serialize, Deserialize)]
pub struct FetchLogs {
    /// Stop after this many bytes have been streamed. `None` means stream
    /// the whole current file. The cloud caller is expected to enforce its
    /// own plan-tier cap on top of this.
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

/// Log-level filter settings. Used in two directions:
/// - As a cloud-to-client push (via the [`crate::ClientHost`] callback)
///   to apply a new override mid-session.
/// - As the response payload to [`GetLogLevel`] so the client can pull
///   the persisted setting on connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetLogLevel {
    /// `EnvFilter`-compatible directive string (for example
    /// `"info,iroh=trace,iroh_blobs=debug"`).
    pub directives: String,
    /// If `Some`, the client reverts after this many seconds. If `None`, the
    /// override is permanent until the next call.
    pub expires_in_secs: Option<u64>,
    /// Directives to revert to when the TTL fires. When `None`, the client
    /// reverts to its install-time default. The cloud sends the project-wide
    /// default here so per-endpoint overrides decay back to project policy
    /// rather than to the client's own startup setting.
    #[serde(default)]
    pub revert_to: Option<String>,
}

/// Client-initiated request for the cloud's current log-level settings.
/// Sent right after auth so the client lands on the correct filter
/// without waiting for the cloud to push.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetLogLevel;

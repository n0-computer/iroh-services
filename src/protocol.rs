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

    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    SendAlert(SendAlert),
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

/// Information about a captured error-level log event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertInfo {
    pub target: String,
    pub message: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub iroh_version: String,
    #[serde(default)]
    pub iroh_n0des_version: String,
    /// Up to 200 recent log messages captured before this error, providing
    /// context for what led to the alert.
    #[serde(default)]
    pub context: Vec<LogEntry>,
}

/// A single log entry captured in the context ring buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub level: String,
    pub target: String,
    pub message: String,
    pub timestamp_ms: u64,
}

/// Send an alert to n0des when an error-level log event is captured.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendAlert {
    pub session_id: Uuid,
    pub alert: AlertInfo,
}

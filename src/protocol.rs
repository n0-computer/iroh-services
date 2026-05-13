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
    NameEndpoint(NameEndpoint),

    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    PutLogs(PutLogs),
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

/// A single structured log line emitted by a client process.
///
/// The shape mirrors the JSON format produced by `tracing-subscriber`'s JSON
/// formatter, with the level, target, and timestamp lifted into top-level
/// fields so the cloud can index them as columns. The remaining structured
/// fields and the span stack travel as `Vec<(String, FieldValue)>` so the
/// schema is closed and `postcard` can encode and decode it without any
/// `deserialize_any` paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogLine {
    /// RFC 3339 timestamp produced at log emission time.
    pub timestamp: String,
    /// Log level: TRACE, DEBUG, INFO, WARN, ERROR.
    pub level: String,
    /// Log target (typically the originating module path).
    pub target: String,
    /// Structured fields attached to the event. By convention, the
    /// `message` field carries the human-readable text.
    pub fields: Vec<(String, FieldValue)>,
    /// Active span stack, outermost first. Empty when no span is in scope.
    pub spans: Vec<SpanInfo>,
}

/// A span recorded as part of a [`LogLine`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpanInfo {
    pub name: String,
    pub fields: Vec<(String, FieldValue)>,
}

/// Wire-safe representation of a structured tracing field value.
///
/// Closed enum so `postcard` can round-trip it without `deserialize_any`.
/// Anything that is not one of the typed variants (a `Debug`-formatted
/// value, a non-finite float, a 128-bit integer) is rendered to a string
/// at the producer with [`FieldValue::Other`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FieldValue {
    Str(String),
    I64(i64),
    U64(u64),
    F64(f64),
    Bool(bool),
    /// Fallback for values that do not fit the typed variants. Carries the
    /// `Debug`-formatted text.
    Other(String),
}

/// A batch of log lines pushed from a client to the cloud.
#[derive(Debug, Serialize, Deserialize)]
pub struct PutLogs {
    pub session_id: Uuid,
    pub lines: Vec<LogLine>,
    /// Number of lines dropped on the client since the last successful push,
    /// either due to the buffer being full or the throttle being exceeded.
    pub dropped: u32,
}

/// Cloud-issued instruction to override the client's tracing filter.
#[derive(Debug, Serialize, Deserialize)]
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

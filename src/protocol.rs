use iroh_blobs::ticket::BlobTicket;
use rcan::Rcan;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::caps::IpsCap;

pub const ALPN: &[u8] = b"/iroh/ips/1";

/// Messages sent from the client to the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    /// Authentication on first request
    Auth(Rcan<IpsCap>),
    /// Request that the node fetches the given blob.
    PutBlob { ticket: BlobTicket, name: String },
    /// Request to store the given metrics data
    PutMetrics { encoded: String, session_id: Uuid },
    /// Simple ping requests
    Ping { req: [u8; 32] },
}

/// Messages sent from the server to the client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Authentication response
    /// if set, error, otherwise ok
    AuthResponse(Option<String>),
    /// If set, this means it was an error.
    PutBlobResponse(Option<String>),
    /// Simple pong response
    Pong { req: [u8; 32] },
}

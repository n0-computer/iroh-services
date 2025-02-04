use iroh_blobs::ticket::BlobTicket;
use serde::{Deserialize, Serialize};

pub const ALPN: &[u8] = b"/iroh/ips/1";

/// Messages sent from the client to the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    /// Request that the node fetches the given blob.
    PutBlob { ticket: BlobTicket, name: String },
}

/// Messages sent from the server to the client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    // If set, this means it was an error.
    PutBlobResponse(Option<String>),
}

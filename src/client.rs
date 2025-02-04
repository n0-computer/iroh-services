use anyhow::{bail, Result};
use iroh::{
    endpoint::{RecvStream, SendStream},
    Endpoint, NodeAddr,
};
use iroh_blobs::{ticket::BlobTicket, BlobFormat, Hash};
use n0_future::{SinkExt, StreamExt};
use tokio_serde::formats::Bincode;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use crate::protocol::{ClientMessage, ServerMessage, ALPN};

#[derive(Debug)]
pub struct Client {
    _endpoint: Endpoint,
    reader: tokio_serde::Framed<
        FramedRead<RecvStream, LengthDelimitedCodec>,
        ClientMessage,
        ServerMessage,
        Bincode<ClientMessage, ServerMessage>,
    >,
    writer: tokio_serde::Framed<
        FramedWrite<SendStream, LengthDelimitedCodec>,
        ClientMessage,
        ServerMessage,
        Bincode<ClientMessage, ServerMessage>,
    >,
}

impl Client {
    /// Create a new client, connected to the provide service node
    pub async fn new(endpoint: &Endpoint, node_addr: impl Into<NodeAddr>) -> Result<Self> {
        let remote_addr = node_addr.into();
        let connection = endpoint.connect(remote_addr.clone(), ALPN).await?;

        let (send_stream, recv_stream) = connection.open_bi().await?;

        // Delimit frames using a length header
        let length_delimited_read = FramedRead::new(recv_stream, LengthDelimitedCodec::new());
        let length_delimited_write = FramedWrite::new(send_stream, LengthDelimitedCodec::new());

        // Deserialize frames
        let reader = tokio_serde::Framed::new(
            length_delimited_read,
            Bincode::<ClientMessage, ServerMessage>::default(),
        );

        let writer = tokio_serde::Framed::new(
            length_delimited_write,
            Bincode::<ClientMessage, ServerMessage>::default(),
        );

        Ok(Self {
            _endpoint: endpoint.clone(),
            writer,
            reader,
        })
    }

    /// Transfer the blob from the local iroh node to the service node.
    pub async fn put_blob(
        &mut self,
        node: impl Into<NodeAddr>,
        hash: Hash,
        format: BlobFormat,
        name: String,
    ) -> Result<()> {
        let ticket = BlobTicket::new(node.into(), hash, format)?;

        self.writer
            .send(ServerMessage::PutBlob { ticket, name })
            .await?;
        match self.reader.next().await {
            Some(Ok(msg)) => match msg {
                ClientMessage::PutBlobResponse(None) => Ok(()),
                ClientMessage::PutBlobResponse(Some(err)) => {
                    bail!("upload failed: {}", err);
                }
            },
            Some(Err(err)) => {
                bail!("failed to receive response: {:?}", err);
            }
            None => bail!("connection closed"),
        }
    }
}

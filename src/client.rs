use std::{path::Path, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use iroh::{
    endpoint::{RecvStream, SendStream},
    Endpoint, NodeAddr, NodeId,
};
use iroh_blobs::{ticket::BlobTicket, BlobFormat, Hash};
use n0_future::{SinkExt, StreamExt};
use rcan::Rcan;
use tokio_serde::formats::Bincode;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use crate::{
    caps::IpsCap,
    protocol::{ClientMessage, ServerMessage, ALPN},
};

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
    cap: Rcan<IpsCap>,
}

/// Constructs an IPS client
pub struct ClientBuilder {
    cap: Option<Rcan<IpsCap>>,
    remote: NodeAddr,
    cap_expiry: Duration,
}

const DEFAULT_CAP_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24 * 30); // 1 month

impl ClientBuilder {
    pub fn new<A: Into<NodeAddr>>(remote: A) -> Self {
        Self {
            cap: None,
            remote: remote.into(),
            cap_expiry: DEFAULT_CAP_EXPIRY,
        }
    }

    /// Loads the private ssh key from the given path, and creates the needed capability.
    pub async fn ssh_key_from_file<P: AsRef<Path>>(self, path: P) -> Result<Self> {
        let file_content = tokio::fs::read_to_string(path).await?;
        let private_key = ssh_key::PrivateKey::from_openssh(&file_content)?;

        self.ssh_key(&private_key)
    }

    /// Creates the capability from the provided private ssh key.
    pub fn ssh_key(mut self, key: &ssh_key::PrivateKey) -> Result<Self> {
        let cap = crate::caps::create_api_token(key, self.remote.node_id, self.cap_expiry)?;
        self.cap.replace(cap);

        Ok(self)
    }

    /// Sets the capability.
    pub fn capability(mut self, cap: Rcan<IpsCap>) -> Result<Self> {
        ensure!(cap.capability() == &IpsCap::Api, "invalid capability");
        ensure!(
            NodeId::from(*cap.audience()) == self.remote.node_id,
            "invalid audience"
        );

        self.cap.replace(cap);
        Ok(self)
    }

    /// Create a new client, connected to the provide service node
    pub async fn build(self, endpoint: &Endpoint) -> Result<Client> {
        let cap = self.cap.context("missing capability")?;

        let remote_addr = self.remote;
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

        let mut this = Client {
            _endpoint: endpoint.clone(),
            writer,
            reader,
            cap,
        };

        this.authenticate().await?;

        Ok(this)
    }
}

impl Client {
    pub fn builder<A: Into<NodeAddr>>(remote: A) -> ClientBuilder {
        ClientBuilder::new(remote)
    }

    /// Trigger the auth handshake with the server
    async fn authenticate(&mut self) -> Result<()> {
        self.writer
            .send(ServerMessage::Auth(self.cap.clone()))
            .await?;

        match self.reader.next().await {
            Some(Ok(msg)) => match msg {
                ClientMessage::AuthResponse(None) => Ok(()),
                ClientMessage::AuthResponse(Some(err)) => {
                    bail!("failed to authenticate: {}", err);
                }
                _ => {
                    bail!("unexpected message from server: {:?}", msg);
                }
            },
            Some(Err(err)) => {
                bail!("auth: failed to receive response: {:?}", err);
            }
            None => bail!("auth: connection closed"),
        }
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
                _ => {
                    bail!("unexpected message from server: {:?}", msg);
                }
            },
            Some(Err(err)) => {
                bail!("failed to receive response: {:?}", err);
            }
            None => bail!("connection closed"),
        }
    }
}

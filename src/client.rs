use std::{path::Path, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use iroh::{
    endpoint::{RecvStream, SendStream},
    Endpoint, NodeAddr, NodeId,
};
use iroh_blobs::{ticket::BlobTicket, BlobFormat, Hash};
use n0_future::{task::AbortOnDropHandle, SinkExt, StreamExt};
use rand::Rng;
use rcan::Rcan;
use tokio::sync::{mpsc, oneshot};
use tokio_serde::formats::Bincode;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{debug, warn};

use crate::{
    caps::{IpsCap, IpsCapV1},
    protocol::{ClientMessage, ServerMessage, ALPN},
};

#[derive(Debug)]
pub struct Client {
    sender: mpsc::Sender<(ServerMessage, oneshot::Sender<anyhow::Result<()>>)>,
    _actor_task: AbortOnDropHandle<()>,
    cap: Rcan<IpsCap>,
}

/// Constructs an IPS client
pub struct ClientBuilder {
    cap: Option<Rcan<IpsCap>>,
    cap_expiry: Duration,
    endpoint: Endpoint,
    enable_metrics: Option<Duration>,
}

const DEFAULT_CAP_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24 * 30); // 1 month

impl ClientBuilder {
    pub fn new(endpoint: &Endpoint) -> Self {
        Self {
            cap: None,
            cap_expiry: DEFAULT_CAP_EXPIRY,
            endpoint: endpoint.clone(),
            enable_metrics: Some(Duration::from_secs(60)),
        }
    }

    /// Set the metrics collection interval
    ///
    /// Defaults to enabled, every 60 seconds.
    pub fn metrics_interval(mut self, interval: Duration) -> Self {
        self.enable_metrics = Some(interval);
        self
    }

    /// Disbale metrics collection.
    pub fn disable_metrics(mut self) -> Self {
        self.enable_metrics = None;
        self
    }

    /// Loads the private ssh key from the given path, and creates the needed capability.
    pub async fn ssh_key_from_file<P: AsRef<Path>>(self, path: P) -> Result<Self> {
        let file_content = tokio::fs::read_to_string(path).await?;
        let private_key = ssh_key::PrivateKey::from_openssh(&file_content)?;

        self.ssh_key(&private_key)
    }

    /// Creates the capability from the provided private ssh key.
    pub fn ssh_key(mut self, key: &ssh_key::PrivateKey) -> Result<Self> {
        let local_node = self.endpoint.node_id();
        let cap = crate::caps::create_api_token(key, local_node, self.cap_expiry)?;
        self.cap.replace(cap);

        Ok(self)
    }

    /// Sets the capability.
    pub fn capability(mut self, cap: Rcan<IpsCap>) -> Result<Self> {
        ensure!(
            cap.capability() == &IpsCap::V1(IpsCapV1::Api),
            "invalid capability"
        );
        ensure!(
            NodeId::from(*cap.audience()) == self.endpoint.node_id(),
            "invalid audience"
        );

        self.cap.replace(cap);
        Ok(self)
    }

    /// Create a new client, connected to the provide service node
    pub async fn build(self, remote: impl Into<NodeAddr>) -> Result<Client> {
        let cap = self.cap.context("missing capability")?;

        let remote_addr = remote.into();
        let connection = self.endpoint.connect(remote_addr.clone(), ALPN).await?;

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

        let (internal_sender, internal_receiver) = mpsc::channel(64);

        let actor = Actor {
            _endpoint: self.endpoint,
            reader,
            writer,
            cap: cap.clone(),
            internal_receiver,
            internal_sender: internal_sender.clone(),
        };
        let enable_metrics = self.enable_metrics;
        let run_handle = tokio::task::spawn(async move {
            actor.run(enable_metrics).await;
        });
        let actor_task = AbortOnDropHandle::new(run_handle);

        let mut this = Client {
            cap,
            sender: internal_sender,
            _actor_task: actor_task,
        };

        this.authenticate().await?;

        Ok(this)
    }
}

impl Client {
    pub fn builder(endpoint: &Endpoint) -> ClientBuilder {
        ClientBuilder::new(endpoint)
    }

    /// Trigger the auth handshake with the server
    async fn authenticate(&mut self) -> Result<()> {
        let (s, r) = oneshot::channel();
        self.sender
            .send((ServerMessage::Auth(self.cap.clone()), s))
            .await?;
        r.await??;
        Ok(())
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

        let (s, r) = oneshot::channel();
        self.sender
            .send((ServerMessage::PutBlob { ticket, name }, s))
            .await?;
        r.await??;
        Ok(())
    }

    /// Pings the remote node.
    pub async fn ping(&mut self) -> Result<()> {
        let (s, r) = oneshot::channel();
        let req = rand::thread_rng().gen();
        self.sender.send((ServerMessage::Ping { req }, s)).await?;
        r.await??;
        Ok(())
    }
}

struct Actor {
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
    internal_receiver: mpsc::Receiver<(ServerMessage, oneshot::Sender<anyhow::Result<()>>)>,
    internal_sender: mpsc::Sender<(ServerMessage, oneshot::Sender<anyhow::Result<()>>)>,
}

impl Actor {
    async fn run(mut self, enable_metrics: Option<Duration>) {
        if enable_metrics.is_some() {
            if let Err(err) = iroh_metrics::core::Core::try_init(|reg, metrics| {
                use iroh::metrics::*;
                use iroh_metrics::core::Metric;

                metrics.insert(RelayMetrics::new(reg));
                metrics.insert(NetReportMetrics::new(reg));
                metrics.insert(PortmapMetrics::new(reg));
                metrics.insert(MagicsockMetrics::new(reg));
            }) {
                // This is usually okay, as it just means metrics already got initialized somewhere else
                debug!("failed to initialize metrics: {:?}", err);
            }
        }
        let metrics_time = enable_metrics.unwrap_or_else(|| Duration::from_secs(60 * 60 * 24));
        let mut metrics_timer = tokio::time::interval(metrics_time);

        loop {
            tokio::select! {
                biased;
                msg = self.internal_receiver.recv() => {
                    match msg {
                        Some((server_msg, response)) => {
                            let res = self.handle_message(server_msg).await;
                            response.send(res).ok();
                        }
                        None => {
                            debug!("shutting down");
                            break;
                        }
                    }
                }
                _ = metrics_timer.tick(), if enable_metrics.is_some() => {
                    self.send_metrics().await;
                }
            }
        }
    }

    async fn handle_message(&mut self, msg: ServerMessage) -> Result<()> {
        match &msg {
            ServerMessage::Auth(_) => {
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
            ServerMessage::PutBlob { .. } => {
                self.writer.send(msg).await?;
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
            ServerMessage::PutMetrics { .. } => {
                self.writer.send(msg).await?;
                // we don't expect a response
                Ok(())
            }
            ServerMessage::Ping { req } => {
                let req = *req;
                self.writer.send(msg).await?;

                match self.reader.next().await {
                    Some(Ok(msg)) => match msg {
                        ClientMessage::Pong { req: req_back } => {
                            ensure!(req_back == req, "unexpected pong response");
                            Ok(())
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
    }

    async fn send_metrics(&mut self) {
        if let Some(core) = iroh_metrics::core::Core::get() {
            let dump = core.encode();

            let (s, r) = oneshot::channel();
            if let Err(err) = self
                .internal_sender
                .send((ServerMessage::PutMetrics { encoded: dump }, s))
                .await
            {
                warn!("failed to send internal message: {:?}", err);
                // spawn a task, to not block the run loop
                tokio::task::spawn(async move {
                    let res = r.await;
                    debug!("metrics sent: {:?}", res);
                });
            }
        }
    }
}

use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

use anyhow::{Result, anyhow, ensure};
use iroh::{Endpoint, EndpointAddr, EndpointId, endpoint::ConnectError};
use iroh_metrics::{MetricsGroup, Registry, encoding::Encoder};
use irpc_iroh::IrohLazyRemoteConnection;
use n0_error::StackResultExt;
use n0_future::{task::AbortOnDropHandle, time::Duration};
use rcan::Rcan;
use tokio::sync::oneshot;
use tracing::{debug, trace, warn};
use uuid::Uuid;

#[cfg(feature = "net_diagnostics")]
use crate::net_diagnostics::{DiagnosticsReport, checks::run_diagnostics};
#[cfg(feature = "net_diagnostics")]
use crate::protocol::PutNetworkDiagnostics;
use crate::{
    api_secret::ApiSecret,
    caps::Caps,
    protocol::{ALPN, Auth, IrohServicesClient, Ping, Pong, PutMetrics, RemoteError},
};

/// Client is the main handle for interacting with iroh-services. It communicates with
/// iroh-services entirely through an iroh endpoint, and is configured through a builder.
/// Client requires either an Ssh Key or [`ApiSecret`]
///
/// ```no_run
/// use iroh::{Endpoint, endpoint::presets};
/// use iroh_services::Client;
///
/// async fn build_client() -> anyhow::Result<()> {
///     let endpoint = Endpoint::bind(presets::N0).await?;
///
///     // needs IROH_SERVICES_API_SECRET set to an environment variable
///     // client will now push endpoint metrics to iroh-services.
///     let client = Client::builder(&endpoint)
///         .api_secret_from_str("MY_API_SECRET")?
///         .build()
///         .await;
///
///     Ok(())
/// }
/// ```
///
/// [`ApiSecret`]: crate::api_secret::ApiSecret
#[derive(Debug, Clone)]
pub struct Client {
    // owned clone of the endpoint for diagnostics, and for connection restarts on actor close
    #[allow(dead_code)]
    endpoint: Endpoint,
    message_channel: tokio::sync::mpsc::Sender<ClientActorMessage>,
    _actor_task: Arc<AbortOnDropHandle<()>>,
}

/// ClientBuilder provides configures and builds a iroh-services client, typically
/// created with [`Client::builder`]
pub struct ClientBuilder {
    #[allow(dead_code)]
    cap_expiry: Duration,
    cap: Option<Rcan<Caps>>,
    endpoint: Endpoint,
    name: Option<String>,
    metrics_interval: Option<Duration>,
    remote: Option<EndpointAddr>,
    registry: Registry,
}

const DEFAULT_CAP_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24 * 30); // 1 month
pub const API_SECRET_ENV_VAR_NAME: &str = "IROH_SERVICES_API_SECRET";

impl ClientBuilder {
    pub fn new(endpoint: &Endpoint) -> Self {
        let mut registry = Registry::default();
        registry.register_all(endpoint.metrics());

        Self {
            cap: None,
            cap_expiry: DEFAULT_CAP_EXPIRY,
            endpoint: endpoint.clone(),
            name: None,
            metrics_interval: Some(Duration::from_secs(60)),
            remote: None,
            registry,
        }
    }

    /// Register a metrics group to forward to iroh-services
    ///
    /// The default registered metrics uses only the endpoint
    pub fn register_metrics_group(mut self, metrics_group: Arc<dyn MetricsGroup>) -> Self {
        self.registry.register(metrics_group);
        self
    }

    /// Set the metrics collection interval
    ///
    /// Defaults to enabled, every 60 seconds.
    pub fn metrics_interval(mut self, interval: Duration) -> Self {
        self.metrics_interval = Some(interval);
        self
    }

    /// Disable metrics collection.
    pub fn disable_metrics_interval(mut self) -> Self {
        self.metrics_interval = None;
        self
    }

    /// Set an optional human-readable name for this endpoint.
    ///
    /// When set, this name is sent as part of authentication and associated
    /// with the endpoint on the server, making metrics from this endpoint
    /// easier to identify in monitoring dashboards.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Check IROH_SERVICES_API_SECRET environment variable for a valid API secret
    pub fn api_secret_from_env(self) -> Result<Self> {
        let ticket = ApiSecret::from_env_var(API_SECRET_ENV_VAR_NAME)?;
        self.api_secret(ticket)
    }

    /// set client API secret from an encoded string
    pub fn api_secret_from_str(self, secret_key: &str) -> Result<Self> {
        let key = ApiSecret::from_str(secret_key).context("invalid iroh services api secret")?;
        self.api_secret(key)
    }

    /// Use a shared secret & remote iroh-services endpoint ID contained within a ticket
    /// to construct a iroh-services client. The resulting client will have "Client"
    /// capabilities.
    ///
    /// API secrets include remote details within them, and will set both the
    /// remote and rcan values on the builder
    pub fn api_secret(mut self, ticket: ApiSecret) -> Result<Self> {
        let local_id = self.endpoint.id();
        let rcan = crate::caps::create_api_token_from_secret_key(
            ticket.secret,
            local_id,
            self.cap_expiry,
            Caps::for_shared_secret(),
        )?;

        self.remote = Some(ticket.remote);
        self.rcan(rcan)
    }

    /// Loads the private ssh key from the given path, and creates the needed capability.
    #[cfg(feature = "ssh-key")]
    pub async fn ssh_key_from_file<P: AsRef<std::path::Path>>(self, path: P) -> Result<Self> {
        let file_content = tokio::fs::read_to_string(path).await?;
        let private_key = ssh_key::PrivateKey::from_openssh(&file_content)?;

        self.ssh_key(&private_key)
    }

    /// Creates the capability from the provided private ssh key.
    #[cfg(feature = "ssh-key")]
    pub fn ssh_key(mut self, key: &ssh_key::PrivateKey) -> Result<Self> {
        let local_id = self.endpoint.id();
        let rcan = crate::caps::create_api_token_from_ssh_key(
            key,
            local_id,
            self.cap_expiry,
            Caps::all(),
        )?;
        self.cap.replace(rcan);

        Ok(self)
    }

    /// Sets the rcan directly.
    pub fn rcan(mut self, cap: Rcan<Caps>) -> Result<Self> {
        ensure!(
            EndpointId::from_verifying_key(*cap.audience()) == self.endpoint.id(),
            "invalid audience"
        );
        self.cap.replace(cap);
        Ok(self)
    }

    /// Sets the remote to dial, must be provided either directly by calling
    /// this method, or through calling the api_secret builder methods.
    pub fn remote(mut self, remote: impl Into<EndpointAddr>) -> Self {
        self.remote = Some(remote.into());
        self
    }

    /// Create a new client, connected to the provide service node
    #[must_use = "dropping the client will silently cancel all client tasks"]
    pub async fn build(self) -> Result<Client, BuildError> {
        debug!("starting iroh-services client");
        let remote = self.remote.ok_or(BuildError::MissingRemote)?;
        let capabilities = self.cap.ok_or(BuildError::MissingCapability)?;

        let conn = IrohLazyRemoteConnection::new(self.endpoint.clone(), remote, ALPN.to_vec());
        let client = IrohServicesClient::boxed(conn);

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let metrics_task = AbortOnDropHandle::new(n0_future::task::spawn(
            ClientActor {
                capabilities,
                client,
                name: self.name,
                session_id: Uuid::new_v4(),
                authorized: false,
            }
            .run(self.registry, self.metrics_interval, rx),
        ));

        Ok(Client {
            endpoint: self.endpoint,
            message_channel: tx,
            _actor_task: Arc::new(metrics_task),
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BuildError {
    #[error("Missing remote endpoint to dial")]
    MissingRemote,
    #[error("Missing capability")]
    MissingCapability,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Remote error: {0}")]
    Remote(#[from] RemoteError),
    #[error("Rpc connection error: {0}")]
    Rpc(irpc::Error),
    #[error("Connection error: {0}")]
    Connect(ConnectError),
}

impl From<irpc::Error> for BuildError {
    fn from(value: irpc::Error) -> Self {
        match value {
            irpc::Error::Request {
                source:
                    irpc::RequestError::Connection {
                        source: iroh::endpoint::ConnectionError::ApplicationClosed(frame),
                        ..
                    },
                ..
            } if frame.error_code == 401u32.into() => Self::Unauthorized,
            value => Self::Rpc(value),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Remote error: {0}")]
    Remote(#[from] RemoteError),
    #[error("Connection error: {0}")]
    Rpc(#[from] irpc::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Client {
    pub fn builder(endpoint: &Endpoint) -> ClientBuilder {
        ClientBuilder::new(endpoint)
    }

    /// Pings the remote node.
    pub async fn ping(&self) -> Result<Pong, Error> {
        let (tx, rx) = oneshot::channel();
        self.message_channel
            .send(ClientActorMessage::Ping { done: tx })
            .await
            .map_err(|_| Error::Other(anyhow!("sending ping request")))?;

        rx.await
            .map_err(|e| Error::Other(anyhow!("response on internal channel: {:?}", e)))?
            .map_err(Error::Remote)
    }

    /// immediately send a single dump of metrics to iroh-services. It's not necessary
    /// to call this function if you're using a non-zero metrics interval,
    /// which will automatically propagate metrics on the set interval for you
    pub async fn push_metrics(&self) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.message_channel
            .send(ClientActorMessage::SendMetrics { done: tx })
            .await
            .map_err(|_| Error::Other(anyhow!("sending metrics")))?;

        rx.await
            .map_err(|e| Error::Other(anyhow!("response on internal channel: {:?}", e)))?
            .map_err(Error::Remote)
    }

    /// Grant capabilities to a remote endpoint. Creates a signed RCAN token
    /// and sends it to iroh-services for storage. The remote can then use this token
    /// when dialing back to authorize its requests.
    #[cfg(feature = "client_host")]
    pub async fn grant_capability(
        &self,
        remote_id: EndpointId,
        caps: impl IntoIterator<Item = impl Into<crate::caps::Cap>>,
    ) -> Result<(), Error> {
        let cap = crate::caps::create_grant_token(
            self.endpoint.secret_key().clone(),
            remote_id,
            DEFAULT_CAP_EXPIRY,
            Caps::new(caps),
        )
        .map_err(Error::Other)?;

        let (tx, rx) = oneshot::channel();
        self.message_channel
            .send(ClientActorMessage::GrantCap {
                cap: Box::new(cap),
                done: tx,
            })
            .await
            .map_err(|_| Error::Other(anyhow!("granting capability")))?;

        rx.await
            .map_err(|e| Error::Other(anyhow!("response on internal channel: {:?}", e)))?
    }

    /// run local network status diagnostics, optionally uploading the results
    #[cfg(feature = "net_diagnostics")]
    pub async fn net_diagnostics(&self, send: bool) -> Result<DiagnosticsReport, Error> {
        let report = run_diagnostics(&self.endpoint).await?;
        if send {
            let (tx, rx) = oneshot::channel();
            self.message_channel
                .send(ClientActorMessage::PutNetworkDiagnostics {
                    done: tx,
                    report: Box::new(report.clone()),
                })
                .await
                .map_err(|_| Error::Other(anyhow!("sending network diagnostics report")))?;

            let _ = rx
                .await
                .map_err(|e| Error::Other(anyhow!("response on internal channel: {:?}", e)))?;
        }

        Ok(report)
    }
}

enum ClientActorMessage {
    SendMetrics {
        done: oneshot::Sender<Result<(), RemoteError>>,
    },
    Ping {
        done: oneshot::Sender<Result<Pong, RemoteError>>,
    },
    // GrantCap is used by the `client_host` feature flag
    #[allow(dead_code)]
    GrantCap {
        // boxed to avoid large enum variants
        cap: Box<Rcan<Caps>>,
        done: oneshot::Sender<Result<(), Error>>,
    },
    #[cfg(feature = "net_diagnostics")]
    PutNetworkDiagnostics {
        report: Box<DiagnosticsReport>,
        done: oneshot::Sender<Result<(), Error>>,
    },
}

struct ClientActor {
    capabilities: Rcan<Caps>,
    client: IrohServicesClient,
    name: Option<String>,
    session_id: Uuid,
    authorized: bool,
}

impl ClientActor {
    async fn run(
        mut self,
        registry: Registry,
        interval: Option<Duration>,
        mut inbox: tokio::sync::mpsc::Receiver<ClientActorMessage>,
    ) {
        let registry = Arc::new(RwLock::new(registry));
        let mut encoder = Encoder::new(registry);
        let mut metrics_timer = interval.map(|interval| n0_future::time::interval(interval));
        trace!("starting client actor");
        loop {
            trace!("client actor tick");
            tokio::select! {
                biased;
                Some(msg) = inbox.recv() => {
                    match msg {
                        ClientActorMessage::Ping{ done } => {
                            let res = self.send_ping().await;
                            if let Err(err) = done.send(res) {
                                debug!("failed to send ping: {:#?}", err);
                                self.authorized = false;
                            }
                        },
                        ClientActorMessage::SendMetrics{ done } => {
                            trace!("sending metrics manually triggered");
                            let res = self.send_metrics(&mut encoder).await;
                            if let Err(err) = done.send(res) {
                                debug!("failed to push metrics: {:#?}", err);
                                self.authorized = false;
                            }
                        }
                        ClientActorMessage::GrantCap{ cap, done } => {
                            let res = self.grant_cap(*cap).await;
                            if let Err(err) = done.send(res) {
                                warn!("failed to grant capability: {:#?}", err);
                            }
                        }
                        #[cfg(feature = "net_diagnostics")]
                        ClientActorMessage::PutNetworkDiagnostics{ report, done } => {
                            let res = self.put_network_diagnostics(*report).await;
                            if let Err(err) = done.send(res) {
                                warn!("failed to publish network diagnostics: {:#?}", err);
                            }
                        }
                    }
                }
                _ = async {
                    if let Some(ref mut timer) = metrics_timer {
                        timer.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    trace!("metrics send tick");
                    if let Err(err) = self.send_metrics(&mut encoder).await {
                        debug!("failed to push metrics: {:#?}", err);
                        self.authorized = false;
                    }
                },
            }
        }
    }

    // sends an authorization request to the server
    async fn auth(&mut self) -> Result<(), RemoteError> {
        if self.authorized {
            return Ok(());
        }
        trace!("client authorizing");
        self.client
            .rpc(Auth {
                caps: self.capabilities.clone(),
                name: self.name.clone(),
            })
            .await
            .inspect_err(|e| debug!("authorization failed: {:?}", e))
            .map_err(|e| RemoteError::AuthError(e.to_string()))?;
        self.authorized = true;
        Ok(())
    }

    async fn send_ping(&mut self) -> Result<Pong, RemoteError> {
        trace!("client actor send ping");
        self.auth().await?;

        let req = rand::random();
        self.client
            .rpc(Ping { req_id: req })
            .await
            .inspect_err(|e| warn!("rpc ping error: {e}"))
            .map_err(|_| RemoteError::InternalServerError)
    }

    async fn send_metrics(&mut self, encoder: &mut Encoder) -> Result<(), RemoteError> {
        trace!("client actor send metrics");
        self.auth().await?;

        let update = encoder.export();
        // let delta = update_delta(&self.latest_ackd_update, &update);
        let req = PutMetrics {
            session_id: self.session_id,
            update,
        };

        self.client
            .rpc(req)
            .await
            .map_err(|_| RemoteError::InternalServerError)??;

        Ok(())
    }

    async fn grant_cap(&mut self, cap: Rcan<Caps>) -> Result<(), Error> {
        trace!("client actor grant capability");
        self.auth().await?;

        self.client
            .rpc(crate::protocol::GrantCap { cap })
            .await
            .map_err(|_| RemoteError::InternalServerError)??;

        Ok(())
    }

    #[cfg(feature = "net_diagnostics")]
    async fn put_network_diagnostics(
        &mut self,
        report: crate::net_diagnostics::DiagnosticsReport,
    ) -> Result<(), Error> {
        trace!("client actor publish network diagnostics");
        self.auth().await?;

        let req = PutNetworkDiagnostics { report };

        self.client
            .rpc(req)
            .await
            .map_err(|_| RemoteError::InternalServerError)??;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use iroh::{Endpoint, EndpointAddr, SecretKey};
    use temp_env_vars::temp_env_vars;

    use crate::{
        Client,
        api_secret::ApiSecret,
        caps::{Cap, Caps},
        client::API_SECRET_ENV_VAR_NAME,
    };

    #[tokio::test]
    #[temp_env_vars]
    async fn test_api_key_from_env() {
        // construct
        let mut rng = rand::rng();
        let shared_secret = SecretKey::generate(&mut rng);
        let fake_endpoint_id = SecretKey::generate(&mut rng).public();
        let api_secret = ApiSecret::new(shared_secret.clone(), fake_endpoint_id);
        unsafe {
            std::env::set_var(API_SECRET_ENV_VAR_NAME, api_secret.to_string());
        };

        let endpoint = Endpoint::empty_builder().bind().await.unwrap();

        let builder = Client::builder(&endpoint).api_secret_from_env().unwrap();

        let fake_endpoint_addr: EndpointAddr = fake_endpoint_id.into();
        assert_eq!(builder.remote, Some(fake_endpoint_addr));

        // Compare capability fields individually to avoid flaky timestamp
        // mismatches between the builder's rcan and a freshly-created one.
        let cap = builder.cap.as_ref().expect("expected capability to be set");
        assert_eq!(cap.capability(), &Caps::new([Cap::Client]));
        assert_eq!(cap.audience(), &endpoint.id().as_verifying_key());
        assert_eq!(cap.issuer(), &shared_secret.public().as_verifying_key());
    }

    /// Assert that disabling metrics interval can manually send metrics without
    /// panicking. Metrics sending itself is expected to fail.
    #[tokio::test]
    async fn test_no_metrics_interval() {
        let mut rng = rand::rng();
        let shared_secret = SecretKey::generate(&mut rng);
        let fake_endpoint_id = SecretKey::generate(&mut rng).public();
        let api_secret = ApiSecret::new(shared_secret.clone(), fake_endpoint_id);

        let endpoint = Endpoint::empty_builder().bind().await.unwrap();

        let client = Client::builder(&endpoint)
            .disable_metrics_interval()
            .api_secret(api_secret)
            .unwrap()
            .build()
            .await
            .unwrap();

        let err = client.push_metrics().await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_name() {
        let mut rng = rand::rng();
        let shared_secret = SecretKey::generate(&mut rng);
        let fake_endpoint_id = SecretKey::generate(&mut rng).public();
        let api_secret = ApiSecret::new(shared_secret.clone(), fake_endpoint_id);

        let endpoint = Endpoint::empty_builder().bind().await.unwrap();

        let builder = Client::builder(&endpoint)
            .name("my-node")
            .api_secret(api_secret)
            .unwrap();

        assert_eq!(builder.name, Some("my-node".to_string()));
    }
}

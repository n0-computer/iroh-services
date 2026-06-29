use std::{
    collections::BTreeMap,
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

use crate::{
    api_secret::{API_SECRET_ENV_VAR_NAME, ApiSecret},
    caps::{Caps, DEFAULT_CAP_EXPIRY},
    net_diagnostics::{DiagnosticsReport, checks::run_diagnostics},
    protocol::{
        ALPN, Auth, IrohServicesClient, NameEndpoint, Ping, Pong, PutMetrics,
        PutNetworkDiagnostics, RemoteError, SetAttributes, SetGroup,
    },
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
    group: Option<String>,
    attributes: Option<BTreeMap<String, String>>,
    metrics_interval: Option<Duration>,
    remote: Option<EndpointAddr>,
    registry: Registry,
}

impl ClientBuilder {
    pub fn new(endpoint: &Endpoint) -> Self {
        let mut registry = Registry::default();
        registry.register_all(endpoint.metrics());

        Self {
            cap: None,
            cap_expiry: DEFAULT_CAP_EXPIRY,
            endpoint: endpoint.clone(),
            name: None,
            group: None,
            attributes: None,
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

    /// Set an optional human-readable name for the endpoint the client is
    /// constructed with, making metrics from this endpoint easier to identify.
    /// This is often used for associating with other services in your app,
    /// like a database user id, machine name, permanent username, etc.
    ///
    /// When this builder method is called, the provided name is sent after the
    /// client initially authenticates the endpoint server-side.
    /// Errors will not interrupt client construction, instead producing a
    /// warn-level log. For explicit error handling, use [`Client::set_name`].
    ///
    /// names can be any UTF-8 string, with a min length of 2 bytes, and
    /// maximum length of 128 bytes. **name uniqueness is not enforced
    /// server-side**, which means using the same name for different endpoints
    /// will not produce an error
    pub fn name(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_name(&name).map_err(BuildError::InvalidName)?;
        self.name = Some(name);
        Ok(self)
    }

    /// Attach the endpoint to a single named group when the client first
    /// authenticates. Group names follow the same rules as endpoint names
    /// (2–128 bytes UTF-8). Errors during startup propagate as warn-level
    /// logs; for explicit error handling use [`Client::set_group`].
    pub fn group(mut self, group: impl Into<String>) -> Result<Self> {
        let group = group.into();
        validate_name(&group).map_err(BuildError::InvalidGroup)?;
        self.group = Some(group);
        Ok(self)
    }

    /// Attach arbitrary key-value attributes to the endpoint when the client
    /// first authenticates. Accepts any iterable of `(key, value)` pairs:
    ///
    /// ```no_run
    /// # use iroh::{Endpoint, endpoint::presets};
    /// # use iroh_services::Client;
    /// # async fn example(endpoint: &Endpoint) -> anyhow::Result<()> {
    /// let _ = Client::builder(endpoint).attributes([("env", "prod"), ("region", "us-west")])?;
    /// # Ok(()) }
    /// ```
    ///
    /// Keys follow the same length rules as endpoint names (2–128 bytes);
    /// values may be empty and are capped at 128 bytes; the map is limited
    /// to 128 entries. Errors during startup propagate as warn-level logs;
    /// for explicit error handling use [`Client::set_attributes`].
    pub fn attributes<I, K, V>(mut self, attrs: I) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let collected: BTreeMap<String, String> = attrs
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        validate_attributes(&collected).map_err(BuildError::InvalidAttributes)?;
        self.attributes = Some(collected);
        Ok(self)
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
    ///
    /// The file must contain an unencrypted PEM-encoded OpenSSH ed25519 private key.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn ssh_key_from_file<P: AsRef<std::path::Path>>(self, path: P) -> Result<Self> {
        let file_content = tokio::fs::read_to_string(path).await?;
        self.ssh_key(&file_content)
    }

    /// Creates the capability from the provided PEM-encoded OpenSSH ed25519 private key.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn ssh_key(mut self, pem: &str) -> Result<Self> {
        let local_id = self.endpoint.id();
        let rcan = crate::caps::create_api_token_from_openssh_pem(
            pem,
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
        let irpc_client = IrohServicesClient::boxed(conn);

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let actor_task = AbortOnDropHandle::new(n0_future::task::spawn(
            ClientActor {
                capabilities,
                client: irpc_client,
                name: self.name.clone(),
                group: self.group.clone(),
                attributes: self.attributes.clone().unwrap_or_default(),
                session_id: Uuid::new_v4(),
                authorized: false,
            }
            .run(
                self.name,
                self.group,
                self.attributes,
                self.registry,
                self.metrics_interval,
                rx,
            ),
        ));

        Ok(Client {
            endpoint: self.endpoint,
            message_channel: tx,
            _actor_task: Arc::new(actor_task),
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
    #[error("Invalid endpoint name: {0}")]
    InvalidName(#[from] ValidateNameError),
    #[error("Invalid endpoint group: {0}")]
    InvalidGroup(ValidateNameError),
    #[error("Invalid endpoint attributes: {0}")]
    InvalidAttributes(#[from] ValidateAttributesError),
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

/// Minimum length in bytes for an endpoint name.
pub const CLIENT_NAME_MIN_LENGTH: usize = 2;
/// Maximum length in bytes for an endpoint name.
pub const CLIENT_NAME_MAX_LENGTH: usize = 128;

/// Error returned when an endpoint name fails validation.
#[derive(Debug, thiserror::Error)]
pub enum ValidateNameError {
    #[error("Name is too long (must be no more than {CLIENT_NAME_MAX_LENGTH} characters).")]
    TooLong,
    #[error("Name is too short (must be at least {CLIENT_NAME_MIN_LENGTH} characters).")]
    TooShort,
}

fn validate_name(name: &str) -> Result<(), ValidateNameError> {
    if name.len() < CLIENT_NAME_MIN_LENGTH {
        Err(ValidateNameError::TooShort)
    } else if name.len() > CLIENT_NAME_MAX_LENGTH {
        Err(ValidateNameError::TooLong)
    } else {
        Ok(())
    }
}

/// Maximum length in bytes for an attribute value. Values may be empty.
pub const CLIENT_ATTRIBUTE_VALUE_MAX_LENGTH: usize = 128;
/// Maximum number of entries allowed in the attributes map.
pub const CLIENT_ATTRIBUTES_MAX_COUNT: usize = 128;

/// Error returned when an attributes map fails validation.
#[derive(Debug, thiserror::Error)]
pub enum ValidateAttributesError {
    #[error("Too many attributes (must be no more than {CLIENT_ATTRIBUTES_MAX_COUNT}).")]
    TooManyEntries,
    #[error("Invalid attribute key: {0}")]
    InvalidKey(#[from] ValidateNameError),
    #[error(
        "Attribute value too long (must be no more than {CLIENT_ATTRIBUTE_VALUE_MAX_LENGTH} bytes)."
    )]
    ValueTooLong,
}

fn validate_attributes(attrs: &BTreeMap<String, String>) -> Result<(), ValidateAttributesError> {
    if attrs.len() > CLIENT_ATTRIBUTES_MAX_COUNT {
        return Err(ValidateAttributesError::TooManyEntries);
    }
    for (k, v) in attrs {
        validate_name(k)?;
        if v.len() > CLIENT_ATTRIBUTE_VALUE_MAX_LENGTH {
            return Err(ValidateAttributesError::ValueTooLong);
        }
    }
    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid endpoint name: {0}")]
    InvalidName(#[from] ValidateNameError),
    #[error("Invalid endpoint group: {0}")]
    InvalidGroup(ValidateNameError),
    #[error("Invalid endpoint attributes: {0}")]
    InvalidAttributes(#[from] ValidateAttributesError),
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

    /// Read the current endpoint name from the local client.
    pub async fn name(&self) -> Result<Option<String>, Error> {
        let (tx, rx) = oneshot::channel();
        self.message_channel
            .send(ClientActorMessage::ReadName { done: tx })
            .await
            .map_err(|_| Error::Other(anyhow!("sending name read request")))?;

        rx.await
            .map_err(|e| Error::Other(anyhow!("response on internal channel: {:?}", e)))
    }

    /// Name the active endpoint cloud-side.
    ///
    /// names can be any UTF-8 string, with a min length of 2 bytes, and
    /// maximum length of 128 bytes. **name uniqueness is not enforced.**
    pub async fn set_name(&self, name: impl Into<String>) -> Result<(), Error> {
        set_name_inner(self.message_channel.clone(), name.into()).await
    }

    /// Attach the active endpoint to a single named group cloud-side.
    ///
    /// Group names follow the same rules as endpoint names: any UTF-8 string,
    /// minimum 2 bytes, maximum 128 bytes. **group uniqueness is not enforced.**
    pub async fn set_group(&self, group: impl Into<String>) -> Result<(), Error> {
        set_group_inner(self.message_channel.clone(), group.into()).await
    }

    /// Replace the arbitrary key-value attributes on the active endpoint cloud-side.
    ///
    /// Accepts any iterable of `(key, value)` pairs (arrays of tuples, `Vec`s,
    /// `HashMap`s, `BTreeMap`s, etc.), so most calls fit on a single line:
    ///
    /// ```no_run
    /// # use iroh_services::Client;
    /// # async fn example(client: Client) -> anyhow::Result<()> {
    /// client
    ///     .set_attributes([("env", "prod"), ("region", "us-west")])
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// Keys follow the same rules as endpoint names (2–128 bytes). Values may
    /// be empty and are limited to 128 bytes. The map is limited to 128
    /// entries. Each call fully replaces the prior set; passing an empty
    /// iterator clears all attributes.
    pub async fn set_attributes<I, K, V>(&self, attrs: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let collected: BTreeMap<String, String> = attrs
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        set_attributes_inner(self.message_channel.clone(), collected).await
    }

    /// Set (or replace) a single attribute, merging it into the endpoint's
    /// existing attributes rather than replacing the whole set. Insertion
    /// order is preserved — re-setting an existing key keeps its position.
    /// Convenience over [`set_attributes`](Self::set_attributes) when you only
    /// need to change one value.
    ///
    /// The key follows endpoint-name rules (2–128 bytes) and the value is
    /// limited to 128 bytes.
    pub async fn set_attribute(
        &self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), Error> {
        set_attribute_inner(self.message_channel.clone(), key.into(), value.into()).await
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
    PutNetworkDiagnostics {
        report: Box<DiagnosticsReport>,
        done: oneshot::Sender<Result<(), Error>>,
    },
    ReadName {
        done: oneshot::Sender<Option<String>>,
    },
    NameEndpoint {
        name: String,
        done: oneshot::Sender<Result<(), RemoteError>>,
    },
    SetGroup {
        group: String,
        done: oneshot::Sender<Result<(), RemoteError>>,
    },
    SetAttributes {
        attributes: BTreeMap<String, String>,
        done: oneshot::Sender<Result<(), RemoteError>>,
    },
    SetAttribute {
        key: String,
        value: String,
        done: oneshot::Sender<Result<(), RemoteError>>,
    },
}

struct ClientActor {
    capabilities: Rcan<Caps>,
    client: IrohServicesClient,
    name: Option<String>,
    group: Option<String>,
    attributes: BTreeMap<String, String>,
    session_id: Uuid,
    authorized: bool,
}

impl ClientActor {
    async fn run(
        mut self,
        initial_name: Option<String>,
        initial_group: Option<String>,
        initial_attributes: Option<BTreeMap<String, String>>,
        registry: Registry,
        interval: Option<Duration>,
        mut inbox: tokio::sync::mpsc::Receiver<ClientActorMessage>,
    ) {
        let registry = Arc::new(RwLock::new(registry));
        let mut encoder = Encoder::new(registry);
        let mut metrics_timer = interval.map(|interval| n0_future::time::interval(interval));
        trace!("starting client actor");

        if let Some(name) = initial_name
            && let Err(err) = self.send_name_endpoint(name).await
        {
            warn!(err = %err, "failed setting endpoint name on startup");
        }

        if let Some(group) = initial_group
            && let Err(err) = self.send_set_group(group).await
        {
            warn!(err = %err, "failed setting endpoint group on startup");
        }

        if let Some(attributes) = initial_attributes
            && let Err(err) = self.send_set_attributes(attributes).await
        {
            warn!(err = %err, "failed setting endpoint attributes on startup");
        }

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
                        ClientActorMessage::ReadName{ done } => {
                            if let Err(err) = done.send(self.name.clone()) {
                                warn!("sending name value: {:#?}", err);
                            }
                        }
                        ClientActorMessage::NameEndpoint{ name, done } => {
                            let res = self.send_name_endpoint(name).await;
                            if let Err(err) = done.send(res) {
                                warn!("failed to name endpoint: {:#?}", err);
                            }
                        }
                        ClientActorMessage::SetGroup{ group, done } => {
                            let res = self.send_set_group(group).await;
                            if let Err(err) = done.send(res) {
                                warn!("failed to set group: {:#?}", err);
                            }
                        }
                        ClientActorMessage::SetAttributes{ attributes, done } => {
                            let res = self.send_set_attributes(attributes).await;
                            if let Err(err) = done.send(res) {
                                warn!("failed to set attributes: {:#?}", err);
                            }
                        }
                        ClientActorMessage::SetAttribute{ key, value, done } => {
                            // Merge into the current set, preserving insertion
                            // order (re-setting an existing key keeps its slot).
                            let mut merged = self.attributes.clone();
                            merged.insert(key, value);
                            let res = self.send_set_attributes(merged).await;
                            if let Err(err) = done.send(res) {
                                warn!("failed to set attribute: {:#?}", err);
                            }
                        }
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

    async fn send_name_endpoint(&mut self, name: String) -> Result<(), RemoteError> {
        trace!("client sending name endpoint request");
        self.auth().await?;

        self.client
            .rpc(NameEndpoint { name: name.clone() })
            .await
            .inspect_err(|e| debug!("name endpoint error: {e}"))
            .map_err(|_| RemoteError::InternalServerError)??;
        self.name = Some(name);
        Ok(())
    }

    async fn send_set_group(&mut self, group: String) -> Result<(), RemoteError> {
        trace!("client sending set group request");
        self.auth().await?;

        self.client
            .rpc(SetGroup {
                group: group.clone(),
            })
            .await
            .inspect_err(|e| debug!("set group error: {e}"))
            .map_err(|_| RemoteError::InternalServerError)??;
        self.group = Some(group);
        Ok(())
    }

    async fn send_set_attributes(
        &mut self,
        attributes: BTreeMap<String, String>,
    ) -> Result<(), RemoteError> {
        trace!("client sending set attributes request");
        self.auth().await?;

        self.client
            .rpc(SetAttributes {
                attributes: attributes.clone(),
            })
            .await
            .inspect_err(|e| debug!("set attributes error: {e}"))
            .map_err(|_| RemoteError::InternalServerError)??;
        self.attributes = attributes;
        Ok(())
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

async fn set_name_inner(
    message_channel: tokio::sync::mpsc::Sender<ClientActorMessage>,
    name: String,
) -> Result<(), Error> {
    validate_name(&name)?;
    debug!(name_len = name.len(), "calling set name");
    let (tx, rx) = oneshot::channel();
    message_channel
        .send(ClientActorMessage::NameEndpoint { name, done: tx })
        .await
        .map_err(|_| Error::Other(anyhow!("sending name endpoint request")))?;
    rx.await
        .map_err(|e| Error::Other(anyhow!("response on internal channel: {:?}", e)))?
        .map_err(Error::Remote)
}

async fn set_group_inner(
    message_channel: tokio::sync::mpsc::Sender<ClientActorMessage>,
    group: String,
) -> Result<(), Error> {
    validate_name(&group).map_err(Error::InvalidGroup)?;
    debug!(group_len = group.len(), "calling set group");
    let (tx, rx) = oneshot::channel();
    message_channel
        .send(ClientActorMessage::SetGroup { group, done: tx })
        .await
        .map_err(|_| Error::Other(anyhow!("sending set group request")))?;
    rx.await
        .map_err(|e| Error::Other(anyhow!("response on internal channel: {:?}", e)))?
        .map_err(Error::Remote)
}

async fn set_attributes_inner(
    message_channel: tokio::sync::mpsc::Sender<ClientActorMessage>,
    attributes: BTreeMap<String, String>,
) -> Result<(), Error> {
    validate_attributes(&attributes)?;
    debug!(attr_count = attributes.len(), "calling set attributes");
    let (tx, rx) = oneshot::channel();
    message_channel
        .send(ClientActorMessage::SetAttributes {
            attributes,
            done: tx,
        })
        .await
        .map_err(|_| Error::Other(anyhow!("sending set attributes request")))?;
    rx.await
        .map_err(|e| Error::Other(anyhow!("response on internal channel: {:?}", e)))?
        .map_err(Error::Remote)
}

async fn set_attribute_inner(
    message_channel: tokio::sync::mpsc::Sender<ClientActorMessage>,
    key: String,
    value: String,
) -> Result<(), Error> {
    // Validate the single entry the same way the full map is validated (key is
    // name-shaped, value within the size limit). The merged-total count is
    // enforced server-side.
    let mut one = BTreeMap::new();
    one.insert(key.clone(), value.clone());
    validate_attributes(&one)?;
    let (tx, rx) = oneshot::channel();
    message_channel
        .send(ClientActorMessage::SetAttribute {
            key,
            value,
            done: tx,
        })
        .await
        .map_err(|_| Error::Other(anyhow!("sending set attribute request")))?;
    rx.await
        .map_err(|e| Error::Other(anyhow!("response on internal channel: {:?}", e)))?
        .map_err(Error::Remote)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use iroh::{Endpoint, EndpointAddr, SecretKey, endpoint::presets};
    use rand::{RngExt, SeedableRng};
    use temp_env_vars::temp_env_vars;

    use crate::{
        Client,
        api_secret::ApiSecret,
        caps::{Cap, Caps},
        client::{
            API_SECRET_ENV_VAR_NAME, BuildError, CLIENT_ATTRIBUTE_VALUE_MAX_LENGTH,
            CLIENT_ATTRIBUTES_MAX_COUNT, CLIENT_NAME_MAX_LENGTH, Error, ValidateAttributesError,
            ValidateNameError,
        },
    };

    #[tokio::test]
    #[temp_env_vars]
    async fn test_api_key_from_env() {
        // construct
        let mut rng = rand::rngs::ChaCha8Rng::seed_from_u64(0);
        let shared_secret = SecretKey::from_bytes(&rng.random());
        let fake_endpoint_id = SecretKey::from_bytes(&rng.random()).public();
        let api_secret = ApiSecret::new(shared_secret.clone(), fake_endpoint_id);
        unsafe {
            std::env::set_var(API_SECRET_ENV_VAR_NAME, api_secret.to_string());
        };

        let endpoint = Endpoint::builder(presets::Minimal).bind().await.unwrap();

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
        let mut rng = rand::rngs::ChaCha8Rng::seed_from_u64(1);
        let shared_secret = SecretKey::from_bytes(&rng.random());
        let fake_endpoint_id = SecretKey::from_bytes(&rng.random()).public();
        let api_secret = ApiSecret::new(shared_secret.clone(), fake_endpoint_id);

        let endpoint = Endpoint::builder(presets::Minimal).bind().await.unwrap();

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
        let mut rng = rand::rngs::ChaCha8Rng::seed_from_u64(0);
        let shared_secret = SecretKey::from_bytes(&rng.random());
        let fake_endpoint_id = SecretKey::from_bytes(&rng.random()).public();
        let api_secret = ApiSecret::new(shared_secret.clone(), fake_endpoint_id);

        let endpoint = Endpoint::builder(presets::Minimal).bind().await.unwrap();

        let builder = Client::builder(&endpoint)
            .name("my-node 👋")
            .unwrap()
            .api_secret(api_secret)
            .unwrap();

        assert_eq!(builder.name, Some("my-node 👋".to_string()));

        let Err(err) = Client::builder(&endpoint).name("a") else {
            panic!("name should fail for strings under 2 bytes");
        };
        assert!(matches!(
            err.downcast_ref::<BuildError>(),
            Some(BuildError::InvalidName(ValidateNameError::TooShort))
        ));

        let too_long_name = "👋".repeat(129);
        let Err(err) = Client::builder(&endpoint).name(&too_long_name) else {
            panic!("name should fail for strings over 128 bytes");
        };
        assert!(matches!(
            err.downcast_ref::<BuildError>(),
            Some(BuildError::InvalidName(ValidateNameError::TooLong))
        ));
    }

    #[tokio::test]
    async fn test_group() {
        let mut rng = rand::rngs::ChaCha8Rng::seed_from_u64(0);
        let shared_secret = SecretKey::from_bytes(&rng.random());
        let fake_endpoint_id = SecretKey::from_bytes(&rng.random()).public();
        let api_secret = ApiSecret::new(shared_secret.clone(), fake_endpoint_id);

        let endpoint = Endpoint::builder(presets::Minimal).bind().await.unwrap();

        let builder = Client::builder(&endpoint)
            .group("staging")
            .unwrap()
            .api_secret(api_secret)
            .unwrap();

        assert_eq!(builder.group, Some("staging".to_string()));

        let Err(err) = Client::builder(&endpoint).group("a") else {
            panic!("group should fail for strings under 2 bytes");
        };
        assert!(matches!(
            err.downcast_ref::<BuildError>(),
            Some(BuildError::InvalidGroup(ValidateNameError::TooShort))
        ));

        let too_long_group = "👋".repeat(129);
        let Err(err) = Client::builder(&endpoint).group(&too_long_group) else {
            panic!("group should fail for strings over 128 bytes");
        };
        assert!(matches!(
            err.downcast_ref::<BuildError>(),
            Some(BuildError::InvalidGroup(ValidateNameError::TooLong))
        ));
    }

    #[tokio::test]
    async fn test_attributes() {
        let endpoint = Endpoint::builder(presets::Minimal).bind().await.unwrap();

        // empty iterator is accepted (clears attributes server-side)
        let builder = Client::builder(&endpoint)
            .attributes(std::iter::empty::<(String, String)>())
            .unwrap();
        assert_eq!(builder.attributes.as_ref().map(|m| m.len()), Some(0));

        // array literal of `&str` tuples — the one-liner ergonomics
        let builder = Client::builder(&endpoint)
            .attributes([("env", "prod"), ("region", "us-west")])
            .unwrap();
        let attrs = builder.attributes.as_ref().expect("attributes set");
        assert_eq!(attrs.get("env").map(String::as_str), Some("prod"));
        assert_eq!(attrs.get("region").map(String::as_str), Some("us-west"));

        // HashMap<String, String> also works
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("k1".into(), "v1".into());
        map.insert("k2".into(), "".into()); // empty value is allowed
        let builder = Client::builder(&endpoint).attributes(map).unwrap();
        let attrs = builder.attributes.as_ref().expect("attributes set");
        assert_eq!(attrs.get("k2").map(String::as_str), Some(""));

        // value over 128 bytes errors
        let too_long_value = "x".repeat(129);
        let Err(err) = Client::builder(&endpoint).attributes([("ok", too_long_value.as_str())])
        else {
            panic!("attributes should fail for value over 128 bytes");
        };
        assert!(matches!(
            err.downcast_ref::<BuildError>(),
            Some(BuildError::InvalidAttributes(
                ValidateAttributesError::ValueTooLong
            ))
        ));

        // key under 2 bytes errors
        let Err(err) = Client::builder(&endpoint).attributes([("a", "v")]) else {
            panic!("attributes should fail for key under 2 bytes");
        };
        assert!(matches!(
            err.downcast_ref::<BuildError>(),
            Some(BuildError::InvalidAttributes(
                ValidateAttributesError::InvalidKey(ValidateNameError::TooShort)
            ))
        ));

        // more than 128 entries errors
        let big: Vec<(String, String)> = (0..(CLIENT_ATTRIBUTES_MAX_COUNT + 1))
            .map(|i| (format!("key_{i:04}"), format!("val_{i}")))
            .collect();
        let Err(err) = Client::builder(&endpoint).attributes(big) else {
            panic!("attributes should fail for more than 128 entries");
        };
        assert!(matches!(
            err.downcast_ref::<BuildError>(),
            Some(BuildError::InvalidAttributes(
                ValidateAttributesError::TooManyEntries
            ))
        ));
    }

    /// Build a client with no reachable server, mirroring `test_no_metrics_interval`.
    /// The runtime setters validate input locally before any network call, so
    /// validation errors surface without a live server.
    async fn build_serverless_client(seed: u64) -> Client {
        let mut rng = rand::rngs::ChaCha8Rng::seed_from_u64(seed);
        let shared_secret = SecretKey::from_bytes(&rng.random());
        let fake_endpoint_id = SecretKey::from_bytes(&rng.random()).public();
        let api_secret = ApiSecret::new(shared_secret, fake_endpoint_id);

        let endpoint = Endpoint::builder(presets::Minimal).bind().await.unwrap();

        Client::builder(&endpoint)
            .disable_metrics_interval()
            .api_secret(api_secret)
            .unwrap()
            .build()
            .await
            .unwrap()
    }

    /// Covers the runtime `Client::set_group` path the builder tests miss:
    /// validation runs locally and returns `Error::InvalidGroup` without a server.
    #[tokio::test]
    async fn test_set_group_runtime_validation() {
        let client = build_serverless_client(2).await;

        let err = client
            .set_group("a")
            .await
            .expect_err("too-short group should fail validation");
        assert!(matches!(
            err,
            Error::InvalidGroup(ValidateNameError::TooShort)
        ));

        let too_long = "x".repeat(CLIENT_NAME_MAX_LENGTH + 1);
        let err = client
            .set_group(too_long)
            .await
            .expect_err("too-long group should fail validation");
        assert!(matches!(
            err,
            Error::InvalidGroup(ValidateNameError::TooLong)
        ));
    }

    /// Covers the runtime `Client::set_attributes` path the builder tests miss:
    /// validation runs locally and returns `Error::InvalidAttributes` without a server.
    #[tokio::test]
    async fn test_set_attributes_runtime_validation() {
        let client = build_serverless_client(3).await;

        // key under 2 bytes
        let err = client
            .set_attributes([("a", "v")])
            .await
            .expect_err("too-short attribute key should fail validation");
        assert!(matches!(
            err,
            Error::InvalidAttributes(ValidateAttributesError::InvalidKey(
                ValidateNameError::TooShort
            ))
        ));

        // value over the max length
        let too_long_value = "x".repeat(CLIENT_ATTRIBUTE_VALUE_MAX_LENGTH + 1);
        let err = client
            .set_attributes([("ok", too_long_value.as_str())])
            .await
            .expect_err("too-long attribute value should fail validation");
        assert!(matches!(
            err,
            Error::InvalidAttributes(ValidateAttributesError::ValueTooLong)
        ));

        // more entries than allowed
        let big: Vec<(String, String)> = (0..(CLIENT_ATTRIBUTES_MAX_COUNT + 1))
            .map(|i| (format!("key_{i:04}"), format!("val_{i}")))
            .collect();
        let err = client
            .set_attributes(big)
            .await
            .expect_err("too many attributes should fail validation");
        assert!(matches!(
            err,
            Error::InvalidAttributes(ValidateAttributesError::TooManyEntries)
        ));
    }

    #[tokio::test]
    async fn test_set_attribute_runtime_validation() {
        let client = build_serverless_client(7).await;

        // A bad single key is rejected before any network call.
        let err = client
            .set_attribute("a", "v")
            .await
            .expect_err("too-short attribute key should fail validation");
        assert!(matches!(
            err,
            Error::InvalidAttributes(ValidateAttributesError::InvalidKey(
                ValidateNameError::TooShort
            ))
        ));

        // A valid single attribute passes validation, then reaches the remote
        // layer (no server) and surfaces a remote error — proving set_attribute
        // is wired through the actor/RPC path.
        let err = client
            .set_attribute("firmware", "2.1.0")
            .await
            .expect_err("no server: remote call must fail after validation passes");
        assert!(matches!(err, Error::Remote(_)), "got {err:?}");
    }

    /// Boundary "accepted" case for the runtime setter. Without a live server we
    /// cannot assert success; instead we assert the input passes local validation
    /// and the call proceeds to the (failing) remote layer, surfacing
    /// `Error::Remote` rather than an `Error::InvalidAttributes` validation error.
    #[tokio::test]
    async fn test_set_attributes_runtime_boundary_accepted() {
        let client = build_serverless_client(4).await;

        // value of exactly the max length is accepted by validation
        let max_value = "x".repeat(CLIENT_ATTRIBUTE_VALUE_MAX_LENGTH);
        let err = client
            .set_attributes([("ok".to_string(), max_value)])
            .await
            .expect_err("no server: remote call must fail after validation passes");
        assert!(
            matches!(err, Error::Remote(_)),
            "expected a remote error (validation accepted), got {err:?}"
        );

        // exactly CLIENT_ATTRIBUTES_MAX_COUNT entries is accepted by validation
        let max_entries: Vec<(String, String)> = (0..CLIENT_ATTRIBUTES_MAX_COUNT)
            .map(|i| (format!("key_{i:04}"), format!("val_{i}")))
            .collect();
        let err = client
            .set_attributes(max_entries)
            .await
            .expect_err("no server: remote call must fail after validation passes");
        assert!(
            matches!(err, Error::Remote(_)),
            "expected a remote error (validation accepted), got {err:?}"
        );
    }
}

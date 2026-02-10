use anyhow::Result;
use irpc::{channel::oneshot, rpc_requests};
use rcan::Rcan;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{caps::Caps, net_diagnostics::DiagnosticsReport};

pub const ALPN: &[u8] = b"/iroh/n0des/1";

pub type N0desClient = irpc::Client<N0desProtocol>;

#[rpc_requests(message = N0desMessage)]
#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum N0desProtocol {
    #[rpc(tx=oneshot::Sender<()>)]
    Auth(Auth),
    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    PutMetrics(PutMetrics),
    #[rpc(tx=oneshot::Sender<Pong>)]
    Ping(Ping),

    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    TicketPublish(PublishTicket),
    #[rpc(tx=oneshot::Sender<RemoteResult<bool>>)]
    TicketUnpublish(UnpublishTicket),
    #[rpc(tx=oneshot::Sender<RemoteResult<Option<TicketData>>>)]
    TicketGet(GetTicket),
    #[rpc(tx=oneshot::Sender<RemoteResult<Vec<TicketData>>>)]
    TicketList(ListTickets),

    #[rpc(tx=oneshot::Sender<RemoteResult<DiagnosticsReport>>)]
    RunNetworkDiagnostics(RunNetworkDiagnostics),
    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    PutNetworkDiagnostics(PutNetworkDiagnostics),

    #[rpc(tx=oneshot::Sender<RemoteResult<()>>)]
    GrantCap(GrantCap),
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

/// Publishing a ticket allows n0des to act as a central hub to ferry tickets
/// between endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct PublishTicket {
    pub req_id: [u8; 16],
    pub name: String,
    pub ticket_kind: String,
    pub ticket: Vec<u8>,
}

/// wire-level request to remove a ticket. Useful for undos, and any situation
/// where the uptime of the endpoint outlasts the utility of the ticket.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnpublishTicket {
    pub req_id: [u8; 16],
    pub name: String,
    pub ticket_kind: String,
}

/// wire-level request get a ticket by name.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetTicket {
    pub req_id: [u8; 16],
    pub name: String,
    pub ticket_kind: String,
}

/// Wire format for requesting a list of tickets
#[derive(Debug, Serialize, Deserialize)]
pub struct ListTickets {
    pub req_id: [u8; 16],
    pub ticket_kind: String,
    pub offset: u32,
    pub limit: u32,
}

/// Signals are opaque data that n0des can ferry between endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketData {
    pub name: String,
    pub ticket_kind: String,
    pub ticket_bytes: Vec<u8>,
}

impl From<PublishTicket> for TicketData {
    fn from(msg: PublishTicket) -> Self {
        TicketData {
            name: msg.name,
            ticket_kind: msg.ticket_kind,
            ticket_bytes: msg.ticket,
        }
    }
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

#[cfg(feature = "client_host")]
pub mod client_host {
    use anyhow::{Result, bail, ensure};
    use iroh::{
        Endpoint, EndpointId,
        endpoint::Connection,
        protocol::{AcceptError, ProtocolHandler},
    };
    use irpc::WithChannels;
    use irpc_iroh::read_request;
    use n0_error::AnyError;
    use rcan::{Capability, CapabilityOrigin, Rcan};
    use tracing::{debug, warn};

    use super::{Caps, N0desMessage, N0desProtocol, Pong, RemoteError};
    use crate::caps::NetDiagnosticsCap;

    #[derive(Debug)]
    pub struct ClientHost {
        endpoint: Endpoint,
    }

    impl ProtocolHandler for ClientHost {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            self.handle_connection(connection).await.map_err(|e| {
                let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
                AcceptError::from(AnyError::from(boxed))
            })
        }
    }

    impl ClientHost {
        /// Create a new client host for the given endpoint. Incoming
        /// connections are authorized by verifying that the first Auth
        /// message contains an RCAN issued by this endpoint.
        pub fn new(endpoint: &Endpoint) -> Self {
            Self {
                endpoint: endpoint.clone(),
            }
        }

        async fn handle_connection(&self, connection: Connection) -> Result<()> {
            let remote_node_id = connection.remote_id();
            let Some(first_request) = read_request::<N0desProtocol>(&connection).await? else {
                return Ok(());
            };

            let N0desMessage::Auth(WithChannels { inner, tx, .. }) = first_request else {
                debug!(remote_node_id = %remote_node_id.fmt_short(), "Expected initial auth message");
                connection.close(400u32.into(), b"Expected initial auth message");
                return Ok(());
            };
            let rcan = inner.caps;
            let capability = rcan.capability();

            let res = self.verify_rcan(remote_node_id, &rcan).await;
            match res {
                Ok(()) => tx.send(()).await?,
                Err(err) => {
                    warn!("authentication failed: {err:?}");
                    connection.close(401u32.into(), b"Unauthorized");
                    return Ok(());
                }
            }

            while let Some(request) = read_request::<N0desProtocol>(&connection).await? {
                tracing::debug!("received RPC request");
                self.handle_request(&connection, remote_node_id, capability, request)
                    .await?;
            }
            connection.closed().await;
            Ok(())
        }

        async fn handle_request(
            &self,
            connection: &Connection,
            remote_node_id: EndpointId,
            capability: &Caps,
            request: N0desMessage,
        ) -> Result<(), anyhow::Error> {
            debug!(remote_node_id = %remote_node_id.fmt_short(), "handle RPC request");
            match request {
                N0desMessage::Auth(_) => {
                    connection.close(400u32.into(), b"Unexpected auth message");
                    bail!("unexpected auth message");
                }
                N0desMessage::Ping(msg) => {
                    let WithChannels { inner, tx, .. } = msg;
                    let req_id = inner.req_id;
                    tx.send(Pong { req_id }).await?;
                }
                N0desMessage::RunNetworkDiagnostics(msg) => {
                    let WithChannels { tx, .. } = msg;
                    let needed_caps = Caps::new([NetDiagnosticsCap::GetAny]);
                    if !capability.permits(&needed_caps) {
                        return send_missing_caps(tx, needed_caps).await;
                    }

                    #[cfg(not(feature = "net_diagnostics"))]
                    {
                        tx.send(Err(RemoteError::AuthError(
                            "this endpoint does not support running remote diagnostics".to_string(),
                        )))
                        .await?;
                    }

                    #[cfg(feature = "net_diagnostics")]
                    {
                        let report =
                            crate::net_diagnostics::checks::run_diagnostics(&self.endpoint).await?;
                        tx.send(Ok(report)).await.inspect_err(|e| {
                            warn!("sending network diagnostics response: {:?}", e)
                        })?;
                    }
                }
                N0desMessage::GrantCap(msg) => {
                    let WithChannels { tx, .. } = msg;
                    // ACK receipt. Server-side storage of granted caps is
                    // handled by the n0des service, not the client host.
                    tx.send(Ok(())).await?;
                }
                _ => {
                    bail!("unsupported message type");
                }
            }
            Ok(())
        }

        async fn verify_rcan(&self, remote_node: EndpointId, rcan: &Rcan<Caps>) -> Result<()> {
            // Must be a first-party token (not delegated)
            ensure!(
                matches!(rcan.capability_origin(), CapabilityOrigin::Issuer),
                "invalid capability origin: expected first-party token"
            );

            // Issuer must be this endpoint (we issued this grant)
            ensure!(
                EndpointId::try_from(rcan.issuer().as_bytes())
                    .map(|id| id == self.endpoint.id())
                    .unwrap_or(false),
                "invalid issuer: RCAN was not issued by this endpoint"
            );

            // Audience must be the remote node (the token is for them)
            ensure!(
                EndpointId::try_from(rcan.audience().as_bytes())
                    .map(|id| id == remote_node)
                    .unwrap_or(false),
                "invalid audience: RCAN audience does not match remote node"
            );

            Ok(())
        }
    }

    async fn send_missing_caps<T>(
        tx: irpc::channel::oneshot::Sender<Result<T, RemoteError>>,
        missing_caps: Caps,
    ) -> Result<()> {
        tx.send(Err(RemoteError::MissingCapability(missing_caps)))
            .await?;
        Ok(())
    }

    #[cfg(test)]
    #[cfg(feature = "net_diagnostics")]
    mod tests {
        use iroh::{RelayMode, address_lookup::MemoryLookup, protocol::Router};
        use irpc_iroh::IrohLazyRemoteConnection;
        use n0_future::time::Duration;

        use super::*;
        use crate::{
            caps::{Caps, create_grant_token},
            protocol::{ALPN, Auth, N0desClient, RunNetworkDiagnostics},
        };

        #[tokio::test]
        async fn test_client_host_run_diagnostics() {
            let lookup = MemoryLookup::new();
            let server_ep = iroh::Endpoint::empty_builder(RelayMode::Disabled)
                .address_lookup(lookup.clone())
                .bind()
                .await
                .unwrap();

            let client_ep = iroh::Endpoint::empty_builder(RelayMode::Disabled)
                .address_lookup(lookup.clone())
                .bind()
                .await
                .unwrap();

            let host = ClientHost::new(&server_ep);
            let router = Router::builder(server_ep.clone())
                .accept(ALPN.to_vec(), host)
                .spawn();

            // The server grants capabilities to the client. The RCAN is
            // issued by the server (issuer = server secret key) with the
            // client as the audience.
            let rcan = create_grant_token(
                server_ep.secret_key().clone(),
                client_ep.id(),
                Duration::from_secs(3600),
                Caps::for_shared_secret(),
            )
            .unwrap();

            let conn =
                IrohLazyRemoteConnection::new(client_ep.clone(), server_ep.addr(), ALPN.to_vec());
            let client = N0desClient::boxed(conn);

            // authenticate with the server-issued grant
            client.rpc(Auth { caps: rcan }).await.unwrap();

            // send RunNetworkDiagnostics and verify we get a report back
            let result = client.rpc(RunNetworkDiagnostics).await.unwrap();
            let report = result.expect("expected Ok(DiagnosticsReport)");
            assert_eq!(report.endpoint_id, server_ep.id());

            router.shutdown().await.unwrap();
            client_ep.close().await;
        }

        #[tokio::test]
        async fn test_client_host_rejects_self_signed_rcan() {
            let lookup = MemoryLookup::new();
            let server_ep = iroh::Endpoint::empty_builder(RelayMode::Disabled)
                .address_lookup(lookup.clone())
                .bind()
                .await
                .unwrap();

            let client_ep = iroh::Endpoint::empty_builder(RelayMode::Disabled)
                .address_lookup(lookup.clone())
                .bind()
                .await
                .unwrap();

            let host = ClientHost::new(&server_ep);
            let router = Router::builder(server_ep.clone())
                .accept(ALPN.to_vec(), host)
                .spawn();

            // Client creates its own RCAN (self-signed, not issued by server).
            // This should be rejected because the issuer doesn't match the
            // server endpoint.
            let rcan = create_grant_token(
                client_ep.secret_key().clone(),
                client_ep.id(),
                Duration::from_secs(3600),
                Caps::for_shared_secret(),
            )
            .unwrap();

            let conn =
                IrohLazyRemoteConnection::new(client_ep.clone(), server_ep.addr(), ALPN.to_vec());
            let client = N0desClient::boxed(conn);

            // auth should fail because the RCAN issuer is the client, not the server
            let result = client.rpc(Auth { caps: rcan }).await;
            assert!(
                result.is_err(),
                "expected auth to be rejected for self-signed RCAN"
            );

            router.shutdown().await.unwrap();
            client_ep.close().await;
        }
    }
}

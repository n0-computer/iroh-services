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

#[cfg(feature = "client_host")]
pub mod client_host {
    use super::{Caps, N0desMessage, N0desProtocol, Pong, RemoteError};
    use crate::caps::NetDiagnosticsCap;

    use anyhow::{Result, bail, ensure};
    use iroh::protocol::{AcceptError, ProtocolHandler};
    use iroh::{Endpoint, EndpointId, endpoint::Connection};
    use irpc::WithChannels;
    use irpc_iroh::read_request;
    use n0_error::{AnyError, e};
    use rcan::{Capability, CapabilityOrigin, Rcan};
    use tracing::{debug, warn};

    #[derive(Debug)]
    pub struct ClientHost {
        // we allow this because the endpoint is used when the net_diagnostics
        // feature is active
        #[allow(dead_code)]
        endpoint: Endpoint,
        /// Set of endpoints that are allowed to dial
        allow: Vec<EndpointId>,
    }

    impl ProtocolHandler for ClientHost {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let remote_id = connection.remote_id();
            if !self.allow.contains(&remote_id) {
                return Err(e!(AcceptError::NotAllowed));
            }
            self.handle_connection(connection).await.map_err(|e| {
                let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
                AcceptError::from(AnyError::from(boxed))
            })
        }
    }

    impl ClientHost {
        /// Create a new client host with the given endpoint and allowed endpoints.
        pub fn new(endpoint: &Endpoint, allow: Vec<EndpointId>) -> Self {
            Self {
                endpoint: endpoint.clone(),
                allow,
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
                            crate::net_diagnostics::run_diagnostics(&self.endpoint).await?;
                        tx.send(Ok(report)).await.inspect_err(|e| {
                            warn!("sending network diagnostics response: {:?}", e)
                        })?;
                    }
                }
                _ => {
                    bail!("unsupported message type");
                }
            }
            Ok(())
        }

        async fn verify_rcan(&self, remote_node: EndpointId, rcan: &Rcan<Caps>) -> Result<()> {
            // Issuer must match the cap_key
            ensure!(
                matches!(rcan.capability_origin(), CapabilityOrigin::Issuer),
                "invalid issuer"
            );

            // Audience must be this endpoint
            ensure!(
                EndpointId::try_from(rcan.audience().as_bytes())
                    .map(|id| id == remote_node)
                    .unwrap_or(false),
                "invalid audience"
            );

            // // The issuer of the capability must be a registered ssh key
            // let issuer = rcan.issuer();
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
        use super::*;
        use crate::caps::{Caps, create_api_token_from_secret_key};
        use crate::protocol::{ALPN, Auth, N0desClient, RunNetworkDiagnostics};
        use iroh::RelayMode;
        use iroh::address_lookup::MemoryLookup;
        use iroh::protocol::Router;
        use irpc_iroh::IrohLazyRemoteConnection;
        use n0_future::time::Duration;

        #[tokio::test]
        async fn test_client_host_run_diagnostics() {
            let lookup = MemoryLookup::new();
            // create the "server" endpoint that will host the ClientHost
            let server_ep = iroh::Endpoint::empty_builder(RelayMode::Disabled)
                .address_lookup(lookup.clone())
                .bind()
                .await
                .unwrap();

            // create the "client" endpoint that will dial the server
            let client_ep = iroh::Endpoint::empty_builder(RelayMode::Disabled)
                .address_lookup(lookup.clone())
                .bind()
                .await
                .unwrap();

            // set up the ClientHost on the server, allowing the client to connect
            let host = ClientHost::new(&server_ep, vec![client_ep.id()]);
            let router = Router::builder(server_ep.clone())
                .accept(ALPN.to_vec(), host)
                .spawn();

            // build an RCAN: issuer is a secret key whose public half equals
            // the client endpoint id; audience is the client endpoint id (the
            // server's verify_rcan checks audience == remote_node_id)
            let client_secret = client_ep.secret_key().clone();
            let rcan = create_api_token_from_secret_key(
                client_secret,
                client_ep.id(),
                Duration::from_secs(3600),
                Caps::for_shared_secret(),
            )
            .unwrap();

            // connect the client to the server over the n0des ALPN
            let conn =
                IrohLazyRemoteConnection::new(client_ep.clone(), server_ep.addr(), ALPN.to_vec());
            let client = N0desClient::boxed(conn);

            // authenticate
            client.rpc(Auth { caps: rcan }).await.unwrap();

            // send RunNetworkDiagnostics and verify we get a report back
            let result = client.rpc(RunNetworkDiagnostics).await.unwrap();
            let report = result.expect("expected Ok(DiagnosticsReport)");
            assert_eq!(report.endpoint_id, server_ep.id());

            // clean up
            router.shutdown().await.unwrap();
            client_ep.close().await;
        }

        #[tokio::test]
        async fn test_client_host_rejects_non_allowed_endpoint() {
            let lookup = MemoryLookup::new();
            // create the "server" endpoint that will host the ClientHost
            let server_ep = iroh::Endpoint::empty_builder(RelayMode::Disabled)
                .address_lookup(lookup.clone())
                .bind()
                .await
                .unwrap();

            // create a client endpoint that is NOT in the allow list
            let client_ep = iroh::Endpoint::empty_builder(RelayMode::Disabled)
                .address_lookup(lookup.clone())
                .bind()
                .await
                .unwrap();

            // set up the ClientHost with an empty allow list
            let host = ClientHost::new(&server_ep, vec![]);
            let router = Router::builder(server_ep.clone())
                .accept(ALPN.to_vec(), host)
                .spawn();

            let client_secret = client_ep.secret_key().clone();
            let rcan = create_api_token_from_secret_key(
                client_secret,
                client_ep.id(),
                Duration::from_secs(3600),
                Caps::for_shared_secret(),
            )
            .unwrap();

            let conn =
                IrohLazyRemoteConnection::new(client_ep.clone(), server_ep.addr(), ALPN.to_vec());
            let client = N0desClient::boxed(conn);

            // the auth RPC should fail because the server rejects the connection
            let result = client.rpc(Auth { caps: rcan }).await;
            assert!(result.is_err(), "expected connection to be rejected");

            router.shutdown().await.unwrap();
            client_ep.close().await;
        }
    }
}

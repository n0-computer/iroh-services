use anyhow::{Result, ensure};
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

use crate::{
    caps::{Caps, NetDiagnosticsCap},
    protocol::{ClientHostProtocol, NetDiagnosticsMessage, RemoteError},
};

/// The ALPN for sending messages from the cloud node to the client.
pub const CLIENT_HOST_ALPN: &[u8] = b"n0/n0des-client-host/1";

pub type ClientHostClient = irpc::Client<ClientHostProtocol>;

/// Protocol handler for cloud-to-endpoint connections.
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
    pub fn new(endpoint: &Endpoint) -> Self {
        Self {
            endpoint: endpoint.clone(),
        }
    }

    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let remote_node_id = connection.remote_id();
        let Some(first_request) = read_request::<ClientHostProtocol>(&connection).await? else {
            return Ok(());
        };

        let NetDiagnosticsMessage::Auth(WithChannels { inner, tx, .. }) = first_request else {
            debug!(remote_node_id = %remote_node_id.fmt_short(), "Expected initial auth message");
            connection.close(400u32.into(), b"Expected initial auth message");
            return Ok(());
        };
        let rcan = inner.caps;
        let capability = rcan.capability();

        let res = verify_rcan(&self.endpoint, remote_node_id, &rcan);
        match res {
            Ok(()) => tx.send(()).await?,
            Err(err) => {
                warn!("authentication failed: {err:?}");
                connection.close(401u32.into(), b"Unauthorized");
                return Ok(());
            }
        }

        // Read exactly one RunNetworkDiagnostics request
        let Some(request) = read_request::<ClientHostProtocol>(&connection).await? else {
            return Ok(());
        };

        match request {
            NetDiagnosticsMessage::Auth(_) => {
                connection.close(400u32.into(), b"Unexpected auth message");
                anyhow::bail!("unexpected auth message");
            }
            NetDiagnosticsMessage::RunNetworkDiagnostics(msg) => {
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
                    tx.send(Ok(report))
                        .await
                        .inspect_err(|e| warn!("sending network diagnostics response: {:?}", e))?;
                }
            }
        }

        connection.closed().await;
        Ok(())
    }
}

fn verify_rcan(endpoint: &Endpoint, remote_node: EndpointId, rcan: &Rcan<Caps>) -> Result<()> {
    // Must be a first-party token (not delegated)
    ensure!(
        matches!(rcan.capability_origin(), CapabilityOrigin::Issuer),
        "invalid capability origin: expected first-party token"
    );

    // Issuer must be this endpoint (we issued this grant)
    ensure!(
        EndpointId::try_from(rcan.issuer().as_bytes())
            .map(|id| id == endpoint.id())
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
        ALPN,
        caps::create_grant_token,
        protocol::{Auth, IrohServicesClient, RunNetworkDiagnostics},
    };

    #[tokio::test]
    async fn test_diagnostics_host_run_diagnostics() {
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
            .accept(CLIENT_HOST_ALPN, host)
            .spawn();

        // The server grants capabilities to the client.
        let rcan = create_grant_token(
            server_ep.secret_key().clone(),
            client_ep.id(),
            Duration::from_secs(3600),
            Caps::for_shared_secret(),
        )
        .unwrap();

        // Connect on the net diagnostics ALPN
        let conn = IrohLazyRemoteConnection::new(
            client_ep.clone(),
            server_ep.addr(),
            CLIENT_HOST_ALPN.to_vec(),
        );
        let client = ClientHostClient::boxed(conn);

        // authenticate with the server-issued grant
        client.rpc(Auth { caps: rcan, label: None }).await.unwrap();

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
            .accept(ALPN, host)
            .spawn();

        // Client creates its own RCAN (self-signed, not issued by server).
        let rcan = create_grant_token(
            client_ep.secret_key().clone(),
            client_ep.id(),
            Duration::from_secs(3600),
            Caps::for_shared_secret(),
        )
        .unwrap();

        let conn =
            IrohLazyRemoteConnection::new(client_ep.clone(), server_ep.addr(), ALPN.to_vec());
        let client = IrohServicesClient::boxed(conn);

        // auth should fail because the RCAN issuer is the client, not the server
        let result = client.rpc(Auth { caps: rcan, label: None }).await;
        assert!(
            result.is_err(),
            "expected auth to be rejected for self-signed RCAN"
        );

        router.shutdown().await.unwrap();
        client_ep.close().await;
    }
}

use anyhow::{Result, ensure};
use iroh::{
    Endpoint, EndpointId,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use irpc::WithChannels;
use irpc_iroh::read_request;
use n0_error::AnyError;
use n0_future::time::Duration;
use rcan::{Capability, CapabilityOrigin, Rcan};
use tracing::{debug, warn};

use crate::{
    caps::{Caps, LogsCap, NetDiagnosticsCap},
    logs::LogCollector,
    protocol::{ClientHostMessage, ClientHostProtocol, FetchLogs, RemoteError},
};

/// The ALPN for sending messages from the cloud node to the client.
pub const CLIENT_HOST_ALPN: &[u8] = b"n0/n0des-client-host/1";

pub type ClientHostClient = irpc::Client<ClientHostProtocol>;

/// Protocol handler for cloud-to-endpoint connections.
#[derive(Debug, Clone)]
pub struct ClientHost {
    endpoint: Endpoint,
    log_collector: Option<LogCollector>,
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
            log_collector: None,
        }
    }

    /// Enables the cloud to set the log level filter at runtime via the
    /// [`SetLogLevel`] callback.
    ///
    /// Without a collector the handler still accepts the message but responds
    /// with [`RemoteError::AuthError`] indicating the feature is disabled.
    ///
    /// [`SetLogLevel`]: crate::protocol::SetLogLevel
    pub fn with_log_collector(mut self, collector: LogCollector) -> Self {
        self.log_collector = Some(collector);
        self
    }

    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let remote_node_id = connection.remote_id();
        let Some(first_request) = read_request::<ClientHostProtocol>(&connection).await? else {
            return Ok(());
        };

        let ClientHostMessage::Auth(WithChannels { inner, tx, .. }) = first_request else {
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

        // Read exactly one callback request
        let Some(request) = read_request::<ClientHostProtocol>(&connection).await? else {
            return Ok(());
        };

        match request {
            ClientHostMessage::Auth(_) => {
                connection.close(400u32.into(), b"Unexpected auth message");
                anyhow::bail!("unexpected auth message");
            }
            ClientHostMessage::RunNetworkDiagnostics(msg) => {
                let WithChannels { tx, .. } = msg;
                let needed_caps = Caps::new([NetDiagnosticsCap::GetAny]);
                if !capability.permits(&needed_caps) {
                    return send_missing_caps(tx, needed_caps).await;
                }

                let report =
                    crate::net_diagnostics::checks::run_diagnostics(&self.endpoint).await?;
                tx.send(Ok(report))
                    .await
                    .inspect_err(|e| warn!("sending network diagnostics response: {:?}", e))?;
            }
            ClientHostMessage::SetLogLevel(msg) => {
                let WithChannels { inner, tx, .. } = msg;
                let needed_caps = Caps::new([LogsCap::SetLevel]);
                if !capability.permits(&needed_caps) {
                    return send_missing_caps(tx, needed_caps).await;
                }
                let Some(ref collector) = self.log_collector else {
                    tx.send(Err(RemoteError::AuthError(
                        "log collection is not enabled on this client".into(),
                    )))
                    .await?;
                    return Ok(());
                };
                let expires_in = inner.expires_in_secs.map(Duration::from_secs);
                match collector.set_filter(
                    &inner.directives,
                    expires_in,
                    inner.revert_to.as_deref(),
                ) {
                    Ok(()) => {
                        debug!(
                            directives = %inner.directives,
                            expires_in_secs = ?inner.expires_in_secs,
                            "applied log level override"
                        );
                        tx.send(Ok(())).await?;
                    }
                    Err(err) => {
                        warn!(?err, "failed to apply log level override");
                        tx.send(Err(RemoteError::AuthError(err.to_string())))
                            .await?;
                    }
                }
            }
            ClientHostMessage::FetchLogs(msg) => {
                let WithChannels { inner, tx, .. } = msg;
                let needed_caps = Caps::new([LogsCap::Fetch]);
                if !capability.permits(&needed_caps) {
                    let _ = tx
                        .send(Err(RemoteError::MissingCapability(needed_caps)))
                        .await;
                } else if let Some(collector) = self.log_collector.clone() {
                    stream_current_log_file(collector, inner, tx).await;
                } else {
                    let _ = tx
                        .send(Err(RemoteError::AuthError(
                            "log collection is not enabled on this client".into(),
                        )))
                        .await;
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

/// Chunk size for streaming the rolling file back. 64 KiB is large enough
/// to amortize the round-trip overhead and small enough that a tight
/// `max_bytes` clamp still produces granular cut-off points.
const FETCH_LOGS_CHUNK_BYTES: usize = 64 * 1024;

/// Open the collector's currently-active rolling file and stream it back
/// over `tx` in 64 KiB chunks. Stops at end-of-file or when
/// `request.max_bytes` is reached. Errors during read are reported as a
/// terminal `Err` chunk; the receiver should treat the stream's end as
/// success.
async fn stream_current_log_file(
    collector: LogCollector,
    request: FetchLogs,
    tx: irpc::channel::mpsc::Sender<Result<Vec<u8>, RemoteError>>,
) {
    use tokio::io::AsyncReadExt;

    let path = match collector.current_log_file() {
        Ok(Some(p)) => p,
        Ok(None) => {
            let _ = tx
                .send(Err(RemoteError::AuthError(
                    "no log file is present on this client".into(),
                )))
                .await;
            return;
        }
        Err(err) => {
            warn!(?err, "failed to locate current log file");
            let _ = tx.send(Err(RemoteError::InternalServerError)).await;
            return;
        }
    };

    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(err) => {
            warn!(?err, path = %path.display(), "failed to open log file");
            let _ = tx.send(Err(RemoteError::InternalServerError)).await;
            return;
        }
    };

    let max_bytes = request.max_bytes.unwrap_or(u64::MAX);
    let mut sent: u64 = 0;
    let mut buf = vec![0u8; FETCH_LOGS_CHUNK_BYTES];
    loop {
        let remaining = max_bytes.saturating_sub(sent);
        if remaining == 0 {
            break;
        }
        let take = (remaining.min(buf.len() as u64)) as usize;
        let n = match file.read(&mut buf[..take]).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) => {
                warn!(?err, "log file read failed");
                let _ = tx.send(Err(RemoteError::InternalServerError)).await;
                return;
            }
        };
        if tx.send(Ok(buf[..n].to_vec())).await.is_err() {
            // Receiver hung up; nothing more to do.
            return;
        }
        sent = sent.saturating_add(n as u64);
    }
    debug!(
        path = %path.display(),
        bytes = sent,
        "streamed log file to remote"
    );
}

#[cfg(test)]
mod tests {
    use iroh::{address_lookup::MemoryLookup, endpoint::presets, protocol::Router};
    use irpc_iroh::IrohLazyRemoteConnection;
    use n0_future::time::Duration;

    use super::*;
    use crate::{
        ALPN,
        caps::create_grant_token,
        logs::{self, FileLoggerConfig},
        protocol::{Auth, FetchLogs as FetchLogsReq, IrohServicesClient, RunNetworkDiagnostics},
    };

    #[tokio::test]
    async fn test_diagnostics_host_run_diagnostics() {
        let lookup = MemoryLookup::new();
        let server_ep = iroh::Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .unwrap();

        let client_ep = iroh::Endpoint::builder(presets::Minimal)
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
        let server_ep = iroh::Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .unwrap();

        let client_ep = iroh::Endpoint::builder(presets::Minimal)
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
        let result = client.rpc(Auth { caps: rcan }).await;
        assert!(
            result.is_err(),
            "expected auth to be rejected for self-signed RCAN"
        );

        router.shutdown().await.unwrap();
        client_ep.close().await;
    }

    /// FetchLogs streams the currently-active rolling file from the
    /// endpoint back to the cloud caller in chunks.
    #[tokio::test]
    async fn test_fetch_logs_streams_current_file() {
        let tmp = tempfile::tempdir().unwrap();
        // Stand up a LogCollector pointing at the tempdir but skip the
        // global subscriber init: we want a controlled file we wrote
        // directly, not whatever the appender buffers.
        let (collector, _layer, guard) =
            logs::layer(FileLoggerConfig::new(tmp.path()).with_file_name_prefix("fetch-test"))
                .unwrap();
        drop(guard);

        // Write a known payload to a file matching the prefix so
        // `current_log_file` picks it up.
        let payload: Vec<u8> = (0..200_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let file_path = tmp.path().join("fetch-test.2026-05-14");
        std::fs::write(&file_path, &payload).unwrap();

        let lookup = MemoryLookup::new();
        let server_ep = iroh::Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .unwrap();
        let client_ep = iroh::Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .unwrap();

        let host = ClientHost::new(&server_ep).with_log_collector(collector);
        let router = Router::builder(server_ep.clone())
            .accept(CLIENT_HOST_ALPN, host)
            .spawn();

        // Issue a grant that includes LogsCap::Fetch.
        let rcan = create_grant_token(
            server_ep.secret_key().clone(),
            client_ep.id(),
            Duration::from_secs(3600),
            Caps::new([LogsCap::Fetch]),
        )
        .unwrap();
        let conn = IrohLazyRemoteConnection::new(
            client_ep.clone(),
            server_ep.addr(),
            CLIENT_HOST_ALPN.to_vec(),
        );
        let client = ClientHostClient::boxed(conn);
        client.rpc(Auth { caps: rcan }).await.unwrap();

        let mut rx = client
            .server_streaming(FetchLogsReq { max_bytes: None }, 16)
            .await
            .unwrap();

        let mut got: Vec<u8> = Vec::new();
        while let Some(chunk) = rx.recv().await.expect("server stream irpc error") {
            let bytes = chunk.expect("server returned RemoteError");
            got.extend_from_slice(&bytes);
        }
        assert_eq!(got, payload, "streamed bytes should match the file");

        router.shutdown().await.unwrap();
        client_ep.close().await;
    }

    /// Endpoints without `LogsCap::Fetch` get a `MissingCapability` error
    /// on the stream and no data.
    #[tokio::test]
    async fn test_fetch_logs_rejects_missing_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let (collector, _layer, guard) =
            logs::layer(FileLoggerConfig::new(tmp.path()).with_file_name_prefix("noaccess"))
                .unwrap();
        drop(guard);

        let lookup = MemoryLookup::new();
        let server_ep = iroh::Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .unwrap();
        let client_ep = iroh::Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await
            .unwrap();

        let host = ClientHost::new(&server_ep).with_log_collector(collector);
        let router = Router::builder(server_ep.clone())
            .accept(CLIENT_HOST_ALPN, host)
            .spawn();

        // Grant SetLevel, not Fetch.
        let rcan = create_grant_token(
            server_ep.secret_key().clone(),
            client_ep.id(),
            Duration::from_secs(3600),
            Caps::new([LogsCap::SetLevel]),
        )
        .unwrap();
        let conn = IrohLazyRemoteConnection::new(
            client_ep.clone(),
            server_ep.addr(),
            CLIENT_HOST_ALPN.to_vec(),
        );
        let client = ClientHostClient::boxed(conn);
        client.rpc(Auth { caps: rcan }).await.unwrap();

        let mut rx = client
            .server_streaming(FetchLogsReq { max_bytes: None }, 4)
            .await
            .unwrap();

        let first = rx
            .recv()
            .await
            .expect("server stream irpc error")
            .expect("stream should produce one error");
        assert!(matches!(first, Err(RemoteError::MissingCapability(_))));
        assert!(
            rx.recv().await.expect("server stream irpc error").is_none(),
            "stream should close after error",
        );

        router.shutdown().await.unwrap();
        client_ep.close().await;
    }
}

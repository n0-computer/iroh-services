//! Network diagnostics for iroh-powered applications.
//!
//! Collects a full network diagnostics report from an existing iroh Endpoint
//! covering UDP connectivity, relay latency, and port mapping protocol
//! availability.
//!
//! Relay latencies and UDP connectivity are read from iroh's [`NetReport`]
//! which the endpoint already produces continuously. The only additional probe
//! performed here is the port-mapping protocol availability check.
use std::net::SocketAddr;

use iroh::NetReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    pub endpoint_id: iroh::EndpointId,
    pub net_report: Option<NetReport>,
    pub direct_addrs: Vec<SocketAddr>,
    pub portmap_probe: Option<PortMapProbe>,
    #[serde(default)]
    pub iroh_version: Option<String>,
    #[serde(default)]
    pub iroh_n0des_version: Option<String>,
}

/// Port mapping protocol availability on the LAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapProbe {
    pub upnp: bool,
    pub pcp: bool,
    pub nat_pmp: bool,
}

#[cfg(feature = "net_diagnostics")]
pub mod checks {
    use std::{net::SocketAddr, time::Duration};

    use anyhow::Result;
    use iroh::{Endpoint, Watcher};

    use super::*;

    /// Run full network diagnostics on an existing endpoint. 10s timeout.
    pub async fn run_diagnostics(endpoint: &Endpoint) -> Result<DiagnosticsReport> {
        run_diagnostics_with_timeout(endpoint, Duration::from_secs(10)).await
    }

    /// Run full network diagnostics with a custom timeout for net report init.
    async fn run_diagnostics_with_timeout(
        endpoint: &Endpoint,
        timeout: Duration,
    ) -> Result<DiagnosticsReport> {
        let endpoint_id = endpoint.id();

        // 1. Wait for relay connection
        if tokio::time::timeout(timeout, endpoint.online())
            .await
            .is_err()
        {
            tracing::warn!("waiting for relay connection timed out after {timeout:?}");
        }

        // 2. Net report (includes relay latencies and UDP connectivity)
        let mut watcher = endpoint.net_report();
        let net_report = match tokio::time::timeout(timeout, watcher.initialized()).await {
            Ok(report) => Some(report),
            Err(_) => {
                tracing::warn!("net report timed out after {timeout:?}, using partial data");
                watcher.get()
            }
        };

        // 3. Endpoint address info
        let addr = endpoint.addr();
        let direct_addrs: Vec<SocketAddr> = addr.ip_addrs().copied().collect();

        // 4. Port mapping probe (the one thing NetReport doesn't include)
        let portmap_probe =
            match tokio::time::timeout(Duration::from_secs(5), probe_port_mapping()).await {
                Ok(Ok(p)) => Some(p),
                Ok(Err(e)) => {
                    tracing::warn!("portmap probe failed: {e}");
                    None
                }
                Err(_) => {
                    tracing::warn!("portmap probe timed out");
                    None
                }
            };

        Ok(DiagnosticsReport {
            endpoint_id,
            net_report,
            direct_addrs,
            portmap_probe,
            iroh_version: Some(crate::IROH_VERSION.to_string()),
            iroh_n0des_version: Some(crate::IROH_N0DES_VERSION.to_string()),
        })
    }

    async fn probe_port_mapping() -> Result<PortMapProbe> {
        let config = portmapper::Config {
            enable_upnp: true,
            enable_pcp: true,
            enable_nat_pmp: true,
            protocol: portmapper::Protocol::Udp,
        };
        let client = portmapper::Client::new(config);
        let probe_rx = client.probe();
        let probe = probe_rx.await?.map_err(|e| anyhow::anyhow!(e))?;
        Ok(PortMapProbe {
            upnp: probe.upnp,
            pcp: probe.pcp,
            nat_pmp: probe.nat_pmp,
        })
    }
}

#[cfg(test)]
#[cfg(feature = "net_diagnostics")]
mod tests {
    use crate::run_diagnostics;

    #[tokio::test]
    async fn test_run_diagnostics() {
        let endpoint = iroh::Endpoint::empty_builder(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        run_diagnostics(&endpoint).await.unwrap();
        endpoint.close().await;
    }
}

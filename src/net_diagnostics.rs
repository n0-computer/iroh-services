//! Network diagnostics for iroh-powered applications.
//!
//! Collects a full network diagnostics report from an existing iroh Endpoint
//! covering UDP connectivity, relay latency, and port mapping protocol
//! availability.

use std::{
    fmt,
    net::SocketAddr,
    time::{Duration, Instant},
};

use anyhow::Result;
use iroh::{Endpoint, NetReport, RelayUrl, SecretKey, Watcher, dns::DnsResolver};
use iroh_relay::protos::relay::{ClientToRelayMsg, RelayToClientMsg};
use n0_future::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayLatency {
    pub url: RelayUrl,
    pub connect_time: Option<Duration>,
    pub ping_latency: Option<Duration>,
    pub error: Option<String>,
}

/// Port mapping protocol availability on the LAN.
/// This can be avoided if we make the original port mapping probe return a serde-able struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapProbe {
    pub upnp: bool,
    pub pcp: bool,
    pub nat_pmp: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    pub endpoint_id: iroh::EndpointId,
    pub net_report: Option<NetReport>,
    pub direct_addrs: Vec<SocketAddr>,
    pub relay_latencies: Vec<RelayLatency>,
    pub portmap_probe: Option<PortMapProbe>,
}

impl fmt::Display for DiagnosticsReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== iroh Network Diagnostics ===")?;
        writeln!(f, "Endpoint ID: {}", self.endpoint_id)?;

        if let Some(ref nr) = self.net_report {
            writeln!(
                f,
                "UDP IPv4: {} | Global: {}",
                yn(nr.udp_v4),
                nr.global_v4
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "none".into())
            )?;
            writeln!(
                f,
                "UDP IPv6: {} | Global: {}",
                yn(nr.udp_v6),
                nr.global_v6
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "none".into())
            )?;
            writeln!(
                f,
                "NAT mapping varies by dest (v4): {}  (v6): {}",
                opt_bool(nr.mapping_varies_by_dest_ipv4),
                opt_bool(nr.mapping_varies_by_dest_ipv6),
            )?;
            writeln!(
                f,
                "Preferred relay: {}",
                nr.preferred_relay
                    .as_ref()
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "none".into())
            )?;
            writeln!(f, "Captive portal: {}", opt_bool(nr.captive_portal))?;
        } else {
            writeln!(f, "Net report: unavailable")?;
        }

        if !self.relay_latencies.is_empty() {
            writeln!(f, "Relay Latency:")?;
            for rl in &self.relay_latencies {
                if let Some(ref err) = rl.error {
                    writeln!(f, "  {} — error: {}", rl.url, err)?;
                } else {
                    writeln!(
                        f,
                        "  {} — connect: {}, ping: {}",
                        rl.url,
                        fmt_dur(rl.connect_time),
                        fmt_dur(rl.ping_latency),
                    )?;
                }
            }
        }

        if self.direct_addrs.is_empty() {
            writeln!(f, "Direct addrs: none")?;
        } else {
            let addrs: Vec<_> = self.direct_addrs.iter().map(|a| a.to_string()).collect();
            writeln!(f, "Direct addrs: {}", addrs.join(", "))?;
        }

        if let Some(ref probe) = self.portmap_probe {
            writeln!(
                f,
                "Port mapping: UPnP: {}, PCP: {}, NAT-PMP: {}",
                yn(probe.upnp),
                yn(probe.pcp),
                yn(probe.nat_pmp),
            )?;
        } else {
            writeln!(f, "Port mapping: probe failed or timed out")?;
        }

        Ok(())
    }
}

/// Run full network diagnostics on an existing endpoint. 10s timeout.
pub async fn diagnose(endpoint: &Endpoint) -> Result<DiagnosticsReport> {
    diagnose_with_timeout(endpoint, Duration::from_secs(10)).await
}

/// Run full network diagnostics with a custom timeout for net report init.
async fn diagnose_with_timeout(
    endpoint: &Endpoint,
    timeout: Duration,
) -> Result<DiagnosticsReport> {
    let endpoint_id = endpoint.id();

    // 1. Wait for relay connection
    if tokio::time::timeout(timeout, endpoint.online())
        .await
        .is_err()
    {
        eprintln!("waiting for relay connection timed out after {timeout:?}");
    }

    // 2. Net report
    let mut watcher = endpoint.net_report();
    let net_report = match tokio::time::timeout(timeout, watcher.initialized()).await {
        Ok(report) => Some(report),
        Err(_) => {
            eprintln!("net report timed out after {timeout:?}, using partial data");
            watcher.get()
        }
    };

    // 3. Endpoint address info
    let addr = endpoint.addr();
    let relay_urls: Vec<RelayUrl> = addr.relay_urls().cloned().collect();
    let direct_addrs: Vec<SocketAddr> = addr.ip_addrs().copied().collect();

    // 4. Relay latency + port mapping probe in parallel
    let relay_fut = async {
        let mut results = Vec::new();
        for url in &relay_urls {
            results.push(probe_relay_latency(url).await);
        }
        results
    };

    let portmap_fut = async {
        match tokio::time::timeout(Duration::from_secs(5), probe_port_mapping()).await {
            Ok(Ok(p)) => Some(p),
            Ok(Err(e)) => {
                eprintln!("portmap probe failed: {e}");
                None
            }
            Err(_) => {
                eprintln!("portmap probe timed out");
                None
            }
        }
    };

    let (relay_latencies, portmap_probe) = tokio::join!(relay_fut, portmap_fut);

    Ok(DiagnosticsReport {
        endpoint_id,
        net_report,
        direct_addrs,
        relay_latencies,
        portmap_probe,
    })
}

async fn probe_relay_latency(url: &RelayUrl) -> RelayLatency {
    let key = SecretKey::generate(&mut rand::rng());
    let dns = DnsResolver::new();
    let builder = iroh_relay::client::ClientBuilder::new(url.clone(), key, dns);

    let start = Instant::now();
    let client = match tokio::time::timeout(Duration::from_secs(3), builder.connect()).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            return RelayLatency {
                url: url.clone(),
                connect_time: None,
                ping_latency: None,
                error: Some(format!("connect error: {e}")),
            };
        }
        Err(_) => {
            return RelayLatency {
                url: url.clone(),
                connect_time: None,
                ping_latency: None,
                error: Some("connect timeout".into()),
            };
        }
    };
    let connect_time = start.elapsed();

    let (mut stream, mut sink) = client.split();
    let data: [u8; 8] = rand::random();
    let ping_start = Instant::now();

    if let Err(e) = sink.send(ClientToRelayMsg::Ping(data)).await {
        return RelayLatency {
            url: url.clone(),
            connect_time: Some(connect_time),
            ping_latency: None,
            error: Some(format!("ping send error: {e}")),
        };
    }

    let ping_result = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(res) = stream.next().await {
            match res {
                Ok(RelayToClientMsg::Pong(d)) if d == data => {
                    return Ok(ping_start.elapsed());
                }
                Ok(_) => continue,
                Err(e) => return Err(anyhow::anyhow!("stream error: {e}")),
            }
        }
        Err(anyhow::anyhow!("stream ended without pong"))
    })
    .await;

    match ping_result {
        Ok(Ok(latency)) => RelayLatency {
            url: url.clone(),
            connect_time: Some(connect_time),
            ping_latency: Some(latency),
            error: None,
        },
        Ok(Err(e)) => RelayLatency {
            url: url.clone(),
            connect_time: Some(connect_time),
            ping_latency: None,
            error: Some(e.to_string()),
        },
        Err(_) => RelayLatency {
            url: url.clone(),
            connect_time: Some(connect_time),
            ping_latency: None,
            error: Some("ping timeout".into()),
        },
    }
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

fn yn(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn opt_bool(b: Option<bool>) -> &'static str {
    match b {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn fmt_dur(d: Option<Duration>) -> String {
    match d {
        Some(d) => format!("{:.1?}", d),
        None => "n/a".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_diagnose() {
        let endpoint = Endpoint::empty_builder(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let report = diagnose(&endpoint).await.unwrap();
        println!("{report}");
        endpoint.close().await;
    }
}

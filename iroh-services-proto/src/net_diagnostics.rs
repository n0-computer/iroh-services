use std::net::SocketAddr;

use iroh::unstable_net_report::NetReport;
use serde::{Deserialize, Serialize};

/// A report about an iroh endpoint's network connectivity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    pub endpoint_id: iroh::EndpointId,
    pub net_report: Option<NetReport>,
    pub direct_addrs: Vec<SocketAddr>,
    pub portmap_probe: Option<PortMapProbe>,
    #[serde(default)]
    pub iroh_version: String,
    #[serde(default)]
    pub iroh_services_version: String,
}

/// Port mapping protocol availability on the LAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapProbe {
    pub upnp: bool,
    pub pcp: bool,
    pub nat_pmp: bool,
}

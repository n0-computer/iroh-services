use anyhow::Result;
use iroh::{EndpointId, SecretKey};
pub use iroh_services_proto::caps::{Cap, CapSet, Caps, MetricsCap, NetDiagnosticsCap, RelayCap};
use n0_future::time::Duration;
use rcan::{Expires, Rcan};

use crate::CapabilityToken;

pub(crate) const DEFAULT_CAP_EXPIRY: Duration = Duration::from_hours(24 * 30); // 1 month

/// Create an rcan token for the api access from a PEM-encoded OpenSSH ed25519
/// private key.
#[cfg(not(wasm_browser))]
pub fn create_api_token_from_openssh_pem(
    pem: &str,
    local_id: EndpointId,
    max_age: Duration,
    capability: Caps,
) -> Result<CapabilityToken> {
    let seed = crate::openssh::parse_ed25519_private_key(pem)?;
    let issuer = ed25519_dalek::SigningKey::from_bytes(&seed);
    let audience = local_id.as_verifying_key();
    let can =
        Rcan::issuing_builder(&issuer, audience, capability).sign(Expires::valid_for(max_age));
    Ok(CapabilityToken::new(can))
}

/// Create an rcan token that grants capabilities to a remote endpoint.
/// The local endpoint is the issuer (granter), and the remote endpoint is the
/// audience (grantee).
pub fn create_grant_token(
    local_secret: SecretKey,
    remote_id: EndpointId,
    max_age: Duration,
    capability: Caps,
) -> Result<CapabilityToken> {
    let issuer = ed25519_dalek::SigningKey::from_bytes(&local_secret.to_bytes());
    let audience = remote_id.as_verifying_key();
    let can =
        Rcan::issuing_builder(&issuer, audience, capability).sign(Expires::valid_for(max_age));
    Ok(CapabilityToken::new(can))
}

/// Create an rcan token for the api access from an iroh secret key
pub fn create_api_token_from_secret_key(
    private_key: SecretKey,
    local_id: EndpointId,
    max_age: Duration,
    capability: Caps,
) -> Result<CapabilityToken> {
    let issuer = ed25519_dalek::SigningKey::from_bytes(&private_key.to_bytes());
    let audience = local_id.as_verifying_key();
    let can =
        Rcan::issuing_builder(&issuer, audience, capability).sign(Expires::valid_for(max_age));
    Ok(CapabilityToken::new(can))
}

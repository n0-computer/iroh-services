use std::time::Duration;

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use iroh::NodeId;
use rcan::{Capability, Expires, Rcan};
use serde::{Deserialize, Serialize};
use ssh_key::PrivateKey as SshPrivateKey;

/// Potential capabilities for IPS
#[derive(Ord, Eq, PartialOrd, PartialEq, Clone, Serialize, Deserialize, Debug)]
#[repr(u8)]
pub enum IpsCap {
    /// API tokens, used in the RPC
    Api,
    /// Used to authenticate users.
    Web,
}

impl Capability for IpsCap {
    fn can_delegate(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Web, _) => false, // web can never delegate
            (Self::Api, _) => false,
        }
    }
}

/// Create an rcan token for the api access.
pub fn create_api_token(
    user_ssh_key: &SshPrivateKey,
    node_id: NodeId,
    max_age: Duration,
) -> Result<Rcan<IpsCap>> {
    let issuer: SigningKey = user_ssh_key
        .key_data()
        .ed25519()
        .context("only Ed25519 keys supported")?
        .private
        .clone()
        .into();

    // TODO: add Into to iroh-base
    let audience = VerifyingKey::from_bytes(node_id.as_bytes())?;
    let can =
        Rcan::issuing_builder(&issuer, audience, IpsCap::Api).sign(Expires::valid_for(max_age));
    Ok(can)
}

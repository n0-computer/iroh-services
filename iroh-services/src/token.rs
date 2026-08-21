use std::time::{SystemTime, UNIX_EPOCH};

use iroh_services_proto::caps::Caps;
use rcan::{Expires, Rcan};

/// An opaque capability token issued by iroh-services.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiToken(Rcan<Caps>);

impl ApiToken {
    pub(crate) fn new(token: Rcan<Caps>) -> Self {
        Self(token)
    }

    pub(crate) fn into_rcan(self) -> Rcan<Caps> {
        self.0
    }

    /// Returns the encoded token.
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }

    /// Returns the token's expiration time, or `None` if it does not expire.
    pub fn expires_at(&self) -> Option<SystemTime> {
        match self.0.expires() {
            Expires::Never => None,
            Expires::At(seconds) => {
                UNIX_EPOCH.checked_add(std::time::Duration::from_secs(*seconds))
            }
        }
    }
}

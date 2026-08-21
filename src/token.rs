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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::SecretKey;

    use super::*;
    use crate::caps::{Caps, RelayCap, create_api_token_from_secret_key};

    #[test]
    fn token_exposes_stable_encoding_and_expiration() {
        let issuer = SecretKey::from_bytes(&[1; 32]);
        let audience = SecretKey::from_bytes(&[2; 32]).public();
        let before = SystemTime::now();
        let token = create_api_token_from_secret_key(
            issuer,
            audience,
            Duration::from_secs(60),
            Caps::new([RelayCap::Use]),
        )
        .unwrap();

        assert!(!token.encode().is_empty());
        assert!(token.expires_at().is_some_and(|expiry| expiry >= before));
    }
}

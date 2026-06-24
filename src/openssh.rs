//! Minimal parser for unencrypted OpenSSH ed25519 private keys.
//!
//! See <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key>
//! for the on-disk format.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};

const MAGIC: &[u8] = b"openssh-key-v1\0";
const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";

/// Parse an unencrypted OpenSSH ed25519 private key (PEM-encoded) and return
/// the 32-byte ed25519 seed.
pub(crate) fn parse_ed25519_private_key(pem: &str) -> Result<[u8; 32]> {
    let begin = pem.find(PEM_BEGIN).context("missing OpenSSH PEM header")?;
    let after_header = begin + PEM_BEGIN.len();
    let end_offset = pem[after_header..]
        .find(PEM_END)
        .context("missing OpenSSH PEM footer")?;
    let body: String = pem[after_header..after_header + end_offset]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes = STANDARD
        .decode(body.as_bytes())
        .context("invalid base64 in OpenSSH key")?;

    let mut r = Reader::new(&bytes);
    ensure!(r.take(MAGIC.len())? == MAGIC, "not an OpenSSH v1 key");
    let cipher = r.string()?;
    ensure!(
        cipher == b"none",
        "encrypted OpenSSH keys are not supported"
    );
    let kdf = r.string()?;
    ensure!(kdf == b"none", "OpenSSH key has unexpected kdf");
    let _kdf_options = r.string()?;
    let nkeys = r.u32()?;
    ensure!(nkeys == 1, "expected exactly one OpenSSH key, got {nkeys}");
    let _public_key = r.string()?;
    let private_section = r.string()?;

    let mut r = Reader::new(private_section);
    let c1 = r.u32()?;
    let c2 = r.u32()?;
    ensure!(c1 == c2, "OpenSSH checkint mismatch (key may be encrypted)");
    let keytype = r.string()?;
    ensure!(
        keytype == b"ssh-ed25519",
        "only ed25519 OpenSSH keys are supported"
    );
    let _public = r.string()?;
    let private = r.string()?;
    ensure!(
        private.len() == 64,
        "unexpected ed25519 private key length: {}",
        private.len()
    );

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&private[..32]);
    Ok(seed)
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            bail!("truncated OpenSSH key");
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated with: ssh-keygen -t ed25519 -N "" -C "test" -f test_ed25519
    const TEST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAWYfB1wGmNdl6aNtsu+TM85xnUGiRWby1yGDF8m/q+SQAAAIgA3R/pAN0f
6QAAAAtzc2gtZWQyNTUxOQAAACAWYfB1wGmNdl6aNtsu+TM85xnUGiRWby1yGDF8m/q+SQ
AAAECl0xpQZcR3+0yDAZzrUcbH14q5kLjm89hZctff1tT1vhZh8HXAaY12Xpo22y75Mzzn
GdQaJFZvLXIYMXyb+r5JAAAABHRlc3QB
-----END OPENSSH PRIVATE KEY-----";

    // Public key bytes from `ssh-keygen -y -f test_ed25519` (the trailing 32
    // bytes after the "ssh-ed25519" wire prefix).
    const TEST_PUBLIC: [u8; 32] = [
        0x16, 0x61, 0xf0, 0x75, 0xc0, 0x69, 0x8d, 0x76, 0x5e, 0x9a, 0x36, 0xdb, 0x2e, 0xf9, 0x33,
        0x3c, 0xe7, 0x19, 0xd4, 0x1a, 0x24, 0x56, 0x6f, 0x2d, 0x72, 0x18, 0x31, 0x7c, 0x9b, 0xfa,
        0xbe, 0x49,
    ];

    #[test]
    fn parses_known_ed25519_key() {
        let seed = parse_ed25519_private_key(TEST_KEY).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(signing.verifying_key().to_bytes(), TEST_PUBLIC);
    }

    #[test]
    fn rejects_non_pem() {
        assert!(parse_ed25519_private_key("not a key").is_err());
    }
}

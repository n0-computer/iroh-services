//! Project-scoped relay authorization wire types and printable proofs.

use anyhow::{Context, Result, bail, ensure};
use iroh_rcan::DelegationChain;
use rcan_v2::CapabilityEncoding;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Prefix identifying a printable relay proof.
pub const PROOF_PREFIX: &str = "irp1_";

/// Maximum number of base32 characters in a printable relay proof payload.
pub const MAX_PROOF_PAYLOAD_LEN: usize = (iroh_rcan::MAX_DELEGATION_CHAIN_BYTES * 8).div_ceil(5);

/// Maximum byte length of a printable relay proof, including [`PROOF_PREFIX`].
pub const MAX_PROOF_LEN: usize = PROOF_PREFIX.len() + MAX_PROOF_PAYLOAD_LEN;

/// Stable, byte-oriented identifier for a relay project.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProjectId([u8; 16]);

impl ProjectId {
    /// Constructs a project identifier from its canonical 16-byte representation.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical 16-byte representation.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<Uuid> for ProjectId {
    fn from(value: Uuid) -> Self {
        Self::from_bytes(*value.as_bytes())
    }
}

impl From<ProjectId> for Uuid {
    fn from(value: ProjectId) -> Self {
        Self::from_bytes(*value.as_bytes())
    }
}

/// Capability to use relay service resources assigned to one project.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RelayCapability {
    /// Initial project-scoped relay capability format.
    V0 {
        /// Project whose relay resources may be used.
        project_id: ProjectId,
    },
}

impl RelayCapability {
    /// Constructs a relay capability for `project_id`.
    pub const fn new(project_id: ProjectId) -> Self {
        Self::V0 { project_id }
    }

    /// Returns the project authorized by this capability.
    pub const fn project_id(&self) -> ProjectId {
        match self {
            Self::V0 { project_id } => *project_id,
        }
    }
}

impl rcan_v2::Capability for RelayCapability {
    fn permits(&self, other: &Self) -> bool {
        self == other
    }
}

/// Encodes a checked delegation chain as a canonical printable relay proof.
pub fn encode_proof<C>(chain: &DelegationChain<C>) -> String
where
    C: CapabilityEncoding,
{
    let payload = data_encoding::BASE32_NOPAD
        .encode(&chain.encode())
        .to_ascii_lowercase();
    format!("{PROOF_PREFIX}{payload}")
}

/// Decodes and checks a canonical printable relay proof.
///
/// This verifies the envelope, bounded chain encoding, signatures, capability
/// type, and chain structure. Only the lowercase, unpadded representation is
/// accepted.
pub fn decode_proof<C>(proof: &str) -> Result<DelegationChain<C>>
where
    C: CapabilityEncoding,
{
    ensure!(
        proof.len() <= MAX_PROOF_LEN,
        "relay proof exceeds maximum length of {MAX_PROOF_LEN} bytes"
    );
    let payload = proof
        .strip_prefix(PROOF_PREFIX)
        .context("relay proof is missing the required prefix")?;
    ensure!(
        payload.len() <= MAX_PROOF_PAYLOAD_LEN,
        "relay proof payload exceeds maximum length of {MAX_PROOF_PAYLOAD_LEN} bytes"
    );

    let uppercase = payload.to_ascii_uppercase();
    let encoded = data_encoding::BASE32_NOPAD
        .decode(uppercase.as_bytes())
        .map_err(|error| anyhow::anyhow!("invalid relay proof base32: {error}"))?;
    ensure!(
        encoded.len() <= iroh_rcan::MAX_DELEGATION_CHAIN_BYTES,
        "relay proof exceeds maximum decoded size of {} bytes",
        iroh_rcan::MAX_DELEGATION_CHAIN_BYTES
    );

    let canonical_payload = data_encoding::BASE32_NOPAD
        .encode(&encoded)
        .to_ascii_lowercase();
    if payload != canonical_payload {
        bail!("relay proof is not in canonical form");
    }

    DelegationChain::<C>::decode(&encoded).context("invalid relay proof chain")
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;
    use rcan_v2::{Capability, Delegation, Expires};
    use serde::{Deserialize, Serialize};

    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_bytes(&[byte; 32])
    }

    fn relay_chain(depth: usize) -> DelegationChain<RelayCapability> {
        assert!((1..=iroh_rcan::MAX_DELEGATION_CHAIN_DEPTH).contains(&depth));

        let keys = (1..=depth + 1)
            .map(|index| key(index.try_into().unwrap()))
            .collect::<Vec<_>>();
        let owner = keys[0].as_signing_key();
        let capability = RelayCapability::new(ProjectId::from_bytes([7; 16]));
        let mut delegations = Vec::with_capacity(depth);
        delegations.push(
            Delegation::issuing_builder(
                owner,
                keys[1].as_signing_key().verifying_key(),
                &capability,
            )
            .sign(Expires::Never),
        );
        for index in 1..depth {
            delegations.push(
                Delegation::delegating_builder(
                    keys[index].as_signing_key(),
                    keys[index + 1].as_signing_key().verifying_key(),
                    owner.verifying_key(),
                    &capability,
                )
                .sign(Expires::Never),
            );
        }

        DelegationChain::new(delegations).unwrap()
    }

    fn printable_bytes(bytes: &[u8]) -> String {
        format!(
            "{PROOF_PREFIX}{}",
            data_encoding::BASE32_NOPAD
                .encode(bytes)
                .to_ascii_lowercase()
        )
    }

    #[test]
    fn capability_is_scoped_to_one_project() {
        let project_a = RelayCapability::new(ProjectId::from_bytes([0xaa; 16]));
        let project_b = RelayCapability::new(ProjectId::from_bytes([0xbb; 16]));

        assert!(project_a.permits(&project_a));
        assert!(!project_a.permits(&project_b));
    }

    #[test]
    fn capability_postcard_snapshot() {
        let capability = RelayCapability::new(ProjectId::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]));

        assert_eq!(
            postcard::to_stdvec(&capability).unwrap(),
            vec![
                0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f,
            ]
        );
    }

    #[test]
    fn printable_proof_roundtrips_maximum_chain_depth() {
        let chain = relay_chain(iroh_rcan::MAX_DELEGATION_CHAIN_DEPTH);
        assert_eq!(
            chain.delegations().len(),
            iroh_rcan::MAX_DELEGATION_CHAIN_DEPTH
        );

        let proof = encode_proof(&chain);
        let decoded = decode_proof::<RelayCapability>(&proof).unwrap();

        assert_eq!(decoded, chain);
        assert_eq!(encode_proof(&decoded), proof);
    }

    #[test]
    fn printable_proof_golden_fixture() {
        // This complete printable proof pins the envelope and the RCAN v2
        // delegation, signature, and capability bytes. Update only for an
        // intentional wire-format change.
        const PROOF: &str = concat!(
            "irp1_aebjkaicrkeohxlubhyzl7ks3mwtzos5olfgocn7dwkbeg7toseadnapn5oicolxb2uh2f27k2rvizwdjr7mzs4nrki",
            "3j3rxujo7md23r7e3hfaaaaiqabyha4dqobyha4dqobyha4dqob3q2zzbsshdzb6x5myqb7mx4becpb6p6dovjpgk5jdddq7",
            "535y7j3wmma5jvuvtd36hzguiqnu62txpuxyichqxokdl4fyw36njv6kalnibakats5yovb6rox2wunkgnq2mp3gmxdmksg2",
            "o4n5clx3a6w4pzgzzj3kjfddcruocy3vosazysbmzkyjjlettuxdd7e3dnqkgcswion6ragfiry65oqe7dfp5klns2pf2lvz",
            "muzyjx4ozieq36n2iqanub5xvyaaraadqobyha4dqobyha4dqobyha4dvi7spcg76vugcjpxtnwayurubnign3xuc5a3t6gw",
            "bqvyymsuwniu5u5un2csq7jz6kekdau2jihhpq44kg7el2i2c2vrcm4l4p7wpbu",
        );

        let chain = relay_chain(2);
        let payload = PROOF.strip_prefix(PROOF_PREFIX).unwrap();
        assert!(
            payload
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
        );
        assert_eq!(encode_proof(&chain), PROOF);
        assert_eq!(decode_proof::<RelayCapability>(PROOF).unwrap(), chain);
    }

    #[test]
    fn printable_proof_rejects_noncanonical_and_unbounded_inputs() {
        let proof = encode_proof(&relay_chain(3));
        assert!(decode_proof::<RelayCapability>(&proof.to_ascii_uppercase()).is_err());
        assert!(decode_proof::<RelayCapability>(&proof[PROOF_PREFIX.len()..]).is_err());

        let overlong = format!("{PROOF_PREFIX}{}", "a".repeat(MAX_PROOF_PAYLOAD_LEN + 1));
        assert!(decode_proof::<RelayCapability>(&overlong).is_err());
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    enum OtherCapability {
        Different,
    }

    #[test]
    fn printable_proof_rejects_wrong_capability_type() {
        let owner = key(10);
        let client = key(11);
        let delegation = Delegation::issuing_builder(
            owner.as_signing_key(),
            client.as_signing_key().verifying_key(),
            &OtherCapability::Different,
        )
        .sign(Expires::Never);
        let chain = DelegationChain::new(vec![delegation]).unwrap();
        let proof = encode_proof(&chain);

        assert!(decode_proof::<RelayCapability>(&proof).is_err());
    }

    #[test]
    fn printable_proof_rejects_malformed_chain() {
        let malformed = printable_bytes(&[1, 0]);
        assert!(decode_proof::<RelayCapability>(&malformed).is_err());
    }
}

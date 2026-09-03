//! Pins the wire encoding against the last released version.
//!
//! The ALPN is not bumped for additive protocol changes (see the versioning
//! policy on [`ALPN`]), so a client built from this crate has to keep talking
//! to a server built from `iroh-services` 1.0.0, and the other way around.
//! These tests encode the same logical value with both versions and compare
//! the postcard bytes, which is the only check that actually catches a silent
//! reshuffle of a field or a variant.
//!
//! A failure here means the change breaks deployed peers. Either revert the
//! shape change, or bump the ALPN and treat it as a new protocol.
//!
//! `iroh_services_v1` is the published 1.0.0 crate, before the wire types were
//! split out into `iroh-services-proto`, so its types live under
//! `iroh_services_v1::protocol` and `iroh_services_v1::caps`.
//!
//! Two things these tests do not reach. `PutMetrics` carries an
//! `iroh_metrics::encoding::Update`, which cannot be built from outside
//! `iroh-metrics`, and `DiagnosticsReport::net_report` carries iroh's
//! `NetReport`, which cannot be built from outside iroh. Both are re-encoded
//! as-is, so their stability is iroh's to keep, not ours. `NetReport` in
//! particular sits behind iroh's `unstable-net-report` feature and may change
//! in a minor release; see the note in Cargo.toml.

use ed25519_dalek::SigningKey;
use iroh_services_proto::{
    ALPN, Auth, CLIENT_HOST_ALPN, ClientHostProtocol, GrantCap, IrohServicesProtocol, NameEndpoint,
    Ping, Pong, PutNetworkDiagnostics, RemoteError, RemoteResult, RunNetworkDiagnostics,
    SetAttributes, SetGroup,
    caps::{Caps, MetricsCap, NetDiagnosticsCap, RelayCap},
    net_diagnostics::{DiagnosticsReport, PortMapProbe},
};
use iroh_services_v1::{caps as v1_caps, net_diagnostics as v1_diag, protocol as v1};
use rcan::{Expires, Rcan};
use serde::Serialize;

/// Fixed so the rcan signatures below are deterministic.
const EXPIRES_AT: Expires = Expires::At(1_700_000_000);

#[track_caller]
fn assert_same_encoding(what: &str, v1_value: &impl Serialize, current: &impl Serialize) {
    let expected = postcard::to_stdvec(v1_value).expect("v1 encode");
    let actual = postcard::to_stdvec(current).expect("encode");
    assert_eq!(
        expected, actual,
        "{what}: the encoding changed since iroh-services 1.0.0\n  \
         v1.0.0:  {expected:02x?}\n  current: {actual:02x?}"
    );
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn endpoint_id(seed: u8) -> iroh::EndpointId {
    iroh::EndpointId::from_bytes(signing_key(seed).verifying_key().as_bytes()).expect("valid key")
}

/// Every capability set, paired with the v1 value it has to match.
///
/// The capability set is the payload of the signed rcan, so a change here
/// invalidates every token a v1 peer has already issued.
fn capability_sets() -> Vec<(&'static str, v1_caps::Caps, Caps)> {
    vec![
        ("all", v1_caps::Caps::all(), Caps::all()),
        (
            "client",
            v1_caps::Caps::for_shared_secret(),
            Caps::for_shared_secret(),
        ),
        (
            "relay:use",
            v1_caps::Caps::new([v1_caps::RelayCap::Use]),
            Caps::new([RelayCap::Use]),
        ),
        (
            "metrics:put-any",
            v1_caps::Caps::new([v1_caps::MetricsCap::PutAny]),
            Caps::new([MetricsCap::PutAny]),
        ),
        (
            "net-diagnostics:get-any",
            v1_caps::Caps::new([v1_caps::NetDiagnosticsCap::GetAny]),
            Caps::new([NetDiagnosticsCap::GetAny]),
        ),
        (
            "net-diagnostics:put-any",
            v1_caps::Caps::new([v1_caps::NetDiagnosticsCap::PutAny]),
            Caps::new([NetDiagnosticsCap::PutAny]),
        ),
        (
            "several caps",
            v1_caps::Caps::new([v1_caps::MetricsCap::PutAny]).extend([v1_caps::RelayCap::Use]),
            Caps::new([MetricsCap::PutAny]).extend([RelayCap::Use]),
        ),
        ("empty", v1_caps::Caps::default(), Caps::default()),
    ]
}

fn v1_report() -> v1_diag::DiagnosticsReport {
    v1_diag::DiagnosticsReport {
        endpoint_id: endpoint_id(3),
        // A NetReport cannot be constructed from outside iroh, so this leaves
        // the field empty. Its contents are iroh's unstable type, which this
        // crate re-encodes as-is; see the note in Cargo.toml.
        net_report: None,
        direct_addrs: vec!["192.0.2.1:1234".parse().unwrap()],
        portmap_probe: Some(v1_diag::PortMapProbe {
            upnp: true,
            pcp: false,
            nat_pmp: true,
        }),
        iroh_version: "1.0.0".into(),
        iroh_services_version: "1.0.0".into(),
    }
}

fn report() -> DiagnosticsReport {
    DiagnosticsReport {
        endpoint_id: endpoint_id(3),
        net_report: None,
        direct_addrs: vec!["192.0.2.1:1234".parse().unwrap()],
        portmap_probe: Some(PortMapProbe {
            upnp: true,
            pcp: false,
            nat_pmp: true,
        }),
        iroh_version: "1.0.0".into(),
        iroh_services_version: "1.0.0".into(),
    }
}

#[test]
fn test_alpns_unchanged() {
    assert_eq!(v1::ALPN, ALPN);
    assert_eq!(iroh_services_v1::CLIENT_HOST_ALPN, CLIENT_HOST_ALPN);
}

#[test]
fn test_caps_encoding_matches_v1() {
    for (name, v1_caps, caps) in capability_sets() {
        assert_same_encoding(name, &v1_caps, &caps);
    }
}

/// Capabilities must also survive the trip in both directions, not just encode
/// to the same bytes: a v1 peer decodes what we send, and we decode what it
/// sends back.
#[test]
fn test_caps_decode_across_versions() {
    for (name, v1_caps, caps) in capability_sets() {
        let v1_bytes = postcard::to_stdvec(&v1_caps).expect("v1 encode");
        let bytes = postcard::to_stdvec(&caps).expect("encode");

        let decoded: Caps = postcard::from_bytes(&v1_bytes)
            .unwrap_or_else(|err| panic!("{name}: cannot decode v1 caps: {err}"));
        assert_eq!(decoded, caps, "{name}: decoding v1 caps changed the value");

        let decoded: v1_caps::Caps = postcard::from_bytes(&bytes)
            .unwrap_or_else(|err| panic!("{name}: v1 cannot decode our caps: {err}"));
        assert_eq!(
            decoded, v1_caps,
            "{name}: v1 decoding our caps changed the value"
        );
    }
}

/// The signed token itself, which is what `Auth` carries.
#[test]
fn test_auth_token_encoding_matches_v1() {
    for (name, v1_caps, caps) in capability_sets() {
        let v1_token =
            Rcan::issuing_builder(&signing_key(1), signing_key(2).verifying_key(), v1_caps)
                .sign(EXPIRES_AT);
        let token = Rcan::issuing_builder(&signing_key(1), signing_key(2).verifying_key(), caps)
            .sign(EXPIRES_AT);
        assert_eq!(
            v1_token.encode(),
            token.encode(),
            "{name}: the signed rcan changed since iroh-services 1.0.0"
        );
    }
}

#[test]
fn test_request_encoding_matches_v1() {
    let v1_token = Rcan::issuing_builder(
        &signing_key(1),
        signing_key(2).verifying_key(),
        v1_caps::Caps::all(),
    )
    .sign(EXPIRES_AT);
    let token = Rcan::issuing_builder(&signing_key(1), signing_key(2).verifying_key(), Caps::all())
        .sign(EXPIRES_AT);

    assert_same_encoding(
        "Auth",
        &v1::IrohServicesProtocol::Auth(v1::Auth {
            caps: v1_token.clone(),
        }),
        &IrohServicesProtocol::Auth(Auth {
            caps: token.clone(),
        }),
    );
    assert_same_encoding(
        "Ping",
        &v1::IrohServicesProtocol::Ping(v1::Ping { req_id: [7; 16] }),
        &IrohServicesProtocol::Ping(Ping { req_id: [7; 16] }),
    );
    assert_same_encoding(
        "GrantCap",
        &v1::IrohServicesProtocol::GrantCap(v1::GrantCap { cap: v1_token }),
        &IrohServicesProtocol::GrantCap(GrantCap { cap: token }),
    );
    assert_same_encoding(
        "NameEndpoint",
        &v1::IrohServicesProtocol::NameEndpoint(v1::NameEndpoint {
            name: "node-1".into(),
        }),
        &IrohServicesProtocol::NameEndpoint(NameEndpoint {
            name: "node-1".into(),
        }),
    );
    assert_same_encoding(
        "PutNetworkDiagnostics",
        &v1::IrohServicesProtocol::PutNetworkDiagnostics(v1::PutNetworkDiagnostics {
            report: v1_report(),
        }),
        &IrohServicesProtocol::PutNetworkDiagnostics(PutNetworkDiagnostics { report: report() }),
    );
    assert_same_encoding(
        "RunNetworkDiagnostics",
        &v1::ClientHostProtocol::RunNetworkDiagnostics(v1::RunNetworkDiagnostics),
        &ClientHostProtocol::RunNetworkDiagnostics(RunNetworkDiagnostics),
    );
}

#[test]
fn test_response_encoding_matches_v1() {
    assert_same_encoding(
        "Pong",
        &v1::Pong { req_id: [9; 16] },
        &Pong { req_id: [9; 16] },
    );
    assert_same_encoding("DiagnosticsReport", &v1_report(), &report());
    assert_same_encoding(
        "RemoteResult::Ok",
        &v1::RemoteResult::<()>::Ok(()),
        &RemoteResult::<()>::Ok(()),
    );
    assert_same_encoding(
        "RemoteResult::Err",
        &v1::RemoteResult::<()>::Err(v1::RemoteError::InternalServerError),
        &RemoteResult::<()>::Err(RemoteError::InternalServerError),
    );
}

/// The three [`RemoteError`] variants a v1 peer knows, at their original
/// positions.
#[test]
fn test_remote_error_encoding_matches_v1() {
    assert_same_encoding(
        "MissingCapability",
        &v1::RemoteError::MissingCapability(v1_caps::Caps::new([v1_caps::RelayCap::Use])),
        &RemoteError::MissingCapability(Caps::new([RelayCap::Use])),
    );
    assert_same_encoding(
        "AuthError",
        &v1::RemoteError::AuthError("nope".into()),
        &RemoteError::AuthError("nope".into()),
    );
    assert_same_encoding(
        "InternalServerError",
        &v1::RemoteError::InternalServerError,
        &RemoteError::InternalServerError,
    );
}

/// Variants added after 1.0.0 must fail to decode on a v1 peer rather than be
/// read as one of the variants it does know. This is what makes appending
/// safe: a v1 server rejects a request it cannot handle instead of acting on
/// the wrong one.
#[test]
fn test_v1_peer_rejects_variants_added_since() {
    let requests = [
        (
            "SetGroup",
            postcard::to_stdvec(&IrohServicesProtocol::SetGroup(SetGroup {
                group: "staging".into(),
            }))
            .expect("encode"),
        ),
        (
            "SetAttributes",
            postcard::to_stdvec(&IrohServicesProtocol::SetAttributes(SetAttributes {
                attributes: Default::default(),
            }))
            .expect("encode"),
        ),
    ];
    for (name, bytes) in requests {
        let decoded = postcard::from_bytes::<v1::IrohServicesProtocol>(&bytes);
        assert!(
            decoded.is_err(),
            "{name} decodes on a v1 peer as {decoded:?}: its variant index collides with a v1 request"
        );
    }

    let errors = [
        (
            "InvalidInput",
            postcard::to_stdvec(&RemoteError::InvalidInput("x".into())).expect("encode"),
        ),
        (
            "RateLimited",
            postcard::to_stdvec(&RemoteError::RateLimited).expect("encode"),
        ),
    ];
    for (name, bytes) in errors {
        let decoded = postcard::from_bytes::<v1::RemoteError>(&bytes);
        assert!(
            decoded.is_err(),
            "{name} decodes on a v1 peer as {decoded:?}: its variant index collides with a v1 error"
        );
    }
}

use std::time::Duration;

use anyhow::Result;
use iroh::protocol::Router;
use iroh::{Endpoint, NodeAddr, NodeId};
use iroh_blobs::BlobFormat;
use iroh_services::Client;
use ssh_key::Algorithm;
use tracing::debug;

#[tokio::main]
pub async fn main() -> Result<()> {
    // Create ssh key for alice
    let mut rng = rand::rngs::OsRng;

    let alice_ssh_key = ssh_key::PrivateKey::random(&mut rng, Algorithm::Ed25519)?;

    println!("SSH Key: {}", alice_ssh_key.public_key().to_openssh()?);

    let client_endpoint = Endpoint::builder().discovery_n0().bind().await?;
    let client_blobs = iroh_blobs::net_protocol::Blobs::memory().build(&client_endpoint);

    let client_router = Router::builder(client_endpoint)
        .accept(iroh_blobs::ALPN, client_blobs.clone())
        .spawn()
        .await?;
    let client_node_id = client_router.endpoint().node_id();
    debug!("local node: {}", client_node_id,);

    let remote_node_id: NodeId = std::env::args().nth(1).unwrap().parse()?;
    let node_addr: NodeAddr = remote_node_id.into();

    println!("press ctrl+c once your sshkey is registerd");
    tokio::signal::ctrl_c().await?;

    // Create iroh services client
    let mut rpc_client = Client::builder(client_router.endpoint())
        .metrics_interval(Duration::from_secs(2))
        .ssh_key(&alice_ssh_key)?
        .build(node_addr.clone())
        .await?;

    // add blob on the client
    let client_blob = client_blobs.client().add_bytes("hello world").await?;

    // upload the blob
    let client_addr = client_router.endpoint().node_addr().await?;
    rpc_client
        .put_blob(
            client_addr,
            client_blob.hash,
            BlobFormat::Raw,
            "my-blob.txt".into(),
        )
        .await?;

    println!("waiting for Ctrl+C..");
    tokio::signal::ctrl_c().await?;

    client_router.shutdown().await?;

    Ok(())
}

//! A simple load test for iroh-services relays: binds one server endpoint and N client
//! endpoints in the same process, then either transfers data at full speed or pings
//! the server at a fixed interval, for a set duration.
//!
//! All endpoints are bound through the iroh-services [`preset`] and registered under
//! [`Client`] names (`LoadTest-{label}-Server` / `LoadTest-{label}-Client-{n}`) so they
//! show up in the iroh-services dashboard.
//!
//! With `--save`, the server's and clients' secret keys are written to a JSON file so
//! that a later run with `--load` reuses the same endpoint ids instead of generating
//! fresh ones.
//!
//! By default, every endpoint also runs a [`ClientHost`] and grants the iroh-services
//! project the capability to request network diagnostics from it, so you can inspect
//! connectivity for any of the load test's endpoints from the dashboard. Pass
//! `--no-diagnostics` to skip this.
//!
//! # Environment variables
//!
//! - `IROH_SERVICES_API_SECRET`: the API secret from your iroh services project. This
//!   is the only thing required to run the load test.
//! - `IROH_RELAYS`: a comma-separated list of relay URLs to use instead of the default
//!   public relay map. Custom relays require a pro or enterprise project.
//!
//! # Examples
//!
//! Run the default load test: one server, 10 clients, downloading at full speed for
//! 30 seconds.
//!
//! ```sh
//! export IROH_SERVICES_API_SECRET=your_api_secret_here
//! cargo run --example load_test
//! ```
//!
//! Ping 20 clients against the server every 200ms with a 64 byte payload for a minute:
//!
//! ```sh
//! cargo run --example load_test -- --clients 20 --mode ping --interval 200ms --size 64 --duration 1m
//! ```
//!
//! Upload and download simultaneously, capped at 1 MiB/s per client:
//!
//! ```sh
//! cargo run --example load_test -- --bidi --max-speed 1MiB
//! ```
//!
//! Save endpoint identities on first run, then reuse them on the next:
//!
//! ```sh
//! cargo run --example load_test -- --save run.json
//! cargo run --example load_test -- --load run.json
//! ```
//!
//! [`preset`]: iroh_services::preset
//! [`Client`]: iroh_services::Client
//! [`ClientHost`]: iroh_services::ClientHost
use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use data_encoding::HEXLOWER;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayUrl, SecretKey,
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_services::{
    CLIENT_HOST_ALPN, Client, ClientHost, IrohServicesPreset, caps::NetDiagnosticsCap,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
    time::{self, MissedTickBehavior},
};
use tracing::{debug, warn};

/// ALPN for the load-test protocol.
const LOAD_ALPN: &[u8] = b"n0/iroh-services/load-test/1";

/// Chunk size used for full-speed reads and writes.
const CHUNK_SIZE: usize = 64 * 1024;

/// Upper bound for an encoded [`Request`], to sanity-check the length prefix.
const MAX_REQUEST_LEN: usize = 64;

/// Run a load test against a single, in-process iroh-services server endpoint.
#[derive(Debug, Clone, Parser)]
struct Cli {
    /// Number of simulated client endpoints to spawn against the server.
    #[clap(long, short = 'n', default_value_t = 10)]
    clients: usize,

    /// Test mode: transfer data continuously, or send periodic pings.
    #[clap(long, value_enum, default_value_t = Mode::Transfer)]
    mode: Mode,

    /// How long to run the load test. Accepts human-readable durations like "30s",
    /// "5m", or "1h".
    #[clap(long, value_parser = parse_duration, default_value = "30s")]
    duration: Duration,

    /// Ping interval. Accepts human-readable durations like "500ms" or "1s".
    /// Only used with `--mode ping`.
    #[clap(long, value_parser = parse_duration, default_value = "1s")]
    interval: Duration,

    /// Ping payload size. Accepts human-readable byte sizes like "32", "1K", "4KiB".
    /// Only used with `--mode ping`.
    #[clap(long, value_parser = parse_byte_size, default_value = "32")]
    size: u64,

    /// Cap the transfer speed, per client and per direction. Accepts human-readable
    /// byte sizes like "1M" or "500KiB". If unset, transfers run at full speed. Only
    /// used with `--mode transfer`.
    #[clap(long, value_parser = parse_byte_size)]
    max_speed: Option<u64>,

    /// Clients upload data to the server.
    #[clap(long, conflicts_with_all = ["download", "bidi"])]
    upload: bool,

    /// Clients download data from the server. This is the default.
    #[clap(long, conflicts_with_all = ["upload", "bidi"])]
    download: bool,

    /// Clients upload and download data simultaneously.
    #[clap(long, conflicts_with_all = ["upload", "download"])]
    bidi: bool,

    /// Label used to build iroh-services client names: `LoadTest-{label}-Server` and
    /// `LoadTest-{label}-Client-{n}`.
    #[clap(long, default_value = "default")]
    label: String,

    /// Interval at which endpoint metrics are pushed to iroh-services. Accepts
    /// human-readable durations like "5s" or "1m".
    #[clap(long, value_parser = parse_duration, default_value = "5s")]
    metrics_interval: Duration,

    /// Save the server's and clients' secret keys to this file, so a later run with
    /// `--load` can reuse the same endpoint ids.
    #[clap(long)]
    save: Option<PathBuf>,

    /// Load the server's and clients' secret keys from a file previously written with
    /// `--save`, instead of generating fresh ones.
    #[clap(long)]
    load: Option<PathBuf>,

    /// Disable remote network diagnostics. By default every endpoint runs a
    /// ClientHost and grants the iroh-services project the capability to request
    /// diagnostics from it.
    #[clap(long)]
    no_diagnostics: bool,

    /// Disable direct IP transports, so all traffic flows through the relays.
    #[clap(long)]
    relay_only: bool,
}

/// Parses a byte size like "32", "1K", or "4MiB" into a byte count.
fn parse_byte_size(s: &str) -> Result<u64, parse_size::Error> {
    parse_size::Config::new().with_binary().parse_size(s)
}

/// Parses a human-readable duration like "500ms", "5s", or "1m".
fn parse_duration(s: &str) -> Result<Duration, humantime::DurationError> {
    humantime::parse_duration(s)
}

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
enum Mode {
    /// Send periodic pings and measure round-trip time.
    Ping,
    /// Transfer data continuously.
    #[default]
    Transfer,
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Upload,
    Download,
    Bidi,
}

impl Direction {
    fn from_cli(cli: &Cli) -> Self {
        if cli.upload {
            Direction::Upload
        } else if cli.bidi {
            Direction::Bidi
        } else {
            Direction::Download
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let direction = Direction::from_cli(&cli);

    let mut identities = Identities::load_or_generate(cli.load.as_deref())?;
    identities.ensure_clients(cli.clients);
    if let Some(path) = &cli.save {
        identities.save(path)?;
        println!("Saved endpoint identities to {}", path.display());
    }

    let relay_urls = relay_urls_from_env()?;
    match &relay_urls {
        Some(urls) => println!(
            "Using custom relay map:\n\t- {}",
            urls.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n\t- ")
        ),
        None => println!("Using default relay map"),
    }

    let server_preset = iroh_services::preset()
        .api_secret_from_env()?
        .secret_key(identities.server_key()?)
        .relay_map(fresh_relay_map(relay_urls.as_deref()))
        .build()?;
    let server_endpoint = bind_endpoint(server_preset.clone(), cli.relay_only).await?;
    println!("Server endpoint id: {}", server_endpoint.id());
    server_endpoint.online().await;
    println!("Server is online.");

    // The services client pushes endpoint metrics for the whole run; dropping it
    // would stop the push, so it stays alive until main returns.
    let server_client = server_preset
        .client_builder(&server_endpoint)
        .metrics_interval(cli.metrics_interval)
        .build()
        .await?;
    // Await naming confirmation so a failure surfaces here instead of the server
    // showing up in the dashboard under a default label.
    server_client
        .set_name(format!("LoadTest-{}-Server", cli.label))
        .await?;

    // Unless disabled, every endpoint runs a ClientHost and grants the iroh-services
    // project the capability to request network diagnostics from it.
    let diagnostics_remote = (!cli.no_diagnostics).then(|| server_preset.api_secret().addr().id);

    let mut router = Router::builder(server_endpoint.clone()).accept(LOAD_ALPN, LoadServer);
    if let Some(remote_id) = diagnostics_remote {
        router = router.accept(CLIENT_HOST_ALPN, ClientHost::new(&server_endpoint));
        spawn_diagnostics_grant(&server_client, remote_id);
    }
    let router = router.spawn();

    println!(
        "Starting load test: {} client(s), mode {:?}, duration {:?}",
        cli.clients, cli.mode, cli.duration
    );

    let mut tasks = JoinSet::new();
    let client_keys = identities.client_keys(cli.clients)?;
    for (index, secret_key) in client_keys.into_iter().enumerate() {
        tasks.spawn(run_client(
            index,
            secret_key,
            relay_urls.clone(),
            server_endpoint.addr(),
            cli.clone(),
            diagnostics_remote,
        ));
    }

    let mut results = Vec::new();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(Ok(stats)) => results.push(stats),
            Ok(Err(err)) => eprintln!("client failed: {err:#}"),
            Err(err) => eprintln!("client task panicked: {err:#}"),
        }
    }
    print_summary(&cli, direction, &results);

    router.shutdown().await?;
    Ok(())
}

/// Hex-encoded secret keys for the server and clients, persisted with `--save` and
/// `--load` so endpoint ids stay stable across runs.
#[derive(Debug, Serialize, Deserialize)]
struct Identities {
    server: String,
    clients: Vec<String>,
}

impl Identities {
    /// Loads identities from `path`, or generates a fresh server identity.
    fn load_or_generate(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(path) => {
                let data = std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                serde_json::from_str(&data)
                    .with_context(|| format!("failed to parse {}", path.display()))
            }
            None => Ok(Self {
                server: encode_secret(&SecretKey::generate()),
                clients: Vec::new(),
            }),
        }
    }

    /// Generates additional client identities until at least `n` exist.
    fn ensure_clients(&mut self, n: usize) {
        while self.clients.len() < n {
            self.clients.push(encode_secret(&SecretKey::generate()));
        }
    }

    fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
    }

    fn server_key(&self) -> Result<SecretKey> {
        decode_secret(&self.server)
    }

    fn client_keys(&self, n: usize) -> Result<Vec<SecretKey>> {
        self.clients[..n].iter().map(|s| decode_secret(s)).collect()
    }
}

fn encode_secret(key: &SecretKey) -> String {
    HEXLOWER.encode(&key.to_bytes())
}

fn decode_secret(s: &str) -> Result<SecretKey> {
    SecretKey::from_str(s).context("invalid secret key hex")
}

/// Reads relay URLs from `IROH_RELAYS`. Returns `None` to use the default relays.
fn relay_urls_from_env() -> Result<Option<Vec<RelayUrl>>> {
    match std::env::var("IROH_RELAYS") {
        Ok(value) if !value.is_empty() => value
            .split(',')
            .map(|url| {
                url.trim()
                    .parse::<RelayUrl>()
                    .with_context(|| format!("failed to parse relay URL: {url}"))
            })
            .collect::<Result<Vec<_>>>()
            .map(Some),
        _ => Ok(None),
    }
}

/// Binds an endpoint from `preset`, without IP transports if `relay_only` is set.
async fn bind_endpoint(preset: IrohServicesPreset, relay_only: bool) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(preset);
    if relay_only {
        builder = builder.clear_ip_transports();
    }
    Ok(builder.bind().await?)
}

/// Builds a relay map from custom URLs, or the default public relay map.
///
/// Each preset needs a fresh map: `RelayMap` clones share their inner state, and
/// the preset writes an endpoint-specific auth token into the map it is given.
/// Sharing one map would leave every endpoint with the token of whichever preset
/// was built last, and the relays would reject all others.
fn fresh_relay_map(urls: Option<&[RelayUrl]>) -> RelayMap {
    match urls {
        Some(urls) => RelayMap::from_iter(urls.iter().cloned()),
        None => iroh::defaults::prod::default_relay_map(),
    }
}

/// Grants the iroh-services project at `remote_id` the capability to request network
/// diagnostics from `client`'s endpoint. Runs in the background so it does not delay
/// the caller; failures are only logged.
fn spawn_diagnostics_grant(client: &Client, remote_id: EndpointId) {
    let client = client.clone();
    tokio::spawn(async move {
        if let Err(err) = client
            .grant_capability(remote_id, vec![NetDiagnosticsCap::GetAny])
            .await
        {
            warn!("failed to grant diagnostics capability: {err:#}");
        }
    });
}

/// Binds one client endpoint, connects it to the server, and runs the configured
/// mode until the test duration elapses.
async fn run_client(
    index: usize,
    secret_key: SecretKey,
    relay_urls: Option<Vec<RelayUrl>>,
    server_addr: EndpointAddr,
    cli: Cli,
    diagnostics_remote: Option<EndpointId>,
) -> Result<ClientStats> {
    let name = format!("LoadTest-{}-Client-{index}", cli.label);

    let preset = iroh_services::preset()
        .api_secret_from_env()?
        .secret_key(secret_key)
        .relay_map(fresh_relay_map(relay_urls.as_deref()))
        .build()?;
    let endpoint = bind_endpoint(preset.clone(), cli.relay_only).await?;
    endpoint.online().await;

    let client = preset
        .client_builder(&endpoint)
        .metrics_interval(cli.metrics_interval)
        .build()
        .await?;
    // Await naming confirmation, as for the server.
    client.set_name(name.clone()).await?;

    let diagnostics_router = diagnostics_remote.map(|remote_id| {
        spawn_diagnostics_grant(&client, remote_id);
        Router::builder(endpoint.clone())
            .accept(CLIENT_HOST_ALPN, ClientHost::new(&endpoint))
            .spawn()
    });

    let conn = endpoint.connect(server_addr, LOAD_ALPN).await?;
    let stats = match cli.mode {
        Mode::Ping => {
            ClientStats::Ping(run_ping_client(&conn, cli.size, cli.interval, cli.duration).await?)
        }
        Mode::Transfer => ClientStats::Transfer(
            run_transfer_client(
                &conn,
                Direction::from_cli(&cli),
                cli.duration,
                cli.max_speed,
            )
            .await?,
        ),
    };
    conn.close(0u32.into(), b"done");
    println!("[{name}] {stats}");

    if let Some(router) = diagnostics_router {
        router.shutdown().await?;
    }
    Ok(stats)
}

/// Pings the server every `interval` until `duration` elapses.
async fn run_ping_client(
    conn: &Connection,
    size: u64,
    interval: Duration,
    duration: Duration,
) -> Result<PingStats> {
    let mut stats = PingStats::default();
    let deadline = time::Instant::now() + duration;
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    while time::timeout_at(deadline, ticker.tick()).await.is_ok() {
        match ping_once(conn, size).await {
            Ok(rtt) => stats.record(rtt),
            Err(err) => warn!("ping failed: {err:#}"),
        }
    }
    Ok(stats)
}

/// Opens a stream, sends a `size` byte payload, and waits for the server to echo it
/// back. Returns the round-trip time.
async fn ping_once(conn: &Connection, size: u64) -> Result<Duration> {
    let payload = vec![0xAA; size as usize];
    let (mut send, mut recv) = conn.open_bi().await?;

    let start = Instant::now();
    Request::Ping { size }.write(&mut send).await?;
    send.write_all(&payload).await?;
    send.finish()?;

    let response = recv.read_to_end(payload.len()).await?;
    ensure!(
        response.len() == payload.len(),
        "unexpected ping response size: got {} want {}",
        response.len(),
        payload.len()
    );
    Ok(start.elapsed())
}

/// Runs one transfer in the given direction, returning per-client statistics.
async fn run_transfer_client(
    conn: &Connection,
    direction: Direction,
    duration: Duration,
    max_speed: Option<u64>,
) -> Result<TransferStats> {
    let start = Instant::now();
    let (sent, received) = match direction {
        Direction::Upload => (upload(conn, duration, max_speed).await?, 0),
        Direction::Download => (0, download(conn, duration, max_speed).await?),
        Direction::Bidi => tokio::try_join!(
            upload(conn, duration, max_speed),
            download(conn, duration, max_speed)
        )?,
    };
    Ok(TransferStats {
        sent,
        received,
        elapsed: start.elapsed(),
    })
}

/// Opens a stream and sends data to the server for `duration`. Returns bytes sent.
async fn upload(conn: &Connection, duration: Duration, max_speed: Option<u64>) -> Result<u64> {
    let (mut send, mut recv) = conn.open_bi().await?;
    Request::Upload.write(&mut send).await?;
    let sent = send_data(&mut send, duration, max_speed).await?;
    send.finish()?;
    // The server finishes its side once it has read everything; waiting for that
    // keeps us from closing the connection while data is still in flight.
    recv.read_to_end(0).await?;
    Ok(sent)
}

/// Opens a stream and requests data from the server. Returns bytes received.
async fn download(conn: &Connection, duration: Duration, max_speed: Option<u64>) -> Result<u64> {
    let (mut send, mut recv) = conn.open_bi().await?;
    Request::Download {
        duration,
        max_speed,
    }
    .write(&mut send)
    .await?;
    let received = read_until_eof(&mut recv).await?;
    // Finishing after the drain confirms receipt to the server.
    send.finish()?;
    Ok(received)
}

/// A request, postcard-encoded with a length prefix as the first bytes of every
/// client-opened stream.
#[derive(Debug, Serialize, Deserialize)]
enum Request {
    /// Echo back the `size` payload bytes that follow the request.
    Ping { size: u64 },
    /// Read data until the client finishes the stream.
    Upload,
    /// Send data for `duration`, throttled to `max_speed` bytes per second if set.
    Download {
        duration: Duration,
        max_speed: Option<u64>,
    },
}

impl Request {
    async fn write(&self, send: &mut SendStream) -> Result<()> {
        let buf = postcard::to_stdvec(self)?;
        send.write_u32(buf.len() as u32).await?;
        send.write_all(&buf).await?;
        Ok(())
    }

    async fn read(recv: &mut RecvStream) -> Result<Self> {
        let len = recv.read_u32().await? as usize;
        ensure!(len <= MAX_REQUEST_LEN, "request too large: {len} bytes");
        let mut buf = vec![0; len];
        recv.read_exact(&mut buf).await?;
        Ok(postcard::from_bytes(&buf)?)
    }
}

/// Sends `0xAB` filled chunks for up to `duration`, throttled to `max_speed` bytes
/// per second if set. Returns the number of bytes written.
async fn send_data(
    send: &mut SendStream,
    duration: Duration,
    max_speed: Option<u64>,
) -> Result<u64> {
    let chunk = vec![0xAB; CHUNK_SIZE];
    let start = Instant::now();
    let mut total = 0u64;

    // The send ends when the duration elapses (cancelling mid-write) or when the
    // peer goes away.
    let _ = time::timeout(duration, async {
        loop {
            if let Some(limit) = max_speed {
                // Sleep off any lead over the byte budget for the elapsed time.
                let budget = (start.elapsed().as_secs_f64() * limit as f64) as u64;
                if total > budget {
                    let lead = (total - budget) as f64;
                    time::sleep(Duration::from_secs_f64(lead / limit as f64)).await;
                }
            }
            if let Err(err) = send.write_all(&chunk).await {
                debug!("send stream ended early: {err:#}");
                break;
            }
            total += CHUNK_SIZE as u64;
        }
    })
    .await;

    Ok(total)
}

/// Reads from `recv` until the peer finishes the stream. Returns bytes read.
async fn read_until_eof(recv: &mut RecvStream) -> Result<u64> {
    let mut buf = vec![0; CHUNK_SIZE];
    let mut total = 0u64;
    while let Some(n) = recv.read(&mut buf).await? {
        total += n as u64;
    }
    Ok(total)
}

/// The load-test server: accepts client connections and answers one [`Request`] per
/// client-opened stream.
#[derive(Debug, Clone)]
struct LoadServer;

impl ProtocolHandler for LoadServer {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        debug!(remote = %connection.remote_id().fmt_short(), "client connected");
        // The JoinSet owns the stream handlers: when the client closes the
        // connection the loop ends and in-flight handlers are aborted with it.
        let mut handlers = JoinSet::new();
        while let Ok((send, recv)) = connection.accept_bi().await {
            handlers.spawn(async move {
                if let Err(err) = handle_stream(send, recv).await {
                    warn!("stream handler failed: {err:#}");
                }
            });
        }
        Ok(())
    }
}

/// Serves a single client-opened stream: reads the request and answers it.
async fn handle_stream(mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    match Request::read(&mut recv).await? {
        Request::Ping { size } => {
            let payload = recv.read_to_end(size as usize).await?;
            send.write_all(&payload).await?;
            send.finish()?;
        }
        Request::Upload => {
            read_until_eof(&mut recv).await?;
            // Finish only after draining: the client waits for this as confirmation
            // that its data arrived before closing the connection.
            send.finish()?;
        }
        Request::Download {
            duration,
            max_speed,
        } => {
            send_data(&mut send, duration, max_speed).await?;
            send.finish()?;
            // Wait for the client to confirm receipt (it finishes after draining).
            recv.read_to_end(0).await?;
        }
    }
    Ok(())
}

/// Per-client results, printed individually and merged into the final summary.
#[derive(Debug, Clone, Copy)]
enum ClientStats {
    Ping(PingStats),
    Transfer(TransferStats),
}

impl fmt::Display for ClientStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientStats::Ping(stats) => stats.fmt(f),
            ClientStats::Transfer(stats) => stats.fmt(f),
        }
    }
}

/// Round-trip time statistics for one client, mergeable across clients.
#[derive(Debug, Clone, Copy, Default)]
struct PingStats {
    count: u64,
    min: Duration,
    max: Duration,
    sum: Duration,
}

impl PingStats {
    fn record(&mut self, rtt: Duration) {
        self.merge(&Self {
            count: 1,
            min: rtt,
            max: rtt,
            sum: rtt,
        });
    }

    fn merge(&mut self, other: &Self) {
        if other.count == 0 {
            return;
        }
        self.min = if self.count == 0 {
            other.min
        } else {
            self.min.min(other.min)
        };
        self.max = self.max.max(other.max);
        self.sum += other.sum;
        self.count += other.count;
    }
}

impl fmt::Display for PingStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.count == 0 {
            return write!(f, "no pings completed");
        }
        let avg = self.sum / self.count as u32;
        write!(
            f,
            "{} pings, rtt min {:?} avg {avg:?} max {:?}",
            self.count, self.min, self.max
        )
    }
}

/// Transferred byte counts for one client, mergeable across clients.
#[derive(Debug, Clone, Copy, Default)]
struct TransferStats {
    sent: u64,
    received: u64,
    elapsed: Duration,
}

impl TransferStats {
    fn merge(&mut self, other: &Self) {
        self.sent += other.sent;
        self.received += other.received;
        self.elapsed = self.elapsed.max(other.elapsed);
    }
}

impl fmt::Display for TransferStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sent {} ({}), received {} ({}) in {:?}",
            human_bytes(self.sent as f64),
            human_rate(self.sent, self.elapsed),
            human_bytes(self.received as f64),
            human_rate(self.received, self.elapsed),
            self.elapsed,
        )
    }
}

/// Prints merged statistics for all clients.
fn print_summary(cli: &Cli, direction: Direction, results: &[ClientStats]) {
    println!("\n=== Load test summary ===");
    println!(
        "clients: {}, mode: {:?}, duration: {:?}",
        cli.clients, cli.mode, cli.duration
    );
    match cli.mode {
        Mode::Ping => {
            let mut totals = PingStats::default();
            for stats in results {
                if let ClientStats::Ping(stats) = stats {
                    totals.merge(stats);
                }
            }
            println!("{totals}");
        }
        Mode::Transfer => {
            let max_speed = match cli.max_speed {
                Some(limit) => format!("{}/s", human_bytes(limit as f64)),
                None => "unlimited".into(),
            };
            println!("direction: {direction:?}, max speed: {max_speed}");
            let mut totals = TransferStats::default();
            for stats in results {
                if let ClientStats::Transfer(stats) = stats {
                    totals.merge(stats);
                }
            }
            println!("{totals}");
        }
    }
}

/// Formats a byte count with a binary (KiB/MiB/...) unit suffix.
fn human_bytes(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

/// Formats a transfer rate in bytes per second over `elapsed`.
fn human_rate(bytes: u64, elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64().max(0.001);
    format!("{}/s", human_bytes(bytes as f64 / secs))
}

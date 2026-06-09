# iroh-services

[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square)](https://docs.rs/iroh-services/)
[![Crates.io](https://img.shields.io/crates/v/iroh-services.svg?style=flat-square)](https://crates.io/crates/iroh-services)
[![downloads](https://img.shields.io/crates/d/iroh-services.svg?style=flat-square)](https://crates.io/crates/iroh-services)
[![Chat](https://img.shields.io/discord/1161119546170687619?logo=discord&style=flat-square)](https://discord.com/invite/DpmJgtU7cW)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE-APACHE)
[![CI](https://img.shields.io/github/actions/workflow/status/n0-computer/iroh-services/ci.yaml?branch=main&style=flat-square&label=CI)](https://github.com/n0-computer/iroh-services/actions/workflows/ci.yaml)

The client library for **[iroh-services]** — a cloud hub that gives you
visibility into, and control over, a fleet of running [iroh] endpoints.

You add this crate to your application, point it at your iroh-services project
with an API secret, and your endpoint connects to the hub **over iroh itself**
— no extra ports or sidecars. From there the endpoint streams metrics to the
hub, and (when you allow it) the hub can call back to run network diagnostics
or manage the endpoint's logs.

## How it works

Communication goes in both directions, over two separate iroh ALPNs:

```
                   push metrics, ping, name, grant caps
   ┌─────────────┐  ────────  IrohServicesProtocol  ───────▶  ┌───────────────┐
   │ your endpoint│            (ALPN)                          │ iroh-services │
   │  (this crate)│                                            │   cloud hub   │
   └─────────────┘  ◀──────  ClientHostProtocol  ────────────  └───────────────┘
                    run diagnostics · set log level · fetch logs
                    (CLIENT_HOST_ALPN, gated by capabilities)
```

- **Endpoint → cloud** (`ALPN`): the `Client` authenticates with your API
  secret, then pushes endpoint metrics on an interval and can ping, name
  itself, and grant the cloud capabilities.
- **Cloud → endpoint** (`CLIENT_HOST_ALPN`): the `ClientHost` protocol
  handler accepts callbacks *from* the hub — e.g. run a network-diagnostics
  report, set the log-level filter, or fetch the current log file. Serving
  `ClientHost` is opt-in; you only run it if you want the cloud to be able to
  reach back.

**Capabilities** decide what the cloud is allowed to do. They're [rcan]
tokens your endpoint grants to the hub — for example `NetDiagnosticsCap::GetAny`
or `LogsCap::SetLevel`. Nothing the cloud asks for happens unless a matching
capability was granted, so each endpoint stays in control of its own data.

## Quickstart

```rust,no_run
use iroh::{Endpoint, endpoint::presets};
use iroh_services::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let endpoint = Endpoint::bind(presets::N0).await?;

    // Reads the API secret from the IROH_SERVICES_API_SECRET env var.
    // Once built, the client pushes this endpoint's metrics to the hub.
    let client = Client::builder(&endpoint)
        .api_secret_from_env()?
        .build()
        .await?;

    client.ping().await?; // confirm the hub is reachable
    Ok(())
}
```

Run it with `cargo run --example quickstart` (set `IROH_SERVICES_API_SECRET`
to a secret from your iroh-services project first).

## What you can do

### Metrics (default)

Once the `Client` is built it streams the endpoint's metrics to the hub on a
configurable interval (`ClientBuilder::metrics_interval`), so you can monitor a
whole fleet from one place. Nothing else needs to be wired up.

### Network diagnostics

Grant `NetDiagnosticsCap::GetAny` and serve `ClientHost` on
`CLIENT_HOST_ALPN`. The hub can then dial the endpoint back and ask it to run a
network report — NAT behaviour, relay latencies, direct addresses, and a
port-mapping probe — useful for debugging connectivity in the field. See
[`examples/net_diagnostics.rs`](examples/net_diagnostics.rs).

### Device-local logs

Endpoints write structured logs to **rolling files on their own disk**, with
the log level **controlled remotely by the cloud**. This lets you turn on
detailed logging for a single misbehaving endpoint from the dashboard without
redeploying — and without shipping every endpoint's logs everywhere by default.

How it fits together:

1. **Install the file logger at startup.** The level filter starts at `off`,
   so nothing is captured until the cloud raises it:

   ```rust,ignore
   use iroh_services::logs::{self, FileLoggerConfig};

   // Rolling JSON log files under ./logs; hold onto `_guard` until shutdown
   // so buffered records flush.
   let (collector, _guard) = logs::install(FileLoggerConfig::new("./logs"))?;
   ```

2. **Let the cloud drive the level.** Hand the same `collector` to
   `ClientHost::with_log_collector`. With `LogsCap::SetLevel`, the hub can
   hot-reload the `EnvFilter` at runtime (e.g. `info,iroh=trace`) and set a TTL
   after which the endpoint reverts to your project default. On connect the
   client also pulls whatever level is already on file for it, so it lands on
   the right setting immediately.

3. **Pull logs on demand.** With `LogsCap::Fetch`, the hub can stream the
   endpoint's current rolling log file back over `FetchLogs`.

Because the files live on the device, operators can also tail, ship, or
aggregate them with whatever tooling they already use. See
[`examples/logs.rs`](examples/logs.rs) for the full flow.

> File logging is native-only; the feature is compiled out on `wasm32`
> targets (browser endpoints have no filesystem), where the protocol calls
> simply report that log collection is unavailable.

### Custom relays

Use the `preset` builder to configure an `iroh::Endpoint` with relays from
your iroh-services project (a bandwidth bump on the public relays, or your own
relay URLs), scoped to your endpoint's key. See
[`examples/relays.rs`](examples/relays.rs).

## Examples

Run any of these with `cargo run --example <name>` (most need
`IROH_SERVICES_API_SECRET` set):

| Example | What it shows |
|---------|---------------|
| [`quickstart`](examples/quickstart.rs) | Connect to the hub and push metrics |
| [`net_diagnostics`](examples/net_diagnostics.rs) | Cloud-initiated network diagnostics |
| [`logs`](examples/logs.rs) | Cloud-controlled, device-local logging |
| [`relays`](examples/relays.rs) | Configuring custom relays via the preset builder |

## License

Copyright 2026 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[iroh-services]: https://services.iroh.computer
[iroh]: https://iroh.computer
[rcan]: https://docs.rs/rcan

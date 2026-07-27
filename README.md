# iroh-services

[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square)](https://docs.rs/iroh-services/)
[![Crates.io](https://img.shields.io/crates/v/iroh-services.svg?style=flat-square)](https://crates.io/crates/iroh-services)
[![downloads](https://img.shields.io/crates/d/iroh-services.svg?style=flat-square)](https://crates.io/crates/iroh-services)
[![Chat](https://img.shields.io/discord/1161119546170687619?logo=discord&style=flat-square)](https://discord.com/invite/DpmJgtU7cW)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE-APACHE)
[![CI](https://img.shields.io/github/actions/workflow/status/n0-computer/iroh-services/ci.yaml?branch=main&style=flat-square&label=CI)](https://github.com/n0-computer/iroh-services/actions/workflows/ci.yaml)

An iroh protocol to interact with iroh-services, using iroh itself.

## Usage

Connect an existing iroh endpoint to iroh-services with an API key from your
project's dashboard. The client then pushes endpoint metrics on an interval:

```rust
use iroh::{Endpoint, endpoint::presets};
use iroh_services::Client;

let endpoint = Endpoint::bind(presets::N0).await?;
let client = Client::builder(&endpoint)
    .api_secret_from_env()?
    .name("my-endpoint")?
    .build()
    .await?;
```

See the [`quickstart`](examples/quickstart.rs) example for a runnable version,
and [docs.rs](https://docs.rs/iroh-services) for the full API.

### Network diagnostics

To let iroh-services fetch a connectivity report from an endpoint on demand,
grant it the `NetDiagnosticsCap::GetAny` capability and accept
`CLIENT_HOST_ALPN` on your router so it can dial back:

```rust
use iroh::protocol::Router;
use iroh_services::{ClientHost, CLIENT_HOST_ALPN};

let router = Router::builder(endpoint.clone())
    .accept(CLIENT_HOST_ALPN, ClientHost::new(&endpoint))
    .spawn();
```

The [`net_diagnostics`](examples/net_diagnostics.rs) example shows the full
flow, including granting the capability.

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

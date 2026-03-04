# iroh-services

Client library for interacting with [iroh](https://services.iroh.computer). Clients attach to the endpoint in your app to add features like metrics aggregation, network diagnostics, etc.

```rust
use iroh::Endpoint;
use iroh_services::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let endpoint = Endpoint::bind().await?;

    // needs IROH_SERVICES_API_KEY set to an environment variable
    // as long as client variable is not dropped it wil
    // push endpoint metrics to iroh services in the background, by default
    // every 60 seconds
    let client = Client::builder(&endpoint)
        .api_key_from_env()?
        .build()
        .await?;

    // we can also ping the service just to confirm everything is working
    client.ping().await?;

    Ok(())
}
```


## License

Copyright 2025 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

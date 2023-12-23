OxHTTP
======

[![actions status](https://github.com/oxigraph/oxhttp/workflows/build/badge.svg)](https://github.com/oxigraph/oxhttp/actions)
[![Latest Version](https://img.shields.io/crates/v/oxhttp.svg)](https://crates.io/crates/oxhttp)
[![Released API docs](https://docs.rs/oxhttp/badge.svg)](https://docs.rs/oxhttp)

OxHTTP is a simple and naive synchronous implementation of [HTTP 1.1](https://httpwg.org/http-core/) in Rust.
It provides both a client and a server.
It does not aim to be a fully-working-in-all-cases HTTP implementation but to be only a naive one to be use in simple usecases.


## Client

OxHTTP provides [a client](https://docs.rs/oxhttp/latest/oxhttp/struct.Client.html).
It aims at following the basic concepts of the [Web Fetch standard](https://fetch.spec.whatwg.org/) without the bits specific to web browsers (context, CORS...).

HTTPS is supported behind the disabled by default `native-tls` feature (to use the current system native implementation), or `rustls-webpki` feature (to use [Rustls](https://github.com/rustls/rustls) with [Common CA Database](https://www.ccadb.org/)),  or `rustls-native` feature (to use [Rustls](https://github.com/rustls/rustls) with host certificates).

Example:
```rust
use oxhttp::Client;
use oxhttp::model::{Request, Method, Status, HeaderName};
use std::io::Read;

let client = Client::new();
let response = client.request(Request::builder(Method::GET, "http://example.com".parse().unwrap()).build()).unwrap();
assert_eq!(response.status(), Status::OK);
assert_eq!(response.header(&HeaderName::CONTENT_TYPE).unwrap().as_ref(), b"text/html; charset=UTF-8");

let body = response.into_body().to_string().unwrap();
```

## Server

OxHTTP provides [a threaded HTTP server](https://docs.rs/oxhttp/latest/oxhttp/struct.Server.html).
It is still a work in progress. Use at your own risks behind a reverse proxy!

Example:
```rust no_run
use oxhttp::Server;
use oxhttp::model::{Response, Status};
use std::time::Duration;

// Builds a new server that returns a 404 everywhere except for "/" where it returns the body 'home'
let mut server = Server::new(|request| {
    if request.url().path() == "/" {
        Response::builder(Status::OK).with_body("home")
    } else {
        Response::builder(Status::NOT_FOUND).build()
    }
});
// Raise a timeout error if the client does not respond after 10s.
server = server.with_global_timeout(Duration::from_secs(10));
// Limits the max number of concurrent connections to 128.
server = server.with_max_concurrent_connections(128);
// Listen to localhost:8080
server.listen(("localhost", 8080)).unwrap();
```

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   `<http://www.apache.org/licenses/LICENSE-2.0>`)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   `<http://opensource.org/licenses/MIT>`)
   
at your option.


### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in OxHTTP by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

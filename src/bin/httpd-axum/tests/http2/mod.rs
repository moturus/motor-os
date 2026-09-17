mod deadlines;
use crate::common::Server;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

pub fn check() {
    deadlines::check();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for tls in [false, true] {
        let options = [
            "--max-active-connections",
            "1",
            "--max-header-deadline-sec",
            "1",
        ];
        let server = if tls {
            Server::start_tls(None, &options)
        } else {
            Server::start(None, &options)
        };
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                let stream = tokio::net::TcpStream::connect(server.address)
                    .await
                    .unwrap();
                if tls {
                    let stream = tokio_rustls::TlsConnector::from(crate::tls_config(b"h2"))
                        .connect("localhost".try_into().unwrap(), stream)
                        .await
                        .unwrap();
                    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
                    exchange(stream, &server, "https").await;
                } else {
                    exchange(stream, &server, "http").await;
                }
            })
            .await
            .unwrap();
        });
        server.stop();
    }
    println!("httpd-axum HTTP/2 cleartext and TLS tests passed");
}

async fn exchange<T>(stream: T, server: &Server, scheme: &str)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
    let driver = tokio::spawn(connection);
    for index in 0..2 {
        client = client.ready().await.unwrap();
        let request = http::Request::builder()
            .uri(format!("{scheme}://localhost/index.html"))
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            bytes.extend_from_slice(&chunk);
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        assert_eq!(bytes, b"test content\n");
        // A parsed request must disarm the initial deadline for HTTP/2.
        if index == 0 {
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
    }
    crate::assert_closed(&mut server.connect());
    drop(client);
    driver.await.unwrap().unwrap();
}

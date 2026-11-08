use super::*;
use tokio::net::TcpListener;

#[test]
fn rejected_remote_bind_text_does_not_enter_setup_or_cancellation_logs() {
    let mut fixture = Fixture::configured("allow_tcp_forwarding = true");
    let invalid = ["forged\n\x1b[31mmessage".to_owned(), "x".repeat(256)];
    block_on(async {
        let session = fixture.connect().await;
        let port = session.tcpip_forward("localhost", 0).await.unwrap();
        for address in &invalid {
            assert!(session.tcpip_forward(address, 22).await.is_err());
            assert!(session.cancel_tcpip_forward(address, 22).await.is_err());
        }
        session
            .cancel_tcpip_forward("localhost", port)
            .await
            .unwrap();
        sftp_handshake(&session).await;
    });
    fixture.child.kill().unwrap();
    fixture.child.wait().unwrap();
    let logs = fixture
        .log_thread
        .take()
        .unwrap()
        .join()
        .unwrap()
        .join("\n");
    assert_eq!(
        logs.matches("remote forward port 22: invalid remote bind address")
            .count(),
        4,
        "{logs}"
    );
    for address in invalid {
        assert!(
            !logs.contains(&address),
            "rejected bind text leaked: {logs}"
        );
    }
    assert!(!logs.contains("forged"), "{logs}");
    assert!(!logs.contains('\x1b'), "{logs}");
}

#[test]
fn remote_listener_requests_require_policy_and_validate_addresses() {
    for (extra, enabled) in [
        ("", false),
        ("gateway_ports = true", false),
        ("allow_tcp_forwarding = true", true),
    ] {
        let fixture = Fixture::configured(extra);
        block_on(async {
            let session = fixture.connect().await;
            if !enabled {
                assert!(matches!(
                    session.tcpip_forward("localhost", 0).await,
                    Err(russh::Error::RequestDenied)
                ));
            }
            for (address, port) in [("has space", 22), ("é", 22), ("127.0.0.1", 65536)] {
                assert!(matches!(
                    session.tcpip_forward(address, port).await,
                    Err(russh::Error::RequestDenied)
                ));
            }
            sftp_handshake(&session).await;
        });
    }
}

#[test]
fn remote_listener_registration_and_cancellation_keep_exact_connection_keys() {
    let fixture = Fixture::configured("allow_tcp_forwarding = true");
    block_on(async {
        let session = fixture.connect().await;
        let other = fixture.connect().await;
        let first = session.tcpip_forward("localhost", 0).await.unwrap();
        let second = session.tcpip_forward("localhost", 0).await.unwrap();
        assert!((1..=65535).contains(&first));
        assert!((1..=65535).contains(&second));
        assert_ne!(first, second);
        for address in ["127.0.0.1", "::1"] {
            assert!(TcpListener::bind((address, first as u16)).await.is_err());
        }
        assert!(session.tcpip_forward("localhost", first).await.is_err());
        assert!(other.tcpip_forward("localhost", first).await.is_err());
        assert!(
            other
                .cancel_tcpip_forward("localhost", first)
                .await
                .is_err()
        );
        assert!(
            session
                .cancel_tcpip_forward("127.0.0.1", first)
                .await
                .is_err()
        );
        session
            .cancel_tcpip_forward("localhost", first)
            .await
            .unwrap();
        // The cancellation reply guarantees every listening socket is gone.
        for address in ["127.0.0.1", "::1"] {
            let rebound = TcpListener::bind((address, first as u16)).await.unwrap();
            assert!(TcpListener::bind((address, second as u16)).await.is_err());
            drop(rebound);
        }
        assert!(
            session
                .cancel_tcpip_forward("localhost", first)
                .await
                .is_err()
        );
        session
            .cancel_tcpip_forward("localhost", second)
            .await
            .unwrap();
        sftp_handshake(&session).await;
        sftp_handshake(&other).await;
    });
}

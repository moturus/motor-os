#[path = "../src/redirect.rs"]
mod redirect;

use axum::body::Body;
use http::{header::LOCATION, Request, StatusCode};
use redirect::RedirectUrl;
use tower::ServiceExt;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    for destination in [
        "https://example.com",
        "https://example.com/landing?a=%2f&b=1#section",
        "https://127.0.0.1:443/",
        "https://[::1]:8443/a%20b",
    ] {
        let app = destination.parse::<RedirectUrl>().unwrap().router();
        for method in ["GET", "HEAD", "POST", "OPTIONS"] {
            for path in ["/", "/missing?q=ignore", "//evil.example/%2f?q=1"] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(path)
                            .header("Host", "attacker.example:1234")
                            .header("Forwarded", "host=attacker.example;proto=http")
                            .header("X-Forwarded-Host", "attacker.example")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
                assert_eq!(response.headers()[LOCATION], destination);
                assert!(axum::body::to_bytes(response.into_body(), 0)
                    .await
                    .unwrap()
                    .is_empty());
            }
        }
    }
    println!("httpd-axum fixed redirect response tests passed");
}

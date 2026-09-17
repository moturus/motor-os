use axum::body::{Body, Bytes};
use http_body::{Body as HttpBody, Frame};
use http_body_util::BodyExt;
use std::pin::Pin;
use std::task::{Context, Poll};

// Keep the original body on a failed fill: replay what was consumed, then
// continue streaming. In particular, preserve errors instead of caching them.
pub async fn collect(mut body: Body, length: usize) -> Result<Bytes, Body> {
    let mut bytes = Vec::with_capacity(length);
    while let Some(frame) = body.frame().await {
        if let Ok(data) = &frame {
            if let Some(data) = data.data_ref() {
                if data.len() <= length - bytes.len() {
                    bytes.extend_from_slice(data);
                    continue;
                }
            }
        }
        return Err(replay(bytes, Some(frame), body));
    }
    if bytes.len() == length {
        Ok(bytes.into())
    } else {
        Err(replay(bytes, None, body))
    }
}

fn replay(bytes: Vec<u8>, frame: Option<Result<Frame<Bytes>, axum::Error>>, body: Body) -> Body {
    Body::new(Replay {
        prefix: (!bytes.is_empty()).then(|| Frame::data(bytes.into())),
        frame,
        body,
    })
}

struct Replay {
    prefix: Option<Frame<Bytes>>,
    frame: Option<Result<Frame<Bytes>, axum::Error>>,
    body: Body,
}

impl HttpBody for Replay {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if let Some(prefix) = self.prefix.take() {
            return Poll::Ready(Some(Ok(prefix)));
        }
        if let Some(frame) = self.frame.take() {
            return Poll::Ready(Some(frame));
        }
        Pin::new(&mut self.body).poll_frame(cx)
    }
}

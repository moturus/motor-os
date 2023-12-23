//! The HTTP model encoded in Rust type system.
//!
//! The main entry points are [`Request`] and [`Response`].
mod body;
mod header;
mod method;
mod request;
mod response;
mod status;

pub use body::{Body, ChunkedTransferPayload};
pub use header::{HeaderName, HeaderValue, Headers, InvalidHeader};
pub use method::{InvalidMethod, Method};
pub use request::{Request, RequestBuilder};
pub use response::{Response, ResponseBuilder};
pub use status::{InvalidStatus, Status};
pub use url::Url;

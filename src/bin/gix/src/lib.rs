pub mod cancellation;
pub mod checkout;
pub mod clone;
pub mod command_config;
pub mod curl;
pub mod curl_capture;
pub mod fetch;
pub mod http;
pub mod http_request;
pub mod https_url;
pub mod mutation;
pub mod network;
pub mod repository;
pub mod status;
mod tracked_filters;
pub mod tree_index;

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

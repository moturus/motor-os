pub mod cancellation;
pub mod command_config;
pub mod curl;
pub mod https_url;
pub mod repository;
pub mod status;

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

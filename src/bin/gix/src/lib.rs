pub mod command_config;
pub mod repository;

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

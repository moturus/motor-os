#[cfg(not(generated_fixture))]
compile_error!("build-script cfg is missing");

#[cfg(generated_fixture)]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

pub const ENVIRONMENT: &str = env!("GENERATED_ENV");

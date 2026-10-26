pub mod config;
pub mod crypto;
mod files;
mod ip;
pub mod schedule;

#[cfg(target_os = "motor")]
fn motor_getrandom(bytes: &mut [u8]) -> Result<(), getrandom::Error> {
    moto_sdk::rt::fill_random_bytes(bytes);
    Ok(())
}

#[cfg(target_os = "motor")]
getrandom::register_custom_getrandom!(motor_getrandom);

#[cfg(test)]
mod config_tests;

#[cfg(test)]
mod crypto_tests;

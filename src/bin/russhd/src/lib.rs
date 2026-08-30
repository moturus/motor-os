#![allow(unexpected_cfgs)]
pub mod applets;
pub mod client;
pub mod config;
pub mod local_session;
pub mod permissions;
pub mod sftp_session;

// `ring` gets its randomness through getrandom 0.2. Register Motor's entropy
// source in the library so every binary in this package carries the hook.
#[cfg(target_os = "motor")]
fn motor_getrandom(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    moto_rt::fill_random_bytes(dest);
    Ok(())
}

#[cfg(target_os = "motor")]
getrandom::register_custom_getrandom!(motor_getrandom);

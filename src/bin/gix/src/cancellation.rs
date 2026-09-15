use std::{
    error::Error,
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
};

#[derive(Clone, Default)]
pub struct Cancellation {
    requested: Arc<AtomicBool>,
    handler_error: Arc<AtomicU16>,
}

impl Cancellation {
    pub fn new() -> Cancellation {
        Self::default()
    }

    #[cfg(not(target_os = "motor"))]
    pub fn install() -> io::Result<Cancellation> {
        Ok(Self::new())
    }

    #[cfg(target_os = "motor")]
    pub fn install() -> io::Result<Cancellation> {
        let cancellation = Self::new();
        let worker = cancellation.clone();
        let (setup_tx, setup_rx) = std::sync::mpsc::sync_channel(0);
        std::thread::Builder::new()
            .name("gix-ctrl-c".into())
            .spawn(move || match moto_rt::process::ctrl_c_register_handler() {
                Ok(last) => {
                    if setup_tx.send(Ok(())).is_err() {
                        return;
                    }
                    match moto_rt::process::ctrl_c_wait(last) {
                        Ok(_) => worker.cancel(),
                        Err(error) => {
                            worker
                                .handler_error
                                .store(moto_rt::ErrorCode::from(error), Ordering::Relaxed);
                            worker.cancel();
                        }
                    }
                }
                Err(moto_rt::Error::NotFound) => {
                    _ = setup_tx.send(Ok(()));
                }
                Err(error) => {
                    _ = setup_tx.send(Err(io::Error::other(format!(
                        "Ctrl+C handler setup failed: {error}"
                    ))));
                }
            })?;
        setup_rx
            .recv()
            .unwrap_or_else(|_| Err(io::Error::other("Ctrl+C handler stopped during setup")))?;
        Ok(cancellation)
    }

    pub fn flag(&self) -> &AtomicBool {
        &self.requested
    }

    pub fn cancel(&self) {
        self.requested.store(true, Ordering::Release);
    }

    pub fn check(&self) -> crate::Result {
        if !self.requested.load(Ordering::Acquire) {
            return Ok(());
        }
        let error = self.handler_error.load(Ordering::Relaxed);
        if error != 0 {
            #[cfg(target_os = "motor")]
            return Err(io::Error::other(format!(
                "Ctrl+C handler wait failed: {}",
                moto_rt::Error::from(error)
            ))
            .into());
            #[cfg(not(target_os = "motor"))]
            return Err(io::Error::other("Ctrl+C handler wait failed").into());
        }
        Err(Cancelled.into())
    }
}

#[derive(Debug)]
struct Cancelled;

impl fmt::Display for Cancelled {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("operation cancelled")
    }
}

impl Error for Cancelled {}

pub fn was_cancelled(mut error: &(dyn Error + 'static)) -> bool {
    loop {
        if error.is::<Cancelled>() {
            return true;
        }
        if let Some(inner) = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
        {
            error = inner;
            continue;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

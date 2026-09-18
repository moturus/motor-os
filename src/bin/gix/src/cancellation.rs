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
        Err(Cancelled { source: None }.into())
    }

    /// Classify an upstream error as cancellation without discarding its source chain.
    pub fn normalize_error(
        &self,
        source: Box<dyn Error + Send + Sync>,
    ) -> Box<dyn Error + Send + Sync> {
        if was_cancelled(source.as_ref()) {
            return source;
        }
        match self.check() {
            Err(error) if was_cancelled(error.as_ref()) => Box::new(Cancelled {
                source: Some(source),
            }),
            _ => source,
        }
    }
}

#[derive(Debug)]
struct Cancelled {
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl fmt::Display for Cancelled {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("operation cancelled")
    }
}

impl Error for Cancelled {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream_error() -> Box<dyn Error + Send + Sync> {
        io::Error::other(io::Error::new(io::ErrorKind::InvalidData, "inner failure")).into()
    }

    fn assert_upstream_chain(error: &(dyn Error + 'static)) {
        let outer = error
            .downcast_ref::<io::Error>()
            .expect("original upstream error");
        assert_eq!(outer.kind(), io::ErrorKind::Other);
        let inner = outer
            .get_ref()
            .and_then(|error| error.downcast_ref::<io::Error>())
            .expect("inner upstream error");
        assert_eq!(inner.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn normalization_preserves_upstream_errors_and_classifies_requested_cancellation() {
        let cancellation = Cancellation::new();
        let unchanged = cancellation.normalize_error(upstream_error());
        assert!(!was_cancelled(unchanged.as_ref()));
        assert_upstream_chain(unchanged.as_ref());

        cancellation.cancel();
        let normalized = cancellation.normalize_error(upstream_error());
        assert!(was_cancelled(normalized.as_ref()));
        assert_eq!(normalized.to_string(), "operation cancelled");
        assert_upstream_chain(normalized.source().expect("preserved upstream source"));
    }
}

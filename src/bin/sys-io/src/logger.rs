use log::{LevelFilter, SetLoggerError};
use log::{Metadata, Record};

struct MotoLogger;

impl log::Log for MotoLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            crate::moto_log!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: MotoLogger = MotoLogger;

pub fn init() -> Result<(), SetLoggerError> {
    #[cfg(debug_assertions)]
    let res = log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Debug));

    #[cfg(not(debug_assertions))]
    let res = log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info));

    res
}

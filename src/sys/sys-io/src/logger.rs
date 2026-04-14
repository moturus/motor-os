use log::{LevelFilter, SetLoggerError};
use log::{Metadata, Record};

struct MotoLogger;

impl log::Log for MotoLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let now =
                moto_rt::time::Instant::now().duration_since(moto_rt::time::Instant::from_u64(0));
            let millis = now.as_millis();
            let secs = millis / 1000;
            let millis = millis % 1000;

            crate::moto_log!(
                "{:3}:{:03}: {} {}:{}: {}\n",
                secs,
                millis,
                record.level(),
                record.file().unwrap_or("-"),
                record.line().unwrap_or(0),
                record.args()
            );
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

//! Motor OS' logging and telemetry utility.
mod io_thread;
mod logging;
mod stats;

fn main() {
    let _ = std::thread::spawn(|| stats::Registry::new().run());
    logging::LogServer::start()
}

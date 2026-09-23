//! Motor OS' logging and telemetry utility.
mod io_thread;
mod logging;
mod stats;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--self-test") {
        io_thread::tests::run();
        return;
    }
    let _ = std::thread::spawn(|| stats::Registry::new().run());
    logging::LogServer::start()
}

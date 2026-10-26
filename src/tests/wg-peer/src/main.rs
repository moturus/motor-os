use std::io::BufRead;
use std::sync::mpsc::sync_channel;
use wg_peer::{
    options::{Options, keygen},
    server::Server,
    transport::Event,
};

fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") if args.len() == 3 => keygen(&args[1], &args[2]),
        Some("serve") => {
            let options = Options::parse(&args[1..])?;
            let (sender, receiver) = sync_channel(64);
            let input_sender = sender.clone();
            std::thread::spawn(move || {
                let mut input = std::io::stdin().lock();
                loop {
                    let mut line = String::new();
                    let mut limited = std::io::Read::take(&mut input, 513);
                    let command = match limited.read_line(&mut line) {
                        Ok(0) | Err(_) => "quit".to_owned(),
                        Ok(_) if line.len() > 512 => "quit".to_owned(),
                        Ok(_) => line,
                    };
                    let quit = command.trim() == "quit";
                    if input_sender.send(Event::Command(command)).is_err() || quit {
                        break;
                    }
                }
            });
            Server::new(options, sender.clone())?.run(receiver, sender)
        }
        _ => Err(
            "usage: wg-peer keygen PRIVATE PUBLIC | serve --bind ADDRESS --address CIDR [--address CIDR] --private-key PATH --peer-key PATH [--endpoint ADDRESS] [--psk PATH] | serve --plain --bind ADDRESS --address CIDR --endpoint ADDRESS",
        ),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("wg-peer: {error}");
        std::process::exit(1);
    }
}

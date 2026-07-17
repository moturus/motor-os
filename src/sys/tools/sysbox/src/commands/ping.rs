use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use moto_sys_io::api_net;
use moto_sys_io::icmp::IcmpEchoClient;

const DEFAULT_COUNT: u16 = 4;
const DEFAULT_DATA_LEN: u16 = 56;
const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, PartialEq)]
struct Options {
    count: u16,
    interval: Duration,
    timeout: Duration,
    data_len: u16,
    destination: String,
}

fn print_usage() {
    eprintln!("usage: ping [-c COUNT] [-i SECONDS] [-W SECONDS] [-s BYTES] DESTINATION");
}

fn usage_error(message: &str) -> ! {
    eprintln!("ping: {message}");
    print_usage();
    std::process::exit(2);
}

fn parse_duration(value: &str, option: &str, allow_zero: bool) -> Result<Duration, String> {
    let seconds = value
        .parse::<f64>()
        .map_err(|_| format!("{option}: invalid duration '{value}'"))?;
    if !seconds.is_finite() || seconds < 0.0 || (!allow_zero && seconds == 0.0) {
        return Err(format!("{option}: invalid duration '{value}'"));
    }

    Duration::try_from_secs_f64(seconds)
        .map_err(|_| format!("{option}: duration is out of range: '{value}'"))
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut count = None;
    let mut interval = None;
    let mut timeout = None;
    let mut data_len = None;
    let mut destination = None;
    let mut positional_only = false;
    let mut idx = 1;

    while idx < args.len() {
        let argument = &args[idx];
        if !positional_only && argument == "--" {
            positional_only = true;
            idx += 1;
            continue;
        }
        if !positional_only && matches!(argument.as_str(), "-c" | "-i" | "-W" | "-s") {
            let option = argument.as_str();
            idx += 1;
            let value = args
                .get(idx)
                .ok_or_else(|| format!("{option}: option requires a value"))?;

            match option {
                "-c" => {
                    if count.is_some() {
                        return Err("-c: option specified more than once".to_owned());
                    }
                    let parsed = value
                        .parse::<u16>()
                        .map_err(|_| format!("-c: invalid count '{value}'"))?;
                    if parsed == 0 {
                        return Err("-c: count must be in 1..=65535".to_owned());
                    }
                    count = Some(parsed);
                }
                "-i" => {
                    if interval.is_some() {
                        return Err("-i: option specified more than once".to_owned());
                    }
                    interval = Some(parse_duration(value, "-i", true)?);
                }
                "-W" => {
                    if timeout.is_some() {
                        return Err("-W: option specified more than once".to_owned());
                    }
                    let parsed = parse_duration(value, "-W", false)?;
                    if parsed.as_millis() == 0
                        || parsed > Duration::from_millis(api_net::ICMP_ECHO_MAX_TIMEOUT_MS as u64)
                    {
                        return Err(format!(
                            "-W: timeout must be between 0.001 and {} seconds",
                            api_net::ICMP_ECHO_MAX_TIMEOUT_MS / 1000
                        ));
                    }
                    timeout = Some(parsed);
                }
                "-s" => {
                    if data_len.is_some() {
                        return Err("-s: option specified more than once".to_owned());
                    }
                    let parsed = value
                        .parse::<u16>()
                        .map_err(|_| format!("-s: invalid byte count '{value}'"))?;
                    if parsed > api_net::ICMP_ECHO_MAX_DATA_LEN {
                        return Err(format!(
                            "-s: byte count must be in 0..={}",
                            api_net::ICMP_ECHO_MAX_DATA_LEN
                        ));
                    }
                    data_len = Some(parsed);
                }
                _ => unreachable!(),
            }
        } else if !positional_only && argument.starts_with('-') {
            return Err(format!("unknown option '{argument}'"));
        } else {
            if destination.is_some() {
                return Err("only one destination may be specified".to_owned());
            }
            destination = Some(argument.clone());
        }
        idx += 1;
    }

    let destination = destination.ok_or_else(|| "destination is required".to_owned())?;
    Ok(Options {
        count: count.unwrap_or(DEFAULT_COUNT),
        interval: interval.unwrap_or(DEFAULT_INTERVAL),
        timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
        data_len: data_len.unwrap_or(DEFAULT_DATA_LEN),
        destination,
    })
}

fn resolve(destination: &str) -> Result<IpAddr, String> {
    if let Ok(address) = destination.parse::<IpAddr>() {
        return Ok(address);
    }

    (destination, 0)
        .to_socket_addrs()
        .map_err(|err| format!("cannot resolve '{destination}': {err}"))?
        .next()
        .map(|address| address.ip())
        .ok_or_else(|| format!("cannot resolve '{destination}': no addresses"))
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn print_summary(destination: &str, transmitted: u32, replies: &[Duration]) {
    let received = replies.len() as u32;
    let lost = transmitted - received;
    let loss_tenths = lost * 1000 / transmitted;
    let transmitted_noun = if transmitted == 1 {
        "packet"
    } else {
        "packets"
    };

    println!();
    println!("--- {destination} ping statistics ---");
    println!(
        "{transmitted} {transmitted_noun} transmitted, {received} received, {}.{}% packet loss",
        loss_tenths / 10,
        loss_tenths % 10
    );

    if !replies.is_empty() {
        let min = replies.iter().copied().min().unwrap();
        let max = replies.iter().copied().max().unwrap();
        let total_ns: u128 = replies.iter().map(Duration::as_nanos).sum();
        let average = Duration::from_nanos((total_ns / replies.len() as u128) as u64);
        println!(
            "rtt min/avg/max = {:.3}/{:.3}/{:.3} ms",
            millis(min),
            millis(average),
            millis(max)
        );
    }
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "ping");

    if args.iter().skip(1).any(|argument| argument == "--help") {
        print_usage();
        return;
    }

    let options = parse_options(args).unwrap_or_else(|error| usage_error(&error));
    let destination = resolve(&options.destination).unwrap_or_else(|error| {
        eprintln!("ping: {error}");
        std::process::exit(1);
    });
    let mut client = IcmpEchoClient::connect().unwrap_or_else(|error| {
        eprintln!("ping: cannot connect to sys-io: {error}");
        std::process::exit(1);
    });

    println!(
        "PING {} ({}): {} data bytes",
        options.destination, destination, options.data_len
    );

    let mut transmitted = 0_u32;
    let mut replies = Vec::new();
    let mut operational_error = false;

    for sequence in 0..options.count {
        let request_started = Instant::now();
        transmitted += 1;

        match client.echo(destination, sequence, options.data_len, options.timeout) {
            Ok(reply) => {
                println!(
                    "{} bytes from {}: icmp_seq={} time={:.3} ms",
                    reply.icmp_bytes,
                    reply.source,
                    sequence,
                    millis(reply.rtt)
                );
                replies.push(reply.rtt);
            }
            Err(moto_rt::Error::TimedOut) => {
                println!("Request timeout for icmp_seq {sequence}");
            }
            Err(error) => {
                eprintln!("ping: echo request failed: {error}");
                operational_error = true;
                break;
            }
        }

        if sequence + 1 < options.count {
            let remaining = options.interval.saturating_sub(request_started.elapsed());
            if !remaining.is_zero() {
                std::thread::sleep(remaining);
            }
        }
    }

    print_summary(&options.destination, transmitted, &replies);

    if operational_error || replies.is_empty() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(arguments: &[&str]) -> Vec<String> {
        arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect()
    }

    #[test]
    fn defaults_and_explicit_options() {
        assert_eq!(
            parse_options(&args(&["ping", "127.0.0.1"])).unwrap(),
            Options {
                count: DEFAULT_COUNT,
                interval: DEFAULT_INTERVAL,
                timeout: DEFAULT_TIMEOUT,
                data_len: DEFAULT_DATA_LEN,
                destination: "127.0.0.1".to_owned(),
            }
        );
        assert_eq!(
            parse_options(&args(&[
                "ping", "-c", "2", "-i", "0", "-W", "1.5", "-s", "0", "::1"
            ]))
            .unwrap(),
            Options {
                count: 2,
                interval: Duration::ZERO,
                timeout: Duration::from_millis(1500),
                data_len: 0,
                destination: "::1".to_owned(),
            }
        );
    }

    #[test]
    fn rejects_invalid_arguments() {
        for invalid in [
            &["ping"][..],
            &["ping", "-c", "0", "127.0.0.1"],
            &["ping", "-W", "0", "127.0.0.1"],
            &["ping", "-c", "1", "-c", "2", "127.0.0.1"],
            &["ping", "--bad", "127.0.0.1"],
            &["ping", "127.0.0.1", "::1"],
        ] {
            assert!(parse_options(&args(invalid)).is_err(), "{invalid:?}");
        }
    }
}

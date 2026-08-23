use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::time::{Duration, Instant};

use moto_dns::{AddressFamily, ClientError, Status};
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

struct AddressCandidates {
    hostname: Option<String>,
    remaining: VecDeque<IpAddr>,
    saw_v4: bool,
    saw_v6: bool,
}

impl AddressCandidates {
    fn new(hostname: Option<String>, addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        let mut remaining = VecDeque::new();
        let mut saw_v4 = false;
        let mut saw_v6 = false;
        for address in addresses {
            saw_v4 |= address.is_ipv4();
            saw_v6 |= address.is_ipv6();
            if !remaining.contains(&address) {
                remaining.push_back(address);
            }
        }
        Self {
            hostname,
            remaining,
            saw_v4,
            saw_v6,
        }
    }

    fn next(&mut self) -> Option<IpAddr> {
        self.remaining.pop_front()
    }

    fn next_after_unroutable(
        &mut self,
        lookup: impl FnOnce(&str, AddressFamily) -> Result<Vec<IpAddr>, String>,
    ) -> Result<Option<IpAddr>, String> {
        if let Some(address) = self.next() {
            return Ok(Some(address));
        }

        let Some(hostname) = &self.hostname else {
            return Ok(None);
        };
        let family = match (self.saw_v4, self.saw_v6) {
            (true, false) => AddressFamily::V6,
            (false, true) => AddressFamily::V4,
            _ => return Ok(None),
        };
        for address in lookup(hostname, family)? {
            if !self.remaining.contains(&address) {
                self.remaining.push_back(address);
            }
        }
        self.saw_v4 |= family == AddressFamily::V4;
        self.saw_v6 |= family == AddressFamily::V6;
        Ok(self.next())
    }
}

fn resolve(destination: &str) -> Result<AddressCandidates, String> {
    if let Ok(address) = destination.parse::<IpAddr>() {
        return Ok(AddressCandidates::new(None, [address]));
    }

    let addresses: Vec<_> = (destination, 0)
        .to_socket_addrs()
        .map_err(|err| format!("cannot resolve '{destination}': {err}"))?
        .map(|address| address.ip())
        .collect();
    if addresses.is_empty() {
        return Err(format!("cannot resolve '{destination}': no addresses"));
    }
    Ok(AddressCandidates::new(
        Some(destination.to_owned()),
        addresses,
    ))
}

fn resolve_family(destination: &str, family: AddressFamily) -> Result<Vec<IpAddr>, String> {
    let mut client = moto_dns::Client::connect()
        .map_err(|error| format!("fallback resolver connection failed: {error:?}"))?;
    let lookup = match client.lookup(destination, family) {
        Ok(lookup) => lookup,
        Err(ClientError::Resolver(Status::NotFound | Status::UnsupportedFamily)) => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(format!("fallback {family:?} lookup failed: {error:?}")),
    };

    lookup
        .addresses
        .into_iter()
        .map(|address| match address.address_family() {
            Ok(AddressFamily::V4) => Ok(IpAddr::V4(Ipv4Addr::new(
                address.bytes[0],
                address.bytes[1],
                address.bytes[2],
                address.bytes[3],
            ))),
            Ok(AddressFamily::V6) => Ok(IpAddr::V6(Ipv6Addr::from(address.bytes))),
            Ok(AddressFamily::Any) | Err(_) => {
                Err("fallback resolver returned an invalid address".to_owned())
            }
        })
        .collect()
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
    let mut candidates = resolve(&options.destination).unwrap_or_else(|error| {
        eprintln!("ping: {error}");
        std::process::exit(1);
    });
    let mut destination = candidates.next().unwrap();
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

        loop {
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
                    break;
                }
                Err(moto_rt::Error::TimedOut) => {
                    println!("Request timeout for icmp_seq {sequence}");
                    break;
                }
                Err(moto_rt::Error::NotConnected) => {
                    match candidates.next_after_unroutable(resolve_family) {
                        Ok(Some(next)) => {
                            eprintln!("ping: no route to {destination}; trying {next}");
                            destination = next;
                            continue;
                        }
                        Ok(None) => {}
                        Err(error) => eprintln!("ping: {error}"),
                    }
                    eprintln!("ping: echo request failed: NotConnected");
                    operational_error = true;
                    break;
                }
                Err(error) => {
                    eprintln!("ping: echo request failed: {error}");
                    operational_error = true;
                    break;
                }
            }
        }

        if operational_error {
            break;
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

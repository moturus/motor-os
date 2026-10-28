//! Insert a peer without rewriting the user's existing TOML.
use crate::config::{Config, MAX_FILE_BYTES, Peer, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use toml::{Table, Value};

fn strings(values: impl IntoIterator<Item = String>) -> Value {
    Value::Array(values.into_iter().map(Value::String).collect())
}

fn peer_fields(peer: &Peer) -> Table {
    let mut fields = Table::new();
    fields.insert(
        "public_key".into(),
        Value::String(STANDARD.encode(peer.public_key)),
    );
    fields.insert(
        "allowed_ips".into(),
        strings(peer.allowed_ips.iter().map(ToString::to_string)),
    );
    if let Some(endpoint) = peer.endpoint {
        fields.insert("endpoint".into(), Value::String(endpoint.to_string()));
    }
    if let Some(seconds) = peer.persistent_keepalive {
        fields.insert(
            "persistent_keepalive".into(),
            Value::Integer(seconds.into()),
        );
    }
    if let Some(key) = peer.preshared_key {
        fields.insert("preshared_key".into(), Value::String(STANDARD.encode(key)));
    }
    fields
}

pub fn serialize(config: &Config) -> Result<String> {
    let mut fields = Table::new();
    fields.insert("name".into(), Value::String(config.name.clone()));
    fields.insert(
        "private_key".into(),
        Value::String(STANDARD.encode(config.private_key)),
    );
    fields.insert(
        "public_key".into(),
        Value::String(STANDARD.encode(config.public_key())),
    );
    fields.insert(
        "listen_port".into(),
        Value::Integer(config.listen_port.into()),
    );
    fields.insert(
        "transport_addresses".into(),
        strings(config.transport_addresses.iter().map(ToString::to_string)),
    );
    fields.insert(
        "cidrs".into(),
        strings(config.cidrs.iter().map(ToString::to_string)),
    );
    if !config.peers.is_empty() {
        fields.insert(
            "peers".into(),
            Value::Array(
                config
                    .peers
                    .iter()
                    .map(|peer| Value::Table(peer_fields(peer)))
                    .collect(),
            ),
        );
    }
    toml::to_string(&fields).map_err(|_| "cannot serialize configuration")
}

pub fn peer_name(name: &str) -> Result<&str> {
    if name.chars().any(char::is_control) {
        return Err("peer name must be one line without control characters");
    }
    let name = name.trim();
    if name.len() > 128 {
        return Err("peer name is limited to 128 UTF-8 bytes");
    }
    Ok(name)
}

#[derive(Deserialize)]
struct PeerSpans {
    peers: Option<toml::Spanned<Vec<toml::Spanned<Value>>>>,
}

pub fn add_peer(text: &str, peer: Peer, name: &str) -> Result<String> {
    let mut expected = Config::parse(text)?;
    let name = peer_name(name)?;
    let fields = peer_fields(&peer);
    expected.peers.push(peer);
    // Validate routing, keys and limits before constructing any source edit.
    let expected = Config::parse(&serialize(&expected)?)?;
    let spans: PeerSpans =
        toml::from_str(text).map_err(|_| "cannot locate peers in configuration")?;
    let newline = if text
        .find('\n')
        .is_some_and(|index| index > 0 && text.as_bytes()[index - 1] == b'\r')
    {
        "\r\n"
    } else {
        "\n"
    };
    let comment = if name.is_empty() {
        String::new()
    } else {
        format!("# Peer: {name}{newline}")
    };
    let mut output = text.to_owned();
    if let Some(array) = spans.peers.filter(|array| {
        let value = &text[array.span()];
        value.starts_with('[') && !value.starts_with("[[") && value.ends_with(']')
    }) {
        let closing = array.span().end - 1;
        // Only the gap after the final parsed element can contain its comma.
        let comma = array.get_ref().last().and_then(|last| {
            let end = last.span().end;
            let gap = &text[end..closing];
            let has_comma = gap
                .lines()
                .any(|line| line.split('#').next().unwrap().contains(','));
            (!has_comma).then_some(end)
        });
        let inline = fields
            .iter()
            .map(|(key, value)| format!("{key} = {value}"))
            .collect::<Vec<_>>()
            .join(", ");
        output.insert_str(
            closing,
            &format!("{newline}{comment}{{ {inline} }}{newline}"),
        );
        if let Some(position) = comma {
            output.insert(position, ',');
        }
    } else {
        if !output.ends_with('\n') {
            output.push_str(newline);
        }
        let block = toml::to_string(&fields).map_err(|_| "cannot serialize peer")?;
        output.push_str(&format!(
            "{newline}{comment}[[peers]]{newline}{}",
            block.replace('\n', newline)
        ));
    }
    if output.len() > MAX_FILE_BYTES {
        return Err("configuration is limited to 64 KiB");
    }
    if Config::parse(&output)? != expected {
        return Err("peer edit did not preserve existing configuration");
    }
    Ok(output)
}

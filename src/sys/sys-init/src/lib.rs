/// Parses the text after `svc:` as a decimal capability mask and command.
pub fn process_service_line(cap_cmd: &str) -> Result<(u64, String), String> {
    let (caps, cmd) = cap_cmd
        .split_once(':')
        .ok_or_else(|| "missing capability mask".to_owned())?;
    let caps = caps
        .parse::<u64>()
        .map_err(|_| "invalid capability mask".to_owned())?;
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return Err("empty command".to_owned());
    }
    Ok((caps, cmd.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_an_explicit_service_mask() {
        assert_eq!(
            process_service_line("0:/system/services/example"),
            Ok((0, "/system/services/example".to_owned()))
        );
    }

    #[test]
    fn a_service_mask_is_required_and_decimal() {
        assert!(process_service_line("/system/services/example").is_err());
        assert!(process_service_line("0x40:/system/services/example").is_err());
        assert!(process_service_line("64:").is_err());
    }
}

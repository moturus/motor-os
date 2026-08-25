#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TtyRole {
    System,
    Interactive,
    None,
}

/// Parses the text after `tty:` as an optional role and a bare program path.
pub fn process_tty_line(value: &str) -> Result<(TtyRole, String), String> {
    let (role, command) = match value.split_once(':') {
        Some((role, command)) => {
            let role = match role {
                "system" => TtyRole::System,
                "interactive" => TtyRole::Interactive,
                "none" => TtyRole::None,
                _ => return Err("invalid role".to_owned()),
            };
            (role, command)
        }
        None => (TtyRole::Interactive, value),
    };
    if command.is_empty() || command.chars().any(char::is_whitespace) {
        return Err("tty command must be a bare program path".to_owned());
    }
    Ok((role, command.to_owned()))
}

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

    #[test]
    fn legacy_tty_lines_default_to_interactive() {
        assert_eq!(
            process_tty_line("/system/services/sys-tty"),
            Ok((TtyRole::Interactive, "/system/services/sys-tty".to_owned()))
        );
    }

    #[test]
    fn explicit_tty_lines_accept_each_role() {
        for (name, role) in [
            ("system", TtyRole::System),
            ("interactive", TtyRole::Interactive),
            ("none", TtyRole::None),
        ] {
            assert_eq!(
                process_tty_line(&format!("{name}:/system/services/sys-tty")),
                Ok((role, "/system/services/sys-tty".to_owned()))
            );
        }
    }

    #[test]
    fn tty_lines_reject_invalid_roles_and_commands() {
        for value in [
            "admin:/system/services/sys-tty",
            "SYSTEM:/system/services/sys-tty",
            ":/system/services/sys-tty",
            "",
            "system:",
            "system: /system/services/sys-tty",
            "system:/system/services/sys-tty --flag",
        ] {
            assert!(process_tty_line(value).is_err(), "{value:?}");
        }
    }
}

use moto_io::fs::{AccessPermissions, FsClient, RolePermissions};
use std::path::Path;

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tchmod MODE PATH...\n");
    eprintln!("MODE is nine characters in System/Interactive/None order.");
    std::process::exit(exit_code);
}

fn parse_triplet(value: &[u8]) -> Option<AccessPermissions> {
    match value {
        b"rwx" => Some(AccessPermissions::Rwx),
        b"rw-" => Some(AccessPermissions::Rw),
        b"r-x" => Some(AccessPermissions::Rx),
        b"r--" => Some(AccessPermissions::R),
        b"---" => Some(AccessPermissions::None),
        _ => None,
    }
}

fn parse_mode(value: &str) -> Option<RolePermissions> {
    let bytes = value.as_bytes();
    if bytes.len() != 9 {
        return None;
    }

    let permissions = RolePermissions::new(
        parse_triplet(&bytes[0..3])?,
        parse_triplet(&bytes[3..6])?,
        parse_triplet(&bytes[6..9])?,
    );
    if !permissions.system.can_narrow_to(permissions.interactive)
        || !permissions.interactive.can_narrow_to(permissions.none)
    {
        return None;
    }

    Some(permissions)
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "chmod");

    if args.get(1).is_some_and(|arg| arg == "--help") {
        print_usage_and_exit(0);
    }
    if args.len() < 3 {
        print_usage_and_exit(1);
    }

    let Some(permissions) = parse_mode(&args[1]) else {
        eprintln!("chmod: invalid mode '{}'", args[1]);
        print_usage_and_exit(1);
    };

    let failed = moto_async::LocalRuntime::new().block_on(async {
        let client = match FsClient::connect() {
            Ok(client) => client,
            Err(err) => {
                eprintln!("chmod: failed to connect to the filesystem: {err:?}");
                return true;
            }
        };

        let mut failed = false;
        for path in &args[2..] {
            let result = match std::fs::canonicalize(Path::new(path)) {
                Ok(path) => match path.to_str() {
                    Some(path) => match client.stat(path).await {
                        Ok((entry_id, _)) => {
                            client.set_all_permissions(entry_id, permissions).await
                        }
                        Err(err) => Err(err),
                    },
                    None => Err(moto_rt::Error::InvalidArgument),
                },
                Err(err) => {
                    eprintln!("chmod: '{}': {err}", path);
                    failed = true;
                    continue;
                }
            };

            if let Err(err) = result {
                eprintln!("chmod: '{}': {err:?}", path);
                failed = true;
            }
        }
        failed
    });

    if failed {
        std::process::exit(1);
    }
}

use moto_sdk::io::fs::{
    perms_monotonic, AccessPermissions, EntryId, EntryKind, FsClient, RolePermissions,
};
use std::path::{Path, PathBuf};
use std::rc::Rc;

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tchmod [-r] MODE PATH...\n");
    eprintln!("MODE is nine characters in System/Interactive/None order, such as");
    eprintln!("rwxr-xr--, or ROLES OP PERMS, such as n+w. ROLES is one or more of");
    eprintln!("s, i and n; OP is +, - or =; PERMS is zero or more of r, w and x.");
    eprintln!("Removing r also removes w and x, and a permission removed from a");
    eprintln!("role is removed from the roles below it.");
    eprintln!("-r also changes everything inside each directory PATH.");
    std::process::exit(exit_code);
}

const R: u8 = 4;
const W: u8 = 2;
const X: u8 = 1;

fn to_bits(access: AccessPermissions) -> u8 {
    let (r, w, x) = access.triple();
    (r as u8 * R) | (w as u8 * W) | (x as u8 * X)
}

fn from_bits(bits: u8) -> Option<AccessPermissions> {
    match bits {
        0b111 => Some(AccessPermissions::Rwx),
        0b110 => Some(AccessPermissions::Rw),
        0b101 => Some(AccessPermissions::Rx),
        0b100 => Some(AccessPermissions::R),
        0b000 => Some(AccessPermissions::None),
        _ => None,
    }
}

fn mode_string(bits: [u8; 3]) -> String {
    let mut mode = String::with_capacity(9);
    for role in bits {
        for (bit, ch) in [(R, 'r'), (W, 'w'), (X, 'x')] {
            mode.push(if role & bit != 0 { ch } else { '-' });
        }
    }
    mode
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

fn parse_absolute(value: &str) -> Option<RolePermissions> {
    let bytes = value.as_bytes();
    if bytes.len() != 9 {
        return None;
    }

    let permissions = RolePermissions::new(
        parse_triplet(&bytes[0..3])?,
        parse_triplet(&bytes[3..6])?,
        parse_triplet(&bytes[6..9])?,
    );
    perms_monotonic(permissions).then_some(permissions)
}

#[derive(Clone, Copy)]
enum Op {
    Add,
    Remove,
    Set,
}

#[derive(Clone, Copy)]
enum Mode {
    Absolute(RolePermissions),
    /// `roles` and the bits are in System/Interactive/None order.
    Symbolic {
        roles: [bool; 3],
        op: Op,
        bits: u8,
    },
}

fn parse_symbolic(value: &str) -> Option<Mode> {
    let bytes = value.as_bytes();
    let op_at = bytes.iter().position(|b| matches!(b, b'+' | b'-' | b'='))?;
    if op_at == 0 {
        return None;
    }

    let mut roles = [false; 3];
    for role in &bytes[..op_at] {
        roles[match role {
            b's' => 0,
            b'i' => 1,
            b'n' => 2,
            _ => return None,
        }] = true;
    }
    let op = match bytes[op_at] {
        b'+' => Op::Add,
        b'-' => Op::Remove,
        _ => Op::Set,
    };
    let mut bits = 0;
    for perm in &bytes[op_at + 1..] {
        bits |= match perm {
            b'r' => R,
            b'w' => W,
            b'x' => X,
            _ => return None,
        };
    }
    // w and x require r, so removing r removes them too.
    if matches!(op, Op::Remove) && bits & R != 0 {
        bits = R | W | X;
    }
    Some(Mode::Symbolic { roles, op, bits })
}

fn parse_mode(value: &str) -> Option<Mode> {
    parse_absolute(value)
        .map(Mode::Absolute)
        .or_else(|| parse_symbolic(value))
}

impl Mode {
    /// The permissions this mode gives an entry that has `current`, or the
    /// invalid mode string it would produce.
    fn apply(self, current: RolePermissions) -> Result<RolePermissions, String> {
        let (roles, op, bits) = match self {
            Mode::Absolute(permissions) => return Ok(permissions),
            Mode::Symbolic { roles, op, bits } => (roles, op, bits),
        };

        let old = [current.system, current.interactive, current.none].map(to_bits);
        let mut new = [0; 3];
        let mut removed = 0;
        for role in 0..3 {
            new[role] = match (roles[role], op) {
                (false, _) => old[role],
                (true, Op::Add) => old[role] | bits,
                (true, Op::Remove) => old[role] & !bits,
                (true, Op::Set) => bits,
            };
            // As in the filesystem, narrowing a role narrows the roles below
            // it; widening never widens another role.
            new[role] &= !removed;
            removed |= old[role] & !new[role];
        }

        let (Some(system), Some(interactive), Some(none)) =
            (from_bits(new[0]), from_bits(new[1]), from_bits(new[2]))
        else {
            return Err(mode_string(new));
        };
        let permissions = RolePermissions::new(system, interactive, none);
        if perms_monotonic(permissions) {
            Ok(permissions)
        } else {
            Err(mode_string(new))
        }
    }
}

/// True when going from `old` to `new` takes nothing away from any role.
fn only_adds(old: RolePermissions, new: RolePermissions) -> bool {
    new.system.can_narrow_to(old.system)
        && new.interactive.can_narrow_to(old.interactive)
        && new.none.can_narrow_to(old.none)
}

enum Step {
    Visit(PathBuf, EntryId),
    /// A directory change that removes permissions is made after the
    /// directory's contents, which it could otherwise make unreachable.
    Finish(PathBuf, EntryId, RolePermissions),
}

struct Chmod<'a> {
    client: Rc<FsClient>,
    mode: Mode,
    mode_arg: &'a str,
    recursive: bool,
}

impl Chmod<'_> {
    fn report(path: &Path, result: moto_rt::Result<()>) -> bool {
        if let Err(err) = result {
            eprintln!("chmod: '{}': {err:?}", path.display());
            return false;
        }
        true
    }

    async fn set(&self, path: &Path, id: EntryId, permissions: RolePermissions) -> bool {
        Self::report(path, self.client.set_all_permissions(id, permissions).await)
    }

    /// Changes one entry, or defers the change, and returns whether it
    /// succeeded so far and whether to descend into the entry.
    async fn visit(&self, path: &Path, id: EntryId, steps: &mut Vec<Step>) -> (bool, bool) {
        let metadata = match self.client.metadata(id).await {
            Ok(metadata) => metadata,
            Err(err) => return (Self::report(path, Err(err)), false),
        };
        let (kind, current) = match (metadata.try_kind(), metadata.permissions()) {
            (Ok(kind), Ok(current)) => (kind, current),
            (Err(err), _) | (_, Err(err)) => {
                eprintln!("chmod: '{}': {err}", path.display());
                return (false, false);
            }
        };

        let descend = self.recursive && kind == EntryKind::Directory;
        let ok = match self.mode.apply(current) {
            Err(invalid) => {
                eprintln!(
                    "chmod: '{}': {} would give invalid mode {invalid}",
                    path.display(),
                    self.mode_arg
                );
                false
            }
            Ok(permissions) if descend && !only_adds(current, permissions) => {
                steps.push(Step::Finish(path.to_owned(), id, permissions));
                true
            }
            Ok(permissions) => self.set(path, id, permissions).await,
        };
        (ok, descend)
    }

    async fn push_children(&self, path: &Path, id: EntryId, steps: &mut Vec<Step>) -> bool {
        let mut child = self.client.get_first_entry(id).await;
        loop {
            let child_id = match child {
                Ok(Some(child_id)) => child_id,
                Ok(None) => return true,
                Err(err) => return Self::report(path, Err(err)),
            };
            match self.client.name(child_id).await {
                Ok(name) => steps.push(Step::Visit(path.join(name), child_id)),
                Err(err) => return Self::report(path, Err(err)),
            }
            child = self.client.get_next_entry(child_id).await;
        }
    }

    async fn run(&self, path: &Path, id: EntryId) -> bool {
        let mut ok = true;
        let mut steps = vec![Step::Visit(path.to_owned(), id)];
        while let Some(step) = steps.pop() {
            match step {
                Step::Finish(path, id, permissions) => {
                    ok &= self.set(&path, id, permissions).await;
                }
                Step::Visit(path, id) => {
                    let (visited, descend) = self.visit(&path, id, &mut steps).await;
                    ok &= visited;
                    if descend {
                        ok &= self.push_children(&path, id, &mut steps).await;
                    }
                }
            }
        }
        ok
    }
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "chmod");

    if args.get(1).is_some_and(|arg| arg == "--help") {
        print_usage_and_exit(0);
    }
    let recursive = args.get(1).is_some_and(|arg| arg == "-r");
    let args = &args[1 + recursive as usize..];
    if args.len() < 2 {
        print_usage_and_exit(1);
    }

    let Some(mode) = parse_mode(&args[0]) else {
        eprintln!("chmod: invalid mode '{}'", args[0]);
        print_usage_and_exit(1);
    };

    let failed = moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let client = match FsClient::connect() {
            Ok(client) => client,
            Err(err) => {
                eprintln!("chmod: failed to connect to the filesystem: {err:?}");
                return true;
            }
        };
        let chmod = Chmod {
            client,
            mode,
            mode_arg: &args[0],
            recursive,
        };

        let mut failed = false;
        for path in &args[1..] {
            let canonical = match std::fs::canonicalize(Path::new(path)) {
                Ok(canonical) => canonical,
                Err(err) => {
                    eprintln!("chmod: '{}': {err}", path);
                    failed = true;
                    continue;
                }
            };
            let stat = match canonical.to_str() {
                Some(canonical) => chmod.client.stat(canonical).await,
                None => Err(moto_rt::Error::InvalidArgument),
            };
            failed |= match stat {
                Ok((id, _)) => !chmod.run(Path::new(path), id).await,
                Err(err) => !Chmod::report(Path::new(path), Err(err)),
            };
        }
        failed
    });

    if failed {
        std::process::exit(1);
    }
}

use crate::support::{Scratch, command, interactive, success};
use moto_sdk::io::fs::{AccessPermissions, FsClient, RolePermissions};

pub fn run() {
    let scratch = Scratch::new("installed-utilities");
    let root = &scratch.0;
    for (tool, flag) in [
        ("gix", "--version"),
        ("hx", "--version"),
        ("sed", "--version"),
        ("lua", "-v"),
        ("javy", "--version"),
        ("wasmi", "--version"),
        ("wasmtime", "--version"),
        ("wasmtime-rt", "--version"),
    ] {
        success(
            command(root, &format!("/user/bin/dev/{tool}")).arg(flag),
            b"",
        );
    }
    let lua = success(
        command(root, "/user/bin/dev/lua").args(["-e", "for l in io.lines() do print(l) end"]),
        b"a\nb\n",
    );
    assert_eq!(lua.stdout, b"a\nb\n");
    let sed = success(
        command(root, "/user/bin/dev/sed").args(["-n", "s/beta/BETA/p"]),
        b"alpha\nbeta\n",
    );
    assert_eq!(sed.stdout, b"BETA\n");

    let file = scratch.write("f", "one\ntwo\n");
    let mode = if interactive() {
        "rwxrw----"
    } else {
        // None may change its own triplet, but not the higher roles' modes.
        "rwxrwxrw-"
    };
    success(command(root, "/user/bin/chmod").args([mode, "f"]), b"");
    let before = permissions(&file, None);
    success(
        command(root, "/user/bin/dev/sed").args(["-i", "s/one/ONE/", "f"]),
        b"",
    );
    success(
        command(root, "/user/bin/dev/sed").args(["-i.bak", "-e", "s/two/TWO/", "f"]),
        b"",
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"ONE\nTWO\n");
    assert_eq!(std::fs::read(root.join("f.bak")).unwrap(), b"ONE\ntwo\n");
    assert_eq!(permissions(&file, None), before);

    // Editing an existing writable file must not require creating a sibling.
    let locked = root.join("locked");
    std::fs::create_dir(&locked).unwrap();
    let file = scratch.write("locked/f", "one\ntwo\n");
    let file_mode = permissions(&file, None);
    let mut directory_mode = permissions(&locked, None);
    directory_mode.none = AccessPermissions::Rx;
    if interactive() {
        directory_mode.interactive = AccessPermissions::Rx;
    }
    let original = permissions(&locked, Some(directory_mode));
    success(
        command(root, "/user/bin/dev/sed").args(["-i", "s/one/ONE/", "locked/f"]),
        b"",
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"ONE\ntwo\n");
    assert_eq!(permissions(&file, None), file_mode);
    permissions(&locked, Some(original));
    println!("installed Lua and sed: PASS");
}

fn permissions(path: &std::path::Path, new: Option<RolePermissions>) -> RolePermissions {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let fs = FsClient::connect().unwrap();
        let (id, _) = fs.stat(path.to_str().unwrap()).await.unwrap();
        let old = fs.metadata(id).await.unwrap().permissions().unwrap();
        if let Some(new) = new {
            fs.set_all_permissions(id, new).await.unwrap();
        }
        old
    })
}

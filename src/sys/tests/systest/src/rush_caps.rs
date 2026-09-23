//! Rush's capability-grant precedence, observed through the child's actual
//! capability word.

use moto_sys::caps::{
    CAP_FS_WRITE, CAP_INTERACTIVE, CAP_LOG, CAP_NET, CAP_SPAWN, CAP_SPAWN_DETACHED, CAP_VSOCK,
    MOTOR_OS_CAPS_ENV_KEY,
};

const PRINT_CAPS: &str = "print-caps";

pub fn is_print_caps_child(args: &[String]) -> bool {
    args.len() == 3 && args[1] == PRINT_CAPS
}

/// Prints `<label>=0x<caps>` for this process.
pub fn run_print_caps_child(args: &[String]) -> ! {
    println!(
        "{}=0x{:x}",
        args[2],
        moto_sys::ProcessStaticPage::get().capabilities
    );
    std::process::exit(0)
}

fn rush(caps: u64, script: &str) -> std::process::Output {
    std::process::Command::new("/system/bin/rush")
        .arg("-c")
        .arg(script)
        .env(MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"))
        .output()
        .unwrap()
}

/// Run with `0x3ec` so the shell can pass detach authority to the probe, which
/// is copied under rush.toml's trusted basename `rmux`.
pub fn test_detach_grant_precedence() {
    let full = CAP_SPAWN
        | CAP_LOG
        | CAP_SPAWN_DETACHED
        | CAP_INTERACTIVE
        | CAP_VSOCK
        | CAP_NET
        | CAP_FS_WRITE;
    assert_eq!(0x3ec, full);
    assert_eq!(full, moto_sys::ProcessStaticPage::get().capabilities);

    let dir = crate::temp_path(&format!(
        "systest-rush-caps-{}",
        moto_sys::ProcessStaticPage::get().pid
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let probe = dir.join("rmux");
    std::fs::copy(std::env::current_exe().unwrap(), &probe).unwrap();
    let probe = probe.to_str().unwrap();
    moto_rt::fs::set_perm(probe, moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC).unwrap();

    let script = format!(
        "P={probe}; $P {PRINT_CAPS} default; \
         MOTOR_OS_CAPS=0x2ec $P {PRINT_CAPS} no-net; \
         MOTOR_OS_CAPS=0x1ec $P {PRINT_CAPS} no-fs-write; \
         MOTOR_OS_CAPS=0xec $P {PRINT_CAPS} neither; \
         MOTOR_OS_CAPS=0 $P {PRINT_CAPS} zero; \
         MOTOR_OS_CAPS=zz $P {PRINT_CAPS} malformed; echo malformed-status=$?; \
         export MOTOR_OS_CAPS=0x2ec; $P {PRINT_CAPS} exported; \
         MOTOR_OS_CAPS=0x1ec $P {PRINT_CAPS} assigned"
    );
    let output = rush(full, &script);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        "default=0x3ec\nno-net=0x2ec\nno-fs-write=0x1ec\nneither=0xec\nzero=0x0\n\
         malformed-status=126\nexported=0x2ec\nassigned=0x1ec\n",
        String::from_utf8(output.stdout).unwrap()
    );
    // Debug runtimes also log to stderr; the malformed mask reached spawn
    // validation rather than being replaced by the grant.
    let stderr = String::from_utf8(output.stderr).unwrap();
    let invalid = format!(
        "rush: {probe}: InvalidArgument (os error {})\n",
        moto_rt::E_INVALID_ARGUMENT
    );
    assert!(stderr.contains(&invalid), "{stderr:?}");

    // Without a mask, the grant is still limited to what the shell holds.
    for shell in [full & !CAP_NET, full & !CAP_FS_WRITE] {
        let output = rush(shell, &format!("{probe} {PRINT_CAPS} default"));
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            format!("default=0x{shell:x}\n"),
            String::from_utf8(output.stdout).unwrap()
        );
    }

    std::fs::remove_dir_all(dir).unwrap();
    println!("rush_caps::test_detach_grant_precedence PASS");
}

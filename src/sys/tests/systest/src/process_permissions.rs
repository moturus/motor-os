use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use moto_sys::caps::{CAP_INTERACTIVE, CAP_SPAWN, CAP_SYS, MOTOR_OS_CAPS_ENV_KEY, ProcessRole};
use moto_sys::{ProcessStaticPage, SysCpu, SysRay};

fn command(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["process-permissions-child", mode]);
    command
}

fn idle_child() -> Child {
    command("idle").stdin(Stdio::piped()).spawn().unwrap()
}

fn assert_none_role() {
    assert_eq!(
        ProcessRole::None,
        ProcessRole::from_caps(ProcessStaticPage::get().capabilities)
    );
}

pub fn run_child(args: &[String]) {
    match args[2].as_str() {
        "idle" => {
            // Keeping stdin open keeps this target alive without timing sleeps.
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
        }
        "branch" => {
            let mut grandchild = idle_child();
            println!("{}", grandchild.id());
            std::io::stdout().flush().unwrap();
            assert_eq!(Some(-1), grandchild.wait().unwrap().code());
        }
        "kill" => {
            assert_none_role();
            // Self, parent, and sibling are all outside our descendant tree.
            for pid in std::iter::once(moto_sys::current_pid())
                .chain(args[3..].iter().map(|pid| pid.parse::<u64>().unwrap()))
            {
                assert_eq!(SysCpu::kill_pid(pid), Err(moto_rt::E_NOT_ALLOWED));
            }

            let mut child = idle_child();
            SysCpu::kill_pid(u64::from(child.id())).unwrap();
            assert_eq!(Some(-1), child.wait().unwrap().code());

            // A grandchild must be permitted too, not just a direct child.
            let mut branch = command("branch").stdout(Stdio::piped()).spawn().unwrap();
            let mut stdout = BufReader::new(branch.stdout.take().unwrap());
            let mut pid = String::new();
            assert_ne!(0, stdout.read_line(&mut pid).unwrap());
            SysCpu::kill_pid(pid.trim().parse().unwrap()).unwrap();
            assert_eq!(Some(0), branch.wait().unwrap().code());
        }
        "debug" => {
            assert_none_role();
            let mut child = idle_child();
            // Even our own child is forbidden; invalid PIDs cannot bypass the
            // role check either. Parent and sibling PIDs come from the runner.
            for pid in [u64::from(child.id()), moto_sys::current_pid(), u64::MAX]
                .into_iter()
                .chain(args[3..].iter().map(|pid| pid.parse::<u64>().unwrap()))
            {
                assert_eq!(SysRay::dbg_attach(pid), Err(moto_rt::E_NOT_ALLOWED));
            }
            assert!(child.try_wait().unwrap().is_none());
            drop(child.stdin.take());
            assert_eq!(Some(0), child.wait().unwrap().code());
        }
        mode => panic!("unknown process permissions child: {mode}"),
    }
}

pub fn test_pid_kill_permissions() {
    let own = ProcessStaticPage::get().capabilities;
    assert_eq!(ProcessRole::Interactive, ProcessRole::from_caps(own));
    let mut sibling = idle_child();
    for caps in [CAP_SPAWN, own & !(CAP_SYS | CAP_INTERACTIVE)] {
        let status = command("kill")
            .args([
                moto_sys::current_pid().to_string(),
                sibling.id().to_string(),
            ])
            .env(MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"))
            .status()
            .unwrap();
        assert_eq!(Some(0), status.code());
        assert!(sibling.try_wait().unwrap().is_none());
    }
    SysCpu::kill_pid(u64::from(sibling.id())).unwrap();
    assert_eq!(Some(-1), sibling.wait().unwrap().code());
    println!("test_pid_kill_permissions PASS");
}

pub fn test_debug_attach_permissions() {
    let own = ProcessStaticPage::get().capabilities;
    assert_eq!(ProcessRole::Interactive, ProcessRole::from_caps(own));
    let mut sibling = idle_child();
    for caps in [CAP_SPAWN, own & !(CAP_SYS | CAP_INTERACTIVE)] {
        let status = command("debug")
            .args([
                moto_sys::current_pid().to_string(),
                sibling.id().to_string(),
            ])
            .env(MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"))
            .status()
            .unwrap();
        assert_eq!(Some(0), status.code());
        assert!(sibling.try_wait().unwrap().is_none());
    }
    // Interactive debuggers retain their existing authority.
    let session = SysRay::dbg_attach(u64::from(sibling.id())).unwrap();
    SysRay::dbg_detach(session).unwrap();
    drop(sibling.stdin.take());
    assert_eq!(Some(0), sibling.wait().unwrap().code());
    println!("test_debug_attach_permissions PASS");
}

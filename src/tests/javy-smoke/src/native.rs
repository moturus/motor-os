use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use moto_stats::Collector;
use moto_sys::stats::MemoryStats;

mod behavior;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SHARE: &str = "/user/share/javy";
const DEADLINE: Duration = Duration::from_secs(120);

struct Suite {
    root: PathBuf,
    cases: usize,
}

impl Suite {
    fn command(&mut self, label: &str, command: &str, code: i32) -> Result<(String, String)> {
        let stdout_path = self.root.join(format!("{label}.stdout"));
        let stderr_path = self.root.join(format!("{label}.stderr"));
        let mut child = Command::new("/system/bin/rush")
            .args(["-c", command])
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout_path)?)
            .stderr(fs::File::create(&stderr_path)?)
            .spawn()?;
        let started = Instant::now();
        let mut last = started;
        let mut gap = Duration::ZERO;
        let mut peak = 0;
        // Sampled whole-VM peaks include this driver; they are not RSS.
        let status = loop {
            let sample = MemoryStats::get().map_err(|e| format!("memory stats: {e:?}"))?;
            peak = peak.max(sample.used());
            let now = Instant::now();
            gap = gap.max(now - last);
            last = now;
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() >= DEADLINE {
                child.kill()?;
                child.wait()?;
                return Err(format!(
                    "{label}: exceeded {DEADLINE:?}; evidence in {:?}",
                    self.root
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let read_log = |path: &Path| -> Result<String> {
            if fs::metadata(path)?.len() > 256 * 1024 {
                return Err(format!("oversized command log: {path:?}").into());
            }
            Ok(fs::read_to_string(path)?)
        };
        let stdout = read_log(&stdout_path)?;
        let stderr = read_log(&stderr_path)?;
        if status.code() != Some(code) {
            return Err(format!(
                "{label}: expected exit {code}, got {status}\n{stdout}\n{stderr}\nevidence: {:?}",
                self.root
            )
            .into());
        }
        println!(
            "PASS {label}: exit={code} elapsed_ms={} sampled_vm_peak_bytes={peak} max_gap_us={}",
            started.elapsed().as_millis(),
            gap.as_micros()
        );
        self.cases += 1;
        Ok((stdout, stderr))
    }

    fn compile(&mut self, label: &str, input: &str, output: &str, flags: &str) -> Result<()> {
        self.command(
            label,
            &format!("MOTOR_OS_CAPS=0x200 /user/bin/javy build {input} -o {output} {flags}"),
            0,
        )?;
        Ok(())
    }

    fn execute(&mut self, label: &str, module: &str, flags: &str, expected: &str) -> Result<()> {
        let (stdout, stderr) = self.command(
            label,
            &format!("MOTOR_OS_CAPS=0 /user/bin/wasmi {module} {flags}"),
            0,
        )?;
        if stdout != expected || !stderr.is_empty() {
            return Err(format!("{label}: unexpected output {stdout:?}, stderr {stderr:?}").into());
        }
        Ok(())
    }

    fn refusal(&mut self, label: &str, command: &str, diagnostic: &str) -> Result<()> {
        let (_, stderr) = self.command(label, command, 1)?;
        if !stderr.contains(diagnostic) {
            return Err(format!("{label}: missing diagnostic {diagnostic:?}: {stderr}").into());
        }
        Ok(())
    }

    fn same_bytes(&self, first: &str, second: &str) -> Result<()> {
        let mut first = fs::File::open(self.root.join(first))?;
        let mut second = fs::File::open(self.root.join(second))?;
        if first.metadata()?.len() != second.metadata()?.len() {
            return Err("output lengths differ".into());
        }
        let mut a = [0; 4096];
        let mut b = [0; 4096];
        loop {
            let count = first.read(&mut a)?;
            if count == 0 {
                return Ok(());
            }
            second.read_exact(&mut b[..count])?;
            if a[..count] != b[..count] {
                return Err("output bytes differ".into());
            }
        }
    }
}

fn admission_refusals() -> Result<u64> {
    let kernel = Collector::kernel();
    let catalog = Collector::describe(&kernel).map_err(|e| format!("metric catalog: {e:?}"))?;
    let values = Collector::query(&kernel).map_err(|e| format!("kernel metrics: {e:?}"))?;
    let mut total = 0;
    for name in ["mem.admission_refused_user", "mem.admission_refused_sys_io"] {
        let id = catalog
            .iter()
            .find(|m| m.name == name)
            .ok_or("missing refusal metric")?
            .id;
        total += values
            .iter()
            .find(|m| m.metric == id)
            .ok_or("missing refusal counter")?
            .value;
    }
    Ok(total)
}

pub fn run() -> Result<()> {
    let root = PathBuf::from(format!("/user/tmp/javy-smoke-{}", std::process::id()));
    fs::create_dir(&root)?;
    if !Command::new("/system/bin/chmod")
        .arg("rwxrwxrwx")
        .arg(&root)
        .status()?
        .success()
    {
        return Err("could not make scratch directory writable to role None".into());
    }
    println!(
        "Javy/Wasmi installed-tool checks; scratch={}",
        root.display()
    );
    println!("{}", fs::read_to_string(format!("{SHARE}/sources.txt"))?);
    println!(
        "usable_memory_bytes={}",
        MemoryStats::get().map_err(|e| format!("{e:?}"))?.available
    );
    let refusals = admission_refusals()?;
    let mut suite = Suite { root, cases: 0 };
    let (version, _) = suite.command(
        "javy-version",
        "MOTOR_OS_CAPS=0 /user/bin/javy --version",
        0,
    )?;
    assert_eq!(version.trim(), "javy 9.1.0");
    suite.command(
        "wasmi-version",
        "MOTOR_OS_CAPS=0 /user/bin/wasmi --version",
        0,
    )?;
    suite.refusal(
        "compiler-role-refusal",
        "/user/bin/javy build missing.js -o forbidden.wasm",
        "role None",
    )?;
    suite.refusal(
        "runner-role-refusal",
        "/user/bin/wasmi missing.wasm",
        "role None",
    )?;
    // The driver can pass its spawn capability; ordinary children do not inherit CAP_LOG.
    suite.refusal(
        "compiler-cap-refusal",
        "MOTOR_OS_CAPS=0x204 /user/bin/javy build missing.js -o forbidden.wasm",
        "excess capabilities",
    )?;
    suite.refusal(
        "runner-cap-refusal",
        "MOTOR_OS_CAPS=0x104 /user/bin/wasmi missing.wasm",
        "excess capabilities",
    )?;
    fs::write(
        suite.root.join("hello.js"),
        "console.log('hello from Motor', 6 * 7);\n",
    )?;
    suite.compile("hello-static", "hello.js", "hello.wasm", "-C deterministic")?;
    suite.execute("hello-execute", "hello.wasm", "", "hello from Motor 42\n")?;
    suite.compile(
        "hello-explicit-plugin",
        "hello.js",
        "explicit.wasm",
        &format!("-C deterministic -C plugin={SHARE}/plugin.wasm"),
    )?;
    suite.same_bytes("hello.wasm", "explicit.wasm")?;
    suite.compile(
        "hello-repeat",
        "hello.js",
        "repeat.wasm",
        "-C deterministic",
    )?;
    suite.same_bytes("hello.wasm", "repeat.wasm")?;
    suite.command(
        "emit-plugin",
        "MOTOR_OS_CAPS=0x200 /user/bin/javy emit-plugin -o emitted.wasm",
        0,
    )?;
    suite.same_bytes("emitted.wasm", &format!("{SHARE}/plugin.wasm"))?;
    suite.compile(
        "hello-dynamic",
        "hello.js",
        "dynamic.wasm",
        "-C dynamic -C plugin=emitted.wasm",
    )?;
    suite.execute(
        "dynamic-execute",
        "dynamic.wasm",
        "--plugin emitted.wasm",
        "hello from Motor 42\n",
    )?;
    suite.command(
        "missing-dynamic-plugin",
        "MOTOR_OS_CAPS=0 /user/bin/wasmi dynamic.wasm",
        1,
    )?;
    behavior::run(&mut suite)?;
    suite.compile(
        "typescript",
        &format!("{SHARE}/typescript-workload.js"),
        "typescript.wasm",
        "",
    )?;
    suite.execute("typescript-execute", "typescript.wasm", "", "{\"version\":\"5.9.3\",\"output\":\";\\nconst item = { value: 42 };\\nconsole.log(item.value);\\n\",\"diagnostics\":0}\n")?;
    fs::write(
        suite.root.join("runner.wasm"),
        include_bytes!(concat!(env!("OUT_DIR"), "/runner.wasm")),
    )?;
    for (name, code) in [
        ("_start", 0),
        ("exit-zero", 0),
        ("exit-seven", 7),
        ("trap", 1),
        ("missing", 1),
        ("loop", 1),
    ] {
        suite.command(
            name,
            &format!("MOTOR_OS_CAPS=0 /user/bin/wasmi runner.wasm --invoke {name} --fuel 1000"),
            code,
        )?;
    }
    fs::write(suite.root.join("invalid.js"), "function { invalid")?;
    suite.command(
        "syntax-error",
        "MOTOR_OS_CAPS=0x200 /user/bin/javy build invalid.js -o invalid.wasm",
        1,
    )?;
    assert!(!suite.root.join("invalid.wasm").exists());
    suite.command(
        "direct-output-denial",
        "MOTOR_OS_CAPS=0 /user/bin/javy emit-plugin -o denied.wasm",
        1,
    )?;
    assert!(!suite.root.join("denied.wasm").exists());
    if admission_refusals()? != refusals {
        return Err("unexpected memory admission refusals".into());
    }
    fs::remove_dir_all(&suite.root)?;
    println!(
        "javy-smoke: {} commands PASS; admission_refusal_delta=0",
        suite.cases
    );
    Ok(())
}

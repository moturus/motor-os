//! Selected upstream p3 regressions; keep their lifetime/resource contracts.
use super::{Result, Suite, expect, invocation};

pub(super) fn run(suite: &mut Suite) -> Result<()> {
    suite.refusal(
        "p3-command-explicit-disabled",
        &invocation("0", "-S p3=n", "p3_cli_hello_stdout"),
        "a matching implementation was not found in the linker",
    )?;
    for program in ["p3_cli_hello_stdout", "p3_cli_hello_stdout_post_return"] {
        let (out, _) = suite.command(program, &invocation("0", "", program), 0)?;
        expect(program, &out, "hello, world\n")?;
    }
    // Upstream commands finish when run returns; suspended post-return stdout
    // is dropped. HTTP responses instead keep the handler's work alive.
    let (out, _) = suite.command(
        "p3-post-return-invoke",
        &invocation(
            "0",
            "--invoke 'wasi:cli/run.run@0.3.0()'",
            "p3_cli_hello_stdout_post_return",
        ),
        0,
    )?;
    expect("p3-post-return-invoke", &out, "hello, world\nok\n")?;
    // The fixture creates and drops 200 stream pairs under a 100-resource cap.
    let (out, _) = suite.command(
        "p3-stream-resources",
        &invocation("0", "-S max-resources=100", "p3_cli_many_stream"),
        0,
    )?;
    expect("p3-stream-resources", &out, "")?;
    // Unfinished tasks consume that same table and must hit its finite limit.
    suite.refusal(
        "p3-task-resources",
        &invocation("0", "-S max-resources=100", "p3_cli_many_tasks"),
        "resource table has no free keys",
    )
}

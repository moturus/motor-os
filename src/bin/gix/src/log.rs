use std::io::{self, Write};

use gix::bstr::ByteSlice;
use motor_gix::cancellation::Cancellation;

pub fn show(repo: &gix::Repository, cancellation: &Cancellation) -> motor_gix::Result {
    let mut output = io::BufWriter::new(io::stdout().lock());
    for info in repo.head_commit()?.ancestors().all()? {
        cancellation.check()?;
        let commit = info?.object()?;
        let message = commit.message()?;
        let title = message.title.trim_end().to_str_lossy();
        writeln!(output, "{} {}", commit.short_id()?, title.escape_debug())?;
    }
    cancellation.check()?;
    output.flush()?;
    cancellation.check()
}

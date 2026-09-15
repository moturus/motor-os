use std::io::{self, Write};

use gix::bstr::ByteSlice;

pub fn show(repo: &gix::Repository) -> motor_gix::Result {
    let mut output = io::BufWriter::new(io::stdout().lock());
    for info in repo.head_commit()?.ancestors().all()? {
        let commit = info?.object()?;
        let message = commit.message()?;
        let title = message.title.trim_end().to_str_lossy();
        writeln!(output, "{} {}", commit.short_id()?, title.escape_debug())?;
    }
    output.flush()?;
    Ok(())
}

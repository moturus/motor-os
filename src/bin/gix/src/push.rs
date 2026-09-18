use std::io::{self, Write};

use crate::{
    cancellation::Cancellation,
    network::Failure,
    push_discovery, push_objects, push_pack,
    push_policy::{self, Spec},
    push_protocol,
    push_report::Report,
    ssh,
};

#[derive(Debug, Eq, PartialEq)]
enum Publication {
    NoOp,
    DryRun,
    Report(Report),
}

pub fn run(
    repo: &gix::Repository,
    remote: &str,
    refspec: &str,
    lease: Option<&str>,
    dry_run: bool,
    cancellation: &Cancellation,
    out: impl Write,
) -> crate::Result {
    let spec = Spec::parse(refspec, lease)?;
    let source = spec
        .resolve(repo, cancellation)
        .map_err(|error| cancellation.normalize_error(error))?;
    let prepared = push_policy::remote(repo, remote)?;
    let (operation, registrar) = ssh::Operation::new(cancellation);
    let mut update_started = false;
    let transfer = (|| -> crate::Result<Publication> {
        let mut transport = prepared.transport(registrar);
        let advertised =
            push_discovery::discover(&mut transport, spec.destination.as_ref(), cancellation)?;
        let command = push_protocol::command(
            advertised.destination_old,
            source,
            spec.destination.as_ref(),
        )?;
        let no_op = spec.validate_update(repo, source, advertised.destination_old, cancellation)?;
        if no_op || dry_run {
            push_protocol::finish_discovery(&mut transport, cancellation)?;
            return Ok(if no_op {
                Publication::NoOp
            } else {
                Publication::DryRun
            });
        }
        let selection = push_objects::select(repo, source, &advertised.advertised, cancellation)?;
        let pack = push_pack::write(repo, &selection, repo.git_dir(), cancellation)?;
        let report = push_protocol::send(
            &mut transport,
            &command,
            spec.destination.as_ref(),
            pack.into_reader()?,
            cancellation,
            &mut update_started,
        )?;
        Ok(Publication::Report(report))
    })();
    // The scoped transport closes stdin before any child completion is inspected.
    let disposition = if transfer.is_ok() {
        ssh::Finish::Complete
    } else {
        ssh::Finish::Abort
    };
    let outcome = finish(
        transfer,
        operation.finish(disposition),
        update_started,
        cancellation,
    )?;
    let status = match outcome {
        Publication::NoOp => "up to date",
        Publication::DryRun => "would update",
        Publication::Report(Report::Accepted) => "remote accepted",
        Publication::Report(Report::Rejected(_)) => {
            unreachable!("finish returns rejections as errors")
        }
    };
    write_status(
        &format!("{status}: {} -> {source}", spec.destination.as_bstr()),
        out,
        cancellation,
    )
}

fn write_status(message: &str, mut out: impl Write, cancellation: &Cancellation) -> crate::Result {
    writeln!(out, "{message}")
        .and_then(|_| out.flush())
        .map_err(|error| {
            Failure::new(
                format!("{message}; failed to write command output"),
                cancellation.normalize_error(error.into()),
            )
        })?;
    cancellation.check().map_err(|source| {
        Failure::new(format!("{message}; command completion failed"), source).into()
    })
}

fn finish(
    transfer: crate::Result<Publication>,
    completion: crate::Result,
    update_started: bool,
    cancellation: &Cancellation,
) -> crate::Result<Publication> {
    let completion = completion.and_then(|()| cancellation.check());
    let (message, primary) = match transfer {
        Err(error) => (
            if update_started {
                "push outcome is unknown; inspect the remote ref before another push"
            } else {
                "push stopped before sending an update"
            }
            .to_owned(),
            Some(error),
        ),
        Ok(Publication::Report(Report::Rejected(reason))) => {
            (format!("remote rejected the update: {reason}"), None)
        }
        Ok(outcome) => match completion {
            Ok(()) => return Ok(outcome),
            Err(error) => {
                let message = match outcome {
                    Publication::Report(Report::Accepted) => {
                        "remote accepted the update; command completion failed"
                    }
                    _ => "no update was sent; command completion failed",
                };
                return Err(
                    Failure::new(message.into(), cancellation.normalize_error(error)).into(),
                );
            }
        },
    };
    let source = match (primary, completion) {
        (Some(primary), Err(secondary)) => Some(
            Failure::with_secondary("command completion also failed", primary, secondary).into(),
        ),
        (Some(primary), Ok(())) => Some(primary),
        (None, Err(secondary)) => Some(secondary),
        (None, Ok(())) => None,
    };
    match source {
        Some(source) => Err(Failure::new(message, cancellation.normalize_error(source)).into()),
        None => Err(io::Error::other(message).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CancelOnFlush<'a>(&'a Cancellation);

    impl Write for CancelOnFlush<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.cancel();
            Ok(())
        }
    }

    #[test]
    fn cancellation_during_successful_output_preserves_acceptance() {
        let cancellation = Cancellation::new();
        let error = write_status(
            "remote accepted: refs/heads/main",
            CancelOnFlush(&cancellation),
            &cancellation,
        )
        .unwrap_err();
        assert!(error.to_string().contains("remote accepted"));
        assert!(crate::cancellation::was_cancelled(error.as_ref()));
    }

    #[test]
    fn completion_preserves_confirmed_results_and_unknown_outcomes() {
        let cancellation = Cancellation::new();
        let failed = || Err(io::Error::other("SSH failed").into());
        let accepted = || Ok(Publication::Report(Report::Accepted));
        assert_eq!(
            finish(accepted(), Ok(()), true, &cancellation).unwrap(),
            Publication::Report(Report::Accepted)
        );
        let error = finish(accepted(), failed(), true, &cancellation).unwrap_err();
        assert!(error.to_string().contains("remote accepted"));
        assert_eq!(error.source().unwrap().to_string(), "SSH failed");
        let rejected = Ok(Publication::Report(Report::Rejected("stale old ID".into())));
        assert!(
            finish(rejected, failed(), true, &cancellation)
                .unwrap_err()
                .to_string()
                .contains("remote rejected")
        );
        for started in [false, true] {
            let protocol = Err(io::Error::other("truncated report").into());
            let error = finish(protocol, failed(), started, &cancellation).unwrap_err();
            assert_eq!(error.to_string().contains("unknown"), started);
            assert!(error.source().unwrap().to_string().contains("SSH failed"));
            assert_eq!(
                error.source().unwrap().source().unwrap().to_string(),
                "truncated report"
            );
        }
        cancellation.cancel();
        for completion in [Ok(()), failed()] {
            let error = finish(accepted(), completion, true, &cancellation).unwrap_err();
            assert!(error.to_string().contains("remote accepted"));
            assert!(crate::cancellation::was_cancelled(error.as_ref()));
        }
    }
}

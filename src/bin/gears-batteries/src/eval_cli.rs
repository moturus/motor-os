//! Manual held-out suites share frozen executables and never change review settings.

use crate::{
    eval_actor::Selection, eval_binary, eval_options::Options, eval_prepare, eval_report,
    eval_suite, eval_task, paths::ToolContext,
};
use gears::{
    process::{self, Cancellation},
    state::StateRoot,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::Write, path::Path, time::Instant};

pub fn run(args: &[String], mut output: impl Write) -> Result<(), String> {
    process::ensure_cleanup()?;
    let mut options = Options::parse(args)?;
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    for path in [&mut options.root, &mut options.output] {
        if !path.is_absolute() {
            *path = cwd.join(&*path);
        }
    }
    let tasks = options
        .tasks
        .iter()
        .map(|path| eval_task::load(path))
        .collect::<Result<Vec<_>, _>>()?;
    let mut names = BTreeSet::new();
    for task in &tasks {
        if !names.insert(task.name.clone()) {
            return Err("evaluation task names must be distinct".into());
        }
    }
    let source = ToolContext::new(
        tasks[0].task.workspace.clone(),
        options.root.clone(),
        "evaluation-source".into(),
        None,
    )?;
    let root = ToolContext::new(
        source.workspace.clone(),
        options.output.clone(),
        "evaluation-output".into(),
        None,
    )?
    .state;
    for task in &tasks {
        if root.path().starts_with(&task.task.workspace)
            || task.task.workspace.starts_with(root.path())
        {
            return Err("evaluation output must be separate from every source workspace".into());
        }
    }
    match std::fs::symlink_metadata(root.path()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("evaluation output must be fresh".into()),
    }
    let mut acquisition = eval_report::acquisition(&source)?;
    let reviews = crate::review_config::load(&source.state)?;
    acquisition["configured_review_pair"] =
        json!({"executor":reviews.executor,"reviewer":reviews.reviewer});
    acquisition["pairing_coverage"] =
        json!("Current source configuration only; historical pairing is not reconstructed.");
    if !gears::platform::install_interrupt_handler() {
        return Err("cannot install evaluation interrupt handler".into());
    }
    let cancel = Cancellation::new();
    let start = Instant::now();
    let configuration = json!({"provider":options.provider,"model":options.model,"actor_seconds":options.actor_timeout.as_secs(),"command_seconds":options.settings.command_timeout.as_secs(),"repetitions":options.settings.repetitions,"tasks":tasks.len()});
    let reporting = Reporting {
        root: &root,
        configuration,
        options: &options,
        acquisition,
        start,
    };
    let mut reports = Vec::new();
    let mut inputs = json!({"tasks":[],"executables":null});
    reporting.save(&reports, &inputs, "running", None)?;
    let result = (|| -> Result<(), String> {
        if cancel.cancelled() {
            return Err("evaluation cancelled".into());
        }
        let binaries = eval_binary::pin(
            &root,
            &options.gears,
            &std::env::current_exe().map_err(|e| e.to_string())?,
        )?;
        inputs["executables"] = binaries;
        let mut prepared = Vec::new();
        // Capture every task before the first model request; subsequent trials read frozen inputs.
        for task in tasks {
            if cancel.cancelled() {
                return Err("evaluation cancelled".into());
            }
            let context = ToolContext::new(
                task.task.workspace.clone(),
                options.root.clone(),
                "evaluation-source".into(),
                None,
            )?;
            let name = task.name.clone();
            let selected = eval_prepare::prepare(
                &context,
                task,
                &options.config,
                &root.path().join("tasks").join(name),
                &root.path().join("bin/gears-batteries"),
            )?;
            inputs["tasks"]
                .as_array_mut()
                .unwrap()
                .push(selected.identity.clone());
            prepared.push(selected);
        }
        root.replace_file(
            Path::new("inputs.json"),
            &serde_json::to_vec_pretty(&inputs).map_err(|e| e.to_string())?,
        )?;
        reporting.save(&reports, &inputs, "running", None)?;
        let program = root.path().join("bin/gears");
        let selection = Selection {
            gears: &program,
            provider: &options.provider,
            model: &options.model,
            timeout: options.actor_timeout,
        };
        for task in &prepared {
            if cancel.cancelled() {
                return Err("evaluation cancelled".into());
            }
            process::ensure_cleanup()?;
            let report = eval_suite::run(
                task,
                &selection,
                &options.settings,
                reporting.acquisition.clone(),
                &cancel,
            )?;
            let completed = report["status"] == "complete";
            reports.push(json!({"task":task.task.name,"report":report,"path":task.root.path().join("report.json"),"directory":task.root.path()}));
            reporting.save(&reports, &inputs, "running", None)?;
            if !completed {
                return Err(format!(
                    "task {} did not complete; see its preserved report",
                    task.task.name
                ));
            }
        }
        Ok(())
    })();
    let (status, error) = match result {
        Ok(()) => ("complete", None),
        Err(error) => (
            if cancel.cancelled() {
                "cancelled"
            } else {
                "failed"
            },
            Some(error),
        ),
    };
    let report = reporting.save(&reports, &inputs, status, error.as_deref())?;
    serde_json::to_writer_pretty(&mut output, &report).map_err(|e| e.to_string())?;
    writeln!(output).map_err(|e| e.to_string())?;
    if let Some(error) = error {
        return Err(format!(
            "{error}; report: {}",
            root.path().join("report.json").display()
        ));
    }
    Ok(())
}

struct Reporting<'a> {
    root: &'a StateRoot,
    configuration: Value,
    options: &'a Options,
    acquisition: Value,
    start: Instant,
}
impl Reporting<'_> {
    fn save(
        &self,
        reports: &[Value],
        inputs: &Value,
        status: &str,
        error: Option<&str>,
    ) -> Result<Value, String> {
        let mut rows = Vec::new();
        for task in reports {
            for row in task["report"]["trials"].as_array().into_iter().flatten() {
                let mut row = row.clone();
                row["task"] = task["task"].clone();
                row["artifacts_base"] = task["directory"].clone();
                rows.push(row);
            }
        }
        let mut report = eval_report::summarize(
            &rows,
            inputs.clone(),
            self.configuration.clone(),
            &self.options.settings.criterion,
            self.acquisition.clone(),
            self.start.elapsed().as_millis().min(u64::MAX as u128) as u64,
        );
        report["status"] = json!(status);
        report["error"] = json!(error);
        report["task_reports"] = json!(
            reports
                .iter()
                .map(|r| json!({"task":r["task"],"status":r["report"]["status"],"path":r["path"]}))
                .collect::<Vec<_>>()
        );
        self.root.replace_file(
            Path::new("report.json"),
            &serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
        )?;
        Ok(report)
    }
}

//! Live evaluations require an explicit task, model, budgets and success criterion.

use crate::eval_suite::Settings;
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

pub const USAGE:&str="usage: gears-batteries eval --task FILE [--task FILE ...] --config FILE --provider NAME --model NAME
       --trials N --seconds N --command-seconds N --criterion TEXT --output DIR
       [--root DIR] [--gears PROGRAM]
Runs both arms 2–16 times each. Output must be fresh and outside the source workspace.
Programs and task checks are trusted user code. Real model requests incur provider costs.";

pub struct Options {
    pub tasks: Vec<PathBuf>,
    pub config: PathBuf,
    pub output: PathBuf,
    pub root: PathBuf,
    pub gears: PathBuf,
    pub provider: String,
    pub model: String,
    pub actor_timeout: Duration,
    pub settings: Settings,
}
impl Options {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some("eval") {
            return Err(USAGE.into());
        }
        let mut tasks = Vec::new();
        let mut values = BTreeMap::new();
        let mut rest = args.iter().skip(1);
        while let Some(flag) = rest.next() {
            if ![
                "--task",
                "--config",
                "--output",
                "--root",
                "--gears",
                "--provider",
                "--model",
                "--trials",
                "--seconds",
                "--command-seconds",
                "--criterion",
            ]
            .contains(&flag.as_str())
            {
                return Err(format!("unknown eval option: {flag}"));
            }
            let value = rest
                .next()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("{flag} needs a value"))?;
            if flag == "--task" {
                tasks.push(PathBuf::from(value));
                continue;
            }
            if values.insert(flag.as_str(), value.as_str()).is_some() {
                return Err(format!("duplicate eval option: {flag}"));
            }
        }
        if tasks.is_empty() || tasks.len() > 32 {
            return Err("evaluation needs 1–32 explicit task files".into());
        }
        let required = |key: &str| {
            values
                .get(key)
                .copied()
                .ok_or_else(|| format!("{key} is required\n{USAGE}"))
        };
        let number = |key: &str, range: std::ops::RangeInclusive<u64>| -> Result<u64, String> {
            let text = required(key)?;
            let value = text
                .parse::<u64>()
                .map_err(|_| format!("{key} needs an integer"))?;
            if !text.bytes().all(|b| b.is_ascii_digit()) || !range.contains(&value) {
                return Err(format!("{key} is outside its supported range"));
            }
            Ok(value)
        };
        let provider = required("--provider")?.to_string();
        let model = required("--model")?.to_string();
        if [&provider, &model]
            .iter()
            .any(|s| s.trim().is_empty() || s.chars().any(char::is_control))
        {
            return Err("provider/model names must be nonempty and contain no controls".into());
        }
        let criterion = required("--criterion")?.to_string();
        if criterion.trim().is_empty()
            || criterion.len() > 8192
            || criterion
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
        {
            return Err("criterion must be nonempty, at most 8 KiB, without controls".into());
        }
        Ok(Self {
            tasks,
            config: required("--config")?.into(),
            output: required("--output")?.into(),
            root: match values.get("--root") {
                Some(value) => PathBuf::from(value),
                None => crate::default_root()?,
            },
            gears: match values.get("--gears") {
                Some(value) => PathBuf::from(value),
                None => std::env::current_exe()
                    .map_err(|e| e.to_string())?
                    .with_file_name("gears"),
            },
            provider,
            model,
            actor_timeout: Duration::from_secs(number("--seconds", 1..=3600)?),
            settings: Settings {
                repetitions: number("--trials", 2..=16)? as usize,
                command_timeout: Duration::from_secs(number("--command-seconds", 1..=3600)?),
                criterion,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Budgets and a quality criterion are required before any evaluation side effects.
    #[test]
    fn budgets_and_criterion_are_required() {
        let root =
            std::env::temp_dir().join(format!("batteries-eval-options-{}", std::process::id()));
        let args = vec![
            "eval".into(),
            "--task".into(),
            "first.toml".into(),
            "--task".into(),
            "second.toml".into(),
            "--config".into(),
            "eval.toml".into(),
            "--root".into(),
            root.display().to_string(),
            "--gears".into(),
            "./gears".into(),
            "--provider".into(),
            "local".into(),
            "--model".into(),
            "chosen-model".into(),
            "--trials".into(),
            "2".into(),
            "--seconds".into(),
            "60".into(),
            "--command-seconds".into(),
            "30".into(),
            "--criterion".into(),
            "More accepted tasks with no regressions.".into(),
            "--output".into(),
            "fresh-output".into(),
        ];
        let options = Options::parse(&args).unwrap();
        assert_eq!(options.tasks.len(), 2);
        assert_eq!(options.settings.repetitions, 2);
        for flag in ["--trials", "--seconds", "--command-seconds", "--criterion"] {
            let index = args.iter().position(|s| s == flag).unwrap();
            let mut bad = args.clone();
            bad[index + 1] = if flag == "--criterion" {
                " ".into()
            } else {
                "0".into()
            };
            assert!(Options::parse(&bad).is_err());
            let mut missing = args.clone();
            missing.drain(index..=index + 1);
            assert!(Options::parse(&missing).is_err());
        }
        let mut duplicate = args.clone();
        duplicate.extend(["--model".into(), "extra".into()]);
        assert!(Options::parse(&duplicate).is_err());
        let mut excessive = args.clone();
        for _ in 0..31 {
            excessive.extend(["--task".into(), "extra.toml".into()]);
        }
        assert!(Options::parse(&excessive).is_err());
        assert!(Options::parse(&["eval".into()]).is_err());
        assert!(!root.exists());
    }
}

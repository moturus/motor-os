//! First-run and `/setup` questions: the provider, a local server's address,
//! the model and the API key. Answers are saved in the Gears directory, never
//! in `gears.toml`.

use std::path::Path;

use crate::config::{Config, NamedProvider};
use crate::provider_choice::ProviderChoice;

/// How a UI asks; `None` means the user cancelled.
pub trait Ask {
    fn choose(&mut self, title: &str, items: &[String]) -> Result<Option<usize>, String>;
    /// `hidden` input is not shown while typed.
    fn text(&mut self, title: &str, hidden: bool) -> Result<Option<String>, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chosen {
    pub provider: String,
    pub model: String,
}

const OTHER: &str = "Other…";

/// When Gears runs from its source tree and the Gears directory has its own
/// settings, ask which to use. `Some(true)` picks the shipped ones.
pub fn ask_settings(
    ask: &mut dyn Ask,
    user: &Path,
    package: &Path,
) -> Result<Option<bool>, String> {
    let title = format!(
        "Gears is running from its source tree, {}. Which settings should it use?",
        package.display()
    );
    let items = [
        format!("Your settings: {}", user.display()),
        format!(
            "The settings that ship with this source: {}",
            package.join("config/gears.toml").display()
        ),
    ];
    Ok(ask.choose(&title, &items)?.map(|index| index == 1))
}

/// Ask for a provider, its address when it is a local server, a model and a
/// missing key; save them in `directory`. `None` if the user cancelled.
pub fn run(config: &Config, directory: &Path, ask: &mut dyn Ask) -> Result<Option<Chosen>, String> {
    let mut names = config.providers.keys().cloned().collect::<Vec<_>>();
    if names.is_empty() {
        return Err("gears.toml defines no providers".into());
    }
    if let Some(index) = names
        .iter()
        .position(|name| *name == config.default_provider)
    {
        let default = names.remove(index);
        names.insert(0, default);
    }
    let labels = names
        .iter()
        .map(|name| format!("{name}  {}", config.providers[name].base_url))
        .collect::<Vec<_>>();
    let Some(index) = ask.choose("Choose a provider", &labels)? else {
        return Ok(None);
    };
    let name = names[index].clone();
    let provider = &config.providers[&name];
    let url = if provider.plain_http {
        let Some(url) = ask_url(ask, &name, provider)? else {
            return Ok(None);
        };
        Some(url)
    } else {
        None
    };
    let mut models = provider.models.clone();
    models.push(OTHER.into());
    let Some(index) = ask.choose(&format!("Choose a model for {name}"), &models)? else {
        return Ok(None);
    };
    let model = if index + 1 == models.len() {
        match ask.text("Model id", false)? {
            Some(model) if !model.trim().is_empty() => model.trim().to_string(),
            _ => return Ok(None),
        }
    } else {
        models[index].clone()
    };
    if !ask_key(ask, &name, provider)? {
        return Ok(None);
    }
    let mut urls = ProviderChoice::load_at(directory)?
        .map(|saved| saved.urls)
        .unwrap_or_default();
    match url {
        Some(url) if url != provider.base_url => {
            urls.insert(name.clone(), url);
        }
        Some(_) => {
            urls.remove(&name);
        }
        None => {}
    }
    ProviderChoice {
        urls,
        ..ProviderChoice::new(&name, &model)?
    }
    .save_at(directory)?;
    Ok(Some(Chosen {
        provider: name,
        model,
    }))
}

/// Ask for the key when the provider's key file is missing. False if cancelled.
pub fn ask_key(ask: &mut dyn Ask, name: &str, provider: &NamedProvider) -> Result<bool, String> {
    let Some(path) = provider.key_file.as_deref().filter(|path| !path.exists()) else {
        return Ok(true);
    };
    let title = format!("API key for {name} (saved in {})", path.display());
    loop {
        let Some(text) = ask.text(&title, true)? else {
            return Ok(false);
        };
        if text.trim().is_empty() {
            return Ok(false);
        }
        match crate::provider::ApiKey::parse(&text, "the key") {
            Ok(key) => {
                save_key(path, key.expose())?;
                return Ok(true);
            }
            Err(_) => continue,
        }
    }
}

fn ask_url(
    ask: &mut dyn Ask,
    name: &str,
    provider: &NamedProvider,
) -> Result<Option<String>, String> {
    let mut suggestions = vec![provider.base_url.clone()];
    // From a Motor OS VM the host machine is 192.168.4.1.
    if cfg!(target_os = "motor") {
        let host = provider
            .base_url
            .replacen("://127.0.0.1", "://192.168.4.1", 1);
        if host != provider.base_url {
            suggestions.push(host);
        }
    }
    suggestions.push(OTHER.into());
    let Some(index) = ask.choose(&format!("Address of the {name} server"), &suggestions)? else {
        return Ok(None);
    };
    if index + 1 < suggestions.len() {
        return Ok(Some(suggestions[index].clone()));
    }
    loop {
        let Some(url) = ask.text("Server URL, such as http://192.168.4.1:8080/v1", false)? else {
            return Ok(None);
        };
        let url = url.trim();
        if url.is_empty() {
            return Ok(None);
        }
        if crate::provider::Endpoint::new(url).is_ok() {
            return Ok(Some(url.to_string()));
        }
    }
}

/// The key file is readable by its owner only.
fn save_key(path: &Path, key: &str) -> Result<(), String> {
    let error = |error: std::io::Error| format!("{}: {error}", path.display());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(error)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(error)?;
    std::io::Write::write_all(&mut file, format!("{key}\n").as_bytes()).map_err(error)?;
    file.sync_data().map_err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug)]
    enum Answer {
        Pick(usize),
        Type(&'static str),
        Cancel,
    }

    #[derive(Default)]
    struct Script {
        answers: VecDeque<Answer>,
        asked: Vec<String>,
    }

    impl Ask for Script {
        fn choose(&mut self, title: &str, items: &[String]) -> Result<Option<usize>, String> {
            self.asked.push(format!("{title}: {}", items.join(" | ")));
            match self.answers.pop_front() {
                Some(Answer::Pick(index)) => Ok(Some(index)),
                Some(Answer::Cancel) => Ok(None),
                other => Err(format!("unexpected answer {other:?} to {title}")),
            }
        }

        fn text(&mut self, title: &str, hidden: bool) -> Result<Option<String>, String> {
            self.asked.push(format!("{title} hidden={hidden}"));
            match self.answers.pop_front() {
                Some(Answer::Type(text)) => Ok(Some(text.into())),
                Some(Answer::Cancel) => Ok(None),
                other => Err(format!("unexpected answer {other:?} to {title}")),
            }
        }
    }

    fn fixture(name: &str) -> (std::path::PathBuf, Config) {
        let root = std::env::temp_dir().join(format!("gears-setup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let config = Config::parse_in(include_str!("../config/gears.toml"), &root).unwrap();
        (root, config)
    }

    fn script(answers: Vec<Answer>) -> Script {
        Script {
            answers: answers.into(),
            asked: Vec::new(),
        }
    }

    #[test]
    fn a_cloud_provider_asks_model_and_hidden_key_and_saves_both() {
        let (root, config) = fixture("cloud");
        let mut ask = script(vec![
            Answer::Pick(0),
            Answer::Pick(1),
            Answer::Type(" sk-typed \n"),
        ]);
        let chosen = run(&config, &root, &mut ask).unwrap().unwrap();
        assert_eq!(chosen.provider, "openrouter");
        assert_eq!(chosen.model, "google/gemini-3.8-flash");
        assert!(ask.asked[0].starts_with("Choose a provider: openrouter "));
        assert!(ask.asked[2].ends_with("hidden=true"), "{:?}", ask.asked);
        assert_eq!(
            std::fs::read_to_string(root.join("openrouter.key")).unwrap(),
            "sk-typed\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.join("openrouter.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let saved = ProviderChoice::load_at(&root).unwrap().unwrap();
        assert_eq!(
            (saved.provider.as_str(), saved.model.as_str()),
            ("openrouter", "google/gemini-3.8-flash")
        );
        // With the key saved, choosing again asks no key question.
        let mut again = script(vec![Answer::Pick(0), Answer::Pick(0)]);
        run(&config, &root, &mut again).unwrap().unwrap();
        assert_eq!(again.asked.len(), 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_local_server_asks_its_address_and_needs_no_key() {
        let (root, config) = fixture("local");
        // The default provider comes first, then the others sorted: local is second.
        let index = 1;
        let mut ask = script(vec![
            Answer::Pick(index),
            Answer::Pick(usize::from(cfg!(target_os = "motor")) + 1),
            Answer::Type("not a url"),
            Answer::Type("http://10.0.0.5:8080/v1"),
            Answer::Pick(1),
            Answer::Type("my-model"),
        ]);
        let chosen = run(&config, &root, &mut ask).unwrap().unwrap();
        assert_eq!(
            chosen,
            Chosen {
                provider: "local".into(),
                model: "my-model".into()
            }
        );
        assert!(
            !ask.asked
                .iter()
                .any(|question| question.contains("API key"))
        );
        let saved = ProviderChoice::load_at(&root).unwrap().unwrap();
        assert_eq!(saved.urls["local"], "http://10.0.0.5:8080/v1");
        // Picking the configured address again drops the saved one.
        let mut again = script(vec![Answer::Pick(index), Answer::Pick(0), Answer::Pick(0)]);
        run(&config, &root, &mut again).unwrap().unwrap();
        assert!(
            ProviderChoice::load_at(&root)
                .unwrap()
                .unwrap()
                .urls
                .is_empty()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancelling_saves_nothing_and_the_settings_question_names_both_files() {
        let (root, config) = fixture("cancel");
        for answers in [
            vec![Answer::Cancel],
            vec![Answer::Pick(0), Answer::Cancel],
            vec![Answer::Pick(0), Answer::Pick(0), Answer::Cancel],
            vec![Answer::Pick(0), Answer::Pick(0), Answer::Type("")],
        ] {
            assert_eq!(run(&config, &root, &mut script(answers)).unwrap(), None);
        }
        assert!(ProviderChoice::load_at(&root).unwrap().is_none());
        assert!(!root.join("openrouter.key").exists());
        let mut ask = script(vec![Answer::Pick(1)]);
        let package = Path::new("/src/gears");
        assert_eq!(
            ask_settings(&mut ask, Path::new("/home/u/.gears/gears.toml"), package).unwrap(),
            Some(true)
        );
        assert!(ask.asked[0].contains("/home/u/.gears/gears.toml"));
        assert!(ask.asked[0].contains("/src/gears/config/gears.toml"));
        std::fs::remove_dir_all(root).unwrap();
    }
}

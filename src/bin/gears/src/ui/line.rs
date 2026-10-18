//! Plain terminal UI for interactive and one-shot runs.

use std::collections::VecDeque;
use std::io::{self, IsTerminal, Write};
use std::sync::mpsc;
use std::time::Duration;

use crate::runtime::{Approval, Approver, Event, Observer, Permission, Runtime};

const POLL: Duration = Duration::from_millis(25);

pub fn run(
    runtime: &mut Runtime,
    initial: Option<String>,
    interactive: bool,
    config: &crate::config::Config,
) -> Result<(), String> {
    runtime.set_interactive(interactive)?;
    let mut input = Input::new()?;
    let mut renderer = Renderer {
        hint: runtime.hint().map(str::to_string),
        ..Renderer::default()
    };
    if interactive {
        show_history(runtime)?;
    }
    for notice in runtime.take_startup_notices() {
        renderer.event(Event::Notice(notice))?;
    }
    if interactive && runtime.pending_hook_questions() {
        run_operation(
            runtime,
            super::Operation::Questions,
            true,
            &mut input,
            &mut renderer,
        )?;
    }
    if let Some(prompt) = initial {
        let result = run_turn(runtime, prompt, interactive, &mut input, &mut renderer);
        renderer.finish_stream();
        result?;
        if !interactive {
            return Ok(());
        }
    }
    if !interactive {
        return Ok(());
    }

    loop {
        show_runtime_notices(runtime, &mut renderer)?;
        let Some(line) = input.read_line("gears> ")? else {
            renderer.finish_stream();
            return Ok(());
        };
        let line = line.trim_end().to_string();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('/') {
            let result = command(runtime, &line, config, &mut input, &mut renderer);
            if !matches!(&result, Ok(Command::Quit)) && runtime.pending_hook_questions() {
                run_operation(
                    runtime,
                    super::Operation::Questions,
                    true,
                    &mut input,
                    &mut renderer,
                )?;
            }
            show_runtime_notices(runtime, &mut renderer)?;
            match result {
                Ok(Command::Continue) => continue,
                Ok(Command::Quit) => return Ok(()),
                Ok(Command::Draft(draft)) => {
                    eprintln!("draft> {draft}");
                    continue;
                }
                Err(error) => {
                    eprintln!("gears: {error}");
                    continue;
                }
            }
        }
        if let Err(error) = run_turn(runtime, line, true, &mut input, &mut renderer) {
            renderer.finish_stream();
            eprintln!("gears: {error}");
        } else {
            renderer.finish_stream();
        }
    }
}

enum Command {
    Continue,
    Quit,
    Draft(String),
}

fn command(
    runtime: &mut Runtime,
    line: &str,
    config: &crate::config::Config,
    input: &mut Input,
    renderer: &mut Renderer,
) -> Result<Command, String> {
    let (name, argument) = line[1..]
        .split_once(char::is_whitespace)
        .map_or((&line[1..], ""), |(name, rest)| (name, rest.trim()));
    match name {
        "quit" | "exit" => Ok(Command::Quit),
        "help" => {
            eprintln!("{}", super::help(runtime));
            Ok(Command::Continue)
        }
        "status" => {
            eprintln!(
                "provider: {}\nmodel: {}\nusage: {}",
                runtime.provider_name(),
                runtime.model(),
                runtime.usage().summary()
            );
            show_session(runtime);
            Ok(Command::Continue)
        }
        "tools" => {
            eprintln!("{}", super::format_tools(runtime)?);
            Ok(Command::Continue)
        }
        "tool" => {
            let (name, state, global) = super::parse_tool_action(argument)?;
            runtime.set_tool_state(name, state, global)?;
            eprintln!("{}", super::format_tools(runtime)?);
            Ok(Command::Continue)
        }
        "permissions" => {
            eprintln!("{}", super::format_permissions(runtime)?);
            Ok(Command::Continue)
        }
        "permission" => {
            let (name, global) = super::parse_permission_action(argument)?;
            runtime.revoke_permission(name, global)?;
            eprintln!("{}", super::format_permissions(runtime)?);
            Ok(Command::Continue)
        }
        "session" => {
            show_session(runtime);
            Ok(Command::Continue)
        }
        "name" => {
            runtime.set_name(argument)?;
            show_session(runtime);
            Ok(Command::Continue)
        }
        "new" => {
            runtime.new_session(argument == "--ephemeral", None)?;
            show_history(runtime)?;
            show_runtime_notices(runtime, renderer)?;
            show_session(runtime);
            Ok(Command::Continue)
        }
        "setup" => {
            let current = super::current_config(config)?;
            let directory = crate::directory::default_root()?;
            match crate::setup::run(&current, &directory, &mut InputAsk(input))? {
                Some(chosen) => runtime.apply_setup(&chosen.provider, chosen.model, renderer)?,
                None => eprintln!("Setup cancelled."),
            }
            Ok(Command::Continue)
        }
        "reset" => {
            let answer = input.read_line(&format!(
                "{} Continue? [yes/no] ",
                crate::reset::DESCRIPTION
            ))?;
            if !matches!(answer.as_deref().map(str::trim), Some("yes" | "y")) {
                eprintln!("Reset cancelled.");
                return Ok(Command::Continue);
            }
            let removed = runtime.reset()?;
            eprintln!("{}", super::reset_notice(removed));
            show_runtime_notices(runtime, renderer)?;
            show_session(runtime);
            Ok(Command::Continue)
        }
        "resume" => {
            let selector = if argument.is_empty() {
                choose_session(runtime, input)?
            } else {
                argument.to_string()
            };
            runtime.resume(&selector)?;
            show_history(runtime)?;
            show_runtime_notices(runtime, renderer)?;
            show_session(runtime);
            Ok(Command::Continue)
        }
        "label" => {
            let (entry, label) = argument
                .split_once(char::is_whitespace)
                .map_or((argument, ""), |(entry, label)| (entry, label.trim()));
            if entry.is_empty() {
                return Err("usage: /label ENTRY [TEXT]".to_string());
            }
            runtime.set_label(entry, (!label.is_empty()).then_some(label))?;
            Ok(Command::Continue)
        }
        "tree" => {
            let id = if argument.is_empty() {
                choose_tree(runtime, input, false)?
            } else {
                argument.to_string()
            };
            eprintln!("note: changing the conversation branch does not undo shell side effects");
            let draft = runtime.select_entry(&id)?;
            show_history(runtime)?;
            match draft {
                Some(draft) => Ok(Command::Draft(draft)),
                None => Ok(Command::Continue),
            }
        }
        "fork" => {
            let id = if argument.is_empty() {
                choose_tree(runtime, input, true)?
            } else {
                argument.to_string()
            };
            eprintln!("note: forking the conversation does not undo shell side effects");
            let draft = runtime.fork_at(&id)?;
            show_history(runtime)?;
            show_runtime_notices(runtime, renderer)?;
            show_session(runtime);
            Ok(Command::Draft(draft))
        }
        "clone" => {
            eprintln!("note: cloning the conversation does not undo shell side effects");
            runtime.clone_session()?;
            show_history(runtime)?;
            show_runtime_notices(runtime, renderer)?;
            show_session(runtime);
            Ok(Command::Continue)
        }
        "compact" => {
            runtime.compact(
                (!argument.is_empty()).then(|| argument.to_string()),
                renderer,
            )?;
            Ok(Command::Continue)
        }
        "model" => {
            let (argument, save_default) = super::selection_and_default(argument);
            let model = if argument.is_empty() {
                choose_model(
                    runtime.model(),
                    &super::model_choices(config, runtime.provider_name()),
                    input,
                )?
            } else {
                argument.to_string()
            };
            runtime.set_model(model, renderer)?;
            if save_default {
                runtime.save_default_selection()?;
                renderer.event(Event::Notice(
                    "saved provider and model defaults".to_string(),
                ))?;
            }
            Ok(Command::Continue)
        }
        "provider" => {
            let (argument, save_default) = super::selection_and_default(argument);
            let provider = if argument.is_empty() {
                choose_named(
                    runtime.provider_name(),
                    &config.providers.keys().cloned().collect::<Vec<_>>(),
                    input,
                    "provider",
                )?
            } else {
                argument.to_string()
            };
            runtime.set_provider(&provider, renderer)?;
            if save_default {
                runtime.save_default_selection()?;
                renderer.event(Event::Notice(
                    "saved provider and model defaults".to_string(),
                ))?;
            }
            Ok(Command::Continue)
        }
        "" => Ok(Command::Continue),
        other => {
            run_operation(
                runtime,
                super::Operation::HookCommand {
                    name: other.into(),
                    argument: argument.into(),
                },
                true,
                input,
                renderer,
            )?;
            renderer.finish_turn();
            Ok(Command::Continue)
        }
    }
}

fn show_runtime_notices(runtime: &mut Runtime, renderer: &mut Renderer) -> Result<(), String> {
    for notice in runtime.take_startup_notices() {
        renderer.event(Event::Notice(notice))?;
    }
    renderer.hint = runtime.hint().map(str::to_string);
    Ok(())
}

fn show_history(runtime: &Runtime) -> Result<(), String> {
    use super::history::Kind;

    let mut output = io::stdout().lock();
    super::history::replay(runtime.session(), |kind, text| {
        if text.is_empty() {
            return Ok(());
        }
        let label = match kind {
            Kind::User => "you",
            Kind::Assistant => "agent",
            Kind::Reasoning => "think",
            Kind::Tool | Kind::ToolOutput => "tool",
            Kind::Notice => "gears",
            Kind::Error => "error",
        };
        let text: String = text
            .chars()
            .map(|character| {
                if character.is_control() && !matches!(character, '\n' | '\t') {
                    '�'
                } else {
                    character
                }
            })
            .collect();
        writeln!(output, "{label}> {text}").map_err(|error| error.to_string())
    })?;
    output.flush().map_err(|error| error.to_string())
}

fn show_session(runtime: &Runtime) {
    let session = runtime.summary();
    eprintln!("session: {}", session.id);
    eprintln!(
        "path: {}",
        session
            .path
            .as_deref()
            .map_or("<ephemeral>".to_string(), |path| path.display().to_string())
    );
    if let Some(name) = session.name {
        eprintln!("name: {name}");
    }
    eprintln!("entries: {}", session.entries);
}

fn choose_session(runtime: &Runtime, input: &mut Input) -> Result<String, String> {
    let sessions = runtime.list_sessions()?;
    if sessions.is_empty() {
        return Err("no saved sessions for this workspace".to_string());
    }
    for (index, session) in sessions.iter().enumerate() {
        eprintln!(
            "{:>3}. {}  {}  {} messages",
            index + 1,
            session.id,
            session.name.as_deref().unwrap_or(""),
            session.messages
        );
    }
    let selected = input
        .read_line("session number or id> ")?
        .ok_or("session selection ended")?;
    if let Ok(index) = selected.trim().parse::<usize>()
        && let Some(session) = sessions.get(index.saturating_sub(1))
    {
        return Ok(session.id.clone());
    }
    Ok(selected.trim().to_string())
}

fn choose_tree(runtime: &Runtime, input: &mut Input, user_only: bool) -> Result<String, String> {
    let items = runtime.tree();
    let visible = items
        .iter()
        .filter(|item| !user_only || item.user_message)
        .collect::<Vec<_>>();
    if visible.is_empty() {
        return Err("the session tree is empty".to_string());
    }
    for (index, item) in visible.iter().enumerate() {
        eprintln!(
            "{:>3}. {}{} [{}] {}",
            index + 1,
            if item.active { "* " } else { "  " },
            item.id,
            item.kind,
            item.summary
        );
    }
    let selected = input
        .read_line("entry number or id> ")?
        .ok_or("tree selection ended")?;
    if let Ok(index) = selected.trim().parse::<usize>()
        && let Some(item) = visible.get(index.saturating_sub(1))
    {
        return Ok(item.id.clone());
    }
    Ok(selected.trim().to_string())
}

fn choose_model(current: &str, models: &[String], input: &mut Input) -> Result<String, String> {
    choose_named(current, models, input, "model")
}

fn choose_named(
    current: &str,
    values: &[String],
    input: &mut Input,
    label: &str,
) -> Result<String, String> {
    let mut choices = vec![current.to_string()];
    for value in values {
        if !choices.contains(value) {
            choices.push(value.clone());
        }
    }
    for (index, value) in choices.iter().enumerate() {
        eprintln!("{:>3}. {value}", index + 1);
    }
    let selected = input
        .read_line(&format!("{label} number or name> "))?
        .ok_or_else(|| format!("{label} selection ended"))?;
    if let Ok(index) = selected.trim().parse::<usize>()
        && let Some(value) = choices.get(index.saturating_sub(1))
    {
        return Ok(value.clone());
    }
    Ok(selected.trim().to_string())
}

#[derive(Default)]
struct Renderer {
    streaming: bool,
    hint: Option<String>,
}

impl Renderer {
    fn finish_turn(&mut self) {
        self.finish_stream();
        if let Some(hint) = &self.hint {
            eprintln!("gears: {hint}");
        }
    }

    fn finish_stream(&mut self) {
        if self.streaming {
            println!();
            self.streaming = false;
        }
    }
}

impl Observer for Renderer {
    fn event(&mut self, event: Event) -> Result<(), String> {
        match event {
            Event::Text(text) => {
                print!("{text}");
                io::stdout().flush().map_err(|error| error.to_string())?;
                self.streaming = true;
            }
            Event::Reasoning(text) => {
                eprint!("{text}");
                io::stderr().flush().map_err(|error| error.to_string())?;
            }
            Event::ToolStart { name, detail, .. } => {
                self.finish_stream();
                eprintln!("tool {name}> {detail}");
            }
            Event::ToolOutput { name, stream, text } => {
                eprint!("{name} {stream:?}> {text}");
                io::stderr().flush().map_err(|error| error.to_string())?;
            }
            Event::ToolEnd {
                name,
                content,
                is_error,
                ..
            } => {
                self.finish_stream();
                let outcome = if is_error { "error" } else { "done" };
                eprintln!("tool {name} {outcome}> {}", fold(&content));
            }
            Event::Permission(_) => {}
            Event::Notice(notice) => {
                self.finish_stream();
                eprintln!("gears: {notice}");
            }
            Event::Hint(hint) => self.hint = hint,
            Event::Usage { .. } => {}
            Event::TurnEnd { .. } => self.finish_turn(),
            Event::ModelChanged(model) => eprintln!("model: {model}"),
            Event::SessionChanged(_) => {}
        }
        Ok(())
    }
}

enum TurnMessage {
    Event(Event),
    Permission(Permission, mpsc::Sender<Approval>),
    Question(crate::hooks::Question, mpsc::Sender<Option<String>>),
    Done(Result<(), String>),
}

struct ChannelObserver {
    sender: mpsc::Sender<TurnMessage>,
}

impl Observer for ChannelObserver {
    fn event(&mut self, event: Event) -> Result<(), String> {
        self.sender
            .send(TurnMessage::Event(event))
            .map_err(|_| "line UI closed".to_string())
    }
}

struct ChannelApprover {
    sender: mpsc::Sender<TurnMessage>,
    interactive: bool,
}

impl Approver for ChannelApprover {
    fn attended(&self) -> bool {
        self.interactive
    }

    fn answer(&mut self, question: &crate::hooks::Question) -> Result<Option<String>, String> {
        if !self.interactive {
            return Ok(None);
        }
        let (sender, receiver) = mpsc::channel();
        self.sender
            .send(TurnMessage::Question(question.clone(), sender))
            .map_err(|_| "line UI closed".to_string())?;
        receiver.recv().map_err(|_| "line UI closed".to_string())
    }

    fn approve(&mut self, request: &Permission) -> Approval {
        if !self.interactive {
            eprintln!("gears: denied unattended tool call: {}", request.detail);
            return Approval::Deny;
        }
        let (sender, receiver) = mpsc::channel();
        if self
            .sender
            .send(TurnMessage::Permission(request.clone(), sender))
            .is_err()
        {
            return Approval::Deny;
        }
        receiver.recv().unwrap_or(Approval::Deny)
    }
}

fn run_turn(
    runtime: &mut Runtime,
    prompt: String,
    interactive: bool,
    input: &mut Input,
    renderer: &mut Renderer,
) -> Result<(), String> {
    run_operation(
        runtime,
        super::Operation::Turn(prompt),
        interactive,
        input,
        renderer,
    )
}

fn run_operation(
    runtime: &mut Runtime,
    operation: super::Operation,
    interactive: bool,
    input: &mut Input,
    renderer: &mut Renderer,
) -> Result<(), String> {
    let cancellation = runtime.cancellation();
    let (sender, receiver) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker_sender = sender.clone();
        scope.spawn(move || {
            let mut observer = ChannelObserver {
                sender: worker_sender.clone(),
            };
            let mut approver = ChannelApprover {
                sender: worker_sender,
                interactive,
            };
            let result = operation.run(runtime, &mut approver, &mut observer);
            let _ = sender.send(TurnMessage::Done(result));
        });
        loop {
            loop {
                match receiver.try_recv() {
                    Ok(TurnMessage::Event(event)) => renderer.event(event)?,
                    Ok(TurnMessage::Question(question, reply)) => {
                        renderer.finish_stream();
                        eprintln!("{}", question.text);
                        for (index, choice) in question.choices.iter().enumerate() {
                            eprintln!("  {}. {}", index + 1, choice.label);
                        }
                        let answer = loop {
                            let text = input.read_line("answer [number or value, Enter skip]> ")?;
                            match super::question_answer(&question, text.as_deref()) {
                                Ok(answer) => break answer,
                                Err(error) => eprintln!("gears: {error}"),
                            }
                        };
                        let _ = reply.send(answer);
                    }
                    Ok(TurnMessage::Permission(request, reply)) => {
                        renderer.finish_stream();
                        eprintln!(
                            "Allow {} in {}?\n  {}",
                            request.tool,
                            request.workspace.display(),
                            request.detail
                        );
                        let answer = input.read_line(
                            "[y allow once / s session / g global / n deny once / S session / G global] ",
                        )?;
                        let _ = reply.send(parse_approval(answer.as_deref()));
                    }
                    Ok(TurnMessage::Done(result)) => return result,
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        return Err("agent worker stopped unexpectedly".to_string());
                    }
                }
            }
            if input.poll_interrupt(POLL)? {
                cancellation.cancel();
            }
        }
    })
}

/// Anything but one explicit choice denies once, including end of input.
fn parse_approval(answer: Option<&str>) -> Approval {
    match answer.map(str::trim) {
        Some("y") => Approval::Once,
        Some("s") => Approval::Session,
        Some("g") => Approval::Global,
        Some("S") => Approval::DenySession,
        Some("G") => Approval::DenyGlobal,
        _ => Approval::Deny,
    }
}

struct Input {
    raw: Option<crate::platform::TerminalInput>,
    queued: VecDeque<u8>,
    skip_lf: bool,
}

impl Input {
    fn new() -> Result<Self, String> {
        let raw = if crate::platform::raw_console() {
            Some(crate::platform::TerminalInput::new().map_err(|error| error.to_string())?)
        } else {
            None
        };
        Ok(Self {
            raw,
            queued: VecDeque::new(),
            skip_lf: false,
        })
    }

    /// Like `read_line`, but what is typed is not shown.
    fn read_hidden(&mut self, prompt: &str) -> Result<Option<String>, String> {
        print!("{prompt}");
        io::stdout().flush().map_err(|error| error.to_string())?;
        let line = match &mut self.raw {
            Some(raw) => read_raw_line(
                &mut self.queued,
                &mut self.skip_lf,
                |buffer| raw.read(buffer, None),
                &mut io::sink(),
            ),
            None if io::stdin().is_terminal() => read_hidden_terminal(),
            None => {
                let mut line = String::new();
                match io::stdin().read_line(&mut line) {
                    Ok(0) => Ok(None),
                    Ok(_) => Ok(Some(line.trim_end_matches(['\r', '\n']).to_string())),
                    Err(error) => Err(error.to_string()),
                }
            }
        };
        println!();
        line
    }

    fn read_line(&mut self, prompt: &str) -> Result<Option<String>, String> {
        print!("{prompt}");
        io::stdout().flush().map_err(|error| error.to_string())?;
        match &mut self.raw {
            None => {
                let mut line = String::new();
                match io::stdin().read_line(&mut line) {
                    Ok(0) => Ok(None),
                    Ok(_) => Ok(Some(line.trim_end_matches(['\r', '\n']).to_string())),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(None),
                    Err(error) => Err(error.to_string()),
                }
            }
            Some(raw) => read_raw_line(
                &mut self.queued,
                &mut self.skip_lf,
                |buffer| raw.read(buffer, None),
                &mut io::stdout().lock(),
            ),
        }
    }

    fn poll_interrupt(&mut self, timeout: Duration) -> Result<bool, String> {
        let Some(raw) = &mut self.raw else {
            std::thread::sleep(timeout);
            return Ok(crate::platform::interrupt_pending());
        };
        let mut buffer = [0_u8; 256];
        match raw.read(&mut buffer, Some(timeout)) {
            Ok(Some(count)) => {
                let mut interrupted = false;
                for byte in &buffer[..count] {
                    if *byte == 3 {
                        crate::platform::note_interrupt();
                        interrupted = true;
                    } else {
                        self.queued.push_back(*byte);
                    }
                }
                Ok(interrupted || crate::platform::interrupt_pending())
            }
            Ok(None) => Ok(crate::platform::interrupt_pending()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(true),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Setup questions as numbered prompts.
struct InputAsk<'a>(&'a mut Input);

impl crate::setup::Ask for InputAsk<'_> {
    fn choose(&mut self, title: &str, items: &[String]) -> Result<Option<usize>, String> {
        eprintln!("{title}");
        for (index, item) in items.iter().enumerate() {
            eprintln!("{:>3}. {item}", index + 1);
        }
        loop {
            let Some(answer) = self.0.read_line("number> ")? else {
                return Ok(None);
            };
            match answer.trim().parse::<usize>() {
                _ if answer.trim().is_empty() => return Ok(None),
                Ok(number @ 1..) if number <= items.len() => return Ok(Some(number - 1)),
                _ => eprintln!("choose 1 to {}, or press Enter to cancel", items.len()),
            }
        }
    }

    fn text(&mut self, title: &str, hidden: bool) -> Result<Option<String>, String> {
        let prompt = format!("{title}> ");
        if hidden {
            self.0.read_hidden(&prompt)
        } else {
            self.0.read_line(&prompt)
        }
    }
}

/// Setup questions asked before the line session starts.
pub struct SetupPrompts(Input);

impl SetupPrompts {
    pub fn new() -> Result<Self, String> {
        Input::new().map(Self)
    }
}

impl crate::setup::Ask for SetupPrompts {
    fn choose(&mut self, title: &str, items: &[String]) -> Result<Option<usize>, String> {
        InputAsk(&mut self.0).choose(title, items)
    }

    fn text(&mut self, title: &str, hidden: bool) -> Result<Option<String>, String> {
        InputAsk(&mut self.0).text(title, hidden)
    }
}

/// A line from a cooked terminal, without echoing it.
fn read_hidden_terminal() -> Result<Option<String>, String> {
    use crossterm::event::{Event as Input, KeyCode, KeyEventKind, KeyModifiers};
    crossterm::terminal::enable_raw_mode().map_err(|error| error.to_string())?;
    let result = (|| {
        let mut text = String::new();
        loop {
            match crossterm::event::read().map_err(|error| error.to_string())? {
                Input::Paste(pasted) => text.push_str(pasted.trim_end_matches(['\r', '\n'])),
                Input::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                    KeyCode::Enter => return Ok(Some(text)),
                    KeyCode::Esc => return Ok(None),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(None);
                    }
                    KeyCode::Backspace => {
                        text.pop();
                    }
                    KeyCode::Char(character) => text.push(character),
                    _ => {}
                },
                _ => {}
            }
        }
    })();
    let _ = crossterm::terminal::disable_raw_mode();
    result
}

fn read_raw_line(
    queued: &mut VecDeque<u8>,
    skip_lf: &mut bool,
    mut read: impl FnMut(&mut [u8]) -> io::Result<Option<usize>>,
    echo: &mut impl Write,
) -> Result<Option<String>, String> {
    let mut bytes = Vec::new();
    loop {
        if queued.is_empty() {
            let mut buffer = [0_u8; 256];
            match read(&mut buffer) {
                Ok(Some(0)) => return Ok(None),
                Ok(Some(count)) => queued.extend(&buffer[..count]),
                Ok(None) => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(None),
                Err(error) => return Err(error.to_string()),
            }
        }
        let byte = queued.pop_front().expect("input byte exists");
        let after_cr = std::mem::take(skip_lf);
        if after_cr && byte == b'\n' {
            continue;
        }
        match byte {
            b'\r' | b'\n' => {
                *skip_lf = byte == b'\r';
                writeln!(echo).map_err(|error| error.to_string())?;
                return Ok(Some(String::from_utf8_lossy(&bytes).into_owned()));
            }
            3 => {
                crate::platform::note_interrupt();
                return Ok(None);
            }
            4 if bytes.is_empty() => return Ok(None),
            8 | 127 if !bytes.is_empty() => {
                let mut byte = bytes.pop().unwrap();
                while byte & 0xc0 == 0x80 {
                    let Some(previous) = bytes.pop() else {
                        break;
                    };
                    byte = previous;
                }
                echo.write_all(b"\x08 \x08")
                    .map_err(|error| error.to_string())?;
                echo.flush().map_err(|error| error.to_string())?;
            }
            byte if !byte.is_ascii_control() => {
                bytes.push(byte);
                echo.write_all(&[byte]).map_err(|error| error.to_string())?;
                echo.flush().map_err(|error| error.to_string())?;
            }
            _ => {}
        }
    }
}

fn fold(text: &str) -> String {
    let text = text.trim();
    if text.len() <= 200 && !text.contains('\n') {
        text.to_string()
    } else {
        format!(
            "{} bytes (use session history for the bounded result)",
            text.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_input_preserves_later_lines_from_the_same_read() {
        let mut queued = VecDeque::new();
        let mut skip_lf = false;
        let mut echo = Vec::new();
        let bytes = b"first\nsecond\n";
        let first = read_raw_line(
            &mut queued,
            &mut skip_lf,
            |buffer| {
                buffer[..bytes.len()].copy_from_slice(bytes);
                Ok(Some(bytes.len()))
            },
            &mut echo,
        )
        .unwrap();
        assert_eq!(first.as_deref(), Some("first"));
        assert_eq!(queued.iter().copied().collect::<Vec<_>>(), b"second\n");
        let second = read_raw_line(
            &mut queued,
            &mut skip_lf,
            |_| panic!("queued line required another read"),
            &mut echo,
        )
        .unwrap();
        assert_eq!(second.as_deref(), Some("second"));
        assert_eq!(echo, b"first\nsecond\n");
    }

    #[test]
    fn raw_input_echoes_utf8_and_backspace_removes_a_complete_character() {
        let mut queued = VecDeque::from("éλ\u{7f}!\n".as_bytes().to_vec());
        let mut echo = Vec::new();
        let text = read_raw_line(
            &mut queued,
            &mut false,
            |_| panic!("unexpected read"),
            &mut echo,
        )
        .unwrap();
        assert_eq!(text.as_deref(), Some("é!"));
        assert_eq!(String::from_utf8(echo).unwrap(), "éλ\u{8} \u{8}!\n");
    }

    #[test]
    fn raw_input_collapses_crlf_even_across_reads() {
        let mut queued = VecDeque::new();
        let mut skip_lf = false;
        let mut echo = Vec::new();
        let mut chunks = VecDeque::from([b"one\r".as_slice(), b"\ntwo\r\n".as_slice()]);
        let mut read = |buffer: &mut [u8]| {
            let bytes = chunks.pop_front().unwrap_or_default();
            buffer[..bytes.len()].copy_from_slice(bytes);
            Ok(Some(bytes.len()))
        };
        assert_eq!(
            read_raw_line(&mut queued, &mut skip_lf, &mut read, &mut echo)
                .unwrap()
                .as_deref(),
            Some("one")
        );
        assert_eq!(
            read_raw_line(&mut queued, &mut skip_lf, &mut read, &mut echo)
                .unwrap()
                .as_deref(),
            Some("two")
        );
        assert!(
            read_raw_line(&mut queued, &mut skip_lf, &mut read, &mut echo)
                .unwrap()
                .is_none()
        );
        assert_eq!(echo, b"one\ntwo\n");
    }

    #[test]
    fn all_six_approval_answers_are_distinct() {
        assert_eq!(parse_approval(Some(" y ")), Approval::Once);
        assert_eq!(parse_approval(Some("s")), Approval::Session);
        assert_eq!(parse_approval(Some("g")), Approval::Global);
        assert_eq!(parse_approval(Some("S")), Approval::DenySession);
        assert_eq!(parse_approval(Some("G")), Approval::DenyGlobal);
        for answer in [None, Some(""), Some("n"), Some("a"), Some("ya")] {
            assert_eq!(parse_approval(answer), Approval::Deny);
        }
    }
}

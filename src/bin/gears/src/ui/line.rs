//! Plain terminal UI for interactive and one-shot runs.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::mpsc;
use std::time::Duration;

use crate::runtime::{Approver, Event, Observer, Permission, Runtime};

const POLL: Duration = Duration::from_millis(25);

pub fn run(
    runtime: &mut Runtime,
    initial: Option<String>,
    interactive: bool,
    models: &[String],
) -> Result<(), String> {
    let mut input = Input::new()?;
    let mut renderer = Renderer::default();
    for notice in runtime.take_startup_notices() {
        renderer.event(Event::Notice(notice))?;
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
        let Some(line) = input.read_line("gears> ")? else {
            renderer.finish_stream();
            return Ok(());
        };
        let line = line.trim_end().to_string();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('/') {
            match command(runtime, &line, models, &mut input, &mut renderer)? {
                Command::Continue => continue,
                Command::Quit => return Ok(()),
                Command::Draft(draft) => {
                    eprintln!("draft> {draft}");
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
    models: &[String],
    input: &mut Input,
    renderer: &mut Renderer,
) -> Result<Command, String> {
    let (name, argument) = line[1..]
        .split_once(char::is_whitespace)
        .map_or((&line[1..], ""), |(name, rest)| (name, rest.trim()));
    match name {
        "quit" | "exit" => Ok(Command::Quit),
        "help" => {
            eprintln!("{}", crate::cli::USAGE);
            Ok(Command::Continue)
        }
        "status" => {
            eprintln!(
                "model: {}\nusage: {}",
                runtime.model(),
                runtime.usage().summary()
            );
            show_session(runtime);
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
            match runtime.select_entry(&id)? {
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
            show_runtime_notices(runtime, renderer)?;
            show_session(runtime);
            Ok(Command::Draft(draft))
        }
        "clone" => {
            eprintln!("note: cloning the conversation does not undo shell side effects");
            runtime.clone_session()?;
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
            let model = if argument.is_empty() {
                choose_model(runtime.model(), models, input)?
            } else {
                argument.to_string()
            };
            runtime.set_model(model, renderer)?;
            Ok(Command::Continue)
        }
        "" => Ok(Command::Continue),
        other => Err(format!("unknown command /{other}; try /help")),
    }
}

fn show_runtime_notices(runtime: &mut Runtime, renderer: &mut Renderer) -> Result<(), String> {
    for notice in runtime.take_startup_notices() {
        renderer.event(Event::Notice(notice))?;
    }
    Ok(())
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
    let mut choices = vec![current.to_string()];
    for model in models {
        if !choices.contains(model) {
            choices.push(model.clone());
        }
    }
    for (index, model) in choices.iter().enumerate() {
        eprintln!("{:>3}. {model}", index + 1);
    }
    let selected = input
        .read_line("model number or id> ")?
        .ok_or("model selection ended")?;
    if let Ok(index) = selected.trim().parse::<usize>()
        && let Some(model) = choices.get(index.saturating_sub(1))
    {
        return Ok(model.clone());
    }
    Ok(selected.trim().to_string())
}

#[derive(Default)]
struct Renderer {
    streaming: bool,
}

impl Renderer {
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
            Event::ToolStart { name, detail } => {
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
            Event::Usage(_) | Event::TurnEnd => {}
            Event::ModelChanged(model) => eprintln!("model: {model}"),
            Event::SessionChanged(_) => {}
        }
        Ok(())
    }
}

enum TurnMessage {
    Event(Event),
    Permission(Permission, mpsc::Sender<bool>),
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
    fn approve(&mut self, request: &Permission) -> bool {
        if !self.interactive {
            eprintln!("gears: denied unattended tool call: {}", request.detail);
            return false;
        }
        let (sender, receiver) = mpsc::channel();
        if self
            .sender
            .send(TurnMessage::Permission(request.clone(), sender))
            .is_err()
        {
            return false;
        }
        receiver.recv().unwrap_or(false)
    }
}

fn run_turn(
    runtime: &mut Runtime,
    prompt: String,
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
            let result = runtime.turn(prompt, &mut approver, &mut observer);
            let _ = sender.send(TurnMessage::Done(result));
        });
        loop {
            loop {
                match receiver.try_recv() {
                    Ok(TurnMessage::Event(event)) => renderer.event(event)?,
                    Ok(TurnMessage::Permission(request, reply)) => {
                        renderer.finish_stream();
                        eprintln!(
                            "Allow {} in {}?\n  {}",
                            request.tool,
                            request.workspace.display(),
                            request.detail
                        );
                        let allowed = input.read_line("[y/N] ")?.is_some_and(|answer| {
                            matches!(answer.trim(), "y" | "Y" | "yes" | "YES")
                        });
                        let _ = reply.send(allowed);
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

struct Input {
    raw: Option<crate::platform::TerminalInput>,
    queued: VecDeque<u8>,
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
        })
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
            Some(raw) => read_raw_line(raw, &mut self.queued),
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

fn read_raw_line(
    input: &mut crate::platform::TerminalInput,
    queued: &mut VecDeque<u8>,
) -> Result<Option<String>, String> {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0_u8; 256];
        let count = if queued.is_empty() {
            match input.read(&mut buffer, None) {
                Ok(Some(0)) => return Ok(None),
                Ok(Some(count)) => count,
                Ok(None) => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(None),
                Err(error) => return Err(error.to_string()),
            }
        } else {
            let count = queued.len().min(buffer.len());
            for destination in &mut buffer[..count] {
                *destination = queued.pop_front().expect("queued byte exists");
            }
            count
        };
        for byte in &buffer[..count] {
            match *byte {
                b'\r' | b'\n' => {
                    println!();
                    return Ok(Some(String::from_utf8_lossy(&bytes).into_owned()));
                }
                3 => {
                    crate::platform::note_interrupt();
                    return Ok(None);
                }
                4 if bytes.is_empty() => return Ok(None),
                8 | 127 if !bytes.is_empty() => {
                    bytes.pop();
                    print!("\x08 \x08");
                    io::stdout().flush().map_err(|error| error.to_string())?;
                }
                byte if !byte.is_ascii_control() => {
                    bytes.push(byte);
                    print!("{}", char::from(byte));
                    io::stdout().flush().map_err(|error| error.to_string())?;
                }
                _ => {}
            }
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

//! The line-mode interface: one thread, one terminal, one event loop.
//!
//! Rendering is deliberately plain — no cursor tricks, no colour, nothing that
//! needs a terminal to be anything more than a stream of lines. The TUI is
//! post-v1 (plan decision 4), and a line mode that works everywhere is what
//! the Motor OS console gets on day one.

use std::io::Write;
use std::sync::mpsc::Receiver;

use crate::agent::bus::{AgentId, Decision, Event, PermissionRequest, ROOT};
use crate::provider::UsageMeter;
use crate::trace::scrub;

/// Everything the event loop needs from an interface: somewhere to put an
/// event, and somebody to answer a permission question — which says which
/// agent is asking, because with several running that is half the question.
pub trait Ui {
    fn render(&mut self, event: &Event) -> std::io::Result<()>;

    fn decide(&mut self, agent: AgentId, request: &PermissionRequest) -> Decision;
}

/// Why the event loop returned.
#[derive(Debug, PartialEq)]
pub enum Pumped {
    /// One prompt has been dealt with; the agent is idle again. `ok` is
    /// whether the model answered rather than failing or being cancelled.
    Turn { usage: UsageMeter, ok: bool },
    /// The agent thread finished.
    Exit,
    /// The agent went away without saying so — it panicked, or was dropped.
    Closed,
    /// The terminal itself failed.
    Broken(String),
}

/// Render events until the agent's turn ends. This is the whole UI thread:
/// it does not compute anything, it only decides how things look and who is
/// asked what.
pub fn pump(events: &Receiver<Event>, ui: &mut dyn Ui) -> Pumped {
    while let Ok(event) = events.recv() {
        if let Some(done) = dispatch(event, ui) {
            return done;
        }
    }
    Pumped::Closed
}

/// Handle one event. Readiness-based interfaces use this between input polls.
pub(crate) fn dispatch(event: Event, ui: &mut dyn Ui) -> Option<Pumped> {
    if let Event::Permission {
        agent,
        request,
        reply,
    } = event
    {
        let decision = ui.decide(agent, &request);
        reply.send(decision);
        return None;
    }
    if let Err(error) = ui.render(&event) {
        return Some(Pumped::Broken(error.to_string()));
    }
    // The user's turn is the root's turn: a sub-agent finishing is not the
    // prompt coming back.
    match event {
        Event::TurnEnd {
            agent: ROOT,
            usage,
            ok,
        } => Some(Pumped::Turn { usage, ok }),
        Event::Exit { agent: ROOT } => Some(Pumped::Exit),
        _ => None,
    }
}

/// Events, as lines.
pub struct Renderer<W> {
    out: W,
    /// Whether the next write starts a line. Streamed tokens arrive in
    /// arbitrary pieces, so this is tracked rather than assumed.
    at_line_start: bool,
    /// Reasoning is announced once, not once per delta.
    in_reasoning: bool,
    /// Whether a `[+]` marker means anything. It points at `/+`, which needs
    /// a prompt to be typed at: under `gears -p` there is none, and a marker
    /// there would be an offer nothing can take up.
    expandable: bool,
    /// Whose line is open. Sub-agents stream at the same time as each other
    /// and as the agent the user is talking to, so whoever writes next gets a
    /// line of their own rather than the tail of somebody else's — and every
    /// line but the root's says whose it is.
    speaking: AgentId,
}

impl<W: Write> Renderer<W> {
    pub fn new(out: W, expandable: bool) -> Renderer<W> {
        Renderer {
            out,
            at_line_start: true,
            in_reasoning: false,
            expandable,
            speaking: ROOT,
        }
    }

    pub fn event(&mut self, event: &Event) -> std::io::Result<()> {
        let agent = event.agent();
        match event {
            // Model output goes through verbatim: it is the answer, and it is
            // also the one text a registered secret cannot have got into.
            Event::Token { text, .. } => {
                self.leave_reasoning()?;
                self.speak(agent)?;
                self.write(text)
            }
            Event::Reasoning { text, .. } => {
                self.enter_reasoning(agent)?;
                self.write(text)
            }
            Event::ToolStart { detail, .. } => self.line_from(agent, &format!("* {detail}")),
            Event::ToolOutput { text, .. } => {
                self.leave_reasoning()?;
                self.speak(agent)?;
                self.write(&scrub(text))
            }
            Event::ToolProgress { elapsed, .. } => {
                self.line_from(agent, &format!("  {:.1}s elapsed", elapsed.as_secs_f64()))
            }
            Event::ToolEnd {
                ok, detail, full, ..
            } => {
                let mark = match full.is_some() && self.expandable {
                    true => "[+] ",
                    false => "",
                };
                let what = match ok {
                    true => "",
                    false => "error: ",
                };
                self.line_from(agent, &format!("  {mark}{what}{detail}"))
            }
            Event::Notice { text, .. } => self.line_from(agent, &format!("- {text}")),
            Event::Failed { text, .. } => self.line_from(agent, &format!("! {text}")),
            Event::TurnEnd { .. } | Event::Exit { .. } => self.break_line(),
            // Answered by the event loop, which has the user; see `pump`.
            Event::Permission { .. } => Ok(()),
        }
    }

    /// One line in the interface's own voice — a slash command's answer, a
    /// complaint about the terminal — which is nobody's agent.
    pub fn line(&mut self, text: &str) -> std::io::Result<()> {
        self.line_from(ROOT, text)
    }

    /// One line from `agent`, starting one if a streamed token left the
    /// cursor mid-line — whoever's it was.
    pub fn line_from(&mut self, agent: AgentId, text: &str) -> std::io::Result<()> {
        self.leave_reasoning()?;
        self.speak(agent)?;
        self.break_line()?;
        self.write(&format!("{}\n", scrub(text)))
    }

    /// A question, with the cursor left after it for the answer.
    pub fn prompt(&mut self, text: &str) -> std::io::Result<()> {
        self.prompt_from(ROOT, text)
    }

    pub fn prompt_from(&mut self, agent: AgentId, text: &str) -> std::io::Result<()> {
        self.leave_reasoning()?;
        self.speak(agent)?;
        self.break_line()?;
        self.write(&scrub(text))
    }

    /// Hand the line to `agent`, closing whatever somebody else left open.
    fn speak(&mut self, agent: AgentId) -> std::io::Result<()> {
        if agent != self.speaking {
            self.break_line()?;
            self.speaking = agent;
        }
        Ok(())
    }

    pub fn break_line(&mut self) -> std::io::Result<()> {
        match self.at_line_start {
            true => Ok(()),
            false => self.write("\n"),
        }
    }

    fn enter_reasoning(&mut self, agent: AgentId) -> std::io::Result<()> {
        self.speak(agent)?;
        if !self.in_reasoning {
            self.break_line()?;
            self.write("(thinking)\n")?;
            self.in_reasoning = true;
        }
        Ok(())
    }

    fn leave_reasoning(&mut self) -> std::io::Result<()> {
        if self.in_reasoning {
            self.in_reasoning = false;
            self.break_line()?;
        }
        Ok(())
    }

    fn write(&mut self, text: &str) -> std::io::Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        // Whose line this is, said once at the start of it. The root goes
        // unmarked: with one agent — the usual case — nothing is in the way.
        if self.at_line_start && self.speaking != ROOT {
            self.out
                .write_all(format!("[{}] ", self.speaking).as_bytes())?;
        }
        self.out.write_all(text.as_bytes())?;
        self.at_line_start = text.ends_with('\n');
        // Flushed per piece: streaming that arrives in one burst at the end is
        // not streaming.
        self.out.flush()
    }

    /// Bytes from the raw line editor: keystrokes echoed back, erasures.
    /// Verbatim and flushed — no scrubbing, no line accounting; the editor
    /// owns the line the cursor is on until Enter hands it back
    /// ([`Renderer::user_typed`]).
    pub fn echo(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.out.write_all(bytes)?;
        self.out.flush()
    }

    /// The user pressed Enter. The terminal is back at a line start, though
    /// nothing gears wrote put it there.
    pub fn user_typed(&mut self) {
        self.at_line_start = true;
    }

    pub fn get_ref(&self) -> &W {
        &self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::bus::{Bus, ROOT, event_channel};
    use crate::provider::{EventSink, Usage};

    /// A UI with a string for a terminal and a list for a user.
    struct Scripted {
        renderer: Renderer<Vec<u8>>,
        answers: Vec<Decision>,
        asked: Vec<String>,
    }

    impl Scripted {
        fn new(answers: &[Decision]) -> Scripted {
            Scripted {
                renderer: Renderer::new(Vec::new(), true),
                answers: answers.iter().rev().copied().collect(),
                asked: Vec::new(),
            }
        }

        fn text(&self) -> String {
            String::from_utf8(self.renderer.get_ref().clone()).unwrap()
        }
    }

    impl Ui for Scripted {
        fn render(&mut self, event: &Event) -> std::io::Result<()> {
            self.renderer.event(event)
        }

        fn decide(&mut self, agent: AgentId, request: &PermissionRequest) -> Decision {
            self.asked.push(match agent {
                ROOT => request.detail.clone(),
                id => format!("[{id}] {}", request.detail),
            });
            self.answers.pop().unwrap_or(Decision::Deny)
        }
    }

    fn render(events: &[Event]) -> String {
        let mut ui = Scripted::new(&[]);
        for event in events {
            ui.render(event).unwrap();
        }
        ui.text()
    }

    fn token(text: &str) -> Event {
        Event::Token {
            agent: ROOT,
            text: text.to_string(),
        }
    }

    #[test]
    fn tokens_stream_out_verbatim() {
        assert_eq!(
            render(&[token("Hel"), token("lo, "), token("world")]),
            "Hello, world"
        );
    }

    #[test]
    fn a_tool_call_reads_as_two_lines() {
        let text = render(&[
            token("Let me look."),
            Event::ToolStart {
                agent: ROOT,
                detail: "read_file src/main.rs".to_string(),
            },
            Event::ToolEnd {
                agent: ROOT,
                ok: true,
                detail: "312 bytes".to_string(),
                full: Some("fn main() {}".to_string()),
            },
            Event::ToolEnd {
                agent: ROOT,
                ok: false,
                detail: "'/etc/passwd' is outside the workspace".to_string(),
                full: None,
            },
        ]);
        // The line the token left open is closed before the tool line starts,
        // and the summary that left something out says so.
        assert_eq!(
            text,
            "Let me look.\n* read_file src/main.rs\n  [+] 312 bytes\n  \
             error: '/etc/passwd' is outside the workspace\n"
        );
    }

    #[test]
    fn live_tool_output_and_elapsed_time_are_rendered_in_event_order() {
        let text = render(&[
            Event::ToolStart {
                agent: ROOT,
                detail: "run compiler".to_string(),
            },
            Event::ToolOutput {
                agent: ROOT,
                stream: crate::agent::ToolStream::Stdout,
                text: "checking\n".to_string(),
            },
            Event::ToolOutput {
                agent: ROOT,
                stream: crate::agent::ToolStream::Stderr,
                text: "warning\n".to_string(),
            },
            Event::ToolProgress {
                agent: ROOT,
                elapsed: std::time::Duration::from_millis(2500),
            },
        ]);
        assert_eq!(text, "* run compiler\nchecking\nwarning\n  2.5s elapsed\n");
    }

    /// Two agents writing at once, which is what the prefixes are for: a
    /// sub-agent never continues somebody else's line, and every line it does
    /// write says whose it is.
    #[test]
    fn agents_do_not_write_over_each_other() {
        let from = |agent: AgentId, text: &str| Event::Token {
            agent,
            text: text.to_string(),
        };
        let text = render(&[
            from(ROOT, "Sending two."),
            Event::ToolStart {
                agent: 2,
                detail: "grep TODO".to_string(),
            },
            from(2, "Looking"),
            from(3, "Also"),
            from(2, " here"),
            Event::Notice {
                agent: 3,
                text: "done".to_string(),
            },
            from(ROOT, "Both are back."),
        ]);
        assert_eq!(
            text,
            "Sending two.\n\
             [2] * grep TODO\n\
             [2] Looking\n\
             [3] Also\n\
             [2]  here\n\
             [3] - done\n\
             Both are back."
        );
    }

    /// The marker is an offer to type `/+`, so it is only made where there is
    /// a prompt to type it at.
    #[test]
    fn nothing_is_marked_expandable_where_nothing_can_expand_it() {
        let mut renderer = Renderer::new(Vec::new(), false);
        renderer
            .event(&Event::ToolEnd {
                agent: ROOT,
                ok: true,
                detail: "312 bytes".to_string(),
                full: Some("fn main() {}".to_string()),
            })
            .unwrap();
        assert_eq!(
            String::from_utf8(renderer.get_ref().clone()).unwrap(),
            "  312 bytes\n"
        );
    }

    #[test]
    fn reasoning_is_announced_once_and_closed_when_content_starts() {
        let reasoning = |text: &str| Event::Reasoning {
            agent: ROOT,
            text: text.to_string(),
        };
        assert_eq!(
            render(&[reasoning("first "), reasoning("second"), token("Answer.")]),
            "(thinking)\nfirst second\nAnswer."
        );
    }

    #[test]
    fn notices_and_failures_are_marked_and_scrubbed() {
        crate::trace::redact("sk-repl-secret");
        assert_eq!(
            render(&[
                Event::Notice {
                    agent: ROOT,
                    text: "cancelled".to_string(),
                },
                Event::Failed {
                    agent: ROOT,
                    text: "authentication failed: bad key sk-repl-secret".to_string(),
                },
            ]),
            "- cancelled\n! authentication failed: bad key [redacted]\n"
        );
    }

    #[test]
    fn the_loop_runs_until_the_turn_ends() {
        let (tx, rx) = event_channel();
        let bus = Bus::new(ROOT, tx);
        bus.tool_start("write_file notes.txt").unwrap();
        bus.tool_end(true, "wrote 6 bytes", None).unwrap();
        let mut usage = UsageMeter::new();
        usage.add(&Usage {
            prompt_tokens: 7,
            completion_tokens: 2,
            ..Usage::default()
        });
        bus.turn_end(usage, true).unwrap();
        // Sent after the end of the turn: the loop must not have consumed it.
        bus.notice("the next turn").unwrap();

        let mut ui = Scripted::new(&[]);
        assert_eq!(pump(&rx, &mut ui), Pumped::Turn { usage, ok: true });
        assert_eq!(ui.text(), "* write_file notes.txt\n  wrote 6 bytes\n");
        assert!(matches!(rx.recv().unwrap(), Event::Notice { .. }));
    }

    #[test]
    fn a_permission_question_is_answered_by_the_ui_side() {
        let (tx, rx) = event_channel();
        let bus = Bus::new(ROOT, tx);
        let asked = std::thread::spawn(move || {
            let decision = bus.ask(PermissionRequest {
                key: "write_file".to_string(),
                detail: "write_file notes.txt".to_string(),
            });
            bus.turn_end(UsageMeter::new(), true).unwrap();
            decision
        });

        let mut ui = Scripted::new(&[Decision::Always]);
        assert!(matches!(pump(&rx, &mut ui), Pumped::Turn { ok: true, .. }));
        assert_eq!(asked.join().unwrap(), Decision::Always);
        assert_eq!(ui.asked, ["write_file notes.txt"]);
    }

    #[test]
    fn an_agent_that_vanishes_ends_the_loop() {
        let (tx, rx) = event_channel();
        let mut bus = Bus::new(ROOT, tx);
        bus.on_content("half a sen").unwrap();
        drop(bus);

        let mut ui = Scripted::new(&[]);
        assert_eq!(pump(&rx, &mut ui), Pumped::Closed);
        assert_eq!(ui.text(), "half a sen");
    }
}

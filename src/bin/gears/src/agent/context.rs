//! Context management: keeping a long conversation inside the model's window.
//!
//! The numbers here are the endpoint's own. Every completion reports what the
//! request it answered came to in tokens, so gears always knows the size of
//! the last thing it sent — never a guess from a tokenizer it does not have.
//! That measurement is a high-water mark: when it passes the threshold the
//! conversation is cut back *before* the next request, and the endpoint's next
//! count says whether it was cut back enough.
//!
//! What goes first is the proposal's policy: the **oldest tool results**,
//! replaced by a stub saying one was dropped, with the call that asked for it
//! left alone — a transcript whose calls are all still answered is one that
//! can still be sent. Only when there is nothing left to stub does the
//! summarization checkpoint follow.
//!
//! None of this touches the session file. What is on disk is the record of
//! what really happened; this is only about what is sent next.

use std::ops::Range;

use crate::provider::{ChatMessage, ChatRequest, Role};

/// What the model's context window will take. There is no way to ask an
/// OpenAI-compatible endpoint how big its window is and no model registry to
/// look it up in, so the budget is the user's to declare; zero turns context
/// management off altogether.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub budget: u64,
    /// Whether a completion may be spent on replacing the oldest part of a
    /// conversation with the model's own summary of it, once there is nothing
    /// left to stub.
    pub summarize: bool,
}

/// What gears assumes until told otherwise: the window most current models
/// have at least. It is a cap on gears' own behaviour rather than a claim
/// about the user's model — too low costs a little detail, too high leaves the
/// endpoint to refuse the request, and either way `context.budget_tokens` is
/// one line of config.
pub const DEFAULT_BUDGET: u64 = 128_000;

/// Act above this share of the budget; cut back to that one. The gap between
/// them is what stops a session from trimming itself every second turn.
const HIGH: u64 = 75;
const TARGET: u64 = 55;

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            budget: DEFAULT_BUDGET,
            summarize: true,
        }
    }
}

/// What to do before the next request. Both parts can be set at once:
/// stubbing is free and always worth doing first, and the range to summarize
/// is chosen knowing what stubbing will already have saved.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Tool results to replace with stubs, oldest first.
    pub evict: Vec<usize>,
    /// The messages a summary would stand in for.
    pub compact: Option<Range<usize>>,
}

fn mark(budget: u64, percent: u64) -> u64 {
    budget / 100 * percent
}

/// One conversation's measured size.
pub struct Context {
    policy: Policy,
    /// The last request's token count as the endpoint reported it, and what
    /// was sent to earn it. The pair is an exchange rate — gears has no
    /// tokenizer, and a rate measured on this very conversation is the next
    /// best thing.
    measured: u64,
    bytes: usize,
}

impl Context {
    pub fn new(policy: Policy) -> Context {
        Context {
            policy,
            measured: 0,
            bytes: 0,
        }
    }

    /// Take one measurement: what the endpoint counted, and what it counted.
    /// Zero is not a measurement — an endpoint that reports no usage leaves
    /// the last rate standing rather than replacing it with nothing.
    pub fn observed(&mut self, prompt_tokens: u64, sent: &[ChatMessage]) {
        let bytes = bytes(sent);
        if prompt_tokens > 0 && bytes > 0 {
            self.measured = prompt_tokens;
            self.bytes = bytes;
        }
    }

    /// What the next request would come to, at the last measured rate. Zero
    /// until something has been measured: the first request of a session goes
    /// out unmanaged, because guessing at its size is the thing this avoids.
    ///
    /// It is an underestimate by design. The rate carries a share of what does
    /// not shrink with the conversation — the tool schemas, the framing — so a
    /// smaller transcript is reckoned smaller than it really is, and the next
    /// measurement is what corrects it.
    pub fn estimate(&self, messages: &[ChatMessage]) -> u64 {
        self.estimate_with_extra(messages, &[])
    }

    fn estimate_with_extra(&self, messages: &[ChatMessage], extra: &[ChatMessage]) -> u64 {
        match self.bytes {
            0 => 0,
            was => {
                let now = bytes(messages).saturating_add(bytes(extra));
                (self.measured as u128 * now as u128 / was as u128) as u64
            }
        }
    }

    /// What has to happen before the next request. Stubbing comes first
    /// because it is free; a summary is asked for only where stubbing
    /// everything there is still leaves the conversation too big.
    pub fn plan(&self, messages: &[ChatMessage]) -> Plan {
        self.plan_with_extra(messages, &[])
    }

    /// Plan for durable conversation messages while accounting for ephemeral
    /// messages that are sent too but must never be evicted or summarized.
    pub fn plan_with_extra(&self, messages: &[ChatMessage], extra: &[ChatMessage]) -> Plan {
        let estimate = self.estimate_with_extra(messages, extra);
        if self.policy.budget == 0 || estimate <= mark(self.policy.budget, HIGH) {
            return Plan::default();
        }
        // The choosing is done in bytes; the estimate is proportional to them,
        // so the target converts without a second rate to get wrong.
        let now = bytes(messages) as u64;
        let fixed = bytes(extra) as u64;
        let total = now.saturating_add(fixed);
        let want = total * mark(self.policy.budget, TARGET) / estimate.max(1);
        let want = want.saturating_sub(fixed);

        let mut evict = Vec::new();
        let mut left = now;
        for index in evictable(messages) {
            if left <= want {
                break;
            }
            left = left.saturating_sub(saving(&messages[index]) as u64);
            evict.push(index);
        }
        let compact = match self.policy.summarize && left > want {
            true => range(messages, left, want),
            false => None,
        };
        Plan { evict, compact }
    }
}

/// The range a summary would stand in for: as much of the front of the
/// conversation as it takes to get under the target, keeping the system
/// prompt — which is the agent's identity, not its history — and never
/// reaching into the round the model is working on now.
fn range(messages: &[ChatMessage], left: u64, want: u64) -> Option<Range<usize>> {
    let head = usize::from(messages.first().is_some_and(|m| m.role == Role::System));
    let ceiling = ceiling(messages);
    let mut upto = head;
    let mut freed = 0;
    while upto < ceiling && left.saturating_sub(freed) > want {
        freed += size(&messages[upto]) as u64;
        upto += 1;
    }
    // A result never outlives the call it answers: a boundary that falls
    // between them moves past the whole round rather than leaving an answer
    // to a question that is no longer there.
    while upto < ceiling && messages[upto].role == Role::Tool {
        upto += 1;
    }
    let cuts_a_round = messages.get(upto).is_some_and(|m| m.role == Role::Tool);
    match upto.saturating_sub(head) >= MIN_COMPACTION && !cuts_a_round {
        true => Some(head..upto),
        false => None,
    }
}

/// How far a summary may reach: no further than the last round of calls,
/// which is the work in hand, and never as far as the last message, which is
/// what the model is answering.
fn ceiling(messages: &[ChatMessage]) -> usize {
    match current_round(messages) {
        round if round < messages.len() => round,
        _ => messages.len().saturating_sub(1),
    }
}

/// Fewer messages than this is not worth a completion — and a summary of a
/// summary of a summary is worth less still.
const MIN_COMPACTION: usize = 4;

/// The one message a checkpoint leaves behind. In the model's own voice,
/// because the model wrote it: what it says is all that is left of the
/// conversation it replaces.
pub fn checkpoint(summary: &str) -> ChatMessage {
    ChatMessage::assistant(format!("{CHECKPOINT}\n\n{summary}"))
}

/// What replaces summarized history. Durable artifact results bring their
/// complete call round with them, so the provider still sees every retained
/// result as the answer to the call that produced it.
pub fn replacement(summary: &str, messages: &[ChatMessage]) -> Vec<ChatMessage> {
    let mut replacement = vec![checkpoint(summary)];
    let mut index = 0;
    while index < messages.len() {
        if messages[index].role != Role::Assistant || messages[index].tool_calls.is_empty() {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < messages.len() && messages[index].role == Role::Tool {
            index += 1;
        }
        if messages[start + 1..index]
            .iter()
            .any(ChatMessage::retains_artifact)
        {
            replacement.extend_from_slice(&messages[start..index]);
        }
    }
    replacement
}

const CHECKPOINT: &str = "[The conversation up to this point was summarized to \
     make room in the context window. What follows is that summary; its other \
     details are gone except for durable artifact call/result pairs retained \
     immediately below.]";

const SUMMARIZE: &str = "\
The conversation above is about to be dropped to make room in your context
window. Write down what your later self will need: what was asked, what you
found out, what you have changed already and what is still to do. Name files,
paths, commands, decisions and open questions exactly — nothing else survives.
Do not address the user and do not summarize this instruction; this is a note
to yourself, and it is all you will have.";

/// The one-off completion that writes a checkpoint. Everything up to the
/// boundary goes in, the system prompt included so that the model knows whose
/// note this is, and no tools, because there is nothing here to do.
pub fn summary_request(model: &str, messages: &[ChatMessage]) -> ChatRequest {
    let mut messages = messages.to_vec();
    messages.push(ChatMessage::user(SUMMARIZE));
    ChatRequest::new(model, messages)
}

/// What is left where a result was. It says what was dropped and how much of
/// it there was, so that a model missing something knows to ask again rather
/// than wondering what it once knew.
const DROPPED: &str = "[gears dropped this result to save context";

fn stub_text(size: usize) -> String {
    format!("{DROPPED}: {size} bytes. Run the call again if you still need it.]")
}

fn is_stub(message: &ChatMessage) -> bool {
    message
        .content
        .as_deref()
        .is_some_and(|text| text.starts_with(DROPPED))
}

/// Replace one result with its stub, and say what that saved.
pub fn stub(message: &mut ChatMessage) -> usize {
    let size = message.content.as_deref().map_or(0, str::len);
    let text = stub_text(size);
    let saved = size.saturating_sub(text.len());
    message.content = Some(text);
    saved
}

fn saving(message: &ChatMessage) -> usize {
    let size = message.content.as_deref().map_or(0, str::len);
    size.saturating_sub(stub_text(size).len())
}

/// The tool results that may be stubbed, oldest first: every one before the
/// round the model is working on now. The current round's results are what it
/// asked for and has not yet said a word about — dropping those would buy the
/// same calls all over again.
fn evictable(messages: &[ChatMessage]) -> Vec<usize> {
    let current = current_round(messages);
    (0..current)
        .filter(|&index| {
            messages[index].role == Role::Tool
                && !messages[index].retains_artifact()
                && !is_stub(&messages[index])
        })
        .collect()
}

/// Where the round in flight starts: the last assistant message that asked
/// for tools, or the end of the conversation when none did.
fn current_round(messages: &[ChatMessage]) -> usize {
    messages
        .iter()
        .rposition(|m| m.role == Role::Assistant && !m.tool_calls.is_empty())
        .unwrap_or(messages.len())
}

/// Per-message framing: the role, the keys, the JSON around it. Small, and
/// not nothing across a few hundred messages.
const FRAMING: usize = 16;

fn size(message: &ChatMessage) -> usize {
    FRAMING
        + message.content.as_deref().map_or(0, str::len)
        + message
            .tool_calls
            .iter()
            .map(|call| call.id.len() + call.name().len() + call.arguments().len())
            .sum::<usize>()
}

/// What a conversation comes to on the wire.
fn bytes(messages: &[ChatMessage]) -> usize {
    messages.iter().map(size).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ToolCall;

    fn asks(id: &str) -> ChatMessage {
        ChatMessage {
            role: Role::Assistant,
            content: None,
            tool_calls: vec![ToolCall::new(id, "read_file", r#"{"path":"a.rs"}"#)],
            tool_call_id: None,
            artifact_reference: false,
        }
    }

    /// A conversation of `rounds` calls, each answered with `size` bytes.
    fn transcript(rounds: usize, size: usize) -> Vec<ChatMessage> {
        let mut messages = vec![ChatMessage::system("you are gears")];
        for round in 0..rounds {
            let id = format!("call_{round}");
            messages.push(asks(&id));
            messages.push(ChatMessage::tool_result(id, "x".repeat(size)));
        }
        messages
    }

    /// A conversation with nothing in it to stub: only what was said.
    fn chat(turns: usize, size: usize) -> Vec<ChatMessage> {
        let mut messages = vec![ChatMessage::system("you are gears")];
        for turn in 0..turns {
            messages.push(ChatMessage::user(format!(
                "{turn}: {}",
                "ask ".repeat(size)
            )));
            messages.push(ChatMessage::assistant("right".repeat(size)));
        }
        messages.push(ChatMessage::user("and now this"));
        messages
    }

    /// Stubbing only, which is the half of the policy that costs nothing.
    fn stubbing(budget: u64) -> Policy {
        Policy {
            budget,
            summarize: false,
        }
    }

    /// A context that has seen `messages` measured at four bytes to the token,
    /// which is what a real endpoint reports within a few per cent.
    fn measured(policy: Policy, messages: &[ChatMessage]) -> Context {
        let mut context = Context::new(policy);
        context.observed((bytes(messages) / 4) as u64, messages);
        context
    }

    fn evict(context: &Context, messages: &mut [ChatMessage]) -> usize {
        let chosen = context.plan(messages).evict;
        for index in &chosen {
            stub(&mut messages[*index]);
        }
        chosen.len()
    }

    #[test]
    fn nothing_is_dropped_until_the_endpoint_has_counted_something() {
        let messages = transcript(20, 4096);
        // Far over any budget by weight, and gears does not know it: no
        // completion has come back yet, and it will not guess.
        let cold = Context::new(stubbing(1_000));
        assert_eq!(cold.estimate(&messages), 0);
        assert_eq!(cold.plan(&messages), Plan::default());

        let warm = measured(stubbing(1_000), &messages);
        assert!(!warm.plan(&messages).evict.is_empty());
    }

    #[test]
    fn ephemeral_state_counts_toward_the_window_but_is_never_an_eviction() {
        let messages = transcript(20, 4096);
        let extra = [ChatMessage::system("task ".repeat(20_000))];
        let mut context = Context::new(stubbing(40_000));
        let mut sent = messages.clone();
        sent.extend_from_slice(&extra);
        context.observed((bytes(&sent) / 4) as u64, &sent);

        assert!(context.plan(&messages).evict.is_empty());
        let plan = context.plan_with_extra(&messages, &extra);
        assert!(!plan.evict.is_empty());
        assert!(plan.evict.iter().all(|index| *index < messages.len()));
    }

    #[test]
    fn the_oldest_results_go_first_and_the_round_in_flight_stays() {
        let messages = transcript(8, 4096);
        let chosen = measured(stubbing(4_000), &messages).plan(&messages).evict;

        // Oldest first, and never the results of the last round of calls.
        assert_eq!(chosen[0], 2);
        assert!(
            chosen.windows(2).all(|pair| pair[0] < pair[1]),
            "{chosen:?}"
        );
        let last = messages.len() - 1;
        assert!(!chosen.contains(&last), "{chosen:?}");
        assert!(chosen.iter().all(|i| messages[*i].role == Role::Tool));
    }

    #[test]
    fn only_as_much_is_dropped_as_it_takes() {
        let mut messages = transcript(20, 4096);
        let context = measured(stubbing(20_000), &messages);
        assert!(context.estimate(&messages) > mark(20_000, HIGH));

        let dropped = evict(&context, &mut messages);
        assert!(context.estimate(&messages) <= mark(20_000, TARGET));
        // Some of it, not all of it: what a smaller window needs is not what
        // this one does, and the rest is still worth having.
        assert!((1..19).contains(&dropped), "{dropped} of 20 dropped");
        assert_eq!(context.plan(&messages), Plan::default());
    }

    #[test]
    fn a_stub_says_what_it_replaced_and_is_not_dropped_twice() {
        let mut messages = transcript(20, 4096);
        let context = measured(stubbing(2_000), &messages);
        evict(&context, &mut messages);

        let stubbed = messages[2].content.clone().unwrap();
        assert!(stubbed.contains("4096 bytes"), "{stubbed}");
        assert!(stubbed.contains("Run the call again"), "{stubbed}");
        // Everything it could take is taken, and a second look finds nothing:
        // a stub is not a result to drop again.
        assert!(context.plan(&messages).evict.is_empty());
        assert_eq!(evictable(&messages), Vec::<usize>::new());
    }

    #[test]
    fn an_artifact_reference_is_not_stubbed() {
        let mut messages = transcript(3, 4096);
        messages[2] = ChatMessage::tool_result("call_0", "complete output is artifact 1")
            .retaining_artifact();
        let original = messages[2].clone();

        let chosen = measured(stubbing(1_000), &messages).plan(&messages).evict;
        assert!(!chosen.contains(&2), "{chosen:?}");
        for index in chosen {
            stub(&mut messages[index]);
        }
        assert_eq!(messages[2], original);
    }

    #[test]
    fn a_budget_of_zero_manages_nothing() {
        let messages = transcript(20, 4096);
        let mut context = Context::new(stubbing(0));
        context.observed(1_000_000, &messages);
        assert_eq!(context.plan(&messages), Plan::default());
    }

    #[test]
    fn an_endpoint_that_counts_nothing_leaves_the_rate_alone() {
        let messages = transcript(4, 1024);
        let mut context = measured(stubbing(10_000), &messages);
        let known = context.estimate(&messages);

        context.observed(0, &messages);
        assert_eq!(context.estimate(&messages), known);
        // And a conversation half the size is reckoned half the tokens.
        let half = &messages[..messages.len() / 2];
        assert!(context.estimate(half) < known);
    }

    /// A summary costs a completion, so it is the second thing tried, never
    /// the first.
    #[test]
    fn a_summary_is_asked_for_only_when_stubbing_was_not_enough() {
        let policy = Policy {
            budget: 4_000,
            summarize: true,
        };
        let results = transcript(20, 4096);
        let plan = measured(policy, &results).plan(&results);
        assert!(!plan.evict.is_empty());
        assert_eq!(plan.compact, None, "summarized with results still to stub");

        // The same conversation with nothing to stub — words, not results —
        // has only the one lever left.
        let talk = chat(20, 200);
        let plan = measured(policy, &talk).plan(&talk);
        assert!(plan.evict.is_empty());
        assert!(
            plan.compact.is_some(),
            "nothing left to try and nothing done"
        );
    }

    #[test]
    fn a_checkpoint_keeps_the_system_prompt_and_what_is_being_answered() {
        let policy = Policy {
            budget: 4_000,
            summarize: true,
        };
        let messages = chat(20, 200);
        let range = measured(policy, &messages).plan(&messages).compact.unwrap();

        // The system prompt is the agent's identity, not its history.
        assert_eq!(range.start, 1);
        // And the last thing said is what the model is answering.
        assert!(range.end < messages.len() - 1, "{range:?}");
        assert!(range.len() >= MIN_COMPACTION, "{range:?}");
    }

    /// A boundary that would fall between a call and its answer moves past
    /// the whole round: a result nothing asked for is a malformed request.
    #[test]
    fn a_checkpoint_never_cuts_a_call_from_its_result() {
        let mut messages = vec![ChatMessage::system("sys"), ChatMessage::user("go")];
        for round in 0..4 {
            let id = format!("call_{round}");
            messages.push(asks(&id));
            messages.push(ChatMessage::tool_result(id, "x".repeat(500)));
        }
        let round_in_flight = messages.len() - 2;

        // Whatever is asked of it, every boundary it offers is a legal one.
        let left = bytes(&messages) as u64;
        for want in (0..left).step_by(37) {
            let Some(range) = range(&messages, left, want) else {
                continue;
            };
            assert_eq!(range.start, 1);
            assert!(range.end <= round_in_flight, "{range:?}");
            assert_ne!(messages[range.end].role, Role::Tool, "{range:?}");
        }
    }

    #[test]
    fn summarizing_can_be_turned_off() {
        let messages = chat(20, 200);
        assert_eq!(
            measured(stubbing(4_000), &messages).plan(&messages),
            Plan::default()
        );
    }

    /// What the summarizing completion is sent: everything it is replacing,
    /// the system prompt for whose note this is, and no tools.
    #[test]
    fn the_summary_request_carries_what_it_is_replacing() {
        let messages = chat(3, 4);
        let request = summary_request("test/model", &messages[..4]);

        assert_eq!(request.model, "test/model");
        assert_eq!(request.messages.len(), 5);
        assert_eq!(request.messages[0].role, Role::System);
        assert!(request.tools.is_empty());
        let last = request.messages.last().unwrap();
        assert_eq!(last.role, Role::User);
        assert!(last.content.as_deref().unwrap().contains("still to do"));

        // And what comes back is marked as what it is, in the model's voice.
        let checkpoint = checkpoint("I read main.rs and changed nothing.");
        assert_eq!(checkpoint.role, Role::Assistant);
        let text = checkpoint.content.unwrap();
        assert!(text.contains("summarized"), "{text}");
        assert!(
            text.ends_with("I read main.rs and changed nothing."),
            "{text}"
        );
    }

    #[test]
    fn a_checkpoint_retains_an_artifact_result_with_its_call() {
        let messages = vec![
            ChatMessage::user("inspect it"),
            asks("ordinary"),
            ChatMessage::tool_result("ordinary", "[gears dropped this result]"),
            asks("artifact"),
            ChatMessage::tool_result("artifact", "complete output is artifact 7")
                .retaining_artifact(),
        ];

        let compacted = replacement("I inspected it.", &messages);
        assert_eq!(compacted.len(), 3, "{compacted:?}");
        assert!(
            compacted[0]
                .content
                .as_deref()
                .unwrap()
                .contains("summarized")
        );
        assert_eq!(compacted[1].tool_calls[0].id, "artifact");
        assert_eq!(compacted[2].tool_call_id.as_deref(), Some("artifact"));
        assert!(compacted[2].retains_artifact());
    }
}

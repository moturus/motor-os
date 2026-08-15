//! Typed task state and the transitions that may change its ordered items.

use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
const MAX_ITEMS: usize = 256;
const MAX_EVIDENCE: usize = 256;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_COMPACT_BYTES: usize = 16 * 1024;
const MAX_COMPACT_TEXT_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Ask,
    Plan,
    Code,
    Review,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    Pending,
    Active,
    Completed,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffReason {
    Paused,
    WaitingForUser,
    StepLimit,
    TokenLimit,
    SpendLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handoff {
    reason: HandoffReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    remaining_items: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    id: u64,
    user_text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model_text: Option<String>,
    state: ItemState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    version: u32,
    generation: u64,
    request: String,
    items: Vec<Item>,
    mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    verification_evidence: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handoff: Option<Handoff>,
}

impl Item {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn user_text(&self) -> &str {
        &self.user_text
    }

    pub fn model_text(&self) -> Option<&str> {
        self.model_text.as_deref()
    }

    pub fn state(&self) -> ItemState {
        self.state
    }
}

impl Handoff {
    pub fn reason(&self) -> HandoffReason {
        self.reason
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    pub fn remaining_items(&self) -> &[u64] {
        &self.remaining_items
    }
}

impl Task {
    pub fn new(request: String, items: Vec<String>, mode: Mode) -> Result<Task, String> {
        valid_text(&request, "task request")?;
        if items.is_empty() || items.len() > MAX_ITEMS {
            return Err(format!("a task must have 1..={MAX_ITEMS} items"));
        }
        let items = items
            .into_iter()
            .enumerate()
            .map(|(index, user_text)| {
                valid_text(&user_text, "task item")?;
                Ok(Item {
                    id: index as u64 + 1,
                    user_text,
                    model_text: None,
                    state: ItemState::Pending,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Task {
            version: VERSION,
            generation: 1,
            request,
            items,
            mode,
            checkpoint: None,
            verification_evidence: Vec::new(),
            handoff: None,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn request(&self) -> &str {
        &self.request
    }

    pub fn items(&self) -> &[Item] {
        &self.items
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn checkpoint(&self) -> Option<u64> {
        self.checkpoint
    }

    pub fn verification_evidence(&self) -> &[u64] {
        &self.verification_evidence
    }

    pub fn handoff(&self) -> Option<&Handoff> {
        self.handoff.as_ref()
    }

    /// Append model-discovered work without changing any existing wording or
    /// identifiers. Later refinements still live in `model_text`.
    pub fn add_item(&mut self, text: String) -> Result<u64, String> {
        self.ensure_running()?;
        if self.items.len() >= MAX_ITEMS {
            return Err(format!("a task may have at most {MAX_ITEMS} items"));
        }
        valid_text(&text, "task item")?;
        let next = self.next_generation()?;
        let id = self.items.len() as u64 + 1;
        self.items.push(Item {
            id,
            user_text: text,
            model_text: None,
            state: ItemState::Pending,
        });
        self.generation = next;
        Ok(id)
    }

    /// Start the next user request after this task has been completed. Earlier
    /// wording remains in the append-only journal snapshots.
    pub fn begin_next(&mut self, request: String, mode: Mode) -> Result<(), String> {
        self.ensure_running()?;
        if !self.complete() {
            return Err("the current task is not complete".to_string());
        }
        valid_text(&request, "task request")?;
        let next = self.next_generation()?;
        self.request = request.clone();
        self.items = vec![Item {
            id: 1,
            user_text: request,
            model_text: None,
            state: ItemState::Pending,
        }];
        self.mode = mode;
        self.checkpoint = None;
        self.verification_evidence.clear();
        self.handoff = None;
        self.generation = next;
        Ok(())
    }

    /// `from` makes stale or duplicate model updates explicit. User-authored
    /// wording has no update path; a model refinement is retained separately.
    pub fn transition(
        &mut self,
        id: u64,
        from: ItemState,
        to: ItemState,
        model_text: Option<String>,
    ) -> Result<(), String> {
        self.ensure_running()?;
        let index = usize::try_from(id.checked_sub(1).ok_or("there is no task item 0")?)
            .map_err(|_| format!("there is no task item {id}"))?;
        let item = self
            .items
            .get(index)
            .ok_or_else(|| format!("there is no task item {id}"))?;
        if item.state != from || from == to || !allowed(from, to) {
            return Err(format!("invalid task item transition {from:?} -> {to:?}"));
        }
        if to == ItemState::Active
            && self
                .items
                .iter()
                .any(|other| other.id != id && other.state == ItemState::Active)
        {
            return Err("another task item is already active".to_string());
        }
        if let Some(text) = &model_text {
            valid_text(text, "model task update")?;
        }
        let next = self
            .generation
            .checked_add(1)
            .ok_or("task generation space is exhausted")?;
        let item = &mut self.items[index];
        item.state = to;
        if model_text.is_some() {
            item.model_text = model_text;
        }
        self.generation = next;
        Ok(())
    }

    pub fn set_mode(&mut self, from: Mode, to: Mode) -> Result<(), String> {
        self.ensure_running()?;
        if self.mode != from || from == to {
            return Err(format!("invalid task mode transition {from:?} -> {to:?}"));
        }
        let next = self.next_generation()?;
        self.mode = to;
        self.generation = next;
        Ok(())
    }

    pub fn set_checkpoint(&mut self, from: Option<u64>, to: Option<u64>) -> Result<(), String> {
        self.ensure_running()?;
        if self.checkpoint != from || from == to || to == Some(0) {
            return Err("invalid task checkpoint transition".to_string());
        }
        let next = self.next_generation()?;
        self.checkpoint = to;
        self.generation = next;
        Ok(())
    }

    pub fn add_verification_evidence(&mut self, id: u64) -> Result<(), String> {
        self.ensure_running()?;
        if id == 0
            || self.verification_evidence.len() >= MAX_EVIDENCE
            || self.verification_evidence.contains(&id)
        {
            return Err("invalid or duplicate verification evidence".to_string());
        }
        let next = self.next_generation()?;
        self.verification_evidence.push(id);
        self.generation = next;
        Ok(())
    }

    pub fn stop(&mut self, reason: HandoffReason, detail: Option<String>) -> Result<(), String> {
        self.ensure_running()?;
        if matches!(reason, HandoffReason::WaitingForUser) != detail.is_some() {
            return Err("only a waiting-for-user handoff carries a question".to_string());
        }
        if let Some(detail) = &detail {
            valid_text(detail, "handoff detail")?;
        }
        let next = self.next_generation()?;
        let remaining_items = self
            .items
            .iter()
            .filter(|item| item.state != ItemState::Completed)
            .map(|item| item.id)
            .collect();
        self.handoff = Some(Handoff {
            reason,
            detail,
            remaining_items,
        });
        self.generation = next;
        Ok(())
    }

    pub fn resume(&mut self, reason: HandoffReason) -> Result<(), String> {
        if self.handoff.as_ref().map(|handoff| handoff.reason) != Some(reason) {
            return Err("task is not stopped for that reason".to_string());
        }
        let next = self.next_generation()?;
        self.handoff = None;
        self.generation = next;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION || self.generation == 0 {
            return Err("unsupported or invalid task version".to_string());
        }
        valid_text(&self.request, "task request")?;
        if self.items.is_empty() || self.items.len() > MAX_ITEMS {
            return Err("invalid task item count".to_string());
        }
        let mut active = 0;
        for (index, item) in self.items.iter().enumerate() {
            if item.id != index as u64 + 1 {
                return Err("task item ids are not ordered".to_string());
            }
            valid_text(&item.user_text, "task item")?;
            if let Some(model_text) = &item.model_text {
                valid_text(model_text, "model task update")?;
            }
            active += usize::from(item.state == ItemState::Active);
        }
        if self.checkpoint == Some(0)
            || self.verification_evidence.len() > MAX_EVIDENCE
            || self.verification_evidence.contains(&0)
            || has_duplicates(&self.verification_evidence)
        {
            return Err("invalid task references".to_string());
        }
        if let Some(handoff) = &self.handoff {
            validate_handoff(handoff, &self.items)?;
        }
        match active <= 1 {
            true => Ok(()),
            false => Err("more than one task item is active".to_string()),
        }
    }

    pub(crate) fn validate_successor(&self, successor: &Task) -> Result<(), String> {
        self.validate()?;
        successor.validate()?;
        if successor.generation != self.next_generation()? || successor.version != self.version {
            return Err("invalid task successor".to_string());
        }
        if self.complete() && self.handoff.is_none() {
            let mut replayed = self.clone();
            replayed.begin_next(successor.request.clone(), successor.mode)?;
            if replayed == *successor {
                return Ok(());
            }
        }
        if successor.request != self.request
            || !(self.items.len()..=self.items.len().saturating_add(1))
                .contains(&successor.items.len())
            || successor
                .items
                .iter()
                .zip(&self.items)
                .any(|(next, current)| next.id != current.id || next.user_text != current.user_text)
        {
            return Err("invalid task successor".to_string());
        }

        if successor.items.len() == self.items.len() + 1 {
            if successor.items[..self.items.len()] != self.items
                || successor.mode != self.mode
                || successor.checkpoint != self.checkpoint
                || successor.verification_evidence != self.verification_evidence
                || successor.handoff != self.handoff
            {
                return Err("a task generation must contain exactly one transition".to_string());
            }
            let mut replayed = self.clone();
            replayed.add_item(successor.items.last().unwrap().user_text.clone())?;
            return match replayed == *successor {
                true => Ok(()),
                false => Err("task successor does not match its transition".to_string()),
            };
        }

        let changed_items = successor
            .items
            .iter()
            .zip(&self.items)
            .filter(|(next, current)| {
                next.state != current.state || next.model_text != current.model_text
            })
            .count();
        let changed_fields = usize::from(changed_items > 0)
            + usize::from(successor.mode != self.mode)
            + usize::from(successor.checkpoint != self.checkpoint)
            + usize::from(successor.verification_evidence != self.verification_evidence)
            + usize::from(successor.handoff != self.handoff);
        if changed_fields != 1 || changed_items > 1 {
            return Err("a task generation must contain exactly one transition".to_string());
        }

        let mut replayed = self.clone();
        if changed_items == 1 {
            let (current, next) = self
                .items
                .iter()
                .zip(&successor.items)
                .find(|(current, next)| {
                    current.state != next.state || current.model_text != next.model_text
                })
                .unwrap();
            let model_text = (current.model_text != next.model_text)
                .then(|| next.model_text.clone())
                .flatten();
            replayed.transition(current.id, current.state, next.state, model_text)?;
        } else if successor.mode != self.mode {
            replayed.set_mode(self.mode, successor.mode)?;
        } else if successor.checkpoint != self.checkpoint {
            replayed.set_checkpoint(self.checkpoint, successor.checkpoint)?;
        } else if successor.verification_evidence != self.verification_evidence {
            let id = successor.verification_evidence.last().copied().unwrap_or(0);
            replayed.add_verification_evidence(id)?;
        } else if let Some(handoff) = &successor.handoff {
            replayed.stop(handoff.reason, handoff.detail.clone())?;
        } else if let Some(handoff) = &self.handoff {
            replayed.resume(handoff.reason)?;
        }

        match replayed == *successor {
            true => Ok(()),
            false => Err("task successor does not match its transition".to_string()),
        }
    }

    pub fn complete(&self) -> bool {
        self.items
            .iter()
            .all(|item| item.state == ItemState::Completed)
    }

    pub fn compact(&self) -> String {
        let mut out = format!(
            "task {} | {:?} | checkpoint {:?} | {} checks",
            self.generation,
            self.mode,
            self.checkpoint,
            self.verification_evidence.len()
        );
        if let Some(handoff) = &self.handoff {
            out.push_str(&format!("\nstopped: {:?}", handoff.reason));
            if let Some(detail) = &handoff.detail {
                out.push_str(&format!(": {}", compact_text(detail)));
            }
        }
        for item in &self.items {
            let wording = item.model_text.as_ref().unwrap_or(&item.user_text);
            let line = format!("\n{}. {:?}: {}", item.id, item.state, compact_text(wording));
            if out.len().saturating_add(line.len()) > MAX_COMPACT_BYTES {
                let omitted = "\n... additional task items omitted";
                if out.len().saturating_add(omitted.len()) <= MAX_COMPACT_BYTES {
                    out.push_str(omitted);
                }
                break;
            }
            out.push_str(&line);
        }
        out
    }

    fn ensure_running(&self) -> Result<(), String> {
        match &self.handoff {
            None => Ok(()),
            Some(_) => Err("the task must be resumed before it can change".to_string()),
        }
    }

    fn next_generation(&self) -> Result<u64, String> {
        self.generation
            .checked_add(1)
            .ok_or_else(|| "task generation space is exhausted".to_string())
    }
}

fn compact_text(value: &str) -> String {
    let mut out = String::new();
    for character in value.chars() {
        let escaped = character.escape_default().to_string();
        if out.len().saturating_add(escaped.len()) > MAX_COMPACT_TEXT_BYTES {
            out.push_str("...");
            break;
        }
        out.push_str(&escaped);
    }
    out
}

fn validate_handoff(handoff: &Handoff, items: &[Item]) -> Result<(), String> {
    if matches!(handoff.reason, HandoffReason::WaitingForUser) != handoff.detail.is_some() {
        return Err("invalid handoff detail".to_string());
    }
    if let Some(detail) = &handoff.detail {
        valid_text(detail, "handoff detail")?;
    }
    let remaining = items
        .iter()
        .filter(|item| item.state != ItemState::Completed)
        .map(|item| item.id)
        .collect::<Vec<_>>();
    match handoff.remaining_items == remaining {
        true => Ok(()),
        false => Err("handoff does not name the remaining task items".to_string()),
    }
}

fn has_duplicates(values: &[u64]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn allowed(from: ItemState, to: ItemState) -> bool {
    matches!(
        (from, to),
        (ItemState::Pending, ItemState::Active | ItemState::Blocked)
            | (ItemState::Active, ItemState::Completed | ItemState::Blocked)
            | (ItemState::Blocked, ItemState::Pending | ItemState::Active)
    )
}

fn valid_text(value: &str, what: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(format!(
            "{what} must contain visible text of at most {MAX_TEXT_BYTES} bytes"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_preserve_user_wording_and_reject_duplicates() {
        let mut task = Task::new(
            "repair it".to_string(),
            vec!["inspect".to_string(), "fix".to_string()],
            Mode::Plan,
        )
        .unwrap();
        task.transition(
            1,
            ItemState::Pending,
            ItemState::Active,
            Some("inspect parser".to_string()),
        )
        .unwrap();
        let before = task.clone();
        assert!(
            task.transition(1, ItemState::Pending, ItemState::Active, None)
                .is_err()
        );
        assert_eq!(task, before);
        assert_eq!(task.items()[0].user_text(), "inspect");
        assert_eq!(task.items()[0].model_text(), Some("inspect parser"));
        assert!(task.compact().contains("Active: inspect parser"));
    }

    #[test]
    fn appended_items_are_ordered_and_successors_cannot_forge_them() {
        let task = Task::new("repair it".into(), vec!["inspect".into()], Mode::Code).unwrap();
        let mut successor = task.clone();
        assert_eq!(successor.add_item("verify".into()).unwrap(), 2);
        assert_eq!(successor.items()[1].state(), ItemState::Pending);
        task.validate_successor(&successor).unwrap();

        let mut forged = successor.clone();
        forged.items[1].model_text = Some("claim success".into());
        assert!(task.validate_successor(&forged).is_err());

        let before = successor.clone();
        assert!(successor.add_item("\0".into()).is_err());
        assert_eq!(successor, before);
    }

    #[test]
    fn multiline_user_wording_is_preserved_but_compact_output_is_single_line_per_item() {
        let task = Task::new(
            "repair\nthe parser".to_string(),
            vec!["inspect\tparser\ncarefully".to_string()],
            Mode::Plan,
        )
        .unwrap();
        assert_eq!(task.request(), "repair\nthe parser");
        assert_eq!(task.items()[0].user_text(), "inspect\tparser\ncarefully");
        assert!(task.compact().contains("inspect\\tparser\\ncarefully"));
    }

    #[test]
    fn compact_state_is_bounded_without_changing_the_task() {
        let wording = "abcdefghij".repeat(1_000);
        let items = (0..40).map(|_| wording.clone()).collect();
        let task = Task::new(wording.clone(), items, Mode::Plan).unwrap();
        let compact = task.compact();
        assert!(compact.len() <= MAX_COMPACT_BYTES);
        assert!(compact.contains("..."));
        assert_eq!(task.request(), wording);
        assert_eq!(task.items()[0].user_text(), wording);
    }

    #[test]
    fn blocked_items_resume_and_only_one_item_is_active() {
        let mut task = Task::new(
            "work".to_string(),
            vec!["one".to_string(), "two".to_string()],
            Mode::Code,
        )
        .unwrap();
        task.transition(1, ItemState::Pending, ItemState::Blocked, None)
            .unwrap();
        task.transition(1, ItemState::Blocked, ItemState::Active, None)
            .unwrap();
        assert!(
            task.transition(2, ItemState::Pending, ItemState::Active, None)
                .is_err()
        );
        task.transition(1, ItemState::Active, ItemState::Completed, None)
            .unwrap();
        task.transition(2, ItemState::Pending, ItemState::Active, None)
            .unwrap();
        task.transition(2, ItemState::Active, ItemState::Completed, None)
            .unwrap();
        assert!(task.complete());
        assert_eq!(task.generation(), 6);
        task.validate().unwrap();
    }

    #[test]
    fn a_completed_task_can_begin_one_new_user_request() {
        let mut task = Task::new("first".into(), vec!["first".into()], Mode::Review).unwrap();
        task.set_checkpoint(None, Some(8)).unwrap();
        task.add_verification_evidence(9).unwrap();
        task.transition(1, ItemState::Pending, ItemState::Active, None)
            .unwrap();
        task.transition(1, ItemState::Active, ItemState::Completed, None)
            .unwrap();
        let completed = task.clone();

        task.begin_next("second".into(), Mode::Code).unwrap();
        assert_eq!(task.request(), "second");
        assert_eq!(task.items().len(), 1);
        assert_eq!(task.items()[0].user_text(), "second");
        assert_eq!(task.items()[0].state(), ItemState::Pending);
        assert_eq!(task.checkpoint(), None);
        assert!(task.verification_evidence().is_empty());
        completed.validate_successor(&task).unwrap();

        let before = task.clone();
        assert!(task.begin_next("third".into(), Mode::Code).is_err());
        assert_eq!(task, before);
    }

    #[test]
    fn task_level_updates_are_ordered_and_stopped_tasks_are_immutable() {
        let mut task = Task::new("work".into(), vec!["one".into()], Mode::Plan).unwrap();
        task.set_checkpoint(None, Some(7)).unwrap();
        task.set_mode(Mode::Plan, Mode::Code).unwrap();
        task.add_verification_evidence(4).unwrap();
        let before_duplicate = task.clone();
        assert!(task.add_verification_evidence(4).is_err());
        assert_eq!(task, before_duplicate);

        task.stop(HandoffReason::WaitingForUser, Some("which parser?".into()))
            .unwrap();
        assert_eq!(task.handoff().unwrap().remaining_items(), &[1]);
        let stopped = task.clone();
        assert!(task.set_checkpoint(Some(7), None).is_err());
        assert_eq!(task, stopped);
        assert!(task.resume(HandoffReason::Paused).is_err());
        task.resume(HandoffReason::WaitingForUser).unwrap();
        assert_eq!(task.generation(), 6);
        assert!(task.handoff().is_none());
    }

    #[test]
    fn every_limit_and_pause_reason_round_trips() {
        for reason in [
            HandoffReason::Paused,
            HandoffReason::StepLimit,
            HandoffReason::TokenLimit,
            HandoffReason::SpendLimit,
        ] {
            let mut task = Task::new("work".into(), vec!["one".into()], Mode::Code).unwrap();
            task.stop(reason, None).unwrap();
            let encoded = serde_json::to_string(&task).unwrap();
            let decoded: Task = serde_json::from_str(&encoded).unwrap();
            decoded.validate().unwrap();
            assert_eq!(decoded.handoff().unwrap().reason(), reason);
            assert!(decoded.compact().contains(&format!("stopped: {reason:?}")));
        }
    }
}

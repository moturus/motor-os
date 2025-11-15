//! Autocompletion logic
//! It gets engaged when you press Tab after entering partial command.
//! Right now it completes the last token using pre-defined prefix tree of known builtin commands.

use std::{
    collections::HashMap,
    iter::{Cycle, Peekable},
    sync::{LazyLock, Mutex},
};

use crate::{exec, line_parser};

static BUILTIN_COMMANDS: LazyLock<Trie> = LazyLock::new(|| {
    let mut t = Trie::new();
    for command in &exec::ALL_BUILTINS {
        t.insert(command.to_string());
    }

    t
});

/// Store last suggestions to propose new options on 2nd tab press
static LAST_SUGGESTION: LazyLock<Mutex<Option<SuggestionState>>> =
    LazyLock::new(|| Mutex::new(None));

struct SuggestionState {
    suggestions: Peekable<Cycle<std::vec::IntoIter<String>>>,
}

impl SuggestionState {
    /// advance the state if the `cmdline` matches the previous suggestion
    fn next_if_mine(&mut self, cmdline: &str) -> Option<String> {
        // use peek() as previous suggestion
        if self.suggestions.peek().unwrap() == cmdline {
            self.next()
        } else {
            None
        }
    }

    /// provide next suggestion
    fn next(&mut self) -> Option<String> {
        self.suggestions.next();
        self.suggestions.peek().map(|s| s.clone())
    }
}

/// tries to complete last token of the command line
/// # Returns
/// None if there're no suggestions
/// Some(next suggestion) if there're options
/// It stores state globally to provide all the options in cycle, see [LAST_SUGGESTION]
pub fn try_complete(partial_cmdline: &str) -> Option<String> {
    if partial_cmdline.is_empty() {
        return None;
    }

    // this code should always reuse common parser,
    // would be good for the parser to just return the last token and its context
    let mut parser = line_parser::LineParser::new();
    let mut commands = parser.parse_line(partial_cmdline)?;
    let last_command_token = commands.pop()?.pop()?;

    let match_tail = BUILTIN_COMMANDS.contains(&last_command_token)?;

    // try to use the current state
    let mut last_suggestion = LAST_SUGGESTION.lock().unwrap();
    if let Some(state) = last_suggestion.as_mut() {
        let maybe_next_suggestion = state.next_if_mine(partial_cmdline);
        if maybe_next_suggestion.is_some() {
            return maybe_next_suggestion;
        }
    }

    // build a new suggestion state
    let suggestions = match_tail
        .all_words()
        .into_iter()
        .map(|mut tail| {
            if !partial_cmdline.ends_with(' ') {
                tail.push(' ');
            }
            tail
        })
        .map(|tail| format!("{partial_cmdline}{tail}"))
        .collect::<Vec<String>>()
        .into_iter()
        .cycle()
        .peekable();

    *last_suggestion = Some(SuggestionState { suggestions });
    last_suggestion.as_mut().and_then(|s| s.next())
}

#[derive(Debug, Default)]
pub struct Trie {
    root: TrieNode,
}

#[derive(Debug, Default)]
struct TrieNode {
    is_end_of_word: bool,
    children: HashMap<char, TrieNode>,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            is_end_of_word: false,
            children: HashMap::new(),
        }
    }

    /// return all words starting from the node
    fn all_words(&self) -> Vec<String> {
        let mut words = vec![];
        let mut trail = vec![];
        trail.push(("".to_string(), self));

        while let Some((head, node)) = trail.pop() {
            for (next_char, next_node) in &node.children {
                trail.push((format!("{head}{next_char}"), next_node));
            }
            if node.is_end_of_word {
                words.push(head);
            }
        }

        words
    }
}

impl Trie {
    fn new() -> Self {
        Trie {
            root: TrieNode::new(),
        }
    }

    fn insert(&mut self, word: String) {
        let mut current_node = &mut self.root;

        for c in word.chars() {
            current_node = current_node.children.entry(c).or_insert(TrieNode::new());
        }
        current_node.is_end_of_word = true;
    }

    /// None - doesn't contain
    /// Some(node) - the very last node
    fn contains(&self, partial_word: &str) -> Option<&TrieNode> {
        let mut current_node = &self.root;

        for c in partial_word.chars() {
            match current_node.children.get(&c) {
                Some(node) => current_node = node,
                None => return None,
            }
        }

        Some(current_node)
    }
}

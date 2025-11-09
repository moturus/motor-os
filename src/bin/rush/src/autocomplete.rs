//! Autocompletion logic
//! TODO: update the desc
//! It gets engaged when you press Tab after entering partial command and does the following:
//! - if there're no spaces in the line - lookup respective binary
//! - if there're spaces - extract first argument as a binary and call a helper for the command
//!

use std::{collections::HashMap, sync::LazyLock};

use crate::line_parser;

static COMMANDS: LazyLock<Trie> = LazyLock::new(|| {
    let mut t = Trie::new();
    // TODO:  fill the list from the OG source
    for command in ["cd", "ps", "pwd", "ls"] {
        t.insert(command);
    }
    t
});

/// tries to complete last token of the command line
/// # Returns
/// None if there's nothing that could be completed
/// Some(all possible lines) if there're options
pub fn try_complete(partial_cmdline: &str) -> Option<Vec<String>> {
    if partial_cmdline.is_empty() {
        return None; // nothing to complete
    }

    // this code should always reuse common parser,
    // would be good for the parser to just return the last token with some context
    let mut parser = line_parser::LineParser::new();
    let mut commands = parser.parse_line(partial_cmdline)?;
    let last_command_token = commands.pop()?.pop()?;

    let match_tail = COMMANDS.contains(&last_command_token)?;

    Some(
        match_tail
            .all_words()
            .into_iter()
            .map(|mut tail| {
                if !partial_cmdline.ends_with(' ') {
                    tail.push(' ');
                }
                tail
            })
            .map(|tail| format!("{partial_cmdline}{tail}"))
            .collect(),
    )
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

    fn insert(&mut self, word: &str) {
        let mut current_node = &mut self.root;

        for c in word.chars() {
            current_node = current_node.children.entry(c).or_insert(TrieNode::new());
        }
        current_node.is_end_of_word = true;
    }

    /// None - doesn't contain
    /// Some(node) - the very last node
    fn contains(&self, word: &str) -> Option<&TrieNode> {
        let mut current_node = &self.root;

        for c in word.chars() {
            match current_node.children.get(&c) {
                Some(node) => current_node = node,
                None => return None,
            }
        }

        Some(current_node)
    }
}

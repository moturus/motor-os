//! # Kibi
//!
//! Kibi is a text editor in ≤1024 lines of code.

pub use crate::{config::Config, editor::Editor, error::Error};

pub mod ansi_escape;
mod config;
mod editor;
mod error;
mod row;
mod syntax;
mod sys;
mod terminal;

#[cfg(not(target_os = "moturus"))]
compile_error!("This crate is designed to be used on Motūrus OS only");

//! The agent layer: what turns a prompt into work.
//!
//! The split that matters is between this module and `ui`. An agent decides
//! *what* to do — call the model, run a tool, ask for permission — and says so
//! on the bus. The UI decides what any of that looks like and who is asked.
//! At N=1 that separation buys little; it is what makes N>1 (plan step 7) a
//! matter of more threads rather than a rewrite.

pub mod artifact;
pub mod bus;
pub mod checkpoint;
pub mod context;
pub mod gate;
pub mod harness;
pub mod prompt;
pub mod registry;
pub mod session;
pub mod task;
pub mod turn;
pub mod undo;

pub use bus::{
    AgentId, Bus, Cancel, Decision, EVENT_QUEUE_CAPACITY, Event, Pause, PermissionRequest, ROOT,
    ToolStream, event_channel,
};
pub use context::{Context, Policy};
pub use gate::Gate;
pub use registry::{Agents, Limits};
pub use session::{Session, Transcript};
pub use turn::{Agent, Budget, Conversation, Journal, Turned};
pub use undo::UndoLog;

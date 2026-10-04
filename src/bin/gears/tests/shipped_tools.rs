// Cargo discovers the executable example automatically; Lorry's native
// package build does not need an explicit, unsupported [[example]] table.
#[path = "../examples/tool-smoke.rs"]
mod shipped_tools;

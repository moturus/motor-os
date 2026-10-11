//! A preview 2 (component) plugin with two globals of its own.

use javy_plugin_api::{
    Config,
    javy::{Runtime, quickjs::prelude::Func},
    javy_plugin,
};

wit_bindgen::generate!({ world: "javy-smoke-plugin", generate_all });

fn config() -> Config {
    let mut config = Config::default();
    config
        .event_loop(true)
        .text_encoding(true)
        .javy_stream_io(true);
    config
}

fn modify_runtime(runtime: Runtime) -> Runtime {
    runtime.context().with(|ctx| {
        let globals = ctx.globals();
        globals.set("motorAnswer", Func::from(|| 42_i32)).unwrap();
        globals
            .set("motorGreeting", "hello from a custom plugin")
            .unwrap();
    });
    runtime
}

struct Component;

javy_plugin!("javy-smoke-plugin-p2", Component, config, modify_runtime);

export!(Component);

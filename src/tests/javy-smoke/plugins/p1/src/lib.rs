//! A preview 1 plugin with Javy's optional APIs, QuickJS's `gc()`,
//! `DOMException` and `atob` intrinsics and its string-kind diagnostic hook,
//! and two globals of its own.

use javy_plugin_api::{
    Config, import_namespace,
    javy::{
        Runtime,
        quickjs::{Ctx, Object, Value, prelude::Func, qjs},
    },
};

import_namespace!("javy-smoke-plugin-p1");

fn config() -> Config {
    let mut config = Config::default();
    config
        .event_loop(true)
        .weak_ref(true)
        .performance(true)
        .text_encoding(true)
        .javy_stream_io(true)
        .memory_limit(256 << 20);
    config
}

fn modify_runtime(runtime: Runtime) -> Runtime {
    runtime.context().with(|ctx| {
        // These intrinsics are optional in QuickJS and absent from Javy's context.
        unsafe {
            assert_eq!(qjs::JS_AddIntrinsicDOMException(ctx.as_raw().as_ptr()), 0);
            assert_eq!(qjs::JS_AddIntrinsicAToB(ctx.as_raw().as_ptr()), 0);
        }
        let hooks = Object::new(ctx.clone()).unwrap();
        // QuickJS's run-test262 harness reads the same diagnostic.
        let string_kind = |ctx: Ctx<'_>, value: Value<'_>| {
            let raw = value.as_raw();
            unsafe { qjs::js_std_cmd(3, ctx.as_raw().as_ptr(), &raw) as i32 }
        };
        hooks.set("getStringKind", Func::from(string_kind)).unwrap();
        let globals = ctx.globals();
        globals.set("qjs", hooks).unwrap();
        globals
            .set("gc", Func::from(|ctx: Ctx<'_>| ctx.run_gc()))
            .unwrap();
        globals.set("motorAnswer", Func::from(|| 42_i32)).unwrap();
        globals
            .set("motorGreeting", "hello from a custom plugin")
            .unwrap();
    });
    runtime
}

#[unsafe(export_name = "initialize-runtime")]
fn initialize_runtime() {
    javy_plugin_api::initialize_runtime(config, modify_runtime).unwrap();
}

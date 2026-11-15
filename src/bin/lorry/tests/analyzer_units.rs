#![allow(dead_code)]

use motor_analyzer_tests::semantic;

mod native_assertions {
    include!("analyzer/native/assertions.rs");
    include!("analyzer/unit/native/assertions.rs");
}
mod native_diagnostics {
    include!("analyzer/native/diagnostics.rs");
    include!("analyzer/unit/native/diagnostics.rs");
}

mod resources {
    include!("analyzer/resources.rs");
    include!("analyzer/unit/resources.rs");
}

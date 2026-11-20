#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Value {
        json!({"interval_ms": 100, "samples": [
            {"elapsed_us": 1000, "physical_used": 10000, "processes": [
                [10, 1, 1, 100, 34, "server"],
                [11, 10, 1, 50, 2, "/user/bin/dev/lorry check…"],
                [99, 1, 1, 999999, 999, "unrelated"]]},
            {"elapsed_us": 101000, "physical_used": 20000, "processes": [
                [10, 1, 1, 200, 3, "server"],
                [11, 10, 0, null, null, "/user/bin/dev/lorry check…"],
                [12, 11, 1, 500, 8, "rustc"]]}
        ]})
    }

    #[test]
    fn missing_server_or_check_and_nonmonotonic_samples_fail() {
        assert!(summarize(&report(), "absent").is_err());
        let mut input = report();
        input["samples"][1]["elapsed_us"] = json!(0);
        assert!(summarize(&input, "server").is_err());
        let mut input = report();
        for sample in input["samples"].as_array_mut().unwrap() {
            sample["processes"]
                .as_array_mut()
                .unwrap()
                .retain(|row| row[0] == 10);
        }
        assert!(summarize(&input, "server").is_err());
    }

    #[test]
    fn approved_limits_accept_boundaries_and_reject_missing_or_excess_measurements() {
        let limits = json!({"server_virtual_bytes_max": 2147483648_u64,
            "lorry_check_virtual_bytes_max": 67108864,
            "lorry_check_threads_max": 16, "whole_vm_physical_bytes_max": 3221225472_u64});
        check_limits(&limits).unwrap();
        check_limits(&summarize(&report(), "server").unwrap()).unwrap();
        for (field, value) in limits.as_object().unwrap() {
            for bad in [Value::Null, json!(value.as_u64().unwrap() + 1)] {
                let mut input = limits.clone();
                input[field] = bad;
                assert!(check_limits(&input).is_err(), "{field}");
            }
        }
    }

    #[test]
    fn descendant_classification_rejects_unexpected_tools() {
        let observed = |name| json!({"observed_processes": [{"debug_name": name}]});
        for name in [
            "server",
            "/user/bin/dev/lorry check…",
            "/user/lib/rust/bin/rustc --cr…",
            "/user/lib/llvm/bin/llvm clang…",
            "/user/bin/rush /user/bin/dev/…",
            "/fixture/target/build-script",
            "/fixture/long-project…",
        ] {
            check_processes(
                &observed(name),
                "server",
                "/user/bin/dev/lorry",
                &["/fixture", "/fixture/long-project-name"],
            )
            .unwrap();
        }
        for name in [
            "/user/bin/dev/cargo check",
            "/user/lib/rust/bin/rust-analyzer-proc-macro-srv",
            "/fixture-unrelated/tool",
            "/user/bin/tool",
        ] {
            assert!(
                check_processes(
                    &observed(name),
                    "server",
                    "/user/bin/dev/lorry",
                    &["/fixture"]
                )
                .is_err()
            );
        }
    }
}

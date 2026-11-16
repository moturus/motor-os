//! Native command tests run serially, including their subprocess helpers.
mod sysbox_caps;
mod sysbox_cat;
mod sysbox_chmod;
mod sysbox_diff;
mod sysbox_find;
mod sysbox_findmnt;
mod sysbox_head;
mod sysbox_less;
mod sysbox_ls;
mod sysbox_mkdir;
mod sysbox_sort;
mod sysbox_tail;
mod sysbox_wc;
mod sysbox_which;

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(name)
}

fn set_directory_access(
    path: &std::path::Path,
    access: moto_sdk::io::fs::AccessPermissions,
) -> moto_rt::Result<()> {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let client = moto_sdk::io::fs::FsClient::connect()?;
        let (id, _) = client.stat(path.to_str().unwrap()).await?;
        client.set_permissions(id, access).await
    })
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    // The cross runner executes this case with System authority against the
    // installed command; ordinary native runs use the crate's own executable.
    if args.len() == 3 && args[1] == "findmnt" {
        sysbox_findmnt::run_test(&args[2]);
        return;
    }
    if sysbox_less::is_helper(&args) {
        sysbox_less::run_helper(&args);
    }
    sysbox_caps::run_test();
    sysbox_cat::run_test();
    sysbox_chmod::run_all_tests();
    sysbox_diff::run_test();
    sysbox_find::run_test();
    sysbox_findmnt::run_test(env!("CARGO_BIN_EXE_sysbox"));
    sysbox_head::run_test();
    sysbox_less::run_test();
    sysbox_ls::run_test();
    sysbox_mkdir::run_test();
    sysbox_sort::run_test();
    sysbox_tail::run_test();
    sysbox_wc::run_test();
    sysbox_which::run_test();
    println!("sysbox commands: ALL PASS");
}

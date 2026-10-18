//! Native coverage of overlapping fills and requests already satisfied by them.

use super::{FsRuntime, Mapping, PAGE, PageBuf, elf, serve};
use crate::self_test::{st_assert, st_assert_eq};
use async_fs::{AccessPermissions, EntryKind, FileSystem, Role, RolePermissions};
use moto_sys::{SysHandle, SysMem, SysObj, syscalls::RaiiHandle};
use std::task::Poll;

pub(in crate::runtime::fs) async fn coalesced_windows(runtime: &FsRuntime) -> Result<(), String> {
    let name = format!(
        ".pager-window-test-{}",
        moto_rt::time::Instant::now().as_u64()
    );
    let entry = runtime
        .fs
        .write()
        .await
        .create_entry(
            Role::System,
            async_fs::ROOT_ID,
            EntryKind::File,
            &name,
            RolePermissions::new(
                AccessPermissions::Rwx,
                AccessPermissions::None,
                AccessPermissions::None,
            ),
        )
        .await
        .map_err(|err| err.to_string())?;

    let result = async {
        let bytes = vec![b'x'; async_fs::BLOCK_SIZE];
        {
            let mut fs = runtime.fs.write().await;
            for offset in (0..8 * PAGE).step_by(bytes.len()) {
                let written = fs
                    .write(Role::System, entry, offset, &bytes)
                    .await
                    .map_err(|err| err.to_string())?;
                st_assert_eq!(written, bytes.len());
            }
        }

        let space = RaiiHandle::from(
            SysObj::create(
                SysHandle::NONE,
                0,
                "address_space:debug_name=pager-window-test",
            )
            .map_err(|err| err.to_string())?,
        );
        let id = SysMem::pager_reserve(space.syshandle(), PAGE, 8, true, false)
            .map_err(|err| err.to_string())?;
        runtime.pager.add(
            id,
            Mapping::new(
                entry,
                Role::System,
                elf::Segment {
                    vaddr: PAGE,
                    offset: 0,
                    filesz: 8 * PAGE,
                    memsz: 8 * PAGE,
                    writable: true,
                    executable: false,
                },
                None,
            ),
        );
        let result = check_windows(runtime, id).await;
        drop(space);
        runtime.pager.drain();
        st_assert!(!runtime.pager.is_live(id));
        result
    }
    .await;

    let cleanup = runtime
        .fs
        .write()
        .await
        .delete_entry(Role::System, entry)
        .await
        .map_err(|err| err.to_string());
    result.and(cleanup)
}

async fn check_windows(runtime: &FsRuntime, id: u64) -> Result<(), String> {
    serve(runtime.clone(), id, PAGE).await;
    serve(runtime.clone(), id, 2 * PAGE).await;
    check_skips(runtime, id, &[2 * PAGE, 3 * PAGE]).await?;

    // Both reads start before either can fill. The wider request covers the
    // other; finishing the latter must not replace that window with a smaller one.
    let writer = runtime.fs.write().await;
    let mut wide = core::pin::pin!(serve(runtime.clone(), id, 4 * PAGE));
    let mut overlap = core::pin::pin!(serve(runtime.clone(), id, 5 * PAGE));
    let waiting = core::future::poll_fn(|cx| {
        let wide_waiting = wide.as_mut().poll(cx).is_pending();
        let overlap_waiting = overlap.as_mut().poll(cx).is_pending();
        Poll::Ready(wide_waiting && overlap_waiting)
    })
    .await;
    st_assert!(waiting);
    drop(writer);
    futures::join!(wide, overlap);
    check_skips(runtime, id, &[4 * PAGE, 7 * PAGE]).await?;

    // The end is exclusive. Fill the remaining page, then ask the kernel to
    // confirm that all eight pages are already installed.
    serve(runtime.clone(), id, 8 * PAGE).await;
    let buf = PageBuf::new(8).ok_or("pager self-test buffer allocation failed")?;
    st_assert_eq!(SysMem::pager_fill(id, PAGE, buf.ptr as u64, 8), Ok(0));
    Ok(())
}

async fn check_skips(runtime: &FsRuntime, id: u64, pages: &[u64]) -> Result<(), String> {
    let _writer = runtime.fs.write().await;
    for &page in pages {
        let faults = runtime.pager.faults.get();
        let mut request = core::pin::pin!(serve(runtime.clone(), id, page));
        // A covered request must finish without reaching the blocked FS read.
        let done =
            core::future::poll_fn(|cx| Poll::Ready(request.as_mut().poll(cx).is_ready())).await;
        if !done || runtime.pager.faults.get() != faults {
            return Err(format!("covered page 0x{page:x} was served again"));
        }
    }
    Ok(())
}

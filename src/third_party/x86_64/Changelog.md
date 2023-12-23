# Unreleased

# 0.14.9 - 2022-03-31

## New Features

- Address in `VirtAddrNotValid` and `PhysAddrNotValid` is now public ([#340](https://github.com/rust-osdev/x86_64/pull/340)).
  - This field now contains the whole invalid address ([#347](https://github.com/rust-osdev/x86_64/pull/347)).
- Remove all uses of external assembly ([#343](https://github.com/rust-osdev/x86_64/pull/343))
  - `external_asm` and `inline_asm` features are deprecated and now have no effect.
  - `instructions` feature (on by default) now requires Rust 1.59
  - Specific MSRV now noted in `README` ([#355](https://github.com/rust-osdev/x86_64/pull/355))
- Implement `core::iter::Step` for `VirtAddr` and `Page` ([#342](https://github.com/rust-osdev/x86_64/pull/342))
  - This trait is only available on nightly.
  - Gated behind `step_trait` feature flag
- Add `UCet` and `SCet` registers ([#349](https://github.com/rust-osdev/x86_64/pull/349))
- Use [`rustversion`](https://crates.io/crates/rustversion) to mark certian functions `const fn` on Rust 1.61 ([#353](https://github.com/rust-osdev/x86_64/pull/353))
- `Entry::handler_addr()` is now public ([#354](https://github.com/rust-osdev/x86_64/pull/354))
- Increase packed structure alignment ([#362](https://github.com/rust-osdev/x86_64/pull/362))
- Make more address methods `const fn` ([#369](https://github.com/rust-osdev/x86_64/pull/369))
  - `VirtAddr::as_ptr()`
  - `VirtAddr::as_mut_ptr()`
  - `PhysAddr::new()`
  - `PhysAddr::try_new()`

## Bug fixes and Documentation

- Fixed overflow bug in PageRangeInclusive ([#351](https://github.com/rust-osdev/x86_64/pull/351))
- Remove stabilized `const_fn_fn_ptr_basics` and `const_fn_trait_bound` features ([#352](https://github.com/rust-osdev/x86_64/pull/352))
- Don't set `nomem` in `load_tss` ([#358](https://github.com/rust-osdev/x86_64/pull/358))
- Correctly initialize TSS's IOPB to be empty ([#357](https://github.com/rust-osdev/x86_64/pull/357))
- Improve `GlobalDescriptorTable::add_entry` error handling ([#361](https://github.com/rust-osdev/x86_64/pull/361))
- Update `tss_segment` documentation ([#366](https://github.com/rust-osdev/x86_64/pull/366))

# 0.14.8 – 2022-02-03

- Add `Cr2::read_raw` ([#334](https://github.com/rust-osdev/x86_64/pull/334))
- Add support for `MXCSR` register ([#336](https://github.com/rust-osdev/x86_64/pull/336))

# 0.14.7 – 2021-12-18

- fix: build error on the latest nightly ([#329](https://github.com/rust-osdev/x86_64/pull/329))
- add `set_general_handler` macro ([#285](https://github.com/rust-osdev/x86_64/pull/285))
- Derive common traits for number, range and enum types ([#315](https://github.com/rust-osdev/x86_64/pull/315))
- Add the VMM Communication Exception (`#VC`) to the `InterruptDescriptorTable` ([#313](https://github.com/rust-osdev/x86_64/pull/313))
- fix: enable manipulation of `InterruptStackFrame` ([#312](https://github.com/rust-osdev/x86_64/pull/312))
- fix docs for `page_table_index` ([#318](https://github.com/rust-osdev/x86_64/pull/318))
- Remove redundant alignment check ([#314](https://github.com/rust-osdev/x86_64/pull/314))
- fix(idt): fix panic messages for `index` and `#VC` ([#321](https://github.com/rust-osdev/x86_64/pull/321))
- remove `const_assert!` in favor of std's `assert!` ([#326](https://github.com/rust-osdev/x86_64/pull/326))
- Move bootloader integration test to separate CI job ([#330](https://github.com/rust-osdev/x86_64/pull/330))

# 0.14.6 – 2021-09-20

- New `registers::segmentation` module ([#309](https://github.com/rust-osdev/x86_64/pull/309)), containing:
  - `instructions::segmentation::{Segment, Segment64, CS, DS, ES, FS, GS, SS}`
  - `structures::gdt::SegmentSelector`
  - Old locations still re-export all the types, so this is not a breaking change.
- Fixes build so that `cargo doc --no-default-features` succeeds.

# 0.14.5 – 2021-09-04

- Add `ExceptionVector` enum and additional flags to `PageFaultErrorCode` ([#303](https://github.com/rust-osdev/x86_64/pull/303))
- Add `clean_up` and `clean_up_with_filter` methods to deallocate unused page tables ([#264](https://github.com/rust-osdev/x86_64/pull/264))
- Rename some XCr0 and CR4 flags (#[275](https://github.com/rust-osdev/x86_64/pull/275))
- Expose `MapperFlush::new` and `MapperFlushAll::new` constructor functions ([#296](https://github.com/rust-osdev/x86_64/pull/296))
- Use `#[cfg(doc)]` instead of docs.rs-specific cfg flag (#[287](https://github.com/rust-osdev/x86_64/pull/287))
- Some documentation updates:
  - Update segment register references in `GDT::load*` method to non-deprecated methods ([#301](https://github.com/rust-osdev/x86_64/pull/301))
  - Remove a panic note ([#300](https://github.com/rust-osdev/x86_64/pull/300))
- Update `bit_field` dependency ([#306](https://github.com/rust-osdev/x86_64/pull/306))

# 0.14.4 – 2021-07-19

- Add `instructions::tables::sgdt` ([#279](https://github.com/rust-osdev/x86_64/pull/279))
- Improve control register bits ([#273](https://github.com/rust-osdev/x86_64/pull/273))
  - Add `Cr0` bits: `EXTENSION_TYPE` (ET)
  - Add `Cr4` bits:
    - `KEY_LOCKER` (KL)
    - `CONTROL_FLOW_ENFORCEMENT` (CET)
    - `PROTECTION_KEY_SUPERVISOR` (PKS)
  - Add `XCr0` bits: `BNDREG`, `BNDCSR`, `OPMASK`, `ZMM_HI256`, `HI16_ZMM`
  - Add consistency checks for `XCr0` bits
- Add `SelectorErrorCode` for parsing interrupt error codes from `#TS`, `#NP`, `#SS`, and `#GP` ([#274](https://github.com/rust-osdev/x86_64/pull/274))
- Make `addr::{align_up,  align_down}` const ([#270](https://github.com/rust-osdev/x86_64/pull/270))
- Make `structures::idt` available on stable Rust ([#271](https://github.com/rust-osdev/x86_64/pull/271))
  - Use dummy types for the `HandlerFunc`s if the `"abi_x86_interrupt"` feature is disabled
  - Add unsafe `set_handler_addr` that just takes a `VirtAddr`
- Add common abstractions for x86 Segments ([#258](https://github.com/rust-osdev/x86_64/pull/258))
  - Add `SS`, `CS`, `DS`, `ES`, `FS`, `GS` marker types
  - Add `Segment` trait for reading/writing the segment register
  - Add `Segment64` trait for reading/writing the segment base
  - Add `GS::swap()`
  - Deprecate the corresponding free functions:
    - `cs`, `set_cs`
    - `swap_gs`
    - `load_{ss,ds,es,fs,gs}`
    - `{wr,rd}{fs,gs}base`
- Bug fixes:
  - Corrected documentation typo ([#278](https://github.com/rust-osdev/x86_64/pull/278))
  - Avoided off-by-one error in `GlobalDescriptorTable::from_raw_slice` when `"const_fn"` is not enabled ([#269](https://github.com/rust-osdev/x86_64/pull/269))
  - Specify `sysv64` as the calling convention for the `"external_asm"` functions ([#267](https://github.com/rust-osdev/x86_64/pull/267))

# 0.14.3 – 2021-05-14

- Make the following types aliases of the new `PortGeneric` type ([#248](https://github.com/rust-osdev/x86_64/pull/248)):
  - `Port<T> = PortGeneric<T, ReadWriteAccess>`
  - `PortReadOnly<T> = PortGeneric<T, ReadOnlyAccess>`
  - `PortWriteOnly<T> = PortGeneric<T, WriteOnlyAccess>`
- The following methods no longer require the `nightly` feature to be `const fn`s ([#255](https://github.com/rust-osdev/x86_64/pull/255)):
  - `PageTable::new`
  - `GlobalDescriptorTable::from_raw_slice`
  - `MappedFrame::{start_address, size}`
  - `Page<Size4KiB>::p1_index`
- Add `Debug` implementation for `InterruptDescriptorTable` ([#253](https://github.com/rust-osdev/x86_64/pull/253))
  - Improve `Debug` implementations for `Entry` and `EntryOptions`

# 0.14.2 – 2021-05-13

- Multiple improvements to assembly code ([#251](https://github.com/rust-osdev/x86_64/pull/251))
  - Added `external_asm` implementations for `bochs_breakpoint` and `XCr0`
  - Updated `options` for `asm!` blocks (to improve performance)
  - Updated docs to use [`doc_cfg`](https://doc.rust-lang.org/unstable-book/language-features/doc-cfg.html)

# 0.14.1 – 2021-05-06

- Use new `const_fn_trait_bound` feature to fix build on latest nightly ([#250](https://github.com/rust-osdev/x86_64/pull/250))
  - _Attention:_ The `const_fn` feature now requires at least Rust nightly `2021-05-06`.
- Add support for `sidt` instruction ([#246](https://github.com/rust-osdev/x86_64/pull/246))
- Fix Debug and PartialEq implementations for IDT entry type ([#249](https://github.com/rust-osdev/x86_64/pull/249))
- Looser trait bounds for Port types ([#247](https://github.com/rust-osdev/x86_64/pull/247))

# 0.14.0 – 2021-04-11

- **Breaking:** Take the interrupt stack frame by value (not by reference) [#242](https://github.com/rust-osdev/x86_64/pull/242)
- **Breaking:** Change `InterruptStackFrame::as_mut` to return a `Volatile<_>` wrapper [#242](https://github.com/rust-osdev/x86_64/pull/242)

# 0.13.5 – 2021-04-01

- Add support for `XCR0` register ([#239](https://github.com/rust-osdev/x86_64/pull/239))

# 0.13.4 – 2021-03-27

- Implement more fmt traits for addr types ([#237](https://github.com/rust-osdev/x86_64/pull/237))

# 0.13.3 – 2021-03-16

- Implement `Clone` for `PageTable` ([#236](https://github.com/rust-osdev/x86_64/pull/236))

# 0.13.2 – 2021-02-02

- Fix build on latest nightly: The feature `const_in_array_repeat_expressions` was removed ([#230](https://github.com/rust-osdev/x86_64/pull/230))

# 0.13.1 – 2020-12-29

- PCID support instructions ([#169])(https://github.com/rust-osdev/x86_64/pull/169))

# 0.13.0 – 2020-12-28

- **Breaking:** Also return flags for `MapperAllSizes::translate()` ([#207](https://github.com/rust-osdev/x86_64/pull/207))
- **Breaking:** Restructure the `TranslateResult` type and create separate `Translate` trait ([#211](https://github.com/rust-osdev/x86_64/pull/211))
- **Breaking:** Rename `PhysToVirt` trait to `PageTableFrameMapping` ([#214](https://github.com/rust-osdev/x86_64/pull/214))
- **Breaking:** Use custom error types instead of `()` ([#199](https://github.com/rust-osdev/x86_64/pull/199))
- **Breaking:** Remove deprecated items
  - `UnusedPhysFrame`
  - `ExceptionStackFrame`
  - `VirtAddr::new_unchecked`
  - `interrupts::enable_interrupts_and_hlt`
- **Breaking:** Make `DescriptorTablePointer::base` a `VirtAddr` ([#215](https://github.com/rust-osdev/x86_64/pull/215))
- **Breaking:** Change return type of `read_rip` to `VirtAddr` ([#216](https://github.com/rust-osdev/x86_64/pull/216))
- **Breaking:** Make writing the RFLAGS register unsafe ([#219](https://github.com/rust-osdev/x86_64/pull/219))
- **Breaking:** Remove `PortReadWrite` trait, which is no longer needed ([#217](https://github.com/rust-osdev/x86_64/pull/217))
- Relaxe `Sized` requirement for `FrameAllocator` in `Mapper::map_to` ([204](https://github.com/rust-osdev/x86_64/pull/204))

# 0.12.4 – 2020-12-28

- Fix bad conversion from llvm_asm! to asm! ([#218](https://github.com/rust-osdev/x86_64/pull/218))
- GDT: Add `load_unchecked`, `from_raw_slice`, and `as_raw_slice` ([#210](https://github.com/rust-osdev/x86_64/pull/210))

# 0.12.3 – 2020-10-31

- Use `asm!` instead of perma-unstable `llvm_asm!` macro ([#165](https://github.com/rust-osdev/x86_64/pull/165))
- Make `GlobalDescriptorTable::add_entry` a const fn ([#191](https://github.com/rust-osdev/x86_64/pull/191))
- Rename `enable_interrupts_and_hlt` to `enable_and_hlt` ([#206](https://github.com/rust-osdev/x86_64/pull/206))
- Provide functions for accessing the underlying L4 table for mapper types ([#184](https://github.com/rust-osdev/x86_64/pull/184))
- Remove Trait constraint for `Port::new()` ([#188](https://github.com/rust-osdev/x86_64/pull/188))

# 0.12.2 – 2020-09-29

- Add additional `DescriptorFlags` and aliases compatible with `syscall`/`sysenter` ([#181](https://github.com/rust-osdev/x86_64/pull/181))
- Fix (another) build error on latest nightly ([#186](https://github.com/rust-osdev/x86_64/pull/186))

# 0.12.1 – 2020-09-24

- Fix build error on latest nightly ([#182](https://github.com/rust-osdev/x86_64/pull/182))

# 0.12.0 – 2020-09-23

- **Breaking**: Decouple instructions into a separate feature flag ([#179](https://github.com/rust-osdev/x86_64/pull/179))
  - Gates the `instructions` module by a new `instructions` feature (enabled by default).
  - Rename the `stable` feature to `external_asm`
  - `PageTable::new` is no longer a `const fn` on stable (i.e. without the `nightly` feature)

# 0.11.8 – 2020-09-23

- Add `VirtAddr::is_null` ([#180](https://github.com/rust-osdev/x86_64/pull/180))

# 0.11.7 – 2020-09-11

- Fix const_item_mutation warnings added in latest Rust nightly ([#178](https://github.com/rust-osdev/x86_64/pull/178))

# 0.11.6 – 2020-09-11 (yanked)

- (accidental empty release)

# 0.11.5 – 2020-09-03

- Don't rely on promotion of `PageTableEntry::new` inside a `const fn` ([#175](https://github.com/rust-osdev/x86_64/pull/175))

# 0.11.4 – 2020-09-01

- Add a function for the `nop` instruction ([#174](https://github.com/rust-osdev/x86_64/pull/174))

# ~~0.11.3 – 2020-09-01~~

- (accidental release, yanked)

# 0.11.2 – 2020-08-13

- Add rdfsbase, rdgsbase, wrfsbase, wrgsbase ([#172](https://github.com/rust-osdev/x86_64/pull/172))

# 0.11.1

- Export `PhysAddrNotValid` and `VirtAddrNotValid` error types ([#163](https://github.com/rust-osdev/x86_64/pull/163))

# 0.11.0

- **Breaking**: Handle parent table flags in Mapper methods ([#114](https://github.com/rust-osdev/x86_64/pull/114))

# 0.10.3

- Fix: Inclusive ranges is_empty() comparison ([#156](https://github.com/rust-osdev/x86_64/pull/156))

# 0.10.2

- **Nightly Breakage**: Use `llvm_asm!` instead of deprecated `asm!` macro ([#151](https://github.com/rust-osdev/x86_64/pull/151))
- Return the correct RPL from GDT::add_entry() ([#153](https://github.com/rust-osdev/x86_64/pull/153))

# 0.10.1

- Add InterruptDescriptorTable::load_unsafe ([#137](https://github.com/rust-osdev/x86_64/pull/137))

# 0.10.0

- **Breaking**: Make `map_to` and `update_flags` unsafe ([#135](https://github.com/rust-osdev/x86_64/pull/135))
- **Breaking**: Make `FrameDeallocator::deallocate_frame` unsafe ([#146](https://github.com/rust-osdev/x86_64/pull/146))
- **Breaking**: Don't pass small trivially copyable types by reference ([#147](https://github.com/rust-osdev/x86_64/pull/147))
- Various improvements to VirtAddr and PhysAddr ([#141](https://github.com/rust-osdev/x86_64/pull/141))
  - Among other things, this renamed the `VirtAddr::new_unchecked` function to `new_truncate`.
- Add `const_fn!{}` macro to make functions const without duplication ([#144](https://github.com/rust-osdev/x86_64/pull/144))
  - Also makes some more functions `const`.
- Add `{PhysFrame,Page}::from_start_address_unchecked` ([#142](https://github.com/rust-osdev/x86_64/pull/142))
- Use `#[inline]` everywhere ([#145](https://github.com/rust-osdev/x86_64/pull/145))
- In `VirtAddr::new_truncate`, use shift instead of mul and div ([#143](https://github.com/rust-osdev/x86_64/pull/143))
- Use `Self::new()` in `InterruptDescriptorTable::reset()` ([#148](https://github.com/rust-osdev/x86_64/pull/148))

# 0.9.6

- Add an enable_interrupts_and_hlt function that executes `sti; hlt` ([#138](https://github.com/rust-osdev/x86_64/pull/138))
- Fix some clippy warnings ([#130](https://github.com/rust-osdev/x86_64/pull/130))
- Resolve remaining clippy warnings and add clippy job to CI ([#132](https://github.com/rust-osdev/x86_64/pull/132))

# 0.9.5

- Add `#[inline]` attribute to small functions ([#129](https://github.com/rust-osdev/x86_64/pull/129))

# 0.9.4

- asm: add target_env = "musl" to pickup the underscore asm names ([#128](https://github.com/rust-osdev/x86_64/pull/128))

# 0.9.3

- Enable usage with non-nightly rust ([#127](https://github.com/rust-osdev/x86_64/pull/127))

# 0.9.2

- Remove the `cast` dependency ([#124](https://github.com/rust-osdev/x86_64/pull/124))

# 0.9.1

- Improve PageTableIndex and PageOffset ([#122](https://github.com/rust-osdev/x86_64/pull/122))

# 0.9.0

- **Breaking:** Return the UnusedPhysFrame on MapToError::PageAlreadyMapped ([#118](https://github.com/rust-osdev/x86_64/pull/118))
- Add User Mode registers ([#119](https://github.com/rust-osdev/x86_64/pull/119))

# 0.8.3

- Allow immediate port version of in/out instructions ([#115](https://github.com/rust-osdev/x86_64/pull/115))
- Make more functions const ([#116](https://github.com/rust-osdev/x86_64/pull/116))

# 0.8.2

- Add support for cr4 control register ([#111](https://github.com/rust-osdev/x86_64/pull/111))

# 0.8.1

- Fix: Add required reexport for new UnusedPhysFrame type ([#110](https://github.com/rust-osdev/x86_64/pull/110))

# 0.8.0

- **Breaking:** Replace `ux` dependency with custom wrapper structs ([#91](https://github.com/rust-osdev/x86_64/pull/91))
- **Breaking:** Add new UnsafePhysFrame type and use it in Mapper::map_to ([#89](https://github.com/rust-osdev/x86_64/pull/89))
- **Breaking:** Rename divide_by_zero field of interrupt descriptor table to divide_error ([#108](https://github.com/rust-osdev/x86_64/pull/108))
- **Breaking:** Introduce new diverging handler functions for double faults and machine check exceptions ([#109](https://github.com/rust-osdev/x86_64/pull/109))
- _Possibly Breaking:_ Make Mapper trait object safe by adding `Self: Sized` bounds on generic functions ([#84](https://github.com/rust-osdev/x86_64/pull/84))


# 0.7.7

- Add `slice` and `slice_mut` methods to IDT ([#95](https://github.com/rust-osdev/x86_64/pull/95))

# 0.7.6

- Use repr C to suppress not-ffi-safe when used with extern handler functions ([#94](https://github.com/rust-osdev/x86_64/pull/94))

# 0.7.5

- Add FsBase and GsBase register support ([#87](https://github.com/rust-osdev/x86_64/pull/87))

# 0.7.4

- Remove raw-cpuid dependency and use rdrand intrinsics ([#85](https://github.com/rust-osdev/x86_64/pull/85))
- Update integration tests to use new testing framework ([#86](https://github.com/rust-osdev/x86_64/pull/86))

# 0.7.3

- Add a new `OffsetPageTable` mapper type ([#83](https://github.com/rust-osdev/x86_64/pull/83))

# 0.7.2

- Add `instructions::bochs_breakpoint` and `registers::read_rip` functions ([#79](https://github.com/rust-osdev/x86_64/pull/79))
- Mark all single instruction functions as `#[inline]` ([#79](https://github.com/rust-osdev/x86_64/pull/79))
- Update GDT docs, add user_data_segment function and WRITABLE flag ([#78](https://github.com/rust-osdev/x86_64/pull/78))
- Reexport MappedPageTable on non-x86_64 platforms too ([#82](https://github.com/rust-osdev/x86_64/pull/82))

# 0.7.1

- Add ring-3 flag to GDT descriptor ([#77](https://github.com/rust-osdev/x86_64/pull/77))

# 0.7.0

- **Breaking**: `Port::read` and `PortReadOnly::read` now take `&mut self` instead of `&self` ([#76](https://github.com/rust-osdev/x86_64/pull/76)).

# 0.6.0

- **Breaking**: Make the `FrameAllocator` unsafe to implement. This way, we can force the implementer to guarantee that all frame allocators are valid. See [#69](https://github.com/rust-osdev/x86_64/issues/69) for more information.

# 0.5.5

- Use [`cast`](https://docs.rs/cast/0.2.2/cast/) crate instead of less general `usize_conversions` crate.

# 0.5.4

- Update dependencies to latest versions (fix [#67](https://github.com/rust-osdev/x86_64/issues/67))

# 0.5.3

- Add `PortReadOnly` and `PortWriteOnly` types in `instructions::port` module ([#66](https://github.com/rust-osdev/x86_64/pull/66)).

# 0.5.2

- Update documentation of `MappedPageTable`: Require that passed `level_4_table` is valid.

# 0.5.1

- Add `PageTable::{iter, iter_mut}` functions to iterate over page table entries.

# 0.5.0

## Breaking

- The `random` module is now a submodule of the `instructions` module.
- The `structures::paging` module was split into several submodules:
    - The `NotGiantPageSize`, `PageRange`, and `PageRangeInclusive` types were moved to a new `page` submodule.
    - The `PhysFrameRange` and `PhysFrameRangeInclusive` types were moved to a new `frame` submodule.
    - The `FrameError` and `PageTableEntry` types were moved to a new `page_table` submodule.
    - The `MapperFlush`, `MapToError`, `UnmapError`, and `FlagUpdateError` types were moved to a new `mapper` submodule.
- The `structures::paging` module received the following changes:
    - The `Mapper::translate_page` function now returns a `Result` with a new `TranslateError` error type.
    - The `NotRecursivelyMapped` error type was removed.
- The `instructions::int3` function was moved into the `instructions::interrupts` module.
- Removed some old deprecated functions.
- Made modifications of the interrupt stack frame unsafe by introducing a new wrapper type and an unsafe `as_mut` method.

## Other

- Added a new `structures::paging::MapperAllSizes` trait with generic translation methods and implement it for `MappedPageTable` and `RecursivePageTable`.
- Added a new `structures::paging::MappedPageTable` type that implements the `Mapper` and `MapperAllSizes` traits.
- Added a `software_interrupt` macro to invoke arbitrary `int x` instructions.
- Renamed the `ExceptionStackFrame` type to `InterruptStackFrame`.

# 0.4.2

- Add `RdRand::get_u{16, 32, 64}` methods
- Deprecate `RdRand::get` because it does not check for failure
- Make `RdRand` Copy

# 0.4.1

- Add support for the RdRand instruction (random number generation)

# 0.4.0

## Breaking

- Make `Mapper::map_to` and `Mapper::identity_map` unsafe because it is possible to break memory safety by passing invalid arguments.
- Rename `FrameAllocator::alloc` to `allocate_frame` and `FrameDeallocator::dealloc` to `deallocate_frame`.
- Remove `From<os_bootinfo::FrameRange>` implementation for `PhysFrameRange`
  - The `os_bootinfo` crate is no longer used by the `bootloader` crate.
  - It is not possible to provide an implementation for all `os_bootinfo` versions.

## Other

- Update to 2018 edition

# 0.3.6

- Add a `SIZE` constant to the `Page` type
- Add two interrupt tests to the `testing` sub-crate

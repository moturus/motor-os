//! Program x86 enclaves.

use core::arch::asm;

/// Execute an enclave system function of specified leaf number.
///
/// # Safety
///   * Function needs to be executed in ring 0.
macro_rules! encls {
    ($rax:expr, $rbx:expr) => {
        $crate::bits64::sgx::encls2($rax as u64, $rbx as u64)
    };

    ($rax:expr, $rbx:expr, $rcx:expr) => {
        $crate::bits64::sgx::encls3($rax as u64, $rbx as u64, $rcx as u64)
    };

    ($rax:expr, $rbx:expr, $rcx:expr, $rdx:expr) => {
        $crate::bits64::sgx::encls4($rax as u64, $rbx as u64, $rcx as u64, $rdx as u64)
    };
}

/// encls with two arguments -- consider calling the encls! macro instead!
unsafe fn encls2(rax: u64, rbx: u64) -> (u32, u64) {
    let eax: u32;
    let out_rbx: u64;
    asm!(
        "pushq %rbx; movq %rsi, %rbx; encls; movq %rbx, %rsi; popq %rbx",
        lateout("eax") eax, lateout("rsi") out_rbx,
        in("rax") rax, in("rsi") rbx,
        options(att_syntax),
    );
    (eax, out_rbx)
}

/// encls with three arguments -- consider calling the encls! macro instead!
unsafe fn encls3(rax: u64, rbx: u64, rcx: u64) -> (u32, u64) {
    let eax: u32;
    let out_rbx: u64;
    asm!(
        "pushq %rbx; movq %rsi, %rbx; encls; movq %rbx, %r11; popq %rbx",
        lateout("eax") eax, lateout("rsi") out_rbx,
        in("rax") rax, in("rsi") rbx, in("rcx") rcx,
        options(att_syntax),
    );
    (eax, out_rbx)
}

/// encls with four arguments -- consider calling the encls! macro instead!
unsafe fn encls4(rax: u64, rbx: u64, rcx: u64, rdx: u64) -> (u32, u64) {
    let eax: u32;
    let out_rbx: u64;
    asm!(
        "pushq %rbx; movq %rsi, %rbx; encls; movq %rbx, %rsi; popq %rbx",
        lateout("eax") eax, lateout("rsi") out_rbx,
        in("rax") rax, in("rsi") rbx, in("rcx") rcx, in("rdx") rdx,
        options(att_syntax),
    );
    (eax, out_rbx)
}

#[allow(clippy::upper_case_acronyms)]
enum EnclsCommand {
    EADD = 0x01,
    EAUG = 0x0D,
    EBLOCK = 0x09,
    ECREATE = 0x00,
    EDBGRD = 0x04,
    EDBGWR = 0x05,
    EEXTEND = 0x06,
    EINIT = 0x02,
    ELDB = 0x07,
    ELDU = 0x08,
    EMODPR = 0x0E,
    EMODT = 0x0F,
    EPA = 0x0A,
    EREMOVE = 0x03,
    ETRACK = 0x0C,
    EWB = 0x0B,
}

/// Add a Page to an Uninitialized Enclave.
///
/// # Arguments
///  * Address of a PAGEINFO.
///  * Address of the destination EPC page.
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_eadd(pageinfo: u64, epc_page: u64) {
    encls!(EnclsCommand::EADD as u64, pageinfo, epc_page);
}

/// Add a Page to an Initialized Enclave.
///
/// # Arguments
///  * Address of a SECINFO
///  * Address of the destination EPC page
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_eaug(secinfo_address: u64, epc_page: u64) {
    encls!(EnclsCommand::EAUG as u64, secinfo_address, epc_page);
}

/// Mark a page in EPC as Blocked.
///
/// # Arguments
///  * Effective address of the EPC page
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_eblock(epc_page: u64) -> u32 {
    encls!(EnclsCommand::EBLOCK as u64, epc_page).0
}

/// Create an SECS page in the Enclave Page Cache
///
/// # Arguments
///  * Address of a PAGEINFO
///  * Address of the destination SECS page
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_create(pageinfo: u64, secs_page: u64) {
    encls!(EnclsCommand::ECREATE as u64, pageinfo, secs_page);
}

/// Read From a Debug Enclave.
///
/// # Return
/// Data read from a debug enclave.
///
/// # Arguments
///  * Address of source memory in the EPC
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_edbgrd(source_address: u64) -> u64 {
    encls!(EnclsCommand::EDBGRD as u64, source_address).1
}

/// Write to a Debug Enclave.
///
/// # Arguments
///  * Data to be written to a debug enclave
///  * Address of Target memory in the EPC
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_edbgwr(data: u64, target_address: u64) {
    encls!(EnclsCommand::EDBGWR as u64, data, target_address);
}

/// Extend Uninitialized Enclave Measurement by 256 Bytes
///
/// # Arguments
///  * Effective address of the SECS of the data chunk
///  * Effective address of a 256-byte chunk in the EPC
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_eextend(secs_chunk: u64, epc_chunk: u64) {
    encls!(EnclsCommand::EEXTEND as u64, secs_chunk, epc_chunk);
}

/// Initialize an Enclave for Execution
///
/// # Arguments
///  * Address of SIGSTRUCT
///  * Address of SECS
///  * Address of EINITTOKEN
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_einit(sigstruct: u64, secs: u64, einittoken: u64) -> u32 {
    encls!(EnclsCommand::EINIT as u64, sigstruct, secs, einittoken).0
}

/// Loads and verifies an EPC page and marks the page as blocked.
///
/// # Arguments
///  * Address of the PAGEINFO
///  * Address of the EPC page
///  * Address of the version-array slot
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_eldb(pageinfo: u64, epc_page: u64, verion_array_slot: u64) -> u32 {
    encls!(
        EnclsCommand::ELDB as u64,
        pageinfo,
        epc_page,
        verion_array_slot
    )
    .0
}

/// Loads, verifies an EPC page and marks the page as unblocked.
///
/// # Arguments
///  * Address of the PAGEINFO
///  * Address of the EPC page
///  * Address of the version-array slot
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_eldu(pageinfo: u64, epc_page: u64, verion_array_slot: u64) -> u32 {
    encls!(
        EnclsCommand::ELDU as u64,
        pageinfo,
        epc_page,
        verion_array_slot
    )
    .0
}

/// Restrict the Permissions of an EPC Page.
///
/// # Arguments
///  * Address of a SECINFO
///  * Address of the destination EPC page
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_emodpr(secinfo: u64, epc_page: u64) -> u32 {
    encls!(EnclsCommand::EMODPR as u64, secinfo, epc_page).0
}

/// Change the Type of an EPC Page.
///
/// # Arguments
///  * Address of a SECINFO
///  * Address of the destination EPC page
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_emodt(secinfo: u64, epc_page: u64) -> u32 {
    encls!(EnclsCommand::EMODT as u64, secinfo, epc_page).0
}

/// Add Version Array.
///
/// # Arguments
///  * PT_VA Constant
///  * Effective address of the EPC page
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_epa(pt_va: u64, epc_page: u64) {
    encls!(EnclsCommand::EPA as u64, pt_va, epc_page);
}

/// Remove a page from the EPC.
///
/// # Arguments
///  * Effective address of the EPC page
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_eremove(epc_page: u64) {
    encls!(EnclsCommand::EREMOVE as u64, epc_page);
}

/// Activates EBLOCK Checks.
///
/// # Arguments
///  * Pointer to the SECS of the EPC page.
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_etrack(secs_pointer: u64) -> u32 {
    encls!(EnclsCommand::ETRACK as u64, secs_pointer).0
}

/// Invalidate an EPC Page and Write out to Main Memory.
///
/// # Arguments
///  * Address of the EPC page.
///  * Address of a VA slot.
///
/// # Safety
/// Requires SGX support.
pub unsafe fn encls_ewb(pageinfo: u64, epc_page: u64, va_slot: u64) -> u32 {
    encls!(EnclsCommand::EWB as u64, pageinfo, epc_page, va_slot).0
}

/// Execute an enclave user function of specified leaf number.
///
/// # Safety
///   * Function needs to be executed in ring 3.
macro_rules! enclu {
    ($rax:expr, $rbx:expr, $rcx:expr) => {
        $crate::bits64::sgx::enclu3($rax as u64, $rbx as u64, $rcx as u64)
    };

    ($rax:expr, $rbx:expr, $rcx:expr, $rdx:expr) => {
        $crate::bits64::sgx::enclu4($rax as u64, $rbx as u64, $rcx as u64, $rdx as u64)
    };
}

/// enclu with three arguments -- consider calling the enclu! macro instead!
unsafe fn enclu3(rax: u64, rbx: u64, rcx: u64) -> (u32, u64) {
    let eax: u32;
    let out_rcx: u64;
    asm!(
        "pushq %rbx; movq %rsi, %rbx; enclu; popq %rbx",
        lateout("eax") eax, lateout("rcx") out_rcx,
        in("rax") rax, in("rsi") rbx, in("rcx") rcx,
        options(att_syntax),
    );
    (eax, out_rcx)
}

/// enclu with four arguments -- consider calling the enclu! macro instead!
unsafe fn enclu4(rax: u64, rbx: u64, rcx: u64, rdx: u64) -> (u32, u64) {
    let eax: u32;
    let out_rcx: u64;
    asm!(
        "pushq %rbx; movq %rsi, %rbx; enclu; popq %rbx",
        lateout("eax") eax, lateout("rcx") out_rcx,
        in("rax") rax, in("rsi") rbx, in("rcx") rcx, in("rdx") rdx,
        options(att_syntax),
    );
    (eax, out_rcx)
}

enum EncluCommand {
    EAccept = 0x05,
    EAcceptCopy = 0x07,
    EEnter = 0x02,
    EExit = 0x04,
    EGetKey = 0x01,
    EModePE = 0x06,
    EReport = 0x00,
    EResume = 0x03,
}

/// Accept Changes to an EPC Page.
///
/// # Arguments
///  * Address of a SECINFO.
///  * Address of the destination EPC page.
///
/// Returns an error code.
///
/// # Safety
/// Requires SGX support.
pub unsafe fn enclu_eaccept(secinfo: u64, epc_page: u64) -> u32 {
    enclu!(EncluCommand::EAccept as u64, secinfo, epc_page).0
}

/// Initialize a Pending Page.
///
/// # Arguments
///  * Address of a SECINFO.
///  * Address of the destination EPC page.
///  * Address of the source EPC page.
///
/// Returns an error code.
///
/// # Safety
/// Requires SGX support.
pub unsafe fn enclu_eacceptcopy(
    secinfo: u64,
    destination_epc_page: u64,
    source_epc_page: u64,
) -> u32 {
    enclu!(
        EncluCommand::EAcceptCopy as u64,
        secinfo,
        destination_epc_page,
        source_epc_page
    )
    .0
}

/// Enters an Enclave.
///
/// # Arguments
///  * Address of a TCS.
///  * Address of AEP.
///  * Address of IP following EEnter.
///
/// Returns content of RBX.CSSA and Address of IP following EEnter.
///
/// # Safety
/// Requires SGX support.
pub unsafe fn enclu_eenter(tcs: u64, aep: u64) -> (u32, u64) {
    enclu!(EncluCommand::EEnter as u64, tcs, aep)
}

/// Exits an Enclave.
///
/// # Arguments
///  * Target address outside the enclave
///  * Address of the current AEP
///
/// # Safety
/// Requires SGX support.
pub unsafe fn enclu_eexit(ip: u64, aep: u64) {
    enclu!(EncluCommand::EExit as u64, ip, aep);
}

/// Retrieves a Cryptographic Key.
///
/// # Arguments
///  * Address to a KEYREQUEST
///  * Address of the OUTPUTDATA
///
/// # Safety
/// Requires SGX support.
pub unsafe fn enclu_egetkey(keyrequest: u64, outputdata: u64) {
    enclu!(EncluCommand::EGetKey as u64, keyrequest, outputdata);
}

/// Extend an EPC Page Permissions.
///
/// # Arguments
///  * Address of a SECINFO
///  * Address of the destination EPC page
///
/// # Safety
/// Requires SGX support.
pub unsafe fn enclu_emodepe(secinfo: u64, epc_page: u64) {
    enclu!(EncluCommand::EModePE as u64, secinfo, epc_page);
}

/// Create a Cryptographic Report of the Enclave.
///
/// # Arguments
///  * Address of TARGETINFO
///  * Address of REPORTDATA
///  * Address where the REPORT is written to in an OUTPUTDATA
///
/// # Safety
/// Requires SGX support.
pub unsafe fn enclu_ereport(targetinfo: u64, reportdata: u64, outputdata: u64) {
    enclu!(
        EncluCommand::EReport as u64,
        targetinfo,
        reportdata,
        outputdata
    );
}

/// Re-Enters an Enclave.
///
/// # Arguments
///  * Address of a TCS.
///  * Address of AEP.
///
/// # Safety
/// Requires SGX support.
pub unsafe fn enclu_eresume(tcs: u64, aep: u64) {
    enclu!(EncluCommand::EResume as u64, tcs, aep);
}

// SPDX-License-Identifier: MPL-2.0

//! Safe Rust wrappers for the CIE-specific extensions exposed by
//! `libopencie-pkcs11` via `include/opencie/cie_ext.h`.
//!
//! All fallible functions return `Result<_, pkcs11::Error>`. The wrapped
//! `CK_RV` value is the same return code documented by the C API. Arguments
//! that cannot be represented as C strings (interior NUL byte) or as a C
//! `int` are rejected with `CKR_ARGUMENTS_BAD` before reaching the library.
//!
//! # Callbacks
//!
//! The C API requires non-NULL progress / completion callbacks for
//! `cie_enable`, `cie_change_pin`, `cie_unblock_pin`, `cie_sign` and
//! `cie_timestamp` (they are invoked unconditionally). The wrappers always
//! install internal callbacks so the library never sees NULL. Progress
//! notifications can be observed with [`with_progress`]; completion
//! callbacks are not exposed (the wrappers return the final result anyway).

use crate::cie_ffi;
use crate::ffi;
use crate::pkcs11::{Error, Result};
use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar, c_ulong, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};

const CKR_FUNCTION_FAILED: cie_ffi::CK_RV = ffi::CKR_FUNCTION_FAILED as cie_ffi::CK_RV;
const CKR_ARGUMENTS_BAD: cie_ffi::CK_RV = ffi::CKR_ARGUMENTS_BAD as cie_ffi::CK_RV;
const CKR_DATA_LEN_RANGE: cie_ffi::CK_RV = ffi::CKR_DATA_LEN_RANGE as cie_ffi::CK_RV;
const CKR_MECHANISM_INVALID: cie_ffi::CK_RV = ffi::CKR_MECHANISM_INVALID as cie_ffi::CK_RV;
const CKR_DEVICE_ERROR: cie_ffi::CK_RV = ffi::CKR_DEVICE_ERROR as cie_ffi::CK_RV;
const CKR_FUNCTION_NOT_SUPPORTED: cie_ffi::CK_RV =
    ffi::CKR_FUNCTION_NOT_SUPPORTED as cie_ffi::CK_RV;
const CKR_PIN_INCORRECT: cie_ffi::CK_RV = ffi::CKR_PIN_INCORRECT as cie_ffi::CK_RV;

/// Semantic classification of a CIE card failure, derived from the ISO 7816
/// status word returned by the card (or from the PACE exchange).
#[repr(u32)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// No error recorded.
    None = 0,
    /// `0x63Cx`, `0x6300`, `0x6700`.
    WrongPin = 1,
    /// `0x6983`.
    PinBlocked = 2,
    /// `0x6984`.
    PinNotSet = 3,
    /// `0x6982`.
    SecurityNotSatisfied = 4,
    /// `0x6A82`.
    FileNotFound = 5,
    /// `0x6A80`, `0x6A86`, `0x6A88`, `0x6B00`.
    WrongParams = 6,
    /// `0x6D00`, `0x6E00`. With [`read_dgs_can`] this means the reader
    /// rejected the extended-length APDUs PACE needs.
    InsNotSupported = 7,
    /// Transport / secure-messaging failure without a usable status word.
    CardCommunication = 8,
    /// A status word the library does not classify.
    Unknown = 9,
    /// The card answered but its chip/applet is not in the supported list.
    UnsupportedCard = 10,
    /// PACE rejected the CAN (mutual authentication failed).
    WrongCan = 11,
}

impl From<cie_ffi::cie_error_kind> for ErrorKind {
    fn from(raw: cie_ffi::cie_error_kind) -> Self {
        match raw {
            cie_ffi::cie_error_kind_CIE_ERR_NONE => ErrorKind::None,
            cie_ffi::cie_error_kind_CIE_ERR_WRONG_PIN => ErrorKind::WrongPin,
            cie_ffi::cie_error_kind_CIE_ERR_PIN_BLOCKED => ErrorKind::PinBlocked,
            cie_ffi::cie_error_kind_CIE_ERR_PIN_NOT_SET => ErrorKind::PinNotSet,
            cie_ffi::cie_error_kind_CIE_ERR_SECURITY_NOT_SATISFIED => {
                ErrorKind::SecurityNotSatisfied
            }
            cie_ffi::cie_error_kind_CIE_ERR_FILE_NOT_FOUND => ErrorKind::FileNotFound,
            cie_ffi::cie_error_kind_CIE_ERR_WRONG_PARAMS => ErrorKind::WrongParams,
            cie_ffi::cie_error_kind_CIE_ERR_INS_NOT_SUPPORTED => ErrorKind::InsNotSupported,
            cie_ffi::cie_error_kind_CIE_ERR_CARD_COMMUNICATION => ErrorKind::CardCommunication,
            cie_ffi::cie_error_kind_CIE_ERR_UNSUPPORTED_CARD => ErrorKind::UnsupportedCard,
            cie_ffi::cie_error_kind_CIE_ERR_WRONG_CAN => ErrorKind::WrongCan,
            _ => ErrorKind::Unknown,
        }
    }
}

/// Largest value that can be a signature count. Counts are returned as
/// `CK_RV` (unsigned long) but are always small; every error value is either
/// a `CIE_SIGN_ERROR_*` code (`0x84000000` and up) or a negative status cast
/// to `CK_RV`, both above `i32::MAX`.
const MAX_SIGN_COUNT: cie_ffi::CK_RV = i32::MAX as cie_ffi::CK_RV;

fn rv_unit(rv: cie_ffi::CK_RV) -> Result<()> {
    if rv == 0 {
        Ok(())
    } else {
        Err(Error(rv))
    }
}

/// Interpret the return value of `cie_get_sign_count`.
fn rv_count(rv: cie_ffi::CK_RV) -> Result<i32> {
    if rv <= MAX_SIGN_COUNT {
        Ok(rv as i32)
    } else {
        Err(Error(rv))
    }
}

/// Interpret the return value of `cie_verify`, given the value that
/// `cie_get_sign_count` reports right after it.
///
/// Per the C API a return value that differs from `cie_get_sign_count()` is
/// an error; small error codes (e.g. `CKR_*`) cannot be told apart from a
/// count by magnitude alone.
fn verify_result(rv: cie_ffi::CK_RV, count: cie_ffi::CK_RV) -> Result<i32> {
    if rv == count && rv <= MAX_SIGN_COUNT {
        Ok(rv as i32)
    } else if rv == 0 {
        // "No signatures" was returned but the count disagrees: never hand
        // out `Error(0)` (CKR_OK) as a failure.
        Err(Error(CKR_FUNCTION_FAILED))
    } else {
        Err(Error(rv))
    }
}

fn cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error(CKR_ARGUMENTS_BAD))
}

fn opt_cstring(s: Option<&str>) -> Result<Option<CString>> {
    s.map(cstring).transpose()
}

fn opt_ptr(s: &Option<CString>) -> *const c_char {
    s.as_deref().map_or(std::ptr::null(), CStr::as_ptr)
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

type ProgressHandler = dyn FnMut(i32, &str);
type ProgressPtr = *mut ProgressHandler;

thread_local! {
    static PROGRESS: Cell<Option<ProgressPtr>> = const { Cell::new(None) };
}

/// Run `f` and forward the progress notifications emitted by any `cie`
/// operation it calls on this thread (`enable`, `change_pin`, `unblock_pin`,
/// `sign`, `timestamp`) to `handler(percent, message)`.
///
/// The handler runs synchronously on the calling thread, inside the library
/// call. A panic in the handler is caught and discarded: unwinding through
/// the C library would be undefined behaviour.
pub fn with_progress<R>(handler: &mut dyn FnMut(i32, &str), f: impl FnOnce() -> R) -> R {
    struct Restore(Option<ProgressPtr>);
    impl Drop for Restore {
        fn drop(&mut self) {
            PROGRESS.with(|p| p.set(self.0));
        }
    }

    let ptr: *mut (dyn FnMut(i32, &str) + '_) = handler;
    // SAFETY: only the lifetime bound of the trait object is erased. The
    // pointer is stored for the duration of `f` and removed (by `Restore`,
    // also on unwind) before `handler`'s borrow ends.
    let ptr = unsafe { std::mem::transmute::<*mut (dyn FnMut(i32, &str) + '_), ProgressPtr>(ptr) };
    let _restore = Restore(PROGRESS.with(|p| p.replace(Some(ptr))));
    f()
}

unsafe extern "C" fn progress_trampoline(progress: c_int, msg: *const c_char) -> cie_ffi::CK_RV {
    // Take the handler out while it runs so a re-entrant call cannot alias it.
    let Some(ptr) = PROGRESS.with(|p| p.take()) else {
        return 0;
    };
    let text = if msg.is_null() {
        std::borrow::Cow::Borrowed("")
    } else {
        CStr::from_ptr(msg).to_string_lossy()
    };
    let _ = catch_unwind(AssertUnwindSafe(|| (*ptr)(progress, &text)));
    PROGRESS.with(|p| p.set(Some(ptr)));
    0
}

unsafe extern "C" fn completed_noop(
    _pan: *const c_char,
    _name: *const c_char,
    _serial: *const c_char,
) -> cie_ffi::CK_RV {
    0
}

unsafe extern "C" fn sign_completed_noop(_ret: c_int) -> cie_ffi::CK_RV {
    0
}

// ---------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------

/// Enrol a CIE card identified by PAN using the 8-digit numeric PIN.
///
/// Progress can be observed with [`with_progress`].
pub fn enable(pan: &str, pin: &str) -> Result<()> {
    let c_pan = cstring(pan)?;
    let c_pin = cstring(pin)?;
    let mut attempts: c_int = 0;
    unsafe {
        rv_unit(cie_ffi::cie_enable(
            c_pan.as_ptr(),
            c_pin.as_ptr(),
            &mut attempts,
            Some(progress_trampoline),
            Some(completed_noop),
        ))
    }
}

/// Return `true` if the card identified by PAN is enrolled, i.e. a cached
/// certificate exists for it: either the cache written by [`enable`] or the
/// pairing cache of the official CIE ID app (`~/.CIEPKI/<PAN>.cache`).
/// A card that is merely inserted is not reported as enabled, because its
/// certificate cannot be read without the PIN.
pub fn is_enabled(pan: &str) -> bool {
    let Ok(c_pan) = CString::new(pan) else {
        return false;
    };
    unsafe { cie_ffi::cie_is_enabled(c_pan.as_ptr()) == 1 }
}

/// Remove the enrolment for the card identified by PAN.
///
/// Fails with `CKR_FUNCTION_FAILED` if the card was not enrolled.
pub fn disable(pan: &str) -> Result<()> {
    let c_pan = cstring(pan)?;
    unsafe { rv_unit(cie_ffi::cie_disable(c_pan.as_ptr())) }
}

/// Change the PIN.
pub fn change_pin(current_pin: &str, new_pin: &str) -> Result<()> {
    let c_cur = cstring(current_pin)?;
    let c_new = cstring(new_pin)?;
    let mut attempts: c_int = 0;
    unsafe {
        rv_unit(cie_ffi::cie_change_pin(
            c_cur.as_ptr(),
            c_new.as_ptr(),
            &mut attempts,
            Some(progress_trampoline),
        ))
    }
}

/// Unblock the PIN using the PUK and set a new PIN.
pub fn unblock_pin(puk: &str, new_pin: &str) -> Result<()> {
    let c_puk = cstring(puk)?;
    let c_new = cstring(new_pin)?;
    let mut attempts: c_int = 0;
    unsafe {
        rv_unit(cie_ffi::cie_unblock_pin(
            c_puk.as_ptr(),
            c_new.as_ptr(),
            &mut attempts,
            Some(progress_trampoline),
        ))
    }
}

// ---------------------------------------------------------------------------
// Sign & verify
// ---------------------------------------------------------------------------

/// Sign a PDF file on behalf of the card identified by PAN.
///
/// `page` is the 0-based page index. `x`, `y`, `w` and `h` are fractions
/// (`0.0..=1.0`) of the page crop box: `x` is the left and `y` the bottom
/// position; a `w` or `h` of `0.0` hides the visible widget.
///
/// `image_data` is the optional PNG byte buffer used as the signature stamp.
/// Pass `None` (or an empty slice) when no stamp should be drawn.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    in_file: &str,
    sig_type: &str,
    pin: &str,
    pan: &str,
    page: i32,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    image_data: Option<&[u8]>,
    out_file: &str,
) -> Result<()> {
    let c_in = cstring(in_file)?;
    let c_type = cstring(sig_type)?;
    let c_pin = cstring(pin)?;
    let c_pan = cstring(pan)?;
    let c_out = cstring(out_file)?;

    let (img_ptr, img_len): (*const c_uchar, c_int) = match image_data {
        Some(b) if !b.is_empty() => (
            b.as_ptr(),
            c_int::try_from(b.len()).map_err(|_| Error(CKR_ARGUMENTS_BAD))?,
        ),
        _ => (std::ptr::null(), 0),
    };

    unsafe {
        rv_unit(cie_ffi::cie_sign(
            c_in.as_ptr(),
            c_type.as_ptr(),
            c_pin.as_ptr(),
            c_pan.as_ptr(),
            page,
            x,
            y,
            w,
            h,
            img_ptr,
            img_len,
            c_out.as_ptr(),
            Some(progress_trampoline),
            Some(sign_completed_noop),
        ))
    }
}

/// Verify a signed document. Returns the number of signatures found (valid
/// or not; inspect each one with [`get_verify_info`]); `0` if the file has
/// none.
///
/// The C function returns the count or an error code in the same `CK_RV`
/// value. A return value that differs from `cie_get_sign_count()` is an
/// error, which is how this wrapper tells them apart.
///
/// The library keeps the result of the last verification in process-global
/// state shared with [`get_sign_count`] and [`get_verify_info`]: do not run
/// verifications concurrently from several threads.
pub fn verify(
    in_file: &str,
    proxy_addr: Option<&str>,
    proxy_port: i32,
    usr_pass: Option<&str>,
) -> Result<i32> {
    let c_in = cstring(in_file)?;
    let c_proxy = opt_cstring(proxy_addr)?;
    let c_pass = opt_cstring(usr_pass)?;

    unsafe {
        let rv = cie_ffi::cie_verify(
            c_in.as_ptr(),
            opt_ptr(&c_proxy),
            proxy_port,
            opt_ptr(&c_pass),
        );
        verify_result(rv, cie_ffi::cie_get_sign_count())
    }
}

/// Number of signatures found by the last [`verify`] call.
pub fn get_sign_count() -> Result<i32> {
    unsafe { rv_count(cie_ffi::cie_get_sign_count()) }
}

/// Per-signature verification info. Mirrors `verifyInfo_t` from `cie_ext.h`.
#[derive(Debug, Clone, Default)]
pub struct VerifyInfo {
    pub name: String,
    pub surname: String,
    pub cn: String,
    pub signing_time: String,
    pub cadn: String,
    pub cert_revoc_status: i32,
    pub is_sign_valid: bool,
    pub is_cert_valid: bool,
}

fn fixed_to_string(buf: &[c_char]) -> String {
    // Reinterpret as bytes and trim at the first NUL byte.
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Retrieve signer info for the n-th signature found by the last [`verify`].
///
/// An out-of-range `index` (or no prior [`verify`]) fails with code `1`.
pub fn get_verify_info(index: i32) -> Result<VerifyInfo> {
    let mut raw: cie_ffi::verifyInfo_t = unsafe { std::mem::zeroed() };
    let rv = unsafe { cie_ffi::cie_get_verify_info(index, &mut raw) };
    if rv != 0 {
        return Err(Error(rv));
    }
    Ok(VerifyInfo {
        name: fixed_to_string(&raw.name),
        surname: fixed_to_string(&raw.surname),
        cn: fixed_to_string(&raw.cn),
        signing_time: fixed_to_string(&raw.signingTime),
        cadn: fixed_to_string(&raw.cadn),
        cert_revoc_status: raw.CertRevocStatus,
        is_sign_valid: raw.isSignValid != 0,
        is_cert_valid: raw.isCertValid != 0,
    })
}

/// Extract the original document from a `.p7m` envelope.
pub fn extract_p7m(in_file: &str, out_file: &str) -> Result<()> {
    let c_in = cstring(in_file)?;
    let c_out = cstring(out_file)?;
    unsafe { rv_unit(cie_ffi::cie_extract_p7m(c_in.as_ptr(), c_out.as_ptr())) }
}

// ---------------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------------

/// Retrieve the DER-encoded X.509 certificate of the paired card `pan`.
///
/// Reads the cache written by [`enable`]. If there is none and the card is
/// on a reader, the certificate is taken from the CIE ID pairing cache
/// (`~/.CIEPKI/<PAN>.cache`), which needs the card present to decrypt; the
/// result is then cached for later calls. An unpaired card fails, because
/// the card never releases the certificate without a verified PIN.
///
/// The buffer allocated by the library is copied and released with
/// `cie_free`, as required by the C API.
pub fn get_certificate(pan: &str) -> Result<Vec<u8>> {
    /// Releases a library-allocated buffer through `cie_free`.
    struct Owned(*mut c_uchar);
    impl Drop for Owned {
        fn drop(&mut self) {
            // `cie_free(NULL)` is a documented no-op.
            unsafe { cie_ffi::cie_free(self.0 as *mut c_void) };
        }
    }

    let c_pan = cstring(pan)?;
    let mut out: *mut c_uchar = std::ptr::null_mut();
    let mut len: c_ulong = 0;
    let rv = unsafe { cie_ffi::cie_get_certificate(c_pan.as_ptr(), &mut out, &mut len) };
    let buf = Owned(out);
    rv_unit(rv)?;
    if buf.0.is_null() {
        return Err(Error(CKR_FUNCTION_FAILED));
    }
    // SAFETY: on success the library returns `len` readable bytes at `out`.
    Ok(unsafe { std::slice::from_raw_parts(buf.0, len as usize) }.to_vec())
}

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

/// Request a standalone RFC 3161 timestamp for a file (no card required).
///
/// Computes the SHA-256 digest of `in_file`, sends a TimeStampRequest to
/// `tsa_url` (optionally with HTTP Basic credentials) and writes the
/// DER-encoded TimeStampToken to `out_token`.
pub fn timestamp(
    in_file: &str,
    tsa_url: &str,
    tsa_username: Option<&str>,
    tsa_password: Option<&str>,
    out_token: &str,
) -> Result<()> {
    let c_in = cstring(in_file)?;
    let c_url = cstring(tsa_url)?;
    let c_user = opt_cstring(tsa_username)?;
    let c_pass = opt_cstring(tsa_password)?;
    let c_out = cstring(out_token)?;
    unsafe {
        rv_unit(cie_ffi::cie_timestamp(
            c_in.as_ptr(),
            c_url.as_ptr(),
            opt_ptr(&c_user),
            opt_ptr(&c_pass),
            c_out.as_ptr(),
            Some(progress_trampoline),
        ))
    }
}

// ---------------------------------------------------------------------------
// Chip data groups (ICAO 9303)
// ---------------------------------------------------------------------------

/// Capacity of the DG1 buffer (header recommends at least 4096 bytes).
const MRZ_CAPACITY: usize = 4096;
/// Capacity of the photo buffer (header recommends at least 524288 bytes).
const PHOTO_CAPACITY: usize = 1 << 20;

/// DG1 and DG2 as read from the chip.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataGroups {
    /// Raw DG1 TLV bytes (contains the MRZ).
    pub mrz: Vec<u8>,
    /// Portrait photo as PNG bytes (JPEG2000 is decoded by the library).
    pub photo_png: Vec<u8>,
}

fn read_dgs_with(
    call: impl FnOnce(*mut c_char, *mut usize, *mut c_uchar, *mut usize) -> cie_ffi::CK_RV,
) -> Result<DataGroups> {
    let mut mrz = vec![0u8; MRZ_CAPACITY];
    let mut photo = vec![0u8; PHOTO_CAPACITY];
    let mut mrz_len = mrz.len();
    let mut photo_len = photo.len();
    rv_unit(call(
        mrz.as_mut_ptr() as *mut c_char,
        &mut mrz_len,
        photo.as_mut_ptr(),
        &mut photo_len,
    ))?;
    mrz.truncate(mrz_len.min(MRZ_CAPACITY));
    photo.truncate(photo_len.min(PHOTO_CAPACITY));
    Ok(DataGroups {
        mrz,
        photo_png: photo,
    })
}

/// `true` if `can` is exactly six ASCII digits, the only form the library
/// accepts.
fn is_valid_can(can: &str) -> bool {
    can.len() == 6 && can.bytes().all(|b| b.is_ascii_digit())
}

/// Read DG1 (MRZ) and DG2 (photo) over ICAO 9303 PACE with the 6-digit Card
/// Access Number (CAN) printed on the card. No PIN is used or consumed.
///
/// A CAN that is not exactly six ASCII digits fails with `CKR_ARGUMENTS_BAD`
/// without touching the reader. For the other failure modes, ask
/// [`can_failure`] right after the call (same thread):
///
/// - wrong CAN: `CKR_PIN_INCORRECT` + [`ErrorKind::WrongCan`]. The library
///   never retries a wrong CAN by itself and neither should the caller;
/// - chip without PACE: `CKR_FUNCTION_NOT_SUPPORTED` +
///   [`ErrorKind::UnsupportedCard`];
/// - reader without extended-length APDUs (e.g. ACS ACR122U):
///   `CKR_DEVICE_ERROR` + [`ErrorKind::InsNotSupported`]. Fall back to
///   [`read_dgs`] (PIN based) or use another reader.
pub fn read_dgs_can(can: &str) -> Result<DataGroups> {
    if !is_valid_can(can) {
        return Err(Error(CKR_ARGUMENTS_BAD));
    }
    let c_can = cstring(can)?;
    read_dgs_with(|mrz, mrz_len, photo, photo_len| unsafe {
        cie_ffi::cie_read_dgs_can(c_can.as_ptr(), mrz, mrz_len, photo, photo_len)
    })
}

/// Read DG1 (MRZ) and DG2 (photo) in one session using the 8-digit PIN.
///
/// Fallback for readers that cannot carry the extended-length APDUs required
/// by [`read_dgs_can`]. Prefer [`read_dgs_can`] when possible: this variant
/// verifies the PIN on the card, so wrong attempts decrease its retry
/// counter.
pub fn read_dgs(pin: &str) -> Result<DataGroups> {
    let c_pin = cstring(pin)?;
    read_dgs_with(|mrz, mrz_len, photo, photo_len| unsafe {
        cie_ffi::cie_read_dgs(c_pin.as_ptr(), mrz, mrz_len, photo, photo_len)
    })
}

/// Why a [`read_dgs_can`] call failed, for choosing what to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanFailure {
    /// The CAN was rejected by the card. Ask the user; do not retry with the
    /// same CAN.
    WrongCan,
    /// The reader (or transport) cannot send extended-length APDUs. Fall back
    /// to [`read_dgs`] or another reader.
    ReaderLacksExtendedLength,
    /// The chip does not offer a supported PACE protocol.
    UnsupportedCard,
    /// Any other failure; inspect the [`Error`] code.
    Other,
}

/// Classify a [`read_dgs_can`] failure from its `CK_RV` and the error kind
/// reported by [`last_error`]. Pure function, no card required.
pub fn classify_can_failure(err: Error, kind: ErrorKind) -> CanFailure {
    match (err.0, kind) {
        (CKR_PIN_INCORRECT, ErrorKind::WrongCan) => CanFailure::WrongCan,
        (CKR_DEVICE_ERROR, ErrorKind::InsNotSupported) => CanFailure::ReaderLacksExtendedLength,
        (CKR_FUNCTION_NOT_SUPPORTED, ErrorKind::UnsupportedCard) => CanFailure::UnsupportedCard,
        _ => CanFailure::Other,
    }
}

/// [`classify_can_failure`] using [`last_error`] of the calling thread. Call
/// it immediately after the failed [`read_dgs_can`].
pub fn can_failure(err: Error) -> CanFailure {
    classify_can_failure(err, last_error().0)
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

/// Number of PC/SC readers currently visible to the library.
pub fn reader_count() -> i32 {
    unsafe { cie_ffi::cie_reader_count() }
}

/// Block until the reader count changes from `current_count`. Returns the new
/// count, or `-1` if the PC/SC context could not be established (always `0`
/// on Android, where readers are not enumerated).
pub fn reader_watch(current_count: i32) -> i32 {
    unsafe { cie_ffi::cie_reader_watch(current_count) }
}

/// Name of the most useful reader, or `None` if no reader is present.
///
/// The library prefers a slot that currently holds a card, then an empty
/// contactless slot, then any other empty non-built-in slot.
pub fn reader_name() -> Option<String> {
    let mut buf = vec![0u8; 512];
    // The C function returns 1 if a reader was found, 0 otherwise (it is NOT
    // the number of bytes written); the name is a NUL-terminated string.
    let found =
        unsafe { cie_ffi::cie_reader_name(buf.as_mut_ptr() as *mut c_char, buf.len() as c_int) };
    if found <= 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// OpenSSL NIDs accepted by [`make_digest_info`].
const NID_SHA1: i32 = 65;
const NID_SHA256: i32 = 672;
const NID_SHA384: i32 = 673;
const NID_SHA512: i32 = 674;

/// DER `DigestInfo` header (everything before the digest bytes) and the
/// digest length it encodes, for the supported OpenSSL NIDs (RFC 8017,
/// section 9.2, note 1).
fn digest_info_header(algid: i32) -> Option<(&'static [u8], usize)> {
    const SHA1: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    const SHA256: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA384: &[u8] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    const SHA512: &[u8] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];
    match algid {
        NID_SHA1 => Some((SHA1, 20)),
        NID_SHA256 => Some((SHA256, 32)),
        NID_SHA384 => Some((SHA384, 48)),
        NID_SHA512 => Some((SHA512, 64)),
        _ => None,
    }
}

/// Build a DER-encoded PKCS#1 DigestInfo from a raw digest value.
///
/// `algid` is the OpenSSL NID of the digest algorithm:
/// SHA-1=65, SHA-256=672, SHA-384=673, SHA-512=674. Any other NID fails
/// with `CKR_MECHANISM_INVALID`, and a `digest` whose length does not match
/// the algorithm fails with `CKR_DATA_LEN_RANGE`.
///
/// This is computed in Rust and does not call `make_digest_info` from
/// `cie_ext.h`: that function lives in the static sign SDK and is not
/// exported by the shared `libopencie-pkcs11` (1.3.0 on Linux does not
/// contain the symbol, despite the header and version script). The output is
/// byte-for-byte what the C function produces for valid input; for an
/// unknown NID the C function reports success without writing anything.
pub fn make_digest_info(algid: i32, digest: &[u8]) -> Result<Vec<u8>> {
    let (header, expected) = digest_info_header(algid).ok_or(Error(CKR_MECHANISM_INVALID))?;
    if digest.len() != expected {
        return Err(Error(CKR_DATA_LEN_RANGE));
    }
    let mut out = Vec::with_capacity(header.len() + digest.len());
    out.extend_from_slice(header);
    out.extend_from_slice(digest);
    Ok(out)
}

/// Classify an ISO 7816 status word. Pure function, no card required.
pub fn classify_sw(sw: u16) -> ErrorKind {
    ErrorKind::from(unsafe { cie_ffi::cie_classify_sw(sw) })
}

/// Detail for the most recent failed cie_* call on the CALLING THREAD.
///
/// Returns a tuple of (ErrorKind, status_word). The error record is
/// thread-local and reports only the most recent failure on this thread.
/// A successful call resets the record to (None, 0).
pub fn last_error() -> (ErrorKind, u16) {
    let mut kind: cie_ffi::cie_error_kind = 0;
    let mut sw: u16 = 0;
    unsafe {
        cie_ffi::cie_last_error(&mut kind, &mut sw);
    }
    (ErrorKind::from(kind), sw)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- struct layout / constants (cie_ext.h) ----

    #[test]
    fn verify_info_layout_matches_header() {
        use std::mem::{align_of, offset_of, size_of};
        assert_eq!(cie_ffi::OPENCIE_MAX_LEN, 512);
        let field = (cie_ffi::OPENCIE_MAX_LEN * 2) as usize;
        let int = size_of::<c_int>();
        assert_eq!(size_of::<cie_ffi::verifyInfo_t>(), 5 * field + 3 * int);
        assert_eq!(align_of::<cie_ffi::verifyInfo_t>(), align_of::<c_int>());
        assert_eq!(offset_of!(cie_ffi::verifyInfo_t, name), 0);
        assert_eq!(offset_of!(cie_ffi::verifyInfo_t, surname), field);
        assert_eq!(offset_of!(cie_ffi::verifyInfo_t, cn), 2 * field);
        assert_eq!(offset_of!(cie_ffi::verifyInfo_t, signingTime), 3 * field);
        assert_eq!(offset_of!(cie_ffi::verifyInfo_t, cadn), 4 * field);
        assert_eq!(
            offset_of!(cie_ffi::verifyInfo_t, CertRevocStatus),
            5 * field
        );
        assert_eq!(
            offset_of!(cie_ffi::verifyInfo_t, isSignValid),
            5 * field + int
        );
        assert_eq!(
            offset_of!(cie_ffi::verifyInfo_t, isCertValid),
            5 * field + 2 * int
        );
    }

    #[test]
    fn ck_rv_is_unsigned_long() {
        assert_eq!(
            std::mem::size_of::<cie_ffi::CK_RV>(),
            std::mem::size_of::<c_ulong>()
        );
        // CK_RV must be unsigned: a negative status cast to CK_RV is huge.
        assert!((-2i64 as cie_ffi::CK_RV) > MAX_SIGN_COUNT);
    }

    #[test]
    fn error_kind_values_match_header() {
        let table = [
            (cie_ffi::cie_error_kind_CIE_ERR_NONE, ErrorKind::None, 0),
            (
                cie_ffi::cie_error_kind_CIE_ERR_WRONG_PIN,
                ErrorKind::WrongPin,
                1,
            ),
            (
                cie_ffi::cie_error_kind_CIE_ERR_PIN_BLOCKED,
                ErrorKind::PinBlocked,
                2,
            ),
            (
                cie_ffi::cie_error_kind_CIE_ERR_PIN_NOT_SET,
                ErrorKind::PinNotSet,
                3,
            ),
            (
                cie_ffi::cie_error_kind_CIE_ERR_SECURITY_NOT_SATISFIED,
                ErrorKind::SecurityNotSatisfied,
                4,
            ),
            (
                cie_ffi::cie_error_kind_CIE_ERR_FILE_NOT_FOUND,
                ErrorKind::FileNotFound,
                5,
            ),
            (
                cie_ffi::cie_error_kind_CIE_ERR_WRONG_PARAMS,
                ErrorKind::WrongParams,
                6,
            ),
            (
                cie_ffi::cie_error_kind_CIE_ERR_INS_NOT_SUPPORTED,
                ErrorKind::InsNotSupported,
                7,
            ),
            (
                cie_ffi::cie_error_kind_CIE_ERR_CARD_COMMUNICATION,
                ErrorKind::CardCommunication,
                8,
            ),
            (
                cie_ffi::cie_error_kind_CIE_ERR_UNKNOWN,
                ErrorKind::Unknown,
                9,
            ),
            (
                cie_ffi::cie_error_kind_CIE_ERR_UNSUPPORTED_CARD,
                ErrorKind::UnsupportedCard,
                10,
            ),
            (
                cie_ffi::cie_error_kind_CIE_ERR_WRONG_CAN,
                ErrorKind::WrongCan,
                11,
            ),
        ];
        for (raw, kind, value) in table {
            assert_eq!(raw, value, "header value for {kind:?}");
            assert_eq!(kind as u32, value, "Rust discriminant for {kind:?}");
            assert_eq!(ErrorKind::from(raw), kind);
        }
        // Unknown future values degrade to Unknown instead of misclassifying.
        assert_eq!(ErrorKind::from(12), ErrorKind::Unknown);
        assert_eq!(ErrorKind::from(u32::MAX), ErrorKind::Unknown);
    }

    // ---- return-value classification ----

    #[test]
    fn get_sign_count_classification() {
        assert_eq!(rv_count(0).unwrap(), 0);
        assert_eq!(rv_count(3).unwrap(), 3);
        assert_eq!(rv_count(MAX_SIGN_COUNT).unwrap(), i32::MAX);
        // CIE_SIGN_ERROR_UNEXPECTED = 0x84000001
        assert_eq!(rv_count(0x8400_0001), Err(Error(0x8400_0001)));
        // A negative status cast to CK_RV.
        let neg = -2i64 as cie_ffi::CK_RV;
        assert_eq!(rv_count(neg), Err(Error(neg)));
    }

    #[test]
    fn verify_result_accepts_only_matching_count() {
        assert_eq!(verify_result(0, 0), Ok(0));
        assert_eq!(verify_result(2, 2), Ok(2));
        // A small error code that differs from the count is an error, even
        // though it is far below the CIE_SIGN_ERROR_* range.
        assert_eq!(verify_result(7, 0), Err(Error(7)));
        assert_eq!(verify_result(5, 2), Err(Error(5)));
        // CIE_SIGN_ERROR_* (0x84000000 + n) and negative statuses.
        assert_eq!(verify_result(0x8400_0002, 0), Err(Error(0x8400_0002)));
        let neg = -2i64 as cie_ffi::CK_RV;
        assert_eq!(verify_result(neg, 0), Err(Error(neg)));
        // Never report success because both calls failed identically.
        assert_eq!(
            verify_result(0x8400_0001, 0x8400_0001),
            Err(Error(0x8400_0001))
        );
        // rv == 0 but the count disagrees must not yield Error(CKR_OK).
        assert_eq!(verify_result(0, 3), Err(Error(CKR_FUNCTION_FAILED)));
    }

    #[test]
    fn can_failure_classification() {
        use CanFailure::*;
        assert_eq!(
            classify_can_failure(Error(CKR_PIN_INCORRECT), ErrorKind::WrongCan),
            WrongCan
        );
        assert_eq!(
            classify_can_failure(Error(CKR_DEVICE_ERROR), ErrorKind::InsNotSupported),
            ReaderLacksExtendedLength
        );
        assert_eq!(
            classify_can_failure(
                Error(CKR_FUNCTION_NOT_SUPPORTED),
                ErrorKind::UnsupportedCard
            ),
            UnsupportedCard
        );
        // The code alone is not enough: a wrong PIN is not a wrong CAN.
        assert_eq!(
            classify_can_failure(Error(CKR_PIN_INCORRECT), ErrorKind::WrongPin),
            Other
        );
        assert_eq!(
            classify_can_failure(Error(CKR_ARGUMENTS_BAD), ErrorKind::None),
            Other
        );
    }

    // ---- argument handling (never reaches a card) ----

    #[test]
    fn read_dgs_can_rejects_malformed_can() {
        for bad in [
            "",
            "12345",
            "1234567",
            "12a456",
            "１２３４５６",
            "12 456",
            "12345\0",
        ] {
            assert_eq!(
                read_dgs_can(bad).unwrap_err(),
                Error(CKR_ARGUMENTS_BAD),
                "{bad:?}"
            );
        }
        assert!(is_valid_can("012345"));
    }

    #[test]
    fn interior_nul_is_arguments_bad() {
        assert_eq!(cstring("a\0b").unwrap_err(), Error(CKR_ARGUMENTS_BAD));
        assert_eq!(
            opt_cstring(Some("a\0b")).unwrap_err(),
            Error(CKR_ARGUMENTS_BAD)
        );
        assert!(opt_cstring(None).unwrap().is_none());
        assert!(opt_ptr(&None).is_null());
        assert_eq!(disable("12\x003").unwrap_err(), Error(CKR_ARGUMENTS_BAD));
        assert_eq!(
            verify("a.pdf", Some("pro\0xy"), 0, None).unwrap_err(),
            Error(CKR_ARGUMENTS_BAD)
        );
        assert!(!is_enabled("12\x003"));
    }

    #[test]
    fn fixed_to_string_trims_at_nul() {
        let mut buf = [0 as c_char; 16];
        for (dst, src) in buf.iter_mut().zip(b"Mario\0junk") {
            *dst = *src as c_char;
        }
        assert_eq!(fixed_to_string(&buf), "Mario");
        let full = [b'a' as c_char; 4];
        assert_eq!(fixed_to_string(&full), "aaaa");
    }

    // ---- callbacks ----

    #[test]
    fn progress_trampoline_forwards_to_handler() {
        let mut seen: Vec<(i32, String)> = Vec::new();
        let msg = CString::new("Lettura dati dalla CIE").unwrap();
        let rv = with_progress(&mut |p, m| seen.push((p, m.to_owned())), || unsafe {
            let a = progress_trampoline(15, msg.as_ptr());
            let b = progress_trampoline(100, std::ptr::null());
            (a, b)
        });
        assert_eq!(rv, (0, 0));
        assert_eq!(
            seen,
            vec![
                (15, "Lettura dati dalla CIE".to_owned()),
                (100, String::new())
            ]
        );
    }

    #[test]
    fn progress_trampoline_without_handler_is_noop() {
        let msg = CString::new("x").unwrap();
        assert_eq!(unsafe { progress_trampoline(1, msg.as_ptr()) }, 0);
        assert_eq!(
            unsafe { completed_noop(msg.as_ptr(), msg.as_ptr(), msg.as_ptr()) },
            0
        );
        assert_eq!(unsafe { sign_completed_noop(0) }, 0);
    }

    #[test]
    fn progress_handler_is_removed_after_scope_and_panics_are_contained() {
        let msg = CString::new("x").unwrap();
        let mut calls = 0;
        with_progress(&mut |_, _| calls += 1, || unsafe {
            progress_trampoline(1, msg.as_ptr());
        });
        // Out of scope: no handler any more.
        unsafe { progress_trampoline(2, msg.as_ptr()) };
        assert_eq!(calls, 1);

        // A panicking handler must not unwind through the extern "C" frame.
        let rv = with_progress(&mut |_, _| panic!("boom"), || unsafe {
            progress_trampoline(3, msg.as_ptr())
        });
        assert_eq!(rv, 0);
    }

    // ---- library-backed pure functions (no card, no reader) ----

    #[test]
    fn classify_sw_matches_documented_ranges() {
        assert_eq!(classify_sw(0x63C2), ErrorKind::WrongPin);
        assert_eq!(classify_sw(0x6300), ErrorKind::WrongPin);
        assert_eq!(classify_sw(0x6983), ErrorKind::PinBlocked);
        assert_eq!(classify_sw(0x6984), ErrorKind::PinNotSet);
        assert_eq!(classify_sw(0x6982), ErrorKind::SecurityNotSatisfied);
        assert_eq!(classify_sw(0x6A82), ErrorKind::FileNotFound);
        assert_eq!(classify_sw(0x6A80), ErrorKind::WrongParams);
        assert_eq!(classify_sw(0x6D00), ErrorKind::InsNotSupported);
        assert_eq!(classify_sw(0x6E00), ErrorKind::InsNotSupported);
    }

    #[test]
    fn verify_and_extract_report_errors_for_missing_files() {
        // Exercises the real cie_verify / cie_get_sign_count pair without a
        // card: a missing input must surface as an error, never as a count.
        let err = verify("/nonexistent/opencie-test.pdf", None, 0, None).unwrap_err();
        assert_ne!(err, Error(0));
        assert_eq!(get_sign_count(), Ok(0));
        assert!(extract_p7m("/nonexistent/in.p7m", "/nonexistent/out").is_err());
        assert!(get_verify_info(0).is_err());
    }

    #[test]
    fn make_digest_info_builds_der() {
        let sha256 = [0xAB; 32];
        let der = make_digest_info(672, &sha256).unwrap();
        // SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING }
        assert_eq!(
            &der[..19],
            &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20
            ]
        );
        assert_eq!(&der[19..], &sha256);

        let sha1 = [0x11; 20];
        let der = make_digest_info(65, &sha1).unwrap();
        assert_eq!(der.len(), 15 + 20);
        assert_eq!(&der[..2], &[0x30, 0x21]);

        assert_eq!(make_digest_info(673, &[0; 48]).unwrap().len(), 19 + 48);
        assert_eq!(make_digest_info(674, &[0; 64]).unwrap().len(), 19 + 64);
    }

    #[test]
    fn make_digest_info_rejects_bad_input() {
        // Unknown NID: the C function would report success with garbage.
        assert_eq!(
            make_digest_info(4, &[0; 16]).unwrap_err(),
            Error(CKR_MECHANISM_INVALID)
        );
        // Digest length not matching the algorithm.
        assert_eq!(
            make_digest_info(672, &[0; 31]).unwrap_err(),
            Error(CKR_DATA_LEN_RANGE)
        );
        assert_eq!(
            make_digest_info(65, &[]).unwrap_err(),
            Error(CKR_DATA_LEN_RANGE)
        );
    }
}

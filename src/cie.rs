//! Safe Rust wrappers for the CIE-specific extensions exposed by
//! `libopencie-pkcs11` via `include/opencie/cie_ext.h`.
//!
//! All functions return `Result<_, pkcs11::Error>`. The wrapped `CK_RV` value
//! is the same return code documented by the C API.
//!
//! Callbacks for `cie_enable`, `cie_change_pin`, `cie_unblock_pin` and
//! `cie_sign` are not yet exposed: NULL is passed through. This matches the
//! current behavior of the upstream library when callers do not need progress
//! reporting.

use crate::cie_ffi;
use crate::pkcs11::{Error, Result};
use std::ffi::{CStr, CString};
use std::os::raw::c_int;

/// Threshold separating "small positive count" from "PKCS#11 error code".
/// PKCS#11 error codes occupy the upper part of the `CK_RV` (unsigned long)
/// range; signature counts are always small. 0x1000 is well above any
/// realistic count and safely below the lowest CKR_* error value.
const RV_COUNT_LIMIT: cie_ffi::CK_RV = 0x1000;

fn rv_unit(rv: cie_ffi::CK_RV) -> Result<()> {
    if rv == 0 {
        Ok(())
    } else {
        Err(Error(rv))
    }
}

fn rv_count(rv: cie_ffi::CK_RV) -> Result<i32> {
    if rv < RV_COUNT_LIMIT {
        Ok(rv as i32)
    } else {
        Err(Error(rv))
    }
}

/// Enrol a CIE card identified by PAN using the 8-digit numeric PIN.
///
/// Note: progress and completion callbacks are not yet wired through the safe
/// wrapper; NULL is passed to the C API.
pub fn enable(pan: &str, pin: &str) -> Result<()> {
    let c_pan = CString::new(pan).map_err(|_| Error(1))?;
    let c_pin = CString::new(pin).map_err(|_| Error(1))?;
    let mut attempts: c_int = 0;
    unsafe {
        rv_unit(cie_ffi::cie_enable(
            c_pan.as_ptr(),
            c_pin.as_ptr(),
            &mut attempts,
            None,
            None,
        ))
    }
}

/// Return `true` if the card identified by PAN is currently enrolled.
pub fn is_enabled(pan: &str) -> bool {
    let Ok(c_pan) = CString::new(pan) else {
        return false;
    };
    unsafe { cie_ffi::cie_is_enabled(c_pan.as_ptr()) == 1 }
}

/// Remove the enrolment for the card identified by PAN.
pub fn disable(pan: &str) -> Result<()> {
    let c_pan = CString::new(pan).map_err(|_| Error(1))?;
    unsafe { rv_unit(cie_ffi::cie_disable(c_pan.as_ptr())) }
}

/// Change the PIN.
pub fn change_pin(current_pin: &str, new_pin: &str) -> Result<()> {
    let c_cur = CString::new(current_pin).map_err(|_| Error(1))?;
    let c_new = CString::new(new_pin).map_err(|_| Error(1))?;
    let mut attempts: c_int = 0;
    unsafe {
        rv_unit(cie_ffi::cie_change_pin(
            c_cur.as_ptr(),
            c_new.as_ptr(),
            &mut attempts,
            None,
        ))
    }
}

/// Unblock the PIN using the PUK and set a new PIN.
pub fn unblock_pin(puk: &str, new_pin: &str) -> Result<()> {
    let c_puk = CString::new(puk).map_err(|_| Error(1))?;
    let c_new = CString::new(new_pin).map_err(|_| Error(1))?;
    let mut attempts: c_int = 0;
    unsafe {
        rv_unit(cie_ffi::cie_unblock_pin(
            c_puk.as_ptr(),
            c_new.as_ptr(),
            &mut attempts,
            None,
        ))
    }
}

/// Sign a PDF file on behalf of the card identified by PAN.
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
    let c_in = CString::new(in_file).map_err(|_| Error(1))?;
    let c_type = CString::new(sig_type).map_err(|_| Error(1))?;
    let c_pin = CString::new(pin).map_err(|_| Error(1))?;
    let c_pan = CString::new(pan).map_err(|_| Error(1))?;
    let c_out = CString::new(out_file).map_err(|_| Error(1))?;

    let (img_ptr, img_len): (*const std::os::raw::c_uchar, c_int) = match image_data {
        Some(b) if !b.is_empty() => (b.as_ptr(), b.len() as c_int),
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
            None,
            None,
        ))
    }
}

/// Verify a signed document. Returns the number of valid signatures found.
pub fn verify(
    in_file: &str,
    proxy_addr: Option<&str>,
    proxy_port: i32,
    usr_pass: Option<&str>,
) -> Result<i32> {
    let c_in = CString::new(in_file).map_err(|_| Error(1))?;
    let c_proxy = proxy_addr.and_then(|s| CString::new(s).ok());
    let c_pass = usr_pass.and_then(|s| CString::new(s).ok());
    let c_proxy_ptr = c_proxy.as_deref().map_or(std::ptr::null(), CStr::as_ptr);
    let c_pass_ptr = c_pass.as_deref().map_or(std::ptr::null(), CStr::as_ptr);

    unsafe {
        rv_count(cie_ffi::cie_verify(
            c_in.as_ptr(),
            c_proxy_ptr,
            proxy_port,
            c_pass_ptr,
        ))
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

fn fixed_to_string(buf: &[std::os::raw::c_char]) -> String {
    // Reinterpret as bytes and trim at the first NUL byte.
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Retrieve signer info for the n-th signature found by the last [`verify`].
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
    let c_in = CString::new(in_file).map_err(|_| Error(1))?;
    let c_out = CString::new(out_file).map_err(|_| Error(1))?;
    unsafe { rv_unit(cie_ffi::cie_extract_p7m(c_in.as_ptr(), c_out.as_ptr())) }
}

/// Number of PC/SC readers currently visible to the library.
pub fn reader_count() -> i32 {
    unsafe { cie_ffi::cie_reader_count() }
}

/// Block until the reader count changes from `current_count`. Returns the new
/// count.
pub fn reader_watch(current_count: i32) -> i32 {
    unsafe { cie_ffi::cie_reader_watch(current_count) }
}

/// Name of the first available reader, or `None` if no reader is present.
pub fn reader_name() -> Option<String> {
    let mut buf = vec![0u8; 256];
    let written = unsafe {
        cie_ffi::cie_reader_name(
            buf.as_mut_ptr() as *mut std::os::raw::c_char,
            buf.len() as c_int,
        )
    };
    if written <= 0 {
        return None;
    }
    let len = (written as usize).min(buf.len());
    buf.truncate(len);
    if let Some(end) = buf.iter().position(|&b| b == 0) {
        buf.truncate(end);
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Build a DER-encoded PKCS#1 DigestInfo from a raw digest value.
///
/// `algid` is the OpenSSL NID of the digest algorithm:
/// SHA-1=65, SHA-256=672, SHA-384=673, SHA-512=674.
pub fn make_digest_info(algid: i32, digest: &[u8]) -> Result<Vec<u8>> {
    // Allocate generously: longest DigestInfo prefix is ~19 bytes for SHA-512.
    let mut out = vec![0u8; digest.len() + 32];
    let mut out_len: usize = out.len();
    let ok = unsafe {
        cie_ffi::make_digest_info(
            algid,
            digest.as_ptr(),
            digest.len(),
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    if ok != 1 {
        return Err(Error(0x60)); // CKR_BUFFER_TOO_SMALL
    }
    out.truncate(out_len);
    Ok(out)
}

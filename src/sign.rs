use crate::pkcs11::{Error, Result};
use crate::sign_ffi;
use std::ffi::CString;
use std::os::raw::c_long;

/// Sign context wrapper
pub struct Ctx(pub sign_ffi::CIE_SIGN_CTX);

// CIE_SIGN_CTX is a void pointer, making it Send is appropriate for this use case
unsafe impl Send for Ctx {}

/// Convert long return value to Result
fn long_to_result(r: c_long) -> Result<()> {
    if r == 0 {
        Ok(())
    } else {
        Err(Error(r as u64))
    }
}

/// Initialize a signing operation
pub fn sign_init() -> Ctx {
    unsafe { Ctx(sign_ffi::cie_sign_sign_init()) }
}

/// Set an integer option for signing
///
/// # Arguments
/// * `ctx` - Signing context
/// * `option` - Option constant (e.g., CIE_SIGN_OPT_*)
/// * `value` - Integer value to set
pub fn sign_set_int(ctx: &Ctx, option: i32, value: i32) -> Result<()> {
    unsafe {
        let rv = sign_ffi::cie_sign_sign_set_int(ctx.0, option, value);
        long_to_result(rv)
    }
}

/// Set a string option for signing
///
/// # Arguments
/// * `ctx` - Signing context
/// * `option` - Option constant (e.g., CIE_SIGN_OPT_*)
/// * `value` - String value to set
pub fn sign_set_string(ctx: &Ctx, option: i32, value: &str) -> Result<()> {
    unsafe {
        let c_value = CString::new(value).map_err(|_| Error(1))?;
        let rv = sign_ffi::cie_sign_sign_set_string(ctx.0, option, c_value.as_ptr() as *mut i8);
        long_to_result(rv)
    }
}

/// Execute the signing operation according to the configured options
///
/// # Arguments
/// * `ctx` - Signing context with configured options
pub fn sign_sign(ctx: &Ctx) -> Result<()> {
    unsafe {
        let rv = sign_ffi::cie_sign_sign_sign(ctx.0);
        long_to_result(rv)
    }
}

/// Clean up memory allocated for the signing operation
///
/// # Arguments
/// * `ctx` - Signing context (consumed)
pub fn sign_cleanup(ctx: Ctx) -> Result<()> {
    unsafe {
        let rv = sign_ffi::cie_sign_sign_cleanup(ctx.0);
        long_to_result(rv)
    }
}

/// Initialize a verification operation
pub fn verify_init() -> Ctx {
    unsafe { Ctx(sign_ffi::cie_sign_verify_init()) }
}

/// Set an integer option for verification
///
/// # Arguments
/// * `ctx` - Verification context
/// * `option` - Option constant (e.g., CIE_SIGN_OPT_*)
/// * `value` - Integer value to set
pub fn verify_set_int(ctx: &Ctx, option: i32, value: i32) -> Result<()> {
    unsafe {
        let rv = sign_ffi::cie_sign_verify_set_int(ctx.0, option, value);
        long_to_result(rv)
    }
}

/// Set a string option for verification
///
/// # Arguments
/// * `ctx` - Verification context
/// * `option` - Option constant (e.g., CIE_SIGN_OPT_*)
/// * `value` - String value to set
pub fn verify_set_string(ctx: &Ctx, option: i32, value: &str) -> Result<()> {
    unsafe {
        let c_value = CString::new(value).map_err(|_| Error(1))?;
        let rv = sign_ffi::cie_sign_verify_set_string(ctx.0, option, c_value.as_ptr() as *mut i8);
        long_to_result(rv)
    }
}

/// Clean up memory allocated for the verification operation
///
/// # Arguments
/// * `ctx` - Verification context (consumed)
pub fn verify_cleanup(ctx: Ctx) -> Result<()> {
    unsafe {
        let rv = sign_ffi::cie_sign_verify_cleanup(ctx.0);
        long_to_result(rv)
    }
}

/// Extract the original document from a .p7m envelope
///
/// # Arguments
/// * `ctx` - Context with configured input/output file paths
pub fn get_file_from_p7m(ctx: &Ctx) -> Result<()> {
    unsafe {
        let rv = sign_ffi::cie_sign_get_file_from_p7m(ctx.0);
        long_to_result(rv)
    }
}

/// Set a global integer option
///
/// # Arguments
/// * `option` - Option constant (e.g., CIE_SIGN_OPT_*)
/// * `value` - Integer value to set
pub fn set_int(option: i32, value: i32) -> Result<()> {
    unsafe {
        let rv = sign_ffi::cie_sign_set_int(option, value);
        long_to_result(rv)
    }
}

/// Set a global string option
///
/// # Arguments
/// * `option` - Option constant (e.g., CIE_SIGN_OPT_*)
/// * `value` - String value to set
pub fn set_string(option: i32, value: &str) -> Result<()> {
    unsafe {
        let c_value = CString::new(value).map_err(|_| Error(1))?;
        let rv = sign_ffi::cie_sign_set_string(option, c_value.as_ptr() as *mut i8);
        long_to_result(rv)
    }
}

/// Clean up global library resources
pub fn cleanup() {
    unsafe {
        sign_ffi::cie_sign_cleanup();
    }
}

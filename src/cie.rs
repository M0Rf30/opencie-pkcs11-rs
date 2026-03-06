use crate::cie_ffi;
use crate::pkcs11::{Error, Result};
use std::ffi::CString;
use std::os::raw::c_int;

/// Enable (enrol) a CIE card identified by PAN using the 8-digit PIN.
///
/// Note: Callback support is not yet implemented. This function passes NULL for callbacks.
///
/// # Arguments
/// * `pan` - PAN identifying the card
/// * `pin` - 8-digit numeric PIN
pub fn enable(pan: &str, pin: &str) -> Result<()> {
    unsafe {
        let c_pan = CString::new(pan).map_err(|_| Error(1))?;
        let c_pin = CString::new(pin).map_err(|_| Error(1))?;
        let mut attempts: c_int = 0;

        let rv = cie_ffi::cie_enable(
            c_pan.as_ptr(),
            c_pin.as_ptr(),
            &mut attempts,
            None, // progressCallBack - not yet implemented
            None, // completedCallBack - not yet implemented
        );

        if rv == 0 {
            Ok(())
        } else {
            Err(Error(rv))
        }
    }
}

/// Check whether the card identified by PAN is currently enrolled.
///
/// # Arguments
/// * `pan` - PAN identifying the card
///
/// # Returns
/// `true` if enrolled, `false` if not
pub fn is_enabled(pan: &str) -> bool {
    unsafe {
        let c_pan = CString::new(pan).unwrap_or_default();
        let rv = cie_ffi::cie_is_enabled(c_pan.as_ptr());
        rv == 1
    }
}

/// Remove the enrolment for the card identified by PAN.
///
/// # Arguments
/// * `pan` - PAN identifying the card
pub fn disable(pan: &str) -> Result<()> {
    unsafe {
        let c_pan = CString::new(pan).map_err(|_| Error(1))?;
        let rv = cie_ffi::cie_disable(c_pan.as_ptr());

        if rv == 0 {
            Ok(())
        } else {
            Err(Error(rv))
        }
    }
}

/// Change the PIN from current to new value.
///
/// Note: Callback support is not yet implemented. This function passes NULL for callbacks.
///
/// # Arguments
/// * `current_pin` - Current PIN
/// * `new_pin` - New PIN
pub fn change_pin(current_pin: &str, new_pin: &str) -> Result<()> {
    unsafe {
        let c_current = CString::new(current_pin).map_err(|_| Error(1))?;
        let c_new = CString::new(new_pin).map_err(|_| Error(1))?;
        let mut attempts: c_int = 0;

        let rv = cie_ffi::cie_change_pin(
            c_current.as_ptr(),
            c_new.as_ptr(),
            &mut attempts,
            None, // progressCallBack - not yet implemented
        );

        if rv == 0 {
            Ok(())
        } else {
            Err(Error(rv))
        }
    }
}

/// Unblock the PIN using the PUK and set a new PIN.
///
/// Note: Callback support is not yet implemented. This function passes NULL for callbacks.
///
/// # Arguments
/// * `puk` - PUK string
/// * `new_pin` - New PIN to set
pub fn unblock_pin(puk: &str, new_pin: &str) -> Result<()> {
    unsafe {
        let c_puk = CString::new(puk).map_err(|_| Error(1))?;
        let c_new = CString::new(new_pin).map_err(|_| Error(1))?;
        let mut attempts: c_int = 0;

        let rv = cie_ffi::cie_unblock_pin(
            c_puk.as_ptr(),
            c_new.as_ptr(),
            &mut attempts,
            None, // progressCallBack - not yet implemented
        );

        if rv == 0 {
            Ok(())
        } else {
            Err(Error(rv))
        }
    }
}

/// Sign a PDF file on behalf of the card identified by PAN.
///
/// Note: Callback support is not yet implemented. This function passes NULL for callbacks.
///
/// # Arguments
/// * `in_file` - Path to the input PDF file
/// * `sig_type` - Signature type string (e.g., "PDF", "P7M")
/// * `pin` - Card PIN
/// * `pan` - PAN of the enrolled card
/// * `page` - Page index (0-based) for the signature widget
/// * `x` - X position of the signature widget (points)
/// * `y` - Y position of the signature widget (points)
/// * `w` - Width of the signature widget (points)
/// * `h` - Height of the signature widget (points)
/// * `image_path` - Optional path to a signature image
/// * `out_file` - Path where the signed output file is written
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
    image_path: Option<&str>,
    out_file: &str,
) -> Result<()> {
    unsafe {
        let c_in = CString::new(in_file).map_err(|_| Error(1))?;
        let c_type = CString::new(sig_type).map_err(|_| Error(1))?;
        let c_pin = CString::new(pin).map_err(|_| Error(1))?;
        let c_pan = CString::new(pan).map_err(|_| Error(1))?;
        let c_out = CString::new(out_file).map_err(|_| Error(1))?;

        let c_image = image_path.map(|p| CString::new(p).ok()).flatten();
        let c_image_ptr = c_image
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null());

        let rv = cie_ffi::cie_sign(
            c_in.as_ptr(),
            c_type.as_ptr(),
            c_pin.as_ptr(),
            c_pan.as_ptr(),
            page,
            x,
            y,
            w,
            h,
            c_image_ptr,
            c_out.as_ptr(),
            None, // progressCallBack - not yet implemented
            None, // completedCallBack - not yet implemented
        );

        if rv == 0 {
            Ok(())
        } else {
            Err(Error(rv))
        }
    }
}

/// Verify a signed document.
///
/// # Arguments
/// * `in_file` - Path to the signed input file
/// * `proxy_addr` - Optional HTTP proxy address
/// * `proxy_port` - HTTP proxy port (0 = no proxy)
/// * `usr_pass` - Optional proxy username:password
///
/// # Returns
/// Number of valid signatures found
pub fn verify(
    in_file: &str,
    proxy_addr: Option<&str>,
    proxy_port: i32,
    usr_pass: Option<&str>,
) -> Result<i32> {
    unsafe {
        let c_in = CString::new(in_file).map_err(|_| Error(1))?;

        let c_proxy = proxy_addr.map(|p| CString::new(p).ok()).flatten();
        let c_proxy_ptr = c_proxy
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null());

        let c_usr_pass = usr_pass.map(|p| CString::new(p).ok()).flatten();
        let c_usr_pass_ptr = c_usr_pass
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null());

        let rv = cie_ffi::cie_verify(c_in.as_ptr(), c_proxy_ptr, proxy_port, c_usr_pass_ptr);

        // CK_RV is unsigned, so negative values are large (error codes).
        // Signature counts are expected to be small positive numbers.
        if rv < 0x1000 {
            Ok(rv as i32)
        } else {
            Err(Error(rv))
        }
    }
}

/// Return the number of signatures found by the last verify call.
pub fn get_sign_count() -> Result<i32> {
    unsafe {
        let rv = cie_ffi::cie_get_sign_count();

        // CK_RV is unsigned, so negative values are large (error codes).
        // Signature counts are expected to be small positive numbers.
        if rv < 0x1000 {
            Ok(rv as i32)
        } else {
            Err(Error(rv))
        }
    }
}

/// Extract the original (unwrapped) document from a .p7m envelope.
///
/// # Arguments
/// * `in_file` - Path to the .p7m input file
/// * `out_file` - Path where the plain document is written
pub fn extract_p7m(in_file: &str, out_file: &str) -> Result<()> {
    unsafe {
        let c_in = CString::new(in_file).map_err(|_| Error(1))?;
        let c_out = CString::new(out_file).map_err(|_| Error(1))?;

        let rv = cie_ffi::cie_extract_p7m(c_in.as_ptr(), c_out.as_ptr());

        if rv == 0 {
            Ok(())
        } else {
            Err(Error(rv))
        }
    }
}

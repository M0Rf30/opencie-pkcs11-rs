// SPDX-License-Identifier: MPL-2.0

use crate::ffi;
use std::fmt;

/// PKCS#11 error type wrapping the CK_RV return value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub ffi::CK_RV);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PKCS#11 error: 0x{:08x}", self.0)
    }
}

impl std::error::Error for Error {}

/// Result type for PKCS#11 operations
pub type Result<T> = std::result::Result<T, Error>;

/// Convert CK_RV to Result
fn rv_to_result(rv: ffi::CK_RV) -> Result<()> {
    if rv == 0 {
        Ok(())
    } else {
        Err(Error(rv))
    }
}

/// Initialize the PKCS#11 library
pub fn initialize() -> Result<()> {
    unsafe {
        let rv = ffi::C_Initialize(std::ptr::null_mut());
        rv_to_result(rv)
    }
}

/// Finalize the PKCS#11 library
pub fn finalize() -> Result<()> {
    unsafe {
        let rv = ffi::C_Finalize(std::ptr::null_mut());
        rv_to_result(rv)
    }
}

/// Get the list of available slots
pub fn get_slot_list(token_present: bool) -> Result<Vec<ffi::CK_SLOT_ID>> {
    unsafe {
        let mut count: ffi::CK_ULONG = 0;
        let rv = ffi::C_GetSlotList(
            token_present as ffi::CK_BBOOL,
            std::ptr::null_mut(),
            &mut count,
        );
        rv_to_result(rv)?;

        let mut slots = vec![0; count as usize];
        let rv = ffi::C_GetSlotList(
            token_present as ffi::CK_BBOOL,
            slots.as_mut_ptr(),
            &mut count,
        );
        rv_to_result(rv)?;

        slots.truncate(count as usize);
        Ok(slots)
    }
}

/// Open a session on the specified slot
///
/// `flags` must include `CKF_SERIAL_SESSION`, as required by PKCS#11.
pub fn open_session(
    slot_id: ffi::CK_SLOT_ID,
    flags: ffi::CK_FLAGS,
) -> Result<ffi::CK_SESSION_HANDLE> {
    unsafe {
        let mut session: ffi::CK_SESSION_HANDLE = 0;
        let rv = ffi::C_OpenSession(slot_id, flags, std::ptr::null_mut(), None, &mut session);
        rv_to_result(rv)?;
        Ok(session)
    }
}

/// Close a session
pub fn close_session(session: ffi::CK_SESSION_HANDLE) -> Result<()> {
    unsafe {
        let rv = ffi::C_CloseSession(session);
        rv_to_result(rv)
    }
}

/// Login to a session
pub fn login(
    session: ffi::CK_SESSION_HANDLE,
    user_type: ffi::CK_USER_TYPE,
    pin: &str,
) -> Result<()> {
    unsafe {
        let pin_bytes = pin.as_bytes();
        let rv = ffi::C_Login(
            session,
            user_type,
            pin_bytes.as_ptr() as *mut u8,
            pin_bytes.len() as ffi::CK_ULONG,
        );
        rv_to_result(rv)
    }
}

/// Logout from a session
pub fn logout(session: ffi::CK_SESSION_HANDLE) -> Result<()> {
    unsafe {
        let rv = ffi::C_Logout(session);
        rv_to_result(rv)
    }
}

/// Initialize object search
pub fn find_objects_init(
    session: ffi::CK_SESSION_HANDLE,
    template: &[ffi::CK_ATTRIBUTE],
) -> Result<()> {
    unsafe {
        let rv = ffi::C_FindObjectsInit(
            session,
            template.as_ptr() as *mut ffi::CK_ATTRIBUTE,
            template.len() as ffi::CK_ULONG,
        );
        rv_to_result(rv)
    }
}

/// Find objects matching the template
pub fn find_objects(
    session: ffi::CK_SESSION_HANDLE,
    max_objects: usize,
) -> Result<Vec<ffi::CK_OBJECT_HANDLE>> {
    unsafe {
        let mut objects = vec![0; max_objects];
        let mut count: ffi::CK_ULONG = 0;
        let rv = ffi::C_FindObjects(
            session,
            objects.as_mut_ptr(),
            max_objects as ffi::CK_ULONG,
            &mut count,
        );
        rv_to_result(rv)?;

        objects.truncate(count as usize);
        Ok(objects)
    }
}

/// Finalize object search
pub fn find_objects_final(session: ffi::CK_SESSION_HANDLE) -> Result<()> {
    unsafe {
        let rv = ffi::C_FindObjectsFinal(session);
        rv_to_result(rv)
    }
}

/// Get attribute value of an object
pub fn get_attribute_value(
    session: ffi::CK_SESSION_HANDLE,
    object: ffi::CK_OBJECT_HANDLE,
    template: &mut [ffi::CK_ATTRIBUTE],
) -> Result<()> {
    unsafe {
        let rv = ffi::C_GetAttributeValue(
            session,
            object,
            template.as_mut_ptr(),
            template.len() as ffi::CK_ULONG,
        );
        rv_to_result(rv)
    }
}

/// Initialize signing operation
pub fn sign_init(
    session: ffi::CK_SESSION_HANDLE,
    mechanism: &ffi::CK_MECHANISM,
    key: ffi::CK_OBJECT_HANDLE,
) -> Result<()> {
    unsafe {
        let rv = ffi::C_SignInit(
            session,
            mechanism as *const ffi::CK_MECHANISM as *mut ffi::CK_MECHANISM,
            key,
        );
        rv_to_result(rv)
    }
}

/// Sign data in a single operation
pub fn sign(session: ffi::CK_SESSION_HANDLE, data: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut signature_len: ffi::CK_ULONG = 0;
        let rv = ffi::C_Sign(
            session,
            data.as_ptr() as *mut u8,
            data.len() as ffi::CK_ULONG,
            std::ptr::null_mut(),
            &mut signature_len,
        );
        rv_to_result(rv)?;

        let mut signature = vec![0u8; signature_len as usize];
        let rv = ffi::C_Sign(
            session,
            data.as_ptr() as *mut u8,
            data.len() as ffi::CK_ULONG,
            signature.as_mut_ptr(),
            &mut signature_len,
        );
        rv_to_result(rv)?;

        signature.truncate(signature_len as usize);
        Ok(signature)
    }
}

/// Update signing operation with more data
pub fn sign_update(session: ffi::CK_SESSION_HANDLE, data: &[u8]) -> Result<()> {
    unsafe {
        let rv = ffi::C_SignUpdate(
            session,
            data.as_ptr() as *mut u8,
            data.len() as ffi::CK_ULONG,
        );
        rv_to_result(rv)
    }
}

/// Finalize multi-part signing operation
pub fn sign_final(session: ffi::CK_SESSION_HANDLE) -> Result<Vec<u8>> {
    unsafe {
        let mut signature_len: ffi::CK_ULONG = 0;
        let rv = ffi::C_SignFinal(session, std::ptr::null_mut(), &mut signature_len);
        rv_to_result(rv)?;

        let mut signature = vec![0u8; signature_len as usize];
        let rv = ffi::C_SignFinal(session, signature.as_mut_ptr(), &mut signature_len);
        rv_to_result(rv)?;

        signature.truncate(signature_len as usize);
        Ok(signature)
    }
}

/// Initialize decryption operation
///
/// The CIE is signing-only: `libopencie-pkcs11` answers
/// `CKR_FUNCTION_NOT_SUPPORTED`.
pub fn decrypt_init(
    session: ffi::CK_SESSION_HANDLE,
    mechanism: &ffi::CK_MECHANISM,
    key: ffi::CK_OBJECT_HANDLE,
) -> Result<()> {
    unsafe {
        let rv = ffi::C_DecryptInit(
            session,
            mechanism as *const ffi::CK_MECHANISM as *mut ffi::CK_MECHANISM,
            key,
        );
        rv_to_result(rv)
    }
}

/// Decrypt data in a single operation
///
/// The CIE is signing-only: `libopencie-pkcs11` answers
/// `CKR_FUNCTION_NOT_SUPPORTED`.
pub fn decrypt(session: ffi::CK_SESSION_HANDLE, encrypted_data: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut data_len: ffi::CK_ULONG = 0;
        let rv = ffi::C_Decrypt(
            session,
            encrypted_data.as_ptr() as *mut u8,
            encrypted_data.len() as ffi::CK_ULONG,
            std::ptr::null_mut(),
            &mut data_len,
        );
        rv_to_result(rv)?;

        let mut data = vec![0u8; data_len as usize];
        let rv = ffi::C_Decrypt(
            session,
            encrypted_data.as_ptr() as *mut u8,
            encrypted_data.len() as ffi::CK_ULONG,
            data.as_mut_ptr(),
            &mut data_len,
        );
        rv_to_result(rv)?;

        data.truncate(data_len as usize);
        Ok(data)
    }
}

/// Initialize encryption operation
///
/// The CIE is signing-only: `libopencie-pkcs11` answers
/// `CKR_FUNCTION_NOT_SUPPORTED`.
pub fn encrypt_init(
    session: ffi::CK_SESSION_HANDLE,
    mechanism: &ffi::CK_MECHANISM,
    key: ffi::CK_OBJECT_HANDLE,
) -> Result<()> {
    unsafe {
        let rv = ffi::C_EncryptInit(
            session,
            mechanism as *const ffi::CK_MECHANISM as *mut ffi::CK_MECHANISM,
            key,
        );
        rv_to_result(rv)
    }
}

/// Encrypt data in a single operation
///
/// The CIE is signing-only: `libopencie-pkcs11` answers
/// `CKR_FUNCTION_NOT_SUPPORTED`.
pub fn encrypt(session: ffi::CK_SESSION_HANDLE, data: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut encrypted_len: ffi::CK_ULONG = 0;
        let rv = ffi::C_Encrypt(
            session,
            data.as_ptr() as *mut u8,
            data.len() as ffi::CK_ULONG,
            std::ptr::null_mut(),
            &mut encrypted_len,
        );
        rv_to_result(rv)?;

        let mut encrypted = vec![0u8; encrypted_len as usize];
        let rv = ffi::C_Encrypt(
            session,
            data.as_ptr() as *mut u8,
            data.len() as ffi::CK_ULONG,
            encrypted.as_mut_ptr(),
            &mut encrypted_len,
        );
        rv_to_result(rv)?;

        encrypted.truncate(encrypted_len as usize);
        Ok(encrypted)
    }
}

/// Generate random data
pub fn generate_random(session: ffi::CK_SESSION_HANDLE, length: usize) -> Result<Vec<u8>> {
    unsafe {
        let mut random_data = vec![0u8; length];
        let rv = ffi::C_GenerateRandom(session, random_data.as_mut_ptr(), length as ffi::CK_ULONG);
        rv_to_result(rv)?;
        Ok(random_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rv_to_result_maps_ok_and_errors() {
        assert_eq!(rv_to_result(0), Ok(()));
        assert_eq!(
            rv_to_result(ffi::CKR_PIN_INCORRECT as ffi::CK_RV),
            Err(Error(0xA0))
        );
    }

    #[test]
    fn error_display_is_hex() {
        assert_eq!(Error(0xA0).to_string(), "PKCS#11 error: 0x000000a0");
        assert_eq!(Error(0x8400_0001).to_string(), "PKCS#11 error: 0x84000001");
    }

    #[test]
    fn ck_types_follow_the_c_unsigned_long() {
        // CK_RV / CK_ULONG are C `unsigned long` (32-bit on Windows, 64-bit
        // on LP64): the bindings must follow the C type, not u32/u64.
        assert_eq!(
            std::mem::size_of::<ffi::CK_RV>(),
            std::mem::size_of::<std::os::raw::c_ulong>()
        );
        assert_eq!(
            std::mem::size_of::<ffi::CK_ULONG>(),
            std::mem::size_of::<std::os::raw::c_ulong>()
        );
    }
}

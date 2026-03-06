pub mod ffi {
    #![allow(
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        dead_code,
        clippy::all
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings_pkcs11.rs"));
}

pub mod cie_ffi {
    #![allow(
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        dead_code,
        clippy::all
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings_cie.rs"));
}

pub mod sign_ffi {
    #![allow(
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        dead_code,
        clippy::all
    )]

    use std::os::raw::{c_char, c_int, c_long, c_void};

    // Manual FFI bindings for sign API
    pub type CIE_SIGN_CTX = *mut c_void;

    extern "C" {
        // Global functions
        pub fn cie_sign_set_int(option: c_int, value: c_int) -> c_long;
        pub fn cie_sign_set_string(option: c_int, value: *mut c_char) -> c_long;
        pub fn cie_sign_cleanup();

        // Sign context functions
        pub fn cie_sign_sign_init() -> CIE_SIGN_CTX;
        pub fn cie_sign_sign_set_int(ctx: CIE_SIGN_CTX, option: c_int, value: c_int) -> c_long;
        pub fn cie_sign_sign_set_string(
            ctx: CIE_SIGN_CTX,
            option: c_int,
            value: *mut c_char,
        ) -> c_long;
        pub fn cie_sign_sign_sign(ctx: CIE_SIGN_CTX) -> c_long;
        pub fn cie_sign_sign_cleanup(ctx: CIE_SIGN_CTX) -> c_long;

        // Verify context functions
        pub fn cie_sign_verify_init() -> CIE_SIGN_CTX;
        pub fn cie_sign_verify_set_int(ctx: CIE_SIGN_CTX, option: c_int, value: c_int) -> c_long;
        pub fn cie_sign_verify_set_string(
            ctx: CIE_SIGN_CTX,
            option: c_int,
            value: *mut c_char,
        ) -> c_long;
        pub fn cie_sign_verify_cleanup(ctx: CIE_SIGN_CTX) -> c_long;

        // Utility functions
        pub fn cie_sign_get_file_from_p7m(ctx: CIE_SIGN_CTX) -> c_long;
    }
}

pub mod cie;
pub mod pkcs11;
pub mod sign;

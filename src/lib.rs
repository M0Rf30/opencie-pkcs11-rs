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

pub mod cie;
pub mod pkcs11;

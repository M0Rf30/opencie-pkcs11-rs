// SPDX-License-Identifier: MPL-2.0

use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Allow downstream users to point at a custom checkout of opencie-pkcs11
    // by setting OPENCIE_PKCS11_DIR. The default assumes a sibling clone.
    let base_path = env::var("OPENCIE_PKCS11_DIR").unwrap_or_else(|_| "../opencie-pkcs11".into());
    println!("cargo:rerun-if-env-changed=OPENCIE_PKCS11_DIR");

    let pkcs11_header = format!("{}/shared/src/pkcs11/pkcs11.h", base_path);
    let cie_ext_header = format!("{}/include/opencie/cie_ext.h", base_path);

    let clang_args = vec![
        format!("-I{}/shared/src", base_path),
        format!("-I{}/include", base_path),
        format!("-I{}/shared/src/pkcs11", base_path),
        "-DCK_DECLARE_FUNCTION(returnType, name)=returnType name".to_string(),
        "-DCK_DECLARE_FUNCTION_POINTER(returnType, name)=returnType (*name)".to_string(),
        "-DCK_CALLBACK_FUNCTION(returnType, name)=returnType (*name)".to_string(),
        "-Wno-implicit-int".to_string(),
        "-Wno-error=implicit-function-declaration".to_string(),
    ];

    println!("cargo:rerun-if-changed={}", pkcs11_header);
    bindgen::Builder::default()
        .header(&pkcs11_header)
        .clang_args(&clang_args)
        .allowlist_function("C_.*")
        .allowlist_type("CK_.*")
        .allowlist_var("CK.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate PKCS#11 bindings")
        .write_to_file(out_dir.join("bindings_pkcs11.rs"))
        .expect("Couldn't write PKCS#11 bindings");

    println!("cargo:rerun-if-changed={}", cie_ext_header);

    // These bindings target libopencie-pkcs11 1.3.0 or newer. Fail early with
    // an actionable message when pointed at an older checkout instead of
    // emitting bindings that miss symbols used by the safe wrappers.
    let header_text = std::fs::read_to_string(&cie_ext_header)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", cie_ext_header, e));
    for required in ["cie_read_dgs_can", "CIE_ERR_WRONG_CAN"] {
        assert!(
            header_text.contains(required),
            "{} does not declare `{}`: opencie-pkcs11 bindings require \
             libopencie-pkcs11 1.3.0 or newer (set OPENCIE_PKCS11_DIR to a \
             1.3.0+ checkout)",
            cie_ext_header,
            required
        );
    }
    bindgen::Builder::default()
        .header(&cie_ext_header)
        .clang_args(&clang_args)
        .allowlist_function("cie_.*")
        .allowlist_function("make_digest_info")
        .allowlist_type("cie_.*")
        .allowlist_type("verifyInfo_t")
        .allowlist_var("CIE_.*")
        .allowlist_var("OPENCIE_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate CIE bindings")
        .write_to_file(out_dir.join("bindings_cie.rs"))
        .expect("Couldn't write CIE bindings");

    println!("cargo:rustc-link-lib=opencie-pkcs11");
}

use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let base_path = "../opencie-pkcs11";
    let pkcs11_header = format!("{}/shared/src/pkcs11/pkcs11.h", base_path);
    let cie_ext_header = format!("{}/include/opencie/cie_ext.h", base_path);
    let _sign_api_header = format!("{}/shared/src/sign/cie_sign_api.h", base_path);

    // Common clang arguments for C bindings
    let clang_args_c = vec![
        format!("-I{}/shared/src", base_path),
        format!("-I{}/include", base_path),
        format!("-I{}/shared/src/pkcs11", base_path),
        "-DCK_DECLARE_FUNCTION(returnType, name)=returnType name".to_string(),
        "-DCK_DECLARE_FUNCTION_POINTER(returnType, name)=returnType (*name)".to_string(),
        "-DCK_CALLBACK_FUNCTION(returnType, name)=returnType (*name)".to_string(),
        "-Wno-implicit-int".to_string(),
        "-Wno-error=implicit-function-declaration".to_string(),
    ];

    // Common clang arguments for C++ bindings (currently unused but kept for future bindgen use)
    let _clang_args_cpp = vec![
        format!("-I{}/shared/src", base_path),
        format!("-I{}/include", base_path),
        format!("-I{}/shared/src/pkcs11", base_path),
        format!("-I{}/sign-sdk/include", base_path),
        "-DCK_DECLARE_FUNCTION(returnType, name)=returnType name".to_string(),
        "-DCK_DECLARE_FUNCTION_POINTER(returnType, name)=returnType (*name)".to_string(),
        "-DCK_CALLBACK_FUNCTION(returnType, name)=returnType (*name)".to_string(),
        "-Wno-implicit-int".to_string(),
        "-Wno-error=implicit-function-declaration".to_string(),
        "-xc++".to_string(),
        "-std=c++17".to_string(),
    ];

    // Generate PKCS#11 bindings
    println!("cargo:rerun-if-changed={}", pkcs11_header);
    let bindings_pkcs11 = bindgen::Builder::default()
        .header(pkcs11_header)
        .clang_args(&clang_args_c)
        .allowlist_function("C_.*")
        .allowlist_type("CK_.*")
        .allowlist_var("CK.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate PKCS#11 bindings");

    bindings_pkcs11
        .write_to_file(out_dir.join("bindings_pkcs11.rs"))
        .expect("Couldn't write PKCS#11 bindings");

    // Generate CIE extension bindings
    println!("cargo:rerun-if-changed={}", cie_ext_header);
    let bindings_cie = bindgen::Builder::default()
        .header(cie_ext_header)
        .clang_args(&clang_args_c)
        .allowlist_function("cie_.*")
        .allowlist_type("cie_.*")
        .allowlist_var("CIE_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate CIE bindings");

    bindings_cie
        .write_to_file(out_dir.join("bindings_cie.rs"))
        .expect("Couldn't write CIE bindings");

    // Skip Sign API bindings for now due to PCSC header issues
    // TODO: Fix PCSC header paths and re-enable
    /*
    // Generate Sign API bindings
    println!("cargo:rerun-if-changed={}", sign_api_header);
    let bindings_sign = bindgen::Builder::default()
        .header(sign_api_header)
        .clang_args(&clang_args_c)  // Try C args first instead of C++
        .allowlist_function("cie_sign_.*")
        .allowlist_type("CIE_SIGN_.*")
        .allowlist_var("CIE_SIGN_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate Sign API bindings");

    bindings_sign
        .write_to_file(out_dir.join("bindings_sign.rs"))
        .expect("Couldn't write Sign API bindings");
    */

    // Link the library
    println!("cargo:rustc-link-lib=opencie-pkcs11");
}

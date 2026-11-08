use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=aidl");
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_file = PathBuf::from(&out_dir).join("fingerprint_aidl.rs");

    rsbinder_aidl::Builder::new()
        .source(&PathBuf::from("aidl"))
        .output(&out_file)
        .generate()
        .expect("failed to generate fingerprint AIDL bindings");

    let generated = fs::read_to_string(&out_file).expect("failed to read generated bindings");
    let patched = generated
        .lines()
        .map(|line| {
            if line.contains("const r#getInterfaceVersion:") {
                "                        pub(crate) const r#getInterfaceVersion: rsbinder::TransactionCode = 16777215;".to_string()
            } else if line.contains("const r#getInterfaceHash:") {
                "                        pub(crate) const r#getInterfaceHash: rsbinder::TransactionCode = 16777214;".to_string()
            } else if line.contains("#![allow(non_upper_case_globals, non_snake_case, dead_code)]") {
                line.replace("dead_code", "dead_code, non_camel_case_types")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let ifp_needle = "let _aidl_return = _service.r#createSession(_arg_sensorId, _arg_userId, &_arg_cb);
                                match &_aidl_return {
                                    Ok(_aidl_return) => {
                                        _reply.write(&rsbinder::Status::from(rsbinder::StatusCode::Ok))?;
                                        _reply.write(_aidl_return)?;
                                    }
                                    Err(_aidl_status) => {
                                        _reply.write(_aidl_status)?;
                                    }
                                }
                                Ok(())
                            }
                            _ => Err(rsbinder::StatusCode::UnknownTransaction),";

    let ifp_replacement = "let _aidl_return = _service.r#createSession(_arg_sensorId, _arg_userId, &_arg_cb);
                                match &_aidl_return {
                                    Ok(_aidl_return) => {
                                        _reply.write(&rsbinder::Status::from(rsbinder::StatusCode::Ok))?;
                                        _reply.write(_aidl_return)?;
                                    }
                                    Err(_aidl_status) => {
                                        _reply.write(_aidl_status)?;
                                    }
                                }
                                Ok(())
                            }
                            1019 => {
                                crate::service::handle_oplus_custom_transact(_reader, _reply)
                            }
                            _ => Err(rsbinder::StatusCode::UnknownTransaction),";

    let isess_needle = "let _aidl_return = _service.r#setIgnoreDisplayTouches(_arg_shouldIgnore);
                                match &_aidl_return {
                                    Ok(_aidl_return) => {
                                        _reply.write(&rsbinder::Status::from(rsbinder::StatusCode::Ok))?;
                                    }
                                    Err(_aidl_status) => {
                                        _reply.write(_aidl_status)?;
                                    }
                                }
                                Ok(())
                            }
                            _ => Err(rsbinder::StatusCode::UnknownTransaction),";

    let isess_replacement = "let _aidl_return = _service.r#setIgnoreDisplayTouches(_arg_shouldIgnore);
                                match &_aidl_return {
                                    Ok(_aidl_return) => {
                                        _reply.write(&rsbinder::Status::from(rsbinder::StatusCode::Ok))?;
                                    }
                                    Err(_aidl_status) => {
                                        _reply.write(_aidl_status)?;
                                    }
                                }
                                Ok(())
                            }
                            1019 => {
                                crate::service::handle_oplus_custom_transact(_reader, _reply)
                            }
                            _ => Err(rsbinder::StatusCode::UnknownTransaction),";

    let mut patched = patched;
    if patched.contains(ifp_needle) {
        patched = patched.replace(ifp_needle, ifp_replacement);
    } else {
        panic!("Failed to find IFingerprint createSession hook point in generated bindings");
    }

    if patched.contains(isess_needle) {
        patched = patched.replace(isess_needle, isess_replacement);
    }

    fs::write(&out_file, patched).expect("failed to write patched bindings");
}

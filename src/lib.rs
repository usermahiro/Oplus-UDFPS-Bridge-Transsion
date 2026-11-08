#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/fingerprint_aidl.rs"));

pub mod hal;
pub mod hbm;
pub mod input;
pub mod log;
pub mod service;

pub const SERVICE_NAME: &str = "android.hardware.biometrics.fingerprint.IFingerprint/default";
pub const INTERFACE_HASH: &str = "637371b53fb7faf9bd43aa51b72c23852d6e6d96";
pub const INTERFACE_VERSION: i32 = 3;
pub const COMMON_INTERFACE_HASH: &str = "a9ebb97f5abea1dc6800b69d821ef61944e80e65";
pub const COMMON_INTERFACE_VERSION: i32 = 3;

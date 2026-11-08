#[cfg(target_os = "android")]
extern "C" {
    fn __android_log_print(prio: libc::c_int, tag: *const libc::c_char, fmt: *const libc::c_char, ...) -> libc::c_int;
}

#[allow(unused_variables)]
pub fn android_log(prio: libc::c_int, msg: &str) {
    #[cfg(target_os = "android")]
    {
        let tag = std::ffi::CStr::from_bytes_with_nul(b"oplus_udfps_transsion\0").unwrap();
        let fmt = std::ffi::CStr::from_bytes_with_nul(b"%s\0").unwrap();
        if let Ok(c_msg) = std::ffi::CString::new(msg) {
            unsafe {
                __android_log_print(prio, tag.as_ptr(), fmt.as_ptr(), c_msg.as_ptr());
            }
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        eprintln!("[oplus_udfps_transsion] {}", msg);
    }
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::log::android_log(4, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::log::android_log(5, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::log::android_log(6, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::log::android_log(3, &format!($($arg)*))
    };
}

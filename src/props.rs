//! Props the ColorOS UI needs to draw an under-display fingerprint icon.
//!
//! The optical geometry props and `persist.vendor.fingerprint.sensor_type` are
//! not shipped in any prop file of the ported ROMs. The stock HAL set them once,
//! so their values lived in `/data/property`. A format data wipes that
//! directory, nothing puts them back, and SystemUI falls back to the rear
//! fingerprint layout, while this HAL and the sensor keep working because the
//! touch target here is a compile-time constant.
//!
//! Setting them from the HAL removes both the prop file and the manual
//! `setprop` from the install: the values are rewritten before SystemUI starts,
//! and again whenever anything changes them.

use crate::{log_info, log_warn};
use std::ffi::CString;
use std::time::Duration;

#[cfg(target_os = "android")]
extern "C" {
    fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> libc::c_int;
    fn __system_property_set(name: *const libc::c_char, value: *const libc::c_char) -> libc::c_int;
}

#[cfg(not(target_os = "android"))]
unsafe fn __system_property_get(_name: *const libc::c_char, _value: *mut libc::c_char) -> libc::c_int {
    0
}

#[cfg(not(target_os = "android"))]
unsafe fn __system_property_set(_name: *const libc::c_char, _value: *const libc::c_char) -> libc::c_int {
    0
}

/// Rewritten every time they drift. SystemUI picks the optical layout from
/// `sensor_type`; a rear/side value or an empty one is what produces the
/// "backfp" icon on a working sensor.
const ENFORCED: &[(&str, &str)] = &[
    ("persist.vendor.fingerprint.sensor_type", "optical"),
    ("vendor.fingerprint.aidl.support", "1"),
];

/// Written only when the ROM left them empty. These describe the panel, so an
/// existing value is the device's own and is left alone: forcing 540::2172 onto
/// a panel that is not 1080x2436 would move the icon off the sensor.
const DEFAULTS: &[(&str, &str)] = &[
    ("persist.vendor.fingerprint.optical.iconsize", "200"),
    ("persist.vendor.fingerprint.optical.iconlocation", "228"),
    ("persist.vendor.fingerprint.optical.sensorlocation", "540::2172"),
    ("persist.vendor.fingerprint.optical.iconnumber", "5"),
];

/// A property set from here is a normal write: root can still change it. The
/// guard only means a change does not last.
const GUARD_INTERVAL: Duration = Duration::from_secs(5);

pub fn get(key: &str) -> String {
    let Ok(c_key) = CString::new(key) else {
        return String::new();
    };
    let mut value = [0u8; 92];
    let len = unsafe {
        __system_property_get(
            c_key.as_ptr(),
            value.as_mut_ptr() as *mut libc::c_char,
        )
    };
    if len <= 0 {
        return String::new();
    }
    let len = (len as usize).min(value.len() - 1);
    String::from_utf8_lossy(&value[..len]).into_owned()
}

fn set(key: &str, value: &str) -> bool {
    let (Ok(c_key), Ok(c_value)) = (CString::new(key), CString::new(value)) else {
        return false;
    };
    unsafe { __system_property_set(c_key.as_ptr(), c_value.as_ptr()) == 0 }
}

/// One pass: enforce the two the UI cannot work without, then fill the geometry
/// the ROM forgot. Logs only what it actually changes, so a guard pass on a
/// healthy device is silent.
pub fn enforce() {
    for (key, want) in ENFORCED {
        if get(key) == *want {
            continue;
        }
        if set(key, want) {
            log_info!("props: {} = {}", key, want);
        } else {
            log_warn!("props: cannot write {} = {} (SELinux?)", key, want);
        }
    }

    for (key, want) in DEFAULTS {
        if !get(key).is_empty() {
            continue;
        }
        if set(key, want) {
            log_info!("props: {} empty, set to {}", key, want);
        } else {
            log_warn!("props: cannot fill {} = {} (SELinux?)", key, want);
        }
    }
}

/// Re-applies in the background. `persist.*` values only matter until the next
/// format, but the process runs for days: an override from a settings app or a
/// late boot script should not leave the device on the rear layout.
pub fn spawn_guard() {
    std::thread::spawn(|| loop {
        std::thread::sleep(GUARD_INTERVAL);
        enforce();
    });
}

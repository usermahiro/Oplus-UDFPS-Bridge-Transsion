#![allow(non_snake_case)]

use oplus_udfps_bridge_transsion::android::hardware::biometrics::fingerprint::IFingerprint::BnFingerprint;
use oplus_udfps_bridge_transsion::service::FingerprintService;
use oplus_udfps_bridge_transsion::{log_error, log_info};
use oplus_udfps_bridge_transsion::SERVICE_NAME;

#[cfg(target_os = "android")]
extern "C" {
    fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> libc::c_int;
}

#[cfg(not(target_os = "android"))]
unsafe fn __system_property_get(_name: *const libc::c_char, _value: *mut libc::c_char) -> libc::c_int {
    0
}

fn get_system_prop(key: &[u8], default: &str) -> String {
    let mut val = [0u8; 92];
    let len = unsafe {
        __system_property_get(key.as_ptr() as *const libc::c_char, val.as_mut_ptr() as *mut libc::c_char)
    };
    if len > 0 {
        String::from_utf8_lossy(&val[..len as usize]).into_owned()
    } else {
        default.to_string()
    }
}

fn main() -> anyhow::Result<()> {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    // The props ColorOS needs to treat this as an under-display sensor, before
    // SystemUI reads them. They are the reason this source no longer needs a
    // prop file: the values live in /data/property, a format data wipes them,
    // and nothing in the ported ROM puts them back.
    oplus_udfps_bridge_transsion::props::enforce();
    oplus_udfps_bridge_transsion::props::spawn_guard();

    // Ensure gesture FOD is enabled in kernel driver
    oplus_udfps_bridge_transsion::input::ensure_gesture_fod_enabled();

    let brand = get_system_prop(b"ro.product.brand\0", "Transsion");
    let model = get_system_prop(b"ro.product.model\0", "Device");
    let platform = get_system_prop(b"ro.board.platform\0", "Universal");

    log_info!(
        "Starting android.hardware.biometrics.fingerprint-service for Transsion ({} {}, SoC: {})...",
        brand, model, platform
    );

    // Initialize Binder process state FIRST
    rsbinder::ProcessState::init_default().map_err(|error| {
        anyhow::anyhow!("failed to initialize Binder process state: {error}")
    })?;
    rsbinder::ProcessState::start_thread_pool();

    // Register AIDL fingerprint service IMMEDIATELY so ServiceManager & system_server never wait/deadlock
    let service = FingerprintService::new();
    let binder = BnFingerprint::new_binder(service);
    rsbinder::hub::add_service(SERVICE_NAME, binder.as_binder())?;

    log_info!(
        "Successfully registered {} with ServiceManager! Waiting for transactions...",
        SERVICE_NAME
    );

    // Asynchronously initialize FingerprintHal, touch listeners and HBM controller in background
    std::thread::spawn(|| {
        log_info!("Initializing FingerprintHal and background listeners...");
        match oplus_udfps_bridge_transsion::hal::FingerprintHal::get_instance() {
            Ok(_) => log_info!("FingerprintHal successfully initialized in background!"),
            Err(e) => log_error!("Failed to initialize FingerprintHal in background: {e}"),
        }
    });

    rsbinder::ProcessState::join_thread_pool()?;
    Ok(())
}

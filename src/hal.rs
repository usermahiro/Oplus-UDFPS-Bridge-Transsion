#![allow(non_camel_case_types)]

use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use parking_lot::Mutex;
use rsbinder::Strong;

use crate::android::hardware::biometrics::fingerprint::AcquiredInfo::AcquiredInfo;
use crate::android::hardware::biometrics::fingerprint::Error::Error;
use crate::android::hardware::biometrics::fingerprint::ISessionCallback::ISessionCallback;
use crate::android::hardware::keymaster::HardwareAuthToken::HardwareAuthToken;
use crate::android::hardware::keymaster::Timestamp::Timestamp;
use crate::{log_debug, log_info, log_warn};

/// Jeda setelah sample enroll sebelum capture berikutnya (biar animasi progress sempat jalan)
const HOLD_ENROLL_REARM_MS: u64 = 450;
/// Jeda sebelum retry auth saat jari masih menempel
const HOLD_AUTH_REARM_MS: u64 = 350;
/// Maks retry auth otomatis per sentuhan (Android lockout setelah 5 gagal)
const HOLD_AUTH_REARM_MAX: u32 = 3;
/// Lama "jari terangkat" palsu antara HBM off dan on
const HOLD_FAKE_UP_MS: u64 = 80;

pub const HARDWARE_MODULE_TAG: u32 = 0x48574D54; // 'HWMT'

// Legacy Fingerprint Message Types (hardware/fingerprint.h)
pub const FINGERPRINT_ERROR: i32 = -1;
pub const FINGERPRINT_ACQUIRED: i32 = 1;
pub const FINGERPRINT_TEMPLATE_ENROLLING: i32 = 3;
pub const FINGERPRINT_TEMPLATE_REMOVED: i32 = 4;
pub const FINGERPRINT_AUTHENTICATED: i32 = 5;
pub const FINGERPRINT_TEMPLATE_ENUMERATING: i32 = 6;

// Legacy Fingerprint Error Codes
pub const FINGERPRINT_ERROR_HW_UNAVAILABLE: i32 = 1;
pub const FINGERPRINT_ERROR_UNABLE_TO_PROCESS: i32 = 2;
pub const FINGERPRINT_ERROR_TIMEOUT: i32 = 3;
pub const FINGERPRINT_ERROR_NO_SPACE: i32 = 4;
pub const FINGERPRINT_ERROR_CANCELED: i32 = 5;
pub const FINGERPRINT_ERROR_UNABLE_TO_REMOVE: i32 = 6;
pub const FINGERPRINT_ERROR_LOCKOUT: i32 = 7;

// Legacy Fingerprint Acquired Info Codes
pub const FINGERPRINT_ACQUIRED_GOOD: i32 = 0;
pub const FINGERPRINT_ACQUIRED_PARTIAL: i32 = 1;
pub const FINGERPRINT_ACQUIRED_INSUFFICIENT: i32 = 2;
pub const FINGERPRINT_ACQUIRED_IMAGER_DIRTY: i32 = 3;
pub const FINGERPRINT_ACQUIRED_TOO_SLOW: i32 = 4;
pub const FINGERPRINT_ACQUIRED_TOO_FAST: i32 = 5;
pub const FINGERPRINT_ACQUIRED_VENDOR: i32 = 6;

#[repr(C)]
pub struct hw_module_t {
    pub tag: u32,
    pub module_api_version: u16,
    pub hal_api_version: u16,
    pub id: *const libc::c_char,
    pub name: *const libc::c_char,
    pub author: *const libc::c_char,
    pub methods: *const hw_module_methods_t,
    pub dso: *mut libc::c_void,
    pub reserved: [u64; 32],
}

#[repr(C)]
pub struct hw_module_methods_t {
    pub open: Option<
        unsafe extern "C" fn(
            module: *const hw_module_t,
            id: *const libc::c_char,
            device: *mut *mut hw_device_t,
        ) -> libc::c_int,
    >,
}

#[repr(C)]
pub struct hw_device_t {
    pub tag: u32,
    pub version: u32,
    pub module: *const hw_module_t,
    pub reserved: [u64; 12],
    pub close: Option<unsafe extern "C" fn(device: *mut hw_device_t) -> libc::c_int>,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct hw_auth_token_t {
    pub version: u8,
    pub challenge: u64,
    pub user_id: u64,
    pub authenticator_id: u64,
    pub authenticator_type: u32,
    pub timestamp: u64,
    pub hmac: [u8; 32],
}

impl hw_auth_token_t {
    pub fn from_aidl(hat: &HardwareAuthToken) -> Self {
        let mut raw = Self::default();
        raw.version = 0;
        raw.challenge = hat.challenge as u64;
        raw.user_id = hat.userId as u64;
        raw.authenticator_id = hat.authenticatorId as u64;
        raw.authenticator_type = (hat.authenticatorType as u32).to_be();
        raw.timestamp = (hat.timestamp.milliSeconds as u64).to_be();
        let len = hat.mac.len().min(32);
        raw.hmac[..len].copy_from_slice(&hat.mac[..len]);
        raw
    }

    pub fn to_aidl(&self) -> HardwareAuthToken {
        HardwareAuthToken {
            challenge: self.challenge as i64,
            userId: self.user_id as i64,
            authenticatorId: self.authenticator_id as i64,
            authenticatorType: u32::from_be(self.authenticator_type) as i32,
            timestamp: Timestamp {
                milliSeconds: u64::from_be(self.timestamp) as i64,
            },
            mac: self.hmac.to_vec(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct fingerprint_finger_id_t {
    pub gid: u32,
    pub fid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct fingerprint_enroll_t {
    pub finger: fingerprint_finger_id_t,
    pub samples_remaining: u32,
    pub msg: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct fingerprint_removed_t {
    pub finger: fingerprint_finger_id_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct fingerprint_acquired_t {
    pub acquired_info: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct fingerprint_authenticated_t {
    pub finger: fingerprint_finger_id_t,
    pub hat: hw_auth_token_t,
}

#[repr(C, align(8))]
pub struct fingerprint_msg_t {
    pub r#type: i32,
    pub _pad: u32,
    pub data: [u8; 96],
}

const _: () = {
    assert!(std::mem::offset_of!(fingerprint_msg_t, data) == 8);
    assert!(std::mem::size_of::<fingerprint_msg_t>() == 104);
};

pub type fingerprint_notify_t = unsafe extern "C" fn(msg: *const fingerprint_msg_t);

#[repr(C)]
pub struct fingerprint_device_t {
    pub common: hw_device_t,
    pub notify: Option<fingerprint_notify_t>,
    pub set_notify: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, notify: fingerprint_notify_t) -> libc::c_int>,
    pub pre_enroll: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> u64>,
    pub enroll: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, hat: *const hw_auth_token_t, gid: u32, timeout_sec: u32) -> libc::c_int>,
    pub post_enroll: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> libc::c_int>,
    pub get_authenticator_id: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> u64>,
    pub cancel: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> libc::c_int>,
    pub enumerate: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> libc::c_int>,
    pub remove: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, gid: u32, fid: u32) -> libc::c_int>,
    pub set_active_group: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, gid: u32, store_path: *const libc::c_char) -> libc::c_int>,
    pub authenticate: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, operation_id: u64, gid: u32) -> libc::c_int>,
    pub reserved: [usize; 4],
}

const _: () = {
    assert!(std::mem::offset_of!(fingerprint_device_t, notify) == 0x78);
    assert!(std::mem::offset_of!(fingerprint_device_t, set_notify) == 0x80);
    assert!(std::mem::offset_of!(fingerprint_device_t, pre_enroll) == 0x88);
    assert!(std::mem::offset_of!(fingerprint_device_t, enroll) == 0x90);
    assert!(std::mem::offset_of!(fingerprint_device_t, post_enroll) == 0x98);
    assert!(std::mem::offset_of!(fingerprint_device_t, get_authenticator_id) == 0xa0);
    assert!(std::mem::offset_of!(fingerprint_device_t, cancel) == 0xa8);
    assert!(std::mem::offset_of!(fingerprint_device_t, enumerate) == 0xb0);
    assert!(std::mem::offset_of!(fingerprint_device_t, remove) == 0xb8);
    assert!(std::mem::offset_of!(fingerprint_device_t, set_active_group) == 0xc0);
    assert!(std::mem::offset_of!(fingerprint_device_t, authenticate) == 0xc8);
    assert!(std::mem::offset_of!(fingerprint_device_t, reserved) == 0xd0);
    assert!(std::mem::size_of::<fingerprint_device_t>() == 0xf0);
};

#[repr(C)]
pub struct goodix_fingerprint_device_t {
    pub common: hw_device_t,
    pub notify: Option<fingerprint_notify_t>,
    pub set_notify: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, notify: fingerprint_notify_t) -> libc::c_int>,
    pub pre_enroll: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> u64>,
    pub post_enroll: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, challenge: u64) -> libc::c_int>,
    pub enroll: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, hat: *const hw_auth_token_t, gid: u32, timeout_sec: u32) -> libc::c_int>,
    pub get_authenticator_id: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> u64>,
    pub invalidate_authenticator_id: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> u64>,
    pub cancel: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> libc::c_int>,
    pub enumerate: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> libc::c_int>,
    pub remove: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, fids: *const u32, count: u32) -> libc::c_int>,
    pub set_active_group: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, gid: u32, store_path: *const libc::c_char) -> libc::c_int>,
    pub authenticate: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, operation_id: u64, gid: u32) -> libc::c_int>,
    pub vendor_event_2: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> libc::c_int>,
    pub vendor_event_4: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t) -> libc::c_int>,
    pub reserved: [usize; 5],
    pub send_custom_cmd: Option<unsafe extern "C" fn(dev: *mut fingerprint_device_t, cmd: u32, arg: u32) -> libc::c_int>,
    pub reserved2: [usize; 3],
}

const _: () = {
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, notify) == 0x78);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, set_notify) == 0x80);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, pre_enroll) == 0x88);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, post_enroll) == 0x90);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, enroll) == 0x98);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, get_authenticator_id) == 0xa0);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, invalidate_authenticator_id) == 0xa8);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, cancel) == 0xb0);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, enumerate) == 0xb8);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, remove) == 0xc0);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, set_active_group) == 0xc8);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, authenticate) == 0xd0);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, vendor_event_2) == 0xd8);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, vendor_event_4) == 0xe0);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, reserved) == 0xe8);
    assert!(std::mem::offset_of!(goodix_fingerprint_device_t, send_custom_cmd) == 0x110);
    assert!(std::mem::size_of::<goodix_fingerprint_device_t>() == 0x130);
};

type FnSileadCustCmd = unsafe extern "C" fn(cmd: u32, arg: u32) -> libc::c_int;
type FnGoodixCustCmd = unsafe extern "C" fn(dev: *mut fingerprint_device_t, cmd: u32, arg: u32) -> libc::c_int;
type FnSilfpCustInit = unsafe extern "C" fn() -> libc::c_int;
type FnSilfpSyncOptic = unsafe extern "C" fn(status: i32) -> libc::c_int;
type FnSilfpSyncFinger = unsafe extern "C" fn() -> libc::c_int;
type FnSilfpMsgSend = unsafe extern "C" fn(msg: i32) -> libc::c_int;
type FnSilfpWorkerScreenState = unsafe extern "C" fn(state: libc::c_int) -> libc::c_int;

pub struct FingerprintHal {
    device: *mut fingerprint_device_t,
    is_goodix: bool,
    current_callback: Arc<Mutex<Option<Strong<dyn ISessionCallback>>>>,
    is_active: AtomicBool,
    is_finger_down: AtomicBool,
    current_user_id: std::sync::atomic::AtomicI32,
    enumerated_ids: Mutex<Vec<i32>>,
    enum_completed: Arc<AtomicBool>,
    remove_pending: Arc<AtomicBool>,
    fn_silead_cmd: Option<FnSileadCustCmd>,
    fn_goodix_cmd: Option<FnGoodixCustCmd>,
    #[allow(dead_code)]
    fn_silfp_cust_init: Option<FnSilfpCustInit>,
    fn_silfp_sync_optic: Option<FnSilfpSyncOptic>,
    fn_silfp_sync_down: Option<FnSilfpSyncFinger>,
    fn_silfp_sync_up: Option<FnSilfpSyncFinger>,
    fn_silfp_msg_send: Option<FnSilfpMsgSend>,
    fn_silfp_worker_screen_state: Option<FnSilfpWorkerScreenState>,
    saved_enroll_fid: AtomicI32,
    step_captured: AtomicBool,
    /// Jari fisik masih menempel di sensor (di-set pointer_down, di-clear pointer_up/cancel)
    finger_held: AtomicBool,
    /// Generasi rearm; dinaikkan tiap pointer_up/cancel supaya rearm yang tertunda batal
    rearm_gen: AtomicU32,
    /// Jumlah rearm auth berturut-turut dalam satu sentuhan (batasi biar tidak lockout)
    auth_rearm_count: AtomicU32,
    pub screen_state: AtomicI32,
}

unsafe impl Send for FingerprintHal {}
unsafe impl Sync for FingerprintHal {}

static GLOBAL_HAL: OnceLock<Arc<FingerprintHal>> = OnceLock::new();
static INIT_MUTEX: Mutex<()> = Mutex::new(());

unsafe extern "C" fn hal_notify_trampoline(msg: *const fingerprint_msg_t) {
    if msg.is_null() {
        return;
    }
    let msg_ref = &*msg;
    if let Some(hal) = GLOBAL_HAL.get() {
        hal.on_notify(msg_ref);
    }
}

impl FingerprintHal {
    pub fn get_instance() -> anyhow::Result<Arc<FingerprintHal>> {
        if let Some(instance) = GLOBAL_HAL.get() {
            return Ok(instance.clone());
        }

        let _guard = INIT_MUTEX.lock();
        if let Some(instance) = GLOBAL_HAL.get() {
            return Ok(instance.clone());
        }

        let mut last_err = String::from("unknown");
        for attempt in 1..=20 {
            match Self::open() {
                Ok(h) => {
                    log_info!("FingerprintHal initialized successfully on attempt {}", attempt);
                    return Ok(h);
                }
                Err(e) => {
                    last_err = e.to_string();
                    log_warn!(
                        "FingerprintHal::open attempt {}/20 failed: {last_err} (retrying in 500ms...)",
                        attempt
                    );
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
        anyhow::bail!("FingerprintHal failed to initialize after 20 attempts: {last_err}")
    }

    fn open() -> anyhow::Result<Arc<Self>> {
        // Goodix devices commonly split the wrapper and implementation:
        // libgf_hal.so is the implementation, while gf_fingerprint.default.so
        // exports the legacy fingerprint HAL module. Preload the implementation
        // globally so its symbols and dependencies resolve from /odm.
        let goodix_impl_paths = [
            "/odm/lib64/libgf_hal.so",
            "/vendor/lib64/libgf_hal.so",
        ];
        let mut goodix_impl_handle: *mut libc::c_void = std::ptr::null_mut();
        for path in goodix_impl_paths {
            let c_path = CString::new(path).unwrap();
            goodix_impl_handle = unsafe {
                libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL)
            };
            if !goodix_impl_handle.is_null() {
                log_info!("Preloaded Goodix implementation from {}", path);
                break;
            }
        }

        let candidate_libs = [
            "/odm/lib64/hw/gf_fingerprint.default.so",
            "/vendor/lib64/hw/gf_fingerprint.default.so",
            "/odm/lib64/hw/fingerprint.default.so",
            "/system/lib64/hw/fingerprint.default.so",
        ];

        let mut handle: *mut libc::c_void = std::ptr::null_mut();
        let mut loaded_path = "";

        for path in candidate_libs {
            let c_path = CString::new(path).unwrap();
            handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW) };
            if !handle.is_null() {
                loaded_path = path;
                log_info!("Successfully loaded fingerprint HAL library from {}", path);
                break;
            }
        }

        if handle.is_null() {
            let err = unsafe {
                let err_ptr = libc::dlerror();
                if !err_ptr.is_null() {
                    CStr::from_ptr(err_ptr).to_string_lossy().into_owned()
                } else {
                    "unknown dlopen error".to_string()
                }
            };
            anyhow::bail!("failed to dlopen fingerprint HAL: {err}");
        }

        let hmi_sym = CString::new("HMI").unwrap();
        let hmi_ptr = unsafe { libc::dlsym(handle, hmi_sym.as_ptr()) as *const hw_module_t };
        if hmi_ptr.is_null() {
            anyhow::bail!("failed to find symbol 'HMI' in {loaded_path}");
        }

        let module = unsafe { &*hmi_ptr };
        if module.tag != HARDWARE_MODULE_TAG {
            anyhow::bail!(
                "invalid module tag: 0x{:x} (expected 0x{:x})",
                module.tag,
                HARDWARE_MODULE_TAG
            );
        }

        let methods = unsafe { module.methods.as_ref() }
            .ok_or_else(|| anyhow::anyhow!("module methods pointer is null"))?;

        let open_fn = methods.open.ok_or_else(|| anyhow::anyhow!("open function pointer is null"))?;

        let mut dev_ptr: *mut hw_device_t = std::ptr::null_mut();
        let id_fp = CString::new("fingerprint").unwrap();
        let ret = unsafe { open_fn(hmi_ptr, id_fp.as_ptr(), &mut dev_ptr) };
        if ret != 0 || dev_ptr.is_null() {
            anyhow::bail!("failed to open fingerprint device: ret = {ret}");
        }

        let fp_dev = dev_ptr as *mut fingerprint_device_t;
        let fp_ref = unsafe { &mut *fp_dev };
        let is_goodix = loaded_path.contains("gf_fingerprint")
            || loaded_path == "/odm/lib64/libgf_hal.so"
            || !goodix_impl_handle.is_null();

        log_info!(
            "Fingerprint HAL device opened successfully (tag=0x{:x}, ver=0x{:x})",
            fp_ref.common.tag,
            fp_ref.common.version
        );

        // 1. Check for Silead custom command: silfp_finger_cust_cmd(cmd, arg)
        let silead_sym = CString::new("silfp_finger_cust_cmd").unwrap();
        let mut fn_silead_cmd: Option<FnSileadCustCmd> = unsafe {
            let sym = libc::dlsym(handle, silead_sym.as_ptr());
            if !sym.is_null() {
                log_info!("Found Silead custom command symbol 'silfp_finger_cust_cmd'");
                Some(std::mem::transmute(sym))
            } else {
                None
            }
        };

        // 2. Check for Goodix custom command: fingerprint_command(dev, cmd, arg)
        let goodix_sym = CString::new("_Z19fingerprint_commandP18fingerprint_devicejj").unwrap();
        let mut fn_goodix_cmd: Option<FnGoodixCustCmd> = unsafe {
            let sym = libc::dlsym(handle, goodix_sym.as_ptr());
            if !sym.is_null() {
                log_info!("Found Goodix custom command symbol 'fingerprint_command'");
                Some(std::mem::transmute(sym))
            } else {
                None
            }
        };

        if fn_goodix_cmd.is_none() && is_goodix {
            let g = unsafe { &*(dev_ptr as *const goodix_fingerprint_device_t) };
            if let Some(cmd_fn) = g.send_custom_cmd {
                log_info!("Using Goodix device-struct send_custom_cmd at offset 0x110");
                fn_goodix_cmd = Some(cmd_fn);
            }
        }

        // 3. Resolve Silead optical worker symbols from handle or libsl_fp_impl.so
        let sl_impl_path = CString::new("/vendor/lib64/libsl_fp_impl.so").unwrap();
        let sl_impl_handle = unsafe { libc::dlopen(sl_impl_path.as_ptr(), libc::RTLD_NOW) };
        if !sl_impl_handle.is_null() {
            log_info!("dlopen(/vendor/lib64/libsl_fp_impl.so) succeeded");
        } else {
            log_warn!("dlopen(/vendor/lib64/libsl_fp_impl.so) returned null, using handle only");
        }

        let resolve_sym = |sym_name: &str| -> *mut libc::c_void {
            let c_sym = CString::new(sym_name).unwrap();
            let mut ptr = unsafe { libc::dlsym(handle, c_sym.as_ptr()) };
            if ptr.is_null() && !sl_impl_handle.is_null() {
                ptr = unsafe { libc::dlsym(sl_impl_handle, c_sym.as_ptr()) };
            }
            if ptr.is_null() && !goodix_impl_handle.is_null() {
                ptr = unsafe { libc::dlsym(goodix_impl_handle, c_sym.as_ptr()) };
            }
            ptr
        };

        if fn_silead_cmd.is_none() {
            let sym = resolve_sym("silfp_finger_cust_cmd");
            if !sym.is_null() {
                log_info!("Found silfp_finger_cust_cmd in implementation lib");
                fn_silead_cmd = Some(unsafe { std::mem::transmute(sym) });
            }
        }

        let fn_silfp_cust_init: Option<FnSilfpCustInit> = {
            let sym = resolve_sym("silfp_finger_cust_init");
            if !sym.is_null() {
                log_info!("Found silfp_finger_cust_init");
                Some(unsafe { std::mem::transmute(sym) })
            } else {
                None
            }
        };

        let fn_silfp_sync_optic: Option<FnSilfpSyncOptic> = {
            let sym = resolve_sym("silfp_impl_sync_finger_status_optic");
            if !sym.is_null() {
                log_info!("Found silfp_impl_sync_finger_status_optic");
                Some(unsafe { std::mem::transmute(sym) })
            } else {
                None
            }
        };

        let fn_silfp_sync_down: Option<FnSilfpSyncFinger> = {
            let sym = resolve_sym("silfp_dev_sync_finger_down");
            if !sym.is_null() {
                log_info!("Found silfp_dev_sync_finger_down");
                Some(unsafe { std::mem::transmute(sym) })
            } else {
                None
            }
        };

        let fn_silfp_sync_up: Option<FnSilfpSyncFinger> = {
            let sym = resolve_sym("silfp_dev_sync_finger_up");
            if !sym.is_null() {
                log_info!("Found silfp_dev_sync_finger_up");
                Some(unsafe { std::mem::transmute(sym) })
            } else {
                None
            }
        };

        let fn_silfp_msg_send: Option<FnSilfpMsgSend> = {
            let sym = resolve_sym("silfp_msg_send");
            if !sym.is_null() {
                log_info!("Found silfp_msg_send");
                Some(unsafe { std::mem::transmute(sym) })
            } else {
                None
            }
        };

        type FnSilfpSetMode = unsafe extern "C" fn(mode: i32) -> libc::c_int;
        let fn_silfp_set_mode: Option<FnSilfpSetMode> = {
            let sym = resolve_sym("silfp_dev_set_finger_status_mode");
            if !sym.is_null() {
                log_info!("Found silfp_dev_set_finger_status_mode");
                Some(unsafe { std::mem::transmute(sym) })
            } else {
                None
            }
        };

        if let Some(set_mode) = fn_silfp_set_mode {
            let ret = unsafe { set_mode(1) };
            log_info!("silfp_dev_set_finger_status_mode(1) returned {}", ret);
        }

        if let Some(cust_init) = fn_silfp_cust_init {
            let ret = unsafe { cust_init() };
            log_info!("silfp_finger_cust_init() returned {}", ret);
        }

        let fn_silfp_worker_screen_state: Option<FnSilfpWorkerScreenState> = {
            let sym = resolve_sym("silfp_worker_screen_state_callback");
            if !sym.is_null() {
                log_info!("Found silfp_worker_screen_state_callback");
                Some(unsafe { std::mem::transmute(sym) })
            } else {
                let sym_def = resolve_sym("silfp_worker_set_screen_state_default");
                if !sym_def.is_null() {
                    log_info!("Found silfp_worker_set_screen_state_default");
                    Some(unsafe { std::mem::transmute(sym_def) })
                } else {
                    None
                }
            }
        };

        if let Some(cb) = fn_silfp_worker_screen_state {
            let ret = unsafe { cb(1) };
            log_info!("Initial silfp_worker_screen_state_callback(1) returned {}", ret);
        }

        let hal = Arc::new(Self {
            device: fp_dev,
            is_goodix,
            current_callback: Arc::new(Mutex::new(None)),
            is_active: AtomicBool::new(false),
            is_finger_down: AtomicBool::new(false),
            current_user_id: std::sync::atomic::AtomicI32::new(0),
            enumerated_ids: Mutex::new(Vec::new()),
            enum_completed: Arc::new(AtomicBool::new(false)),
            remove_pending: Arc::new(AtomicBool::new(false)),
            fn_silead_cmd,
            fn_goodix_cmd,
            fn_silfp_cust_init,
            fn_silfp_sync_optic,
            fn_silfp_sync_down,
            fn_silfp_sync_up,
            fn_silfp_msg_send,
            fn_silfp_worker_screen_state,
            saved_enroll_fid: AtomicI32::new(0),
            step_captured: AtomicBool::new(false),
            finger_held: AtomicBool::new(false),
            rearm_gen: AtomicU32::new(0),
            auth_rearm_count: AtomicU32::new(0),
            screen_state: AtomicI32::new(1),
        });

        // Set up callback notification
        let set_notify = if is_goodix {
            unsafe { (*(dev_ptr as *const goodix_fingerprint_device_t)).set_notify }
        } else {
            fp_ref.set_notify
        };
        if let Some(set_notify) = set_notify {
            let n_ret = unsafe { set_notify(fp_dev, hal_notify_trampoline) };
            log_info!("set_notify returned {}", n_ret);
        }

        let _ = GLOBAL_HAL.set(hal.clone());
        crate::input::start_screen_off_touch_monitor(hal.clone());
        Ok(hal)
    }

    pub fn is_active(&self) -> bool {
        self.is_active.load(Ordering::SeqCst)
    }

    pub fn is_finger_down(&self) -> bool {
        self.is_finger_down.load(Ordering::SeqCst)
    }

    pub fn set_callback(&self, cb: Option<Strong<dyn ISessionCallback>>) {
        let mut guard = self.current_callback.lock();
        *guard = cb;
    }

    pub fn set_active_user(&self, user_id: i32, store_path: &str) {
        self.current_user_id.store(user_id, Ordering::SeqCst);
        if self.is_goodix {
            let dev = unsafe { &mut *(self.device as *mut goodix_fingerprint_device_t) };
            if let Some(set_active_group) = dev.set_active_group {
                let c_path = CString::new(store_path).unwrap_or_default();
                let ret = unsafe { set_active_group(self.device, user_id as u32, c_path.as_ptr()) };
                log_info!("[Goodix] set_active_group({}, '{}') returned {}", user_id, store_path, ret);
            }
            return;
        }
        let dev = unsafe { &mut *self.device };
        if let Some(set_active_group) = dev.set_active_group {
            let c_path = CString::new(store_path).unwrap_or_default();
            let ret = unsafe { set_active_group(self.device, user_id as u32, c_path.as_ptr()) };
            log_info!("set_active_group({}, '{}') returned {}", user_id, store_path, ret);
        }
    }

    pub fn check_and_clear_remove_pending(&self) -> bool {
        self.remove_pending.swap(false, Ordering::SeqCst)
    }

    pub fn notify_framework_touch(&self, is_down: bool) {
        log_info!("notify_framework_touch({}) invoked", is_down);
        let cb = {
            let cb_guard = self.current_callback.lock();
            match cb_guard.as_ref() {
                Some(cb) => cb.clone(),
                None => {
                    log_warn!("notify_framework_touch: current_callback is None!");
                    return;
                }
            }
        };

        let sib = cb.as_binder();
        let Some(proxy) = sib.as_proxy() else {
            log_warn!("notify_framework_touch: callback binder is not a remote proxy");
            return;
        };

        let mut parcel = match proxy.prepare_transact(false) {
            Ok(p) => p,
            Err(e) => {
                log_warn!("notify_framework_touch: failed to prepare parcel: {:?}", e);
                return;
            }
        };

        // Standard Android 11+ Parcel interface token header:
        // 1. StrictMode policy (0)
        let strict_policy: i32 = 0;
        // 2. WorkSource (-1)
        let work_source: i32 = -1;
        // 3. Android 11+ INTERFACE_HEADER magic: 0x53595354 ("SYST")
        let header: u32 = 0x53595354;
        // 4. Interface descriptor String16
        let descriptor = "android.hardware.biometrics.fingerprint.ISessionCallback";

        if let Err(e) = parcel.write(&strict_policy) {
            log_warn!("notify_framework_touch: write strict_policy failed: {:?}", e);
            return;
        }
        if let Err(e) = parcel.write(&work_source) {
            log_warn!("notify_framework_touch: write work_source failed: {:?}", e);
            return;
        }
        if let Err(e) = parcel.write(&header) {
            log_warn!("notify_framework_touch: write header failed: {:?}", e);
            return;
        }
        if let Err(e) = parcel.write(&descriptor) {
            log_warn!("notify_framework_touch: write descriptor failed: {:?}", e);
            return;
        }

        // ColorOS Framework onTransactFromHal expects:
        // cmdId: 1201 (0x4b1) for TouchDown, 1202 (0x4b2) for TouchUp
        // resultLen: 8
        // result: 8-byte little-endian timestamp (SystemClock.uptimeMillis())
        let cmd_id: i32 = if is_down { 1201 } else { 1202 };
        let now_ms = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_millis() as u64,
            Err(_) => 0,
        };
        let now_bytes = now_ms.to_le_bytes();
        let result_len: i32 = now_bytes.len() as i32;

        if let Err(e) = parcel.write(&cmd_id) {
            log_warn!("notify_framework_touch: write cmd_id failed: {:?}", e);
            return;
        }
        if let Err(e) = parcel.write(&result_len) {
            log_warn!("notify_framework_touch: write result_len failed: {:?}", e);
            return;
        }
        if let Err(e) = parcel.write(&now_bytes[..]) {
            log_warn!("notify_framework_touch: write bytes failed: {:?}", e);
            return;
        }

        match proxy.submit_transact(1001, &parcel, 0) {
            Ok(_) => {
                log_info!(
                    "notify_framework_touch({}): dispatched ColorOS binder transact 1001 (cmd {})",
                    is_down, cmd_id
                );
            }
            Err(e) => {
                log_warn!("notify_framework_touch: submit_transact(1001) failed: {:?}", e);
            }
        }
    }

    pub fn pre_enroll(&self) -> anyhow::Result<u64> {
        self.step_captured.store(false, Ordering::SeqCst);
        self.saved_enroll_fid.store(0, Ordering::SeqCst);
        if self.is_goodix {
            let dev = unsafe { &mut *(self.device as *mut goodix_fingerprint_device_t) };
            let pre_enroll_fn = dev.pre_enroll.ok_or_else(|| anyhow::anyhow!("pre_enroll is null"))?;
            let challenge = unsafe { pre_enroll_fn(self.device) };
            log_info!("[Goodix] pre_enroll returned challenge: 0x{:x}", challenge);
            return Ok(challenge);
        }
        let dev = unsafe { &mut *self.device };
        let pre_enroll_fn = dev.pre_enroll.ok_or_else(|| anyhow::anyhow!("pre_enroll is null"))?;
        let challenge = unsafe { pre_enroll_fn(self.device) };
        log_info!("pre_enroll returned challenge: 0x{:x}", challenge);
        Ok(challenge)
    }

    pub fn post_enroll(&self, challenge: u64) {
        if self.is_goodix {
            let dev = unsafe { &mut *(self.device as *mut goodix_fingerprint_device_t) };
            if let Some(post_enroll_fn) = dev.post_enroll {
                let ret = unsafe { post_enroll_fn(self.device, challenge) };
                log_info!("[Goodix] post_enroll(0x{:x}) returned {}", challenge, ret);
            }
            return;
        }
        let dev = unsafe { &mut *self.device };
        if let Some(post_enroll_fn) = dev.post_enroll {
            let ret = unsafe { post_enroll_fn(self.device) };
            log_info!("post_enroll returned {}", ret);
        }
    }

    pub fn enroll(&self, hat: &hw_auth_token_t, timeout_sec: u32) -> i32 {
        self.step_captured.store(false, Ordering::SeqCst);
        self.saved_enroll_fid.store(0, Ordering::SeqCst);
        log_info!("FingerprintHal::enroll invoked");

        if let Some(msg_send) = self.fn_silfp_msg_send {
            unsafe { msg_send(3) }; // Ensure clean finger-up state in Silead message queue
        }

        if self.is_goodix {
            let dev = unsafe { &mut *(self.device as *mut goodix_fingerprint_device_t) };
            if let Some(enroll_fn) = dev.enroll {
                self.is_active.store(true, Ordering::SeqCst);
                let gid = self.current_user_id.load(Ordering::SeqCst) as u32;
                let ret = unsafe { enroll_fn(self.device, hat as *const hw_auth_token_t, gid, timeout_sec) };
                log_info!("[Goodix] dev.enroll invoked (gid={gid}), ret = {}", ret);
                return ret;
            }
            return -1;
        }

        let dev = unsafe { &mut *self.device };
        if let Some(enroll_fn) = dev.enroll {
            self.is_active.store(true, Ordering::SeqCst);
            let gid = self.current_user_id.load(Ordering::SeqCst) as u32;
            let ret = unsafe { enroll_fn(self.device, hat as *const hw_auth_token_t, gid, timeout_sec) };
            log_info!("dev.enroll invoked (gid={gid}), ret = {}", ret);
            ret
        } else {
            -1
        }
    }

    pub fn authenticate(&self, operation_id: u64) -> i32 {
        if self.is_goodix {
            let dev = unsafe { &mut *(self.device as *mut goodix_fingerprint_device_t) };
            if let Some(auth_fn) = dev.authenticate {
                self.is_active.store(true, Ordering::SeqCst);
                let gid = self.current_user_id.load(Ordering::SeqCst) as u32;
                let ret = unsafe { auth_fn(self.device, operation_id, gid) };
                log_info!("[Goodix] authenticate invoked (op_id=0x{:x}, gid={gid}), ret = {}", operation_id, ret);
                return ret;
            }
            return -1;
        }
        let dev = unsafe { &mut *self.device };
        if let Some(auth_fn) = dev.authenticate {
            self.is_active.store(true, Ordering::SeqCst);
            let gid = self.current_user_id.load(Ordering::SeqCst) as u32;
            let ret = unsafe { auth_fn(self.device, operation_id, gid) };
            log_info!("authenticate invoked (op_id=0x{:x}, gid={gid}), ret = {}", operation_id, ret);
            ret
        } else {
            -1
        }
    }

    pub fn set_screen_state(&self, mut state: i32) {
        // ColorOS notifyScreenStateToHal reports 0 for both deep sleep and AOD.
        // If state is reported as 0 but DRM display DPMS is still ON, the display is in AOD / Doze mode (state 2).
        if state == 0 && Self::is_display_dpms_on() {
            log_info!("Screen state reported 0, but DPMS is ON -> resolving to Doze/AOD (state 2)");
            state = 2;
        }

        let old = self.screen_state.swap(state, Ordering::SeqCst);
        log_info!("FingerprintHal::set_screen_state transition: {} -> {}", old, state);

        // Notify Silead worker thread so its internal screen state ([0x6b23c]) matches hardware
        if let Some(cb) = self.fn_silfp_worker_screen_state {
            let vendor_state = if state == 0 { 0 } else { 1 };
            let ret = unsafe { cb(vendor_state) };
            log_info!("silfp_worker_screen_state_callback({}) returned {}", vendor_state, ret);
        }

        // Ensure HBM is deactivated and finger state reset when entering screen OFF
        if state == 0 {
            crate::hbm::set_hbm(false);
            self.is_finger_down.store(false, Ordering::SeqCst);
        }

        match state {
            0 => {
                // State 0: fully sleep (Off)
                log_info!("[SleepState: OFF] Screen reached fully sleep (Off). Arming low-power gesture mode.");
                crate::input::ensure_gesture_fod_enabled();
            }
            2 => {
                // State 2: Dozing / Doze (AOD)
                log_info!("[SleepState: DOZE] Screen reached Dozing/Doze (AOD). Maintaining touch & optical readiness.");
                crate::input::ensure_gesture_fod_enabled();
                self.send_custom_cmd(10, 1, 0x10001, 1);
            }
            1 => {
                // State 1: Awake (Screen ON)
                log_info!("[SleepState: AWAKE] Screen is ON / active.");
                self.send_custom_cmd(10, 1, 0x10001, 1);
            }
            _ => {
                log_info!("[SleepState: UNKNOWN] Received screen state {}", state);
            }
        }
    }

    pub fn get_screen_state(&self) -> i32 {
        self.screen_state.load(Ordering::SeqCst)
    }

    pub fn is_display_dpms_on() -> bool {
        match std::fs::read_to_string("/sys/class/drm/card0-DSI-1/dpms") {
            Ok(s) => s.trim().eq_ignore_ascii_case("on"),
            Err(_) => true,
        }
    }

    pub fn send_custom_cmd(&self, silead_cmd: u32, silead_arg: u32, goodix_cmd: u32, goodix_arg: u32) {
        if let Some(cmd_fn) = self.fn_silead_cmd {
            unsafe {
                let _ = cmd_fn(silead_cmd, silead_arg);
            }
        } else if let Some(cmd_fn) = self.fn_goodix_cmd {
            unsafe {
                let _ = cmd_fn(self.device, goodix_cmd, goodix_arg);
            }
        }
    }

    pub fn cancel(&self) {
        let _was_down = self.is_finger_down.swap(false, Ordering::SeqCst);
        self.finger_held.store(false, Ordering::SeqCst);
        self.rearm_gen.fetch_add(1, Ordering::SeqCst);
        self.step_captured.store(false, Ordering::SeqCst);
        crate::hbm::set_hbm(false);
        if _was_down {
            self.notify_framework_touch(false);
        }
        self.send_custom_cmd(10, 0, 0x10001, 0);
        self.send_custom_cmd(11, 0, 0x10001, 0);
        if let Some(sync_optic) = self.fn_silfp_sync_optic {
            unsafe { sync_optic(0) };
        } else if let Some(msg_send) = self.fn_silfp_msg_send {
            unsafe { msg_send(3) };
        }
        if self.is_goodix {
            let dev = unsafe { &mut *(self.device as *mut goodix_fingerprint_device_t) };
            if let Some(cancel_fn) = dev.cancel {
                let ret = unsafe { cancel_fn(self.device) };
                log_info!("[Goodix] cancel invoked, ret = {}", ret);
            }
        } else {
            let dev = unsafe { &mut *self.device };
            if let Some(cancel_fn) = dev.cancel {
                let ret = unsafe { cancel_fn(self.device) };
                log_info!("cancel invoked, ret = {}", ret);
            }
        }
        self.is_active.store(false, Ordering::SeqCst);
    }

    pub fn enumerate(&self) {
        self.enumerated_ids.lock().clear();
        self.enum_completed.store(false, Ordering::SeqCst);
        let ret = if self.is_goodix {
            let dev = unsafe { &mut *(self.device as *mut goodix_fingerprint_device_t) };
            if let Some(enum_fn) = dev.enumerate {
                unsafe { enum_fn(self.device) }
            } else {
                -1
            }
        } else {
            let dev = unsafe { &mut *self.device };
            if let Some(enum_fn) = dev.enumerate {
                unsafe { enum_fn(self.device) }
            } else {
                -1
            }
        };
        log_info!("enumerate invoked, ret = {}", ret);

        // Allow up to 100ms for asynchronous notification from vendor HAL
        for _ in 0..10 {
            if self.enum_completed.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Guaranteed fallback: If vendor HAL never called notify (e.g. empty DB or error),
        // explicitly send onEnrollmentsEnumerated so Android framework's
        // FingerprintInternalCleanupClient completes and is never stuck!
        if !self.enum_completed.swap(true, Ordering::SeqCst) {
            let list = self.enumerated_ids.lock().clone();
            log_warn!("Vendor HAL enumeration did not report completion; sending onEnrollmentsEnumerated({:?}) fallback", list);
            if let Some(cb) = self.current_callback.lock().as_ref() {
                let _ = cb.onEnrollmentsEnumerated(&list);
            }
        }
    }

    pub fn remove(&self, finger_id: u32) {
        self.remove_pending.store(true, Ordering::SeqCst);
        if self.is_goodix {
            let dev = unsafe { &mut *(self.device as *mut goodix_fingerprint_device_t) };
            if let Some(remove_fn) = dev.remove {
                let ids = [finger_id];
                let ret = unsafe { remove_fn(self.device, ids.as_ptr(), 1) };
                log_info!("[Goodix] remove(fid={}) invoked, ret = {}", finger_id, ret);
                if ret == 0 {
                    self.remove_pending.store(false, Ordering::SeqCst);
                    if let Some(cb) = self.current_callback.lock().as_ref() {
                        log_info!("[Goodix] reporting requested removal fid {}", finger_id);
                        let _ = cb.onEnrollmentsRemoved(&[finger_id as i32]);
                    }
                }
            }
            return;
        }
        let dev = unsafe { &mut *self.device };
        let gid = self.current_user_id.load(Ordering::SeqCst) as u32;
        if let Some(remove_fn) = dev.remove {
            let ret = unsafe { remove_fn(self.device, gid, finger_id) };
            log_info!("remove(gid={}, fid={}) invoked, ret = {}", gid, finger_id, ret);
        }
    }

    pub fn get_authenticator_id(&self) -> u64 {
        let dev = unsafe { &mut *self.device };
        if let Some(get_auth_fn) = dev.get_authenticator_id {
            unsafe { get_auth_fn(self.device) }
        } else {
            0
        }
    }

    // Touch & Optical Illumination Callbacks
    pub fn on_pointer_down(&self, x: i32, y: i32, _minor: f32, _major: f32) {
        // Calibrate touch boundary: reject any touch outside the calibrated FOD sensor circle
        // (x == 0 && y == 0 is preserved as a special fallback for hardware gesture keys without coordinates)
        if (x != 0 || y != 0) && !crate::input::is_inside_fod_area(x, y) {
            log_info!(
                "on_pointer_down at ({}, {}) rejected: outside calibrated FOD area (center: {}, {}, radius: {})",
                x, y, crate::input::FOD_CENTER_X, crate::input::FOD_CENTER_Y, crate::input::FOD_TOUCH_RADIUS
            );
            return;
        }

        let screen_state = self.get_screen_state();

        if !self.is_active() {
            if screen_state == 1 {
                log_debug!("on_pointer_down while inactive and screen is ON -> ignored");
                return;
            }
            log_info!("on_pointer_down while inactive (screen_state={}) -> auto-starting authenticate for SOFOD", screen_state);
            self.authenticate(0);
        }

        self.finger_held.store(true, Ordering::SeqCst);
        if self.is_finger_down.swap(true, Ordering::SeqCst) {
            log_debug!("Duplicate pointer_down ignored");
            return;
        }
        self.step_captured.store(false, Ordering::SeqCst);
        self.auth_rearm_count.store(0, Ordering::SeqCst);
        log_info!(
            "on_pointer_down at ({}, {}) (screen_state={}) -> activating HBM & optical capture",
            x, y, screen_state
        );

        // 1. Notify framework touch start (standard AIDL AcquiredInfo::START)
        if let Some(cb) = self.current_callback.lock().as_ref() {
            let _ = cb.onAcquired(AcquiredInfo::START, 0);
        }

        // 2. Notify ColorOS framework of touch down via binder transact 1001 (cmd 1201)
        // This triggers dispatchTouchDown() -> SystemUI reason 8 -> startPressedAnimation()!
        self.notify_framework_touch(true);

        // Acquire wake lock if screen is not awake to keep CPU running during display transition
        if screen_state != 1 {
            crate::input::acquire_wakelock("oplus_udfps_fod_wake");
        }

        // 3. Activate hardware HBM backlight and synchronize until panel confirms active (0xOK)
        let hbm_ok = crate::hbm::set_hbm_sync(true, 500);
        if !hbm_ok {
            log_warn!("Hardware LCM HBM did not confirm 0xOK within 500ms, proceeding with capture fallback");
        }

        // If finger was lifted during HBM synchronization, abort capture
        if !self.is_finger_down.load(Ordering::SeqCst) {
            log_info!("Finger lifted during optical sync delay, aborting capture");
            crate::hbm::set_hbm(false);
            if self.get_screen_state() == 0 {
                crate::input::release_wakelock("oplus_udfps_fod_wake");
            }
            return;
        }

        // Fast settling delay (5ms) for CMOS exposure uniformity aligned with ColorOS animation flare
        std::thread::sleep(std::time::Duration::from_millis(5));

        // Re-check if finger was lifted during settling delay
        if !self.is_finger_down.load(Ordering::SeqCst) {
            log_info!("Finger lifted during settling delay, aborting capture");
            crate::hbm::set_hbm(false);
            if self.get_screen_state() == 0 {
                crate::input::release_wakelock("oplus_udfps_fod_wake");
            }
            return;
        }

        // 5. Wake vendor sensor and start optical capture
        self.send_custom_cmd(10, 1, 0x10001, 1);
        self.send_custom_cmd(11, 1, 0x10001, 1);

        if let Some(sync_optic) = self.fn_silfp_sync_optic {
            unsafe { sync_optic(1) };
        } else if let Some(sync_down) = self.fn_silfp_sync_down {
            unsafe { sync_down() };
        } else if let Some(msg_send) = self.fn_silfp_msg_send {
            unsafe { msg_send(2) }; // FINGER_DOWN = 2
        }
    }

    pub fn on_pointer_up(&self) {
        let was_down = self.is_finger_down.swap(false, Ordering::SeqCst);
        self.finger_held.store(false, Ordering::SeqCst);
        self.rearm_gen.fetch_add(1, Ordering::SeqCst);
        self.step_captured.store(false, Ordering::SeqCst);
        log_info!("on_pointer_up (was_down={}, is_active={}) -> deactivating HBM", was_down, self.is_active());

        // Always guarantee HBM is turned off immediately on pointer up
        crate::hbm::set_hbm(false);

        // Inform vendor sensor of finger lift
        self.send_custom_cmd(11, 0, 0x10001, 0);

        if let Some(sync_optic) = self.fn_silfp_sync_optic {
            unsafe { sync_optic(0) };
        } else if let Some(sync_up) = self.fn_silfp_sync_up {
            unsafe { sync_up() };
        } else if let Some(msg_send) = self.fn_silfp_msg_send {
            unsafe { msg_send(3) }; // FINGER_UP = 3
        }

        // Notify ColorOS framework of touch up via binder transact 1001 (cmd 1202)
        // This triggers dispatchTouchUp() -> SystemUI reason 9 -> stops pressed animation!
        self.notify_framework_touch(false);

        // Release FOD wake lock
        crate::input::release_wakelock("oplus_udfps_fod_wake");
    }

    /// Jadwalkan capture ulang selama jari fisik masih menempel.
    /// Dibatalkan otomatis oleh on_pointer_up()/cancel()/sukses auth (rearm_gen naik).
    fn schedule_hold_rearm(&self, delay_ms: u64) {
        if !self.finger_held.load(Ordering::SeqCst) || !self.is_active() {
            return;
        }
        let gen = self.rearm_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let hal = match GLOBAL_HAL.get() {
            Some(h) => h.clone(),
            None => return,
        };
        let spawned = std::thread::Builder::new()
            .name("fod_hold_rearm".to_string())
            .spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                if hal.rearm_gen.load(Ordering::SeqCst) != gen {
                    return;
                }
                hal.rearm_capture(gen);
            });
        if let Err(e) = spawned {
            log_warn!("Hold-rearm: failed to spawn thread: {e}");
        }
    }

    /// Simulasi "angkat lalu tekan lagi" ke vendor HAL tanpa mengubah state UI framework
    /// (pressed icon tetap tampil, tidak ada notify touch up/down ke SystemUI).
    fn rearm_capture(&self, gen: u32) {
        let still = |s: &Self| {
            s.finger_held.load(Ordering::SeqCst)
                && s.is_active()
                && s.rearm_gen.load(Ordering::SeqCst) == gen
        };
        if !still(self) {
            return;
        }
        log_info!("Hold-rearm: finger still held -> re-triggering capture (HBM cycle)");

        // fake lift: HBM off + disarm vendor capture
        crate::hbm::set_hbm(false);
        self.send_custom_cmd(11, 0, 0x10001, 0);
        if let Some(sync_optic) = self.fn_silfp_sync_optic {
            unsafe { sync_optic(0) };
        } else if let Some(msg_send) = self.fn_silfp_msg_send {
            unsafe { msg_send(3) };
        }
        std::thread::sleep(std::time::Duration::from_millis(HOLD_FAKE_UP_MS));
        if !still(self) {
            return;
        }

        // fake press: HBM on (kernel kirim uevent FULL_HBM_SET -> HAL Goodix capture) + arm
        self.is_finger_down.store(true, Ordering::SeqCst);
        self.step_captured.store(false, Ordering::SeqCst);
        if !crate::hbm::set_hbm_sync(true, 500) {
            log_warn!("Hold-rearm: HBM did not confirm within 500ms, continuing");
        }
        if !still(self) {
            crate::hbm::set_hbm(false);
            self.is_finger_down.store(false, Ordering::SeqCst);
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        self.send_custom_cmd(10, 1, 0x10001, 1);
        self.send_custom_cmd(11, 1, 0x10001, 1);
        if let Some(sync_optic) = self.fn_silfp_sync_optic {
            unsafe { sync_optic(1) };
        } else if let Some(sync_down) = self.fn_silfp_sync_down {
            unsafe { sync_down() };
        } else if let Some(msg_send) = self.fn_silfp_msg_send {
            unsafe { msg_send(2) };
        }
    }

    pub fn is_finger_held(&self) -> bool {
        self.finger_held.load(Ordering::SeqCst)
    }

    pub fn on_ui_ready(&self) {
        log_info!("on_ui_ready received from framework -> notifying vendor HAL icon ready");
        self.send_custom_cmd(10, 1, 0x10001, 1);
    }

    // Internal notification dispatcher from C trampoline
    fn on_notify(&self, msg: &fingerprint_msg_t) {
        let cb_opt = self.current_callback.lock().clone();
        let cb = match cb_opt {
            Some(c) => c,
            None => {
                log_warn!("on_notify dropped: no active ISessionCallback registered");
                return;
            }
        };

        match msg.r#type {
            FINGERPRINT_AUTHENTICATED => {
                let (fid, hat) = if self.is_goodix {
                    let p = msg.data.as_ptr();
                    let fid = unsafe { *(p as *const u32) } as i32;
                    let hat = unsafe { &*((p.add(4)) as *const hw_auth_token_t) };
                    (fid, hat.to_aidl())
                } else {
                    let auth_data = unsafe { &*(msg.data.as_ptr() as *const fingerprint_authenticated_t) };
                    (auth_data.finger.fid as i32, auth_data.hat.to_aidl())
                };

                self.send_custom_cmd(11, 0, 0x10001, 0);
                if let Some(sync_optic) = self.fn_silfp_sync_optic {
                    unsafe { sync_optic(0) };
                } else if let Some(msg_send) = self.fn_silfp_msg_send {
                    unsafe { msg_send(3) };
                }

                // Immediately extinguish HBM backlight!
                // Optical capture and matching are completed. We must not leave HBM active
                // when entering homescreen or waiting for finger release!
                crate::hbm::set_hbm(false);
                self.is_finger_down.store(false, Ordering::SeqCst);

                if fid != 0 {
                    self.is_active.store(false, Ordering::SeqCst);
                    self.send_custom_cmd(10, 0, 0x10001, 0);
                    self.rearm_gen.fetch_add(1, Ordering::SeqCst);
                    log_info!("Authentication SUCCEEDED for fid {}", fid);
                    let _ = cb.onAuthenticationSucceeded(fid, &hat);
                    if self.get_screen_state() == 0 && !Self::is_display_dpms_on() {
                        log_info!("SOFOD authentication succeeded while display was fully asleep. Waking display pipeline");
                        crate::input::wake_display_pipeline();
                    }
                } else {
                    log_info!("Authentication FAILED (unrecognized finger, keeping session active for next touch)");
                    let _ = cb.onAuthenticationFailed();
                    // Jari masih ditekan -> coba capture lagi tanpa perlu angkat jari (dibatasi)
                    let n = self.auth_rearm_count.fetch_add(1, Ordering::SeqCst) + 1;
                    if n <= HOLD_AUTH_REARM_MAX {
                        self.schedule_hold_rearm(HOLD_AUTH_REARM_MS);
                    } else {
                        log_info!("Hold-rearm: auth retry cap ({}) reached, waiting for finger lift", HOLD_AUTH_REARM_MAX);
                    }
                }
            }
            FINGERPRINT_ACQUIRED => {
                let acq_data = unsafe { &*(msg.data.as_ptr() as *const fingerprint_acquired_t) };
                let (info, vendor_code) = match acq_data.acquired_info {
                    FINGERPRINT_ACQUIRED_GOOD => (AcquiredInfo::GOOD, 0),
                    FINGERPRINT_ACQUIRED_PARTIAL => (AcquiredInfo::PARTIAL, 0),
                    FINGERPRINT_ACQUIRED_INSUFFICIENT => (AcquiredInfo::INSUFFICIENT, 0),
                    FINGERPRINT_ACQUIRED_IMAGER_DIRTY => (AcquiredInfo::SENSOR_DIRTY, 0),
                    FINGERPRINT_ACQUIRED_TOO_SLOW => (AcquiredInfo::TOO_SLOW, 0),
                    FINGERPRINT_ACQUIRED_TOO_FAST => (AcquiredInfo::TOO_FAST, 0),
                    FINGERPRINT_ACQUIRED_VENDOR => (AcquiredInfo::VENDOR, 0),
                    1001 | 1002 | 1020 => {
                        // Suppress Silead internal hardware signals from framework logcat
                        // (1001 = down, 1002 = up, 1020 = wait ui ready)
                        log_debug!("Silead internal acquired event: {}", acq_data.acquired_info);
                        return;
                    }
                    other => (AcquiredInfo::VENDOR, other),
                };
                let _ = cb.onAcquired(info, vendor_code);
            }
            FINGERPRINT_TEMPLATE_ENROLLING => {
                let (raw_fid, raw_remaining) = if self.is_goodix {
                    let p = msg.data.as_ptr() as *const u32;
                    let fid = unsafe { *p } as i32;
                    let remaining = unsafe { *p.add(1) } as i32;
                    (fid, remaining)
                } else {
                    let enroll_data = unsafe { &*(msg.data.as_ptr() as *const fingerprint_enroll_t) };
                    (enroll_data.finger.fid as i32, enroll_data.samples_remaining as i32)
                };

                if !self.is_goodix && self.step_captured.swap(true, Ordering::SeqCst) {
                    log_debug!("Duplicate enroll step during same touch ignored (raw_remaining={})", raw_remaining);
                    return;
                }

                log_info!("Enroll progress: raw_fid {}, raw_remaining {}", raw_fid, raw_remaining);

                if raw_fid != 0 {
                    self.saved_enroll_fid.store(raw_fid, Ordering::SeqCst);
                }

                // Disarm capture for this touch so Silead does not burst multiple captures
                self.send_custom_cmd(11, 0, 0x10001, 0);
                if let Some(sync_optic) = self.fn_silfp_sync_optic {
                    unsafe { sync_optic(0) };
                } else if let Some(msg_send) = self.fn_silfp_msg_send {
                    unsafe { msg_send(3) };
                }

                // Turn off HBM after sample capture to prompt user to lift and press again
                crate::hbm::set_hbm(false);
                self.is_finger_down.store(false, Ordering::SeqCst);

                let fid = if raw_remaining == 0 {
                    let saved = self.saved_enroll_fid.load(Ordering::SeqCst);
                    if saved != 0 {
                        saved
                    } else if raw_fid != 0 {
                        raw_fid
                    } else {
                        1
                    }
                } else {
                    raw_fid
                };

                log_info!("Reporting enrollment progress: fid {}, remaining {}", fid, raw_remaining);
                let _ = cb.onEnrollmentProgress(fid, raw_remaining);
                if raw_remaining > 0 {
                    // Jari masih ditekan -> lanjut sample berikutnya otomatis (spam enroll)
                    self.schedule_hold_rearm(HOLD_ENROLL_REARM_MS);
                } else {
                    self.rearm_gen.fetch_add(1, Ordering::SeqCst);
                }

                if raw_remaining == 0 {
                    log_info!("Enrollment completed successfully (final fid {})", fid);
                    self.is_active.store(false, Ordering::SeqCst);
                    self.send_custom_cmd(10, 0, 0x10001, 0);
                }
            }
            FINGERPRINT_TEMPLATE_REMOVED => {
                let (gid, fid) = if self.is_goodix {
                    let p = msg.data.as_ptr() as *const u32;
                    let gid = unsafe { *p } as i32;
                    let fid = unsafe { *p.add(1) } as i32;
                    (gid, fid)
                } else {
                    let rem_data = unsafe { &*(msg.data.as_ptr() as *const fingerprint_removed_t) };
                    (rem_data.finger.gid as i32, rem_data.finger.fid as i32)
                };
                self.remove_pending.store(false, Ordering::SeqCst);
                log_info!("Enrollment removed via vendor callback: gid {}, fid {}", gid, fid);
                if fid == 0 {
                    log_warn!("Ignoring vendor removal callback with fid 0; requested fid was already reported");
                    return;
                }
                let _ = cb.onEnrollmentsRemoved(&[fid]);
            }
            FINGERPRINT_TEMPLATE_ENUMERATING => {
                let (fid, remaining) = if self.is_goodix {
                    let p = msg.data.as_ptr() as *const u32;
                    let fid = unsafe { *p } as i32;
                    let remaining = unsafe { *p.add(1) } as usize;
                    (fid, remaining)
                } else {
                    let enum_data = unsafe { &*(msg.data.as_ptr() as *const fingerprint_enroll_t) };
                    (enum_data.finger.fid as i32, enum_data.samples_remaining as usize)
                };

                let mut list = self.enumerated_ids.lock();
                if fid != 0 {
                    list.push(fid);
                }
                if remaining == 0 {
                    log_info!("Enumeration finished: {:?}", *list);
                    self.enum_completed.store(true, Ordering::SeqCst);
                    let _ = cb.onEnrollmentsEnumerated(&list);
                }
            }
            FINGERPRINT_ERROR => {
                let err_code = unsafe { *(msg.data.as_ptr() as *const i32) };
                self.is_finger_down.store(false, Ordering::SeqCst);
                crate::hbm::set_hbm(false);
                self.is_active.store(false, Ordering::SeqCst);
                self.send_custom_cmd(10, 0, 0x10001, 0);
                self.send_custom_cmd(11, 0, 0x10001, 0);

                let (err, vendor_code) = match err_code {
                    FINGERPRINT_ERROR_HW_UNAVAILABLE => (Error::HW_UNAVAILABLE, 0),
                    FINGERPRINT_ERROR_UNABLE_TO_PROCESS => (Error::UNABLE_TO_PROCESS, 0),
                    FINGERPRINT_ERROR_TIMEOUT => (Error::TIMEOUT, 0),
                    FINGERPRINT_ERROR_NO_SPACE => (Error::NO_SPACE, 0),
                    FINGERPRINT_ERROR_CANCELED => (Error::CANCELED, 0),
                    FINGERPRINT_ERROR_UNABLE_TO_REMOVE => (Error::UNABLE_TO_REMOVE, 0),
                    FINGERPRINT_ERROR_LOCKOUT => (Error::VENDOR, 7), // Lockout handled via vendor code
                    other => (Error::VENDOR, other),
                };
                log_warn!("Fingerprint ERROR reported: {:?} (vendorCode={})", err, vendor_code);
                let _ = cb.onError(err, vendor_code);
            }
            _ => {
                log_debug!("Unhandled fingerprint legacy message type: {}", msg.r#type);
            }
        }
    }
}

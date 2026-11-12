use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use parking_lot::Mutex;
use crate::{log_info, log_warn};

const TRAN_LCM_HBM_STATE: &str = "/sys/kernel/tran_display/lcm_hbm_state";
const OPLUS_DISPLAY_DIR: &str = "/data/addon/oplus_display";
const OPLUS_DISPLAY_HBM: &str = "/data/addon/oplus_display/hbm";
const OPLUS_DISPLAY_FPPRESS: &str = "/data/addon/oplus_display/notify_fppress";

const HBM_SAFETY_TIMEOUT_MS: u64 = 10_000;

struct HbmController {
    is_enabled: bool,
}

static GLOBAL_HBM: Mutex<Option<HbmController>> = Mutex::new(None);
static HBM_GENERATION: AtomicU64 = AtomicU64::new(0);

impl HbmController {
    fn new() -> Self {
        Self { is_enabled: false }
    }

    fn write(&mut self, enabled: bool) {
        if enabled {
            let generation = HBM_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(HBM_SAFETY_TIMEOUT_MS));
                if HBM_GENERATION.load(Ordering::SeqCst) == generation {
                    log_warn!(
                        "HBM safety watchdog: forced off after {}ms without pointer-up",
                        HBM_SAFETY_TIMEOUT_MS
                    );
                    set_hbm(false);
                }
            });
        } else {
            HBM_GENERATION.fetch_add(1, Ordering::SeqCst);
        }

        // 1. Direct hardware write to MTK/Transsion panel HBM node
        let val_tran = if enabled { b"1\n" } else { b"0\n" };
        if let Err(e) = fs::write(TRAN_LCM_HBM_STATE, val_tran) {
            log_warn!("Failed to write to {}: {}", TRAN_LCM_HBM_STATE, e);
        } else if enabled {
            std::thread::sleep(Duration::from_millis(30));
            let _ = fs::write(TRAN_LCM_HBM_STATE, val_tran);
        }

        // 2. ColorOS display addon command files (fallback)
        let _ = fs::create_dir_all(OPLUS_DISPLAY_DIR);
        let value = if enabled { b"1\n" } else { b"0\n" };

        if enabled {
            let _ = fs::write(OPLUS_DISPLAY_FPPRESS, value);
            let _ = fs::write(OPLUS_DISPLAY_HBM, value);
        } else {
            let _ = fs::write(OPLUS_DISPLAY_HBM, value);
            let _ = fs::write(OPLUS_DISPLAY_FPPRESS, value);
        }

        let changed = self.is_enabled != enabled;
        self.is_enabled = enabled;
        if changed {
            if enabled {
                log_info!("Hardware LCM HBM & OPPO display enabled");
            } else {
                log_info!("Hardware LCM HBM & OPPO display disabled");
            }
        }
    }
}

pub fn set_hbm(enabled: bool) -> bool {
    set_hbm_sync(enabled, 0)
}

pub fn set_hbm_sync(enabled: bool, _max_wait_ms: u64) -> bool {
    let mut lock = GLOBAL_HBM.lock();
    if lock.is_none() {
        *lock = Some(HbmController::new());
    }
    if let Some(ctrl) = lock.as_mut() {
        ctrl.write(enabled);
        true
    } else {
        false
    }
}

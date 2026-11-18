use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::Mutex;
use crate::{log_info, log_warn};

const TRAN_LCM_HBM_STATE: &str = "/sys/kernel/tran_display/lcm_hbm_state";
const OPLUS_DISPLAY_DIR: &str = "/data/addon/oplus_display";
const OPLUS_DISPLAY_HBM: &str = "/data/addon/oplus_display/hbm";
const OPLUS_DISPLAY_FPPRESS: &str = "/data/addon/oplus_display/notify_fppress";

const HBM_SAFETY_TIMEOUT_MS: u64 = 10_000;
/// How often the disable path re-writes the panel node when the read-back
/// still reports HBM on (the vendor HAL can re-latch it while it finishes a
/// capture, which used to leave the panel lit after the session ended).
const OFF_RETRIES: u32 = 4;
const OFF_RETRY_GAP_MS: u64 = 10;

struct HbmController {
    is_enabled: bool,
}

static GLOBAL_HBM: Mutex<Option<HbmController>> = Mutex::new(None);
static HBM_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Reads the panel HBM node. `None` when the node is missing or not numeric
/// (device without the node, or an unusual panel driver).
fn read_tran() -> Option<i32> {
    let raw = fs::read_to_string(TRAN_LCM_HBM_STATE).ok()?;
    let t = raw.trim();
    match t {
        "0" => Some(0),
        "1" => Some(1),
        _ => t.parse::<i32>().ok().or_else(|| {
            let digits = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
            i32::from_str_radix(digits, 16).ok()
        }),
    }
}

impl HbmController {
    fn new() -> Self {
        Self { is_enabled: false }
    }

    fn write_node(&self, enabled: bool) {
        let val = if enabled { b"1\n" } else { b"0\n" };
        if let Err(e) = fs::write(TRAN_LCM_HBM_STATE, val) {
            log_warn!("Failed to write to {}: {}", TRAN_LCM_HBM_STATE, e);
            return;
        }
        if enabled {
            // Some panels need a second write after the first one starts the boost.
            std::thread::sleep(Duration::from_millis(30));
            let _ = fs::write(TRAN_LCM_HBM_STATE, val);
        }
    }

    fn write_addon(&self, enabled: bool) {
        let _ = fs::create_dir_all(OPLUS_DISPLAY_DIR);
        let value = if enabled { b"1\n" } else { b"0\n" };
        if enabled {
            let _ = fs::write(OPLUS_DISPLAY_FPPRESS, value);
            let _ = fs::write(OPLUS_DISPLAY_HBM, value);
        } else {
            let _ = fs::write(OPLUS_DISPLAY_HBM, value);
            let _ = fs::write(OPLUS_DISPLAY_FPPRESS, value);
        }
    }

    fn write(&mut self, enabled: bool) {
        // Bump the generation before touching hardware: a pending watchdog from an
        // older enable must not fire on top of this write.
        let generation = HBM_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        if enabled {
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(HBM_SAFETY_TIMEOUT_MS));
                // Re-check under the lock so a concurrent enable/disable wins.
                force_off_if_generation(generation);
            });
        }

        // 1. Direct hardware write to MTK/Transsion panel HBM node
        self.write_node(enabled);

        // 2. ColorOS display addon command files (fallback)
        self.write_addon(enabled);

        // 3. Disable is verified: a stale "on" here is the reported bug (panel stays
        //    lit after enrolment/authentication already finished).
        if !enabled {
            for attempt in 1..=OFF_RETRIES {
                match read_tran() {
                    Some(0) | None => break,
                    Some(v) => {
                        log_warn!(
                            "HBM still on (node={}) after disable, retry {}/{}",
                            v, attempt, OFF_RETRIES
                        );
                        std::thread::sleep(Duration::from_millis(OFF_RETRY_GAP_MS));
                        self.write_node(false);
                        self.write_addon(false);
                    }
                }
            }
            if let Some(v) = read_tran() {
                if v != 0 {
                    log_warn!("HBM node still reports {} after {} retries", v, OFF_RETRIES);
                }
            }
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

/// Turns HBM off only when the generation is still the one that armed the
/// watchdog, so a newer press/disable is never overridden.
fn force_off_if_generation(expected: u64) {
    let mut lock = GLOBAL_HBM.lock();
    if HBM_GENERATION.load(Ordering::SeqCst) != expected {
        return;
    }
    HBM_GENERATION.fetch_add(1, Ordering::SeqCst);
    if let Some(ctrl) = lock.as_mut() {
        log_warn!(
            "HBM safety watchdog: forced off after {}ms without pointer-up",
            HBM_SAFETY_TIMEOUT_MS
        );
        ctrl.write(false);
    }
}

/// True while this bridge believes the panel backlight boost is on.
pub fn is_enabled() -> bool {
    GLOBAL_HBM.lock().as_ref().map_or(false, |c| c.is_enabled)
}

pub fn set_hbm(enabled: bool) -> bool {
    set_hbm_sync(enabled, 0)
}

/// Enables/disables HBM. For `enabled == true` with `max_wait_ms > 0` this waits
/// until the panel node confirms the boost, returning `false` on timeout. A
/// missing node counts as confirmed (nothing to poll on such a panel).
pub fn set_hbm_sync(enabled: bool, max_wait_ms: u64) -> bool {
    {
        let mut lock = GLOBAL_HBM.lock();
        if lock.is_none() {
            *lock = Some(HbmController::new());
        }
        match lock.as_mut() {
            Some(ctrl) => ctrl.write(enabled),
            None => return false,
        }
    }

    if !enabled || max_wait_ms == 0 {
        return true;
    }

    let deadline = Instant::now() + Duration::from_millis(max_wait_ms);
    loop {
        match read_tran() {
            Some(1) => return true,
            // No readable node: nothing to confirm against.
            None => return true,
            _ => {}
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

use std::fs::{File, OpenOptions};
use std::io;
use parking_lot::Mutex;
use crate::{log_error, log_info, log_warn};

/// Fixed settle delay after enabling HBM. lcm_hbm_state always reads back a constant (0xFA on X6886),
/// so it cannot be used as an ack; we do not poll it.
pub const HBM_SETTLE_MS: u64 = 50;

const HBM_PRIMARY: &str = "/sys/kernel/tran_display/lcm_hbm_state";
const OPLUS_DISPLAY_DIR: &str = "/data/addon/oplus_display";
const OPLUS_DISPLAY_HBM: &str = "/data/addon/oplus_display/hbm";

const HBM_CANDIDATES: &[&str] = &[
    "/sys/kernel/tran_display/lcm_hbm_state", // Transsion/Infinix primary
    "/sys/devices/platform/soc/14013000.dsi/lcm_hbm_state", // MT6789 / Helio G99 / Dimensity
    "/sys/devices/platform/soc/14000000.dispsys_config/lcm_hbm_state",
    "/sys/class/drm/card0-DSI-1/hbm",
];


pub struct HbmController {
    active_path: Option<String>,
    hbm_file: Option<File>,
    is_enabled: bool,
}

static GLOBAL_HBM: Mutex<Option<HbmController>> = Mutex::new(None);
static HBM_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl HbmController {
    pub fn new() -> Self {
        let mut ctrl = Self {
            active_path: None,
            hbm_file: None,
            is_enabled: false,
        };
        ctrl.init();
        ctrl
    }

    fn init(&mut self) {
        if self.hbm_file.is_some() {
            return;
        }

        // 1. Check known candidates
        for &path in HBM_CANDIDATES {
            if std::path::Path::new(path).exists() {
                log_info!("Found LCM HBM control node at {}", path);
                self.active_path = Some(path.to_string());
                self.hbm_file = OpenOptions::new().read(true).write(true).open(path).ok();
                return;
            }
        }

        // 2. Dynamic platform soc search
        if let Ok(dir) = std::fs::read_dir("/sys/devices/platform/soc") {
            for entry in dir.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.contains(".dsi") {
                    let path = format!("/sys/devices/platform/soc/{}/lcm_hbm_state", name);
                    if std::path::Path::new(&path).exists() {
                        log_info!("Discovered LCM HBM node at {}", path);
                        self.active_path = Some(path.clone());
                        self.hbm_file = OpenOptions::new().read(true).write(true).open(&path).ok();
                        return;
                    }
                }
            }
        }

        log_error!("No LCM HBM node found!");
    }

    pub fn write_hbm(&mut self, enabled: bool) -> io::Result<()> {
        let _ = self.write_hbm_sync(enabled, if enabled { 500 } else { 0 });
        Ok(())
    }

    pub fn write_hbm_sync(&mut self, enabled: bool, max_wait_ms: u64) -> bool {
        let path = self.active_path.as_deref().unwrap_or(HBM_PRIMARY);

        if enabled {
            let gen = HBM_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;

            // Safety watchdog: guarantees HBM can NEVER remain on for > 800ms
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(800));
                if HBM_GENERATION.load(std::sync::atomic::Ordering::SeqCst) == gen {
                    log_warn!("Hardware LCM HBM safety watchdog: forced HBM off after 800ms timeout");
                    set_hbm(false);
                }
            });

            let _ = std::fs::create_dir_all(OPLUS_DISPLAY_DIR);
            let _ = std::fs::write(OPLUS_DISPLAY_HBM, b"1\n");

            let _ = max_wait_ms;
            let _ = std::fs::write(path, b"1\n");
            self.is_enabled = true;
            log_info!("Hardware LCM HBM enabled");
            true
        } else {
            HBM_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.is_enabled = false;
            let _ = std::fs::write(OPLUS_DISPLAY_HBM, b"0\n");
            let _ = std::fs::write(path, b"0\n");
            log_info!("Hardware LCM HBM disabled");
            true
        }
    }
}

pub fn set_hbm(enabled: bool) -> bool {
    set_hbm_sync(enabled, if enabled { HBM_SETTLE_MS } else { 0 })
}

pub fn set_hbm_sync(enabled: bool, settle_ms: u64) -> bool {
    // Hold the global lock only for the sysfs write, never while sleeping,
    // so set_hbm(false) from the HAL callback thread is never blocked.
    let ok = {
        let mut lock = GLOBAL_HBM.lock();
        if lock.is_none() {
            *lock = Some(HbmController::new());
        }
        match lock.as_mut() {
            Some(ctrl) => ctrl.write_hbm_sync(enabled, 0),
            None => false,
        }
    };
    if enabled && settle_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(settle_ms));
    }
    ok
}

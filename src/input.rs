use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use parking_lot::Mutex;
use crate::{log_info, log_warn};

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_ABS: u16 = 0x03;
pub const FOD_KEYCODE: u16 = 195;     // 0x00c3 on FocalTech / Transsion mtk-tpd
pub const KEY_GESTURE_38: u16 = 38;    // 0x0026 on FocalTech FT3683G (Gesture ID 38 FOD tap in deep sleep)
pub const KEY_F20: u16 = 190;         // 0x00be on adaptive-ts when gesture is 0xbe (FOD)
pub const KEY_F13: u16 = 183;         // 0x00b7 on adaptive-ts when gesture is 0xcc (Gesture Click)
pub const BTN_TOUCH: u16 = 330;
pub const ABS_MT_POSITION_X: u16 = 0x35;
pub const ABS_MT_POSITION_Y: u16 = 0x36;
pub const ABS_MT_TRACKING_ID: u16 = 0x39;

// Goodix MTK touchscreen scaling factor for Infinix GT 20 Pro (x6860-g3t)
// Raw touch coordinates from mtk-tpd (max ~17279, 38399) scale by 1/16 to panel logical coords
pub const TOUCH_SCALE_FACTOR: i32 = 16;
pub const TOUCH_MAX_X: i32 = 17279;
pub const TOUCH_MAX_Y: i32 = 38399;

// Calibrated Optical FOD Sensor Location & Touch Target for Infinix GT 20 Pro (x6860-g3t, MT6789)
// Hardware property persist.vendor.fingerprint.optical.sensorlocation: [550::2171], diameter: 228 (radius: 114)
pub const FOD_CENTER_X: i32 = 550;
pub const FOD_CENTER_Y: i32 = 2171;
pub const FOD_TOUCH_RADIUS: i32 = 140; // 114px sensor radius + 26px thumb margin
pub const FOD_TOUCH_RADIUS_SQ: i32 = FOD_TOUCH_RADIUS * FOD_TOUCH_RADIUS; // 19600

#[inline]
pub fn is_inside_fod_area(x: i32, y: i32) -> bool {
    if x < 0 || y < 0 {
        return false;
    }
    let dx = x - FOD_CENTER_X;
    let dy = y - FOD_CENTER_Y;
    (dx * dx + dy * dy) <= FOD_TOUCH_RADIUS_SQ
}

const KEY_CNT: usize = 768;
const ULONG_BITS: usize = 8 * std::mem::size_of::<libc::c_ulong>();
const KEY_WORDS: usize = (KEY_CNT + ULONG_BITS - 1) / ULONG_BITS;

#[cfg(target_os = "android")]
type IoctlReq = libc::c_int;
#[cfg(not(target_os = "android"))]
type IoctlReq = libc::c_ulong;

const EVIOCGNAME_128: IoctlReq = 0x80804506u32 as IoctlReq;
const EVIOCGBIT_KEY: IoctlReq = 0x80684521u32 as IoctlReq;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct InputEvent {
    pub time: libc::timeval,
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

pub fn acquire_wakelock(name: &str) {
    if let Err(e) = std::fs::write("/sys/power/wake_lock", name.as_bytes()) {
        crate::log_debug!("acquire_wakelock({name}) error: {e}");
    } else {
        crate::log_info!("Acquired wakelock: {name}");
    }
}

pub fn release_wakelock(name: &str) {
    if let Err(e) = std::fs::write("/sys/power/wake_unlock", name.as_bytes()) {
        crate::log_debug!("release_wakelock({name}) error: {e}");
    } else {
        crate::log_info!("Released wakelock: {name}");
    }
}

static GESTURE_INITIAL_LOG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn ensure_gesture_fod_enabled() {
    let first = !GESTURE_INITIAL_LOG.swap(true, std::sync::atomic::Ordering::SeqCst);
    if let Err(e) = std::fs::write("/proc/fingerprint_status", b"1") {
        if first { log_warn!("Failed to write 1 to /proc/fingerprint_status: {e}"); }
    } else if first {
        log_info!("Ensured /proc/fingerprint_status has 1");
    }

    if let Err(e) = std::fs::write("/proc/gesture_function", b"fp1") {
        if first { log_warn!("Failed to write fp1 to /proc/gesture_function: {e}"); }
    } else if first {
        log_info!("Ensured /proc/gesture_function has fp1");
    }

    let fts_node = "/sys/class/input/event4/device/device/fts_gesture_mode";
    if std::path::Path::new(fts_node).exists() {
        if let Err(e) = std::fs::write(fts_node, b"1") {
            if first { log_warn!("Failed to write 1 to {fts_node}: {e}"); }
        } else if first {
            log_info!("Ensured {fts_node} has 1");
        }
    }
}

pub fn get_fts_gesture_point() -> Option<(i32, i32)> {
    let content = std::fs::read_to_string("/sys/class/input/event4/device/device/fts_gesture_buf").ok()?;
    let start = content.find("0(")?;
    let slice = &content[start + 2..];
    let end = slice.find(')')?;
    let coords = &slice[..end];
    let mut parts = coords.split(',');
    let x: i32 = parts.next()?.trim().parse().ok()?;
    let y: i32 = parts.next()?.trim().parse().ok()?;
    Some((x, y))
}

pub fn test_bit(bit: usize, arr: &[libc::c_ulong]) -> bool {
    let word = bit / ULONG_BITS;
    let offset = bit % ULONG_BITS;
    if word < arr.len() {
        ((arr[word] >> offset) & 1) != 0
    } else {
        false
    }
}

pub fn get_device_name(fd: libc::c_int) -> String {
    let mut name_buf = [0u8; 128];
    let res = unsafe { libc::ioctl(fd, EVIOCGNAME_128, name_buf.as_mut_ptr()) };
    if res >= 0 {
        CStr::from_bytes_until_nul(&name_buf)
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        String::new()
    }
}

pub fn get_key_bits(fd: libc::c_int) -> [libc::c_ulong; KEY_WORDS] {
    let mut key_bits = [0 as libc::c_ulong; KEY_WORDS];
    unsafe {
        libc::ioctl(fd, EVIOCGBIT_KEY, key_bits.as_mut_ptr());
    }
    key_bits
}

pub fn find_fod_touch_device() -> Option<(File, String)> {
    let dir = std::fs::read_dir("/dev/input").ok()?;
    for entry in dir.flatten() {
        let path = entry.path();
        let file_name = path.file_name()?.to_string_lossy();
        if !file_name.starts_with("event") {
            continue;
        }

        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(f) => f,
            Err(_) => continue,
        };

        let fd = file.as_raw_fd();
        let name = get_device_name(fd);
        let key_bits = get_key_bits(fd);

        let mut matches = false;
        if test_bit(FOD_KEYCODE as usize, &key_bits)
            || test_bit(KEY_GESTURE_38 as usize, &key_bits)
            || test_bit(KEY_F20 as usize, &key_bits)
            || test_bit(KEY_F13 as usize, &key_bits)
        {
            matches = true;
        } else if name == "mtk-tpd" {
            matches = true;
        }

        if matches {
            let path_str = path.to_string_lossy().into_owned();
            log_info!("Found FOD touch device: {} ({})", path_str, name);
            return Some((file, path_str));
        }
    }

    None
}

static LAST_WAKE_TIME: Mutex<Option<std::time::Instant>> = Mutex::new(None);

pub fn find_power_key_device() -> Option<(File, String)> {
    let dir = std::fs::read_dir("/dev/input").ok()?;
    for entry in dir.flatten() {
        let path = entry.path();
        let file_name = path.file_name()?.to_string_lossy();
        if !file_name.starts_with("event") {
            continue;
        }

        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(f) => f,
            Err(_) => continue,
        };

        let fd = file.as_raw_fd();
        let name = get_device_name(fd);
        let key_bits = get_key_bits(fd);

        // Prefer mtk-pmic-keys or device declaring KEY_POWER (116)
        if name.contains("pmic-keys") || (test_bit(116, &key_bits) && !name.contains("tpd")) {
            let path_str = path.to_string_lossy().into_owned();
            log_info!("Found power key device: {} ({})", path_str, name);
            return Some((file, path_str));
        }
    }

    None
}

pub fn wake_display_pipeline() {
    // Goodix/ColorOS: Do NOT inject KEY_POWER (116) here.
    // ColorOS theiaPwkReport detects KEY_POWER and cancels AOD auth with CANCELED_forAod / CANCELED_sleepLocked.
    // Display wake is handled by Binder transact 1001 (cmd 1201) in notify_framework_touch().
    log_info!("wake_display_pipeline: KEY_POWER injection suppressed for Goodix/ColorOS compatibility");
}

pub fn start_screen_off_touch_monitor(hal: Arc<crate::hal::FingerprintHal>) {
    ensure_gesture_fod_enabled();

    std::thread::Builder::new()
        .name("fod_touch_monitor".to_string())
        .spawn(move || {
            loop {
                ensure_gesture_fod_enabled();

                let (file, path) = match find_fod_touch_device() {
                    Some(pair) => pair,
                    None => {
                        log_warn!("Waiting for FOD touch device (/dev/input/event*)...");
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        continue;
                    }
                };

                log_info!("FOD touch monitor active on {}", path);
                let fd = file.as_raw_fd();
                let mut is_down = false;
                let mut last_down_time = std::time::Instant::now();
                let mut last_rearm_time = std::time::Instant::now();
                let mut cur_x: i32 = -1;
                let mut cur_y: i32 = -1;
                let mut touch_active = false;

                let event_size = std::mem::size_of::<InputEvent>();
                let mut buf = vec![0u8; event_size * 16];

                loop {
                    if last_rearm_time.elapsed() >= std::time::Duration::from_secs(3) {
                        last_rearm_time = std::time::Instant::now();
                        if hal.get_screen_state() == 0 {
                            ensure_gesture_fod_enabled();
                        }
                    }

                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ret = unsafe { libc::poll(&mut pfd, 1, 30) };

                    if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
                        use std::io::Read;
                        let mut f_ref = &file;
                        match f_ref.read(&mut buf) {
                            Ok(bytes_read) if bytes_read >= event_size => {
                                let num_events = bytes_read / event_size;
                                for i in 0..num_events {
                                    let offset = i * event_size;
                                    let event: InputEvent = unsafe {
                                        std::ptr::read_unaligned(
                                            buf[offset..].as_ptr() as *const InputEvent
                                        )
                                    };

                                    if event.type_ == EV_ABS {
                                        if event.code == ABS_MT_POSITION_X {
                                            cur_x = if event.value > 1080 { event.value / 16 } else { event.value };
                                        } else if event.code == ABS_MT_POSITION_Y {
                                            cur_y = if event.value > 2436 { event.value / 16 } else { event.value };
                                        } else if event.code == ABS_MT_TRACKING_ID {
                                            if event.value == -1 {
                                                touch_active = false;
                                                cur_x = -1;
                                                cur_y = -1;
                                                if is_down {
                                                    log_info!("Tracking ID lifted (-1) -> releasing FOD");
                                                    is_down = false;
                                                    hal.on_pointer_up();
                                                    release_wakelock("oplus_udfps_fod_wake");
                                                }
                                            } else {
                                                touch_active = true;
                                            }
                                        }
                                    } else if event.type_ == EV_KEY {
                                        if event.code == FOD_KEYCODE || event.code == KEY_GESTURE_38 {
                                            if event.value == 1 {
                                                let target = if cur_x >= 0 && cur_y >= 0 {
                                                    Some((cur_x, cur_y))
                                                } else {
                                                    get_fts_gesture_point()
                                                };

                                                match target {
                                                    Some((tx, ty)) => {
                                                        if is_inside_fod_area(tx, ty) {
                                                            // Only inject KEY_POWER if the display panel is completely OFF (deep sleep / DPMS off).
                                                            // When DPMS is ON (Awake or AOD/Doze), do NOT inject KEY_POWER as it aborts the AOD dream!
                                                            if !crate::hal::FingerprintHal::is_display_dpms_on() {
                                                                wake_display_pipeline();
                                                            }
                                                            acquire_wakelock("oplus_udfps_fod_wake");
                                                            log_info!(
                                                                "FOD touch detected in sleep at ({}, {}) (KEY {}, screen_state={}) -> activating HBM and capture",
                                                                tx, ty, event.code, hal.get_screen_state()
                                                            );
                                                            is_down = true;
                                                            last_down_time = std::time::Instant::now();
                                                            hal.on_pointer_down(tx, ty, 0.0, 0.0);
                                                        } else {
                                                            log_info!(
                                                                "FOD touch rejected at ({}, {}): outside calibrated FOD area (KEY {})",
                                                                tx, ty, event.code
                                                            );
                                                        }
                                                    }
                                                    None => {
                                                        log_info!("FOD KEY {} down received, waiting for coordinate in SYN_REPORT", event.code);
                                                    }
                                                }
                                            }
                                            // NOTE: We deliberately DO NOT cancel FOD on event.value == 0 (KEY up)!
                                            // The touch controller emits key release almost immediately (~250ms)
                                            // while the finger remains pressed. Real finger lift is tracked by
                                            // ABS_MT_TRACKING_ID == -1 and BTN_TOUCH == 0.
                                        } else if event.code == KEY_F20 || event.code == KEY_F13 {
                                            if event.value == 1 {
                                                let target = if cur_x >= 0 && cur_y >= 0 {
                                                    Some((cur_x, cur_y))
                                                } else {
                                                    get_fts_gesture_point()
                                                };
                                                if let Some((tx, ty)) = target {
                                                    if is_inside_fod_area(tx, ty) {
                                                        // Only inject KEY_POWER if the display panel is completely OFF (deep sleep / DPMS off).
                                                        // When DPMS is ON (Awake or AOD/Doze), do NOT inject KEY_POWER as it aborts the AOD dream!
                                                        if !crate::hal::FingerprintHal::is_display_dpms_on() {
                                                            wake_display_pipeline();
                                                        }
                                                        acquire_wakelock("oplus_udfps_fod_wake");
                                                        log_info!(
                                                            "FOD gesture pulse detected in sleep at ({}, {}) (KEY {}, screen_state={}) -> activating HBM and capture",
                                                            tx, ty, event.code, hal.get_screen_state()
                                                        );
                                                        is_down = true;
                                                        last_down_time = std::time::Instant::now();
                                                        hal.on_pointer_down(tx, ty, 0.0, 0.0);
                                                    }
                                                }
                                            }
                                        } else if event.code == BTN_TOUCH {
                                            if event.value == 1 {
                                                touch_active = true;
                                            } else if event.value == 0 {
                                                touch_active = false;
                                                cur_x = -1;
                                                cur_y = -1;
                                                if is_down {
                                                    log_info!("Touch release (BTN_TOUCH 0) detected -> resetting FOD");
                                                    is_down = false;
                                                    hal.on_pointer_up();
                                                    release_wakelock("oplus_udfps_fod_wake");
                                                }
                                            }
                                        }
                                    } else if event.type_ == EV_SYN && event.code == 0 {
                                        // SYN_REPORT: Full multi-touch frame synchronized
                                        // Only trigger when touch coordinate falls precisely inside calibrated FOD area!
                                        if touch_active && !is_down {
                                            if is_inside_fod_area(cur_x, cur_y) {
                                                // Only inject KEY_POWER if the display panel is completely OFF (deep sleep / DPMS off).
                                                // When DPMS is ON (Awake or AOD/Doze), do NOT inject KEY_POWER as it aborts the AOD dream!
                                                if !crate::hal::FingerprintHal::is_display_dpms_on() {
                                                    wake_display_pipeline();
                                                }
                                                log_info!("FOD touch coordinate confirmed via SYN_REPORT at ({}, {}) -> activating HBM and capture", cur_x, cur_y);
                                                is_down = true;
                                                last_down_time = std::time::Instant::now();
                                                hal.on_pointer_down(cur_x, cur_y, 0.0, 0.0);
                                            } else if cur_x >= 0 && cur_y >= 0 {
                                                // Coordinate is outside FOD area: completely ignore!
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(_) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(e) => {
                                log_warn!("Error reading from FOD touch device: {e}, re-opening...");
                                break;
                            }
                        }
                    } else if ret < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        log_warn!("Poll error: {err}, re-opening...");
                        break;
                    }

                    // If HAL cleared finger state (e.g. on screen transition to sleep/off or session cancel), sync is_down
                    if is_down && !hal.is_finger_down() {
                        is_down = false;
                        release_wakelock("oplus_udfps_fod_wake");
                    }

                    // Watchdog: prevent HBM from ever being stuck on (> 1500ms)
                    if is_down && last_down_time.elapsed() >= std::time::Duration::from_millis(1500) {
                        log_warn!("Watchdog: FOD touch timed out (1500ms) -> forcing HBM off");
                        is_down = false;
                        hal.on_pointer_up();
                        release_wakelock("oplus_udfps_fod_wake");
                    }
                }

                if is_down {
                    hal.on_pointer_up();
                    release_wakelock("oplus_udfps_fod_wake");
                }

                log_warn!("FOD touch device disconnected or error, re-opening in 1s...");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        })
        .expect("failed to spawn fod_touch_monitor thread");
}

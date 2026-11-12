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
pub const ABS_MT_SLOT: u16 = 47;
pub const ABS_MT_TOUCH_MAJOR: u16 = 48;
pub const ABS_MT_POSITION_X: u16 = 0x35;
pub const ABS_MT_POSITION_Y: u16 = 0x36;
pub const ABS_MT_TRACKING_ID: u16 = 0x39;
pub const SYN_REPORT: u16 = 0;

pub const SOFOD_TID: i32 = 900;
pub const SOFOD_MAJOR: i32 = 80;
pub const SOFOD_DELAY_MS: u64 = 200;
pub const SOFOD_HOLD_MS: u64 = 1000;

// Calibrated Optical FOD Sensor Location & Touch Target for Transsion Camon 30 Pro (1080x2436)
// Hardware property persist.vendor.fingerprint.optical.sensorlocation: [540::2172], diameter: 228 (radius: 114)
pub const FOD_CENTER_X: i32 = 540;
pub const FOD_CENTER_Y: i32 = 2172;
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

impl InputEvent {
    pub fn new(type_: u16, code: u16, value: i32) -> Self {
        Self {
            time: libc::timeval { tv_sec: 0, tv_usec: 0 },
            type_,
            code,
            value,
        }
    }
}

pub fn write_input_events(dev: &mut File, events: &[InputEvent]) -> std::io::Result<()> {
    use std::io::Write;
    let sz = std::mem::size_of::<InputEvent>() * events.len();
    let bytes = unsafe { std::slice::from_raw_parts(events.as_ptr() as *const u8, sz) };
    dev.write_all(bytes)
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

pub const KEY_WAKEUP: u16 = 143;

pub fn find_wake_key_device() -> Option<(File, String)> {
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

        if name.contains("tran-keys") || test_bit(KEY_WAKEUP as usize, &key_bits) {
            let path_str = path.to_string_lossy().into_owned();
            log_info!("Found wake key device: {} ({})", path_str, name);
            return Some((file, path_str));
        }
    }

    find_power_key_device()
}

pub fn wake_display_pipeline() {
    let mut last_wake = LAST_WAKE_TIME.lock();
    if let Some(t) = *last_wake {
        if t.elapsed() < std::time::Duration::from_millis(600) {
            log_info!("wake_display_pipeline: debounced (<600ms)");
            return;
        }
    }
    *last_wake = Some(std::time::Instant::now());

    let (dev_file, path, code) = match find_wake_key_device() {
        Some((f, p)) => {
            // Pilih keycode dari kemampuan device (bukan dari nama path), karena
            // path selalu "/dev/input/eventN" dan tidak pernah berisi "tran-keys".
            let bits = get_key_bits(f.as_raw_fd());
            let code = if test_bit(KEY_WAKEUP as usize, &bits) {
                KEY_WAKEUP
            } else {
                116
            };
            (f, p, code)
        }
        None => match OpenOptions::new().write(true).open("/dev/input/event2") {
            Ok(f) => (f, "/dev/input/event2".to_string(), KEY_WAKEUP),
            Err(_) => match OpenOptions::new().write(true).open("/dev/input/event0") {
                Ok(f) => (f, "/dev/input/event0".to_string(), 116),
                Err(e) => {
                    log_warn!("wake_display_pipeline: failed to open wake/power key device: {e}");
                    return;
                }
            },
        },
    };

    use std::io::Write;
    let mut dev = dev_file;
    let ev_down = InputEvent {
        time: libc::timeval { tv_sec: 0, tv_usec: 0 },
        type_: EV_KEY,
        code,
        value: 1,
    };
    let ev_syn = InputEvent {
        time: libc::timeval { tv_sec: 0, tv_usec: 0 },
        type_: EV_SYN,
        code: 0,
        value: 0,
    };
    let ev_up = InputEvent {
        time: libc::timeval { tv_sec: 0, tv_usec: 0 },
        type_: EV_KEY,
        code,
        value: 0,
    };

    let sz = std::mem::size_of::<InputEvent>();
    unsafe {
        let p_down = std::slice::from_raw_parts(&ev_down as *const _ as *const u8, sz);
        let p_syn = std::slice::from_raw_parts(&ev_syn as *const _ as *const u8, sz);
        let p_up = std::slice::from_raw_parts(&ev_up as *const _ as *const u8, sz);

        let _ = dev.write_all(p_down);
        let _ = dev.write_all(p_syn);
        std::thread::sleep(std::time::Duration::from_millis(15));
        let _ = dev.write_all(p_up);
        let _ = dev.write_all(p_syn);
    }

    log_info!("wake_display_pipeline: injected KEY {} pulse via {} to exit doze/sleep", code, path);
}


/// Lama logo FOD ditahan (display tetap hidup) setelah sensor disentuh saat screen off.
pub const SOFOD_LOGO_HOLD_MS: u64 = 5000;
static LOGO_HOLD_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Fake SOFOD: saat layar benar-benar mati dan sensor ditekan, HAL hanya inject KEY_WAKEUP.
/// Capture TIDAK dilakukan sekarang; ditandai lewat `pending` dan dieksekusi oleh monitor loop
/// begitu layar sudah nyala, selama jari masih menempel (tidak perlu tekan ulang).
/// Wakelock ditahan SOFOD_LOGO_HOLD_MS supaya layar/logo tidak langsung padam.
/// Return true kalau event ini sudah ditangani (caller skip jalur capture lama).
pub fn try_screen_off_wake_only(
    hal: &Arc<crate::hal::FingerprintHal>,
    fired: &mut bool,
    pending: &mut Option<(std::time::Instant, i32, i32)>,
    x: i32,
    y: i32,
) -> bool {
    let screen_off = hal.get_screen_state() == 0 || !crate::hal::FingerprintHal::is_display_dpms_on();
    if !screen_off {
        return false;
    }
    if *fired {
        // sentuhan yang sama masih ditahan, jangan wake berulang
        return true;
    }
    *fired = true;

    log_info!("SOFOD fake: sensor pressed while screen off -> KEY_WAKEUP, auto-capture after display on (logo hold {}ms)", SOFOD_LOGO_HOLD_MS);
    wake_display_pipeline();
    *pending = Some((std::time::Instant::now(), x, y));

    acquire_wakelock("oplus_udfps_logo_hold");
    let gen = LOGO_HOLD_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(SOFOD_LOGO_HOLD_MS));
        if LOGO_HOLD_GEN.load(std::sync::atomic::Ordering::SeqCst) == gen {
            release_wakelock("oplus_udfps_logo_hold");
            log_info!("SOFOD wake-only: logo hold ended ({}ms)", SOFOD_LOGO_HOLD_MS);
        }
    });
    true
}

static SOFOD_REFIRE_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SOFOD_REFIRE_CANCEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn cancel_sofod_refire() {
    SOFOD_REFIRE_CANCEL.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub fn find_touchscreen_device() -> Option<String> {
    let dir = std::fs::read_dir("/dev/input").ok()?;
    for entry in dir.flatten() {
        let path = entry.path();
        let file_name = path.file_name()?.to_string_lossy();
        if !file_name.starts_with("event") {
            continue;
        }

        if let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
        {
            let name = get_device_name(file.as_raw_fd());
            if name == "mtk-tpd" {
                return Some(path.to_string_lossy().into_owned());
            }
        }
    }
    None
}

pub struct SofodConfig {
    pub delay_ms: u64,
    pub hold_ms: u64,
    pub major: i32,
    pub tid: i32,
}

impl Default for SofodConfig {
    fn default() -> Self {
        Self {
            delay_ms: SOFOD_DELAY_MS,
            hold_ms: SOFOD_HOLD_MS,
            major: SOFOD_MAJOR,
            tid: SOFOD_TID,
        }
    }
}

pub fn load_sofod_config() -> SofodConfig {
    let mut cfg = SofodConfig::default();
    if let Ok(content) = std::fs::read_to_string("/data/adb/fod/sofod_touch.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches('"').trim_matches('\'');
                match k {
                    "DELAY" => {
                        if let Ok(sec) = v.parse::<f64>() {
                            cfg.delay_ms = (sec * 1000.0) as u64;
                        }
                    }
                    "HOLD" => {
                        if let Ok(sec) = v.parse::<f64>() {
                            cfg.hold_ms = (sec * 1000.0) as u64;
                        }
                    }
                    "MAJOR" => {
                        if let Ok(m) = v.parse::<i32>() {
                            cfg.major = m;
                        }
                    }
                    "TID" => {
                        if let Ok(t) = v.parse::<i32>() {
                            cfg.tid = t;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    cfg
}

pub fn refire_sofod_touch(px: i32, py: i32, default_path: &str) {
    if SOFOD_REFIRE_BUSY.swap(true, std::sync::atomic::Ordering::SeqCst) {
        log_info!("SOFOD refire: already active, skipping duplicate");
        return;
    }
    SOFOD_REFIRE_CANCEL.store(false, std::sync::atomic::Ordering::SeqCst);

    let dev_path = find_touchscreen_device().unwrap_or_else(|| default_path.to_string());
    let px = if px > 0 { px } else { FOD_CENTER_X };
    let py = if py > 0 { py } else { FOD_CENTER_Y };

    std::thread::Builder::new()
        .name("sofod_refire".to_string())
        .spawn(move || {
            let mut dev = match OpenOptions::new().write(true).open(&dev_path) {
                Ok(f) => f,
                Err(e) => {
                    log_warn!("SOFOD refire: failed to open {} for writing: {e}", dev_path);
                    SOFOD_REFIRE_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
                    return;
                }
            };

            let cfg = load_sofod_config();

            // panel units: 16 per pixel (X max 17279, Y max 38399)
            let panel_x = (px * 16).min(17279);
            let panel_y = (py * 16).min(38399);

            std::thread::sleep(std::time::Duration::from_millis(cfg.delay_ms));
            if SOFOD_REFIRE_CANCEL.load(std::sync::atomic::Ordering::SeqCst) {
                log_info!("SOFOD refire: cancelled before touch_down");
                SOFOD_REFIRE_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
                return;
            }

            log_info!(
                "SOFOD refire: inject DOWN px=({},{}) panel=({},{}) to {}",
                px, py, panel_x, panel_y, dev_path
            );

            let down_events = [
                InputEvent::new(EV_ABS, ABS_MT_SLOT, 0),
                InputEvent::new(EV_ABS, ABS_MT_TRACKING_ID, cfg.tid),
                InputEvent::new(EV_ABS, ABS_MT_POSITION_X, panel_x),
                InputEvent::new(EV_ABS, ABS_MT_POSITION_Y, panel_y),
                InputEvent::new(EV_ABS, ABS_MT_TOUCH_MAJOR, cfg.major),
                InputEvent::new(EV_KEY, BTN_TOUCH, 1),
                InputEvent::new(EV_SYN, SYN_REPORT, 0),
            ];
            let _ = write_input_events(&mut dev, &down_events);

            let start = std::time::Instant::now();
            let hold_dur = std::time::Duration::from_millis(cfg.hold_ms);
            while start.elapsed() < hold_dur {
                if SOFOD_REFIRE_CANCEL.load(std::sync::atomic::Ordering::SeqCst) {
                    log_info!("SOFOD refire: finger lifted early, ending hold");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }

            log_info!("SOFOD refire: inject UP to {}", dev_path);
            let up_events = [
                InputEvent::new(EV_ABS, ABS_MT_SLOT, 0),
                InputEvent::new(EV_ABS, ABS_MT_TRACKING_ID, -1),
                InputEvent::new(EV_KEY, BTN_TOUCH, 0),
                InputEvent::new(EV_SYN, SYN_REPORT, 0),
            ];
            let _ = write_input_events(&mut dev, &up_events);

            SOFOD_REFIRE_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
        })
        .expect("failed to spawn sofod_refire thread");
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
                let mut wake_fired = false;
                let mut pending_capture: Option<(std::time::Instant, i32, i32)> = None;

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
                                                cancel_sofod_refire();
                                                touch_active = false;
                                                wake_fired = false;
                                                pending_capture = None;
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
                                                            if try_screen_off_wake_only(&hal, &mut wake_fired, &mut pending_capture, tx, ty) {
                                                                continue;
                                                            }
                                                            if !crate::hal::FingerprintHal::is_display_dpms_on() {
                                                                wake_display_pipeline();
                                                                std::thread::sleep(std::time::Duration::from_millis(60));
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
                                                        if try_screen_off_wake_only(&hal, &mut wake_fired, &mut pending_capture, tx, ty) {
                                                            continue;
                                                        }
                                                        if !crate::hal::FingerprintHal::is_display_dpms_on() {
                                                            wake_display_pipeline();
                                                            std::thread::sleep(std::time::Duration::from_millis(60));
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
                                                cancel_sofod_refire();
                                                touch_active = false;
                                                wake_fired = false;
                                                pending_capture = None;
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
                                        // Only trigger in deep sleep / doze. When screen is ON (state 1), framework dispatches onPointerDown!
                                        if touch_active && !is_down && hal.get_screen_state() != 1 {
                                            if is_inside_fod_area(cur_x, cur_y) {
                                                if try_screen_off_wake_only(&hal, &mut wake_fired, &mut pending_capture, cur_x, cur_y) {
                                                    continue;
                                                }
                                                if !crate::hal::FingerprintHal::is_display_dpms_on() {
                                                    wake_display_pipeline();
                                                    std::thread::sleep(std::time::Duration::from_millis(60));
                                                }
                                                log_info!("FOD touch coordinate confirmed via SYN_REPORT at ({}, {}) -> activating HBM and capture", cur_x, cur_y);
                                                is_down = true;
                                                last_down_time = std::time::Instant::now();
                                                hal.on_pointer_down(cur_x, cur_y, 0.0, 0.0);
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


                    // Fake SOFOD: layar sudah nyala setelah KEY_WAKEUP dan jari masih menempel
                    // -> langsung capture tanpa perlu tekan ulang.
                    if let Some((t0, px, py)) = pending_capture {
                        let el = t0.elapsed();
                        if el >= std::time::Duration::from_millis(1500) {
                            log_warn!("SOFOD fake: display did not come on within 1500ms, giving up");
                            pending_capture = None;
                        } else if crate::hal::FingerprintHal::is_display_dpms_on()
                            && el >= std::time::Duration::from_millis(120)
                        {
                            pending_capture = None;
                            // Beri waktu framework (keyguard) memulai sesi authenticate
                            let mut waited = 0;
                            while !hal.is_active() && waited < 1500 {
                                std::thread::sleep(std::time::Duration::from_millis(20));
                                waited += 20;
                            }
                            if !hal.is_active() {
                                log_info!("SOFOD fake: framework session not active after {}ms -> starting authenticate", waited);
                                hal.authenticate(0);
                            }
                            acquire_wakelock("oplus_udfps_fod_wake");
                            log_info!("SOFOD fake: display on, finger still held at ({}, {}) -> auto capture", px, py);
                            is_down = true;
                            last_down_time = std::time::Instant::now();
                            hal.on_pointer_down(px, py, 0.0, 0.0);
                            refire_sofod_touch(px, py, &path);
                        }
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

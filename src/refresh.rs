//! Lock the panel to 120Hz while the FOD is pressed, then restore the
//! original refresh rate 4 seconds after the finger is lifted.
//!
//! Works through `Settings.System` (`min_refresh_rate` / `peak_refresh_rate`),
//! which DisplayModeDirector reads. The original values are saved on the first
//! lock and written back on restore; a key that was unset is deleted again.
//!
//! All the shell work runs on worker threads, so `on_pointer_down` is never
//! delayed by process spawning. A generation counter makes the pending restore
//! cancel itself whenever a newer press or release arrives.

use crate::{log_debug, log_info, log_warn};
use parking_lot::Mutex;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Refresh rate forced while the finger is on the sensor.
const LOCK_FPS: &str = "120.0";
/// Delay between finger-up and restoring the original refresh rate.
const RESTORE_DELAY_MS: u64 = 4_000;
/// Guard against accidental touches: the lock only happens if the finger is
/// still down after this long. A brush over the sensor (shorter than this)
/// never touches the refresh rate.
const LOCK_DEBOUNCE_MS: u64 = 50;
/// Safety net: restore anyway if no finger-up ever arrives.
const SAFETY_TIMEOUT_MS: u64 = 15_000;

const KEYS: &[&str] = &["min_refresh_rate", "peak_refresh_rate"];

struct State {
    /// Original value of each key in `KEYS`; `None` = key was unset.
    saved: Option<Vec<Option<String>>>,
}

static STATE: Mutex<State> = Mutex::new(State { saved: None });
static GENERATION: AtomicU64 = AtomicU64::new(0);

fn run_settings(args: &[&str]) -> Option<String> {
    for bin in ["/system/bin/cmd", "/system/bin/settings"] {
        let mut cmd = Command::new(bin);
        if bin.ends_with("/cmd") {
            cmd.arg("settings");
        }
        match cmd.args(args).output() {
            Ok(out) if out.status.success() => {
                return Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
            }
            Ok(out) => {
                log_debug!(
                    "refresh: {} {:?} exited with {:?}",
                    bin,
                    args,
                    out.status.code()
                );
            }
            Err(e) => {
                log_debug!("refresh: cannot run {}: {}", bin, e);
            }
        }
    }
    None
}

fn get_key(key: &str) -> Option<String> {
    let v = run_settings(&["get", "system", key])?;
    if v.is_empty() || v == "null" {
        None
    } else {
        Some(v)
    }
}

fn put_key(key: &str, value: &str) -> bool {
    run_settings(&["put", "system", key, value]).is_some()
}

fn delete_key(key: &str) -> bool {
    run_settings(&["delete", "system", key]).is_some()
}

/// Runs one settings call per key in parallel, so the lock costs one process
/// round-trip instead of one per key.
fn put_all(values: &[&str]) -> bool {
    std::thread::scope(|sc| {
        let handles: Vec<_> = KEYS
            .iter()
            .zip(values.iter())
            .map(|(k, v)| sc.spawn(move || put_key(k, v)))
            .collect();
        handles.into_iter().all(|h| h.join().unwrap_or(false))
    })
}

fn get_all() -> Vec<Option<String>> {
    std::thread::scope(|sc| {
        let handles: Vec<_> = KEYS.iter().map(|k| sc.spawn(move || get_key(k))).collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or(None))
            .collect()
    })
}

fn is_locked_value(v: Option<&str>) -> bool {
    match (v.and_then(|x| x.parse::<f32>().ok()), LOCK_FPS.parse::<f32>()) {
        (Some(cur), Ok(lock)) => (cur - lock).abs() < 0.5,
        _ => false,
    }
}

fn apply_lock() {
    let mut st = STATE.lock();
    if st.saved.is_some() {
        // Already locked (a new press inside the 4s restore window): nothing to do.
        return;
    }

    let originals = get_all();
    if put_all(&[LOCK_FPS, LOCK_FPS]) {
        log_info!(
            "refresh: locked to {}Hz (saved originals: {:?})",
            LOCK_FPS,
            originals
        );
        st.saved = Some(originals);
    } else {
        log_warn!("refresh: failed to write refresh rate settings (SELinux?)");
        // Roll back whatever did get written so nothing stays half-locked.
        for (key, orig) in KEYS.iter().zip(originals.iter()) {
            match orig {
                Some(v) => {
                    put_key(key, v);
                }
                None => {
                    delete_key(key);
                }
            }
        }
    }
}

fn apply_restore(expected_gen: u64) {
    let mut st = STATE.lock();
    // A newer press/release arrived while we were waiting for the lock.
    if GENERATION.load(Ordering::SeqCst) != expected_gen {
        return;
    }
    let Some(originals) = st.saved.take() else {
        return;
    };
    for (key, orig) in KEYS.iter().zip(originals.iter()) {
        // Guard: only restore a key that still holds our locked value. If the
        // user or the framework changed it meanwhile, that value wins.
        if !is_locked_value(get_key(key).as_deref()) {
            log_info!("refresh: {} changed by someone else, not restoring", key);
            continue;
        }
        match orig {
            Some(v) => {
                put_key(key, v);
            }
            None => {
                delete_key(key);
            }
        }
    }
    log_info!("refresh: restored original refresh rate ({:?})", originals);
}

fn schedule_restore(generation: u64, delay_ms: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(delay_ms));
        if GENERATION.load(Ordering::SeqCst) == generation {
            apply_restore(generation);
        }
    });
}

/// Finger is on the FOD: lock to 120Hz. Returns immediately.
pub fn lock_high() {
    let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(LOCK_DEBOUNCE_MS));
        // Finger lifted (release) or a newer press/keep-alive superseded us
        // during the debounce: it was an accidental touch, leave the rate alone.
        if GENERATION.load(Ordering::SeqCst) != generation {
            log_debug!("refresh: touch shorter than {}ms, lock skipped", LOCK_DEBOUNCE_MS);
            return;
        }
        apply_lock();
    });
    // Safety net in case the matching `release()` never comes.
    schedule_restore(generation, SAFETY_TIMEOUT_MS);
}

/// Finger left the FOD: restore the original refresh rate after 4 seconds,
/// unless the finger comes back first. Returns immediately.
pub fn release() {
    let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    schedule_restore(generation, RESTORE_DELAY_MS);
}

/// Finger is still held and the capture was re-armed: push the safety timeout
/// back without touching the settings again.
pub fn keep_alive() {
    let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    schedule_restore(generation, SAFETY_TIMEOUT_MS);
}

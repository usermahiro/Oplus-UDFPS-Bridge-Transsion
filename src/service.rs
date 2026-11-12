use std::sync::Arc;
use rsbinder::Strong;

use crate::android::hardware::biometrics::common::CommonProps::CommonProps;
use crate::android::hardware::biometrics::common::ICancellationSignal::{
    BnCancellationSignal, ICancellationSignal,
};
use crate::android::hardware::biometrics::common::OperationContext::OperationContext;
use crate::android::hardware::biometrics::fingerprint::FingerprintSensorType::FingerprintSensorType;
use crate::android::hardware::biometrics::fingerprint::IFingerprint::{BnFingerprint, IFingerprint};
use crate::android::hardware::biometrics::fingerprint::ISession::{BnSession, ISession};
use crate::android::hardware::biometrics::fingerprint::ISessionCallback::ISessionCallback;
use crate::android::hardware::biometrics::fingerprint::PointerContext::PointerContext;
use crate::android::hardware::biometrics::fingerprint::SensorLocation::SensorLocation;
use crate::android::hardware::biometrics::fingerprint::SensorProps::SensorProps;
use crate::android::hardware::biometrics::fingerprint::SensorShape::SensorShape;
use crate::android::hardware::keymaster::HardwareAuthToken::HardwareAuthToken;
use crate::hal::{hw_auth_token_t, FingerprintHal};
use crate::{log_debug, log_error, log_info, log_warn};
use crate::{COMMON_INTERFACE_HASH, COMMON_INTERFACE_VERSION};

pub struct CancellationSignalService {
    hal: Option<Arc<FingerprintHal>>,
}

impl CancellationSignalService {
    pub fn new(hal: Option<Arc<FingerprintHal>>) -> Self {
        Self { hal }
    }
}

impl rsbinder::Interface for CancellationSignalService {}

impl ICancellationSignal for CancellationSignalService {
    fn r#cancel(&self) -> rsbinder::BinderResult<()> {
        log_info!("ICancellationSignal::cancel invoked");
        if let Some(ref hal) = self.hal {
            hal.cancel();
        }
        Ok(())
    }

    fn r#getInterfaceVersion(&self) -> rsbinder::BinderResult<i32> {
        Ok(COMMON_INTERFACE_VERSION)
    }

    fn r#getInterfaceHash(&self) -> rsbinder::BinderResult<String> {
        Ok(COMMON_INTERFACE_HASH.to_string())
    }
}

pub struct SessionService {
    #[allow(dead_code)]
    sensor_id: i32,
    #[allow(dead_code)]
    user_id: i32,
    cb: Strong<dyn ISessionCallback>,
    hal: parking_lot::Mutex<Option<Arc<FingerprintHal>>>,
}

impl SessionService {
    pub fn new(
        sensor_id: i32,
        user_id: i32,
        cb: Strong<dyn ISessionCallback>,
        hal: Option<Arc<FingerprintHal>>,
    ) -> Self {
        Self {
            sensor_id,
            user_id,
            cb,
            hal: parking_lot::Mutex::new(hal),
        }
    }

    fn get_hal(&self) -> Option<Arc<FingerprintHal>> {
        let mut guard = self.hal.lock();
        if guard.is_none() {
            if let Ok(h) = FingerprintHal::get_instance() {
                let store_path = format!("/data/vendor_de/{}/fpdata", self.user_id);
                let _ = std::fs::create_dir_all(&store_path);
                h.set_callback(Some(self.cb.clone()));
                h.set_active_user(self.user_id, &store_path);
                *guard = Some(h);
            }
        }
        guard.clone()
    }
}

impl rsbinder::Interface for SessionService {}

impl ISession for SessionService {
    fn r#generateChallenge(&self) -> rsbinder::BinderResult<()> {
        log_info!("ISession::generateChallenge called");
        let cb = self.cb.clone();
        let hal_opt = self.get_hal();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            let challenge = match hal_opt.and_then(|h| h.pre_enroll().ok()) {
                Some(c) if c != 0 => c as i64,
                _ => {
                    let fallback = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0x1234567887654321)) | 1;
                    log_warn!("pre_enroll returned 0 or failed; using fallback challenge 0x{:x}", fallback);
                    fallback as i64
                }
            };
            log_info!("Dispatching onChallengeGenerated(0x{:x}) asynchronously", challenge);
            if let Err(e) = cb.onChallengeGenerated(challenge) {
                log_error!("cb.onChallengeGenerated failed: {e}");
            }
        });
        Ok(())
    }

    fn r#revokeChallenge(&self, challenge: i64) -> rsbinder::BinderResult<()> {
        log_info!("ISession::revokeChallenge called (challenge=0x{:x})", challenge);
        let cb = self.cb.clone();
        let hal_opt = self.get_hal();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            if let Some(hal) = hal_opt {
                hal.post_enroll(challenge as u64);
            }
            log_info!("Dispatching onChallengeRevoked(0x{:x}) asynchronously", challenge);
            if let Err(e) = cb.onChallengeRevoked(challenge) {
                log_error!("cb.onChallengeRevoked failed: {e}");
            }
        });
        Ok(())
    }

    fn r#enroll(&self, hat: &HardwareAuthToken) -> rsbinder::BinderResult<Strong<dyn ICancellationSignal>> {
        log_info!("ISession::enroll called (challenge=0x{:x}, userId={})", hat.challenge, hat.userId);
        let hal_opt = self.get_hal();
        if let Some(ref hal) = hal_opt {
            let raw_hat = hw_auth_token_t::from_aidl(hat);
            let ret = hal.enroll(&raw_hat, 60);
            if ret != 0 {
                log_warn!("hal.enroll returned {ret}");
            }
        }
        let cancel = BnCancellationSignal::new_binder(CancellationSignalService::new(hal_opt));
        Ok(cancel)
    }

    fn r#authenticate(&self, operation_id: i64) -> rsbinder::BinderResult<Strong<dyn ICancellationSignal>> {
        log_info!("ISession::authenticate called (op_id=0x{:x})", operation_id);
        let hal_opt = self.get_hal();
        if let Some(ref hal) = hal_opt {
            let ret = hal.authenticate(operation_id as u64);
            if ret != 0 {
                log_warn!("hal.authenticate returned {ret}");
            }
        }
        let cancel = BnCancellationSignal::new_binder(CancellationSignalService::new(hal_opt));
        Ok(cancel)
    }

    fn r#detectInteraction(&self) -> rsbinder::BinderResult<Strong<dyn ICancellationSignal>> {
        log_info!("ISession::detectInteraction called");
        let cancel = BnCancellationSignal::new_binder(CancellationSignalService::new(self.get_hal()));
        Ok(cancel)
    }

    fn r#enumerateEnrollments(&self) -> rsbinder::BinderResult<()> {
        log_info!("ISession::enumerateEnrollments called -> scheduling asynchronous worker");
        let hal_opt = self.get_hal();
        let cb = self.cb.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            if let Some(hal) = hal_opt {
                hal.enumerate();
            } else {
                let _ = cb.onEnrollmentsEnumerated(&[]);
            }
        });
        Ok(())
    }

    fn r#removeEnrollments(&self, enrollment_ids: &[i32]) -> rsbinder::BinderResult<()> {
        log_info!("ISession::removeEnrollments called with ids {:?}", enrollment_ids);
        let ids = enrollment_ids.to_vec();
        let cb = self.cb.clone();
        let hal_opt = self.get_hal();
        std::thread::spawn(move || {
            if let Some(hal) = hal_opt {
                for &id in &ids {
                    hal.remove(id as u32);
                }
                // Allow up to 150ms for asynchronous notification from vendor HAL
                std::thread::sleep(std::time::Duration::from_millis(150));
                if hal.check_and_clear_remove_pending() {
                    log_info!("Vendor HAL did not dispatch remove notification; sending fallback onEnrollmentsRemoved({:?})", ids);
                    if let Err(e) = cb.onEnrollmentsRemoved(&ids) {
                        log_error!("cb.onEnrollmentsRemoved failed: {e}");
                    }
                }
            } else {
                let _ = cb.onEnrollmentsRemoved(&ids);
            }
        });
        Ok(())
    }

    fn r#getAuthenticatorId(&self) -> rsbinder::BinderResult<()> {
        log_info!("ISession::getAuthenticatorId called");
        let hal_opt = self.get_hal();
        let cb = self.cb.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            let auth_id = hal_opt.map(|h| h.get_authenticator_id()).unwrap_or(0);
            log_info!("Dispatching onAuthenticatorIdRetrieved(0x{:x}) asynchronously", auth_id);
            if let Err(e) = cb.onAuthenticatorIdRetrieved(auth_id as i64) {
                log_error!("cb.onAuthenticatorIdRetrieved failed: {e}");
            }
        });
        Ok(())
    }

    fn r#invalidateAuthenticatorId(&self) -> rsbinder::BinderResult<()> {
        log_info!("ISession::invalidateAuthenticatorId called");
        let hal_opt = self.get_hal();
        let cb = self.cb.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            let new_auth_id = hal_opt.map(|h| h.get_authenticator_id()).unwrap_or(0);
            log_info!("Dispatching onAuthenticatorIdInvalidated(0x{:x}) asynchronously", new_auth_id);
            if let Err(e) = cb.onAuthenticatorIdInvalidated(new_auth_id as i64) {
                log_error!("cb.onAuthenticatorIdInvalidated failed: {e}");
            }
        });
        Ok(())
    }

    fn r#resetLockout(&self, _hat: &HardwareAuthToken) -> rsbinder::BinderResult<()> {
        log_info!("ISession::resetLockout called");
        let cb = self.cb.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            log_info!("Dispatching onLockoutCleared asynchronously");
            if let Err(e) = cb.onLockoutCleared() {
                log_error!("cb.onLockoutCleared failed: {e}");
            }
        });
        Ok(())
    }

    fn r#close(&self) -> rsbinder::BinderResult<()> {
        log_info!("ISession::close called");
        if let Some(hal) = self.get_hal() {
            hal.cancel();
        }
        let cb = self.cb.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            log_info!("Dispatching onSessionClosed asynchronously");
            if let Err(e) = cb.onSessionClosed() {
                log_error!("cb.onSessionClosed failed: {e}");
            }
        });
        Ok(())
    }

    fn r#onPointerDown(&self, _pointer_id: i32, x: i32, y: i32, minor: f32, major: f32) -> rsbinder::BinderResult<()> {
        log_info!("onPointerDown at ({}, {}) minor={} major={}", x, y, minor, major);
        if let Some(hal) = self.get_hal() {
            hal.on_pointer_down(x, y, minor, major);
        }
        Ok(())
    }

    fn r#onPointerUp(&self, _pointer_id: i32) -> rsbinder::BinderResult<()> {
        log_info!("onPointerUp");
        if let Some(hal) = self.get_hal() {
            hal.on_pointer_up();
        }
        Ok(())
    }

    fn r#onUiReady(&self) -> rsbinder::BinderResult<()> {
        log_info!("onUiReady");
        if let Some(hal) = self.get_hal() {
            hal.on_ui_ready();
        }
        Ok(())
    }

    fn r#authenticateWithContext(
        &self,
        operation_id: i64,
        _context: &OperationContext,
    ) -> rsbinder::BinderResult<Strong<dyn ICancellationSignal>> {
        self.r#authenticate(operation_id)
    }

    fn r#enrollWithContext(
        &self,
        hat: &HardwareAuthToken,
        _context: &OperationContext,
    ) -> rsbinder::BinderResult<Strong<dyn ICancellationSignal>> {
        self.r#enroll(hat)
    }

    fn r#detectInteractionWithContext(
        &self,
        _context: &OperationContext,
    ) -> rsbinder::BinderResult<Strong<dyn ICancellationSignal>> {
        self.r#detectInteraction()
    }

    fn r#onPointerDownWithContext(&self, context: &PointerContext) -> rsbinder::BinderResult<()> {
        log_info!("onPointerDownWithContext at ({}, {}) (isAod={})", context.x, context.y, context.isAod);
        if let Some(hal) = self.get_hal() {
            hal.on_pointer_down(context.x as i32, context.y as i32, context.minor, context.major);
        }
        Ok(())
    }

    fn r#onPointerUpWithContext(&self, _context: &PointerContext) -> rsbinder::BinderResult<()> {
        log_info!("onPointerUpWithContext");
        if let Some(hal) = self.get_hal() {
            hal.on_pointer_up();
        }
        Ok(())
    }

    fn r#onContextChanged(&self, _context: &OperationContext) -> rsbinder::BinderResult<()> {
        log_debug!("onContextChanged");
        Ok(())
    }

    fn r#onPointerCancelWithContext(&self, _context: &PointerContext) -> rsbinder::BinderResult<()> {
        log_info!("onPointerCancelWithContext");
        if let Some(hal) = self.get_hal() {
            hal.on_pointer_up();
        }
        Ok(())
    }

    fn r#setIgnoreDisplayTouches(&self, _should_ignore: bool) -> rsbinder::BinderResult<()> {
        Ok(())
    }
}

pub struct FingerprintService;

impl FingerprintService {
    pub fn new() -> Self {
        Self
    }

    pub fn create_binder() -> Strong<dyn IFingerprint> {
        BnFingerprint::new_binder(Self::new())
    }
}

impl rsbinder::Interface for FingerprintService {}

impl IFingerprint for FingerprintService {
    fn r#getSensorProps(&self) -> rsbinder::BinderResult<Vec<SensorProps>> {
        log_info!("IFingerprint::getSensorProps called");
        let props = vec![SensorProps {
            r#commonProps: CommonProps {
                r#sensorId: 0,
                r#sensorStrength: 2, // SensorStrength::STRONG (15)
                r#maxEnrollmentsPerUser: 5,
                r#componentInfo: vec![],
            },
            r#sensorType: FingerprintSensorType::UNDER_DISPLAY_OPTICAL,
            r#sensorLocations: vec![SensorLocation {
                r#displayId: 0,
                r#sensorLocationX: 540,
                r#sensorLocationY: 2172,
                r#sensorRadius: 114,
                r#display: "".to_string(),
                r#sensorShape: SensorShape::CIRCLE,
            }],
            r#supportsNavigationGestures: false,
            r#supportsDetectInteraction: false,
            r#halHandlesDisplayTouches: false,
            r#halControlsIllumination: false,
            r#touchDetectionParameters: None,
        }];
        Ok(props)
    }

    fn r#createSession(
        &self,
        sensor_id: i32,
        user_id: i32,
        cb: &Strong<dyn ISessionCallback>,
    ) -> rsbinder::BinderResult<Strong<dyn ISession>> {
        log_info!("IFingerprint::createSession called (sensorId={}, userId={})", sensor_id, user_id);

        let mut hal_opt = FingerprintHal::get_instance().ok();
        if hal_opt.is_none() {
            log_warn!("FingerprintHal::get_instance failed on first try in createSession, retrying briefly...");
            for _ in 0..5 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Ok(h) = FingerprintHal::get_instance() {
                    hal_opt = Some(h);
                    break;
                }
            }
        }

        if let Some(ref hal) = hal_opt {
            let store_path = format!("/data/vendor_de/{}/fpdata", user_id);
            let _ = std::fs::create_dir_all(&store_path);
            hal.set_callback(Some(cb.clone()));
            hal.set_active_user(user_id, &store_path);
        } else {
            log_warn!("FingerprintHal not ready yet; session created in deferred mode (prevents system_server crash)");
        }

        let session = SessionService::new(sensor_id, user_id, cb.clone(), hal_opt);
        Ok(BnSession::new_binder(session))
    }
}

pub fn handle_oplus_custom_transact(
    reader: &mut rsbinder::Parcel,
    reply: &mut rsbinder::Parcel,
) -> rsbinder::Result<()> {
    let cmd_id: i32 = reader.read().unwrap_or(0);
    let in_len: i32 = reader.read().unwrap_or(0);
    let mut in_buffer = Vec::new();
    if in_len > 0 {
        if let Ok(buf) = reader.read::<Vec<u8>>() {
            in_buffer = buf;
        }
    }

    log_info!(
        "[handle_oplus_custom_transact] cmdId: {}, in_len: {}, in_buf_len: {}",
        cmd_id,
        in_len,
        in_buffer.len()
    );

    let res: i32 = match cmd_id {
        1010 => {
            // getEnrollmentTotalTimes: ColorOS expects total enrollment steps.
            // Silead optical UDFPS enrolls in 20 steps (remaining from 19 down to 0).
            log_info!("Handling OPlus custom cmd 1010 (getEnrollmentTotalTimes) -> returning 20 steps");
            20
        }
        1011 => {
            // notifyScreenStateToHal: in_buffer[0] = screenState (0 = off, 1 = on, 2 = aod/doze)
            let state = in_buffer.first().copied().unwrap_or(1) as i32;
            log_info!("Handling OPlus custom cmd 1011 (notifyScreenStateToHal) -> screenState: {}", state);
            if let Ok(hal) = FingerprintHal::get_instance() {
                hal.set_screen_state(state);
            }
            0
        }
        1023 => {
            // sFeatureFphalLockoutMode
            log_info!("Handling OPlus custom cmd 1023 (sFeatureFphalLockoutMode) -> 0");
            0
        }
        1001 => {
            // startSetFingerKeymode
            log_info!("Handling OPlus custom cmd 1001 (startSetFingerKeymode) -> 0");
            0
        }
        other => {
            log_info!("Handling OPlus unknown custom cmd {} -> 0", other);
            0
        }
    };

    reply.write(&rsbinder::Status::from(rsbinder::StatusCode::Ok))?;
    reply.write::<i32>(&res)?;
    Ok(())
}

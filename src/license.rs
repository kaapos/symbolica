//! License activation, verification, library unlocks, and execution limits.

use std::{
    cell::Cell,
    collections::HashMap,
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};
#[cfg(not(target_arch = "wasm32"))]
use std::{
    cell::RefCell,
    collections::HashSet,
    env,
    fs::{DirBuilder, File, OpenOptions, TryLockError},
    io::{self, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::abort,
    sync::{LazyLock, Mutex},
    time::Duration,
};

use data_encoding::BASE64URL_NOPAD;
#[cfg(not(target_arch = "wasm32"))]
use directories::ProjectDirs;
use ed25519_compact::{PublicKey, Signature};
use once_cell::sync::OnceCell;
#[cfg(not(target_arch = "wasm32"))]
use signed::{Purpose, verify};
use tinyjson::JsonValue;

pub(crate) const SYMBOLICA_PUBLIC_KEY: &str = "Symbol0xSzzb9RiGMF9hUS-YG6mM0aptGeWJ6gZ5syI";

const OUTDATED_LICENSE_KEY_ERROR: &str =
    "┌────────────────────────────────────────────────────────┐
│ The Symbolica license key format is outdated.          │
│ Renew your key at https://symbolica.io/license/        │
└────────────────────────────────────────────────────────┘";

static LICENSE_KEY: OnceCell<String> = OnceCell::new();
#[cfg(not(target_arch = "wasm32"))]
static LICENSE_MANAGER: OnceCell<LicenseManager> = OnceCell::new();
static LICENSED: AtomicBool = LicenseManager::init();

std::thread_local! {
    static INTERNAL_LICENSE_BYPASS_DEPTH: Cell<usize> = const { Cell::new(0) };
}

#[allow(dead_code)]
pub(crate) struct InternalLicenseBypassGuard;

impl InternalLicenseBypassGuard {
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        INTERNAL_LICENSE_BYPASS_DEPTH.with(|depth| {
            depth.set(
                depth
                    .get()
                    .checked_add(1)
                    .expect("license bypass scope nesting overflow"),
            );
        });
        Self
    }
}

impl Drop for InternalLicenseBypassGuard {
    fn drop(&mut self) {
        INTERNAL_LICENSE_BYPASS_DEPTH.with(|depth| {
            let current = depth.get();
            debug_assert!(current > 0, "unbalanced license bypass scope");
            depth.set(current.saturating_sub(1));
        });
    }
}

#[allow(dead_code)]
pub(crate) fn bypass_license_check_internal() -> InternalLicenseBypassGuard {
    InternalLicenseBypassGuard::new()
}

/// Manage the license of the Symbolica instance.
#[allow(dead_code)]
pub struct LicenseManager {
    has_license: bool,
}

#[cfg(not(target_arch = "wasm32"))]
struct RestrictedThreadPermit {
    pid: u32,
    _lock: File,
}

#[cfg(not(target_arch = "wasm32"))]
std::thread_local! {
    static RESTRICTED_THREAD_PERMIT: RefCell<Option<RestrictedThreadPermit>> = const { RefCell::new(None) };
}

/// Runtime capabilities that depend on the current target and enabled features.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionCapabilities {
    /// Whether this build requires a Symbolica license before unrestricted use.
    pub license_required: bool,
    /// Whether this instance is currently considered licensed.
    pub is_licensed: bool,
    /// Maximum number of worker threads Symbolica should use for licensed-gated parallel paths.
    pub max_threads: usize,
    /// Whether native code generation and shared-library evaluator loading are available.
    pub native_code_generation: bool,
    /// Whether the built-in license server networking path is available.
    pub license_networking: bool,
}

#[cfg(not(target_arch = "wasm32"))]
const RESTRICTED_THREAD_WARNING: &str = "┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Cannot start another restricted Symbolica thread while this user's thread allowance is in use.   │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘"
;

#[cfg(not(target_arch = "wasm32"))]
const RESOLVE_ERROR: &str = "
┌───────────────────────────────────────────────────────────┐
│ Could not resolve the IP of the Symbolica license server. │
│                                                           │
│ Please check your DNS configuration.                      │
└───────────────────────────────────────────────────────────┘";

#[cfg(not(target_arch = "wasm32"))]
const CONNECTION_ERROR: &str = "
┌────────────────────────────────────────────────┐
│ Could not connect to Symbolica license server. │
│                                                │
│ Some networks block traffic to uncommon ports. │
│ Consider switching networks or using a VPN.    │
└────────────────────────────────────────────────┘";

#[cfg(not(target_arch = "wasm32"))]
const NETWORK_ERROR: &str = "
┌───────────────────────────────────────────────────┐
│ Connection to Symbolica license server timed out. │
│                                                   │
│ Please check your network configuration.          │
└───────────────────────────────────────────────────┘";

#[cfg(not(target_arch = "wasm32"))]
const MISSING_LICENSE_ERROR: &str = "
┌───────────────────────────────┐
│ Symbolica license key missing │
└───────────────────────────────┘";

impl Default for LicenseManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Activate a signed OEM license bound to the calling crate.
/// Regular users should call [LicenseManager::set_license_key] instead.
#[macro_export]
macro_rules! activate_oem_license {
    ($key:literal) => {{
        $crate::license::LicenseManager::set_oem_license_key($key, env!("CARGO_CRATE_NAME"))
            .unwrap_or_else(|e| panic!("{}", e));
    }};
}

/// Verify and register a signed library unlock token for the calling Rust crate.
///
/// Store the returned [`LibraryUnlock`] and unlock each library operation with a guard.
///
/// A static `LibraryUnlock` must not be exported beyond the crate.
///
/// # Examples
///
/// ```no_run
/// use std::sync::LazyLock;
/// use symbolica::{license::LibraryUnlock, register_library_unlock};
///
/// pub(crate) static UNLOCK: LazyLock<LibraryUnlock> = LazyLock::new(|| {
///     register_library_unlock!("YOUR_KEY").unwrap()
/// });
///
/// fn main() {
///     let _unlock = UNLOCK.unlock();
/// }
/// ```
#[macro_export]
macro_rules! register_library_unlock {
    ($token:expr) => {{ $crate::license::LibraryUnlock::for_crate($token, env!("CARGO_CRATE_NAME")) }};
}

impl LicenseManager {
    #[inline]
    fn is_library_unlocked() -> bool {
        if current_thread_is_unlocked() {
            return true;
        }

        #[cfg(any(feature = "python_api", feature = "python_export"))]
        {
            if crate::api::python::has_library_unlock_frame() {
                return true;
            }
        }

        false
    }

    #[inline]
    fn is_check_bypassed() -> bool {
        INTERNAL_LICENSE_BYPASS_DEPTH.with(|depth| depth.get() != 0) || Self::is_library_unlocked()
    }

    /// Create a new license manager.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn new() -> LicenseManager {
        LICENSED.store(true, Relaxed);
        LicenseManager { has_license: true }
    }

    /// Create a new license manager.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn new() -> LicenseManager {
        match Self::check_license_key() {
            Ok(()) => {
                return LicenseManager { has_license: true };
            }
            Err(e) => {
                if !e.contains("missing") {
                    eprintln!("{e}");
                }
            }
        }

        if env::var("SYMBOLICA_HIDE_BANNER").is_err() {
            use std::io::IsTerminal;

            let styled = std::io::stdout().is_terminal()
                && env::var_os("NO_COLOR").is_none()
                && env::var_os("TERM").is_some_and(|term| term != "dumb");
            let (accent, bold, reset) = if styled {
                ("\x1b[36m", "\x1b[1m", "\x1b[0m")
            } else {
                ("", "", "")
            };
            println!(
                "┌────────────────────────────────────────────────────────┐
│ You are running a restricted Symbolica instance.       │
│                                                        │
│ For non-commercial use only, limited to one            │
│ Symbolica thread per user.                             │
│                                                        │
├─ {accent}Unlock all cores{reset} ─────────────────────────────────────┤
│                                                        │
│ {bold}Hobbyists and students: free annual key{reset}                │
│ https://symbolica.io/license/#get-hobbyist-license     │
│                                                        │
│ {bold}Free 30-day professional trial:{reset}                        │
│ https://symbolica.io/license/#get-trial-license        │
│                                                        │
└────────────────────────────────────────────────────────┘"
            );
        }

        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build_global();

        LicenseManager { has_license: false }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn acquire_restricted_thread_permit() {
        let pid = std::process::id();
        RESTRICTED_THREAD_PERMIT.with(|permit| {
            let mut permit = permit.borrow_mut();
            if permit.as_ref().is_some_and(|permit| permit.pid == pid) {
                return;
            }

            // A forked child must not share its parent's inherited lock description.
            *permit = None;
            match try_acquire_lock("symbolica-restricted-thread-0.lock") {
                Ok(Some(lock)) => {
                    *permit = Some(RestrictedThreadPermit { pid, _lock: lock });
                }
                Ok(None) => {
                    println!("{RESTRICTED_THREAD_WARNING}");
                    abort();
                }
                Err(error) => {
                    eprintln!("Could not acquire Symbolica thread permit: {error}");
                    println!("{RESTRICTED_THREAD_WARNING}");
                    abort();
                }
            }
        });
    }

    const fn init() -> AtomicBool {
        AtomicBool::new(false)
    }

    #[cfg(target_arch = "wasm32")]
    fn check_license_key() -> Result<(), String> {
        LICENSED.store(true, Relaxed);
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn check_license_key() -> Result<(), String> {
        let key = LICENSE_KEY
            .get()
            .cloned()
            .or(env::var("SYMBOLICA_LICENSE").ok());

        let Some(key) = key else {
            std::thread::spawn(|| {
                let mut m: HashMap<String, JsonValue> = HashMap::default();
                m.insert(
                    "version".to_owned(),
                    env!("CARGO_PKG_VERSION").to_owned().into(),
                );
                let mut v = JsonValue::from(m).stringify().unwrap();
                v.push('\n');

                if let Ok(mut stream) = Self::connect() {
                    let _ = stream.write_all(v.as_bytes());
                };
            });

            return Err(MISSING_LICENSE_ERROR.to_owned());
        };

        Self::validate_license_key(&key, Self::check_registration)?;

        LICENSED.store(true, Relaxed);
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn connect() -> Result<TcpStream, String> {
        let mut ip = ("symbolica.io", 12012)
            .to_socket_addrs()
            .map_err(|e| format!("{RESOLVE_ERROR}\nError: {e}"))?;
        let Some(n) = ip.next() else {
            return Err(RESOLVE_ERROR.to_owned());
        };

        let stream = match TcpStream::connect_timeout(&n, Duration::from_secs(5)) {
            Ok(stream) => stream,
            Err(_) => {
                return Err(CONNECTION_ERROR.to_owned());
            }
        };

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;

        Ok(stream)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn check_registration(key: String) -> Result<(), String> {
        let mut stream = Self::connect()?;

        let mut m: HashMap<String, JsonValue> = HashMap::default();
        m.insert(
            "version".to_owned(),
            env!("CARGO_PKG_VERSION").to_owned().into(),
        );
        m.insert("license".to_owned(), key.into());
        let mut v = JsonValue::from(m).stringify().unwrap();
        v.push('\n');

        stream
            .write_all(v.as_bytes())
            .map_err(|e| format!("{NETWORK_ERROR}\nError: {e}"))?;

        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .map_err(|e| format!("{NETWORK_ERROR}\nError: {e}"))?;
        let read_str =
            std::str::from_utf8(&buf).map_err(|e| format!("{NETWORK_ERROR}\nError: {e}"))?;

        if read_str == "{\"status\":\"ok\"}\n" {
            Ok(())
        } else if read_str.is_empty() {
            Err("┌──────────────────────────────────────────┐
│ Could not activate the Symbolica license │
└──────────────────────────────────────────┘"
                .to_owned())
        } else {
            let message: JsonValue = read_str[..read_str.len() - 1]
                .parse()
                .map_err(|e| format!("{NETWORK_ERROR}\nError: {e}"))?;
            let message_parsed: &HashMap<_, _> = message
                .get()
                .ok_or_else(|| format!("{NETWORK_ERROR}\nError: Empty response"))?;
            let status: &String = message_parsed
                .get("status")
                .unwrap()
                .get()
                .ok_or_else(|| format!("{NETWORK_ERROR}\nError: missing status"))?;
            Err(format!(
                "┌──────────────────────────────────────────┐
│ Could not activate the Symbolica license │
└──────────────────────────────────────────┘
Error: {status}",
            ))
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn validate_license_key(
        key: &str,
        check_registration: impl FnOnce(String) -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        if key.starts_with("S-")
            || key.starts_with("SL")
            || key.strip_prefix('S').is_some_and(|body| {
                body.starts_with(|c: char| c.is_ascii_digit())
                    || (body.contains('-') && body.contains('.'))
            })
        {
            verify(key, Purpose::Offline)?;
            Self::check_offline_license_registration(key.to_owned(), check_registration);
            Ok(())
        } else if key.contains('#') || key.starts_with("SYMBOLICA_OEM_") {
            Err(OUTDATED_LICENSE_KEY_ERROR.to_owned())
        } else {
            check_registration(key.to_owned())
        }
    }

    /// Check revocation without delaying activation or requiring network access.
    #[cfg(not(target_arch = "wasm32"))]
    fn check_offline_license_registration(
        key: String,
        check_registration: impl FnOnce(String) -> Result<(), String> + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            if let Err(error) = check_registration(key)
                && Self::offline_license_is_rejected(&error)
            {
                println!("{error}");
                abort();
            }
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn offline_license_is_rejected(error: &str) -> bool {
        let error = error.to_ascii_lowercase();
        ["banned", "revoked", "expired", "unknown license"]
            .iter()
            .any(|status| error.contains(status))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn check_library_unlock_registration(key: String) {
        std::thread::spawn(|| {
            if let Err(error) = Self::check_registration(key)
                && error.contains("Unknown license")
            {
                println!("{error}");
                abort();
            }
        });
    }

    #[inline(always)]
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn check() {
        LICENSED.store(true, Relaxed);
    }

    #[inline(always)]
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn check() {
        if LICENSED.load(Relaxed) || Self::is_check_bypassed() {
            return;
        }

        Self::check_impl();
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn check_impl() {
        let manager = LICENSE_MANAGER.get_or_init(LicenseManager::new);

        if manager.has_license {
            return;
        }

        Self::acquire_restricted_thread_permit();
    }

    /// Set the license key. Can only be called before calling any other Symbolica functions.
    /// Valid offline keys activate immediately and are also checked with the server in the
    /// background. A server-reported ban, revocation, expiration, or unknown license terminates
    /// the process; an unavailable server does not prevent offline use.
    pub fn set_license_key(key: &str) -> Result<(), String> {
        if LICENSE_KEY.get_or_init(|| key.to_owned()) != key {
            Err("Different license key cannot be set in same session")?;
        }

        Self::check_license_key()
    }

    /// Activate a signed OEM license. Use [crate::activate_oem_license] to supply the crate name.
    #[cfg(target_arch = "wasm32")]
    pub fn set_oem_license_key(_key: &str, _crate_name: &str) -> Result<(), String> {
        LICENSED.store(true, Relaxed);
        Ok(())
    }

    /// Activate a signed OEM license. Use [crate::activate_oem_license] to supply the crate name.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_oem_license_key(key: &str, crate_name: &str) -> Result<(), String> {
        verify(key, Purpose::Oem(crate_name))?;
        LICENSED.store(true, Relaxed);
        Ok(())
    }

    /// Returns `true` iff this instance has a valid license key set.
    #[cfg(target_arch = "wasm32")]
    pub fn is_licensed() -> bool {
        LICENSED.store(true, Relaxed);
        true
    }

    /// Returns `true` iff this instance has a valid license key or active library unlock.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn is_licensed() -> bool {
        LICENSED.load(Relaxed) || Self::is_library_unlocked() || Self::check_license_key().is_ok()
    }

    /// Clamp a requested worker-thread count to what the current target and license allow.
    pub fn max_threads(requested: usize) -> usize {
        #[cfg(target_arch = "wasm32")]
        {
            return requested.min(1);
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if Self::is_library_unlocked() {
                return requested;
            }

            if Self::is_licensed() {
                requested
            } else {
                requested.min(1)
            }
        }
    }

    /// Return target and licensing capabilities without requiring callers to know cfg details.
    pub fn execution_capabilities() -> ExecutionCapabilities {
        ExecutionCapabilities {
            license_required: !cfg!(target_arch = "wasm32"),
            is_licensed: Self::is_licensed(),
            max_threads: Self::max_threads(usize::MAX),
            native_code_generation: cfg!(feature = "native_code_generation"),
            license_networking: !cfg!(target_arch = "wasm32"),
        }
    }

    /// Get the current Symbolica version.
    pub fn get_version() -> &'static str {
        env!("SYMBOLICA_VERSION")
    }

    #[cfg(target_arch = "wasm32")]
    fn request_license_email(_data: HashMap<String, JsonValue>) -> Result<(), String> {
        Err("No Symbolica license key is required for WASM builds.".to_owned())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn request_license_email(mut data: HashMap<String, JsonValue>) -> Result<(), String> {
        // Request Symbolica v3 keys regardless of the current package version.
        data.insert("version".to_owned(), JsonValue::Number(3.0));
        let mut stream = Self::connect()?;
        let mut v = JsonValue::from(data).stringify().unwrap();
        v.push('\n');

        stream
            .write_all(v.as_bytes())
            .map_err(|e| format!("{NETWORK_ERROR}\nError: {e}"))?;

        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .map_err(|e| format!("{NETWORK_ERROR}\nError: {e}"))?;
        let read_str = std::str::from_utf8(&buf).map_err(|_| "Bad server response".to_string())?;

        if read_str == "{\"status\":\"email sent\"}\n" {
            Ok(())
        } else if read_str.is_empty() {
            Err("Empty response".to_owned())
        } else {
            let message: JsonValue = read_str[..read_str.len() - 1]
                .parse()
                .map_err(|_| "Bad server response".to_string())?;
            let message_parsed: &HashMap<_, _> = message
                .get()
                .ok_or_else(|| "Bad server response".to_string())?;
            let status: &String = message_parsed
                .get("status")
                .unwrap()
                .get()
                .ok_or_else(|| "Bad server response".to_string())?;
            Err(status.clone())
        }
    }

    /// Request a key for **non-professional** use for the user `name`, that will be sent to the e-mail address
    /// `email`.
    pub fn request_hobbyist_license(name: &str, email: &str) -> Result<(), String> {
        let mut m: HashMap<String, JsonValue> = HashMap::default();
        m.insert("name".to_owned(), name.to_owned().into());
        m.insert("email".to_owned(), email.to_owned().into());
        m.insert("type".to_owned(), "hobbyist".to_owned().into());
        Self::request_license_email(m)
    }

    /// Request a key for a trial license for the user `name` working at `company`, that will be sent to the e-mail address
    /// `email`.
    pub fn request_trial_license(name: &str, email: &str, company: &str) -> Result<(), String> {
        let mut m: HashMap<String, JsonValue> = HashMap::default();
        m.insert("name".to_owned(), name.to_owned().into());
        m.insert("email".to_owned(), email.to_owned().into());
        m.insert("company".to_owned(), company.to_owned().into());
        m.insert("type".to_owned(), "trial".to_owned().into());
        Self::request_license_email(m)
    }

    /// Request a sublicense key for the user `name` working at `company` that has the site-wide license `super_license`.
    /// The key will be sent to the e-mail address `email`.
    pub fn request_sublicense(
        name: &str,
        email: &str,
        company: &str,
        super_license: &str,
    ) -> Result<(), String> {
        let mut m: HashMap<String, JsonValue> = HashMap::default();
        m.insert("name".to_owned(), name.to_owned().into());
        m.insert("email".to_owned(), email.to_owned().into());
        m.insert("company".to_owned(), company.to_owned().into());
        m.insert("type".to_owned(), "sublicense".to_owned().into());
        m.insert("super_license".to_owned(), super_license.to_owned().into());
        Self::request_license_email(m)
    }

    /// Get the license key for the account registered with the provided email address.
    pub fn get_license_key(email: &str) -> Result<(), String> {
        let mut m: HashMap<String, JsonValue> = HashMap::default();
        m.insert("email".to_owned(), email.to_owned().into());
        Self::request_license_email(m)
    }
}

#[cfg(test)]
mod license_bypass_tests {
    use super::*;

    #[test]
    fn internal_license_bypass_guard_is_nested_and_thread_local() {
        assert!(!LicenseManager::is_check_bypassed());

        let outer = bypass_license_check_internal();
        assert!(LicenseManager::is_check_bypassed());
        assert!(
            crate::parser::Token::parse("x + 1", crate::parser::ParseSettings::default()).is_ok()
        );

        {
            let _inner = InternalLicenseBypassGuard::new();
            assert!(LicenseManager::is_check_bypassed());
        }

        assert!(LicenseManager::is_check_bypassed());
        assert!(
            std::thread::spawn(|| !LicenseManager::is_check_bypassed())
                .join()
                .unwrap()
        );

        drop(outer);
        assert!(!LicenseManager::is_check_bypassed());
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod offline_license_tests {
    use super::*;

    #[test]
    fn online_license_still_checks_registration() {
        LicenseManager::validate_license_key("online-key", |key| {
            assert_eq!(key, "online-key");
            Ok(())
        })
        .unwrap();
        assert_eq!(
            LicenseManager::validate_license_key("online-key", |_| Err("expired".to_owned())),
            Err("expired".to_owned())
        );
    }

    #[test]
    fn offline_registration_runs_in_background_and_sends_the_full_key() {
        let (started, receive_started) = std::sync::mpsc::channel();
        let (finish, receive_finish) = std::sync::mpsc::channel();
        let key = "S-123-2030.01.01-signature";
        let caller = std::thread::current().id();
        let worker =
            LicenseManager::check_offline_license_registration(key.to_owned(), move |key| {
                assert_ne!(std::thread::current().id(), caller);
                started.send(key).unwrap();
                receive_finish.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(())
            });
        assert_eq!(
            receive_started
                .recv_timeout(Duration::from_secs(5))
                .unwrap(),
            key
        );
        // Activation can continue even while the server request has not completed.
        finish.send(()).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn offline_registration_tolerates_network_and_unrecognized_errors() {
        for error in [
            RESOLVE_ERROR,
            CONNECTION_ERROR,
            NETWORK_ERROR,
            "Empty response",
            "Server unavailable",
        ] {
            assert!(!LicenseManager::offline_license_is_rejected(error));
            LicenseManager::check_offline_license_registration(
                "offline-key".to_owned(),
                move |_| Err(error.to_owned()),
            )
            .join()
            .unwrap();
        }
    }

    #[test]
    fn offline_registration_recognizes_server_rejections() {
        for status in [
            "License banned",
            "License REVOKED",
            "License expired",
            "Unknown license",
        ] {
            // check_registration wraps server statuses in the activation error message.
            let error = format!("Could not activate the Symbolica license\nError: {status}");
            assert!(LicenseManager::offline_license_is_rejected(&error));
        }
    }

    #[test]
    fn unsigned_or_malformed_keys_cannot_fall_back_to_online_activation() {
        for key in [
            "5381#ffffffff#fake",
            "bad#not-a-date#fake",
            "SYMBOLICA_OEM_KEY_123",
            "SL1.invalid",
            "SL2.invalid",
            "S-123-2030.01.01-invalid",
            "S123-2030.01.01-invalid",
            "S-",
            "S-123",
            "SYMBOLICA2-123-2030.01.01-invalid",
        ] {
            assert!(
                LicenseManager::validate_license_key(key, |_| {
                    panic!("must not contact server for an invalid offline/OEM key")
                })
                .is_err()
            );
        }
    }
}

#[cfg(any(test, debug_assertions))]
const TEST_UNLOCK_PUBLIC_KEY: &str = "FTlMMgb7IKbxHiS-E7bp_W2ZqhPeqXpZ_Or40Jpjvns";
#[cfg(any(test, debug_assertions))]
const TEST_UNLOCK_LICENSE: &str = "SYMBOLICA_UNLOCK_TEST";

#[cfg(any(test, debug_assertions))]
pub(crate) const TEST_UNLOCK_TOKEN: &str = concat!(
    "eyJsaWNlbnNlIjoiU1lNQk9MSUNBX1VOTE9DS19URVNUIiwicGFja2FnZSI6InB5c2VjZGVjIiwidmVyc2lvbiI6MX0",
    ".",
    "VKUj1gBSnqHBETCWB7UV2ySynCfmPlTZ8RvEx4HR0Nr4w1n-SDHkneMOKFAuKfDmvY14YmW9WwDx7JDCHKKOBQ"
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnlockClaims {
    pub package: String,
    license: String,
    token_id: String,
}

#[cfg(not(target_arch = "wasm32"))]
static CHECKED_UNLOCK_LICENSES: LazyLock<Mutex<HashSet<(u32, String)>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

thread_local! {
    static LIBRARY_UNLOCK_DEPTH: Cell<usize> = const { Cell::new(0) };
}

fn verify_signature(
    public_key: &str,
    payload: &[u8],
    signature: &Signature,
) -> Result<bool, String> {
    let public_key_bytes: [u8; 32] = BASE64URL_NOPAD
        .decode(public_key.as_bytes())
        .map_err(|_| "Invalid compiled Symbolica library unlock public key".to_owned())?
        .try_into()
        .map_err(|_| "Invalid compiled Symbolica library unlock public key length".to_owned())?;

    Ok(PublicKey::new(public_key_bytes)
        .verify(payload, signature)
        .is_ok())
}

fn get_usize_claim(claims: &HashMap<String, JsonValue>, name: &str) -> Result<usize, String> {
    let value = claims
        .get(name)
        .and_then(JsonValue::get::<f64>)
        .copied()
        .ok_or_else(|| format!("Library unlock token is missing integer claim '{name}'"))?;

    if !value.is_finite() || value < 1.0 || value.fract() != 0.0 || value > usize::MAX as f64 {
        return Err(format!(
            "Library unlock token has invalid integer claim '{name}'"
        ));
    }

    Ok(value as usize)
}

pub(crate) fn verify_token(token: &str) -> Result<UnlockClaims, String> {
    let (payload, signature_text) = token
        .split_once('.')
        .ok_or_else(|| "Invalid Symbolica library unlock token format".to_owned())?;

    if signature_text.contains('.') {
        return Err("Invalid Symbolica library unlock token format".to_owned());
    }

    let payload_bytes = BASE64URL_NOPAD
        .decode(payload.as_bytes())
        .map_err(|_| "Invalid Symbolica library unlock token payload encoding".to_owned())?;
    let signature_bytes: [u8; 64] = BASE64URL_NOPAD
        .decode(signature_text.as_bytes())
        .map_err(|_| "Invalid Symbolica library unlock token signature encoding".to_owned())?
        .try_into()
        .map_err(|_| "Invalid Symbolica library unlock token signature length".to_owned())?;
    let signature = Signature::new(signature_bytes);
    let signature_is_valid = verify_signature(SYMBOLICA_PUBLIC_KEY, &payload_bytes, &signature)?;
    #[cfg(any(test, debug_assertions))]
    let signature_is_valid =
        signature_is_valid || verify_signature(TEST_UNLOCK_PUBLIC_KEY, &payload_bytes, &signature)?;
    if !signature_is_valid {
        return Err("Invalid Symbolica library unlock token signature".to_owned());
    }

    let payload = std::str::from_utf8(&payload_bytes)
        .map_err(|_| "Symbolica library unlock token payload is not UTF-8".to_owned())?;
    let value: JsonValue = payload
        .parse()
        .map_err(|_| "Invalid Symbolica library unlock token JSON".to_owned())?;
    let claims = value
        .get::<HashMap<String, JsonValue>>()
        .ok_or_else(|| "Symbolica library unlock token payload is not an object".to_owned())?;

    let version = get_usize_claim(claims, "version")?;
    if version != 1 {
        return Err(format!(
            "Unsupported Symbolica library unlock token version {version}"
        ));
    }

    let package = claims
        .get("package")
        .and_then(JsonValue::get::<String>)
        .filter(|package| {
            !package.is_empty()
                && package
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_'))
        })
        .cloned()
        .ok_or_else(|| "Symbolica library unlock token has invalid package claim".to_owned())?;
    let license = claims
        .get("license")
        .and_then(JsonValue::get::<String>)
        .filter(|license| license.starts_with("SYMBOLICA_UNLOCK_") && license.len() > 17)
        .cloned()
        .ok_or_else(|| "Symbolica library unlock token has invalid license claim".to_owned())?;

    Ok(UnlockClaims {
        package,
        license,
        token_id: signature_text.to_owned(),
    })
}

pub(crate) fn start_license_check(claims: &UnlockClaims) {
    #[cfg(not(target_arch = "wasm32"))]
    {
        #[cfg(any(test, debug_assertions))]
        if claims.license == TEST_UNLOCK_LICENSE
            && claims.token_id == TEST_UNLOCK_TOKEN.split_once('.').unwrap().1
        {
            return;
        }

        let pid = std::process::id();
        let mut checked = CHECKED_UNLOCK_LICENSES.lock().unwrap();
        if checked.insert((pid, claims.license.clone())) {
            LicenseManager::check_library_unlock_registration(claims.license.clone());
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn lock_directory() -> io::Result<(PathBuf, bool)> {
    if let Some(path) = std::env::var_os("SYMBOLICA_LOCK_DIR") {
        return Ok((PathBuf::from(path), false));
    }

    let project_dirs = ProjectDirs::from("io", "symbolica", "symbolica").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Could not determine the per-user Symbolica lock directory; set SYMBOLICA_LOCK_DIR",
        )
    })?;
    let base = project_dirs
        .runtime_dir()
        .unwrap_or_else(|| project_dirs.cache_dir());
    Ok((base.join("locks"), true))
}

#[cfg(not(target_arch = "wasm32"))]
fn prepare_lock_directory(path: &Path, repair_permissions: bool) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Symbolica lock path '{}' is not a directory",
                path.display()
            ),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            if repair_permissions {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "SYMBOLICA_LOCK_DIR '{}' must only be accessible by its owner",
                        path.display()
                    ),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn try_acquire_lock_in(directory: &Path, name: &str) -> io::Result<Option<File>> {
    let path = directory.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Symbolica lock path '{}' is not a regular file",
                    path.display()
                ),
            ));
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options.open(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn try_acquire_lock(name: &str) -> io::Result<Option<File>> {
    let (directory, repair_permissions) = lock_directory()?;
    prepare_lock_directory(&directory, repair_permissions)?;
    try_acquire_lock_in(&directory, name)
}

/// A verified unlock for a Rust library.
///
/// Construct this through [`crate::register_library_unlock!`], then call [`Self::unlock`] around every
/// synchronous library operation. Library-owned worker closures must unlock their own thread;
/// Symbolica propagates an active unlock to threads it creates internally.
///
/// # Examples
///
/// ```no_run
/// use std::sync::LazyLock;
/// use symbolica::{license::LibraryUnlock, register_library_unlock};
///
/// pub(crate) static UNLOCK: LazyLock<LibraryUnlock> = LazyLock::new(|| {
///     register_library_unlock!("YOUR_KEY").unwrap()
/// });
///
/// fn main() {
///     let _unlock = UNLOCK.unlock();
/// }
/// ```
#[derive(Clone, Debug)]
pub struct LibraryUnlock {
    _private: (),
}

impl LibraryUnlock {
    /// Verify a token and bind it to the crate name supplied by [`crate::register_library_unlock!`].
    #[doc(hidden)]
    pub fn for_crate(token: &str, crate_name: &str) -> Result<Self, String> {
        let claims = verify_token(token)?;
        if claims.package != crate_name {
            return Err(format!(
                "Library unlock token for package '{}' cannot be registered by crate '{}'",
                claims.package, crate_name
            ));
        }
        start_license_check(&claims);
        Ok(Self { _private: () })
    }

    /// Authorize Symbolica calls on the current thread until the returned guard is dropped.
    #[inline]
    pub fn unlock(&self) -> LibraryUnlockGuard {
        LibraryUnlockGuard::activate()
    }
}

/// A thread-bound Rust library unlock guard.
///
/// Same-thread callbacks inherit the authorization. The guard is deliberately not `Send`; worker
/// threads owned by the library must call [`LibraryUnlock::unlock`] themselves.
#[must_use = "the library is unlocked only while this guard is alive"]
pub struct LibraryUnlockGuard {
    _not_send: PhantomData<Rc<()>>,
}

impl LibraryUnlockGuard {
    #[inline]
    fn activate() -> Self {
        LIBRARY_UNLOCK_DEPTH.with(|depth| {
            depth.set(
                depth
                    .get()
                    .checked_add(1)
                    .expect("library unlock scope nesting overflow"),
            );
        });
        Self {
            _not_send: PhantomData,
        }
    }
}

impl Drop for LibraryUnlockGuard {
    #[inline]
    fn drop(&mut self) {
        LIBRARY_UNLOCK_DEPTH.with(|depth| {
            let current = depth.get();
            debug_assert!(current > 0, "unbalanced library unlock scope");
            depth.set(current.saturating_sub(1));
        });
    }
}

/// Return whether the current Rust thread is inside a library unlock scope.
#[inline]
pub(crate) fn current_thread_is_unlocked() -> bool {
    LIBRARY_UNLOCK_DEPTH.with(|depth| depth.get() != 0)
}

/// Authorization captured before Symbolica dispatches work to one of its own threads.
#[derive(Clone, Copy)]
pub(crate) struct InheritedLibraryUnlock(bool);

impl InheritedLibraryUnlock {
    /// Capture both Rust guard and Python package-frame authorization on the calling thread.
    #[inline]
    pub(crate) fn capture() -> Self {
        Self(LicenseManager::is_library_unlocked())
    }

    /// Establish captured authorization on the worker for the lifetime of the returned guard.
    #[inline]
    pub(crate) fn activate(self) -> Option<LibraryUnlockGuard> {
        self.0.then(LibraryUnlockGuard::activate)
    }
}

#[cfg(test)]
mod unlock_tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    fn test_lock_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("symbolica-lock-test-{}-{name}", std::process::id()))
    }

    #[test]
    fn verifies_development_unlock_token() {
        assert_eq!(
            verify_token(TEST_UNLOCK_TOKEN).unwrap(),
            UnlockClaims {
                package: "pysecdec".to_owned(),
                license: TEST_UNLOCK_LICENSE.to_owned(),
                token_id: TEST_UNLOCK_TOKEN.split_once('.').unwrap().1.to_owned(),
            }
        );
    }

    #[test]
    fn rejects_noncanonical_unlock_token_encoding() {
        let (payload, signature) = TEST_UNLOCK_TOKEN.split_once('.').unwrap();
        for token in [
            format!("{payload}=.{signature}"),
            format!("{payload}.{signature}="),
            format!("{payload}.{signature}\n"),
            format!("{payload}.{}", signature.replace('-', "+")),
        ] {
            assert!(verify_token(&token).unwrap_err().contains("encoding"));
        }

        // Changing only unused trailing bits must not create an alternate token ID.
        assert!(signature.ends_with('Q'));
        let noncanonical = format!("{payload}.{}R", &signature[..signature.len() - 1]);
        assert!(
            verify_token(&noncanonical)
                .unwrap_err()
                .contains("encoding")
        );
    }

    #[test]
    fn rejects_tampered_unlock_token() {
        let mut token = TEST_UNLOCK_TOKEN.to_owned();
        token.replace_range(..1, "f");
        assert_eq!(
            verify_token(&token).unwrap_err(),
            "Invalid Symbolica library unlock token signature"
        );
    }

    #[test]
    fn rust_guard_is_thread_bound() {
        let registration = LibraryUnlock::for_crate(TEST_UNLOCK_TOKEN, "pysecdec").unwrap();
        assert!(!current_thread_is_unlocked());
        {
            let _guard = registration.unlock();
            assert!(current_thread_is_unlocked());
            assert!(
                !std::thread::spawn(current_thread_is_unlocked)
                    .join()
                    .unwrap()
            );
        }
        assert!(!current_thread_is_unlocked());
    }

    #[test]
    fn rust_guard_is_nested() {
        let registration = LibraryUnlock::for_crate(TEST_UNLOCK_TOKEN, "pysecdec").unwrap();
        let outer = registration.unlock();
        {
            let _inner = registration.unlock();
            assert!(current_thread_is_unlocked());
        }
        assert!(current_thread_is_unlocked());
        drop(outer);
        assert!(!current_thread_is_unlocked());
    }

    #[test]
    fn symbolica_worker_can_inherit_unlock() {
        let registration = LibraryUnlock::for_crate(TEST_UNLOCK_TOKEN, "pysecdec").unwrap();
        let _guard = registration.unlock();
        let inherited = InheritedLibraryUnlock::capture();

        assert!(
            std::thread::spawn(move || {
                assert!(!current_thread_is_unlocked());
                let _guard = inherited.activate();
                current_thread_is_unlocked()
            })
            .join()
            .unwrap()
        );
    }

    #[test]
    fn parallel_symbolica_callback_inherits_unlock() {
        use crate::atom::AtomCore;

        let registration = LibraryUnlock::for_crate(TEST_UNLOCK_TOKEN, "pysecdec").unwrap();
        let _guard = registration.unlock();
        let expression = crate::parse!("a+b+c+d+e+f+g+h");

        let result = expression.map_terms(
            |term| {
                assert!(current_thread_is_unlocked());
                term.to_owned()
            },
            4,
        );
        assert_eq!(result, expression);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn private_per_user_lock_excludes_other_handles() {
        let directory = test_lock_directory("exclusive");
        let _ = std::fs::remove_dir_all(&directory);
        prepare_lock_directory(&directory, true).unwrap();

        let first = try_acquire_lock_in(&directory, "test.lock")
            .unwrap()
            .unwrap();
        assert!(
            try_acquire_lock_in(&directory, "test.lock")
                .unwrap()
                .is_none()
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o077,
                0
            );
            assert_eq!(
                std::fs::metadata(directory.join("test.lock"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }

        drop(first);
        assert!(
            try_acquire_lock_in(&directory, "test.lock")
                .unwrap()
                .is_some()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn explicit_lock_directory_must_be_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = test_lock_directory("permissions");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = prepare_lock_directory(&directory, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        std::fs::remove_dir(directory).unwrap();
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod signed {
    //! Compact issuer-signed offline and OEM licenses. See docs/signed-licenses.md.

    use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
    use ed25519_compact::{PublicKey, Signature};
    use std::time::{SystemTime, UNIX_EPOCH};

    const PREFIX: &str = "SL1.";
    const DOMAIN: &[u8] = b"Symbolica license v1\0";
    const HEADER_LEN: usize = 13;
    const SIGNATURE_LEN: usize = 64;
    const ENCODED_SIGNATURE_LEN: usize = 103;
    // Allow an optional separator between each pair of Base32 characters.
    const MAX_SIGNATURE_TEXT_LEN: usize = ENCODED_SIGNATURE_LEN * 2 - 1;
    const MAX_CRATE_LEN: usize = 255;

    #[derive(Clone, Copy)]
    pub(crate) enum Purpose<'a> {
        Offline,
        Oem(&'a str),
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct Claims {
        pub user_id: u64,
        pub expires_at: u32,
    }

    pub(crate) fn verify(token: &str, purpose: Purpose<'_>) -> Result<Claims, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "System clock is before the Unix epoch".to_owned())?
            .as_secs();
        verify_with_key(token, purpose, now, super::SYMBOLICA_PUBLIC_KEY)
    }

    // Offline dates represent exclusive expiration at midnight UTC. The bounded year
    // range fits the existing unsigned 32-bit timestamp used in the signed payload.
    fn parse_expiration(date: &str) -> Result<u32, String> {
        let invalid = || {
            "Invalid offline expiration date: expected YYYY.MM.DD within the supported timestamp range".to_owned()
        };
        let bytes = date.as_bytes();
        if bytes.len() != 10
            || bytes[4] != b'.'
            || bytes[7] != b'.'
            || !bytes
                .iter()
                .enumerate()
                .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
        {
            return Err(invalid());
        }
        let year: u32 = date[..4].parse().map_err(|_| invalid())?;
        let month: usize = date[5..7].parse().map_err(|_| invalid())?;
        let day: u32 = date[8..].parse().map_err(|_| invalid())?;
        if !(1970..=2106).contains(&year) || !(1..=12).contains(&month) {
            return Err(invalid());
        }
        let leap = |year: u32| {
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
        };
        let months = [
            31,
            if leap(year) { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        if day == 0 || day > months[month - 1] {
            return Err(invalid());
        }
        let days = (1970..year)
            .map(|y| if leap(y) { 366 } else { 365 })
            .sum::<u32>()
            + months[..month - 1].iter().sum::<u32>()
            + day
            - 1;
        days.checked_mul(86400)
            .filter(|seconds| *seconds > 0)
            .ok_or_else(invalid)
    }

    fn decode_offline_signature(signature: &str) -> Result<Vec<u8>, String> {
        if signature.len() > MAX_SIGNATURE_TEXT_LEN || signature.split('-').any(str::is_empty) {
            return Err("Invalid offline signature length or grouping".to_owned());
        }
        let encoded: Vec<_> = signature.bytes().filter(|&b| b != b'-').collect();
        if encoded.len() != ENCODED_SIGNATURE_LEN {
            return Err("Invalid offline signature length".to_owned());
        }
        let decoded = BASE32_NOPAD
            .decode(&encoded)
            .map_err(|_| "Invalid signed Symbolica license encoding")?;
        if decoded.len() != SIGNATURE_LEN {
            return Err("Invalid signed Symbolica license signature length".to_owned());
        }
        Ok(decoded)
    }

    fn decode_offline(token: &str) -> Result<Vec<u8>, String> {
        if token.starts_with("SYMBOLICA2-")
            || (token.starts_with("SL") && !token.starts_with(PREFIX))
        {
            return Err(super::OUTDATED_LICENSE_KEY_ERROR.to_owned());
        }
        // 20 decimal digits suffice for any u64 user ID.
        if token.len() > 2 + 20 + 1 + 10 + 1 + MAX_SIGNATURE_TEXT_LEN {
            return Err("Signed Symbolica license is too long".to_owned());
        }
        let encoded = token
            .strip_prefix("S-")
            .ok_or("Invalid signed Symbolica offline license format")?;
        // Keep the grouped signature intact after splitting the user ID and date.
        let mut fields = encoded.splitn(3, '-');
        let user = fields.next().unwrap();
        let date = fields.next().ok_or("Missing offline expiration date")?;
        let signature = fields.next().ok_or("Missing offline license signature")?;
        if user.is_empty() || user.starts_with('0') || !user.bytes().all(|b| b.is_ascii_digit()) {
            return Err("Invalid offline license user ID".to_owned());
        }
        let user_id: u64 = user
            .parse()
            .map_err(|_| "Invalid offline license user ID")?;
        let expires_at = parse_expiration(date)?;
        let signature = decode_offline_signature(signature)?;
        let mut bytes = Vec::with_capacity(HEADER_LEN + SIGNATURE_LEN);
        bytes.push(1);
        bytes.extend_from_slice(&expires_at.to_be_bytes());
        bytes.extend_from_slice(&user_id.to_be_bytes());
        bytes.extend_from_slice(&signature);
        Ok(bytes)
    }

    fn verify_with_key(
        token: &str,
        purpose: Purpose<'_>,
        now: u64,
        public_key: &str,
    ) -> Result<Claims, String> {
        let bytes = match purpose {
            Purpose::Offline => decode_offline(token)?,
            Purpose::Oem(_) => {
                let encoded = token
                    .strip_prefix(PREFIX)
                    .ok_or(super::OUTDATED_LICENSE_KEY_ERROR)?;
                if encoded.len() > (HEADER_LEN + MAX_CRATE_LEN + SIGNATURE_LEN).div_ceil(3) * 4 {
                    return Err("Signed Symbolica license is too long".to_owned());
                }
                BASE64URL_NOPAD
                    .decode(encoded.as_bytes())
                    .map_err(|_| "Invalid signed Symbolica license encoding")?
            }
        };
        if bytes.len() < HEADER_LEN + SIGNATURE_LEN {
            return Err("Signed Symbolica license is truncated".to_owned());
        }
        let (payload, signature) = bytes.split_at(bytes.len() - SIGNATURE_LEN);
        let key: [u8; 32] = BASE64URL_NOPAD
            .decode(public_key.as_bytes())
            .map_err(|_| "Invalid compiled Symbolica public key")?
            .try_into()
            .map_err(|_| "Invalid compiled Symbolica public key length")?;
        let signature = Signature::from_slice(signature)
            .map_err(|_| "Invalid signed Symbolica license signature length")?;
        let mut message = Vec::with_capacity(DOMAIN.len() + payload.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(payload);
        PublicKey::new(key)
            .verify(&message, &signature)
            .map_err(|_| "Invalid signed Symbolica license signature")?;

        match purpose {
            Purpose::Offline if payload[0] == 1 && payload.len() == HEADER_LEN => {}
            Purpose::Oem(crate_name) if payload[0] == 2 => {
                let package = &payload[HEADER_LEN..];
                if package.is_empty()
                    || package.len() > MAX_CRATE_LEN
                    || !package
                        .iter()
                        .all(|c| c.is_ascii_alphanumeric() || *c == b'_')
                    || package != crate_name.as_bytes()
                {
                    return Err("OEM license does not match the calling crate".to_owned());
                }
            }
            _ => {
                return Err(
                    "Signed Symbolica license has the wrong purpose or payload length".to_owned(),
                );
            }
        }
        // Fixed-width fields are read only after checking the minimum length and signature.
        let expires_at = u32::from_be_bytes(payload[1..5].try_into().unwrap());
        let user_id = u64::from_be_bytes(payload[5..13].try_into().unwrap());
        if user_id == 0 {
            return Err("Signed Symbolica license has an invalid user ID".to_owned());
        }
        if now >= u64::from(expires_at) {
            return Err("Signed Symbolica license has expired; request a new key".to_owned());
        }
        Ok(Claims {
            user_id,
            expires_at,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ed25519_compact::{KeyPair, Seed};

        fn issuer() -> KeyPair {
            KeyPair::from_seed(Seed::new([42; 32]))
        }

        fn payload(kind: u8, expires: u32, user: u64, package: &str) -> Vec<u8> {
            let mut payload = vec![kind];
            payload.extend_from_slice(&expires.to_be_bytes());
            payload.extend_from_slice(&user.to_be_bytes());
            payload.extend_from_slice(package.as_bytes());
            payload
        }

        fn sign(payload: &[u8]) -> String {
            let mut message = DOMAIN.to_vec();
            message.extend_from_slice(payload);
            let mut bytes = payload.to_vec();
            bytes.extend_from_slice(issuer().sk.sign(message, None).as_ref());
            format!("{PREFIX}{}", BASE64URL_NOPAD.encode(&bytes))
        }

        fn group_signature(signature: &[u8]) -> String {
            let encoded = BASE32_NOPAD.encode(signature);
            encoded
                .as_bytes()
                .chunks(8)
                .map(|group| std::str::from_utf8(group).unwrap())
                .collect::<Vec<_>>()
                .join("-")
        }

        fn sign_offline(user: u64, date: &str) -> String {
            let p = payload(1, parse_expiration(date).unwrap(), user, "");
            let mut message = DOMAIN.to_vec();
            message.extend_from_slice(&p);
            format!(
                "S-{user}-{date}-{}",
                BASE32_NOPAD.encode(issuer().sk.sign(message, None).as_ref())
            )
        }

        fn check(token: &str, purpose: Purpose<'_>, now: u64) -> Result<Claims, String> {
            verify_with_key(
                token,
                purpose,
                now,
                &BASE64URL_NOPAD.encode(issuer().pk.as_ref()),
            )
        }

        #[test]
        fn readable_offline_round_trip_and_expiration_boundary() {
            let token = sign_offline(u64::MAX, "2030.01.01");
            // Shared with the Python issuer test: catches serialization and signing drift.
            assert_eq!(
                token,
                "S-18446744073709551615-2030.01.01-GAOSLAUT2OILZPBWRLPQNFWSKVU2FBE2PK6RKPXSL3RKZ6CXPT6RV2EG6A7ZJ7Y7O4XKQQPJLBCPHSUM6EI5EA27GIUTYXE2QZUEKCI"
            );
            assert_eq!(token.len(), 137);
            for user in [1, 123, 1_000_000_000, u64::MAX] {
                let token = sign_offline(user, "2030.01.01");
                assert_eq!(
                    check(&token, Purpose::Offline, 1_893_455_999).unwrap(),
                    Claims {
                        user_id: user,
                        expires_at: 1_893_456_000
                    }
                );
            }
            for now in [1_893_456_000, 1_893_456_001, u64::MAX] {
                assert!(
                    check(&token, Purpose::Offline, now)
                        .unwrap_err()
                        .contains("expired")
                );
            }
            assert!(check(&token, Purpose::Oem("my_crate"), 0).is_err());
            assert!(
                verify(&token, Purpose::Offline)
                    .unwrap_err()
                    .contains("signature")
            );
        }

        #[test]
        fn readable_offline_fields_and_signature_are_authenticated() {
            let token = sign_offline(123, "2030.01.01");
            assert_eq!(token.len(), 120);
            let signature = token.strip_prefix("S-123-2030.01.01-").unwrap();
            assert!(!signature.contains('-'));
            for changed in [
                token.replace("S-123-", "S-124-"),
                token.replace("2030.01.01", "2030.01.02"),
            ] {
                assert!(
                    check(&changed, Purpose::Offline, 0)
                        .unwrap_err()
                        .contains("signature")
                );
            }
            let bytes = decode_offline_signature(signature).unwrap();
            for i in 0..bytes.len() {
                let mut changed = bytes.clone();
                changed[i] ^= 1;
                let token = format!("S-123-2030.01.01-{}", group_signature(&changed));
                assert!(
                    check(&token, Purpose::Offline, 0).is_err(),
                    "signature byte {i}"
                );
            }
        }

        #[test]
        fn uppercase_base32_accepts_optional_signature_grouping() {
            let bytes = [0xfb; SIGNATURE_LEN];
            let grouped = group_signature(&bytes);
            assert!(
                grouped
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || matches!(b, b'2'..=b'7' | b'-'))
            );
            assert!(!grouped.contains("--"));
            assert_eq!(decode_offline_signature(&grouped).unwrap(), bytes);
            assert_eq!(
                decode_offline_signature(&BASE32_NOPAD.encode(&bytes)).unwrap(),
                bytes
            );
            for index in (8..grouped.len()).step_by(9) {
                for separator in [".", "_", " ", "--"] {
                    let mut bad = grouped.clone();
                    bad.replace_range(index..index + 1, separator);
                    assert!(
                        decode_offline_signature(&bad).is_err(),
                        "separator {index}: {separator:?}"
                    );
                }
            }
            for invalid in ["a", "0", "1", "8", "9", "_", "=", "-"] {
                let mut bad = grouped.clone();
                bad.replace_range(..1, invalid);
                assert!(decode_offline_signature(&bad).is_err(), "symbol {invalid}");
            }
            assert!(decode_offline_signature(&grouped.to_ascii_lowercase()).is_err());
            // Canonical unpadded Base32 requires the final three unused bits to be zero.
            let mut noncanonical = group_signature(&[0; SIGNATURE_LEN]);
            noncanonical.pop();
            noncanonical.push('B');
            assert!(decode_offline_signature(&noncanonical).is_err());
            for group_len in [1, 4, 8, 16, ENCODED_SIGNATURE_LEN] {
                let valid = sign_offline(u64::MAX, "2030.01.01");
                let (header, signature) = valid.rsplit_once('-').unwrap();
                let grouped = signature
                    .as_bytes()
                    .chunks(group_len)
                    .map(|group| std::str::from_utf8(group).unwrap())
                    .collect::<Vec<_>>()
                    .join("-");
                assert!(check(&format!("{header}-{grouped}"), Purpose::Offline, 0).is_ok());
            }
            for bad in [format!("-{grouped}"), format!("{grouped}-")] {
                assert!(decode_offline_signature(&bad).is_err());
            }
            let valid = sign_offline(123, "2030.01.01");
            assert!(check(&valid.replacen("S-", "S", 1), Purpose::Offline, 0).is_err());
            assert!(check(&valid.replace('-', ""), Purpose::Offline, 0).is_err());
        }

        #[test]
        fn offline_dates_follow_the_utc_calendar() {
            for (date, seconds) in [
                ("1970.01.02", 86400),
                ("2000.02.29", 951782400),
                ("2024.02.29", 1709164800),
                ("2030.01.01", 1893456000),
                ("2100.03.01", 4107542400),
                ("2106.02.07", 4294944000),
            ] {
                assert_eq!(parse_expiration(date).unwrap(), seconds, "{date}");
            }
            for date in [
                "1970.01.01",
                "1969.12.31",
                "2106.02.08",
                "9999.01.01",
                "2023.02.29",
                "2100.02.29",
                "2030.04.31",
                "2030.00.01",
                "2030.13.01",
                "2030.01.00",
                "2030.1.01",
                "2030-01-01",
                "abcd.ef.gh",
                "2030.01.é",
            ] {
                assert!(parse_expiration(date).is_err(), "{date}");
            }
        }

        #[test]
        fn readable_offline_rejects_malformed_fields() {
            let valid = sign_offline(123, "2030.01.01");
            for user in [
                "",
                "0",
                "0123",
                "+123",
                "-123",
                "18446744073709551616",
                "１２３",
                "1 23",
            ] {
                assert!(
                    check(
                        &valid.replace("S-123-", &format!("S-{user}-")),
                        Purpose::Offline,
                        0
                    )
                    .is_err(),
                    "{user}"
                );
            }
            for token in [
                "S-123",
                "S-123-2030.01.01",
                "S-123-2030.01.01-",
                "SYMBOLICA2-123-2030.01.01-AAAA",
                "S-123-2030.01.01-AAAA",
            ] {
                assert!(check(token, Purpose::Offline, 0).is_err());
            }
            assert!(check(&(valid.clone() + "="), Purpose::Offline, 0).is_err());
            assert!(check(&(valid + "\n"), Purpose::Offline, 0).is_err());
            // Binary SL1 tokens remain reserved for OEM activation.
            assert!(check(&sign(&payload(1, 1893456000, 123, "")), Purpose::Offline, 0).is_err());
        }

        #[test]
        fn oem_is_bound_to_purpose_and_exact_crate() {
            let token = sign(&payload(2, 100, 1, "my_crate"));
            assert!(check(&token, Purpose::Oem("my_crate"), 99).is_ok());
            assert!(check(&token, Purpose::Oem("other_crate"), 99).is_err());
            assert!(check(&token, Purpose::Offline, 99).is_err());
            assert!(check(&token, Purpose::Oem("my_crate"), 100).is_err());
            assert!(check(&sign(&payload(1, 100, 1, "")), Purpose::Oem("my_crate"), 99).is_err());
        }

        #[test]
        fn every_payload_and_signature_byte_is_authenticated() {
            let token = sign(&payload(2, 100, 1, "my_crate"));
            let original = BASE64URL_NOPAD
                .decode(token[PREFIX.len()..].as_bytes())
                .unwrap();
            for i in 0..original.len() {
                let mut bytes = original.clone();
                bytes[i] ^= 1;
                let changed = format!("{PREFIX}{}", BASE64URL_NOPAD.encode(&bytes));
                assert!(
                    check(&changed, Purpose::Oem("my_crate"), 99).is_err(),
                    "byte {i}"
                );
            }
            // A test issuer is never trusted by the production entry point, even in debug builds.
            assert!(
                verify(&token, Purpose::Oem("my_crate"))
                    .unwrap_err()
                    .contains("signature")
            );
        }

        #[test]
        fn rejects_malformed_and_invalid_signed_claims() {
            for token in ["", "SL2.AAAA", "SL1.====", "SL1.a.b", "SL1.AAAA"] {
                assert!(check(token, Purpose::Offline, 0).is_err());
            }
            assert!(check(&format!("SL1.{}", "A".repeat(1000)), Purpose::Offline, 0).is_err());
            for p in [
                payload(0, 100, 1, ""),
                payload(1, 100, 0, ""),
                payload(1, 100, 1, "extra"),
                payload(1, 0, 1, ""),
            ] {
                assert!(check(&sign(&p), Purpose::Offline, 0).is_err());
            }
            for package in ["", "bad-crate", "x.y"] {
                assert!(
                    check(
                        &sign(&payload(2, 100, 1, package)),
                        Purpose::Oem(package),
                        0
                    )
                    .is_err()
                );
            }
            // Library unlock signatures use another message format and cannot authorize licenses.
            let p = payload(1, 100, 1, "");
            let mut bytes = p.clone();
            bytes.extend_from_slice(issuer().sk.sign(p, None).as_ref());
            assert!(
                check(
                    &format!("SL1.{}", BASE64URL_NOPAD.encode(&bytes)),
                    Purpose::Offline,
                    0
                )
                .is_err()
            );
        }
    }
}

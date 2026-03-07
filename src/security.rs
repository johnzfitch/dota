//! Process-level security hardening and secret memory types
//!
//! Provides:
//! - `SecretString` / `SecretVec`: heap wrappers that zero memory on drop
//! - OS hardening: disable core dumps, ptrace, swap for secrets
//! - Signal handling: ensure destructors run on SIGTERM/SIGINT
//!
//! Uses raw FFI to avoid adding the `libc` crate as a dependency.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Secret memory types ─────────────────────────────────────────────────────

/// A `String` that is zeroized on drop.
///
/// Use for passphrases, plaintext secrets, and any other sensitive string data
/// that must not persist on the heap after the variable goes out of scope.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap a `String` in a zeroizing wrapper.
    /// The original `String`'s buffer is moved (not copied).
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Borrow the inner string for read-only access.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// A `Vec<u8>` that is zeroized on drop.
///
/// Use for decrypted key bytes, plaintext buffers, and any other sensitive
/// byte data that must not persist on the heap.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    /// Wrap a `Vec<u8>` in a zeroizing wrapper.
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }

    /// Borrow the inner bytes for read-only access.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Consume the wrapper and return the inner `Vec<u8>`.
    /// **Caller must ensure the returned Vec is zeroized or moved into
    /// another zeroizing container.**
    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED BYTES]")
    }
}

// ── OS-level hardening (raw FFI — no libc crate dependency) ─────────────────

// Linux constants (stable ABI)
#[cfg(target_os = "linux")]
mod linux {
    use std::os::raw::c_int;

    pub const RLIMIT_CORE: c_int = 4;
    pub const PR_SET_DUMPABLE: c_int = 4;
    pub const MCL_CURRENT: c_int = 1;
    pub const MCL_FUTURE: c_int = 2;
    pub const SIGTERM: c_int = 15;
    pub const SIGINT: c_int = 2;
    pub const SIGHUP: c_int = 1;

    pub const SA_RESTART: c_int = 0x10000000;

    #[repr(C)]
    pub struct Rlimit {
        pub rlim_cur: u64,
        pub rlim_max: u64,
    }

    /// POSIX sigaction struct (Linux x86_64 layout)
    #[repr(C)]
    pub struct SigAction {
        pub sa_handler: extern "C" fn(c_int),
        pub sa_flags: u64,
        pub sa_restorer: usize,
        pub sa_mask: [u64; 16], // sigset_t on Linux
    }

    unsafe extern "C" {
        pub fn setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int;
        pub fn prctl(option: c_int, ...) -> c_int;
        pub fn mlockall(flags: c_int) -> c_int;
        pub fn sigaction(signum: c_int, act: *const SigAction, oldact: *mut SigAction) -> c_int;
        pub fn _exit(status: c_int) -> !;
    }
}

/// Apply OS-level security hardening at process startup.
///
/// Best-effort: failures are logged to stderr but do not abort (the user
/// may lack `CAP_IPC_LOCK` or be on a non-Linux platform).
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        harden_linux();
    }
}

#[cfg(target_os = "linux")]
fn harden_linux() {
    use linux::*;
    unsafe {
        // 1. Disable core dumps — prevents secrets from being written to disk
        //    on crash or signal-induced core generation.
        let rlim = Rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if setrlimit(RLIMIT_CORE, &rlim) != 0 {
            eprintln!("warning: failed to disable core dumps");
        }

        // 2. Mark process as non-dumpable — blocks ptrace attach and
        //    /proc/self/mem reads by same-UID processes.
        if prctl(PR_SET_DUMPABLE, 0i32) != 0 {
            eprintln!("warning: failed to set PR_SET_DUMPABLE");
        }

        // 3. Lock current and future pages into RAM — prevents swap-to-disk.
        //    Requires CAP_IPC_LOCK; silently ignore EPERM.
        let _ = mlockall(MCL_CURRENT | MCL_FUTURE);
    }
}

// ── Signal handling ─────────────────────────────────────────────────────────

/// Global flag set by signal handlers to request graceful shutdown.
/// Checked by the TUI event loop and long-running operations.
pub static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Install signal handlers for SIGTERM, SIGINT, and SIGHUP using `sigaction`.
///
/// First signal sets `SHUTDOWN_REQUESTED`, allowing destructors (and thus
/// `ZeroizeOnDrop`) to fire during graceful exit. A second signal calls
/// `_exit(128 + sig)` for immediate termination — both operations are
/// async-signal-safe per POSIX.
pub fn install_signal_handlers() {
    #[cfg(target_os = "linux")]
    {
        use linux::*;
        let action = SigAction {
            sa_handler: signal_handler,
            sa_flags: SA_RESTART as u64,
            sa_restorer: 0,
            sa_mask: [0u64; 16],
        };
        unsafe {
            for &sig in &[SIGTERM, SIGINT, SIGHUP] {
                sigaction(sig, &action, std::ptr::null_mut());
            }
        }
    }
}

#[cfg(target_os = "linux")]
extern "C" fn signal_handler(_sig: std::os::raw::c_int) {
    if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
        // Second signal — immediate exit (async-signal-safe)
        unsafe {
            linux::_exit(128 + _sig);
        }
    } else {
        // First signal — request graceful shutdown (atomic store is async-signal-safe)
        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
    }
}

/// Check whether a graceful shutdown has been requested.
pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
}

// ── Constant-time utilities ─────────────────────────────────────────────────

/// Constant-time byte-slice equality comparison.
///
/// Visits every byte in both slices without short-circuiting.
/// Returns `false` if lengths differ.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let xor = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (&x, &y)| acc | (x ^ y));
    xor == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_string_redacted_debug() {
        let s = SecretString::new("hunter2".to_string());
        assert_eq!(format!("{:?}", s), "[REDACTED]");
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn test_secret_vec_redacted_debug() {
        let v = SecretVec::new(vec![1, 2, 3]);
        assert_eq!(format!("{:?}", v), "[REDACTED BYTES]");
        assert_eq!(v.expose(), &[1, 2, 3]);
    }

    #[test]
    fn test_secret_string_zeroize() {
        let mut s = SecretString::new("password".to_string());
        s.zeroize();
        assert_eq!(s.expose(), "");
    }

    #[test]
    fn test_secret_vec_zeroize() {
        let mut v = SecretVec::new(vec![0xAA; 32]);
        v.zeroize();
        assert_eq!(v.expose(), &[0u8; 0]);
    }

    #[test]
    fn test_secret_vec_into_inner() {
        let v = SecretVec::new(vec![1, 2, 3, 4]);
        let inner = v.into_inner();
        assert_eq!(inner, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(constant_time_eq(&[], &[]));
        assert!(constant_time_eq(&[0u8; 32], &[0u8; 32]));
    }
}

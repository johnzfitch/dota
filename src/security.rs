//! Process-level setup and wrappers for in-memory key material
//!
//! Provides:
//! - `SecretString` / `SecretVec`: heap wrappers that wipe on drop
//! - Linux process setup: rlimit, prctl, mlockall via raw FFI
//! - Signal handling for graceful shutdown
//!
//! Uses raw FFI to avoid pulling `libc` into the dependency graph.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Wrapping types for in-memory bytes ──────────────────────────────────────

/// `String` that wipes its buffer on drop. Use for passphrases and other
/// in-memory string values that should not linger on the heap.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap a `String`. The buffer is moved, not copied.
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

/// `Vec<u8>` that wipes its buffer on drop. Use for decrypted byte buffers
/// and other in-memory values that should not linger on the heap.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    /// Wrap a `Vec<u8>`.
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }

    /// Borrow the inner bytes for read-only access.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Consume the wrapper and return the inner `Vec<u8>`.
    /// **Caller must ensure the returned Vec is wiped or moved into another
    /// wrapping container.**
    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED BYTES]")
    }
}

// ── Process setup (raw FFI — no libc crate dependency) ─────────────────────

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
    pub const SIG_DFL: usize = 0;

    #[repr(C)]
    pub struct Rlimit {
        pub rlim_cur: u64,
        pub rlim_max: u64,
    }

    unsafe extern "C" {
        pub fn setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int;
        pub fn prctl(option: c_int, ...) -> c_int;
        pub fn mlockall(flags: c_int) -> c_int;
        pub fn signal(signum: c_int, handler: usize) -> usize;
        pub fn raise(sig: c_int) -> c_int;
    }
}

/// Apply process setup at startup. Best-effort; failures are logged to
/// stderr and do not abort.
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
        let rlim = Rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if setrlimit(RLIMIT_CORE, &rlim) != 0 {
            eprintln!("warning: failed to set RLIMIT_CORE");
        }

        if prctl(PR_SET_DUMPABLE, 0i32) != 0 {
            eprintln!("warning: failed to set PR_SET_DUMPABLE");
        }

        // Requires CAP_IPC_LOCK; EPERM is silently ignored.
        let _ = mlockall(MCL_CURRENT | MCL_FUTURE);
    }
}

// ── Signal handling ─────────────────────────────────────────────────────────

/// Set by signal handlers. Polled by the TUI loop and other long-running
/// operations.
pub static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Install handlers for SIGTERM, SIGINT, SIGHUP. The first delivery sets
/// `SHUTDOWN_REQUESTED` so the program can unwind through normal drops; a
/// second delivery restores the default action and re-raises.
pub fn install_signal_handlers() {
    #[cfg(target_os = "linux")]
    {
        use linux::*;
        unsafe {
            for &sig in &[SIGTERM, SIGINT, SIGHUP] {
                signal(sig, signal_handler as *const () as usize);
            }
        }
    }
}

#[cfg(target_os = "linux")]
extern "C" fn signal_handler(sig: std::os::raw::c_int) {
    if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
        unsafe {
            linux::signal(sig, linux::SIG_DFL);
            linux::raise(sig);
        }
    } else {
        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
    }
}

/// Whether a graceful shutdown has been requested.
pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
}

// ── Comparison utilities ────────────────────────────────────────────────────

/// Length-checked byte-slice equality with no early exit on mismatching bytes.
/// Returns `false` if lengths differ. On equal-length inputs every byte is
/// visited and `std::hint::black_box` runs each iteration so the compiler
/// cannot optimise the loop into an early exit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc = std::hint::black_box(acc | (x ^ y));
    }
    std::hint::black_box(acc) == 0
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

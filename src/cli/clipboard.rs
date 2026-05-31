//! OS clipboard helper for `dota get --copy` and the TUI `copy` command.
//!
//! Keeps the supply chain narrow: `arboard` with `default-features = false`
//! (drops the `image` crate and its transitives) plus a plain `std::thread`
//! sleep for the auto-clear timer (no tokio runtime).
//!
//! Auto-clear semantics: `copy_with_autoclear` **blocks** the calling
//! process for the timeout duration, then clears the clipboard before
//! returning. This is the same UX as `pass show -c` from password-store
//! and is necessary because the X11/Wayland clipboard is process-scoped
//! on some backends -- a detached "fire and forget" thread inside a
//! short-lived CLI invocation would be reaped before it could run.
//!
//! A graceful-shutdown signal (Ctrl-C / SIGINT / SIGTERM / SIGHUP) cuts
//! the wait short, clears the clipboard, and returns. The polling loop
//! checks `security::shutdown_requested` once per 250ms.

use crate::security::{SecretString, shutdown_requested};
use anyhow::{Context, Result};
use std::thread;
use std::time::{Duration, Instant};

/// Default clear timeout when DOTA_CLIPBOARD_TIMEOUT_SECS is unset / invalid.
const DEFAULT_CLEAR_SECS: u64 = 30;
/// Maximum value accepted from the env var, to keep a runaway timer from
/// pinning a secret in the clipboard "forever" by accident.
const MAX_CLEAR_SECS: u64 = 600;
/// Polling interval for the shutdown-signal check while the timer runs.
const SHUTDOWN_POLL: Duration = Duration::from_millis(250);

/// Read the auto-clear duration from `DOTA_CLIPBOARD_TIMEOUT_SECS`, falling
/// back to a 30-second default. Values outside `1..=MAX_CLEAR_SECS` are
/// rejected silently in favour of the default.
pub fn clear_timeout_from_env() -> Duration {
    let secs = std::env::var("DOTA_CLIPBOARD_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&s| (1..=MAX_CLEAR_SECS).contains(&s))
        .unwrap_or(DEFAULT_CLEAR_SECS);
    Duration::from_secs(secs)
}

/// Copy a secret to the OS clipboard, hold the clipboard until `clear_after`
/// elapses (or a shutdown signal arrives), then clear it.
///
/// Returns once the clipboard has been cleared. The intermediate `String`
/// `arboard::Clipboard::set_text` needs is owned by us so we can zeroize
/// our local copy after the OS call -- arboard itself may keep an internal
/// copy until the next clipboard write, which is unavoidable.
///
/// On platforms where arboard cannot reach a clipboard (no `DISPLAY`, no
/// X11/Wayland, headless CI), this returns an error rather than silently
/// echoing the secret.
pub fn copy_with_autoclear(secret: &SecretString, clear_after: Duration) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new().context(
        "failed to open OS clipboard (DISPLAY/Wayland required on Linux). \
         If you're on a headless session, use `dota get` instead.",
    )?;

    // Pass the secret slice directly to arboard -- avoids a second local
    // heap allocation we'd otherwise have to zeroize.
    clipboard
        .set_text(secret.expose())
        .context("failed to set clipboard contents")?;

    // Block until timeout or shutdown signal, polling the signal flag so
    // a Ctrl-C clears the clipboard immediately rather than after the
    // full wait.
    let deadline = Instant::now() + clear_after;
    while Instant::now() < deadline {
        if shutdown_requested() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(SHUTDOWN_POLL.min(remaining));
    }

    // Best-effort clear. If we lost the clipboard owner role to another
    // process (X11 selection semantics), our `set_text("")` may be a
    // no-op against the actual current owner -- still safe; what we wrote
    // is gone the moment another process replaces it.
    let _ = clipboard.set_text(String::new());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Consolidated env-var tests live in one `#[test]` so the parallel
    /// test runner cannot interleave `set_var`/`remove_var` calls across
    /// threads. Splitting them out caused intermittent failures.
    #[test]
    fn clear_timeout_handles_all_env_inputs() {
        // SAFETY: env mutation is `unsafe` in Rust 2024 edition; ok in tests.
        unsafe {
            std::env::remove_var("DOTA_CLIPBOARD_TIMEOUT_SECS");
        }
        assert_eq!(
            clear_timeout_from_env(),
            Duration::from_secs(30),
            "default when unset"
        );

        unsafe {
            std::env::set_var("DOTA_CLIPBOARD_TIMEOUT_SECS", "15");
        }
        assert_eq!(
            clear_timeout_from_env(),
            Duration::from_secs(15),
            "honors valid value"
        );

        unsafe {
            std::env::set_var("DOTA_CLIPBOARD_TIMEOUT_SECS", "99999");
        }
        assert_eq!(
            clear_timeout_from_env(),
            Duration::from_secs(30),
            "falls back on value above MAX_CLEAR_SECS"
        );

        unsafe {
            std::env::set_var("DOTA_CLIPBOARD_TIMEOUT_SECS", "0");
        }
        assert_eq!(
            clear_timeout_from_env(),
            Duration::from_secs(30),
            "falls back on zero"
        );

        unsafe {
            std::env::set_var("DOTA_CLIPBOARD_TIMEOUT_SECS", "garbage");
        }
        assert_eq!(
            clear_timeout_from_env(),
            Duration::from_secs(30),
            "falls back on unparseable input"
        );

        unsafe {
            std::env::remove_var("DOTA_CLIPBOARD_TIMEOUT_SECS");
        }
    }
}

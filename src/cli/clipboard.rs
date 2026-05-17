//! OS clipboard helper for `dota get --copy` and the TUI `copy` command.
//!
//! Keeps the supply chain narrow: `arboard` with `default-features = false`
//! (drops the `image` crate and its transitives) plus a plain `std::thread`
//! sleep for the auto-clear timer (no tokio runtime).

use crate::security::SecretString;
use anyhow::{Context, Result};
use std::thread;
use std::time::Duration;
use zeroize::Zeroize;

/// Default clear timeout when DOTA_CLIPBOARD_TIMEOUT_SECS is unset / invalid.
const DEFAULT_CLEAR_SECS: u64 = 30;
/// Maximum value accepted from the env var, to keep a runaway timer from
/// pinning a secret in the clipboard "forever" by accident.
const MAX_CLEAR_SECS: u64 = 600;

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

/// Copy a secret to the OS clipboard, then spawn a background thread that
/// clears the clipboard after `clear_after`.
///
/// The intermediate `String` arboard requires is zeroized once the OS call
/// returns. The background-thread copy is also zeroized after the OS clear.
///
/// On platforms where arboard cannot reach a clipboard (no DISPLAY, no
/// X11/Wayland, headless CI), this returns an error rather than silently
/// echoing the secret.
pub fn copy_with_autoclear(secret: &SecretString, clear_after: Duration) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new().context(
        "failed to open OS clipboard (DISPLAY/Wayland required on Linux). \
         If you're on a headless session, use `dota get` instead.",
    )?;

    let mut owned = secret.expose().to_string();
    clipboard
        .set_text(owned.clone())
        .context("failed to set clipboard contents")?;
    owned.zeroize();

    let timeout = clear_after;
    thread::Builder::new()
        .name("dota-clipboard-clear".into())
        .spawn(move || {
            thread::sleep(timeout);
            if let Ok(mut clip) = arboard::Clipboard::new() {
                // Best-effort: failure to clear is logged but not fatal —
                // the user can clear manually. We do not surface a panic
                // because the helper thread runs after the parent has
                // returned and the process may have moved on.
                let _ = clip.set_text(String::new());
            }
        })
        .context("failed to spawn clipboard auto-clear thread")?;

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

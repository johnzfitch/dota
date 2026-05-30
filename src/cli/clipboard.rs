//! Clipboard integration with a timed auto-clear.
//!
//! `dota get NAME --copy` and the interactive shell's `copy NAME` route through
//! here instead of writing the secret to stdout, where it would persist in
//! terminal scrollback, `script(1)` captures, tmux history, and IDE buffers
//! (SECURITY-AUDIT.md H1 / M5).
//!
//! The secret is placed on the system clipboard and cleared after
//! [`CLIPBOARD_CLEAR_SECONDS`]. Clearing is done with a plain `std::thread`
//! timer — no async runtime is involved.
//!
//! Two entry points exist because clipboard ownership semantics differ by
//! process lifetime:
//!
//! * [`copy_blocking`] is for the one-shot CLI. On X11 the clipboard contents
//!   only persist while the owning process is alive, so a one-shot `dota get`
//!   must stay resident for the hold window; it blocks, then clears, then
//!   returns. This also guarantees the secret is wiped before the command exits.
//! * [`copy_background`] is for the long-lived interactive shell, which stays
//!   alive on its own. It spawns a detached timer thread that clears the
//!   clipboard after the window without blocking the prompt.

use anyhow::{Context, Result};
use arboard::Clipboard;
use std::io::IsTerminal;
use std::thread;
use std::time::Duration;

/// How long a copied secret lingers on the clipboard before it is cleared.
pub const CLIPBOARD_CLEAR_SECONDS: u64 = 30;

/// Copy `value` to the clipboard, block for the auto-clear window, then clear.
///
/// Intended for the one-shot CLI (`dota get NAME --copy`). Blocking keeps the
/// clipboard owned for the hold window on X11 and ensures the secret is cleared
/// before the process exits even if it is interrupted by a normal return.
pub fn copy_blocking(value: &str) -> Result<()> {
    let mut clipboard = open_clipboard()?;
    clipboard
        .set_text(value.to_owned())
        .context("Failed to write secret to the system clipboard")?;

    // Status goes to stderr, and only when stderr is a terminal: `dota get
    // NAME --copy` keeps stdout empty so it stays safe to pipe/redirect, and a
    // non-interactive caller should not get a banner at all.
    if std::io::stderr().is_terminal() {
        eprintln!(
            "Secret copied to clipboard; it will be cleared in {CLIPBOARD_CLEAR_SECONDS}s. \
             Press Ctrl-C to exit sooner (the clipboard is then cleared by your session)."
        );
    }
    thread::sleep(Duration::from_secs(CLIPBOARD_CLEAR_SECONDS));

    // Best-effort clear. If another application has since taken ownership of the
    // clipboard there is nothing to clear, which is fine.
    let _ = clipboard.clear();
    Ok(())
}

/// Copy `value` to the clipboard and arrange for it to be cleared after the
/// auto-clear window without blocking the caller.
///
/// Intended for the long-lived interactive shell, which keeps the process (and
/// therefore X11 clipboard ownership) alive after this returns.
pub fn copy_background(value: &str) -> Result<()> {
    let mut clipboard = open_clipboard()?;
    clipboard
        .set_text(value.to_owned())
        .context("Failed to write secret to the system clipboard")?;

    // Move the clipboard handle into the timer thread so it (and the X11
    // selection ownership it carries) survives until the clear fires.
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(CLIPBOARD_CLEAR_SECONDS));
        let _ = clipboard.clear();
    });
    Ok(())
}

fn open_clipboard() -> Result<Clipboard> {
    Clipboard::new().context(
        "Failed to access the system clipboard. A clipboard requires a desktop \
         session; on a headless host use plain `dota get NAME` (and mind that it \
         prints to stdout) or `dota export-env`.",
    )
}

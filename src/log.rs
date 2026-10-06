use std::fmt::Display;
use std::sync::atomic::{AtomicU8, Ordering};

/// How much keysafe prints to stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Warnings and errors only.
    Quiet = 0,
    /// Also informational messages.
    Normal = 1,
    /// Also details for debugging.
    Verbose = 2,
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Normal as u8);

/// Sets how much keysafe prints to stderr.
pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Returns true if messages of `level` are printed.
fn enabled(level: Level) -> bool {
    LEVEL.load(Ordering::Relaxed) >= level as u8
}

/// Prints a warning to stderr.
pub fn warn(message: impl Display) {
    eprintln!("keysafe: warning: {message}");
}

/// Prints an informational message to stderr, unless quiet.
pub fn info(message: impl Display) {
    if enabled(Level::Normal) {
        eprintln!("keysafe: {message}");
    }
}

/// Prints a detail for debugging to stderr, if verbose. Never pass secret values.
pub fn debug(message: impl Display) {
    if enabled(Level::Verbose) {
        eprintln!("keysafe: debug: {message}");
    }
}

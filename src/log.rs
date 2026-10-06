use console::{style, StyledObject, Term};
use indicatif::{ProgressBar, ProgressStyle};
use std::fmt::Display;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::Duration;

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

/// Whether output on stdout is styled. Off unless `main` turns it on for a terminal, so
/// output written elsewhere, like in tests, stays plain.
static STYLE_STDOUT: AtomicBool = AtomicBool::new(false);

/// The spinner currently shown on stderr, if any. Messages are printed above it.
static SPINNER: Mutex<Option<ProgressBar>> = Mutex::new(None);

/// Sets how much keysafe prints to stderr.
pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Sets whether output on stdout is styled.
pub fn set_style_stdout(enabled: bool) {
    STYLE_STDOUT.store(enabled, Ordering::Relaxed);
}

/// Returns true if messages of `level` are printed.
fn enabled(level: Level) -> bool {
    LEVEL.load(Ordering::Relaxed) >= level as u8
}

/// Returns `value` styled for stdout, when stdout styling is on.
pub fn styled<D>(value: D) -> StyledObject<D> {
    style(value).force_styling(STYLE_STDOUT.load(Ordering::Relaxed))
}

/// Prints a line to stderr, above the spinner if one is shown.
fn print(line: String) {
    match SPINNER.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        Some(spinner) => spinner.println(line),
        None => eprintln!("{line}"),
    }
}

/// Prints an error to stderr.
pub fn error(message: impl Display) {
    print(format!(
        "keysafe: {} {message}",
        style("error:").red().bold().for_stderr()
    ));
}

/// Prints a warning to stderr.
pub fn warn(message: impl Display) {
    print(format!(
        "keysafe: {} {message}",
        style("warning:").yellow().bold().for_stderr()
    ));
}

/// Prints an informational message to stderr, unless quiet.
pub fn info(message: impl Display) {
    if enabled(Level::Normal) {
        print(format!("keysafe: {message}"));
    }
}

/// Prints the outcome of an action to stderr, unless quiet.
pub fn success(message: impl Display) {
    if enabled(Level::Normal) {
        print(format!(
            "{} {message}",
            style("✓").green().bold().for_stderr()
        ));
    }
}

/// Prints a detail for debugging to stderr, if verbose. Never pass secret values.
pub fn debug(message: impl Display) {
    if enabled(Level::Verbose) {
        print(
            style(format!("keysafe: debug: {message}"))
                .dim()
                .for_stderr()
                .to_string(),
        );
    }
}

/// Spinner shows a message on stderr while something slow runs, until it is dropped.
///
/// Nothing is shown when stderr is not a terminal or keysafe runs quietly.
pub struct Spinner(Option<ProgressBar>);

/// Shows `message` with a spinner on stderr until the returned [`Spinner`] is dropped.
pub fn spinner(message: impl Into<String>) -> Spinner {
    if !enabled(Level::Normal) || !Term::stderr().is_term() {
        return Spinner(None);
    }

    let bar = ProgressBar::new_spinner();
    if let Ok(template) = ProgressStyle::with_template("{spinner:.cyan} {msg}") {
        bar.set_style(template);
    }
    bar.set_message(message.into());
    bar.enable_steady_tick(Duration::from_millis(80));
    *SPINNER.lock().unwrap_or_else(|e| e.into_inner()) = Some(bar.clone());
    Spinner(Some(bar))
}

impl Drop for Spinner {
    fn drop(&mut self) {
        if let Some(bar) = self.0.take() {
            bar.finish_and_clear();
            *SPINNER.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }
}

/// Returns `count` with `noun`, pluralized by appending `s` (e.g. "1 secret", "3 secrets").
pub fn count(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_pluralizes() {
        assert_eq!(count(0, "secret"), "0 secrets");
        assert_eq!(count(1, "SSH key"), "1 SSH key");
        assert_eq!(count(3, "SSH key"), "3 SSH keys");
    }

    #[test]
    fn styled_is_plain_unless_enabled() {
        assert_eq!(styled("✓").green().to_string(), "✓");
    }
}

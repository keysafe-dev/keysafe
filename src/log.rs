use std::fmt::Display;

/// Prints a warning to stderr.
pub fn warn(message: impl Display) {
    eprintln!("secret-env: warning: {message}");
}

/// Prints an informational message to stderr.
pub fn info(message: impl Display) {
    eprintln!("secret-env: {message}");
}

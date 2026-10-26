use anyhow::{anyhow, bail, Context, Result};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

use crate::log::debug;
use crate::vault::SecretStore;

/// The Apple-signed tool the items are read and written through.
const SECURITY: &str = "/usr/bin/security";

/// Exit status of `security` when the item does not exist (errSecItemNotFound).
const NOT_FOUND: i32 = 44;

/// SecurityKeychain stores secrets in the macOS keychain through `/usr/bin/security`.
///
/// The Security framework ties an item's access list to the identity of the calling binary,
/// so a `keysafe` that is rebuilt (an ad-hoc signature is a hash of the code) asks for access
/// to every item again. Items written by `security` trust `security`, a stable binary, so one
/// **Always Allow** lasts. The price is isolation: any process of the user can run `security`
/// and read the items without being asked.
#[derive(Default)]
pub struct SecurityKeychain {
    /// Keychain file to use instead of the default keychain, for tests.
    keychain: Option<PathBuf>,
}

/// One run of `security`: its arguments and what is written to its stdin.
#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    args: Vec<String>,
    stdin: Option<String>,
}

impl SecurityKeychain {
    /// Creates a store using the default keychain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses the keychain file at `path` instead of the default keychain.
    #[cfg(test)]
    pub fn with_keychain(path: impl Into<PathBuf>) -> Self {
        Self {
            keychain: Some(path.into()),
        }
    }

    /// Returns `command` followed by the keychain argument, if one is selected.
    fn command(&self, command: &str, options: &[&str]) -> Invocation {
        let mut args: Vec<String> = [command]
            .into_iter()
            .chain(options.iter().copied())
            .map(String::from)
            .collect();
        args.extend(self.keychain.iter().map(|p| p.display().to_string()));
        Invocation { args, stdin: None }
    }

    /// Returns the invocation reading `service` / `account`.
    ///
    /// `-g` prints the data on stderr as `password: "text"` for plain values and as
    /// `password: 0x<hex>  "text"` otherwise. `-w` is no use: it prints hex for values it
    /// cannot show as text, so a plain value that looks like hex is indistinguishable.
    fn read(&self, service: &str, account: &str) -> Invocation {
        self.command(
            "find-generic-password",
            &["-g", "-s", service, "-a", account],
        )
    }

    /// Returns the invocation deleting `service` / `account`.
    fn remove(&self, service: &str, account: &str) -> Invocation {
        self.command("delete-generic-password", &["-s", service, "-a", account])
    }

    /// Returns the invocation listing the attributes of every item, never the data.
    fn list(&self) -> Invocation {
        self.command("dump-keychain", &[])
    }

    /// Returns the invocation writing `value` to `service` / `account`.
    ///
    /// The command goes to the stdin of `security -i`, as hex (`-X`), so the value is not in
    /// the arguments of a process every user can list.
    fn write(&self, service: &str, account: &str, value: &str) -> Result<Invocation> {
        if value.is_empty() {
            bail!("security cannot store an empty value");
        }

        let mut line = format!(
            "add-generic-password -U -s {} -a {} -X {}",
            quote(service)?,
            quote(account)?,
            encode_hex(value.as_bytes())
        );
        if let Some(keychain) = &self.keychain {
            line.push(' ');
            line.push_str(&quote(&keychain.display().to_string())?);
        }
        line.push('\n');
        Ok(Invocation {
            args: vec!["-i".to_string()],
            stdin: Some(line),
        })
    }

    /// Runs `security`, returning its exit status, stdout and stderr.
    fn run(&self, invocation: &Invocation) -> Result<(Option<i32>, String, String)> {
        // Only the arguments are logged: the stdin of a write holds the value
        debug(format!("running: security {}", invocation.args.join(" ")));
        let mut child = Command::new(SECURITY)
            .args(&invocation.args)
            .stdin(match invocation.stdin {
                Some(_) => Stdio::piped(),
                None => Stdio::null(),
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!("failed to run {SECURITY}; the security backend needs macOS")
            })?;
        if let (Some(stdin), Some(mut pipe)) = (&invocation.stdin, child.stdin.take()) {
            pipe.write_all(stdin.as_bytes())
                .with_context(|| format!("failed to write to {SECURITY}"))?;
        }

        let output = child
            .wait_with_output()
            .with_context(|| format!("failed to run {SECURITY}"))?;
        Ok((
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ))
    }
}

impl SecretStore for SecurityKeychain {
    fn describe(&self) -> String {
        SECURITY.to_string()
    }

    fn accounts(&self, service: &str) -> Result<Vec<String>> {
        let (status, stdout, stderr) = self.run(&self.list())?;
        if status != Some(0) {
            bail!(
                "failed to list the keychain for {service}: {}",
                first_line(&stderr)
            );
        }
        Ok(parse_accounts(&stdout, service))
    }

    fn get(&self, service: &str, account: &str) -> Result<Option<String>> {
        let (status, _, stderr) = self.run(&self.read(service, account))?;
        match status {
            Some(0) => parse_password(&stderr)
                .with_context(|| format!("failed to read {service}/{account} from the keychain"))
                .map(Some),
            Some(NOT_FOUND) => Ok(None),
            _ => Err(anyhow!("{}", first_line(&stderr))).context(format!(
                "failed to read {service}/{account} from the keychain"
            )),
        }
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<()> {
        let (status, _, stderr) = self.run(&self.write(service, account, value)?)?;
        if status != Some(0) {
            return Err(anyhow!("{}", first_line(&stderr))).context(format!(
                "failed to write {service}/{account} to the keychain"
            ));
        }
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool> {
        let (status, _, stderr) = self.run(&self.remove(service, account))?;
        match status {
            Some(0) => Ok(true),
            Some(NOT_FOUND) => Ok(false),
            _ => Err(anyhow!("{}", first_line(&stderr))).context(format!(
                "failed to delete {service}/{account} from the keychain"
            )),
        }
    }
}

/// Returns the first line of `text`, which is where `security` puts its error.
fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or("unknown error").trim()
}

/// Quotes `text` as one argument of a `security -i` command line.
fn quote(text: &str) -> Result<String> {
    if text.chars().any(char::is_control) {
        bail!("{text:?} has a control character, which security cannot take");
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// Returns `bytes` as lowercase hex.
fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns the bytes `hex` stands for, or `None` if it is not hex.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Parses a value as `security` prints it: `"text"`, `0x<hex>  "text"` or `<NULL>`.
///
/// The hex form is the data itself; the text after it is only a rendering. A value in the
/// plain form may hold quotes, so it is everything between the first and the last one.
fn parse_value(text: &str) -> Result<Option<String>> {
    let text = text.trim_end();
    if text == "<NULL>" {
        return Ok(None);
    }
    if let Some(rest) = text.strip_prefix("0x") {
        let hex = rest.split_whitespace().next().unwrap_or_default();
        let bytes = decode_hex(hex).ok_or_else(|| anyhow!("malformed hex in the output"))?;
        return Ok(Some(
            String::from_utf8(bytes).context("the value is not valid UTF-8")?,
        ));
    }
    match text.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
        Some(plain) => Ok(Some(plain.to_string())),
        None => bail!("unexpected output"),
    }
}

/// Returns the data from the stderr of `find-generic-password -g`.
fn parse_password(stderr: &str) -> Result<String> {
    let value = stderr
        .lines()
        .find_map(|line| line.strip_prefix("password:"))
        .ok_or_else(|| anyhow!("no password in the output"))?;
    // An empty password is printed without a value
    let value = value.trim_start();
    if value.is_empty() {
        return Ok(String::new());
    }
    Ok(parse_value(value)?.unwrap_or_default())
}

/// Returns the accounts of the generic passwords stored for `service` in the output of
/// `dump-keychain`, which lists attributes only.
fn parse_accounts(dump: &str, service: &str) -> Vec<String> {
    let mut accounts = Vec::new();
    let (mut generic, mut svce, mut acct) = (false, None, None);
    // Every item starts with a `keychain:` line; the extra one flushes the last
    for line in dump.lines().chain(["keychain:"]) {
        let line = line.trim_start();
        if line.starts_with("keychain:") {
            if let (true, Some(s), Some(a)) = (generic, svce.take(), acct.take()) {
                if s == service {
                    accounts.push(a);
                }
            }
            (generic, svce, acct) = (false, None, None);
        } else if let Some(class) = line.strip_prefix("class:") {
            generic = class.trim() == "\"genp\"";
        } else if let Some(value) = line.strip_prefix("\"svce\"<blob>=") {
            svce = parse_value(value).ok().flatten();
        } else if let Some(value) = line.strip_prefix("\"acct\"<blob>=") {
            acct = parse_value(value).ok().flatten();
        }
    }
    accounts.sort();
    accounts.dedup();
    accounts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_keeps_the_value_out_of_the_arguments() {
        let store = SecurityKeychain::new();
        let value = "s3cr3t-value";
        let invocation = store.write("keysafe.work", "TOKEN", value).unwrap();

        assert_eq!(invocation.args, ["-i"]);
        let stdin = invocation.stdin.unwrap();
        assert!(!stdin.contains(value), "the value is sent as hex");
        assert_eq!(
            stdin,
            format!(
                "add-generic-password -U -s \"keysafe.work\" -a \"TOKEN\" -X {}\n",
                encode_hex(value.as_bytes())
            )
        );
    }

    #[test]
    fn write_targets_the_selected_keychain() {
        let store = SecurityKeychain::with_keychain("/tmp/a b/test.keychain-db");
        let invocation = store.write("svc", "acct", "v").unwrap();
        assert!(invocation
            .stdin
            .unwrap()
            .ends_with(" -X 76 \"/tmp/a b/test.keychain-db\"\n"));
    }

    #[test]
    fn write_quotes_names_and_rejects_control_characters() {
        let store = SecurityKeychain::new();
        let stdin = store
            .write("svc", "a \"b\" \\c", "v")
            .unwrap()
            .stdin
            .unwrap();
        assert!(stdin.contains(r#"-a "a \"b\" \\c" "#));

        assert!(store.write("svc", "two\nlines", "v").is_err());
        assert!(store.write("svc", "acct", "").is_err());
    }

    #[test]
    fn reads_never_carry_a_value() {
        let store = SecurityKeychain::with_keychain("/tmp/test.keychain-db");
        assert_eq!(
            store.read("svc", "acct").args,
            [
                "find-generic-password",
                "-g",
                "-s",
                "svc",
                "-a",
                "acct",
                "/tmp/test.keychain-db"
            ]
        );
        assert_eq!(
            store.remove("svc", "acct").args,
            [
                "delete-generic-password",
                "-s",
                "svc",
                "-a",
                "acct",
                "/tmp/test.keychain-db"
            ]
        );
        assert_eq!(
            store.list().args,
            ["dump-keychain", "/tmp/test.keychain-db"]
        );
    }

    #[test]
    fn parses_plain_multi_line_non_ascii_and_hex_looking_values() {
        let read = |stderr: &str| parse_password(stderr).unwrap();

        assert_eq!(read("password: \"hello\"\n"), "hello");
        assert_eq!(read("password: \"say \"hi\"\"\n"), "say \"hi\"");
        assert_eq!(read("password: \" padded \"\n"), " padded ");
        // Looks like hex, but is plain text
        assert_eq!(read("password: \"DEADBEEF\"\n"), "DEADBEEF");
        assert_eq!(read("password: \"0xABCD\"\n"), "0xABCD");
        // The data is the hex; the text after it is only a rendering
        assert_eq!(
            read("password: 0x6C696E65310A6C696E6532  \"line1\\012line2\"\n"),
            "line1\nline2"
        );
        assert_eq!(
            read("password: 0xE29C93  \"\\342\\234\\223\"\n"),
            "\u{2713}"
        );
        assert_eq!(read("password: 0x615C62  \"a\\134b\"\n"), "a\\b");
        // Other output around it
        assert_eq!(read("some warning\npassword: \"value\"\n"), "value");
    }

    #[test]
    fn rejects_output_without_a_password() {
        assert!(parse_password("nothing here\n").is_err());
        assert!(parse_password("password: 0xZZ  \"x\"\n").is_err());
        assert!(parse_password("password: 0xFF  \"x\"\n").is_err());
    }

    #[test]
    fn lists_the_accounts_of_a_service_only() {
        let item = |class: &str, service: &str, account: &str| {
            format!(
                "keychain: \"/Users/me/Library/Keychains/login.keychain-db\"\n\
                 version: 256\n\
                 class: \"{class}\"\n\
                 attributes:\n\
                 \x20   0x00000007 <blob>=\"{service}\"\n\
                 \x20   \"acct\"<blob>={account}\n\
                 \x20   \"cdat\"<timedate>=0x32303236  \"2026\\000\"\n\
                 \x20   \"svce\"<blob>=\"{service}\"\n"
            )
        };
        let dump = [
            item("genp", "keysafe.work", "\"TOKEN\""),
            item("genp", "keysafe.other", "\"ELSEWHERE\""),
            item("genp", "keysafe.work", "\"API_KEY\""),
            item("inet", "keysafe.work", "\"NOT_GENERIC\""),
            // Non-ASCII names come as hex only
            item("genp", "keysafe.work", "0xD0BAD0BBD18ED187 "),
            item("genp", "keysafe.work", "<NULL>"),
            item("genp", "keysafe.work", "\"TOKEN\""),
        ]
        .concat();

        assert_eq!(
            parse_accounts(&dump, "keysafe.work"),
            ["API_KEY", "TOKEN", "\u{43a}\u{43b}\u{44e}\u{447}"]
        );
        assert!(parse_accounts(&dump, "keysafe.missing").is_empty());
        assert!(parse_accounts("", "keysafe.work").is_empty());
    }

    /// Runs `security` against a keychain made for the test, never the login keychain.
    #[cfg(target_os = "macos")]
    mod keychain {
        use super::*;

        /// Creates an unlocked keychain in `dir`.
        fn temporary(dir: &std::path::Path) -> SecurityKeychain {
            let path = dir.join("test.keychain-db");
            for args in [
                ["create-keychain", "-p", "test-password"],
                ["unlock-keychain", "-p", "test-password"],
            ] {
                let status = Command::new(SECURITY)
                    .args(args)
                    .arg(&path)
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            SecurityKeychain::with_keychain(path)
        }

        #[test]
        fn round_trips_values() {
            let dir = tempfile::tempdir().unwrap();
            let store = temporary(dir.path());
            let service = "keysafe.test";
            let values = [
                ("PLAIN", "hello"),
                ("MULTI_LINE", "line1\nline2 \"quoted\" \\ \u{2713}"),
                ("NON_ASCII", "\u{43a}\u{43b}\u{44e}\u{447}"),
                ("HEX_LOOKING", "DEADBEEF"),
                ("PADDED", "  padded  "),
                ("with \"odd\" \\name", "odd"),
            ];

            for (account, value) in values {
                store.set(service, account, value).unwrap();
            }
            for (account, value) in values {
                assert_eq!(
                    store.get(service, account).unwrap().as_deref(),
                    Some(value),
                    "{account}"
                );
            }
        }

        #[test]
        fn replaces_lists_and_deletes() {
            let dir = tempfile::tempdir().unwrap();
            let store = temporary(dir.path());

            store.set("keysafe.a", "ONE", "1").unwrap();
            store.set("keysafe.a", "TWO", "2").unwrap();
            store.set("keysafe.b", "OTHER", "3").unwrap();
            store.set("keysafe.a", "ONE", "replaced").unwrap();

            assert_eq!(
                store.get("keysafe.a", "ONE").unwrap().as_deref(),
                Some("replaced")
            );
            assert_eq!(store.accounts("keysafe.a").unwrap(), ["ONE", "TWO"]);
            assert!(store.accounts("keysafe.none").unwrap().is_empty());

            assert!(store.delete("keysafe.a", "ONE").unwrap());
            assert!(!store.delete("keysafe.a", "ONE").unwrap());
            assert_eq!(store.get("keysafe.a", "ONE").unwrap(), None);
            assert_eq!(store.accounts("keysafe.a").unwrap(), ["TWO"]);
        }
    }
}

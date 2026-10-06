use anyhow::{bail, Context, Result};
use std::{
    cell::RefCell,
    collections::HashMap,
    process::{Command, Stdio},
};

use crate::vault::Provider;

#[cfg(test)]
use mockall::automock;

/// SecretClient reads secrets from a password manager.
#[cfg_attr(test, automock)]
pub trait SecretClient {
    /// Reads the secret referenced by `path` from `provider`.
    fn read(&self, provider: &Provider, path: &str) -> Result<String>;
}

/// Client reads secrets through the CLI of each provider: `op` for 1Password.
#[derive(Default)]
pub struct Client {
    /// 1Password sign-in state per account, checked once per run.
    signed_in: RefCell<HashMap<Option<String>, bool>>,
}

impl Client {
    /// Creates a new client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the `--account` arguments selecting `account`, if any.
    fn account_args(account: Option<&str>) -> Vec<&str> {
        account.map(|a| vec!["--account", a]).unwrap_or_default()
    }

    /// Fails with a hint when the 1Password CLI is not signed in to `account`.
    fn ensure_signed_in(&self, account: Option<&str>) -> Result<()> {
        let mut cache = self.signed_in.borrow_mut();
        let key = account.map(str::to_string);
        let signed_in = match cache.get(&key) {
            Some(value) => *value,
            None => {
                let status = Command::new("op")
                    .args(["account", "get"])
                    .args(Self::account_args(account))
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .context("failed to run the 1Password CLI (op); is it installed?")?;
                *cache.entry(key).or_insert(status.success())
            }
        };

        if !signed_in {
            match account {
                Some(account) => bail!(
                    "not signed in to 1Password account {account} (run: op signin --account {account})"
                ),
                None => bail!("not signed in to 1Password (run: op signin)"),
            }
        }
        Ok(())
    }

    /// Reads `path` from 1Password with the `op` CLI.
    fn read_1password(&self, account: Option<&str>, path: &str) -> Result<String> {
        self.ensure_signed_in(account)?;

        // stdin and stderr stay attached to the terminal, so `op` can prompt
        // for authorization and report its own errors.
        let output = Command::new("op")
            .args(["read", "--no-newline"])
            .args(Self::account_args(account))
            .arg(path)
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run the 1Password CLI (op); is it installed?")?;
        if !output.status.success() {
            bail!("failed to read {path} from 1Password");
        }

        let value = String::from_utf8(output.stdout)
            .with_context(|| format!("secret {path} is not valid UTF-8"))?;
        if value.is_empty() {
            bail!("secret {path} is empty");
        }
        Ok(value)
    }
}

impl SecretClient for Client {
    fn read(&self, provider: &Provider, path: &str) -> Result<String> {
        match provider {
            Provider::OnePassword { account } => self.read_1password(account.as_deref(), path),
        }
    }
}

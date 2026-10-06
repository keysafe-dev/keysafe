use anyhow::Result;

use crate::log::warn;
use crate::vault::{
    fingerprint, public_key, Cache, KeyAgent, Profile, RuntimeDir, Secret, SecretClient, SecretKind,
};

/// Source decides where secret values may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The keychain cache only; secrets that are not cached are skipped.
    Cache,
    /// The keychain cache, falling back to 1Password; `true` skips the cache.
    Any(bool),
}

/// An environment variable to export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    /// Variable name.
    pub key: String,
    /// Variable value.
    pub value: String,
}

/// An SSH key [`Loader::add_key`] added to the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedKey {
    /// SHA256 fingerprint, as printed by `ssh-add -l`.
    pub fingerprint: String,
    /// OpenSSH public key, which is enough to remove the key from the agent again.
    pub public_key: String,
}

/// What [`Loader::add_key`] did with an SSH key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOutcome {
    /// The key was added to the agent, with its fingerprint and public key if the private
    /// key could be parsed.
    Added(Option<AddedKey>),
    /// The agent already held the key, so it was left alone.
    Present,
}

/// Loader resolves secret values from the keychain cache or 1Password.
pub struct Loader {
    /// Client used to fetch secrets from 1Password.
    pub client: Box<dyn SecretClient>,
    /// Cache holding previously fetched secrets.
    pub cache: Cache,
}

impl Loader {
    /// Returns the value of `secret`: from the cache unless `refresh` is set, otherwise
    /// from 1Password, caching the fetched value.
    pub fn load(&self, account: &Profile, secret: &Secret, refresh: bool) -> Result<String> {
        if !refresh {
            match self.cache.get(&account.name, &secret.name) {
                Ok(Some(value)) => return Ok(value),
                Ok(None) => {}
                Err(err) => warn(format!("{err:#}; fetching it from 1Password")),
            }
        }

        let value = self.client.read(&account.provider, &secret.path)?;
        // A failed cache write only costs a 1Password round trip next time.
        if let Err(err) = self.cache.set(&account.name, &secret.name, &value) {
            warn(format!("{err:#}"));
        }
        Ok(value)
    }

    /// Resolves the variables of the given env and file secrets, writing file secrets to
    /// `runtime`. Each secret that fails is reported and counted rather than aborting the rest.
    pub fn resolve<'a>(
        &self,
        runtime: &RuntimeDir,
        account: &Profile,
        secrets: impl IntoIterator<Item = &'a Secret>,
        source: Source,
    ) -> (Vec<Variable>, usize) {
        let mut variables = Vec::new();
        let mut failed = 0;

        for secret in secrets {
            let result = match source {
                Source::Cache => self.cache.get(&account.name, &secret.name),
                Source::Any(refresh) => self.load(account, secret, refresh).map(Some),
            }
            .and_then(|value| match (value, secret.kind) {
                (Some(value), SecretKind::File) => runtime
                    .write(&account.name, &secret.name, &value)
                    .map(|path| Some(path.to_string_lossy().into_owned())),
                (value, _) => Ok(value),
            });

            match result {
                Ok(Some(value)) => variables.push(Variable {
                    key: secret.name.clone(),
                    value,
                }),
                Ok(None) => {}
                Err(err) => {
                    warn(format!("failed to load '{}': {err:#}", secret.name));
                    failed += 1;
                }
            }
        }

        (variables, failed)
    }

    /// Adds the SSH key `secret` to the agent, unless the agent already holds it and
    /// `refresh` is not set.
    pub fn add_key(
        &self,
        agent: &dyn KeyAgent,
        present: &[String],
        account: &Profile,
        secret: &Secret,
        lifetime: &str,
        refresh: bool,
    ) -> Result<KeyOutcome> {
        let key = self.load(account, secret, refresh)?;
        let added =
            fingerprint(&key)
                .ok()
                .zip(public_key(&key).ok())
                .map(|(fingerprint, public_key)| AddedKey {
                    fingerprint,
                    public_key,
                });
        // Re-adding a key resets its lifetime, so only do it when a refresh was requested.
        if !refresh
            && added
                .as_ref()
                .is_some_and(|k| present.contains(&k.fingerprint))
        {
            return Ok(KeyOutcome::Present);
        }

        agent.add(&key, lifetime)?;
        Ok(KeyOutcome::Added(added))
    }
}

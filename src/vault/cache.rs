use anyhow::{anyhow, Context, Result};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use crate::log::{debug, warn};
use crate::vault::Profile;

/// SecretStore persists secret values in a secure credential store.
pub trait SecretStore {
    /// Returns the value stored for `service` / `account`, or `None` if there is none.
    fn get(&self, service: &str, account: &str) -> Result<Option<String>>;
    /// Stores `value` for `service` / `account`, replacing any existing value.
    fn set(&self, service: &str, account: &str, value: &str) -> Result<()>;
    /// Deletes the value stored for `service` / `account`. Returns false if there was none.
    fn delete(&self, service: &str, account: &str) -> Result<bool>;
}

/// Keychain stores secrets in the platform credential store: the login keychain on macOS
/// and the Secret Service on Linux.
#[derive(Default)]
pub struct Keychain;

impl Keychain {
    /// Creates a new keychain-backed store. The platform store is opened on first use.
    pub fn new() -> Self {
        Self
    }

    /// Returns the keyring entry for `service` / `account`.
    fn entry(service: &str, account: &str) -> Result<keyring_core::Entry> {
        static STORE: OnceLock<Result<(), String>> = OnceLock::new();
        STORE
            .get_or_init(|| open_store().map_err(|e| e.to_string()))
            .as_ref()
            .map_err(|e| anyhow!("failed to open the credential store: {e}"))?;

        Ok(keyring_core::Entry::new(service, account)?)
    }
}

/// Opens the platform credential store and makes it the keyring default.
fn open_store() -> keyring_core::Result<()> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new()?;
    #[cfg(target_os = "linux")]
    let store = zbus_secret_service_keyring_store::Store::new()?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        keyring_core::set_default_store(store);
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    Err(keyring_core::Error::NotSupportedByStore(
        "only macOS and Linux are supported".to_string(),
    ))
}

impl SecretStore for Keychain {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>> {
        match Self::entry(service, account)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(e).context(format!(
                "failed to read {service}/{account} from the keychain"
            )),
        }
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<()> {
        Self::entry(service, account)?
            .set_password(value)
            .with_context(|| format!("failed to write {service}/{account} to the keychain"))
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool> {
        match Self::entry(service, account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring_core::Error::NoEntry) => Ok(false),
            Err(e) => Err(e).context(format!(
                "failed to delete {service}/{account} from the keychain"
            )),
        }
    }
}

/// Cache keeps fetched secrets in a [`SecretStore`] and remembers which profiles were loaded.
///
/// Secrets are stored under the service `keysafe.<profile>` with the secret name as the
/// account. Loaded profiles are recorded in `<dir>/<profile>.metadata`, one `kind:name` line
/// per secret, so they can be exported on shell startup without contacting 1Password.
///
/// Secrets and metadata stored before keysafe had its own name (and by zsh-op) are still
/// found: secrets under `op-secrets-<profile>` move to the new service when they are first
/// read, and metadata is read from the legacy directory until the profile is loaded again.
pub struct Cache {
    /// Store holding the secret values.
    pub store: Box<dyn SecretStore>,
    /// Directory holding the profile metadata files.
    pub dir: PathBuf,
    /// Directory holding metadata files written before keysafe had its own name.
    pub legacy_dir: Option<PathBuf>,
}

impl Cache {
    /// Creates a cache backed by `store` that keeps its metadata in `dir`.
    pub fn new(store: Box<dyn SecretStore>, dir: &Path) -> Self {
        Self {
            store,
            dir: dir.to_path_buf(),
            legacy_dir: None,
        }
    }

    /// Also reads metadata files from `dir`, written before keysafe had its own name.
    pub fn with_legacy_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.legacy_dir = dir;
        self
    }

    /// Returns the store service name used for the secrets of `profile`.
    pub fn service(profile: &str) -> String {
        format!("keysafe.{profile}")
    }

    /// Returns the store service name used for the secrets of `profile` before keysafe had
    /// its own name.
    pub fn legacy_service(profile: &str) -> String {
        format!("op-secrets-{profile}")
    }

    /// Returns the cached value of secret `name` in `profile`.
    pub fn get(&self, profile: &str, name: &str) -> Result<Option<String>> {
        let service = Self::service(profile);
        if let Some(value) = self.store.get(&service, name)? {
            return Ok(Some(value));
        }

        // Move a secret cached under the legacy service, so no copy stays behind
        let legacy = Self::legacy_service(profile);
        let Some(value) = self.store.get(&legacy, name)? else {
            return Ok(None);
        };
        match self.store.set(&service, name, &value) {
            Ok(()) => {
                debug(format!(
                    "moved '{name}' from {legacy} to {service} in the keychain"
                ));
                if let Err(err) = self.store.delete(&legacy, name) {
                    warn(format!("{err:#}"));
                }
            }
            Err(err) => warn(format!("{err:#}")),
        }
        Ok(Some(value))
    }

    /// Caches `value` as secret `name` in `profile`.
    pub fn set(&self, profile: &str, name: &str, value: &str) -> Result<()> {
        self.store.set(&Self::service(profile), name, value)
    }

    /// Returns the path of the metadata file of `profile`.
    pub fn metadata_path(&self, profile: &str) -> PathBuf {
        self.dir.join(format!("{profile}.metadata"))
    }

    /// Returns the metadata files of `profile`: the current one, then the legacy one.
    fn metadata_paths(&self, profile: &str) -> impl Iterator<Item = PathBuf> + '_ {
        let file = format!("{profile}.metadata");
        std::iter::once(self.dir.join(&file))
            .chain(self.legacy_dir.iter().map(move |dir| dir.join(&file)))
    }

    /// Returns the secret names recorded for `profile`, or `None` if it was never loaded.
    pub fn loaded(&self, profile: &str) -> Result<Option<Vec<String>>> {
        for path in self.metadata_paths(profile) {
            let data = match std::fs::read_to_string(&path) {
                Ok(data) => data,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(e).context(format!("failed to read {}", path.display())),
            };

            let names = data
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                // Parse: kind:name (e.g. "env:GITHUB_TOKEN" or "ssh:github-work")
                .filter_map(|line| line.split_once(':').map(|(_, name)| name.to_string()))
                .collect();
            return Ok(Some(names));
        }
        Ok(None)
    }

    /// Records every secret of `account` as loaded.
    pub fn save(&self, account: &Profile) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("failed to create {}", self.dir.display()))?;

        let mut data = format!(
            "# keysafe metadata for profile: {}\n# Format: kind:name\n\n",
            account.name
        );
        for secret in &account.secrets {
            data.push_str(&format!("{}:{}\n", secret.kind, secret.name));
        }

        let path = self.metadata_path(&account.name);
        std::fs::write(&path, data).with_context(|| format!("failed to write {}", path.display()))
    }

    /// Deletes every cached secret of `account`, including secrets that are only recorded in
    /// its metadata or stored under the legacy service, and forgets that it was loaded.
    /// Returns the number of deleted secrets.
    pub fn clear(&self, account: &Profile) -> Result<usize> {
        let mut names: Vec<String> = account.secrets.iter().map(|s| s.name.clone()).collect();
        for name in self.loaded(&account.name)?.unwrap_or_default() {
            if !names.contains(&name) {
                names.push(name);
            }
        }

        let services = [
            Self::service(&account.name),
            Self::legacy_service(&account.name),
        ];
        let mut count = 0;
        for name in &names {
            let mut deleted = false;
            for service in &services {
                deleted |= self.store.delete(service, name)?;
            }
            count += usize::from(deleted);
        }

        self.forget(&account.name)?;
        Ok(count)
    }

    /// Forgets that `profile` was loaded, so it is no longer exported in new shells. Its
    /// cached secrets stay.
    pub fn forget(&self, profile: &str) -> Result<()> {
        for path in self.metadata_paths(profile) {
            match std::fs::remove_file(&path) {
                Err(e) if e.kind() != ErrorKind::NotFound => {
                    return Err(e).context(format!("failed to remove {}", path.display()));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// An SSH key keysafe added to an ssh-agent, recorded so `status` can say when it expires.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeyRecord {
    /// Profile the key belongs to.
    pub profile: String,
    /// Name of the key in the profile.
    pub name: String,
    /// SHA256 fingerprint, as printed by `ssh-add -l`.
    pub fingerprint: String,
    /// OpenSSH public key, used to remove the key from the agent.
    #[serde(default)]
    pub public_key: String,
    /// When the agent drops the key, in seconds since the Unix epoch.
    pub expires: u64,
}

impl Cache {
    /// Returns the path of the file recording the SSH keys keysafe added to an agent.
    fn keys_path(&self) -> PathBuf {
        self.dir.join("agent-keys.json")
    }

    /// Returns the recorded SSH keys keysafe added to an agent.
    pub fn keys(&self) -> Result<Vec<KeyRecord>> {
        let path = self.keys_path();
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data)
                .with_context(|| format!("failed to parse {}", path.display())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e).context(format!("failed to read {}", path.display())),
        }
    }

    /// Records `added` SSH keys, replacing earlier records of the same keys and dropping
    /// records that expired before `now`.
    pub fn record_keys(&self, added: &[KeyRecord], now: u64) -> Result<()> {
        let mut keys: Vec<KeyRecord> = self
            .keys()?
            .into_iter()
            .filter(|k| k.expires > now && !added.iter().any(|a| a.fingerprint == k.fingerprint))
            .collect();
        keys.extend_from_slice(added);
        self.write_keys(&keys)
    }

    /// Drops the records of the SSH keys with the given `fingerprints`.
    pub fn drop_keys(&self, fingerprints: &[String]) -> Result<()> {
        let keys: Vec<KeyRecord> = self
            .keys()?
            .into_iter()
            .filter(|k| !fingerprints.contains(&k.fingerprint))
            .collect();
        self.write_keys(&keys)
    }

    /// Replaces the recorded SSH keys with `keys`.
    fn write_keys(&self, keys: &[KeyRecord]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("failed to create {}", self.dir.display()))?;
        let path = self.keys_path();
        std::fs::write(&path, serde_json::to_string_pretty(keys)?)
            .with_context(|| format!("failed to write {}", path.display()))
    }
}

/// MemoryStore is an in-memory [`SecretStore`] used by tests.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct MemoryStore(
    pub std::rc::Rc<std::cell::RefCell<std::collections::BTreeMap<(String, String), String>>>,
);

#[cfg(test)]
impl MemoryStore {
    /// Creates a store holding the given `(service, account, value)` items.
    pub fn with(items: &[(&str, &str, &str)]) -> Self {
        let store = Self::default();
        for (service, account, value) in items {
            store.set(service, account, value).unwrap();
        }
        store
    }

    /// Returns the value stored for `service` / `account`.
    pub fn value(&self, service: &str, account: &str) -> Option<String> {
        self.get(service, account).unwrap()
    }
}

#[cfg(test)]
impl SecretStore for MemoryStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>> {
        let key = (service.to_string(), account.to_string());
        Ok(self.0.borrow().get(&key).cloned())
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<()> {
        let key = (service.to_string(), account.to_string());
        self.0.borrow_mut().insert(key, value.to_string());
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool> {
        let key = (service.to_string(), account.to_string());
        Ok(self.0.borrow_mut().remove(&key).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Config;
    use indoc::indoc;

    fn account() -> Profile {
        let config = Config::parse(indoc! {"
            version: 1
            profiles:
              - name: personal
                provider:
                  type: 1password
                  account: my.1password.com
                secrets:
                  - kind: env
                    name: GITHUB_TOKEN
                    path: op://Personal/GitHub/token
                  - kind: ssh
                    name: my-key
                    path: op://Private/SSH/private key
        "})
        .unwrap();
        config.profiles[0].clone()
    }

    #[test]
    #[ignore = "writes to the real platform keychain"]
    fn keychain_round_trips_values() {
        let keychain = Keychain::new();
        let (service, account) = ("keysafe-test", "ROUND_TRIP");
        let value = "multi\nline \\ \"quoted\" ✓";

        keychain.set(service, account, value).unwrap();
        let read = keychain.get(service, account);
        let deleted = keychain.delete(service, account);

        assert_eq!(read.unwrap().as_deref(), Some(value));
        assert!(deleted.unwrap());
        assert_eq!(keychain.get(service, account).unwrap(), None);
        assert!(!keychain.delete(service, account).unwrap());
    }

    #[test]
    fn record_keys_replaces_and_expires_records() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(Box::new(MemoryStore::default()), dir.path());
        let record = |name: &str, fingerprint: &str, expires| KeyRecord {
            profile: "work".into(),
            name: name.into(),
            fingerprint: fingerprint.into(),
            public_key: String::new(),
            expires,
        };
        assert_eq!(cache.keys().unwrap(), vec![]);

        cache
            .record_keys(
                &[
                    record("old", "SHA256:a", 100),
                    record("kept", "SHA256:b", 500),
                ],
                0,
            )
            .unwrap();
        cache
            .record_keys(&[record("new", "SHA256:b", 900)], 200)
            .unwrap();

        // "old" expired, "kept" was replaced by the new record of the same key
        assert_eq!(cache.keys().unwrap(), vec![record("new", "SHA256:b", 900)]);
    }

    #[test]
    fn forget_and_drop_keys_keep_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemoryStore::with(&[("keysafe.personal", "GITHUB_TOKEN", "a")]);
        let cache = Cache::new(Box::new(store.clone()), dir.path());
        cache.save(&account()).unwrap();
        let record = KeyRecord {
            profile: "personal".into(),
            name: "my-key".into(),
            fingerprint: "SHA256:a".into(),
            public_key: "ssh-ed25519 AAAA".into(),
            expires: 900,
        };
        cache.record_keys(&[record], 0).unwrap();

        cache.forget("personal").unwrap();
        cache.drop_keys(&["SHA256:a".into()]).unwrap();

        assert_eq!(cache.loaded("personal").unwrap(), None);
        assert_eq!(cache.keys().unwrap(), vec![]);
        assert_eq!(
            store.value("keysafe.personal", "GITHUB_TOKEN").as_deref(),
            Some("a")
        );
    }

    #[test]
    fn service_uses_profile_prefix() {
        assert_eq!(Cache::service("work"), "keysafe.work");
        assert_eq!(Cache::legacy_service("work"), "op-secrets-work");
    }

    #[test]
    fn get_moves_secrets_from_the_legacy_service() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemoryStore::with(&[("op-secrets-personal", "GITHUB_TOKEN", "brown-fox")]);
        let cache = Cache::new(Box::new(store.clone()), dir.path());

        assert_eq!(
            cache.get("personal", "GITHUB_TOKEN").unwrap().as_deref(),
            Some("brown-fox")
        );

        assert_eq!(
            store.value("keysafe.personal", "GITHUB_TOKEN").as_deref(),
            Some("brown-fox")
        );
        assert_eq!(store.value("op-secrets-personal", "GITHUB_TOKEN"), None);
    }

    #[test]
    fn loaded_falls_back_to_the_legacy_dir() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("op");
        std::fs::create_dir(&legacy).unwrap();
        std::fs::write(legacy.join("personal.metadata"), "env:OLD\n").unwrap();
        let cache = Cache::new(Box::new(MemoryStore::default()), &dir.path().join("new"))
            .with_legacy_dir(Some(legacy));

        assert_eq!(cache.loaded("personal").unwrap(), Some(vec!["OLD".into()]));

        // Once the profile is loaded again, the current metadata wins
        cache.save(&account()).unwrap();
        assert_eq!(
            cache.loaded("personal").unwrap(),
            Some(vec!["GITHUB_TOKEN".to_string(), "my-key".to_string()])
        );
    }

    #[test]
    fn get_and_set_use_profile_service() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemoryStore::default();
        let cache = Cache::new(Box::new(store.clone()), dir.path());

        cache.set("personal", "GITHUB_TOKEN", "brown-fox").unwrap();

        assert_eq!(
            store.value("keysafe.personal", "GITHUB_TOKEN").as_deref(),
            Some("brown-fox")
        );
        assert_eq!(
            cache.get("personal", "GITHUB_TOKEN").unwrap().as_deref(),
            Some("brown-fox")
        );
        assert_eq!(cache.get("work", "GITHUB_TOKEN").unwrap(), None);
    }

    #[test]
    fn loaded_returns_none_for_unloaded_profile() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(Box::new(MemoryStore::default()), dir.path());
        assert_eq!(cache.loaded("personal").unwrap(), None);
    }

    #[test]
    fn save_writes_metadata_that_loaded_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(Box::new(MemoryStore::default()), &dir.path().join("op"));

        cache.save(&account()).unwrap();

        let data = std::fs::read_to_string(cache.metadata_path("personal")).unwrap();
        assert!(data.ends_with("\nenv:GITHUB_TOKEN\nssh:my-key\n"));
        assert_eq!(
            cache.loaded("personal").unwrap(),
            Some(vec!["GITHUB_TOKEN".to_string(), "my-key".to_string()])
        );
    }

    #[test]
    fn loaded_reads_metadata_written_by_the_zsh_plugin() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::new(Box::new(MemoryStore::default()), dir.path());
        std::fs::write(
            cache.metadata_path("personal"),
            "# zsh-op metadata for profile: personal\n# Format: type:name\n# Generated: Mon\n\nenv:GITHUB_TOKEN\nfile:GCP\n",
        )
        .unwrap();

        assert_eq!(
            cache.loaded("personal").unwrap(),
            Some(vec!["GITHUB_TOKEN".to_string(), "GCP".to_string()])
        );
    }

    #[test]
    fn clear_deletes_configured_recorded_and_legacy_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemoryStore::with(&[
            ("keysafe.personal", "GITHUB_TOKEN", "a"),
            ("op-secrets-personal", "GITHUB_TOKEN", "a"),
            ("keysafe.personal", "REMOVED", "b"),
            ("op-secrets-personal", "my-key", "c"),
            ("keysafe.work", "GITHUB_TOKEN", "d"),
        ]);
        let legacy = dir.path().join("op");
        std::fs::create_dir(&legacy).unwrap();
        std::fs::write(legacy.join("personal.metadata"), "env:REMOVED\n").unwrap();
        let cache = Cache::new(Box::new(store.clone()), &dir.path().join("new"))
            .with_legacy_dir(Some(legacy.clone()));

        assert_eq!(cache.clear(&account()).unwrap(), 3);

        for service in ["keysafe.personal", "op-secrets-personal"] {
            for name in ["GITHUB_TOKEN", "REMOVED", "my-key"] {
                assert_eq!(store.value(service, name), None);
            }
        }
        assert_eq!(
            store.value("keysafe.work", "GITHUB_TOKEN").as_deref(),
            Some("d")
        );
        assert_eq!(cache.loaded("personal").unwrap(), None);
        assert!(!legacy.join("personal.metadata").exists());
    }
}

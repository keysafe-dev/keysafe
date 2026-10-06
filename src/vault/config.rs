use anyhow::{anyhow, bail, Context, Result};
use std::{fmt::Display, path::Path};

/// Raw representation of the configuration file, before validation.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    /// Version of the configuration format.
    version: Option<serde_yaml_ng::Value>,
    /// Profiles and the secrets they load.
    #[serde(default)]
    profiles: Vec<ProfileSpec>,
    /// Profiles in the zsh-op format, which named them accounts.
    accounts: Option<serde_yaml_ng::Value>,
}

/// Raw representation of a configured profile, before validation.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileSpec {
    name: Option<String>,
    /// Whether this profile is used when none is given.
    #[serde(default)]
    default: bool,
    provider: Option<ProviderSpec>,
    /// The 1Password account, which used to sit on the profile itself.
    account: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    secrets: Vec<SecretSpec>,
}

/// Raw representation of a configured provider, selected by its `type`.
#[derive(serde::Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum ProviderSpec {
    #[serde(rename = "1password", alias = "onepassword")]
    OnePassword { account: Option<String> },
}

impl From<ProviderSpec> for Provider {
    fn from(spec: ProviderSpec) -> Self {
        match spec {
            ProviderSpec::OnePassword { account } => Self::OnePassword {
                account: account.filter(|s| !s.is_empty()),
            },
        }
    }
}

/// Raw representation of a configured secret, before validation.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretSpec {
    kind: Option<String>,
    name: Option<String>,
    path: Option<String>,
}

/// Validated configuration: the profiles and the secrets they load.
#[derive(Debug, Clone)]
pub struct Config {
    /// Configured profiles.
    pub profiles: Vec<Profile>,
}

impl Config {
    /// Reads, parses and validates the configuration file at `path`.
    pub fn read_from_file(path: &Path) -> Result<Config> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        Self::parse(&data).with_context(|| format!("invalid config file {}", path.display()))
    }

    /// Parses and validates configuration content.
    pub fn parse(data: &str) -> Result<Config> {
        let spec: Spec = serde_yaml_ng::from_str(data)?;
        Self::try_from(spec)
    }

    /// Returns the default profile: the one marked `default: true`, or else the first one.
    pub fn default_profile(&self) -> &Profile {
        self.profiles
            .iter()
            .find(|p| p.default)
            .unwrap_or(&self.profiles[0])
    }

    /// Returns the profile with the given name, or the default profile if none is given.
    pub fn resolve(&self, name: Option<&str>) -> Result<&Profile> {
        match name {
            Some(name) => self.profile(name),
            None => Ok(self.default_profile()),
        }
    }

    /// Returns the profile with the given name.
    pub fn profile(&self, name: &str) -> Result<&Profile> {
        self.profiles
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| {
                let names: Vec<&str> = self.profiles.iter().map(|a| a.name.as_str()).collect();
                anyhow!(
                    "profile '{}' not found in config (available profiles: {})",
                    name,
                    names.join(", ")
                )
            })
    }
}

impl TryFrom<Spec> for Config {
    type Error = anyhow::Error;

    fn try_from(spec: Spec) -> Result<Self> {
        let version = match spec.version {
            Some(serde_yaml_ng::Value::Number(n)) => n.to_string(),
            Some(serde_yaml_ng::Value::String(s)) => s,
            Some(_) | None => bail!("config missing 'version' field"),
        };
        if version != "1" {
            bail!("unsupported config version: {version} (supported versions: 1)");
        }
        if spec.accounts.is_some() {
            bail!("config uses 'accounts', the zsh-op format: rename it to 'profiles'");
        }
        if spec.profiles.is_empty() {
            bail!("config has no profiles defined");
        }

        let mut profiles = Vec::new();
        for (i, profile) in spec.profiles.into_iter().enumerate() {
            let name = profile
                .name
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("profile at index {i} missing 'name' field"))?;
            // Profile names are used in file paths and keychain service names.
            if name.starts_with('.')
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            {
                bail!("profile name '{name}' may only contain letters, digits, '.', '_' and '-'");
            }
            if profiles.iter().any(|a: &Profile| a.name == name) {
                bail!("profile '{name}' is defined more than once");
            }
            if profile.account.is_some() {
                bail!("profile '{name}' has 'account': move it into its provider (provider: {{ type: 1password, account: ... }})");
            }
            let provider: Provider = profile
                .provider
                .ok_or_else(|| anyhow!("profile '{name}' missing 'provider' field"))?
                .into();

            let mut secrets = Vec::new();
            for (j, secret) in profile.secrets.into_iter().enumerate() {
                let kind = secret.kind.filter(|s| !s.is_empty()).ok_or_else(|| {
                    anyhow!("secret at profile '{name}' index {j} missing 'kind' field")
                })?;
                let secret_name = secret.name.filter(|s| !s.is_empty()).ok_or_else(|| {
                    anyhow!("secret at profile '{name}' index {j} missing 'name' field")
                })?;
                let kind = kind.parse::<SecretKind>().map_err(|_| {
                    anyhow!(
                        "secret '{secret_name}' has invalid kind: {kind} (valid kinds: env, ssh, file)"
                    )
                })?;
                // Environment and file secrets become shell variables, so their names end up in
                // `export NAME=...` statements that are evaluated by the shell.
                if kind != SecretKind::Ssh && !is_variable_name(&secret_name) {
                    bail!(
                        "{kind} secret '{secret_name}' must use a valid environment variable name"
                    );
                }
                let path = secret.path.filter(|s| !s.is_empty()).ok_or_else(|| {
                    anyhow!("secret '{secret_name}' in profile '{name}' missing 'path' field")
                })?;
                let scheme = provider.scheme();
                if !path.starts_with(scheme) {
                    bail!("secret '{secret_name}' has invalid path: {path} (path must start with '{scheme}' for provider {provider})");
                }
                if secrets.iter().any(|s: &Secret| s.name == secret_name) {
                    bail!("secret '{secret_name}' is defined more than once in profile '{name}'");
                }

                secrets.push(Secret {
                    kind,
                    name: secret_name,
                    path,
                });
            }

            profiles.push(Profile {
                name,
                default: profile.default,
                provider,
                secrets,
            });
        }

        let defaults: Vec<&str> = profiles
            .iter()
            .filter(|p| p.default)
            .map(|p| p.name.as_str())
            .collect();
        if defaults.len() > 1 {
            bail!(
                "more than one profile is marked as default: {}",
                defaults.join(", ")
            );
        }

        Ok(Config { profiles })
    }
}

/// Returns true if `name` is a valid shell environment variable name.
fn is_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A profile: a provider and the secrets loaded from it.
#[derive(Debug, Clone)]
pub struct Profile {
    /// Profile name.
    pub name: String,
    /// Whether this profile is used when none is given.
    pub default: bool,
    /// Password manager the secrets are read from.
    pub provider: Provider,
    /// Secrets loaded by this profile.
    pub secrets: Vec<Secret>,
}

/// Provider is the password manager a profile reads its secrets from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provider {
    /// 1Password, through its CLI (`op`).
    OnePassword {
        /// Account to read from, as accepted by `op --account`: a sign-in address, an email
        /// address or an account ID. The CLI's default account is used if not set.
        account: Option<String>,
    },
}

impl Provider {
    /// Returns the prefix of the secret references this provider reads.
    pub fn scheme(&self) -> &'static str {
        match self {
            Self::OnePassword { .. } => "op://",
        }
    }
}

impl Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OnePassword { .. } => write!(f, "1password"),
        }
    }
}

impl Profile {
    /// Returns the secret with the given name.
    pub fn secret(&self, name: &str) -> Result<&Secret> {
        self.secrets.iter().find(|s| s.name == name).ok_or_else(|| {
            let names: Vec<&str> = self.secrets.iter().map(|s| s.name.as_str()).collect();
            anyhow!(
                "secret '{}' not found in profile '{}' (available secrets: {})",
                name,
                self.name,
                names.join(", ")
            )
        })
    }
}

/// Kind of a configured secret, which decides how it is loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// Exported as an environment variable.
    Env,
    /// Added to ssh-agent.
    Ssh,
    /// Written to a private file whose path is exported as an environment variable.
    File,
}

impl std::str::FromStr for SecretKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "env" => Ok(Self::Env),
            "ssh" => Ok(Self::Ssh),
            "file" => Ok(Self::File),
            _ => Err(format!("unknown secret kind: {}", s)),
        }
    }
}

impl Display for SecretKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Env => write!(f, "env"),
            Self::Ssh => write!(f, "ssh"),
            Self::File => write!(f, "file"),
        }
    }
}

/// A secret: a name and the 1Password reference it is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// How the secret is loaded.
    pub kind: SecretKind,
    /// Variable name for env and file secrets, a label for SSH keys.
    pub name: String,
    /// 1Password secret reference (op://vault/item/field).
    pub path: String,
}

impl Secret {
    /// Returns true for the secrets that become environment variables (env and file).
    pub fn is_variable(&self) -> bool {
        self.kind != SecretKind::Ssh
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    const VALID: &str = indoc! {"
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
                path: op://Private/SSH/private key?ssh-format=openssh
              - kind: file
                name: GOOGLE_APPLICATION_CREDENTIALS
                path: op://Personal/GCP/service-account
          - name: work
            provider:
              type: 1password
              account: team.1password.com
    "};

    /// Builds a single-account config around the given secrets YAML block.
    fn with_secrets(secrets: &str) -> String {
        format!("version: 1\nprofiles:\n  - name: p\n    provider:\n      type: 1password\n      account: a.1password.com\n    secrets:\n{secrets}")
    }

    fn parse_err(data: &str) -> String {
        Config::parse(data).unwrap_err().to_string()
    }

    #[test]
    fn parse_accepts_valid_config() {
        let config = Config::parse(VALID).unwrap();
        assert_eq!(config.profiles.len(), 2);

        let personal = config.profile("personal").unwrap();
        assert_eq!(
            personal.provider,
            Provider::OnePassword {
                account: Some("my.1password.com".into())
            }
        );
        assert_eq!(
            personal.secrets.iter().map(|s| s.kind).collect::<Vec<_>>(),
            vec![SecretKind::Env, SecretKind::Ssh, SecretKind::File]
        );
        assert!(config.profile("work").unwrap().secrets.is_empty());
    }

    #[test]
    fn parse_accepts_quoted_version() {
        let data = VALID.replace("version: 1", "version: \"1\"");
        assert!(Config::parse(&data).is_ok());
    }

    #[test]
    fn parse_fails_when_version_is_missing() {
        let data = VALID.replace("version: 1\n", "");
        assert_eq!(parse_err(&data), "config missing 'version' field");
    }

    #[test]
    fn parse_fails_when_version_is_not_1() {
        let data = VALID.replace("version: 1", "version: 2");
        assert_eq!(
            parse_err(&data),
            "unsupported config version: 2 (supported versions: 1)"
        );
    }

    #[test]
    fn parse_fails_on_the_zsh_op_format() {
        let data = VALID.replace("profiles:", "accounts:");
        assert_eq!(
            parse_err(&data),
            "config uses 'accounts', the zsh-op format: rename it to 'profiles'"
        );
    }

    #[test]
    fn parse_fails_when_profiles_are_empty() {
        assert_eq!(
            parse_err("version: 1\nprofiles: []\n"),
            "config has no profiles defined"
        );
    }

    #[test]
    fn parse_fails_when_account_name_is_missing() {
        assert_eq!(
            parse_err("version: 1\nprofiles:\n  - account: a.1password.com\n"),
            "profile at index 0 missing 'name' field"
        );
    }

    #[test]
    fn parse_fails_when_account_name_is_not_path_safe() {
        assert_eq!(
            parse_err("version: 1\nprofiles:\n  - name: ../p\n    provider:\n      type: 1password\n      account: a.1password.com\n"),
            "profile name '../p' may only contain letters, digits, '.', '_' and '-'"
        );
    }

    #[test]
    fn parse_fails_when_account_name_is_duplicated() {
        let account =
            "  - name: p\n    provider:\n      type: 1password\n      account: a.1password.com\n";
        assert_eq!(
            parse_err(&format!("version: 1\nprofiles:\n{}", account.repeat(2))),
            "profile 'p' is defined more than once"
        );
    }

    #[test]
    fn parse_accepts_1password_without_account() {
        let config = Config::parse(
            "version: 1\nprofiles:\n  - name: p\n    provider:\n      type: 1password\n",
        )
        .unwrap();
        assert_eq!(
            config.profiles[0].provider,
            Provider::OnePassword { account: None }
        );
    }

    #[test]
    fn parse_accepts_onepassword_as_provider_alias() {
        let data = VALID.replacen("type: 1password", "type: onepassword", 1);
        let config = Config::parse(&data).unwrap();
        assert_eq!(config.profiles[0].provider.to_string(), "1password");
    }

    #[test]
    fn parse_fails_on_unknown_provider() {
        let data = VALID.replacen("type: 1password", "type: keepass", 1);
        let err = parse_err(&data);
        assert!(err.contains("unknown variant `keepass`"), "{err}");
    }

    #[test]
    fn parse_fails_on_account_outside_the_provider() {
        let data = "version: 1\nprofiles:\n  - name: p\n    account: a.1password.com\n";
        assert_eq!(
            parse_err(data),
            "profile 'p' has 'account': move it into its provider (provider: { type: 1password, account: ... })"
        );
    }

    #[test]
    fn parse_fails_on_unknown_fields() {
        let data = VALID.replacen("    secrets:", "    secret:", 1);
        let err = parse_err(&data);
        assert!(err.contains("unknown field `secret`"), "{err}");
    }

    #[test]
    fn default_profile_is_the_first_one_unless_marked() {
        let config = Config::parse(VALID).unwrap();
        assert_eq!(config.default_profile().name, "personal");
        assert_eq!(config.resolve(None).unwrap().name, "personal");
        assert_eq!(config.resolve(Some("work")).unwrap().name, "work");

        let data = VALID.replace("  - name: work\n", "  - name: work\n    default: true\n");
        let config = Config::parse(&data).unwrap();
        assert_eq!(config.default_profile().name, "work");
    }

    #[test]
    fn parse_fails_when_several_profiles_are_default() {
        let data = VALID
            .replace(
                "  - name: personal\n",
                "  - name: personal\n    default: true\n",
            )
            .replace("  - name: work\n", "  - name: work\n    default: true\n");
        assert_eq!(
            parse_err(&data),
            "more than one profile is marked as default: personal, work"
        );
    }

    #[test]
    fn parse_fails_when_provider_is_missing() {
        assert_eq!(
            parse_err("version: 1\nprofiles:\n  - name: p\n"),
            "profile 'p' missing 'provider' field"
        );
    }

    #[test]
    fn parse_fails_when_secret_kind_is_missing() {
        let data = with_secrets("      - name: A\n        path: op://v/i/f\n");
        assert_eq!(
            parse_err(&data),
            "secret at profile 'p' index 0 missing 'kind' field"
        );
    }

    #[test]
    fn parse_fails_when_secret_kind_is_invalid() {
        let data = with_secrets("      - kind: token\n        name: A\n        path: op://v/i/f\n");
        assert_eq!(
            parse_err(&data),
            "secret 'A' has invalid kind: token (valid kinds: env, ssh, file)"
        );
    }

    #[test]
    fn parse_fails_when_secret_name_is_missing() {
        let data = with_secrets("      - kind: env\n        path: op://v/i/f\n");
        assert_eq!(
            parse_err(&data),
            "secret at profile 'p' index 0 missing 'name' field"
        );
    }

    #[test]
    fn parse_fails_when_secret_path_is_missing() {
        let data = with_secrets("      - kind: env\n        name: A\n");
        assert_eq!(
            parse_err(&data),
            "secret 'A' in profile 'p' missing 'path' field"
        );
    }

    #[test]
    fn parse_fails_when_secret_path_is_not_an_op_reference() {
        let data = with_secrets("      - kind: env\n        name: A\n        path: vault/item\n");
        assert_eq!(
            parse_err(&data),
            "secret 'A' has invalid path: vault/item (path must start with 'op://' for provider 1password)"
        );
    }

    #[test]
    fn parse_fails_when_file_secret_name_is_not_a_variable_name() {
        let data =
            with_secrets("      - kind: file\n        name: gcp-creds\n        path: op://v/i/f\n");
        assert_eq!(
            parse_err(&data),
            "file secret 'gcp-creds' must use a valid environment variable name"
        );
    }

    #[test]
    fn parse_fails_when_env_secret_name_is_not_a_variable_name() {
        let data = with_secrets(
            "      - kind: env\n        name: \"A;rm -rf ~\"\n        path: op://v/i/f\n",
        );
        assert_eq!(
            parse_err(&data),
            "env secret 'A;rm -rf ~' must use a valid environment variable name"
        );
    }

    #[test]
    fn parse_accepts_any_ssh_key_name() {
        let data = with_secrets(
            "      - kind: ssh\n        name: github-work\n        path: op://v/i/f\n",
        );
        assert!(Config::parse(&data).is_ok());
    }

    #[test]
    fn parse_fails_when_secret_name_is_duplicated() {
        let secret = "      - kind: env\n        name: A\n        path: op://v/i/f\n";
        let data = with_secrets(&secret.repeat(2));
        assert_eq!(
            parse_err(&data),
            "secret 'A' is defined more than once in profile 'p'"
        );
    }

    #[test]
    fn parse_fails_on_malformed_yaml() {
        assert!(Config::parse("version: [1\n").is_err());
    }

    #[test]
    fn read_from_file_fails_when_file_is_missing() {
        let err = Config::read_from_file(Path::new("/nonexistent/config.yml")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "failed to read config file /nonexistent/config.yml"
        );
    }

    #[test]
    fn profile_fails_with_available_profiles() {
        let config = Config::parse(VALID).unwrap();
        assert_eq!(
            config.profile("staging").unwrap_err().to_string(),
            "profile 'staging' not found in config (available profiles: personal, work)"
        );
    }

    #[test]
    fn secret_fails_with_available_secrets() {
        let config = Config::parse(VALID).unwrap();
        let account = config.profile("personal").unwrap();
        assert_eq!(account.secret("my-key").unwrap().kind, SecretKind::Ssh);
        assert_eq!(
            account.secret("NOPE").unwrap_err().to_string(),
            "secret 'NOPE' not found in profile 'personal' (available secrets: GITHUB_TOKEN, my-key, GOOGLE_APPLICATION_CREDENTIALS)"
        );
    }
}

use crate::app::args::*;
use crate::log::{count, info, styled, success, warn};
use crate::vault::*;
use anyhow::{bail, Context, Result};
use clap::{builder::PossibleValuesParser, CommandFactory};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Display;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

/// Fails when any secret failed to load. The warnings were already printed.
fn finish(failed: usize) -> Result<()> {
    if failed > 0 {
        bail!("failed to load {failed} secret(s)");
    }
    Ok(())
}

/// Quotes `value` for POSIX shells, so it survives `eval` unchanged.
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Writes `variables` to `writer` in the given format.
fn write_variables(
    writer: &mut dyn Write,
    format: ExportFormat,
    variables: &[Variable],
) -> Result<()> {
    match format {
        ExportFormat::Zsh | ExportFormat::Bash => {
            for variable in variables {
                writeln!(writer, "export {}={}", variable.key, quote(&variable.value))?;
            }
        }
        ExportFormat::Json => {
            let environment: BTreeMap<&str, &str> = variables
                .iter()
                .map(|v| (v.key.as_str(), v.value.as_str()))
                .collect();
            writeln!(writer, "{}", serde_json::to_string(&environment)?)?;
        }
    }
    Ok(())
}

/// Hands the temporary directory `runtime` created for file secrets, if any, to whoever removes
/// it: the shell integration, through a statement it evaluates, or the user.
fn write_runtime_dir(
    writer: &mut dyn Write,
    format: ExportFormat,
    runtime: &RuntimeDir,
    eval: bool,
) -> Result<()> {
    let Some(dir) = runtime.created() else {
        return Ok(());
    };

    let path = quote(&dir.to_string_lossy());
    match (eval, format) {
        (true, ExportFormat::Zsh) => writeln!(writer, "typeset -g _KEYSAFE_RUNTIME_DIR={path}")?,
        (true, ExportFormat::Bash) => writeln!(writer, "_KEYSAFE_RUNTIME_DIR={path}")?,
        _ => warn(format!(
            "file secrets are written to {}; remove it when done",
            dir.display()
        )),
    }
    Ok(())
}

/// Resolves the cached env and file secrets of `account` from the keychain only, if the
/// profile was loaded before. Only secrets that are still configured are exported, and their
/// kind always comes from the current config.
fn resolve_cached(
    loader: &Loader,
    runtime: &RuntimeDir,
    account: &Profile,
) -> Result<(Vec<Variable>, usize)> {
    let Some(names) = loader.cache.loaded(&account.name)? else {
        return Ok((Vec::new(), 0));
    };

    let secrets = account
        .secrets
        .iter()
        .filter(|s| s.is_variable())
        .filter(|s| names.contains(&s.name));
    Ok(loader.resolve(runtime, account, secrets, Source::Cache))
}

/// Load secrets of a profile into the current shell.
pub struct LoadCommand {
    /// Writer used to output the shell statements.
    pub writer: Box<dyn Write>,
    /// Loader used to resolve the secrets.
    pub loader: Loader,
    /// Agent the SSH keys are added to.
    pub agent: Box<dyn KeyAgent>,
}

impl LoadCommand {
    /// Execute the LoadCommand with the provided arguments.
    pub fn execute(&mut self, args: &LoadCommandArgs) -> Result<()> {
        let config = Config::read_from_file(&args.parent.config)?;
        let account = config.resolve(args.profile.as_deref())?;
        let secrets: Vec<&Secret> = if args.names.is_empty() {
            account.secrets.iter().collect()
        } else {
            args.names
                .iter()
                .map(|name| account.secret(name))
                .collect::<Result<_>>()?
        };
        let runtime = RuntimeDir::new(args.output.runtime_dir.clone());

        // Export the environment and file secrets, unless the statements would only be shown
        // on a terminal: then the variables can't be set, and secrets must not be printed
        let selected: Vec<&Secret> = secrets
            .iter()
            .copied()
            .filter(|s| s.is_variable())
            .collect();
        let stranded = args.output.statements_stranded();
        let (variables, mut failed) = if stranded {
            (Vec::new(), 0)
        } else {
            self.loader.resolve(
                &runtime,
                account,
                selected.iter().copied(),
                Source::Any(args.refresh),
            )
        };
        let format = args.output.export_format();
        write_runtime_dir(&mut self.writer, format, &runtime, args.output.is_eval())?;
        write_variables(&mut self.writer, format, &variables)?;
        if !variables.is_empty() {
            let (cached, fetched) = self.loader.counts();
            let source = match (cached, fetched) {
                (0, _) => format!("from {}", account.provider),
                (_, 0) => "from the keychain".to_string(),
                _ => format!(
                    "{cached} from the keychain, {fetched} from {}",
                    account.provider
                ),
            };
            success(format!(
                "Loaded {} from {}  ({source})",
                count(variables.len(), "secret"),
                account.name
            ));
        }

        // Add the SSH keys to the agent
        let keys: Vec<&Secret> = secrets
            .iter()
            .copied()
            .filter(|s| s.kind == SecretKind::Ssh)
            .collect();
        failed += self.add_keys(account, &keys, args);

        // SSH keys don't need the shell; variables do
        if stranded && !selected.is_empty() {
            bail!(
                "{} not set: the shell integration isn't active here; {}",
                count(selected.len(), "variable"),
                args.output.integration_hint("load")
            );
        }

        // Record a fully loaded profile, so its cached secrets are exported in new shells
        if args.names.is_empty() {
            self.loader.cache.save(account)?;
        }
        finish(failed)
    }

    /// Adds `keys` to the agent, reporting what happened. Returns the number of failures.
    fn add_keys(&self, account: &Profile, keys: &[&Secret], args: &LoadCommandArgs) -> usize {
        if keys.is_empty() {
            return 0;
        }
        let present = match self.agent.fingerprints() {
            Ok(present) => present,
            Err(err) => {
                warn(format!("failed to load {} SSH key(s): {err:#}", keys.len()));
                return keys.len();
            }
        };

        let lifetime = lifetime_seconds(&args.expiration).ok();
        let now = unix_now();
        let mut records = Vec::new();
        let (mut added, mut kept, mut failed) = (0, 0, 0);
        for key in keys {
            match self.loader.add_key(
                self.agent.as_ref(),
                &present,
                account,
                key,
                &args.expiration,
                args.refresh,
            ) {
                Ok(KeyOutcome::Added(added_key)) => {
                    added += 1;
                    if let (Some(added_key), Some(lifetime)) = (added_key, lifetime) {
                        records.push(KeyRecord {
                            profile: account.name.clone(),
                            name: key.name.clone(),
                            fingerprint: added_key.fingerprint,
                            public_key: added_key.public_key,
                            expires: now + lifetime,
                        });
                    }
                }
                Ok(KeyOutcome::Present) => kept += 1,
                Err(err) => {
                    warn(format!("failed to load SSH key '{}': {err:#}", key.name));
                    failed += 1;
                }
            }
        }

        if added > 0 {
            let expiry = lifetime
                .map(duration)
                .unwrap_or_else(|| args.expiration.clone());
            success(format!(
                "Added {} to ssh-agent  (expire in {expiry})",
                count(added, "SSH key")
            ));
        }
        if kept > 0 {
            info(format!(
                "{} already in ssh-agent (use --refresh to reset the expiration)",
                count(kept, "SSH key")
            ));
        }

        // Remember when the keys expire, for `keysafe status`
        if !records.is_empty() {
            if let Err(err) = self.loader.cache.record_keys(&records, now) {
                warn(format!("{err:#}"));
            }
        }
        failed
    }
}

/// Unload secrets of a profile from the current shell.
pub struct UnloadCommand {
    /// Writer used to output the shell statements.
    pub writer: Box<dyn Write>,
    /// Cache holding the profile records and the SSH keys keysafe added.
    pub cache: Cache,
    /// Agent the SSH keys are removed from.
    pub agent: Box<dyn KeyAgent>,
    /// Environment of the shell keysafe runs in.
    pub environment: HashMap<String, String>,
}

impl UnloadCommand {
    /// Execute the UnloadCommand with the provided arguments.
    pub fn execute(&mut self, args: &UnloadCommandArgs) -> Result<()> {
        let config = Config::read_from_file(&args.parent.config)?;
        let profile = config.resolve(args.profile.as_deref())?;
        let secrets: Vec<&Secret> = if args.names.is_empty() {
            profile.secrets.iter().collect()
        } else {
            args.names
                .iter()
                .map(|name| profile.secret(name))
                .collect::<Result<_>>()?
        };
        if args.output.export_format() == ExportFormat::Json {
            bail!("unload prints shell statements; use --format zsh or --format bash");
        }

        // Unset the variables, deleting the files of file secrets keysafe wrote. Without a way
        // to reach the shell, the variables stay, and so do the files they point to.
        let variables: Vec<&Secret> = secrets
            .iter()
            .copied()
            .filter(|s| s.is_variable())
            .collect();
        let stranded = args.output.statements_stranded();
        if !stranded {
            for secret in &variables {
                if secret.kind == SecretKind::File {
                    self.remove_file(profile, secret);
                }
                writeln!(self.writer, "unset {}", secret.name)?;
            }
        }

        // Remove the SSH keys keysafe added from the agent
        let keys: Vec<&Secret> = secrets
            .iter()
            .copied()
            .filter(|s| s.kind == SecretKind::Ssh)
            .collect();
        let (removed, failed) = self.remove_keys(profile, &keys);

        // SSH keys don't need the shell; variables do
        if stranded && !variables.is_empty() {
            if removed > 0 {
                success(format!(
                    "Removed {} from ssh-agent",
                    count(removed, "SSH key")
                ));
            }
            bail!(
                "{} not unset: the shell integration isn't active here; {}",
                count(variables.len(), "variable"),
                args.output.integration_hint("unload")
            );
        }

        // An unloaded profile is no longer exported in new shells; its cache stays
        if args.names.is_empty() {
            self.cache.forget(&profile.name)?;
        }

        let unloaded = match (variables.len(), removed) {
            (n, 0) => count(n, "secret"),
            (0, k) => count(k, "SSH key"),
            (n, k) => format!("{} and {}", count(n, "secret"), count(k, "SSH key")),
        };
        success(format!("Unloaded {unloaded} from {}", profile.name));
        finish(failed)
    }

    /// Deletes the file of the file secret `secret`, if its variable points to a file that
    /// keysafe wrote (`<runtime dir>/files/<profile>/<name>`).
    fn remove_file(&self, profile: &Profile, secret: &Secret) {
        let Some(value) = self.environment.get(&secret.name) else {
            return;
        };
        let path = Path::new(value);
        let written = Path::new("files").join(&profile.name).join(&secret.name);
        if path.ends_with(&written) {
            if let Err(err) = std::fs::remove_file(path) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn(format!("failed to remove {}: {err}", path.display()));
                }
            }
        }
    }

    /// Removes `keys` from the agent, if keysafe added them and the agent still holds them.
    /// Returns the number of removed keys and of failures.
    fn remove_keys(&self, profile: &Profile, keys: &[&Secret]) -> (usize, usize) {
        if keys.is_empty() {
            return (0, 0);
        }
        // Without a running agent, there is nothing to remove
        let Ok(present) = self.agent.fingerprints() else {
            return (0, 0);
        };
        let records = match self.cache.keys() {
            Ok(records) => records,
            Err(err) => {
                warn(format!("{err:#}"));
                return (0, keys.len());
            }
        };

        let (mut removed, mut failed) = (Vec::new(), 0);
        for key in keys {
            let Some(record) = records.iter().find(|r| {
                r.profile == profile.name && r.name == key.name && present.contains(&r.fingerprint)
            }) else {
                continue;
            };
            if record.public_key.is_empty() {
                warn(format!(
                    "SSH key '{}' was added by an older keysafe; remove it with `ssh-add -d`",
                    key.name
                ));
                continue;
            }
            match self.agent.remove(&record.public_key) {
                Ok(()) => removed.push(record.fingerprint.clone()),
                Err(err) => {
                    warn(format!("failed to remove SSH key '{}': {err:#}", key.name));
                    failed += 1;
                }
            }
        }

        if !removed.is_empty() {
            if let Err(err) = self.cache.drop_keys(&removed) {
                warn(format!("{err:#}"));
            }
        }
        (removed.len(), failed)
    }
}

/// Print the value of a secret.
pub struct ReadCommand {
    /// Writer used to output the value.
    pub writer: Box<dyn Write>,
    /// Loader used to resolve the secret.
    pub loader: Loader,
}

impl ReadCommand {
    /// Execute the ReadCommand with the provided arguments.
    pub fn execute(&mut self, args: &ReadCommandArgs) -> Result<()> {
        let config = Config::read_from_file(&args.parent.config)?;
        let account = config.resolve(args.profile.as_deref())?;
        let secret = account.secret(&args.name)?;
        if secret.kind == SecretKind::Ssh {
            bail!(
                "'{}' is an SSH key, which is not printed; use `keysafe load {}` to add it to ssh-agent",
                secret.name,
                secret.name
            );
        }

        let value = self.loader.load(account, secret, args.refresh)?;
        writeln!(self.writer, "{value}")?;
        Ok(())
    }
}

/// Export the environment and file secrets of a profile as shell statements.
pub struct ExportCommand {
    /// Writer used to output the export statements.
    pub writer: Box<dyn Write>,
    /// Loader used to resolve the secrets.
    pub loader: Loader,
}

impl ExportCommand {
    /// Execute the ExportCommand with the provided arguments.
    pub fn execute(&mut self, args: &ExportCommandArgs) -> Result<()> {
        let config = Config::read_from_file(&args.parent.config)?;
        let accounts = if args.all {
            config.profiles.iter().collect()
        } else {
            vec![config.resolve(args.profile.as_deref())?]
        };
        let runtime = RuntimeDir::new(args.output.runtime_dir.clone());

        let mut variables = Vec::new();
        let mut failed = 0;
        for account in accounts {
            let (mut resolved, count) = if args.cached {
                resolve_cached(&self.loader, &runtime, account)?
            } else {
                let secrets = account.secrets.iter().filter(|s| s.is_variable());
                let resolved =
                    self.loader
                        .resolve(&runtime, account, secrets, Source::Any(args.refresh));
                self.loader.cache.save(account)?;
                resolved
            };
            variables.append(&mut resolved);
            failed += count;
        }

        let format = args.output.export_format();
        write_runtime_dir(&mut self.writer, format, &runtime, args.output.is_eval())?;
        write_variables(&mut self.writer, format, &variables)?;
        finish(failed)
    }
}

/// Generates the completion script for `shell`, offering the profile and secret names of
/// `config` where the command line takes them.
fn completion(shell: Shell, config: Option<&Config>) -> Result<String> {
    let mut command = Program::command();
    if let Some(config) = config {
        let profiles: Vec<String> = config.profiles.iter().map(|a| a.name.clone()).collect();
        let mut secrets: Vec<String> = config
            .profiles
            .iter()
            .flat_map(|a| a.secrets.iter().map(|s| s.name.clone()))
            .collect();
        secrets.sort();
        secrets.dedup();
        command = complete_names(command, &profiles, &secrets);
    }

    let shell = match shell {
        Shell::Zsh => clap_complete::Shell::Zsh,
        Shell::Bash => clap_complete::Shell::Bash,
    };
    let mut out = Vec::new();
    clap_complete::generate(shell, &mut command, "keysafe", &mut out);
    Ok(String::from_utf8(out)?)
}

/// Offers `profiles` for every `profile` argument and `secrets` for every secret name
/// argument of `command` and its subcommands.
fn complete_names(
    mut command: clap::Command,
    profiles: &[String],
    secrets: &[String],
) -> clap::Command {
    for (id, values) in [("profile", profiles), ("name", secrets), ("names", secrets)] {
        if command.get_arguments().any(|a| a.get_id() == id) {
            let values = PossibleValuesParser::new(values.to_vec());
            command = command.mut_arg(id, |a| a.value_parser(values));
        }
    }

    let subcommands: Vec<String> = command
        .get_subcommands()
        .map(|c| c.get_name().to_string())
        .collect();
    for name in subcommands {
        command = command.mut_subcommand(name, |c| complete_names(c, profiles, secrets));
    }
    command
}

/// Print the shell integration script for zsh or bash.
pub struct InitCommand {
    /// Writer used to output the script.
    pub writer: Box<dyn Write>,
    /// Loader used to read the cached secrets.
    pub loader: Loader,
    /// Path of the binary the shell function runs.
    pub bin: PathBuf,
}

impl InitCommand {
    /// Execute the InitCommand with the provided arguments.
    pub fn execute(&mut self, args: &InitCommandArgs) -> Result<()> {
        // This runs on every shell start, so a missing or broken config must not break it:
        // completions fall back to the plain command line and nothing is exported.
        let config = match args.parent.config.exists() {
            true => match Config::read_from_file(&args.parent.config) {
                Ok(config) => Some(config),
                Err(err) => {
                    warn(format!("{err:#}"));
                    None
                }
            },
            false => None,
        };

        let template = match args.shell {
            Shell::Zsh => include_str!("init.zsh"),
            Shell::Bash => include_str!("init.bash"),
        };
        let script = template
            .replace("{{bin}}", &quote(&self.bin.to_string_lossy()))
            .replace(
                "{{completion}}",
                completion(args.shell, config.as_ref())?.trim_end(),
            );
        write!(self.writer, "{script}")?;

        let Some(config) = config.filter(|_| !args.no_export) else {
            return Ok(());
        };

        // Export the cached secrets of the loaded profiles; failures were already reported
        let runtime = RuntimeDir::new(None);
        let mut variables = Vec::new();
        for account in &config.profiles {
            match resolve_cached(&self.loader, &runtime, account) {
                Ok((mut resolved, _)) => variables.append(&mut resolved),
                Err(err) => warn(format!("{err:#}")),
            }
        }

        let format = args.shell.into();
        write_runtime_dir(&mut self.writer, format, &runtime, true)?;
        write_variables(&mut self.writer, format, &variables)
    }
}

/// Execute a command with the secrets of a profile in its environment.
pub struct ExecCommand {
    /// Loader used to resolve the secrets.
    pub loader: Loader,
}

impl ExecCommand {
    /// Execute the ExecCommand with the provided arguments.
    pub fn execute(&mut self, args: &ExecCommandArgs) -> Result<ExitStatus> {
        let config = Config::read_from_file(&args.parent.config)?;
        let account = config.resolve(args.profile.as_deref())?;

        // File secrets live only as long as the command
        let dir = tempfile::Builder::new()
            .prefix("keysafe.")
            .tempdir()
            .context("failed to create file secret runtime directory")?;
        let runtime = RuntimeDir::new(Some(dir.path().to_path_buf()));

        let secrets = account.secrets.iter().filter(|s| s.is_variable());
        let (variables, failed) =
            self.loader
                .resolve(&runtime, account, secrets, Source::Any(args.refresh));
        // Do not run the command with a partial environment
        finish(failed)?;

        // Prepare the command
        let mut arguments = VecDeque::from(args.command.clone());
        let name = match arguments.pop_front() {
            Some(value) => value,
            None => String::from("sh"),
        };

        // Execute the command
        let mut child = Command::new(&name)
            .args(arguments)
            .envs(variables.iter().map(|v| (&v.key, &v.value)))
            .spawn()
            .with_context(|| format!("failed to execute {name}"))?;

        // Like system(3): the terminal delivers Ctrl-C and Ctrl-\ to the whole process
        // group, so let the command handle them while we wait to clean up the file secrets.
        let _guard = SignalGuard::ignore(&[libc::SIGINT, libc::SIGQUIT]);
        let status = child.wait()?;
        Ok(status)
    }
}

/// SignalGuard ignores signals until it is dropped, then restores their previous handlers.
struct SignalGuard(Vec<(libc::c_int, libc::sighandler_t)>);

impl SignalGuard {
    fn ignore(signals: &[libc::c_int]) -> Self {
        Self(
            signals
                .iter()
                // SAFETY: SIG_IGN is a valid disposition and no Rust handler is installed.
                .map(|&signal| (signal, unsafe { libc::signal(signal, libc::SIG_IGN) }))
                .collect(),
        )
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for &(signal, handler) in &self.0 {
            // SAFETY: restores the disposition returned by signal(2) above.
            unsafe { libc::signal(signal, handler) };
        }
    }
}

/// Returns the current time in seconds since the Unix epoch.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Formats a number of seconds as a short duration, like `1h 5m`.
fn duration(seconds: u64) -> String {
    let (days, hours, minutes) = (seconds / 86_400, seconds / 3600 % 24, seconds / 60 % 60);
    match (days, hours, minutes) {
        (0, 0, 0) => format!("{seconds}s"),
        (0, 0, m) => format!("{m}m"),
        (0, h, 0) => format!("{h}h"),
        (0, h, m) => format!("{h}h {m}m"),
        (d, 0, _) => format!("{d}d"),
        (d, h, _) => format!("{d}d {h}h"),
    }
}

/// Show what keysafe has going: secrets in this shell, SSH keys in the agent, and the
/// profiles exported in new shells.
pub struct StatusCommand {
    /// Writer used to output the status.
    pub writer: Box<dyn Write>,
    /// Cache used to tell which profiles are exported and which SSH keys were added.
    pub cache: Cache,
    /// Agent the SSH keys were added to.
    pub agent: Box<dyn KeyAgent>,
    /// Environment of the shell keysafe runs in.
    pub environment: HashMap<String, String>,
    /// Current time, in seconds since the Unix epoch.
    pub now: u64,
}

impl StatusCommand {
    /// Execute the StatusCommand with the provided arguments.
    pub fn execute(&mut self, args: &StatusCommandArgs) -> Result<()> {
        let config = Config::read_from_file(&args.parent.config)?;
        let profiles = match &args.profile {
            Some(name) => vec![config.profile(name)?],
            None => config.profiles.iter().collect(),
        };

        match args.shell {
            Some(shell) => writeln!(
                self.writer,
                "Shell integration: {}",
                styled(format!("active ({shell})")).green()
            )?,
            None => writeln!(
                self.writer,
                "Shell integration: {} (add `eval \"$(keysafe init zsh)\"` to ~/.zshrc, or `init bash` to ~/.bashrc)",
                styled("not active").yellow()
            )?,
        }
        writeln!(self.writer, "Config: {}", args.parent.config.display())?;

        // Only ask the agent if a profile has SSH keys
        let has_keys = profiles
            .iter()
            .any(|p| p.secrets.iter().any(|s| s.kind == SecretKind::Ssh));
        let present = if has_keys {
            self.agent.fingerprints().ok()
        } else {
            None
        };
        let records = self.cache.keys()?;

        for profile in profiles {
            writeln!(self.writer)?;
            let default = if profile.name == config.default_profile().name {
                " (default)"
            } else {
                ""
            };
            writeln!(
                self.writer,
                "{} {}{default}",
                styled("Profile:").bold(),
                styled(&profile.name).bold()
            )?;
            let exported = self.cache.loaded(&profile.name)?.is_some();
            writeln!(
                self.writer,
                "  Exported in new shells: {}",
                if exported { "yes" } else { "no" }
            )?;

            let width = profile
                .secrets
                .iter()
                .map(|s| s.name.len())
                .max()
                .unwrap_or(0);
            let variables: Vec<&Secret> =
                profile.secrets.iter().filter(|s| s.is_variable()).collect();
            if !variables.is_empty() {
                writeln!(self.writer, "  Variables in this shell:")?;
                for secret in variables {
                    let state = match self.environment.get(&secret.name) {
                        Some(value) if !value.is_empty() => match secret.kind {
                            SecretKind::File if Path::new(value).exists() => {
                                styled("set (file)").green()
                            }
                            SecretKind::File => styled("set, but the file is missing").yellow(),
                            _ => styled("set").green(),
                        },
                        _ => styled("not set").dim(),
                    };
                    writeln!(self.writer, "    {:<width$}  {state}", secret.name)?;
                }
            }

            let keys: Vec<&Secret> = profile
                .secrets
                .iter()
                .filter(|s| s.kind == SecretKind::Ssh)
                .collect();
            if !keys.is_empty() {
                writeln!(self.writer, "  SSH keys:")?;
                for key in keys {
                    let state = match &present {
                        None => styled("SSH agent not running".to_string()).yellow(),
                        Some(present) => records
                            .iter()
                            .filter(|r| r.profile == profile.name && r.name == key.name)
                            .find(|r| present.contains(&r.fingerprint))
                            .map(|r| match r.expires.checked_sub(self.now) {
                                Some(left) if left > 0 => {
                                    styled(format!("in agent, expires in {}", duration(left)))
                                        .green()
                                }
                                _ => styled("in agent".to_string()).green(),
                            })
                            .unwrap_or_else(|| styled("not in agent".to_string()).dim()),
                    };
                    writeln!(self.writer, "    {:<width$}  {state}", key.name)?;
                }
            }
        }

        Ok(())
    }
}

/// The starter config written by `keysafe config init`.
const STARTER_CONFIG: &str = include_str!("config.yml");

/// Create a starter config file.
pub struct ConfigInitCommand;

impl ConfigInitCommand {
    /// Execute the ConfigInitCommand with the provided arguments.
    pub fn execute(&mut self, args: &ConfigInitCommandArgs) -> Result<()> {
        let path = &args.parent.config;
        if path.exists() && !args.force {
            bail!(
                "{} already exists (edit it with `keysafe config edit`, or replace it with --force)",
                path.display()
            );
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        std::fs::write(path, STARTER_CONFIG)
            .with_context(|| format!("failed to write {}", path.display()))?;

        success(format!("Created {}", path.display()));
        info("add your secrets with `keysafe config edit`");
        Ok(())
    }
}

/// Open the config file in an editor, then check it.
pub struct ConfigEditCommand {
    /// Editor command, which may include arguments (e.g. `code --wait`).
    pub editor: String,
}

impl ConfigEditCommand {
    /// Execute the ConfigEditCommand with the provided arguments.
    pub fn execute(&mut self, args: &ConfigEditCommandArgs) -> Result<()> {
        let path = &args.parent.config;
        if !path.exists() {
            bail!(
                "config file not found: {} (create one with `keysafe config init`)",
                path.display()
            );
        }

        // Run the editor through the shell, so commands with arguments work
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("{} \"$1\"", self.editor))
            .arg("sh")
            .arg(path)
            .status()
            .with_context(|| format!("failed to run the editor ({})", self.editor))?;
        if !status.success() {
            bail!("the editor ({}) exited with {status}", self.editor);
        }

        let config = Config::read_from_file(path)
            .context("the config is not valid; fix it with `keysafe config edit`")?;
        success(format!(
            "{} is valid  ({})",
            path.display(),
            count(config.profiles.len(), "profile")
        ));
        Ok(())
    }
}

/// Returns where the config file `path` comes from, given `KEYSAFE_CONFIG_FILE`.
fn config_source(path: &Path, env: Option<&Path>) -> String {
    if env == Some(path) {
        "set by KEYSAFE_CONFIG_FILE".into()
    } else if path == default_config() {
        "the default location".into()
    } else if path == legacy_config() {
        format!(
            "zsh-op's location; move it to {}",
            default_config().display()
        )
    } else {
        "set by --config".into()
    }
}

/// Print the path of the config file in use.
pub struct ConfigPathCommand {
    /// Writer used to output the path.
    pub writer: Box<dyn Write>,
    /// Value of `KEYSAFE_CONFIG_FILE`, if set.
    pub env: Option<PathBuf>,
}

impl ConfigPathCommand {
    /// Execute the ConfigPathCommand with the provided arguments.
    pub fn execute(&mut self, args: &ConfigPathCommandArgs) -> Result<()> {
        let path = &args.parent.config;
        writeln!(self.writer, "{}", path.display())?;

        let source = config_source(path, self.env.as_deref());
        if path.exists() {
            info(source);
        } else {
            info(format!(
                "{source}; it does not exist yet (create it with `keysafe config init`)"
            ));
        }
        Ok(())
    }
}

/// Result of one `doctor` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    /// Works.
    Ok,
    /// Works, but worth fixing.
    Warning,
    /// Broken.
    Failure,
}

impl Check {
    /// Returns the mark printed in front of the check.
    fn mark(self) -> &'static str {
        match self {
            Self::Ok => "✓",
            Self::Warning => "!",
            Self::Failure => "✗",
        }
    }
}

/// Check the setup and say how to fix problems.
pub struct DoctorCommand {
    /// Writer used to output the checks.
    pub writer: Box<dyn Write>,
    /// Client used to check the providers.
    pub client: Box<dyn SecretClient>,
    /// Cache whose store is checked.
    pub cache: Cache,
    /// Agent the SSH keys are added to.
    pub agent: Box<dyn KeyAgent>,
    /// Value of `KEYSAFE_CONFIG_FILE`, if set.
    pub env: Option<PathBuf>,
}

impl DoctorCommand {
    /// Writes one check.
    fn report(&mut self, check: Check, label: &str, detail: impl Display) -> Result<()> {
        let mark = styled(check.mark());
        let mark = match check {
            Check::Ok => mark.green(),
            Check::Warning => mark.yellow(),
            Check::Failure => mark.red(),
        };
        writeln!(
            self.writer,
            "{} {}: {detail}",
            mark.bold(),
            styled(label).bold()
        )?;
        Ok(())
    }

    /// Execute the DoctorCommand with the provided arguments.
    pub fn execute(&mut self, args: &DoctorCommandArgs) -> Result<()> {
        let mut failures = 0;

        // The config file
        let path = &args.parent.config;
        let config = match Config::read_from_file(path) {
            Ok(config) => {
                let check = if *path == legacy_config() {
                    Check::Warning
                } else {
                    Check::Ok
                };
                let source = config_source(path, self.env.as_deref());
                let detail = format!(
                    "{} ({source}), {} profile(s)",
                    path.display(),
                    config.profiles.len()
                );
                self.report(check, "Config", detail)?;
                Some(config)
            }
            Err(err) => {
                failures += 1;
                self.report(Check::Failure, "Config", format!("{err:#}"))?;
                None
            }
        };

        // Each provider setting once, with the profiles that use it
        let profiles = config
            .as_ref()
            .map(|c| c.profiles.as_slice())
            .unwrap_or_default();
        let mut providers: Vec<(&Provider, Vec<&str>)> = Vec::new();
        for profile in profiles {
            match providers.iter_mut().find(|(p, _)| **p == profile.provider) {
                Some((_, names)) => names.push(&profile.name),
                None => providers.push((&profile.provider, vec![&profile.name])),
            }
        }
        for (provider, names) in providers {
            let label = format!("{provider} ({})", names.join(", "));
            match self.client.check(provider) {
                Ok(detail) => self.report(Check::Ok, &label, detail)?,
                Err(err) => {
                    failures += 1;
                    self.report(Check::Failure, &label, format!("{err:#}"))?;
                }
            }
        }

        // The keychain: looking up a missing item needs the store, but never prompts
        match self.cache.store.get("keysafe.doctor", "check") {
            Ok(_) => self.report(Check::Ok, "Keychain", "reachable")?,
            Err(err) => {
                failures += 1;
                self.report(Check::Failure, "Keychain", format!("{err:#}"))?;
            }
        }

        // The SSH agent, if a profile has SSH keys
        let has_keys = profiles
            .iter()
            .any(|p| p.secrets.iter().any(|s| s.kind == SecretKind::Ssh));
        if has_keys {
            match self.agent.fingerprints() {
                Ok(keys) => self.report(
                    Check::Ok,
                    "SSH agent",
                    format!("running, {} key(s)", keys.len()),
                )?,
                Err(err) => {
                    failures += 1;
                    self.report(Check::Failure, "SSH agent", format!("{err:#}"))?;
                }
            }
        }

        // The shell integration: everything but `load`, `unload` and `export` works without it
        match args.shell {
            Some(shell) => self.report(Check::Ok, "Shell integration", format!("active ({shell})"))?,
            None => self.report(
                Check::Warning,
                "Shell integration",
                "not active in this shell (add `eval \"$(keysafe init zsh)\"` to ~/.zshrc, or `init bash` to ~/.bashrc)",
            )?,
        }

        if failures > 0 {
            bail!("found {failures} problem(s)");
        }
        Ok(())
    }
}

/// List the profile names, one per line.
pub struct ProfileListCommand {
    /// Writer used to output the names.
    pub writer: Box<dyn Write>,
}

impl ProfileListCommand {
    /// Execute the ProfileListCommand with the provided arguments.
    pub fn execute(&mut self, args: &ProfileListCommandArgs) -> Result<()> {
        let config = Config::read_from_file(&args.parent.config)?;
        for account in &config.profiles {
            writeln!(self.writer, "{}", account.name)?;
        }

        Ok(())
    }
}

/// Show profiles, their secrets and whether they were loaded.
pub struct ProfileShowCommand {
    /// Writer used to output the profiles.
    pub writer: Box<dyn Write>,
    /// Cache used to tell which profiles were loaded.
    pub cache: Cache,
}

impl ProfileShowCommand {
    /// Execute the ProfileShowCommand with the provided arguments.
    pub fn execute(&mut self, args: &ProfileShowCommandArgs) -> Result<()> {
        let config = Config::read_from_file(&args.parent.config)?;
        let accounts = match &args.profile {
            Some(profile) => vec![config.profile(profile)?],
            None => config.profiles.iter().collect(),
        };

        for (i, account) in accounts.iter().enumerate() {
            if i > 0 {
                writeln!(self.writer)?;
            }
            let loaded = self.cache.loaded(&account.name)?.is_some();
            let default = if account.name == config.default_profile().name {
                " (default)"
            } else {
                ""
            };
            writeln!(
                self.writer,
                "{} {}{default}",
                styled("Profile:").bold(),
                styled(&account.name).bold()
            )?;
            match &account.provider {
                Provider::OnePassword {
                    account: Some(name),
                } => writeln!(self.writer, "  Provider: {} ({name})", account.provider)?,
                provider => writeln!(self.writer, "  Provider: {provider}")?,
            }
            writeln!(
                self.writer,
                "  Exported in new shells: {}",
                if loaded { "yes" } else { "no" }
            )?;
            if !account.secrets.is_empty() {
                writeln!(self.writer, "  Secrets:")?;
                for secret in &account.secrets {
                    let kind = secret.kind.to_string();
                    writeln!(
                        self.writer,
                        "    {kind:<4} {} ({})",
                        secret.name, secret.path
                    )?;
                }
            }
        }

        Ok(())
    }
}

/// Clear the cached secrets of a profile.
pub struct ProfileClearCommand {
    /// Cache the secrets are deleted from.
    pub cache: Cache,
}

impl ProfileClearCommand {
    /// Execute the ProfileClearCommand with the provided arguments.
    pub fn execute(&mut self, args: &ProfileClearCommandArgs) -> Result<()> {
        let config = Config::read_from_file(&args.parent.config)?;
        let account = config.profile(&args.profile)?;

        let cleared = self.cache.clear(account)?;
        success(format!(
            "Cleared {} of {}",
            count(cleared, "cached secret"),
            account.name
        ));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use std::path::{Path, PathBuf};
    use std::sync::*;

    #[derive(Clone)]
    struct Writer(Arc<Mutex<Vec<u8>>>);

    impl Writer {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }

        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Writer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const CONFIG: &str = indoc! {"
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
              - kind: file
                name: GCP_CREDENTIALS
                path: op://Personal/GCP/credentials
              - kind: ssh
                name: my-key
                path: op://Private/SSH/private key?ssh-format=openssh
          - name: work
            provider:
              type: 1password
              account: team.1password.com
            secrets:
              - kind: env
                name: API_KEY
                path: op://Infra/Prod/API_KEY
    "};

    /// Fixture holds a temporary config, cache directory, runtime directory and store.
    struct Fixture {
        dir: tempfile::TempDir,
        store: MemoryStore,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("config.yml"), CONFIG).unwrap();
            Self {
                dir,
                store: MemoryStore::default(),
            }
        }

        /// Caches `value` as secret `name` of `profile`.
        fn cached(self, profile: &str, name: &str, value: &str) -> Self {
            self.store
                .set(&Cache::service(profile), name, value)
                .unwrap();
            self
        }

        /// Records `profile` as loaded with the given metadata lines.
        fn loaded(self, profile: &str, metadata: &str) -> Self {
            let dir = self.dir.path().join("cache");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(format!("{profile}.metadata")), metadata).unwrap();
            self
        }

        fn parent(&self) -> ProgramArgs {
            ProgramArgs {
                config: self.dir.path().join("config.yml"),
                state_dir: self.dir.path().join("cache"),
                ..Default::default()
            }
        }

        fn output(&self, format: ExportFormat) -> OutputArgs {
            OutputArgs {
                format: Some(format),
                runtime_dir: Some(self.runtime_dir()),
                ..Default::default()
            }
        }

        fn runtime_dir(&self) -> PathBuf {
            self.dir.path().join("runtime")
        }

        fn file(&self, profile: &str, name: &str) -> PathBuf {
            self.runtime_dir().join("files").join(profile).join(name)
        }

        fn cache(&self) -> Cache {
            Cache::new(Box::new(self.store.clone()), &self.dir.path().join("cache"))
        }

        fn loader(&self, client: MockSecretClient) -> Loader {
            Loader::new(Box::new(client), self.cache())
        }

        fn value(&self, profile: &str, name: &str) -> Option<String> {
            self.store.value(&Cache::service(profile), name)
        }
    }

    fn offline() -> MockSecretClient {
        let mut client = MockSecretClient::new();
        client.expect_read().never();
        client
    }

    fn expect_read(client: &mut MockSecretClient, path: &'static str, value: &'static str) {
        client
            .expect_read()
            .withf(move |_, p| p == path)
            .times(1)
            .returning(move |_, _| Ok(value.to_string()));
    }

    fn agent(present: Vec<String>) -> MockKeyAgent {
        let mut agent = MockKeyAgent::new();
        agent.expect_fingerprints().return_once(move || Ok(present));
        agent
    }

    fn load_args(fixture: &Fixture, names: &[&str], refresh: bool) -> LoadCommandArgs {
        LoadCommandArgs {
            parent: fixture.parent(),
            names: names.iter().map(|n| n.to_string()).collect(),
            profile: Some("personal".into()),
            expiration: "1h".into(),
            refresh,
            output: fixture.output(ExportFormat::Zsh),
        }
    }

    fn read_args(fixture: &Fixture, name: &str) -> ReadCommandArgs {
        ReadCommandArgs {
            parent: fixture.parent(),
            name: name.into(),
            profile: Some("personal".into()),
            refresh: false,
        }
    }

    fn export_args(fixture: &Fixture, all: bool, cached: bool) -> ExportCommandArgs {
        ExportCommandArgs {
            parent: fixture.parent(),
            profile: Some("personal".into()),
            all,
            cached,
            refresh: false,
            output: fixture.output(ExportFormat::Zsh),
        }
    }

    #[test]
    fn quote_wraps_value_in_single_quotes() {
        assert_eq!(quote("brown fox"), "'brown fox'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn quoted_values_survive_shell_eval() {
        let values = [
            "plain",
            "it's \"quoted\"",
            "multi\nline\n",
            "$(touch /tmp/keysafe-pwned) `id` $HOME \\n",
            "unicode ✓ 🔑",
        ];
        for value in values {
            let mut out = Vec::new();
            let vars = [Variable {
                key: "VALUE".into(),
                value: value.into(),
            }];
            write_variables(&mut out, ExportFormat::Zsh, &vars).unwrap();

            let output = Command::new("sh")
                .args(["-c", r#"eval "$1"; printf %s "$VALUE""#, "sh"])
                .arg(String::from_utf8(out).unwrap())
                .output()
                .unwrap();
            assert_eq!(String::from_utf8(output.stdout).unwrap(), value);
        }
    }

    #[test]
    fn write_variables_writes_json_object() {
        let mut out = Vec::new();
        let vars = [
            Variable {
                key: "B".into(),
                value: "2".into(),
            },
            Variable {
                key: "A".into(),
                value: "line\n".into(),
            },
        ];
        write_variables(&mut out, ExportFormat::Json, &vars).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\"A\":\"line\\n\",\"B\":\"2\"}\n"
        );
    }

    #[test]
    fn profile_show_writes_profiles() -> Result<()> {
        let fixture = Fixture::new().loaded("personal", "env:GITHUB_TOKEN\n");
        let writer = Writer::new();
        let mut cmd = ProfileShowCommand {
            writer: Box::new(writer.clone()),
            cache: fixture.cache(),
        };

        cmd.execute(&ProfileShowCommandArgs {
            parent: fixture.parent(),
            profile: None,
        })?;

        let expected = indoc! {"
            Profile: personal (default)
              Provider: 1password (my.1password.com)
              Exported in new shells: yes
              Secrets:
                env  GITHUB_TOKEN (op://Personal/GitHub/token)
                file GCP_CREDENTIALS (op://Personal/GCP/credentials)
                ssh  my-key (op://Private/SSH/private key?ssh-format=openssh)

            Profile: work
              Provider: 1password (team.1password.com)
              Exported in new shells: no
              Secrets:
                env  API_KEY (op://Infra/Prod/API_KEY)
        "};
        assert_eq!(writer.contents(), expected);
        Ok(())
    }

    #[test]
    fn profile_show_fails_for_unknown_profile() {
        let fixture = Fixture::new();
        let mut cmd = ProfileShowCommand {
            writer: Box::new(Writer::new()),
            cache: fixture.cache(),
        };

        let result = cmd.execute(&ProfileShowCommandArgs {
            parent: fixture.parent(),
            profile: Some("staging".into()),
        });

        assert_eq!(
            result.unwrap_err().to_string(),
            "profile 'staging' not found in config (available profiles: personal, work)"
        );
    }

    #[test]
    fn profile_list_writes_profile_names() -> Result<()> {
        let fixture = Fixture::new();
        let writer = Writer::new();
        let mut cmd = ProfileListCommand {
            writer: Box::new(writer.clone()),
        };

        cmd.execute(&ProfileListCommandArgs {
            parent: fixture.parent(),
        })?;

        assert_eq!(writer.contents(), "personal\nwork\n");
        Ok(())
    }

    #[test]
    fn load_loads_cached_profile_without_contacting_1password() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "brown-fox")
            .cached("personal", "GCP_CREDENTIALS", "{\"type\":\"sa\"}")
            .cached("personal", "my-key", &TEST_KEY);
        let mut agent = agent(vec![]);
        agent
            .expect_add()
            .withf(|key, lifetime| *key == *TEST_KEY && lifetime == "1h")
            .times(1)
            .returning(|_, _| Ok(()));
        let writer = Writer::new();
        let mut cmd = LoadCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
            agent: Box::new(agent),
        };

        cmd.execute(&load_args(&fixture, &[], false))?;

        let file = fixture.file("personal", "GCP_CREDENTIALS");
        assert_eq!(
            writer.contents(),
            format!(
                "export GITHUB_TOKEN='brown-fox'\nexport GCP_CREDENTIALS='{}'\n",
                file.display()
            )
        );
        assert_eq!(std::fs::read_to_string(file)?, "{\"type\":\"sa\"}");
        assert_eq!(
            fixture.cache().loaded("personal")?,
            Some(vec![
                "GITHUB_TOKEN".into(),
                "GCP_CREDENTIALS".into(),
                "my-key".into()
            ])
        );
        Ok(())
    }

    #[test]
    fn load_fetches_uncached_secrets_and_caches_them() -> Result<()> {
        let fixture = Fixture::new();
        let mut client = MockSecretClient::new();
        expect_read(&mut client, "op://Personal/GitHub/token", "brown-fox");
        expect_read(&mut client, "op://Personal/GCP/credentials", "{}");
        expect_read(
            &mut client,
            "op://Private/SSH/private key?ssh-format=openssh",
            TEST_KEY.as_str(),
        );
        let mut agent = agent(vec![]);
        agent.expect_add().times(1).returning(|_, _| Ok(()));
        let mut cmd = LoadCommand {
            writer: Box::new(Writer::new()),
            loader: fixture.loader(client),
            agent: Box::new(agent),
        };

        cmd.execute(&load_args(&fixture, &[], false))?;

        assert_eq!(
            fixture.value("personal", "GITHUB_TOKEN").as_deref(),
            Some("brown-fox")
        );
        assert_eq!(
            fixture.value("personal", "GCP_CREDENTIALS").as_deref(),
            Some("{}")
        );
        assert_eq!(
            fixture.value("personal", "my-key").as_deref(),
            Some(TEST_KEY.as_str())
        );
        Ok(())
    }

    #[test]
    fn load_refresh_bypasses_cache_and_readds_keys() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "stale")
            .cached("personal", "GCP_CREDENTIALS", "stale")
            .cached("personal", "my-key", &TEST_KEY);
        let mut client = MockSecretClient::new();
        expect_read(&mut client, "op://Personal/GitHub/token", "fresh");
        expect_read(&mut client, "op://Personal/GCP/credentials", "fresh");
        expect_read(
            &mut client,
            "op://Private/SSH/private key?ssh-format=openssh",
            TEST_KEY.as_str(),
        );
        let mut agent = agent(vec![fingerprint(&TEST_KEY)?]);
        agent.expect_add().times(1).returning(|_, _| Ok(()));
        let mut cmd = LoadCommand {
            writer: Box::new(Writer::new()),
            loader: fixture.loader(client),
            agent: Box::new(agent),
        };

        cmd.execute(&load_args(&fixture, &[], true))?;

        assert_eq!(
            fixture.value("personal", "GITHUB_TOKEN").as_deref(),
            Some("fresh")
        );
        Ok(())
    }

    #[test]
    fn load_skips_keys_already_in_agent() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "a")
            .cached("personal", "GCP_CREDENTIALS", "b")
            .cached("personal", "my-key", &TEST_KEY);
        let mut agent = agent(vec![fingerprint(&TEST_KEY)?]);
        agent.expect_add().never();
        let mut cmd = LoadCommand {
            writer: Box::new(Writer::new()),
            loader: fixture.loader(offline()),
            agent: Box::new(agent),
        };

        cmd.execute(&load_args(&fixture, &[], false))
    }

    #[test]
    fn load_continues_past_failing_secrets() -> Result<()> {
        let fixture = Fixture::new().cached("personal", "GCP_CREDENTIALS", "{}");
        let mut client = MockSecretClient::new();
        client
            .expect_read()
            .withf(|_, p| p == "op://Personal/GitHub/token")
            .returning(|_, _| Err(anyhow::anyhow!("oh no")));
        let mut agent = MockKeyAgent::new();
        agent
            .expect_fingerprints()
            .returning(|| Err(anyhow::anyhow!("SSH agent is not running")));
        let writer = Writer::new();
        let mut cmd = LoadCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(client),
            agent: Box::new(agent),
        };

        let result = cmd.execute(&load_args(&fixture, &[], false));

        assert_eq!(
            result.unwrap_err().to_string(),
            "failed to load 2 secret(s)"
        );
        assert!(writer.contents().starts_with("export GCP_CREDENTIALS="));
        assert!(fixture.cache().loaded("personal")?.is_some());
        Ok(())
    }

    #[test]
    fn load_named_secrets_does_not_record_the_profile() -> Result<()> {
        let fixture = Fixture::new().cached("personal", "GITHUB_TOKEN", "brown-fox");
        let writer = Writer::new();
        // No SSH key is selected, so the agent must not be contacted
        let mut cmd = LoadCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
            agent: Box::new(MockKeyAgent::new()),
        };

        cmd.execute(&load_args(&fixture, &["GITHUB_TOKEN"], false))?;

        assert_eq!(writer.contents(), "export GITHUB_TOKEN='brown-fox'\n");
        assert_eq!(fixture.cache().loaded("personal")?, None);
        Ok(())
    }

    #[test]
    fn load_named_ssh_key_adds_it_with_expiration() -> Result<()> {
        let fixture = Fixture::new().cached("personal", "my-key", &TEST_KEY);
        let mut agent = agent(vec![]);
        agent
            .expect_add()
            .withf(|_, lifetime| lifetime == "8h")
            .times(1)
            .returning(|_, _| Ok(()));
        let writer = Writer::new();
        let mut cmd = LoadCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
            agent: Box::new(agent),
        };

        cmd.execute(&LoadCommandArgs {
            expiration: "8h".into(),
            ..load_args(&fixture, &["my-key"], false)
        })?;

        assert_eq!(writer.contents(), "");
        Ok(())
    }

    #[test]
    fn load_fails_for_unknown_secret() {
        let fixture = Fixture::new();
        let mut cmd = LoadCommand {
            writer: Box::new(Writer::new()),
            loader: fixture.loader(offline()),
            agent: Box::new(MockKeyAgent::new()),
        };

        let result = cmd.execute(&load_args(&fixture, &["GITHUB_TOKEN", "NOPE"], false));

        assert!(result
            .unwrap_err()
            .to_string()
            .starts_with("secret 'NOPE' not found in profile 'personal'"));
    }

    #[test]
    fn read_prints_env_value() -> Result<()> {
        let fixture = Fixture::new().cached("personal", "GITHUB_TOKEN", "brown-fox");
        let writer = Writer::new();
        let mut cmd = ReadCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
        };

        cmd.execute(&read_args(&fixture, "GITHUB_TOKEN"))?;

        assert_eq!(writer.contents(), "brown-fox\n");
        Ok(())
    }

    #[test]
    fn read_prints_file_contents_without_writing_a_file() -> Result<()> {
        let fixture = Fixture::new();
        let mut client = MockSecretClient::new();
        expect_read(&mut client, "op://Personal/GCP/credentials", "{}");
        let writer = Writer::new();
        let mut cmd = ReadCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(client),
        };

        cmd.execute(&read_args(&fixture, "GCP_CREDENTIALS"))?;

        assert_eq!(writer.contents(), "{}\n");
        assert!(!fixture.runtime_dir().exists());
        Ok(())
    }

    #[test]
    fn read_refuses_ssh_keys() {
        let fixture = Fixture::new().cached("personal", "my-key", &TEST_KEY);
        let writer = Writer::new();
        let mut cmd = ReadCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
        };

        let result = cmd.execute(&read_args(&fixture, "my-key"));

        assert_eq!(
            result.unwrap_err().to_string(),
            "'my-key' is an SSH key, which is not printed; use `keysafe load my-key` to add it to ssh-agent"
        );
        assert_eq!(writer.contents(), "");
    }

    #[test]
    fn export_cached_exports_only_loaded_profiles() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "brown-fox")
            .cached("work", "API_KEY", "not-loaded")
            .loaded(
                "personal",
                "env:GITHUB_TOKEN\nfile:GCP_CREDENTIALS\nssh:my-key\n",
            );
        let writer = Writer::new();
        let mut cmd = ExportCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
        };

        cmd.execute(&export_args(&fixture, true, true))?;

        // GCP_CREDENTIALS is recorded but not cached, so it is skipped silently.
        assert_eq!(writer.contents(), "export GITHUB_TOKEN='brown-fox'\n");
        Ok(())
    }

    #[test]
    fn export_cached_uses_kind_from_current_config() -> Result<()> {
        // The metadata still says env, but the config now declares a file secret.
        let fixture = Fixture::new()
            .cached("personal", "GCP_CREDENTIALS", "{}")
            .loaded("personal", "env:GCP_CREDENTIALS\n");
        let writer = Writer::new();
        let mut cmd = ExportCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
        };

        cmd.execute(&export_args(&fixture, false, true))?;

        let file = fixture.file("personal", "GCP_CREDENTIALS");
        assert_eq!(
            writer.contents(),
            format!("export GCP_CREDENTIALS='{}'\n", file.display())
        );
        assert_eq!(std::fs::read_to_string(file)?, "{}");
        Ok(())
    }

    #[test]
    fn export_cached_writes_nothing_without_loaded_profiles() -> Result<()> {
        let fixture = Fixture::new().cached("personal", "GITHUB_TOKEN", "brown-fox");
        let writer = Writer::new();
        let mut cmd = ExportCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
        };

        cmd.execute(&export_args(&fixture, true, true))?;

        assert_eq!(writer.contents(), "");
        Ok(())
    }

    #[test]
    fn export_fetches_profile_and_records_it() -> Result<()> {
        let fixture = Fixture::new();
        let mut client = MockSecretClient::new();
        expect_read(&mut client, "op://Infra/Prod/API_KEY", "it's");
        let writer = Writer::new();
        let mut cmd = ExportCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(client),
        };

        cmd.execute(&ExportCommandArgs {
            profile: Some("work".into()),
            output: fixture.output(ExportFormat::Json),
            ..export_args(&fixture, false, false)
        })?;

        assert_eq!(writer.contents(), "{\"API_KEY\":\"it's\"}\n");
        assert_eq!(
            fixture.cache().loaded("work")?,
            Some(vec!["API_KEY".into()])
        );
        Ok(())
    }

    #[test]
    fn exec_runs_command_with_secrets() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "brown-fox")
            .cached("personal", "GCP_CREDENTIALS", "{}");
        let mut cmd = ExecCommand {
            loader: fixture.loader(offline()),
        };

        let status = cmd.execute(&ExecCommandArgs {
            parent: fixture.parent(),
            profile: Some("personal".into()),
            refresh: false,
            command: vec![
                "sh".into(),
                "-c".into(),
                r#"[ "$GITHUB_TOKEN" = "brown-fox" ] && [ "$(cat "$GCP_CREDENTIALS")" = "{}" ] && printf %s "$GCP_CREDENTIALS" > "$0""#.into(),
                fixture.dir.path().join("path").to_string_lossy().into_owned(),
            ],
        })?;

        assert!(status.success());
        // The file secret is removed once the command exits.
        let file = std::fs::read_to_string(fixture.dir.path().join("path"))?;
        assert!(!Path::new(&file).exists());
        Ok(())
    }

    #[test]
    fn exec_returns_command_exit_status() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "a")
            .cached("personal", "GCP_CREDENTIALS", "b");
        let mut cmd = ExecCommand {
            loader: fixture.loader(offline()),
        };

        let status = cmd.execute(&ExecCommandArgs {
            parent: fixture.parent(),
            profile: Some("personal".into()),
            refresh: false,
            command: vec!["sh".into(), "-c".into(), "exit 3".into()],
        })?;

        assert_eq!(status.code(), Some(3));
        Ok(())
    }

    #[test]
    fn exec_does_not_run_command_with_partial_environment() {
        let fixture = Fixture::new().cached("personal", "GITHUB_TOKEN", "a");
        let mut client = MockSecretClient::new();
        client
            .expect_read()
            .returning(|_, _| Err(anyhow::anyhow!("oh no")));
        let mut cmd = ExecCommand {
            loader: fixture.loader(client),
        };
        let marker = fixture.dir.path().join("ran");

        let result = cmd.execute(&ExecCommandArgs {
            parent: fixture.parent(),
            profile: Some("personal".into()),
            refresh: false,
            command: vec!["touch".into(), marker.to_string_lossy().into_owned()],
        });

        assert_eq!(
            result.unwrap_err().to_string(),
            "failed to load 1 secret(s)"
        );
        assert!(!marker.exists());
    }

    /// Returns the runtime directory assigned by the statements in `output`, if any.
    fn assigned_runtime_dir(output: &str) -> Option<PathBuf> {
        output.lines().find_map(|line| {
            let value = line
                .strip_prefix("typeset -g _KEYSAFE_RUNTIME_DIR=")
                .or_else(|| line.strip_prefix("_KEYSAFE_RUNTIME_DIR="))?;
            Some(PathBuf::from(value.trim_matches('\'')))
        })
    }

    fn eval_output(shell: Shell) -> OutputArgs {
        OutputArgs {
            eval: Some(shell),
            ..Default::default()
        }
    }

    fn init_args(fixture: &Fixture, shell: Shell, no_export: bool) -> InitCommandArgs {
        InitCommandArgs {
            parent: fixture.parent(),
            shell,
            no_export,
        }
    }

    #[test]
    fn init_writes_zsh_script_with_cached_exports() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "brown-fox")
            .cached("personal", "GCP_CREDENTIALS", "{}")
            .loaded("personal", "env:GITHUB_TOKEN\nfile:GCP_CREDENTIALS\n");
        let writer = Writer::new();
        let mut cmd = InitCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
            bin: PathBuf::from("/opt/it's/keysafe"),
        };

        cmd.execute(&init_args(&fixture, Shell::Zsh, false))?;

        let output = writer.contents();
        assert!(output.contains("typeset -g _KEYSAFE_BIN='/opt/it'\\''s/keysafe'\n"));
        assert!(output.contains("\nkeysafe() {\n"));
        assert!(output.contains("_keysafe() {"));
        assert!(!output.contains("{{"));
        assert!(output.contains("\nexport GITHUB_TOKEN='brown-fox'\n"));

        // The file secret lives in a directory the shell removes when it exits
        let dir = assigned_runtime_dir(&output).expect("runtime directory is assigned");
        let file = dir.join("files/personal/GCP_CREDENTIALS");
        assert!(output.ends_with(&format!("export GCP_CREDENTIALS='{}'\n", file.display())));
        assert_eq!(std::fs::read_to_string(&file)?, "{}");
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn init_writes_bash_script() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "brown-fox")
            .loaded("personal", "env:GITHUB_TOKEN\n");
        let writer = Writer::new();
        let mut cmd = InitCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
            bin: PathBuf::from("/usr/local/bin/keysafe"),
        };

        cmd.execute(&init_args(&fixture, Shell::Bash, false))?;

        let output = writer.contents();
        assert!(output.contains("_KEYSAFE_BIN='/usr/local/bin/keysafe'\n"));
        assert!(output.contains("KEYSAFE_EVAL=bash"));
        assert!(output.contains("complete -F _keysafe"));
        assert!(output.ends_with("export GITHUB_TOKEN='brown-fox'\n"));
        assert_eq!(assigned_runtime_dir(&output), None);
        Ok(())
    }

    #[test]
    fn init_without_export_writes_script_only() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "brown-fox")
            .loaded("personal", "env:GITHUB_TOKEN\n");
        let writer = Writer::new();
        let mut cmd = InitCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
            bin: PathBuf::from("keysafe"),
        };

        cmd.execute(&init_args(&fixture, Shell::Zsh, true))?;

        assert!(!writer
            .contents()
            .lines()
            .any(|line| line.starts_with("export ")));
        Ok(())
    }

    #[test]
    fn init_without_config_writes_script_only() -> Result<()> {
        let fixture = Fixture::new();
        std::fs::remove_file(fixture.parent().config)?;
        let writer = Writer::new();
        let mut cmd = InitCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
            bin: PathBuf::from("keysafe"),
        };

        cmd.execute(&init_args(&fixture, Shell::Zsh, false))?;

        let output = writer.contents();
        assert!(output.contains("\nkeysafe() {\n"));
        assert!(!output.lines().any(|line| line.starts_with("export ")));
        Ok(())
    }

    #[test]
    fn init_with_broken_config_still_writes_script() -> Result<()> {
        let fixture = Fixture::new();
        std::fs::write(fixture.parent().config, "version: 2\n")?;
        let writer = Writer::new();
        let mut cmd = InitCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
            bin: PathBuf::from("keysafe"),
        };

        cmd.execute(&init_args(&fixture, Shell::Bash, false))?;

        assert!(writer.contents().contains("\nkeysafe() {\n"));
        Ok(())
    }

    #[test]
    fn completion_offers_configured_profiles_and_secrets() -> Result<()> {
        let config = Config::parse(CONFIG)?;

        let bash = completion(Shell::Bash, Some(&config))?;
        assert!(bash.contains("personal work"));
        assert!(bash.contains("API_KEY GCP_CREDENTIALS GITHUB_TOKEN my-key"));

        let zsh = completion(Shell::Zsh, Some(&config))?;
        assert!(zsh.contains("(personal work)"));
        assert!(zsh.contains("(API_KEY GCP_CREDENTIALS GITHUB_TOKEN my-key)"));

        // Without a config only the command line itself is completed
        assert!(!completion(Shell::Zsh, None)?.contains("(personal work)"));
        Ok(())
    }

    #[test]
    fn load_in_eval_mode_hands_runtime_dir_to_the_shell() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "a")
            .cached("personal", "GCP_CREDENTIALS", "{}");
        let writer = Writer::new();
        let mut cmd = LoadCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
            agent: Box::new(MockKeyAgent::new()),
        };

        cmd.execute(&LoadCommandArgs {
            output: eval_output(Shell::Zsh),
            ..load_args(&fixture, &["GITHUB_TOKEN", "GCP_CREDENTIALS"], false)
        })?;

        let output = writer.contents();
        assert!(output.starts_with("typeset -g _KEYSAFE_RUNTIME_DIR='"));
        let dir = assigned_runtime_dir(&output).unwrap();
        assert!(dir.join("files/personal/GCP_CREDENTIALS").exists());
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn load_uses_the_default_profile() -> Result<()> {
        let fixture = Fixture::new().cached("personal", "GITHUB_TOKEN", "brown-fox");
        let writer = Writer::new();
        let mut cmd = LoadCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
            agent: Box::new(MockKeyAgent::new()),
        };

        cmd.execute(&LoadCommandArgs {
            profile: None,
            ..load_args(&fixture, &["GITHUB_TOKEN"], false)
        })?;

        assert_eq!(writer.contents(), "export GITHUB_TOKEN='brown-fox'\n");
        Ok(())
    }

    #[test]
    fn load_records_the_keys_it_adds() -> Result<()> {
        let fixture = Fixture::new().cached("personal", "my-key", &TEST_KEY);
        let mut agent = agent(vec![]);
        agent.expect_add().times(1).returning(|_, _| Ok(()));
        let mut cmd = LoadCommand {
            writer: Box::new(Writer::new()),
            loader: fixture.loader(offline()),
            agent: Box::new(agent),
        };
        let before = unix_now();

        cmd.execute(&load_args(&fixture, &["my-key"], false))?;

        let keys = fixture.cache().keys()?;
        assert_eq!(keys.len(), 1);
        assert_eq!(
            (keys[0].profile.as_str(), keys[0].name.as_str()),
            ("personal", "my-key")
        );
        assert_eq!(keys[0].fingerprint, fingerprint(&TEST_KEY)?);
        assert_eq!(keys[0].public_key, public_key(&TEST_KEY)?);
        assert!((before + 3600..=unix_now() + 3600).contains(&keys[0].expires));
        Ok(())
    }

    #[test]
    fn duration_is_short_and_readable() {
        assert_eq!(duration(42), "42s");
        assert_eq!(duration(45 * 60), "45m");
        assert_eq!(duration(3600), "1h");
        assert_eq!(duration(3600 + 5 * 60), "1h 5m");
        assert_eq!(duration(2 * 86_400 + 3 * 3600 + 59), "2d 3h");
    }

    fn status(
        fixture: &Fixture,
        agent: MockKeyAgent,
        environment: &[(&str, &str)],
    ) -> StatusCommand {
        StatusCommand {
            writer: Box::new(Writer::new()),
            cache: fixture.cache(),
            agent: Box::new(agent),
            environment: environment
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            now: 1_000,
        }
    }

    #[test]
    fn status_shows_variables_keys_and_exported_profiles() -> Result<()> {
        let fixture = Fixture::new().loaded("personal", "env:GITHUB_TOKEN\n");
        let key = fingerprint(&TEST_KEY)?;
        fixture.cache().record_keys(
            &[KeyRecord {
                profile: "personal".into(),
                name: "my-key".into(),
                fingerprint: key.clone(),
                public_key: public_key(&TEST_KEY)?,
                expires: 1_000 + 45 * 60,
            }],
            1_000,
        )?;
        let gcp = fixture.dir.path().join("gcp.json");
        std::fs::write(&gcp, "{}")?;
        let writer = Writer::new();
        let mut cmd = StatusCommand {
            writer: Box::new(writer.clone()),
            ..status(
                &fixture,
                agent(vec![key]),
                &[
                    ("GITHUB_TOKEN", "x"),
                    ("GCP_CREDENTIALS", &gcp.to_string_lossy()),
                ],
            )
        };

        cmd.execute(&StatusCommandArgs {
            parent: fixture.parent(),
            profile: None,
            shell: Some(Shell::Zsh),
        })?;

        let expected = format!(
            indoc! {"
                Shell integration: active (zsh)
                Config: {}

                Profile: personal (default)
                  Exported in new shells: yes
                  Variables in this shell:
                    GITHUB_TOKEN     set
                    GCP_CREDENTIALS  set (file)
                  SSH keys:
                    my-key           in agent, expires in 45m

                Profile: work
                  Exported in new shells: no
                  Variables in this shell:
                    API_KEY  not set
            "},
            fixture.parent().config.display()
        );
        assert_eq!(writer.contents(), expected);
        Ok(())
    }

    #[test]
    fn status_reports_missing_agent_and_inactive_integration() -> Result<()> {
        let fixture = Fixture::new();
        let mut agent = MockKeyAgent::new();
        agent
            .expect_fingerprints()
            .returning(|| Err(anyhow::anyhow!("SSH agent is not running")));
        let writer = Writer::new();
        let mut cmd = StatusCommand {
            writer: Box::new(writer.clone()),
            ..status(&fixture, agent, &[])
        };

        cmd.execute(&StatusCommandArgs {
            parent: fixture.parent(),
            profile: Some("personal".into()),
            shell: None,
        })?;

        let output = writer.contents();
        assert!(output.starts_with("Shell integration: not active"));
        assert!(output.contains("    my-key           SSH agent not running\n"));
        assert!(!output.contains("Profile: work"));
        Ok(())
    }

    fn unload(
        fixture: &Fixture,
        agent: MockKeyAgent,
        environment: &[(&str, &str)],
    ) -> UnloadCommand {
        UnloadCommand {
            writer: Box::new(Writer::new()),
            cache: fixture.cache(),
            agent: Box::new(agent),
            environment: environment
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn unload_args(fixture: &Fixture, names: &[&str]) -> UnloadCommandArgs {
        UnloadCommandArgs {
            parent: fixture.parent(),
            names: names.iter().map(|n| n.to_string()).collect(),
            profile: None,
            output: fixture.output(ExportFormat::Zsh),
        }
    }

    #[test]
    fn unload_unsets_variables_and_deletes_the_files_it_wrote() -> Result<()> {
        let fixture = Fixture::new().loaded("personal", "env:GITHUB_TOKEN\n");
        let file = RuntimeDir::new(Some(fixture.runtime_dir())).write(
            "personal",
            "GCP_CREDENTIALS",
            "{}",
        )?;
        let writer = Writer::new();
        let mut cmd = UnloadCommand {
            writer: Box::new(writer.clone()),
            ..unload(
                &fixture,
                agent(vec![]),
                &[
                    ("GITHUB_TOKEN", "x"),
                    ("GCP_CREDENTIALS", &file.to_string_lossy()),
                ],
            )
        };

        cmd.execute(&unload_args(&fixture, &[]))?;

        assert_eq!(
            writer.contents(),
            "unset GITHUB_TOKEN\nunset GCP_CREDENTIALS\n"
        );
        assert!(!file.exists());
        // The whole profile was unloaded, so new shells no longer get it
        assert_eq!(fixture.cache().loaded("personal")?, None);
        Ok(())
    }

    #[test]
    fn unload_leaves_files_it_did_not_write() -> Result<()> {
        let fixture = Fixture::new();
        let other = fixture.dir.path().join("credentials.json");
        std::fs::write(&other, "{}")?;
        let mut cmd = unload(
            &fixture,
            MockKeyAgent::new(),
            &[("GCP_CREDENTIALS", &other.to_string_lossy())],
        );

        cmd.execute(&unload_args(&fixture, &["GCP_CREDENTIALS"]))?;

        assert!(other.exists());
        Ok(())
    }

    #[test]
    fn unload_named_secrets_keeps_the_profile_exported() -> Result<()> {
        let fixture = Fixture::new().loaded("personal", "env:GITHUB_TOKEN\n");
        let writer = Writer::new();
        let mut cmd = UnloadCommand {
            writer: Box::new(writer.clone()),
            ..unload(&fixture, MockKeyAgent::new(), &[])
        };

        cmd.execute(&unload_args(&fixture, &["GITHUB_TOKEN"]))?;

        assert_eq!(writer.contents(), "unset GITHUB_TOKEN\n");
        assert!(fixture.cache().loaded("personal")?.is_some());
        Ok(())
    }

    #[test]
    fn unload_removes_the_keys_it_added() -> Result<()> {
        let fixture = Fixture::new();
        let key = fingerprint(&TEST_KEY)?;
        let public = public_key(&TEST_KEY)?;
        fixture.cache().record_keys(
            &[KeyRecord {
                profile: "personal".into(),
                name: "my-key".into(),
                fingerprint: key.clone(),
                public_key: public.clone(),
                expires: u64::MAX,
            }],
            0,
        )?;
        let mut agent = agent(vec![key]);
        agent
            .expect_remove()
            .withf(move |k| k == public)
            .times(1)
            .returning(|_| Ok(()));
        let mut cmd = unload(&fixture, agent, &[]);

        cmd.execute(&unload_args(&fixture, &["my-key"]))?;

        assert_eq!(fixture.cache().keys()?, vec![]);
        Ok(())
    }

    #[test]
    fn unload_rejects_json() {
        let fixture = Fixture::new();
        let mut cmd = unload(&fixture, MockKeyAgent::new(), &[]);

        let result = cmd.execute(&UnloadCommandArgs {
            output: fixture.output(ExportFormat::Json),
            ..unload_args(&fixture, &["GITHUB_TOKEN"])
        });

        assert_eq!(
            result.unwrap_err().to_string(),
            "unload prints shell statements; use --format zsh or --format bash"
        );
    }

    #[test]
    fn starter_config_is_valid() -> Result<()> {
        let config = Config::parse(STARTER_CONFIG)?;
        assert_eq!(config.default_profile().name, "personal");
        assert!(config.default_profile().secrets.is_empty());
        Ok(())
    }

    fn config_init_args(fixture: &Fixture, force: bool) -> ConfigInitCommandArgs {
        ConfigInitCommandArgs {
            parent: ProgramArgs {
                config: fixture.dir.path().join("new/keysafe/config.yml"),
                ..fixture.parent()
            },
            force,
        }
    }

    #[test]
    fn config_init_writes_the_starter_config() -> Result<()> {
        let fixture = Fixture::new();
        let args = config_init_args(&fixture, false);

        ConfigInitCommand.execute(&args)?;

        assert_eq!(
            std::fs::read_to_string(&args.parent.config)?,
            STARTER_CONFIG
        );
        Ok(())
    }

    #[test]
    fn config_init_replaces_a_config_only_with_force() -> Result<()> {
        let fixture = Fixture::new();
        let args = config_init_args(&fixture, false);
        ConfigInitCommand.execute(&args)?;
        std::fs::write(&args.parent.config, "mine")?;

        let err = ConfigInitCommand.execute(&args).unwrap_err().to_string();
        assert!(
            err.ends_with(
                "already exists (edit it with `keysafe config edit`, or replace it with --force)"
            ),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(&args.parent.config)?, "mine");

        ConfigInitCommand.execute(&config_init_args(&fixture, true))?;
        assert_eq!(
            std::fs::read_to_string(&args.parent.config)?,
            STARTER_CONFIG
        );
        Ok(())
    }

    #[test]
    fn config_edit_runs_the_editor_and_checks_the_config() -> Result<()> {
        let fixture = Fixture::new();
        let args = ConfigEditCommandArgs {
            parent: fixture.parent(),
        };

        // An editor with arguments, which leaves a valid config
        let marker = fixture.dir.path().join("edited");
        let mut cmd = ConfigEditCommand {
            editor: format!("touch '{}' &&  test -f", marker.display()),
        };
        cmd.execute(&args)?;
        assert!(marker.exists());

        // An editor that breaks the config
        let mut cmd = ConfigEditCommand {
            editor: "printf 'version: 2\\n' >".into(),
        };
        let err = cmd.execute(&args).unwrap_err();
        assert_eq!(
            err.to_string(),
            "the config is not valid; fix it with `keysafe config edit`"
        );
        assert!(format!("{err:#}").contains("unsupported config version: 2"));
        Ok(())
    }

    #[test]
    fn config_edit_fails_without_a_config() {
        let fixture = Fixture::new();
        let mut cmd = ConfigEditCommand {
            editor: "true".into(),
        };

        let err = cmd
            .execute(&ConfigEditCommandArgs {
                parent: ProgramArgs {
                    config: fixture.dir.path().join("missing.yml"),
                    ..fixture.parent()
                },
            })
            .unwrap_err();

        assert!(err
            .to_string()
            .ends_with("(create one with `keysafe config init`)"));
    }

    #[test]
    fn config_source_says_where_the_path_comes_from() {
        let custom = Path::new("/etc/keysafe.yml");
        assert_eq!(
            config_source(custom, Some(custom)),
            "set by KEYSAFE_CONFIG_FILE"
        );
        assert_eq!(config_source(custom, None), "set by --config");
        assert_eq!(
            config_source(&default_config(), None),
            "the default location"
        );
        assert!(config_source(&legacy_config(), None).starts_with("zsh-op's location"));
    }

    fn doctor(
        fixture: &Fixture,
        client: MockSecretClient,
        agent: MockKeyAgent,
    ) -> (DoctorCommand, Writer) {
        let writer = Writer::new();
        let cmd = DoctorCommand {
            writer: Box::new(writer.clone()),
            client: Box::new(client),
            cache: fixture.cache(),
            agent: Box::new(agent),
            env: None,
        };
        (cmd, writer)
    }

    #[test]
    fn doctor_reports_a_working_setup() -> Result<()> {
        let fixture = Fixture::new();
        let mut client = MockSecretClient::new();
        client
            .expect_check()
            .times(2)
            .returning(|provider| Ok(format!("checked {provider:?}")));
        let (mut cmd, writer) = doctor(&fixture, client, agent(vec!["SHA256:a".into()]));

        cmd.execute(&DoctorCommandArgs {
            parent: fixture.parent(),
            shell: Some(Shell::Zsh),
        })?;

        let config = fixture.parent().config;
        let expected = format!(
            indoc! {"
                ✓ Config: {} (set by --config), 2 profile(s)
                ✓ 1password (personal): checked OnePassword {{ account: Some(\"my.1password.com\") }}
                ✓ 1password (work): checked OnePassword {{ account: Some(\"team.1password.com\") }}
                ✓ Keychain: reachable
                ✓ SSH agent: running, 1 key(s)
                ✓ Shell integration: active (zsh)
            "},
            config.display()
        );
        assert_eq!(writer.contents(), expected);
        Ok(())
    }

    #[test]
    fn doctor_counts_failures_but_not_warnings() {
        let fixture = Fixture::new();
        let mut client = MockSecretClient::new();
        client.expect_check().returning(|provider| match provider {
            Provider::OnePassword { account }
                if account.as_deref() == Some("team.1password.com") =>
            {
                Err(anyhow::anyhow!(
                    "op does not know account team.1password.com (run: op account add)"
                ))
            }
            _ => Ok("fine".into()),
        });
        let mut agent = MockKeyAgent::new();
        agent
            .expect_fingerprints()
            .returning(|| Err(anyhow::anyhow!("SSH agent is not running")));
        let (mut cmd, writer) = doctor(&fixture, client, agent);

        let result = cmd.execute(&DoctorCommandArgs {
            parent: fixture.parent(),
            shell: None,
        });

        assert_eq!(result.unwrap_err().to_string(), "found 2 problem(s)");
        let output = writer.contents();
        assert!(output.contains("✗ 1password (work): op does not know account team.1password.com (run: op account add)\n"));
        assert!(output.contains("✗ SSH agent: SSH agent is not running\n"));
        assert!(output.contains("! Shell integration: not active in this shell"));
    }

    #[test]
    fn doctor_checks_the_rest_without_a_config() {
        let fixture = Fixture::new();
        let mut client = MockSecretClient::new();
        client.expect_check().never();
        let mut agent = MockKeyAgent::new();
        agent.expect_fingerprints().never();
        let (mut cmd, writer) = doctor(&fixture, client, agent);

        let result = cmd.execute(&DoctorCommandArgs {
            parent: ProgramArgs {
                config: fixture.dir.path().join("missing.yml"),
                ..fixture.parent()
            },
            shell: Some(Shell::Bash),
        });

        assert_eq!(result.unwrap_err().to_string(), "found 1 problem(s)");
        let output = writer.contents();
        assert!(output.starts_with("✗ Config: config file not found: "));
        assert!(output.contains("✓ Keychain: reachable\n"));
        assert!(output.ends_with("✓ Shell integration: active (bash)\n"));
    }

    #[test]
    fn doctor_skips_the_agent_without_ssh_keys() -> Result<()> {
        let fixture = Fixture::new();
        std::fs::write(
            fixture.parent().config,
            "version: 1\nprofiles:\n  - name: p\n    provider:\n      type: 1password\n",
        )?;
        let mut client = MockSecretClient::new();
        client.expect_check().returning(|_| Ok("fine".into()));
        let mut agent = MockKeyAgent::new();
        agent.expect_fingerprints().never();
        let (mut cmd, writer) = doctor(&fixture, client, agent);

        cmd.execute(&DoctorCommandArgs {
            parent: fixture.parent(),
            shell: Some(Shell::Zsh),
        })?;

        assert!(!writer.contents().contains("SSH agent"));
        Ok(())
    }

    /// Output settings for a terminal without the shell integration.
    fn terminal_output() -> OutputArgs {
        OutputArgs {
            terminal: true,
            ..Default::default()
        }
    }

    #[test]
    fn load_on_a_terminal_adds_keys_but_never_prints_secrets() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "brown-fox")
            .cached("personal", "my-key", &TEST_KEY);
        let mut agent = agent(vec![]);
        agent.expect_add().times(1).returning(|_, _| Ok(()));
        let writer = Writer::new();
        let mut cmd = LoadCommand {
            writer: Box::new(writer.clone()),
            loader: fixture.loader(offline()),
            agent: Box::new(agent),
        };

        let result = cmd.execute(&LoadCommandArgs {
            output: terminal_output(),
            ..load_args(&fixture, &["GITHUB_TOKEN", "my-key"], false)
        });

        let err = result.unwrap_err().to_string();
        assert!(
            err.starts_with(
                "1 variable not set: the shell integration isn't active here; add `eval"
            ),
            "{err}"
        );
        assert_eq!(writer.contents(), "");
        // Only the SSH key was read; the variable wasn't even fetched
        assert_eq!(cmd.loader.counts(), (1, 0));
        Ok(())
    }

    #[test]
    fn load_on_a_terminal_works_for_ssh_keys_alone() -> Result<()> {
        let fixture = Fixture::new().cached("personal", "my-key", &TEST_KEY);
        let mut agent = agent(vec![]);
        agent.expect_add().times(1).returning(|_, _| Ok(()));
        let mut cmd = LoadCommand {
            writer: Box::new(Writer::new()),
            loader: fixture.loader(offline()),
            agent: Box::new(agent),
        };

        cmd.execute(&LoadCommandArgs {
            output: terminal_output(),
            ..load_args(&fixture, &["my-key"], false)
        })
    }

    #[test]
    fn unload_on_a_terminal_removes_keys_but_keeps_variables() -> Result<()> {
        let fixture = Fixture::new().loaded("personal", "env:GITHUB_TOKEN\n");
        let file = RuntimeDir::new(Some(fixture.runtime_dir())).write(
            "personal",
            "GCP_CREDENTIALS",
            "{}",
        )?;
        let key = fingerprint(&TEST_KEY)?;
        fixture.cache().record_keys(
            &[KeyRecord {
                profile: "personal".into(),
                name: "my-key".into(),
                fingerprint: key.clone(),
                public_key: public_key(&TEST_KEY)?,
                expires: u64::MAX,
            }],
            0,
        )?;
        let mut agent = agent(vec![key]);
        agent.expect_remove().times(1).returning(|_| Ok(()));
        let writer = Writer::new();
        let mut cmd = UnloadCommand {
            writer: Box::new(writer.clone()),
            ..unload(
                &fixture,
                agent,
                &[("GCP_CREDENTIALS", &file.to_string_lossy())],
            )
        };

        let result = cmd.execute(&UnloadCommandArgs {
            output: terminal_output(),
            ..unload_args(&fixture, &[])
        });

        assert!(result
            .unwrap_err()
            .to_string()
            .starts_with("2 variables not unset: the shell integration isn't active here"));
        assert_eq!(writer.contents(), "");
        assert!(file.exists());
        assert!(fixture.cache().loaded("personal")?.is_some());
        assert_eq!(fixture.cache().keys()?, vec![]);
        Ok(())
    }

    #[test]
    fn profile_clear_deletes_cached_secrets() -> Result<()> {
        let fixture = Fixture::new()
            .cached("personal", "GITHUB_TOKEN", "a")
            .cached("work", "API_KEY", "b")
            .loaded("personal", "env:GITHUB_TOKEN\n");
        let mut cmd = ProfileClearCommand {
            cache: fixture.cache(),
        };

        cmd.execute(&ProfileClearCommandArgs {
            parent: fixture.parent(),
            profile: "personal".into(),
        })?;

        assert_eq!(fixture.value("personal", "GITHUB_TOKEN"), None);
        assert_eq!(fixture.value("work", "API_KEY").as_deref(), Some("b"));
        assert_eq!(fixture.cache().loaded("personal")?, None);
        Ok(())
    }
}

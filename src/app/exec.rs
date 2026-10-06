use crate::app::args::*;
use crate::log::{info, warn};
use crate::vault::*;
use anyhow::{bail, Context, Result};
use clap::{builder::PossibleValuesParser, CommandFactory};
use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::path::PathBuf;
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
        let account = config.profile(&args.profile)?;
        let secrets: Vec<&Secret> = if args.names.is_empty() {
            account.secrets.iter().collect()
        } else {
            args.names
                .iter()
                .map(|name| account.secret(name))
                .collect::<Result<_>>()?
        };
        let runtime = RuntimeDir::new(args.output.runtime_dir.clone());

        // Export the environment and file secrets
        let variables = secrets.iter().copied().filter(|s| s.is_variable());
        let (variables, mut failed) =
            self.loader
                .resolve(&runtime, account, variables, Source::Any(args.refresh));
        let format = args.output.export_format();
        write_runtime_dir(&mut self.writer, format, &runtime, args.output.is_eval())?;
        write_variables(&mut self.writer, format, &variables)?;
        if !variables.is_empty() {
            info(format!(
                "loaded {} environment and file secret(s)",
                variables.len()
            ));
        }

        // Add the SSH keys to the agent
        let keys: Vec<&Secret> = secrets
            .iter()
            .copied()
            .filter(|s| s.kind == SecretKind::Ssh)
            .collect();
        failed += self.add_keys(account, &keys, args);

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
                Ok(true) => added += 1,
                Ok(false) => kept += 1,
                Err(err) => {
                    warn(format!("failed to load SSH key '{}': {err:#}", key.name));
                    failed += 1;
                }
            }
        }

        if added > 0 {
            info(format!(
                "added {added} SSH key(s) with {} expiration",
                args.expiration
            ));
        }
        if kept > 0 {
            info(format!(
                "{kept} SSH key(s) already in the agent (use --refresh to reset their expiration)"
            ));
        }
        failed
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
        let account = config.profile(&args.profile)?;
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
            vec![config.profile(&args.profile)?]
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
        let account = config.profile(&args.profile)?;

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
            writeln!(self.writer, "Profile: {}", account.name)?;
            match &account.provider {
                Provider::OnePassword {
                    account: Some(name),
                } => writeln!(self.writer, "  Provider: {} ({name})", account.provider)?,
                provider => writeln!(self.writer, "  Provider: {provider}")?,
            }
            writeln!(
                self.writer,
                "  Loaded: {}",
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

        let count = self.cache.clear(account)?;
        info(format!(
            "cleared {count} cached secret(s) for profile '{}'",
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
            }
        }

        fn output(&self, format: ExportFormat) -> OutputArgs {
            OutputArgs {
                format: Some(format),
                runtime_dir: Some(self.runtime_dir()),
                eval: None,
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
            Loader {
                client: Box::new(client),
                cache: self.cache(),
            }
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
            profile: "personal".into(),
            expiration: "1h".into(),
            refresh,
            output: fixture.output(ExportFormat::Zsh),
        }
    }

    fn read_args(fixture: &Fixture, name: &str) -> ReadCommandArgs {
        ReadCommandArgs {
            parent: fixture.parent(),
            name: name.into(),
            profile: "personal".into(),
            refresh: false,
        }
    }

    fn export_args(fixture: &Fixture, all: bool, cached: bool) -> ExportCommandArgs {
        ExportCommandArgs {
            parent: fixture.parent(),
            profile: "personal".into(),
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
            Profile: personal
              Provider: 1password (my.1password.com)
              Loaded: yes
              Secrets:
                env  GITHUB_TOKEN (op://Personal/GitHub/token)
                file GCP_CREDENTIALS (op://Personal/GCP/credentials)
                ssh  my-key (op://Private/SSH/private key?ssh-format=openssh)

            Profile: work
              Provider: 1password (team.1password.com)
              Loaded: no
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
            profile: "work".into(),
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
            profile: "personal".into(),
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
            profile: "personal".into(),
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
            profile: "personal".into(),
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

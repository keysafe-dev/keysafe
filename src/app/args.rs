use clap::{Args, Parser, Subcommand, ValueEnum};
use core::fmt::Display;
use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Program is the main entry point for the secret-env CLI.
#[derive(Debug, Parser)]
#[command(
    name = "secret-env",
    about = "1Password secrets for your shell.",
    long_about = "Fetch secrets from 1Password, cache them in the system keychain, export them into your shell, and add SSH keys to ssh-agent.",
    version
)]
pub struct Program {
    /// Command specifies the subcommand to execute.
    #[command(subcommand)]
    pub command: ProgramCommand,
}

/// ProgramArgs holds the shared global flags available to every subcommand.
#[derive(Debug, Args)]
pub struct ProgramArgs {
    /// Path to the secret-env configuration file.
    #[arg(
        help = "Config file path.",
        env = "SECRET_ENV_CONFIG_FILE",
        default_value_os_t = default_config(),
        long,
        short
    )]
    pub config: PathBuf,

    /// Path to the directory recording which profiles were loaded.
    #[arg(
        help = "State directory path.",
        env = "SECRET_ENV_STATE_DIR",
        default_value_os_t = default_state_dir(),
        long
    )]
    pub state_dir: PathBuf,
}

impl Default for ProgramArgs {
    fn default() -> Self {
        Self {
            config: default_config(),
            state_dir: default_state_dir(),
        }
    }
}

impl ProgramArgs {
    /// Falls back to the config file used before secret-env had its own name (and by zsh-op)
    /// when the default one does not exist yet. Returns the config file that is now used, if
    /// it changed.
    pub fn use_legacy_config(&mut self) -> Option<&Path> {
        let legacy = legacy_config();
        if self.config != default_config() || self.config.exists() || !legacy.exists() {
            return None;
        }

        self.config = legacy;
        Some(&self.config)
    }

    /// Returns the state directory used before secret-env had its own name, which is still
    /// read when the default state directory is in use.
    pub fn legacy_state_dir(&self) -> Option<PathBuf> {
        (self.state_dir == default_state_dir()).then(|| home_dir().join(".cache/op"))
    }
}

/// Returns the home directory of the current user.
fn home_dir() -> PathBuf {
    env::var_os("HOME").map(PathBuf::from).unwrap_or_default()
}

/// Returns the XDG base directory in `$var`, or `$HOME/<fallback>` when it is not set to an
/// absolute path.
fn xdg_dir(var: &str, fallback: &str) -> PathBuf {
    env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home_dir().join(fallback))
}

/// Returns the default config file: `$XDG_CONFIG_HOME/secret-env/config.yml`.
pub fn default_config() -> PathBuf {
    xdg_dir("XDG_CONFIG_HOME", ".config").join("secret-env/config.yml")
}

/// Returns the default state directory: `$XDG_STATE_HOME/secret-env`.
pub fn default_state_dir() -> PathBuf {
    xdg_dir("XDG_STATE_HOME", ".local/state").join("secret-env")
}

/// Returns the config file used before secret-env had its own name.
fn legacy_config() -> PathBuf {
    home_dir().join(".config/op/config.yml")
}

/// Top-level subcommand dispatched by [`Program`].
#[derive(Debug, Subcommand)]
pub enum ProgramCommand {
    /// Load secrets of a profile into the current shell.
    #[command(
        name = "load",
        about = "Load secrets of a profile into the current shell.",
        long_about = "Export environment secrets, write file secrets and export their paths, and add SSH keys to ssh-agent. Without names, every secret of the profile is loaded and the profile is recorded, so its cached secrets are exported in new shells. Needs the shell integration (`secret-env init`); otherwise, evaluate the printed statements yourself.",
        next_display_order = 1
    )]
    Load(LoadCommandArgs),

    /// Print the value of a secret.
    #[command(
        name = "read",
        about = "Print the value of a secret.",
        long_about = "Print the value of an environment or file secret, from the keychain cache or 1Password. SSH keys are not printed; use `load` to add them to ssh-agent.",
        next_display_order = 2
    )]
    Read(ReadCommandArgs),

    /// Export the environment and file secrets of a profile as shell statements.
    #[command(
        name = "export",
        about = "Export the environment and file secrets of a profile as shell statements.",
        long_about = "Emit shell-ready export statements (or JSON) for the environment and file secrets of a profile. With --cached, only secrets of previously loaded profiles are read from the keychain and 1Password is never contacted.",
        next_display_order = 3
    )]
    Export(ExportCommandArgs),

    /// Execute a command with the secrets of a profile in its environment.
    #[command(
        name = "exec",
        about = "Execute a command with the secrets of a profile in its environment.",
        long_about = "Resolve the environment and file secrets of a profile, then run the given command with them in its environment. File secrets are removed once the command exits.",
        next_display_order = 4
    )]
    Exec(ExecCommandArgs),

    /// List, show and clear profiles.
    #[command(
        name = "profile",
        about = "List, show and clear profiles.",
        next_display_order = 5
    )]
    Profile(ProfileCommandArgs),

    /// Print the shell integration script for zsh or bash.
    #[command(
        name = "init",
        about = "Print the shell integration script for zsh or bash.",
        long_about = "Print a script that defines the `secret-env` shell function, which applies `load` and `export` to the current shell, along with completions. It also exports the cached secrets of loaded profiles. Add `eval \"$(secret-env init zsh)\"` to ~/.zshrc, or `eval \"$(secret-env init bash)\"` to ~/.bashrc.",
        next_display_order = 6
    )]
    Init(InitCommandArgs),
}

impl ProgramCommand {
    /// Returns the shared global flags of the subcommand.
    pub fn parent_mut(&mut self) -> &mut ProgramArgs {
        match self {
            Self::Load(args) => &mut args.parent,
            Self::Read(args) => &mut args.parent,
            Self::Export(args) => &mut args.parent,
            Self::Exec(args) => &mut args.parent,
            Self::Profile(args) => match &mut args.command {
                ProfileCommand::List(args) => &mut args.parent,
                ProfileCommand::Show(args) => &mut args.parent,
                ProfileCommand::Clear(args) => &mut args.parent,
            },
            Self::Init(args) => &mut args.parent,
        }
    }
}

/// Subcommand of `profile`.
#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List the profile names, one per line.
    #[command(
        name = "list",
        about = "List the profile names, one per line.",
        next_display_order = 1
    )]
    List(ProfileListCommandArgs),

    /// Show profiles, their secrets and whether they were loaded.
    #[command(
        name = "show",
        about = "Show profiles, their secrets and whether they were loaded.",
        long_about = "Print a profile, or every profile, with its 1Password account, its secrets and whether it has been loaded into the keychain cache. Secret values are never printed.",
        next_display_order = 2
    )]
    Show(ProfileShowCommandArgs),

    /// Clear the cached secrets of a profile.
    #[command(
        name = "clear",
        about = "Clear the cached secrets of a profile.",
        long_about = "Delete every cached secret of a profile from the keychain and forget that the profile was loaded.",
        next_display_order = 3
    )]
    Clear(ProfileClearCommandArgs),
}

/// Shell specifies a shell supported by the shell integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    /// Zsh.
    Zsh,

    /// Bash.
    Bash,
}

impl From<Shell> for ExportFormat {
    fn from(shell: Shell) -> Self {
        match shell {
            Shell::Zsh => ExportFormat::Zsh,
            Shell::Bash => ExportFormat::Bash,
        }
    }
}

/// ExportFormat specifies the output format for exported secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum ExportFormat {
    /// Zsh format.
    #[default]
    Zsh,

    /// Bash format.
    Bash,

    /// Json format.
    Json,
}

impl FromStr for ExportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "zsh" => Ok(Self::Zsh),
            "bash" => Ok(Self::Bash),
            "json" => Ok(Self::Json),
            _ => Err(format!("unknown export format: {}", s)),
        }
    }
}

impl Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zsh => write!(f, "zsh"),
            Self::Bash => write!(f, "bash"),
            Self::Json => write!(f, "json"),
        }
    }
}

/// OutputArgs holds the flags shared by subcommands that emit secrets.
#[derive(Debug, Default, Args)]
pub struct OutputArgs {
    /// Output format for the exported secrets.
    /// Auto-detected from $SHELL if not provided.
    #[arg(
        help = "Output format (auto-detected from $SHELL if not provided).",
        long,
        short
    )]
    pub format: Option<ExportFormat>,

    /// Directory where file secrets are written.
    /// A new private temporary directory is created if not provided.
    #[arg(
        help = "Directory for file secrets (a new temporary one if not provided).",
        env = "SECRET_ENV_RUNTIME_DIR",
        long
    )]
    pub runtime_dir: Option<PathBuf>,

    /// Shell whose integration function runs this command and evaluates its statements.
    /// Set by the script that `init` prints; not meant to be set by hand.
    #[arg(long, env = "SECRET_ENV_EVAL", hide = true)]
    pub eval: Option<Shell>,
}

impl OutputArgs {
    /// Returns true when the shell integration evaluates the statements, i.e. it runs this
    /// command and no format was requested explicitly.
    pub fn is_eval(&self) -> bool {
        self.eval.is_some() && self.format.is_none()
    }

    /// Get the export format: the explicit one, the integration's shell, or $SHELL detection.
    pub fn export_format(&self) -> ExportFormat {
        self.format
            .or(self.eval.map(ExportFormat::from))
            .unwrap_or_else(|| {
                let shell_path = env::var("SHELL").unwrap_or_default();
                let shell_name = Path::new(&shell_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("zsh");

                <ExportFormat as FromStr>::from_str(shell_name).unwrap_or(ExportFormat::Zsh)
            })
    }
}

/// LoadCommandArgs defines the arguments for the LoadCommand.
#[derive(Debug, Args)]
pub struct LoadCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Names of the secrets to load. Every secret of the profile is loaded if not provided.
    #[arg(help = "Secret names (the whole profile if not provided).")]
    pub names: Vec<String>,

    /// Profile the secrets belong to.
    #[arg(
        help = "Profile name.",
        env = "SECRET_ENV_DEFAULT_PROFILE",
        default_value = "personal",
        long,
        short
    )]
    pub profile: String,

    /// Lifetime of the SSH keys added to ssh-agent.
    #[arg(
        help = "SSH key expiration time (e.g. 30m, 1h, 8h).",
        default_value = "1h",
        long,
        short
    )]
    pub expiration: String,

    /// Bypass the keychain cache and fetch the secrets from 1Password.
    #[arg(help = "Force refresh from 1Password.", long, short)]
    pub refresh: bool,

    /// Output flags.
    #[command(flatten)]
    pub output: OutputArgs,
}

/// ReadCommandArgs defines the arguments for the ReadCommand.
#[derive(Debug, Args)]
pub struct ReadCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Name of the secret to print.
    #[arg(help = "Secret name.")]
    pub name: String,

    /// Profile the secret belongs to.
    #[arg(
        help = "Profile name.",
        env = "SECRET_ENV_DEFAULT_PROFILE",
        default_value = "personal",
        long,
        short
    )]
    pub profile: String,

    /// Bypass the keychain cache and fetch the secret from 1Password.
    #[arg(help = "Force refresh from 1Password.", long, short)]
    pub refresh: bool,
}

/// ProfileCommandArgs defines the arguments for the profile subcommands.
#[derive(Debug, Args)]
pub struct ProfileCommandArgs {
    /// Command specifies the profile subcommand to execute.
    #[command(subcommand)]
    pub command: ProfileCommand,
}

/// ProfileListCommandArgs defines the arguments for the ProfileListCommand.
#[derive(Debug, Args)]
pub struct ProfileListCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,
}

/// ProfileShowCommandArgs defines the arguments for the ProfileShowCommand.
#[derive(Debug, Args)]
pub struct ProfileShowCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile to show. Every profile is shown if not provided.
    #[arg(help = "Profile name (all profiles if not provided).")]
    pub profile: Option<String>,
}

/// ProfileClearCommandArgs defines the arguments for the ProfileClearCommand.
#[derive(Debug, Args)]
pub struct ProfileClearCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile whose cached secrets are deleted.
    #[arg(help = "Profile name.")]
    pub profile: String,
}

/// ExportCommandArgs defines the arguments for the ExportCommand.
#[derive(Debug, Args)]
pub struct ExportCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile to export.
    #[arg(
        help = "Profile name.",
        env = "SECRET_ENV_DEFAULT_PROFILE",
        default_value = "personal",
        long,
        short
    )]
    pub profile: String,

    /// Export every profile instead of a single one.
    #[arg(help = "Export every profile.", long, short)]
    pub all: bool,

    /// Read previously loaded secrets from the keychain only, never contacting 1Password.
    #[arg(
        help = "Only export cached secrets of loaded profiles.",
        long,
        conflicts_with = "refresh"
    )]
    pub cached: bool,

    /// Bypass the keychain cache and fetch every secret from 1Password.
    #[arg(help = "Force refresh from 1Password.", long, short)]
    pub refresh: bool,

    /// Output flags.
    #[command(flatten)]
    pub output: OutputArgs,
}

/// ExecCommandArgs defines the arguments for the ExecCommand.
#[derive(Debug, Args)]
pub struct ExecCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile whose secrets are applied.
    #[arg(
        help = "Profile name.",
        env = "SECRET_ENV_DEFAULT_PROFILE",
        default_value = "personal",
        long,
        short
    )]
    pub profile: String,

    /// Bypass the keychain cache and fetch every secret from 1Password.
    #[arg(help = "Force refresh from 1Password.", long, short)]
    pub refresh: bool,

    /// Command and arguments to execute.
    #[arg(
        help = "Command and arguments to execute.",
        required = true,
        trailing_var_arg = true
    )]
    pub command: Vec<String>,
}

/// InitCommandArgs defines the arguments for the InitCommand.
#[derive(Debug, Args)]
pub struct InitCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Shell to print the integration script for.
    #[arg(help = "Shell to integrate with.")]
    pub shell: Shell,

    /// Do not export the cached secrets of loaded profiles.
    #[arg(help = "Do not export cached secrets of loaded profiles.", long)]
    pub no_export: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn program_definition_is_valid() {
        Program::command().debug_assert();
    }

    #[test]
    fn export_format_displays_as_lowercase_name() {
        assert_eq!(ExportFormat::Zsh.to_string(), "zsh");
        assert_eq!(ExportFormat::Bash.to_string(), "bash");
        assert_eq!(ExportFormat::Json.to_string(), "json");
    }

    #[test]
    fn export_format_parses_case_insensitively() {
        assert_eq!(
            <ExportFormat as FromStr>::from_str("ZSH"),
            Ok(ExportFormat::Zsh)
        );
        assert!(<ExportFormat as FromStr>::from_str("fish").is_err());
    }

    #[test]
    fn export_format_prefers_explicit_format() {
        let args = OutputArgs {
            format: Some(ExportFormat::Json),
            eval: Some(Shell::Bash),
            ..Default::default()
        };
        assert_eq!(args.export_format(), ExportFormat::Json);
        assert!(!args.is_eval());
    }

    #[test]
    fn export_format_follows_shell_integration() {
        let args = OutputArgs {
            eval: Some(Shell::Bash),
            ..Default::default()
        };
        assert_eq!(args.export_format(), ExportFormat::Bash);
        assert!(args.is_eval());
    }

    #[test]
    fn init_parses_shell() {
        let program =
            Program::try_parse_from(["secret-env", "init", "bash", "--no-export"]).unwrap();
        let ProgramCommand::Init(args) = program.command else {
            panic!("expected the init command");
        };
        assert_eq!(args.shell, Shell::Bash);
        assert!(args.no_export);
        assert!(Program::try_parse_from(["secret-env", "init", "fish"]).is_err());
    }

    #[test]
    fn export_rejects_cached_with_refresh() {
        let result = Program::try_parse_from(["secret-env", "export", "--cached", "--refresh"]);
        assert!(result.is_err());
    }

    #[test]
    fn load_parses_names_and_flags() {
        let program = Program::try_parse_from([
            "secret-env",
            "load",
            "-p",
            "work",
            "-e",
            "8h",
            "API_KEY",
            "deploy-key",
        ])
        .unwrap();
        let ProgramCommand::Load(args) = program.command else {
            panic!("expected the load command");
        };
        assert_eq!(args.names, ["API_KEY", "deploy-key"]);
        assert_eq!(args.profile, "work");
        assert_eq!(args.expiration, "8h");
    }

    #[test]
    fn load_without_names_loads_the_profile() {
        let program = Program::try_parse_from(["secret-env", "load", "-p", "work"]).unwrap();
        let ProgramCommand::Load(args) = program.command else {
            panic!("expected the load command");
        };
        assert!(args.names.is_empty());
    }

    #[test]
    fn profile_subcommands_take_the_profile_as_argument() {
        let mut program = Program::try_parse_from([
            "secret-env",
            "profile",
            "clear",
            "work",
            "--state-dir",
            "/s",
        ])
        .unwrap();
        assert_eq!(program.command.parent_mut().state_dir, Path::new("/s"));
        let ProgramCommand::Profile(ProfileCommandArgs {
            command: ProfileCommand::Clear(args),
        }) = program.command
        else {
            panic!("expected the profile clear command");
        };
        assert_eq!(args.profile, "work");

        // Clearing needs an explicit profile
        assert!(Program::try_parse_from(["secret-env", "profile", "clear"]).is_err());
    }

    #[test]
    fn legacy_state_dir_is_read_only_with_the_default_state_dir() {
        let args = ProgramArgs::default();
        assert_eq!(args.legacy_state_dir(), Some(home_dir().join(".cache/op")));

        let args = ProgramArgs {
            state_dir: PathBuf::from("/custom"),
            ..Default::default()
        };
        assert_eq!(args.legacy_state_dir(), None);
    }
}

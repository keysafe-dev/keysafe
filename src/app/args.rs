use clap::{Args, Parser, Subcommand, ValueEnum};
use core::fmt::Display;
use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Examples shown at the end of each command's help.
const PROGRAM_HELP: &str = "Get started:
  keysafe config init         # create a starter config
  keysafe config edit         # add your secrets
  eval \"$(keysafe init zsh)\"  # in ~/.zshrc (or `init bash` in ~/.bashrc)
  keysafe load                # load the default profile

If something doesn't work, run `keysafe doctor`.";
const LOAD_EXAMPLES: &str = "Examples:
  keysafe load                # every secret of the default profile
  keysafe load -p work -e 8h  # the work profile, SSH keys for 8 hours
  keysafe load GITHUB_TOKEN   # one secret
  keysafe load -r -p work     # fetch again from 1Password";
const UNLOAD_EXAMPLES: &str = "Examples:
  keysafe unload               # the whole default profile
  keysafe unload -p work       # the work profile
  keysafe unload GITHUB_TOKEN  # one secret";
const READ_EXAMPLES: &str = "Examples:
  keysafe read GITHUB_TOKEN              # print a value
  keysafe read -p work API_KEY | pbcopy  # copy it to the clipboard";
const EXPORT_EXAMPLES: &str = "Examples:
  eval \"$(keysafe export -p work)\"      # without the shell integration
  keysafe export -p work --format json  # as a JSON object
  keysafe export --all --cached         # what new shells get";
const EXEC_EXAMPLES: &str = "Examples:
  keysafe exec -- terraform plan          # with the default profile
  keysafe exec -p work -- npm run deploy  # with the work profile";
const STATUS_EXAMPLES: &str = "Examples:
  keysafe status          # every profile
  keysafe status -p work  # one profile";
const DOCTOR_EXAMPLES: &str = "Examples:
  keysafe doctor  # check everything";
const LIST_EXAMPLES: &str = "Examples:
  keysafe profile list  # one name per line";
const SHOW_EXAMPLES: &str = "Examples:
  keysafe profile show       # every profile
  keysafe profile show work  # one profile";
const CLEAR_EXAMPLES: &str = "Examples:
  keysafe profile clear work  # delete its cached secrets";
const PRUNE_EXAMPLES: &str = "Examples:
  keysafe profile prune work  # delete what the config no longer names
  keysafe profile prune old   # everything of a profile removed from the config";
const INIT_CONFIG_EXAMPLES: &str = "Examples:
  keysafe config init          # create ~/.config/keysafe/config.yml
  keysafe config init --force  # start over";
const EDIT_EXAMPLES: &str = "Examples:
  keysafe config edit                       # in $VISUAL or $EDITOR
  EDITOR=\"code --wait\" keysafe config edit  # in VS Code";
const PATH_EXAMPLES: &str = "Examples:
  keysafe config path           # print the path
  cat \"$(keysafe config path)\"  # use it in a script";
const INIT_SHELL_EXAMPLES: &str = "Examples:
  eval \"$(keysafe init zsh)\"              # add to ~/.zshrc
  eval \"$(keysafe init bash)\"             # add to ~/.bashrc
  eval \"$(keysafe init zsh --no-export)\"  # without exporting cached secrets";

/// Program is the main entry point for the keysafe CLI.
#[derive(Debug, Parser)]
#[command(
    name = "keysafe",
    about = "1Password secrets for your shell.",
    long_about = "Fetch secrets from 1Password, cache them in the system keychain, export them into your shell, and add SSH keys to ssh-agent.",
    after_help = PROGRAM_HELP,
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
    /// Path to the keysafe configuration file.
    #[arg(
        help = "Config file path.",
        env = "KEYSAFE_CONFIG_FILE",
        default_value_os_t = default_config(),
        long,
        short
    )]
    pub config: PathBuf,

    /// Path to the directory recording which profiles were loaded.
    #[arg(
        help = "State directory path.",
        env = "KEYSAFE_STATE_DIR",
        default_value_os_t = default_state_dir(),
        long
    )]
    pub state_dir: PathBuf,

    /// Print warnings and errors only.
    #[arg(
        help = "Print warnings and errors only.",
        long,
        short,
        conflicts_with = "verbose"
    )]
    pub quiet: bool,

    /// Print details for debugging.
    #[arg(
        help = "Print details for debugging (never secret values).",
        long,
        short
    )]
    pub verbose: bool,
}

impl Default for ProgramArgs {
    fn default() -> Self {
        Self {
            config: default_config(),
            state_dir: default_state_dir(),
            quiet: false,
            verbose: false,
        }
    }
}

impl ProgramArgs {
    /// Falls back to the config file used before keysafe had its own name (and by zsh-op)
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

    /// Returns the state directory used before keysafe had its own name, which is still
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

/// Returns the default config file: `$XDG_CONFIG_HOME/keysafe/config.yml`.
pub fn default_config() -> PathBuf {
    xdg_dir("XDG_CONFIG_HOME", ".config").join("keysafe/config.yml")
}

/// Returns the default state directory: `$XDG_STATE_HOME/keysafe`.
pub fn default_state_dir() -> PathBuf {
    xdg_dir("XDG_STATE_HOME", ".local/state").join("keysafe")
}

/// Returns the config file used before keysafe had its own name.
pub fn legacy_config() -> PathBuf {
    home_dir().join(".config/op/config.yml")
}

/// Top-level subcommand dispatched by [`Program`].
#[derive(Debug, Subcommand)]
pub enum ProgramCommand {
    /// Load secrets of a profile into the current shell.
    #[command(
        name = "load",
        after_help = LOAD_EXAMPLES,
        about = "Load secrets of a profile into the current shell.",
        long_about = "Export environment secrets, write file secrets and export their paths, and add SSH keys to ssh-agent. Without names, every secret of the profile is loaded and the profile is recorded, so its cached secrets are exported in new shells. Needs the shell integration (`keysafe init`); otherwise, evaluate the printed statements yourself.",
        next_display_order = 1
    )]
    Load(LoadCommandArgs),

    /// Unload secrets of a profile from the current shell.
    #[command(
        name = "unload",
        after_help = UNLOAD_EXAMPLES,
        about = "Unload secrets of a profile from the current shell.",
        long_about = "Undo `load`: unset the environment variables, delete the files of file secrets, and remove the SSH keys keysafe added from ssh-agent. Without names, the whole profile is unloaded and no longer exported in new shells, including secrets loaded before they were removed from the config. Its cached secrets stay; use `profile clear` to delete them. Needs the shell integration (`keysafe init`); otherwise, evaluate the printed statements yourself.",
        next_display_order = 2
    )]
    Unload(UnloadCommandArgs),

    /// Print the value of a secret.
    #[command(
        name = "read",
        after_help = READ_EXAMPLES,
        about = "Print the value of a secret.",
        long_about = "Print the value of an environment or file secret, from the keychain cache or 1Password. SSH keys are not printed; use `load` to add them to ssh-agent.",
        next_display_order = 3
    )]
    Read(ReadCommandArgs),

    /// Export the environment and file secrets of a profile as shell statements.
    #[command(
        name = "export",
        after_help = EXPORT_EXAMPLES,
        about = "Export the environment and file secrets of a profile as shell statements.",
        long_about = "Emit shell-ready export statements (or JSON) for the environment and file secrets of a profile. With --cached, only secrets of previously loaded profiles are read from the keychain and 1Password is never contacted.",
        next_display_order = 4
    )]
    Export(ExportCommandArgs),

    /// Execute a command with the secrets of a profile in its environment.
    #[command(
        name = "exec",
        after_help = EXEC_EXAMPLES,
        about = "Execute a command with the secrets of a profile in its environment.",
        long_about = "Resolve the environment and file secrets of a profile, then run the given command with them in its environment. File secrets are removed once the command exits.",
        next_display_order = 5
    )]
    Exec(ExecCommandArgs),

    /// Show what is loaded: secrets in this shell, SSH keys in the agent, exported profiles.
    #[command(
        name = "status",
        after_help = STATUS_EXAMPLES,
        about = "Show what is loaded: secrets in this shell, SSH keys in the agent, exported profiles.",
        long_about = "Show, for each profile, which of its variables are set in this shell, which of its SSH keys are in ssh-agent and when they expire, and whether its cached secrets are exported in new shells. Secret values are never printed.",
        next_display_order = 6
    )]
    Status(StatusCommandArgs),

    /// Check the setup and say how to fix problems.
    #[command(
        name = "doctor",
        after_help = DOCTOR_EXAMPLES,
        about = "Check the setup and say how to fix problems.",
        long_about = "Check the config, each provider's CLI (without prompting: being signed in is checked when secrets are read), the keychain, ssh-agent and the shell integration. Prints how to fix each problem, and exits with an error if anything is broken.",
        next_display_order = 7
    )]
    Doctor(DoctorCommandArgs),

    /// List, show, clear and prune profiles.
    #[command(
        name = "profile",
        about = "List, show, clear and prune profiles.",
        next_display_order = 8
    )]
    Profile(ProfileCommandArgs),

    /// Create, edit and locate the config file.
    #[command(
        name = "config",
        about = "Create, edit and locate the config file.",
        next_display_order = 9
    )]
    Config(ConfigCommandArgs),

    /// Print the shell integration script for zsh or bash.
    #[command(
        name = "init",
        after_help = INIT_SHELL_EXAMPLES,
        about = "Print the shell integration script for zsh or bash.",
        long_about = "Print a script that defines the `keysafe` shell function, which applies `load` and `export` to the current shell, along with completions. It also exports the cached secrets of loaded profiles. Add `eval \"$(keysafe init zsh)\"` to ~/.zshrc, or `eval \"$(keysafe init bash)\"` to ~/.bashrc.",
        next_display_order = 10
    )]
    Init(InitCommandArgs),
}

impl ProgramCommand {
    /// Returns the shared global flags of the subcommand.
    pub fn parent_mut(&mut self) -> &mut ProgramArgs {
        match self {
            Self::Load(args) => &mut args.parent,
            Self::Unload(args) => &mut args.parent,
            Self::Read(args) => &mut args.parent,
            Self::Export(args) => &mut args.parent,
            Self::Exec(args) => &mut args.parent,
            Self::Status(args) => &mut args.parent,
            Self::Doctor(args) => &mut args.parent,
            Self::Profile(args) => match &mut args.command {
                ProfileCommand::List(args) => &mut args.parent,
                ProfileCommand::Show(args) => &mut args.parent,
                ProfileCommand::Clear(args) => &mut args.parent,
                ProfileCommand::Prune(args) => &mut args.parent,
            },
            Self::Config(args) => match &mut args.command {
                ConfigCommand::Init(args) => &mut args.parent,
                ConfigCommand::Edit(args) => &mut args.parent,
                ConfigCommand::Path(args) => &mut args.parent,
            },
            Self::Init(args) => &mut args.parent,
        }
    }
}

/// Subcommand of `config`.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Create a starter config file.
    #[command(
        name = "init",
        after_help = INIT_CONFIG_EXAMPLES,
        about = "Create a starter config file.",
        long_about = "Write a commented starter config, with one profile and examples of each kind of secret, to the config path (see `keysafe config path`). An existing file is never replaced unless --force is given.",
        next_display_order = 1
    )]
    Init(ConfigInitCommandArgs),

    /// Open the config file in your editor, then check it.
    #[command(
        name = "edit",
        after_help = EDIT_EXAMPLES,
        about = "Open the config file in your editor, then check it.",
        long_about = "Open the config file in $VISUAL or $EDITOR (vi if neither is set), and check that it is valid once the editor exits.",
        next_display_order = 2
    )]
    Edit(ConfigEditCommandArgs),

    /// Print the path of the config file in use.
    #[command(
        name = "path",
        after_help = PATH_EXAMPLES,
        about = "Print the path of the config file in use.",
        long_about = "Print the path of the config file keysafe uses, and say on stderr where it comes from: --config, KEYSAFE_CONFIG_FILE, the default location, or zsh-op's location.",
        next_display_order = 3
    )]
    Path(ConfigPathCommandArgs),
}

/// Subcommand of `profile`.
#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List the profile names, one per line.
    #[command(
        name = "list",
        after_help = LIST_EXAMPLES,
        about = "List the profile names, one per line.",
        next_display_order = 1
    )]
    List(ProfileListCommandArgs),

    /// Show profiles, their secrets and whether they were loaded.
    #[command(
        name = "show",
        after_help = SHOW_EXAMPLES,
        about = "Show profiles, their secrets and whether they were loaded.",
        long_about = "Print a profile, or every profile, with its 1Password account, its secrets and whether it has been loaded into the keychain cache. Secret values are never printed.",
        next_display_order = 2
    )]
    Show(ProfileShowCommandArgs),

    /// Clear the cached secrets of a profile.
    #[command(
        name = "clear",
        after_help = CLEAR_EXAMPLES,
        about = "Clear the cached secrets of a profile.",
        long_about = "Delete every cached secret of a profile from the keychain and forget that the profile was loaded. The next `load` fetches every secret from 1Password again. To delete only the secrets the config no longer names, use `profile prune`.",
        next_display_order = 3
    )]
    Clear(ProfileClearCommandArgs),

    /// Delete what keysafe keeps of secrets removed from the config.
    #[command(
        name = "prune",
        after_help = PRUNE_EXAMPLES,
        about = "Delete what keysafe keeps of secrets removed from the config.",
        long_about = "Delete the cached secrets of a profile that its config no longer names, and remove the SSH keys keysafe added for them from ssh-agent. The profile stays loaded. For a profile removed from the config, everything keysafe kept of it is deleted. Variables already set in open shells stay; use `unload` there. `keysafe doctor` says when there is something to prune. To delete every cached secret of a profile, use `profile clear`.",
        next_display_order = 4
    )]
    Prune(ProfilePruneCommandArgs),
}

/// Shell specifies a shell supported by the shell integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    /// Zsh.
    Zsh,

    /// Bash.
    Bash,
}

impl Display for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zsh => write!(f, "zsh"),
            Self::Bash => write!(f, "bash"),
        }
    }
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
#[derive(Debug, Clone, Default, Args)]
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
        env = "KEYSAFE_RUNTIME_DIR",
        long
    )]
    pub runtime_dir: Option<PathBuf>,

    /// Shell whose integration function runs this command and evaluates its statements.
    /// Set by the script that `init` prints; not meant to be set by hand.
    #[arg(long, env = "KEYSAFE_EVAL", hide = true)]
    pub eval: Option<Shell>,

    /// Whether stdout is a terminal. Set by `main`, not a command-line flag.
    #[arg(skip)]
    pub terminal: bool,
}

impl OutputArgs {
    /// Returns true when the shell integration evaluates the statements, i.e. it runs this
    /// command and no format was requested explicitly.
    pub fn is_eval(&self) -> bool {
        self.eval.is_some() && self.format.is_none()
    }

    /// Returns true when shell statements can't reach the shell: stdout is a terminal, the
    /// shell integration isn't active and no format was requested, so printing them would
    /// only show secret values on screen.
    pub fn statements_stranded(&self) -> bool {
        self.terminal && self.eval.is_none() && self.format.is_none()
    }

    /// Explains how to make `command` change the shell.
    pub fn integration_hint(&self, command: &str) -> String {
        let (shell, rc) = match self.export_format() {
            ExportFormat::Bash => ("bash", "~/.bashrc"),
            _ => ("zsh", "~/.zshrc"),
        };
        format!(
            "add `eval \"$(keysafe init {shell})\"` to {rc}, or run `eval \"$(keysafe {command})\"`"
        )
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
        help = "Profile name (the default profile if not provided).",
        env = "KEYSAFE_DEFAULT_PROFILE",
        long,
        short
    )]
    pub profile: Option<String>,

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

/// UnloadCommandArgs defines the arguments for the UnloadCommand.
#[derive(Debug, Args)]
pub struct UnloadCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Names of the secrets to unload. Every secret of the profile is unloaded if not provided.
    #[arg(help = "Secret names (the whole profile if not provided).")]
    pub names: Vec<String>,

    /// Profile the secrets belong to.
    #[arg(
        help = "Profile name (the default profile if not provided).",
        env = "KEYSAFE_DEFAULT_PROFILE",
        long,
        short
    )]
    pub profile: Option<String>,

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
        help = "Profile name (the default profile if not provided).",
        env = "KEYSAFE_DEFAULT_PROFILE",
        long,
        short
    )]
    pub profile: Option<String>,

    /// Bypass the keychain cache and fetch the secret from 1Password.
    #[arg(help = "Force refresh from 1Password.", long, short)]
    pub refresh: bool,
}

/// StatusCommandArgs defines the arguments for the StatusCommand.
#[derive(Debug, Args)]
pub struct StatusCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile to show. Every profile is shown if not provided.
    #[arg(help = "Profile name (all profiles if not provided).", long, short)]
    pub profile: Option<String>,

    /// Shell whose integration runs this command.
    /// Set by the script that `init` prints; not meant to be set by hand.
    #[arg(long, env = "KEYSAFE_SHELL", hide = true)]
    pub shell: Option<Shell>,
}

/// ConfigCommandArgs defines the arguments for the config subcommands.
#[derive(Debug, Args)]
pub struct ConfigCommandArgs {
    /// Command specifies the config subcommand to execute.
    #[command(subcommand)]
    pub command: ConfigCommand,
}

/// ConfigInitCommandArgs defines the arguments for the ConfigInitCommand.
#[derive(Debug, Args)]
pub struct ConfigInitCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Replace an existing config file.
    #[arg(help = "Replace an existing config file.", long, short)]
    pub force: bool,
}

/// ConfigEditCommandArgs defines the arguments for the ConfigEditCommand.
#[derive(Debug, Args)]
pub struct ConfigEditCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,
}

/// ConfigPathCommandArgs defines the arguments for the ConfigPathCommand.
#[derive(Debug, Args)]
pub struct ConfigPathCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,
}

/// DoctorCommandArgs defines the arguments for the DoctorCommand.
#[derive(Debug, Args)]
pub struct DoctorCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Shell whose integration runs this command.
    /// Set by the script that `init` prints; not meant to be set by hand.
    #[arg(long, env = "KEYSAFE_SHELL", hide = true)]
    pub shell: Option<Shell>,
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

/// ProfilePruneCommandArgs defines the arguments for the ProfilePruneCommand.
#[derive(Debug, Args)]
pub struct ProfilePruneCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile whose orphaned secrets are deleted.
    #[arg(help = "Profile name (may be one removed from the config).")]
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
        help = "Profile name (the default profile if not provided).",
        env = "KEYSAFE_DEFAULT_PROFILE",
        long,
        short
    )]
    pub profile: Option<String>,

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
        help = "Profile name (the default profile if not provided).",
        env = "KEYSAFE_DEFAULT_PROFILE",
        long,
        short
    )]
    pub profile: Option<String>,

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

    /// Returns every subcommand of `command`, nested ones included.
    fn subcommands(command: &clap::Command) -> Vec<clap::Command> {
        command
            .get_subcommands()
            .flat_map(|c| std::iter::once(c.clone()).chain(subcommands(c)))
            .collect()
    }

    #[test]
    fn every_command_has_examples() {
        for command in subcommands(&Program::command()) {
            if command.get_subcommands().next().is_none() {
                assert!(
                    command.get_after_help().is_some(),
                    "`{}` has no examples",
                    command.get_name()
                );
            }
        }
    }

    #[test]
    fn examples_are_valid_commands() {
        let program = Program::command();
        let helps = std::iter::once(program.clone())
            .chain(subcommands(&program))
            .filter_map(|c| c.get_after_help().map(|h| h.to_string()));
        let mut checked = 0;
        for help in helps {
            for line in help.lines() {
                // The command is what follows `keysafe`, up to a comment, `)"`, a pipe or the
                // closing backtick of a command quoted in prose
                let Some(start) = line.find("keysafe ") else {
                    continue;
                };
                let command = line[start..]
                    .split("  #")
                    .next()
                    .and_then(|c| c.split('`').next())
                    .and_then(|c| c.split(")\"").next())
                    .and_then(|c| c.split(" |").next())
                    .unwrap();
                let words: Vec<&str> = command.split_whitespace().collect();
                if let Err(err) = Program::try_parse_from(&words) {
                    panic!("example `{command}` does not parse: {err}");
                }
                checked += 1;
            }
        }
        assert!(checked > 20, "only {checked} examples found");
    }

    #[test]
    fn quiet_and_verbose_conflict() {
        assert!(Program::try_parse_from(["keysafe", "status", "-q", "-v"]).is_err());
        let mut program = Program::try_parse_from(["keysafe", "load", "-q"]).unwrap();
        assert!(program.command.parent_mut().quiet);
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
    fn statements_are_stranded_on_a_terminal_without_the_integration() {
        let terminal = OutputArgs {
            terminal: true,
            ..Default::default()
        };
        assert!(terminal.statements_stranded());

        // Piped or evaluated, under the integration, or with an explicit format: they arrive
        assert!(!OutputArgs::default().statements_stranded());
        assert!(!OutputArgs {
            eval: Some(Shell::Zsh),
            ..terminal.clone()
        }
        .statements_stranded());
        assert!(!OutputArgs {
            format: Some(ExportFormat::Zsh),
            ..terminal
        }
        .statements_stranded());
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
        let program = Program::try_parse_from(["keysafe", "init", "bash", "--no-export"]).unwrap();
        let ProgramCommand::Init(args) = program.command else {
            panic!("expected the init command");
        };
        assert_eq!(args.shell, Shell::Bash);
        assert!(args.no_export);
        assert!(Program::try_parse_from(["keysafe", "init", "fish"]).is_err());
    }

    #[test]
    fn export_rejects_cached_with_refresh() {
        let result = Program::try_parse_from(["keysafe", "export", "--cached", "--refresh"]);
        assert!(result.is_err());
    }

    #[test]
    fn load_parses_names_and_flags() {
        let program = Program::try_parse_from([
            "keysafe",
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
        assert_eq!(args.profile.as_deref(), Some("work"));
        assert_eq!(args.expiration, "8h");
    }

    #[test]
    fn load_without_names_loads_the_profile() {
        let program = Program::try_parse_from(["keysafe", "load", "-p", "work"]).unwrap();
        let ProgramCommand::Load(args) = program.command else {
            panic!("expected the load command");
        };
        assert!(args.names.is_empty());
    }

    #[test]
    fn profile_subcommands_take_the_profile_as_argument() {
        let mut program =
            Program::try_parse_from(["keysafe", "profile", "clear", "work", "--state-dir", "/s"])
                .unwrap();
        assert_eq!(program.command.parent_mut().state_dir, Path::new("/s"));
        let ProgramCommand::Profile(ProfileCommandArgs {
            command: ProfileCommand::Clear(args),
        }) = program.command
        else {
            panic!("expected the profile clear command");
        };
        assert_eq!(args.profile, "work");

        // Clearing and pruning need an explicit profile
        assert!(Program::try_parse_from(["keysafe", "profile", "clear"]).is_err());
        assert!(Program::try_parse_from(["keysafe", "profile", "prune"]).is_err());
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

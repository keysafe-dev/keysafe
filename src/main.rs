mod app;
mod log;
mod vault;

use std::fs::File;
use std::io::{IsTerminal, Write};
use std::os::fd::FromRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ExitCode, ExitStatus};

use crate::app::args::*;
use crate::app::exec::*;
use crate::log::info;
use crate::vault::*;

use anyhow::Result;
use clap::Parser;

fn main() -> ExitCode {
    let mut program = Program::parse();
    // The shell integration passes these to this process only; commands it runs, like the
    // one `exec` starts, must not inherit them.
    std::env::remove_var("KEYSAFE_EVAL");
    std::env::remove_var("KEYSAFE_RUNTIME_DIR");
    std::env::remove_var("KEYSAFE_SHELL");

    let parent = program.command.parent_mut();
    log::set_level(match (parent.quiet, parent.verbose) {
        (true, _) => log::Level::Quiet,
        (_, true) => log::Level::Verbose,
        _ => log::Level::Normal,
    });

    // Keep working with the config used before keysafe had its own name. The hint is
    // left out of `init`, which runs on every shell start.
    // `config init` always creates the config at the new location.
    let init = matches!(program.command, ProgramCommand::Init(_));
    let config_init = matches!(
        program.command,
        ProgramCommand::Config(ConfigCommandArgs {
            command: ConfigCommand::Init(_)
        })
    );
    if !config_init {
        if let Some(legacy) = program.command.parent_mut().use_legacy_config() {
            if !init {
                info(format!(
                    "using {}; move it to {} (or set KEYSAFE_CONFIG_FILE)",
                    legacy.display(),
                    default_config().display()
                ));
            }
        }
    }

    let parent = program.command.parent_mut();
    log::debug(format!("config: {}", parent.config.display()));
    log::debug(format!("state directory: {}", parent.state_dir.display()));

    // Process the correct command
    match run(program) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("keysafe: error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(program: Program) -> Result<ExitCode> {
    match program.command {
        ProgramCommand::Load(args) => {
            args.output
                .check_destination("load", std::io::stdout().is_terminal())?;
            let writer = statements(&args.output);
            let loader = loader(&args.parent);
            let agent = Box::new(Agent::new());
            let mut command = LoadCommand {
                writer,
                loader,
                agent,
            };
            command.execute(&args)?
        }
        ProgramCommand::Unload(args) => {
            args.output
                .check_destination("unload", std::io::stdout().is_terminal())?;
            let writer = statements(&args.output);
            let cache = cache(&args.parent);
            let agent = Box::new(Agent::new());
            let environment = std::env::vars().collect();
            let mut command = UnloadCommand {
                writer,
                cache,
                agent,
                environment,
            };
            command.execute(&args)?
        }
        ProgramCommand::Read(args) => {
            let writer = Box::new(std::io::stdout());
            let loader = loader(&args.parent);
            let mut command = ReadCommand { writer, loader };
            command.execute(&args)?
        }
        ProgramCommand::Export(args) => {
            let writer = statements(&args.output);
            let loader = loader(&args.parent);
            let mut command = ExportCommand { writer, loader };
            command.execute(&args)?
        }
        ProgramCommand::Exec(args) => {
            let loader = loader(&args.parent);
            let mut command = ExecCommand { loader };
            return Ok(exit_code(command.execute(&args)?));
        }
        ProgramCommand::Status(args) => {
            let writer = Box::new(std::io::stdout());
            let cache = cache(&args.parent);
            let agent = Box::new(Agent::new());
            let environment = std::env::vars().collect();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default();
            let mut command = StatusCommand {
                writer,
                cache,
                agent,
                environment,
                now,
            };
            command.execute(&args)?
        }
        ProgramCommand::Doctor(args) => {
            let writer = Box::new(std::io::stdout());
            let client = Box::new(Client::new());
            let cache = cache(&args.parent);
            let agent = Box::new(Agent::new());
            let env = std::env::var_os("KEYSAFE_CONFIG_FILE").map(PathBuf::from);
            let mut command = DoctorCommand {
                writer,
                client,
                cache,
                agent,
                env,
            };
            command.execute(&args)?
        }
        ProgramCommand::Profile(args) => match args.command {
            ProfileCommand::List(args) => {
                let writer = Box::new(std::io::stdout());
                let mut command = ProfileListCommand { writer };
                command.execute(&args)?
            }
            ProfileCommand::Show(args) => {
                let writer = Box::new(std::io::stdout());
                let cache = cache(&args.parent);
                let mut command = ProfileShowCommand { writer, cache };
                command.execute(&args)?
            }
            ProfileCommand::Clear(args) => {
                let cache = cache(&args.parent);
                let mut command = ProfileClearCommand { cache };
                command.execute(&args)?
            }
        },
        ProgramCommand::Config(args) => match args.command {
            ConfigCommand::Init(args) => {
                let mut command = ConfigInitCommand;
                command.execute(&args)?
            }
            ConfigCommand::Edit(args) => {
                let editor = std::env::var("VISUAL")
                    .or_else(|_| std::env::var("EDITOR"))
                    .unwrap_or_else(|_| "vi".to_string());
                let mut command = ConfigEditCommand { editor };
                command.execute(&args)?
            }
            ConfigCommand::Path(args) => {
                let writer = Box::new(std::io::stdout());
                let env = std::env::var_os("KEYSAFE_CONFIG_FILE").map(PathBuf::from);
                let mut command = ConfigPathCommand { writer, env };
                command.execute(&args)?
            }
        },
        ProgramCommand::Init(args) => {
            let writer = Box::new(std::io::stdout());
            let loader = loader(&args.parent);
            let bin = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("keysafe"));
            let mut command = InitCommand {
                writer,
                loader,
                bin,
            };
            command.execute(&args)?
        }
    }

    Ok(ExitCode::SUCCESS)
}

/// Returns where shell statements go: fd 3 when the shell integration evaluates them (see
/// app/init.zsh), stdout otherwise.
fn statements(output: &OutputArgs) -> Box<dyn Write> {
    if output.is_eval() {
        // fd 3 is the pipe the integration reads the statements from. Close it on exec, so
        // that processes we start, like a background helper of `op`, do not keep it open and
        // leave the shell waiting. fcntl fails when fd 3 is not open.
        // SAFETY: fcntl only changes the descriptor flags of fd 3.
        if unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } != -1 {
            // SAFETY: fd 3 is open and nothing else in this process owns it.
            return Box::new(unsafe { File::from_raw_fd(3) });
        }
    }
    Box::new(std::io::stdout())
}

/// Returns the keychain-backed cache keeping its metadata in the state directory.
fn cache(parent: &ProgramArgs) -> Cache {
    Cache::new(Box::new(Keychain::new()), &parent.state_dir)
        .with_legacy_dir(parent.legacy_state_dir())
}

/// Returns a loader reading from the keychain cache and the 1Password CLI.
fn loader(parent: &ProgramArgs) -> Loader {
    Loader {
        client: Box::new(Client::new()),
        cache: cache(parent),
    }
}

/// Maps the exit status of a child process to our own, shell style.
fn exit_code(status: ExitStatus) -> ExitCode {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitCode::from(code as u8),
        (None, Some(signal)) => ExitCode::from(128 + signal as u8),
        (None, None) => ExitCode::FAILURE,
    }
}

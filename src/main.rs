mod app;
mod log;
mod vault;

use std::fs::File;
use std::io::Write;
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

    // Keep working with the config used before keysafe had its own name. The hint is
    // left out of `init`, which runs on every shell start.
    let init = matches!(program.command, ProgramCommand::Init(_));
    if let Some(legacy) = program.command.parent_mut().use_legacy_config() {
        if !init {
            info(format!(
                "using {}; move it to {} (or set KEYSAFE_CONFIG_FILE)",
                legacy.display(),
                default_config().display()
            ));
        }
    }

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

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::path::Path;

const CONFIG: &str = "version: 1
accounts:
  - name: personal
    account: my.1password.com
    secrets:
      - kind: env
        name: GITHUB_TOKEN
        path: op://Personal/GitHub/token
      - kind: ssh
        name: my-key
        path: op://Private/SSH/private key?ssh-format=openssh
  - name: work
    account: team.1password.com
";

/// Returns a temporary directory holding `config.yml` and an empty `cache` directory.
fn workspace(config: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.yml"), config).unwrap();
    std::fs::create_dir(dir.path().join("cache")).unwrap();
    dir
}

/// Returns a secret-env command that uses the config and cache of `dir`.
fn secret_env(dir: &Path) -> assert_cmd::Command {
    let mut cmd = cargo_bin_cmd!();
    cmd.env_remove("SECRET_ENV_DEFAULT_PROFILE")
        .env("HOME", dir)
        .env("SECRET_ENV_CONFIG_FILE", dir.join("config.yml"))
        .env("SECRET_ENV_CACHE_DIR", dir.join("cache"));
    cmd
}

#[test]
fn help_lists_subcommands() {
    cargo_bin_cmd!().arg("--help").assert().success().stdout(
        predicate::str::contains("inspect")
            .and(predicate::str::contains("shell"))
            .and(predicate::str::contains("secret"))
            .and(predicate::str::contains("export"))
            .and(predicate::str::contains("exec")),
    );
}

#[test]
fn list_profiles() {
    let dir = workspace(CONFIG);
    secret_env(dir.path())
        .arg("list")
        .assert()
        .success()
        .stdout("personal\nwork\n");
}

#[test]
fn list_secrets_with_config_flag() {
    let dir = workspace(CONFIG);
    cargo_bin_cmd!()
        .args(["list", "--profile", "personal", "--config"])
        .arg(dir.path().join("config.yml"))
        .assert()
        .success()
        .stdout("GITHUB_TOKEN\nmy-key\n");
}

#[test]
fn inspect_shows_profiles() {
    let dir = workspace(CONFIG);
    secret_env(dir.path())
        .args(["inspect", "-p", "work"])
        .assert()
        .success()
        .stdout("Profile: work\n  Account: team.1password.com\n  Loaded: no\n");
}

#[test]
fn inspect_fails_when_config_missing() {
    let dir = tempfile::tempdir().unwrap();
    secret_env(dir.path())
        .arg("inspect")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "secret-env: error: failed to read config file",
        ));
}

#[test]
fn inspect_fails_on_invalid_config() {
    let dir = workspace(&CONFIG.replace("kind: env", "kind: token"));
    secret_env(dir.path())
        .arg("inspect")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "secret 'GITHUB_TOKEN' has invalid kind: token (valid kinds: env, ssh, file)",
        ));
}

#[test]
fn export_cached_writes_nothing_before_any_profile_is_loaded() {
    let dir = workspace(CONFIG);
    secret_env(dir.path())
        .args(["export", "--all", "--cached", "--format", "zsh"])
        .assert()
        .success()
        .stdout("");
}

#[test]
fn export_rejects_cached_with_refresh() {
    let dir = workspace(CONFIG);
    secret_env(dir.path())
        .args(["export", "--cached", "--refresh"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn secret_fails_for_unknown_profile() {
    let dir = workspace(CONFIG);
    secret_env(dir.path())
        .args(["secret", "-p", "staging", "GITHUB_TOKEN"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "profile 'staging' not found in config (available profiles: personal, work)",
        ));
}

#[test]
fn shell_uses_default_profile_from_environment() {
    let dir = workspace(CONFIG);
    secret_env(dir.path())
        .env("SECRET_ENV_DEFAULT_PROFILE", "staging")
        .arg("shell")
        .assert()
        .failure()
        .stderr(predicate::str::contains("profile 'staging' not found"));
}

#[test]
fn exec_requires_a_command() {
    let dir = workspace(CONFIG);
    secret_env(dir.path()).arg("exec").assert().failure();
}

/// Runs `script` in a clean `shell` (zsh or bash) whose home, config and cache are in `dir`,
/// so nothing it starts can reach the real keychain cache.
fn run_shell(shell: &str, dir: &Path, script: &str) -> std::process::Output {
    let flags: &[&str] = match shell {
        "zsh" => &["-f", "-c"],
        _ => &["--norc", "--noprofile", "-c"],
    };
    std::process::Command::new(shell)
        .args(flags)
        .arg(script)
        .env_remove("SECRET_ENV_DEFAULT_PROFILE")
        .env("HOME", dir)
        .env("SECRET_ENV_CONFIG_FILE", dir.join("config.yml"))
        .env("SECRET_ENV_CACHE_DIR", dir.join("cache"))
        .output()
        .unwrap()
}

/// Returns the statement that sets up the shell integration for `shell`.
fn init(shell: &str) -> String {
    let bin = env!("CARGO_BIN_EXE_secret-env");
    format!("eval \"$('{bin}' init {shell})\"")
}

/// Runs `script` in a clean `shell` after `eval "$(secret-env init <shell>)"`.
fn with_init(shell: &str, dir: &Path, script: &str) -> std::process::Output {
    run_shell(shell, dir, &format!("{}\n{script}", init(shell)))
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Writes a stand-in for the binary that sends `statements` to fd 3, prints `raw` to stdout and
/// exits with `code`, the way secret-env does under the shell integration.
fn stub(dir: &Path, statements: &str, raw: &str, code: i32) -> String {
    let path = dir.join("stub");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$SECRET_ENV_EVAL\" > '{}'\nprintf '%s\\n' '{statements}' >&3\n[ -z '{raw}' ] || printf '%s\\n' '{raw}'\nexit {code}\n",
        dir.join("eval").display()
    );
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn init_scripts_are_valid_shell() {
    let dir = workspace(CONFIG);
    // /bin/bash is bash 3.2 on macOS, which parses some constructs differently
    for (shell, interpreter) in [("zsh", "zsh"), ("bash", "bash"), ("bash", "/bin/bash")] {
        if interpreter.starts_with('/') && !Path::new(interpreter).exists() {
            continue;
        }
        let script = secret_env(dir.path())
            .args(["init", shell])
            .output()
            .unwrap();
        assert!(script.status.success());
        let flag = if shell == "zsh" { "-fn" } else { "-n" };
        let status = std::process::Command::new(interpreter)
            .args([flag, "-c"])
            .arg(String::from_utf8(script.stdout).unwrap())
            .status()
            .unwrap();
        assert!(status.success(), "{interpreter} rejects the init script");
    }
}

#[test]
fn init_function_passes_other_commands_through() {
    let dir = workspace(CONFIG);
    for shell in ["zsh", "bash"] {
        let output = with_init(shell, dir.path(), "secret-env list");
        assert_eq!(stdout(&output), "personal\nwork\n", "{shell}");
    }
}

#[test]
fn init_function_prints_explicit_formats_instead_of_evaluating_them() {
    let dir = workspace(CONFIG);
    for shell in ["zsh", "bash"] {
        let output = with_init(
            shell,
            dir.path(),
            "secret-env export --all --cached --format json",
        );
        assert_eq!(stdout(&output), "{}\n", "{shell}");
    }
}

#[test]
fn init_function_returns_the_exit_status() {
    let dir = workspace(CONFIG);
    for shell in ["zsh", "bash"] {
        let output = with_init(
            shell,
            dir.path(),
            "secret-env shell staging; echo \"rc=$?\"",
        );
        assert_eq!(stdout(&output), "rc=1\n", "{shell}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("profile 'staging' not found"));
    }
}

#[test]
fn init_function_evaluates_fd3_and_prints_stdout() {
    let dir = workspace(CONFIG);
    let stub = stub(dir.path(), "export ROUTED=yes", "raw output", 3);
    for shell in ["zsh", "bash"] {
        let script = format!(
            "_SECRET_ENV_BIN='{stub}'\nsecret-env secret -x A; echo \"rc=$? ROUTED=$ROUTED\""
        );
        let output = with_init(shell, dir.path(), &script);
        assert_eq!(stdout(&output), "raw output\nrc=3 ROUTED=yes\n", "{shell}");
        let eval = std::fs::read_to_string(dir.path().join("eval")).unwrap();
        assert_eq!(eval, format!("{shell}\n"));
    }
}

#[test]
fn init_removes_the_runtime_directory_on_exit() {
    let dir = workspace(CONFIG);
    for shell in ["zsh", "bash"] {
        let runtime = dir.path().join(format!("runtime-{shell}"));
        std::fs::create_dir(&runtime).unwrap();
        let assign = match shell {
            "zsh" => format!("typeset -g _SECRET_ENV_RUNTIME_DIR={}", runtime.display()),
            _ => format!("_SECRET_ENV_RUNTIME_DIR={}", runtime.display()),
        };
        let stub = stub(dir.path(), &assign, "", 0);
        let script = format!("_SECRET_ENV_BIN='{stub}'\nsecret-env export\n[ -d \"$_SECRET_ENV_RUNTIME_DIR\" ] && echo tracked");
        let output = with_init(shell, dir.path(), &script);
        assert_eq!(stdout(&output), "tracked\n", "{shell}");
        assert!(
            !runtime.exists(),
            "{shell} leaves the runtime directory behind"
        );
    }
}

#[test]
fn init_registers_zsh_completions_before_and_after_compinit() {
    let dir = workspace(CONFIG);
    let check = "print -r -- \"${_comps[secret-env]:-none}\"";
    let compinit = format!(
        "autoload -Uz compinit; compinit -u -d '{}'",
        dir.path().join("zcd").display()
    );

    // compinit already ran: registered right away
    let script = format!("{compinit}\n{}\n{check}", init("zsh"));
    let output = run_shell("zsh", dir.path(), &script);
    assert_eq!(stdout(&output), "_secret-env\n");

    // compinit runs later in ~/.zshrc: registered before the first prompt
    let script = format!("{check}\n{compinit}\nfor f in $precmd_functions; do $f; done\n{check}");
    let output = with_init("zsh", dir.path(), &script);
    assert_eq!(stdout(&output), "none\n_secret-env\n");
}

#[test]
fn init_registers_bash_completions() {
    let dir = workspace(CONFIG);
    let output = with_init("bash", dir.path(), "complete -p secret-env");
    assert!(stdout(&output).contains("-F _secret__env"));
}

#[test]
fn init_keeps_an_existing_bash_exit_trap() {
    let dir = workspace(CONFIG);
    // Evaluating the integration twice must not add the cleanup twice
    let script = format!(
        "trap 'echo previous trap' EXIT\n{init}\n{init}\ntrap -p EXIT",
        init = init("bash")
    );
    let output = run_shell("bash", dir.path(), &script);
    assert_eq!(
        stdout(&output),
        "trap -- '_secret_env_cleanup; echo previous trap' EXIT\nprevious trap\n"
    );
}

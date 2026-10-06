use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::path::Path;

const CONFIG: &str = "version: 1
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
  - name: work
    provider:
      type: 1password
      account: team.1password.com
";

/// Returns a temporary directory holding `config.yml` and an empty `cache` directory.
fn workspace(config: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.yml"), config).unwrap();
    std::fs::create_dir(dir.path().join("cache")).unwrap();
    dir
}

/// Returns a keysafe command that uses the config and cache of `dir`.
fn keysafe(dir: &Path) -> assert_cmd::Command {
    let mut cmd = cargo_bin_cmd!();
    cmd.env_remove("KEYSAFE_DEFAULT_PROFILE")
        .env("HOME", dir)
        .env("KEYSAFE_CONFIG_FILE", dir.join("config.yml"))
        .env("KEYSAFE_STATE_DIR", dir.join("cache"));
    cmd
}

#[test]
fn help_lists_subcommands() {
    cargo_bin_cmd!().arg("--help").assert().success().stdout(
        predicate::str::contains("load")
            .and(predicate::str::contains("read"))
            .and(predicate::str::contains("export"))
            .and(predicate::str::contains("exec"))
            .and(predicate::str::contains("profile"))
            .and(predicate::str::contains("init")),
    );
}

#[test]
fn profile_list_prints_profiles() {
    let dir = workspace(CONFIG);
    keysafe(dir.path())
        .args(["profile", "list"])
        .assert()
        .success()
        .stdout("personal\nwork\n");
}

#[test]
fn profile_show_with_config_flag() {
    let dir = workspace(CONFIG);
    keysafe(dir.path())
        .env_remove("KEYSAFE_CONFIG_FILE")
        .args(["profile", "show", "work", "--config"])
        .arg(dir.path().join("config.yml"))
        .assert()
        .success()
        .stdout("Profile: work\n  Provider: 1password (team.1password.com)\n  Exported in new shells: no\n");
}

#[test]
fn profile_show_marks_the_default_profile() {
    let dir = workspace(&CONFIG.replace("  - name: work\n", "  - name: work\n    default: true\n"));
    keysafe(dir.path())
        .args(["profile", "show"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Profile: personal\n")
                .and(predicate::str::contains("Profile: work (default)\n")),
        );
}

#[test]
fn status_without_shell_integration() {
    let dir = workspace(CONFIG);
    keysafe(dir.path())
        .args(["status", "-p", "work"])
        .assert()
        .success()
        .stdout(
            predicate::str::starts_with("Shell integration: not active").and(
                predicate::str::contains("Profile: work\n  Exported in new shells: no\n"),
            ),
        );
}

#[test]
fn profile_show_fails_when_config_missing() {
    let dir = tempfile::tempdir().unwrap();
    keysafe(dir.path())
        .args(["profile", "show"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("keysafe: error: config file not found: ").and(
                predicate::str::contains("(create one with `keysafe config init`)"),
            ),
        );
}

#[test]
fn profile_show_fails_on_invalid_config() {
    let dir = workspace(&CONFIG.replace("kind: env", "kind: token"));
    keysafe(dir.path())
        .args(["profile", "show"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "secret 'GITHUB_TOKEN' has invalid kind: token (valid kinds: env, ssh, file)",
        ));
}

#[test]
fn export_cached_writes_nothing_before_any_profile_is_loaded() {
    let dir = workspace(CONFIG);
    keysafe(dir.path())
        .args(["export", "--all", "--cached", "--format", "zsh"])
        .assert()
        .success()
        .stdout("");
}

#[test]
fn export_rejects_cached_with_refresh() {
    let dir = workspace(CONFIG);
    keysafe(dir.path())
        .args(["export", "--cached", "--refresh"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn read_fails_for_unknown_profile() {
    let dir = workspace(CONFIG);
    keysafe(dir.path())
        .args(["read", "-p", "staging", "GITHUB_TOKEN"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "profile 'staging' not found in config (available profiles: personal, work)",
        ));
}

#[test]
fn load_uses_default_profile_from_environment() {
    let dir = workspace(CONFIG);
    keysafe(dir.path())
        .env("KEYSAFE_DEFAULT_PROFILE", "staging")
        .arg("load")
        .assert()
        .failure()
        .stderr(predicate::str::contains("profile 'staging' not found"));
}

/// Returns a keysafe command with `dir` as home and no location set explicitly, so the
/// default locations apply.
fn keysafe_defaults(dir: &Path) -> assert_cmd::Command {
    let mut cmd = cargo_bin_cmd!();
    for var in [
        "KEYSAFE_CONFIG_FILE",
        "KEYSAFE_STATE_DIR",
        "KEYSAFE_DEFAULT_PROFILE",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("HOME", dir);
    cmd
}

#[test]
fn default_config_follows_xdg_config_home() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("xdg/keysafe/config.yml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, CONFIG).unwrap();

    keysafe_defaults(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("xdg"))
        .args(["profile", "list"])
        .assert()
        .success()
        .stdout("personal\nwork\n");
}

#[test]
fn config_init_creates_a_usable_config_at_the_default_location() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(".config/keysafe/config.yml");

    keysafe_defaults(dir.path())
        .args(["config", "path"])
        .assert()
        .success()
        .stdout(format!("{}\n", config.display()))
        .stderr(predicate::str::contains("it does not exist yet"));

    keysafe_defaults(dir.path())
        .args(["config", "init"])
        .assert()
        .success();
    keysafe_defaults(dir.path())
        .args(["profile", "list"])
        .assert()
        .success()
        .stdout("personal\n");

    // A second init leaves the config alone
    keysafe_defaults(dir.path())
        .args(["config", "init"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn doctor_reports_a_missing_config() {
    let dir = tempfile::tempdir().unwrap();
    keysafe(dir.path())
        .arg("doctor")
        .assert()
        .failure()
        .stdout(
            predicate::str::starts_with("✗ Config: config file not found: ")
                .and(predicate::str::contains("! Shell integration: not active")),
        )
        .stderr(predicate::str::contains("keysafe: error: found "));
}

#[test]
fn quiet_and_verbose_change_what_goes_to_stderr() {
    let dir = workspace(CONFIG);
    let stderr = |flag: Option<&str>| {
        let mut cmd = keysafe(dir.path());
        cmd.args(["config", "path"]);
        if let Some(flag) = flag {
            cmd.arg(flag);
        }
        let output = cmd.output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stderr).unwrap()
    };

    assert_eq!(stderr(Some("-q")), "");
    assert_eq!(stderr(None), "keysafe: set by KEYSAFE_CONFIG_FILE\n");
    let verbose = stderr(Some("-v"));
    assert!(verbose.contains("keysafe: debug: config: "), "{verbose}");
    assert!(
        verbose.contains("keysafe: set by KEYSAFE_CONFIG_FILE"),
        "{verbose}"
    );
}

#[test]
fn config_init_ignores_the_legacy_config() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join(".config/op/config.yml");
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    std::fs::write(&legacy, CONFIG).unwrap();

    keysafe_defaults(dir.path())
        .args(["config", "init"])
        .assert()
        .success();

    assert!(dir.path().join(".config/keysafe/config.yml").exists());
    assert_eq!(std::fs::read_to_string(&legacy).unwrap(), CONFIG);
}

#[test]
fn default_config_falls_back_to_the_legacy_location() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join(".config/op/config.yml");
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    std::fs::write(&legacy, CONFIG).unwrap();

    keysafe_defaults(dir.path())
        .args(["profile", "list"])
        .assert()
        .success()
        .stdout("personal\nwork\n")
        .stderr(predicate::str::contains(format!(
            "using {}; move it to {}",
            legacy.display(),
            dir.path().join(".config/keysafe/config.yml").display()
        )));

    // The hint is left out of `init`, which runs on every shell start
    keysafe_defaults(dir.path())
        .args(["init", "zsh"])
        .assert()
        .success()
        .stderr("");
}

#[test]
fn default_config_prefers_the_new_location() {
    let dir = tempfile::tempdir().unwrap();
    for (path, config) in [
        (
            ".config/op/config.yml",
            CONFIG.replace("name: work", "name: legacy"),
        ),
        (".config/keysafe/config.yml", CONFIG.to_string()),
    ] {
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, config).unwrap();
    }

    keysafe_defaults(dir.path())
        .args(["profile", "list"])
        .assert()
        .success()
        .stdout("personal\nwork\n")
        .stderr("");
}

#[test]
fn profile_show_reads_legacy_state() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(".config/keysafe/config.yml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, CONFIG).unwrap();
    std::fs::create_dir_all(dir.path().join(".cache/op")).unwrap();
    std::fs::write(dir.path().join(".cache/op/work.metadata"), "env:API_KEY\n").unwrap();

    keysafe_defaults(dir.path())
        .args(["profile", "show", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Exported in new shells: yes"));
}

#[test]
fn exec_requires_a_command() {
    let dir = workspace(CONFIG);
    keysafe(dir.path()).arg("exec").assert().failure();
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
        .env_remove("KEYSAFE_DEFAULT_PROFILE")
        .env("HOME", dir)
        .env("KEYSAFE_CONFIG_FILE", dir.join("config.yml"))
        .env("KEYSAFE_STATE_DIR", dir.join("cache"))
        .output()
        .unwrap()
}

/// Returns the statement that sets up the shell integration for `shell`.
fn init(shell: &str) -> String {
    let bin = env!("CARGO_BIN_EXE_keysafe");
    format!("eval \"$('{bin}' init {shell})\"")
}

/// Runs `script` in a clean `shell` after `eval "$(keysafe init <shell>)"`.
fn with_init(shell: &str, dir: &Path, script: &str) -> std::process::Output {
    run_shell(shell, dir, &format!("{}\n{script}", init(shell)))
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Writes a stand-in for the binary that sends `statements` to fd 3, prints `raw` to stdout and
/// exits with `code`, the way keysafe does under the shell integration.
fn stub(dir: &Path, statements: &str, raw: &str, code: i32) -> String {
    let path = dir.join("stub");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$KEYSAFE_EVAL\" > '{}'\nprintf '%s\\n' '{statements}' >&3\n[ -z '{raw}' ] || printf '%s\\n' '{raw}'\nexit {code}\n",
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
        let script = keysafe(dir.path()).args(["init", shell]).output().unwrap();
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
fn init_function_tells_status_the_integration_is_active() {
    let dir = workspace(CONFIG);
    for shell in ["zsh", "bash"] {
        let output = with_init(shell, dir.path(), "keysafe status -p work");
        assert!(
            stdout(&output).starts_with(&format!("Shell integration: active ({shell})\n")),
            "{shell}: {}",
            stdout(&output)
        );
    }
}

#[test]
fn init_function_unloads_secrets() {
    let dir = workspace(CONFIG);
    for shell in ["zsh", "bash"] {
        let script = "export GITHUB_TOKEN=x\nkeysafe unload GITHUB_TOKEN; echo \"rc=$? token=${GITHUB_TOKEN-unset}\"";
        let output = with_init(shell, dir.path(), script);
        assert_eq!(stdout(&output), "rc=0 token=unset\n", "{shell}");
    }
}

#[test]
fn init_function_passes_other_commands_through() {
    let dir = workspace(CONFIG);
    for shell in ["zsh", "bash"] {
        let output = with_init(shell, dir.path(), "keysafe profile list");
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
            "keysafe export --all --cached --format json",
        );
        assert_eq!(stdout(&output), "{}\n", "{shell}");
    }
}

#[test]
fn init_function_returns_the_exit_status() {
    let dir = workspace(CONFIG);
    for shell in ["zsh", "bash"] {
        let output = with_init(shell, dir.path(), "keysafe load -p staging; echo \"rc=$?\"");
        assert_eq!(stdout(&output), "rc=1\n", "{shell}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("profile 'staging' not found"));
    }
}

#[test]
fn init_function_evaluates_fd3_and_prints_stdout() {
    let dir = workspace(CONFIG);
    let stub = stub(dir.path(), "export ROUTED=yes", "raw output", 3);
    for shell in ["zsh", "bash"] {
        let script =
            format!("_KEYSAFE_BIN='{stub}'\nkeysafe load A; echo \"rc=$? ROUTED=$ROUTED\"");
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
            "zsh" => format!("typeset -g _KEYSAFE_RUNTIME_DIR={}", runtime.display()),
            _ => format!("_KEYSAFE_RUNTIME_DIR={}", runtime.display()),
        };
        let stub = stub(dir.path(), &assign, "", 0);
        let script = format!("_KEYSAFE_BIN='{stub}'\nkeysafe export\n[ -d \"$_KEYSAFE_RUNTIME_DIR\" ] && echo tracked");
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
    let check = "print -r -- \"${_comps[keysafe]:-none}\"";
    let compinit = format!(
        "autoload -Uz compinit; compinit -u -d '{}'",
        dir.path().join("zcd").display()
    );

    // compinit already ran: registered right away
    let script = format!("{compinit}\n{}\n{check}", init("zsh"));
    let output = run_shell("zsh", dir.path(), &script);
    assert_eq!(stdout(&output), "_keysafe\n");

    // compinit runs later in ~/.zshrc: registered before the first prompt
    let script = format!("{check}\n{compinit}\nfor f in $precmd_functions; do $f; done\n{check}");
    let output = with_init("zsh", dir.path(), &script);
    assert_eq!(stdout(&output), "none\n_keysafe\n");
}

#[test]
fn init_registers_bash_completions() {
    let dir = workspace(CONFIG);
    let script = "if type complete >/dev/null 2>&1; then complete -p keysafe; else echo none; fi";
    let output = with_init("bash", dir.path(), script);
    // A bash without readline has no `complete`: the integration must load without errors
    match stdout(&output).as_str() {
        "none\n" => assert_eq!(String::from_utf8_lossy(&output.stderr), ""),
        registered => assert!(registered.contains("-F _keysafe"), "{registered}"),
    }
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
        "trap -- '_keysafe_cleanup; echo previous trap' EXIT\nprevious trap\n"
    );
}

# keysafe

> Your 1Password secrets in every shell: cached in the system keychain, exported as environment variables or files, and added to ssh-agent.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![CI](https://github.com/keysafe-dev/keysafe/actions/workflows/ci.yml/badge.svg)](https://github.com/keysafe-dev/keysafe/actions/workflows/ci.yml)

`keysafe` is not another password manager: 1Password stays the source of truth. It reads a YAML config of profiles, fetches each secret from 1Password on first use, and caches it in the macOS Keychain or the Linux Secret Service. After that, secrets come from the keychain: your shell starts without waiting for 1Password or asking for Touch ID.

- **Environment secrets** are printed as shell-quoted `export` statements (or JSON).
- **File secrets** are written to private `0600` files, and their path is exported.
- **SSH keys** are added to ssh-agent with an expiration, piped through `ssh-add` without touching the disk.
- Secrets never appear in process arguments.

Add one line to your shell's startup file and `keysafe` sets up your secrets in every new shell, with completions for your profiles and secrets.

## Requirements

- macOS (Keychain) or Linux (Secret Service)
- [1Password CLI](https://developer.1password.com/docs/cli/get-started/) (`op`)
- OpenSSH (`ssh-add`) for SSH keys

## Installation

**Nix:**

```bash
nix profile install github:keysafe-dev/keysafe
```

**Cargo:**

```bash
cargo install --git https://github.com/keysafe-dev/keysafe
```

**Prebuilt:** download `keysafe-<system>` from the [latest release](https://github.com/keysafe-dev/keysafe/releases/latest).

## Configuration

Create a starter config, then add your secrets:

```bash
keysafe config init    # writes ~/.config/keysafe/config.yml (or $XDG_CONFIG_HOME/keysafe/config.yml)
keysafe config edit    # opens it in $VISUAL or $EDITOR, and checks it when you close the editor
keysafe config path    # shows which config file is used, and why
```

A complete config looks like this:

```yaml
version: 1

profiles:
  - name: personal
    provider:
      type: 1password
      account: my.1password.com
    secrets:
      - kind: env
        name: GITHUB_TOKEN
        path: op://Personal/GitHub/Secrets/GITHUB_TOKEN

      - kind: ssh
        name: personal-key
        path: op://Private/SSH Key/private key?ssh-format=openssh

      - kind: file
        name: GOOGLE_APPLICATION_CREDENTIALS
        path: op://Personal/GCP/service-account-json

  - name: work
    provider:
      type: 1password
      account: team.1password.com
    secrets:
      - kind: env
        name: MYAPP_API_KEY
        path: op://Infra/Prod/API_KEY
```

See [config.example.yml](config.example.yml) for a complete annotated example. To find an `op://` path, right-click an item in the 1Password desktop app and select **Copy Secret Reference**. Append `?ssh-format=openssh` for SSH keys.

Each profile reads its secrets from one `provider`. Today that's `type: 1password`, with an optional `account`: the account to use, as `op --account` takes it (a sign-in address, an email address or an account ID). Without it, the 1Password CLI's default account is used.

Commands use the profile marked `default: true`, or the first profile, when you don't pass `-p`.

Secret names of `env` and `file` secrets must be valid environment variable names; SSH key names can be any label.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYSAFE_CONFIG_FILE` | `$XDG_CONFIG_HOME/keysafe/config.yml` (`~/.config/keysafe/config.yml`) | Config file (`--config`) |
| `KEYSAFE_STATE_DIR` | `$XDG_STATE_HOME/keysafe` (`~/.local/state/keysafe`) | Records which profiles were loaded (`--state-dir`) |
| `KEYSAFE_DEFAULT_PROFILE` | the profile marked `default: true`, or the first one | Profile used when none is given (`-p`) |

## Shell integration

Add to `~/.zshrc`:

```zsh
eval "$(keysafe init zsh)"
```

or to `~/.bashrc`:

```bash
eval "$(keysafe init bash)"
```

This defines a `keysafe` shell function, so `load`, `unload` and `export` change your current shell. On every new shell, it also:

- exports the cached secrets of the profiles you loaded before, from the keychain only, without contacting 1Password (`init zsh --no-export` turns this off),
- completes commands, options, profile names and secret names,
- removes the files of file secrets when the shell exits.

## Usage

```
Usage: keysafe <COMMAND>

Commands:
  load     Load secrets of a profile into the current shell.
  unload   Unload secrets of a profile from the current shell.
  read     Print the value of a secret.
  export   Export the environment and file secrets of a profile as shell statements.
  exec     Execute a command with the secrets of a profile in its environment.
  status   Show what is loaded: secrets in this shell, SSH keys in the agent, exported profiles.
  doctor   Check the setup and say how to fix problems.
  profile  List, show and clear profiles.
  config   Create, edit and locate the config file.
  init     Print the shell integration script for zsh or bash.
```

### Loading secrets

`load` puts secrets in place: environment secrets are exported, file secrets are written to private files whose paths are exported, and SSH keys are added to ssh-agent.

```bash
keysafe load -p work                  # every secret of the profile
keysafe load -p work -e 8h            # ... with SSH keys that expire after 8 hours
keysafe load GITHUB_TOKEN             # one secret of the default profile
keysafe load github-work -e 4h        # one SSH key
```

Loading a whole profile records it, so its cached secrets are exported in every new shell. Loading individual secrets doesn't.

`unload` undoes `load`: it unsets the variables, deletes the files of file secrets and removes the SSH keys keysafe added from ssh-agent.

```bash
keysafe unload -p work                # the whole profile; new shells no longer get it either
keysafe unload GITHUB_TOKEN           # one secret
```

The cached secrets stay in the keychain, so loading again is instant. `keysafe profile clear` deletes them.

### Reading and running

```bash
keysafe read GITHUB_TOKEN               # print a value (SSH keys are never printed)
keysafe exec -p work -- terraform plan  # run one command with the secrets; files are removed afterwards
keysafe export -p work --format json    # the secrets as a JSON object
```

Without the shell integration, for example in scripts, `load` and `export` print `export` statements to evaluate yourself, since a program can't change the environment of the shell that started it:

```bash
eval "$(keysafe export -p work)"
```

Add `--refresh` (`-r`) to `load`, `read`, `export` or `exec` to bypass the cache and fetch from 1Password again.

### Status

```bash
keysafe status                   # every profile: variables set in this shell, SSH keys and their expiry
keysafe status -p work           # one profile
```

`status` never prints values. It also tells you whether the shell integration is active.

### Profiles

```bash
keysafe profile list          # profile names
keysafe profile show work     # provider, secrets and whether it's exported in new shells (never values)
keysafe profile clear work    # delete its cached secrets and forget it was loaded
```

## How It Works

1. **Configuration**: profiles map secret names to `op://` references.
2. **1Password CLI**: secrets are fetched with `op read` when they aren't cached, so `op` can still ask for authorization.
3. **Keychain cache**: values are stored as generic passwords, service `keysafe.<profile>`, account `<secret name>`. Loaded profiles are recorded in `<state dir>/<profile>.metadata`.
4. **Output**: `export` statements single-quote every value, so quotes, `$`, backticks and newlines survive `eval` unchanged. Under the shell integration they travel on file descriptor 3, so values, JSON, help and errors still go straight to the terminal.
5. **SSH agent**: keys are piped to `ssh-add -` with your expiration. A key the agent already holds is left alone unless you pass `--refresh`.
6. **File secrets** are written to `--runtime-dir` when given, otherwise to a private temporary directory: the shell integration removes it when the shell exits, `exec` once the command exits, and otherwise you are told to remove it.

### Coming from zsh-op

keysafe picks up where the zsh-op plugin left off:

- With no config at the new location, `~/.config/op/config.yml` is used, with a hint to move it.
- Profiles recorded in `~/.cache/op` count as loaded until you load them again.
- Secrets cached under `op-secrets-<profile>` move to `keysafe.<profile>` the first time they are read; the old items are deleted.

## Troubleshooting

Start with `keysafe doctor`. It checks the config, the 1Password CLI and your accounts, the keychain, ssh-agent and the shell integration, without prompting for anything, and says how to fix each problem:

```
✓ Config: /Users/me/.config/keysafe/config.yml (the default location), 2 profile(s)
✗ 1password (work): op does not know account team.1password.com (run: op account add)
✓ Keychain: reachable
✓ SSH agent: running, 1 key(s)
! Shell integration: not active in this shell (add `eval "$(keysafe init zsh)"` to ~/.zshrc, or `init bash` to ~/.bashrc)
```

**"not signed in to 1Password account"**: run `op signin --account my.1password.com`.

**macOS asks to allow `keysafe` access to the keychain**: secrets cached by other programs (for example older zsh-op versions, which used `/usr/bin/security`) need your approval once per item. Choose **Always Allow**. Locally built binaries are not signed with a stable identity, so the prompt can come back after an upgrade. Alternatively, run `keysafe profile clear <profile>` and then `keysafe load -r -p <profile>` to re-cache the secrets.

**"SSH agent is not running"**: start one with `eval $(ssh-agent)`.

## License

[MIT](LICENSE)

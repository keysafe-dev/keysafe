# secret-env

> Load 1Password secrets into your shell: cached in the system keychain, exported as environment variables or files, and added to ssh-agent.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![CI](https://github.com/secret-env/secret-env/actions/workflows/ci.yml/badge.svg)](https://github.com/secret-env/secret-env/actions/workflows/ci.yml)

`secret-env` reads a YAML config of profiles, fetches each secret from 1Password on first use, and caches it in the macOS Keychain or the Linux Secret Service. After that, secrets come from the keychain: your shell starts without waiting for 1Password or asking for Touch ID.

- **Environment secrets** are printed as shell-quoted `export` statements (or JSON).
- **File secrets** are written to private `0600` files, and their path is exported.
- **SSH keys** are added to ssh-agent with an expiration, piped through `ssh-add` without touching the disk.
- Secrets never appear in process arguments.

Add one line to your shell's startup file and `secret-env` sets up your secrets in every new shell, with completions for your profiles and secrets.

## Requirements

- macOS (Keychain) or Linux (Secret Service)
- [1Password CLI](https://developer.1password.com/docs/cli/get-started/) (`op`)
- OpenSSH (`ssh-add`) for SSH keys

## Installation

**Nix:**

```bash
nix profile install github:secret-env/secret-env
```

**Cargo:**

```bash
cargo install --git https://github.com/secret-env/secret-env
```

**Prebuilt:** download `secret-env-<system>` from the [latest release](https://github.com/secret-env/secret-env/releases/latest).

## Configuration

Create `~/.config/secret-env/config.yml` (or `$XDG_CONFIG_HOME/secret-env/config.yml`):

```yaml
version: 1

accounts:
  - name: personal
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
    account: team.1password.com
    secrets:
      - kind: env
        name: MYAPP_API_KEY
        path: op://Infra/Prod/API_KEY
```

See [config.example.yml](config.example.yml) for a complete annotated example. To find an `op://` path, right-click an item in the 1Password desktop app and select **Copy Secret Reference**. Append `?ssh-format=openssh` for SSH keys.

Each account is a **profile**. Secret names of `env` and `file` secrets must be valid environment variable names; SSH key names can be any label.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_ENV_CONFIG_FILE` | `$XDG_CONFIG_HOME/secret-env/config.yml` (`~/.config/secret-env/config.yml`) | Config file (`--config`) |
| `SECRET_ENV_STATE_DIR` | `$XDG_STATE_HOME/secret-env` (`~/.local/state/secret-env`) | Records which profiles were loaded (`--state-dir`) |
| `SECRET_ENV_DEFAULT_PROFILE` | `personal` | Profile used when none is given (`-p`) |

## Shell integration

Add to `~/.zshrc`:

```zsh
eval "$(secret-env init zsh)"
```

or to `~/.bashrc`:

```bash
eval "$(secret-env init bash)"
```

This defines a `secret-env` shell function, so `load` and `export` apply secrets to your current shell. On every new shell, it also:

- exports the cached secrets of the profiles you loaded before, from the keychain only, without contacting 1Password (`init zsh --no-export` turns this off),
- completes commands, options, profile names and secret names,
- removes the files of file secrets when the shell exits.

## Usage

```
Usage: secret-env <COMMAND>

Commands:
  load     Load secrets of a profile into the current shell.
  read     Print the value of a secret.
  export   Export the environment and file secrets of a profile as shell statements.
  exec     Execute a command with the secrets of a profile in its environment.
  profile  List, show and clear profiles.
  init     Print the shell integration script for zsh or bash.
```

### Loading secrets

`load` puts secrets in place: environment secrets are exported, file secrets are written to private files whose paths are exported, and SSH keys are added to ssh-agent.

```bash
secret-env load -p work                  # every secret of the profile
secret-env load -p work -e 8h            # ... with SSH keys that expire after 8 hours
secret-env load GITHUB_TOKEN             # one secret of the default profile
secret-env load github-work -e 4h        # one SSH key
```

Loading a whole profile records it, so its cached secrets are exported in every new shell. Loading individual secrets doesn't.

### Reading and running

```bash
secret-env read GITHUB_TOKEN               # print a value (SSH keys are never printed)
secret-env exec -p work -- terraform plan  # run one command with the secrets; files are removed afterwards
secret-env export -p work --format json    # the secrets as a JSON object
```

Without the shell integration, for example in scripts, `load` and `export` print `export` statements to evaluate yourself, since a program can't change the environment of the shell that started it:

```bash
eval "$(secret-env export -p work)"
```

Add `--refresh` (`-r`) to `load`, `read`, `export` or `exec` to bypass the cache and fetch from 1Password again.

### Profiles

```bash
secret-env profile list          # profile names
secret-env profile show work     # account, secrets and whether it was loaded (never values)
secret-env profile clear work    # delete its cached secrets and forget it was loaded
```

## How It Works

1. **Configuration**: profiles map secret names to `op://` references.
2. **1Password CLI**: secrets are fetched with `op read` when they aren't cached, so `op` can still ask for authorization.
3. **Keychain cache**: values are stored as generic passwords, service `secret-env.<profile>`, account `<secret name>`. Loaded profiles are recorded in `<state dir>/<profile>.metadata`.
4. **Output**: `export` statements single-quote every value, so quotes, `$`, backticks and newlines survive `eval` unchanged. Under the shell integration they travel on file descriptor 3, so values, JSON, help and errors still go straight to the terminal.
5. **SSH agent**: keys are piped to `ssh-add -` with your expiration. A key the agent already holds is left alone unless you pass `--refresh`.
6. **File secrets** are written to `--runtime-dir` when given, otherwise to a private temporary directory: the shell integration removes it when the shell exits, `exec` once the command exits, and otherwise you are told to remove it.

### Coming from zsh-op

secret-env picks up where the zsh-op plugin left off:

- With no config at the new location, `~/.config/op/config.yml` is used, with a hint to move it.
- Profiles recorded in `~/.cache/op` count as loaded until you load them again.
- Secrets cached under `op-secrets-<profile>` move to `secret-env.<profile>` the first time they are read; the old items are deleted.

## Troubleshooting

**"not signed in to 1Password account"**: run `op signin --account my.1password.com`.

**macOS asks to allow `secret-env` access to the keychain**: secrets cached by other programs (for example older zsh-op versions, which used `/usr/bin/security`) need your approval once per item. Choose **Always Allow**. Locally built binaries are not signed with a stable identity, so the prompt can come back after an upgrade. Alternatively, run `secret-env profile clear <profile>` and then `secret-env load -r -p <profile>` to re-cache the secrets.

**"SSH agent is not running"**: start one with `eval $(ssh-agent)`.

## License

[MIT](LICENSE)

# secret-env

> Load 1Password secrets into your shell: cached in the system keychain, exported as environment variables or files, and added to ssh-agent.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![CI](https://github.com/secret-env/secret-env/actions/workflows/ci.yml/badge.svg)](https://github.com/secret-env/secret-env/actions/workflows/ci.yml)

`secret-env` reads a YAML config of profiles, fetches each secret from 1Password on first use, and caches it in the macOS Keychain or the Linux Secret Service. After that, secrets come from the keychain: your shell starts without waiting for 1Password or asking for Touch ID.

- **Environment secrets** are printed as shell-quoted `export` statements (or JSON).
- **File secrets** are written to private `0600` files, and their path is exported.
- **SSH keys** are added to ssh-agent with an expiration, piped through `ssh-add` without touching the disk.
- Secrets never appear in process arguments.

For zsh, the [zsh-op](https://github.com/zsh-contrib/zsh-op) plugin wraps `secret-env` with the `op-shell` and `op-secret` commands, completions, and automatic export on shell startup.

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

Create `~/.config/op/config.yml`:

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
| `SECRET_ENV_CONFIG_FILE` | `~/.config/op/config.yml` | Config file location (`--config`) |
| `SECRET_ENV_CACHE_DIR` | `~/.cache/op` | Directory recording loaded profiles (`--cache-dir`) |
| `SECRET_ENV_DEFAULT_PROFILE` | `personal` | Profile used when none is given |

The defaults are shared with zsh-op, so both use the same config and cache.

## Usage

```
Usage: secret-env <COMMAND>

Commands:
  inspect  Inspect and display the configured profiles, their secrets and their cache state.
  list     List profile names, or the secret names of a profile, one per line.
  shell    Set up the shell environment with all secrets from a profile.
  secret   Load an individual secret on demand.
  export   Export the environment and file secrets of a profile as shell statements.
  exec     Execute a command with the secrets of a profile in its environment.
  clear    Clear the cached secrets of a profile.
```

A program can't change the environment of the shell that started it, so commands that set variables print `export` statements for your shell to `eval`:

```bash
eval "$(secret-env shell work -e 8h)"      # env + file secrets, SSH keys with 8h expiration
eval "$(secret-env export -p work)"        # env + file secrets only
eval "$(secret-env secret -x GITHUB_TOKEN)" # a single secret
```

Other commands:

```bash
secret-env exec -p work -- terraform plan  # run one command with the secrets; files are removed afterwards
secret-env export -p work --format json    # the secrets as a JSON object
secret-env secret GITHUB_TOKEN             # print a value
secret-env secret github-work -e 4h        # add one SSH key to ssh-agent
secret-env inspect                         # profiles, secrets and cache state (never values)
secret-env clear -p work                   # delete the cached secrets of a profile
```

Add `--refresh` (`-r`) to `shell`, `secret`, `export` or `exec` to bypass the cache and fetch from 1Password again.

`export --all --cached` exports every previously loaded profile from the keychain only, without contacting 1Password. This is what zsh-op runs on shell startup.

File secrets are written to `--runtime-dir` when given. Otherwise `secret-env` creates a private temporary directory and tells you to remove it when done; `exec` removes its own once the command exits.

## How It Works

1. **Configuration**: profiles map secret names to `op://` references.
2. **1Password CLI**: secrets are fetched with `op read` when they aren't cached, so `op` can still ask for authorization.
3. **Keychain cache**: values are stored as generic passwords, service `op-secrets-<profile>`, account `<secret name>`. Loaded profiles are recorded in `<cache dir>/<profile>.metadata`.
4. **Output**: `export` statements single-quote every value, so quotes, `$`, backticks and newlines survive `eval` unchanged.
5. **SSH agent**: keys are piped to `ssh-add -` with your expiration. A key the agent already holds is left alone unless you pass `--refresh`.

## Troubleshooting

**"not signed in to 1Password account"**: run `op signin --account my.1password.com`.

**macOS asks to allow `secret-env` access to the keychain**: secrets cached by other programs (for example older zsh-op versions, which used `/usr/bin/security`) need your approval once per item. Choose **Always Allow**. Locally built binaries are not signed with a stable identity, so the prompt can come back after an upgrade. Alternatively, run `secret-env clear -p <profile>` and then `secret-env shell -r <profile>` to re-cache the secrets.

**"SSH agent is not running"**: start one with `eval $(ssh-agent)`.

## License

[MIT](LICENSE)

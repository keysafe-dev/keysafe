# secret-env shell integration for zsh
#
# Add to ~/.zshrc:
#
#   eval "$(secret-env init zsh)"

typeset -g _SECRET_ENV_BIN={{bin}}

# Wrap the binary, so that `shell`, `export` and `secret --export` change the
# current shell. The binary writes the shell statements to fd 3, which is
# captured and evaluated; everything else (values, JSON, help, errors) goes
# straight to the terminal.
secret-env() {
    case "$1" in
    shell | export | secret) ;;
    *)
        command "$_SECRET_ENV_BIN" "$@"
        return
        ;;
    esac

    # Reuse the runtime directory of this shell, if it has one yet. (No comments
    # inside the $(...) below: bash 3.2 misparses them.)
    local statements rc
    {
        statements="$(
            [[ -n "${_SECRET_ENV_RUNTIME_DIR-}" ]] &&
                export SECRET_ENV_RUNTIME_DIR="$_SECRET_ENV_RUNTIME_DIR"
            SECRET_ENV_EVAL=zsh command "$_SECRET_ENV_BIN" "$@" 3>&1 1>&4 4>&-
        )"
        rc=$?
    } 4>&1
    eval "$statements"

    return $rc
}

# Remove the file secrets of this shell when it exits. The directory is not
# exported, so child shells create (and remove) their own.
_secret_env_cleanup() {
    [[ -n "${_SECRET_ENV_RUNTIME_DIR-}" ]] || return 0

    rm -rf -- "$_SECRET_ENV_RUNTIME_DIR"
    unset _SECRET_ENV_RUNTIME_DIR
}

autoload -Uz add-zsh-hook
add-zsh-hook zshexit _secret_env_cleanup

# Completions, generated from the command line definition and the profiles
# and secrets in the config.
_secret_env_completion() {
{{completion}}
}

# Register the completions once compinit has run, which may be later in
# ~/.zshrc than this script.
_secret_env_compdef() {
    (( $+functions[compdef] )) || return 1

    _secret_env_completion
    add-zsh-hook -d precmd _secret_env_compdef
}

_secret_env_compdef || add-zsh-hook precmd _secret_env_compdef

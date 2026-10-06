# secret-env shell integration for bash
#
# Add to ~/.bashrc:
#
#   eval "$(secret-env init bash)"

_SECRET_ENV_BIN={{bin}}

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
            SECRET_ENV_EVAL=bash command "$_SECRET_ENV_BIN" "$@" 3>&1 1>&4 4>&-
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

# bash has a single EXIT trap, so run the cleanup before the one that is
# already set instead of replacing it.
_secret_env_trap() {
    eval "set -- $(trap -p EXIT)"
    local previous="${3-}"

    case "$previous" in
    *_secret_env_cleanup*) ;;
    *) trap -- "_secret_env_cleanup${previous:+; $previous}" EXIT ;;
    esac
}

_secret_env_trap

# Completions, generated from the command line definition and the profiles
# and secrets in the config. Builds of bash without readline, like the
# non-interactive ones some distributions ship, have no `complete`.
if type complete >/dev/null 2>&1; then
{{completion}}
fi

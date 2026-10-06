# keysafe shell integration for bash
#
# Add to ~/.bashrc:
#
#   eval "$(keysafe init bash)"

_KEYSAFE_BIN={{bin}}

# Wrap the binary, so that `load`, `unload` and `export` change the current
# shell. The binary writes the shell statements to fd 3, which is captured
# and evaluated; everything else (values, JSON, help, errors) goes straight
# to the terminal.
keysafe() {
    case "$1" in
    load | unload | export) ;;
    *)
        KEYSAFE_SHELL=bash command "$_KEYSAFE_BIN" "$@"
        return
        ;;
    esac

    # Reuse the runtime directory of this shell, if it has one yet. (No comments
    # inside the $(...) below: bash 3.2 misparses them.)
    local statements rc
    {
        statements="$(
            [[ -n "${_KEYSAFE_RUNTIME_DIR-}" ]] &&
                export KEYSAFE_RUNTIME_DIR="$_KEYSAFE_RUNTIME_DIR"
            KEYSAFE_EVAL=bash KEYSAFE_SHELL=bash command "$_KEYSAFE_BIN" "$@" 3>&1 1>&4 4>&-
        )"
        rc=$?
    } 4>&1
    eval "$statements"

    return $rc
}

# Remove the file secrets of this shell when it exits. The directory is not
# exported, so child shells create (and remove) their own.
_keysafe_cleanup() {
    [[ -n "${_KEYSAFE_RUNTIME_DIR-}" ]] || return 0

    rm -rf -- "$_KEYSAFE_RUNTIME_DIR"
    unset _KEYSAFE_RUNTIME_DIR
}

# bash has a single EXIT trap, so run the cleanup before the one that is
# already set instead of replacing it.
_keysafe_trap() {
    eval "set -- $(trap -p EXIT)"
    local previous="${3-}"

    case "$previous" in
    *_keysafe_cleanup*) ;;
    *) trap -- "_keysafe_cleanup${previous:+; $previous}" EXIT ;;
    esac
}

_keysafe_trap

# Completions, generated from the command line definition and the profiles
# and secrets in the config. Builds of bash without readline, like the
# non-interactive ones some distributions ship, have no `complete`.
if type complete >/dev/null 2>&1; then
{{completion}}
fi

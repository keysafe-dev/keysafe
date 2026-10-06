# keysafe shell integration for zsh
#
# Add to ~/.zshrc:
#
#   eval "$(keysafe init zsh)"

typeset -g _KEYSAFE_BIN={{bin}}

# Wrap the binary, so that `load`, `unload` and `export` change the current
# shell. The binary writes the shell statements to fd 3, which is captured
# and evaluated; everything else (values, JSON, help, errors) goes straight
# to the terminal.
keysafe() {
    case "$1" in
    load | unload | export) ;;
    *)
        KEYSAFE_SHELL=zsh command "$_KEYSAFE_BIN" "$@"
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
            KEYSAFE_EVAL=zsh KEYSAFE_SHELL=zsh command "$_KEYSAFE_BIN" "$@" 3>&1 1>&4 4>&-
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

autoload -Uz add-zsh-hook
add-zsh-hook zshexit _keysafe_cleanup

# Completions, generated from the command line definition and the profiles
# and secrets in the config.
_keysafe_completion() {
{{completion}}
}

# Register the completions once compinit has run, which may be later in
# ~/.zshrc than this script.
_keysafe_compdef() {
    (( $+functions[compdef] )) || return 1

    _keysafe_completion
    add-zsh-hook -d precmd _keysafe_compdef
}

_keysafe_compdef || add-zsh-hook precmd _keysafe_compdef

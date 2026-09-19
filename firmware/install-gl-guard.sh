#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${HS_FIRMWARE_ROOT:-}
BACKUPS=${HS_BACKUPS:-/root/hotswapper/firmware-backups}
CATALOG="$DIR/gl-targets.tsv"
WORK="${HS_PATCH_WORK:-/tmp}/hotswapper-patch.$$"
OLD_RTP=5c4b26eebdd3cdb6876b7b5e9f48901d8061b525837c1d879f0d059d856f150c
hash() { sha256sum "$1" | awk '{print $1}'; }
syntax() {
    case "$1" in
        *.lua) HS_LUA_FILE="$1" lua -e 'assert(loadfile(os.getenv("HS_LUA_FILE")))';;
        *) sh -n "$1";;
    esac
}
check() {
    local id path stock patched actual
    while IFS="$(printf '\t')" read -r id path stock patched; do
        [ -f "$ROOT$path" ] && [ ! -L "$ROOT$path" ] || return 1
        actual=$(hash "$ROOT$path")
        [ "$actual" = "$patched" ] && continue
        [ "${1:-}" != installed ] || return 1
        [ "$actual" = "$stock" ] || { [ "$id" = rtp ] && [ "$actual" = "$OLD_RTP" ]; } || return 1
    done < "$CATALOG"
}
cleanup() {
    local status=$? id path actual patched
    trap - EXIT
    if [ -f "$WORK/changes" ]; then
        while IFS="$(printf '\t')" read -r id path actual patched; do
            rm -f "$ROOT$path.hotswap-new-$$"
            [ "$status" = 0 ] && continue
            # Restore only bytes written by this attempt; never overwrite an outsider.
            [ ! -L "$ROOT$path" ] && [ "$(hash "$ROOT$path")" = "$patched" ] || continue
            [ "$(hash "$BACKUPS/$actual")" = "$actual" ] || continue
            [ ! -e "$ROOT$path.hotswap-restore-$$" ] && [ ! -L "$ROOT$path.hotswap-restore-$$" ] || continue
            cp -p "$BACKUPS/$actual" "$ROOT$path.hotswap-restore-$$" &&
                mv -f "$ROOT$path.hotswap-restore-$$" "$ROOT$path"
        done < "$WORK/changes"
    fi
    rm -rf "$WORK"
    exit "$status"
}
install() {
    local id path stock patched actual input output
    check || { echo 'Unsupported GL coordination target; nothing changed.' >&2; return 1; }
    check installed && return 0
    if [ -z "$ROOT" ]; then
        . "$DIR/gl-coordination.sh"
        hs_daemon_alive && { echo 'Stop Hotswapper before changing firmware.' >&2; return 1; }
        hs_lock || return 1
    fi
    umask 077
    mkdir "$WORK"
    trap cleanup EXIT
    [ ! -L "$BACKUPS" ] || return 1
    mkdir -p "$BACKUPS"
    # Validate every output before replacing the first target.
    while IFS="$(printf '\t')" read -r id path stock patched; do
        actual=$(hash "$ROOT$path")
        [ "$actual" != "$patched" ] || continue
        input="$ROOT$path"
        if [ "$id" = rtp ] && [ "$actual" = "$OLD_RTP" ]; then
            input="$WORK/rtp.stock"
            awk '
                $0 == "cmd=\"$1\";shift" {print; after=1; next}
                after && $0 == "" {next}
                after && $0 == "# hotswapper GL reconciliation guard v1" {skip=1; after=0; next}
                skip {if ($0 == "fi") skip=0; next}
                {after=0; print}
            ' "$ROOT$path" > "$input"
            [ "$(hash "$input")" = "$stock" ] || return 1
        fi
        output="$WORK/$id"
        awk -v target="$id" -f "$DIR/gl-patches.awk" "$input" > "$output"
        [ "$(hash "$output")" = "$patched" ] || return 1
        case "$path" in *.lua) cp "$output" "$output.lua"; syntax "$output.lua";; *) syntax "$output";; esac
        [ ! -L "$BACKUPS/$actual" ] || return 1
        [ -f "$BACKUPS/$actual" ] || cp -p "$ROOT$path" "$BACKUPS/$actual"
        [ "$(hash "$BACKUPS/$actual")" = "$actual" ] || return 1
        printf '%s\t%s\t%s\t%s\n' "$id" "$path" "$actual" "$patched" >> "$WORK/changes"
    done < "$CATALOG"
    [ -f "$WORK/changes" ] || return 0
    while IFS="$(printf '\t')" read -r id path actual patched; do
        [ ! -L "$ROOT$path" ] && [ "$(hash "$ROOT$path")" = "$actual" ] || return 1
        # Keep replacement on the target filesystem and preserve its permissions.
        [ ! -e "$ROOT$path.hotswap-new-$$" ] && [ ! -L "$ROOT$path.hotswap-new-$$" ] || return 1
        cp -p "$ROOT$path" "$ROOT$path.hotswap-new-$$"
        cat "$WORK/$id" > "$ROOT$path.hotswap-new-$$"
        mv -f "$ROOT$path.hotswap-new-$$" "$ROOT$path"
        [ "$(hash "$ROOT$path")" = "$patched" ] || return 1
    done < "$WORK/changes"
}
case "${1:---check}" in
    --check) check;;
    --verify) check installed;;
    --install) install;;
    *) echo 'Usage: install-gl-guard.sh [--check|--verify|--install]' >&2; exit 2;;
esac

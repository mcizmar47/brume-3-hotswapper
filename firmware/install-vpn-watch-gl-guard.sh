#!/bin/sh
set -eu

TARGET="${VPN_WATCH_RTP2_TARGET:-/usr/bin/rtp2.sh}"
BACKUP_DIR="/root/vpn-watch-firmware-backups"
MARKER="# vpn-watch GL reconciliation guard v1"
ANCHOR='cmd="$1";shift'

usage() {
    echo "Usage: $0 [--check|--install|--restore BACKUP]"
}

count_anchor() {
    grep -Fxc "$ANCHOR" "$TARGET" 2>/dev/null || true
}

check_target() {
    [ -f "$TARGET" ] || { echo "ERROR: $TARGET not found" >&2; return 1; }
    if grep -Fq "$MARKER" "$TARGET"; then
        echo "PATCHED: $TARGET already contains vpn-watch guard v1"
        return 0
    fi
    c="$(count_anchor)"
    [ "$c" = "1" ] || {
        echo "MISMATCH: expected exactly one anchor: $ANCHOR" >&2
        echo "Found: $c" >&2
        return 1
    }
    echo "MATCH: current firmware contains the expected unique insertion anchor"
    sha256sum "$TARGET" 2>/dev/null || true
}

install_patch() {
    check_target
    if grep -Fq "$MARKER" "$TARGET"; then
        exit 0
    fi

    mkdir -p "$BACKUP_DIR"
    hash="$(sha256sum "$TARGET" | awk '{print $1}')"
    backup="$BACKUP_DIR/rtp2.sh.$hash"
    [ -f "$backup" ] || cp -p "$TARGET" "$backup"
    echo "Backup: $backup"

    tmp="/tmp/rtp2.sh.vpn-watch.$$"
    awk -v anchor="$ANCHOR" '
        BEGIN { inserted=0 }
        {
            print
            if ($0 == anchor) {
                print ""
                print "# vpn-watch GL reconciliation guard v1"
                print "# During vpn-watch fast promotion, defer rtp2 reconciliation so GL cannot"
                print "# rebuild route-policy/firewall state underneath the transaction."
                print "VPN_WATCH_GUARD_DIR=\"/tmp/vpn-watch\""
                print "VPN_WATCH_GUARD_FLAG=\"${VPN_WATCH_GUARD_DIR}/promotion-in-progress\""
                print "VPN_WATCH_GUARD_PENDING=\"${VPN_WATCH_GUARD_DIR}/gl-reconcile-pending\""
                print "vpn_watch_guard_active() {"
                print "    [ -f \"$VPN_WATCH_GUARD_FLAG\" ] || return 1"
                print "    guard_pid=\"$(sed -n '\''s/^pid=//p'\'' \"$VPN_WATCH_GUARD_FLAG\" 2>/dev/null | head -n1)\""
                print "    guard_started=\"$(sed -n '\''s/^started=//p'\'' \"$VPN_WATCH_GUARD_FLAG\" 2>/dev/null | head -n1)\""
                print "    guard_now=\"$(date +%s)\""
                print "    echo \"$guard_pid\" | grep -Eq '\''^[0-9]+$'\'' || { rm -f \"$VPN_WATCH_GUARD_FLAG\"; return 1; }"
                print "    echo \"$guard_started\" | grep -Eq '\''^[0-9]+$'\'' || { rm -f \"$VPN_WATCH_GUARD_FLAG\"; return 1; }"
                print "    echo \"$guard_now\" | grep -Eq '\''^[0-9]+$'\'' || { rm -f \"$VPN_WATCH_GUARD_FLAG\"; return 1; }"
                print "    guard_age=$((guard_now - guard_started))"
                print "    if [ \"$guard_age\" -ge 0 ] 2>/dev/null && [ \"$guard_age\" -le 5 ] 2>/dev/null && kill -0 \"$guard_pid\" 2>/dev/null; then"
                print "        return 0"
                print "    fi"
                print "    rm -f \"$VPN_WATCH_GUARD_FLAG\""
                print "    return 1"
                print "}"
                print "if vpn_watch_guard_active; then"
                print "    mkdir -p \"$VPN_WATCH_GUARD_DIR\""
                print "    printf '\''%s pid=%s cmd=%s args=%s\\n'\'' \"$(date +%s)\" \"$$\" \"$cmd\" \"$*\" >> \"$VPN_WATCH_GUARD_PENDING\""
                print "    logger -t vpn-watch \"Deferred GL rtp2 reconciliation during fast promotion: cmd=$cmd\" 2>/dev/null || true"
                print "    exit 0"
                print "fi"
                inserted=1
            }
        }
        END { if (inserted != 1) exit 42 }
    ' "$TARGET" > "$tmp" || {
        rc=$?
        rm -f "$tmp"
        echo "ERROR: patch generation failed ($rc); firmware untouched" >&2
        exit 1
    }

    chmod --reference="$TARGET" "$tmp" 2>/dev/null || chmod 755 "$tmp"
    chown --reference="$TARGET" "$tmp" 2>/dev/null || true

    # Structural verification before touching firmware-owned file.
    grep -Fq "$MARKER" "$tmp" || { rm -f "$tmp"; echo "ERROR: marker missing from generated patch" >&2; exit 1; }
    [ "$(grep -Fc "$MARKER" "$tmp")" = "1" ] || { rm -f "$tmp"; echo "ERROR: marker not unique" >&2; exit 1; }
    sh -n "$tmp" || { rm -f "$tmp"; echo "ERROR: patched shell syntax invalid" >&2; exit 1; }

    cp "$tmp" "$TARGET"
    rm -f "$tmp"
    sync

    echo "INSTALLED: vpn-watch GL reconciliation guard v1"
    sha256sum "$TARGET" 2>/dev/null || true
    echo "Re-run '$0 --check' after any firmware update before reinstalling."
}

restore_backup() {
    backup="${1:-}"
    [ -n "$backup" ] || { echo "ERROR: provide backup path" >&2; exit 2; }
    [ -f "$backup" ] || { echo "ERROR: backup not found: $backup" >&2; exit 1; }
    sh -n "$backup" || { echo "ERROR: backup fails shell syntax check" >&2; exit 1; }
    cp "$backup" "$TARGET"
    sync
    echo "RESTORED: $TARGET from $backup"
}

case "${1:---check}" in
    --check) check_target ;;
    --install) install_patch ;;
    --restore) shift; restore_backup "${1:-}" ;;
    *) usage; exit 2 ;;
esac

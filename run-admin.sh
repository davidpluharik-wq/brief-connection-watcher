#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if (( EUID == 0 )); then
    exec /bin/bash "$SCRIPT_DIR/run.sh" "$@"
fi
if ! command -v pkexec >/dev/null; then
    printf "%s\n" "Administrator launch requires pkexec. Install your distribution's PolicyKit package." >&2
    exit 1
fi
if [[ -z "${DISPLAY:-}" ]]; then
    printf 'Administrator GUI launch needs an X11 display (DISPLAY is unset).\n' >&2
    exit 1
fi
env_args=("DISPLAY=$DISPLAY" "XAUTHORITY=${XAUTHORITY:-$HOME/.Xauthority}")
for key in HONEYPOT_INTERFACE HONEYPOT_IP HONEYPOT_HOSTAPD_CONF HONEYPOT_DNSMASQ_CONF; do
    if [[ -v "$key" ]]; then env_args+=("$key=${!key}"); fi
done
exec pkexec /usr/bin/env "${env_args[@]}" /bin/bash "$SCRIPT_DIR/run.sh" "$@"

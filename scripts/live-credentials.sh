#!/usr/bin/env bash
# Fill in or update the live-test credentials in ONE file,
# ~/.config/credprox-live/live.env (mode 600), without typing secrets on a command
# line or seeing them on screen.
#
#   ./scripts/live-credentials.sh           walk every variable; Enter keeps the current value
#   ./scripts/live-credentials.sh status    names, set or unset, and the file mode; never values
#
# Secret prompts are hidden (read -s). The GitHub App private key is asked for as a
# PEM file path and stored as base64. TENANT_ID can be filled from your az sign-in.
# Values are written with bash builtins only, so they never appear in a process list.
set -euo pipefail

dir="$HOME/.config/credprox-live"
file="$dir/live.env"
display="~/.config/credprox-live/live.env"

# name|vendor|kind   kind: plain (echoed input), secret (hidden), pem (file path), tenant
vars=(
    "TENANT_ID|graph, agenttokens, aca|tenant"
    "APP_ID|githubapp|plain"
    "INSTALLATION_ID|githubapp|plain"
    "PRIVATE_KEY_BASE64|githubapp|pem"
    "ANTHROPIC_API_KEY|aigateway|secret"
)

declare -A val=()
order=()
load() {
    [ -f "$file" ] || return 0
    local line k
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue;; esac
        k="${line%%=*}"
        [ "$k" = "$line" ] && continue
        [ -n "${val[$k]+x}" ] || order+=("$k")
        val[$k]="${line#*=}"
    done < "$file"
}

save() {
    umask 077
    mkdir -p "$dir"
    local tmp k
    tmp="$(mktemp "$dir/.live.env.XXXXXX")"
    {
        printf '# CredProx live-test credentials. Mode 600. Edit with scripts/live-credentials.sh.\n'
        for k in "${order[@]}"; do
            printf '%s=%s\n' "$k" "${val[$k]}"
        done
    } > "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$file"
}

set_val() { # name value
    [ -n "${val[$1]+x}" ] || order+=("$1")
    val[$1]="$2"
}

status() {
    if [ ! -f "$file" ]; then
        echo "$display does not exist yet; run ./scripts/live-credentials.sh"
        return 0
    fi
    echo "$display  mode $(stat -c '%a' "$file") (must be 600)"
    local spec name vendor
    for spec in "${vars[@]}"; do
        IFS='|' read -r name vendor _ <<< "$spec"
        if [ -n "${val[$name]:-}" ]; then
            printf '  %-20s set     (%s)\n' "$name" "$vendor"
        else
            printf '  %-20s unset   (%s)\n' "$name" "$vendor"
        fi
    done
}

load
if [ "${1:-}" = "status" ]; then
    status
    exit 0
fi
[ $# -eq 0 ] || { echo "usage: $0 [status]" >&2; exit 2; }

echo "Updating $display. Press Enter to keep a value as it is."
for spec in "${vars[@]}"; do
    IFS='|' read -r name vendor kind <<< "$spec"
    cur="unset"; [ -n "${val[$name]:-}" ] && cur="set"
    case "$kind" in
        plain)
            read -rp "$name ($vendor) [$cur]: " input
            [ -z "$input" ] || set_val "$name" "$input"
            ;;
        secret)
            read -rsp "$name ($vendor, hidden) [$cur]: " input; echo
            [ -z "$input" ] || set_val "$name" "$input"
            ;;
        pem)
            read -rp "$name ($vendor): path to the private-key .pem [$cur]: " input
            if [ -n "$input" ]; then
                input="${input/#\~/$HOME}"
                if [ -r "$input" ] && grep -q -- '-----BEGIN' "$input"; then
                    set_val "$name" "$(base64 -w0 "$input")"
                else
                    echo "  not a readable PEM file; $name left $cur"
                fi
            fi
            ;;
        tenant)
            read -rp "$name ($vendor): Enter keeps, 'az' reads it from your az sign-in, or paste it [$cur]: " input
            if [ "$input" = "az" ]; then
                t="$(az account show --query homeTenantId -o tsv 2>/dev/null || true)"
                if [ -n "$t" ]; then set_val "$name" "$t"; else echo "  az is not signed in; $name left $cur"; fi
            elif [ -n "$input" ]; then
                set_val "$name" "$input"
            fi
            ;;
    esac
done
unset input t
save
echo
status

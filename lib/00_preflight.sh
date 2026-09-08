#!/usr/bin/env bash
# 00_preflight.sh — sanity checks before anything runs
# all checks must pass or the script aborts
set -euo pipefail

PASS=0
FAIL=0
WARN_COUNT=0

RED='\\033[0;31m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'; RESET='\\033[0m'

pass() { echo -e "  ${GREEN}✓${RESET} $*"; (( PASS++ )) || true; }
fail() { echo -e "  ${RED}✗${RESET} $*"; (( FAIL++ )) || true; }
warn() { echo -e "  ${YELLOW}⚠${RESET} $*"; (( WARN_COUNT++ )) || true; }

echo ""
echo "  running preflight checks..."
echo "  ──────────────────────────────────────────"

# must be root
if [[ "${EUID}" -eq 0 ]]; then
    pass "running as root"
else
    fail "must be run as root (use: sudo bash harden.sh)"
fi

# check os — we only officially support ubuntu 22.04
if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "22.04" ]]; then
        pass "os: ubuntu 22.04 lts (${PRETTY_NAME})"
    elif [[ "${ID:-}" == "ubuntu" ]]; then
        warn "ubuntu ${VERSION_ID:-unknown} detected — tested on 22.04, proceed with caution"
    elif [[ "${ID:-}" == "debian" ]]; then
        warn "debian detected — most modules work but some package names may differ"
    else
        fail "unsupported os: ${PRETTY_NAME:-unknown}"
    fi
else
    fail "/etc/os-release not found — cannot determine os"
fi

# need internet to install packages
if curl -sf --max-time 5 https://archive.ubuntu.com > /dev/null 2>&1; then
    pass "internet: archive.ubuntu.com reachable"
else
    fail "no internet — required for package installation"
fi

# deploy pubkey must be set and not be the placeholder
if [[ -z "${DEPLOY_PUBKEY:-}" || "${DEPLOY_PUBKEY}" == *"CHANGE_THIS"* ]]; then
    fail "DEPLOY_PUBKEY not set in hardening.conf — required before disabling password auth"
else
    if echo "${DEPLOY_PUBKEY}" | grep -qE '^(ssh-|ecdsa-)'; then
        pass "DEPLOY_PUBKEY looks valid"
    else
        fail "DEPLOY_PUBKEY doesn't look like a valid ssh public key"
    fi
fi

# check the target ssh port isn't already taken by something else
if ss -tlnp 2>/dev/null | grep -q ":${SSH_PORT} "; then
    warn "port ${SSH_PORT} is already in use — ssh module will skip port change"
else
    pass "ssh port ${SSH_PORT} is free"
fi

# check all required tools are present
REQUIRED_CMDS=(apt-get systemctl ss ufw awk sed grep)
MISSING_CMDS=()
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "${cmd}" &>/dev/null; then
        MISSING_CMDS+=("${cmd}")
    fi
done

if [[ ${#MISSING_CMDS[@]} -eq 0 ]]; then
    pass "all required commands present"
else
    fail "missing commands: ${MISSING_CMDS[*]}"
fi

# warn if we've been here before — modules are idempotent but worth knowing
if [[ -f /etc/ssh/sshd_config.harden.bak ]]; then
    warn "backup /etc/ssh/sshd_config.harden.bak exists — server may have been hardened before"
    warn "re-running is safe but review the changes carefully"
fi

# note existing ufw state
UFW_STATUS=$(ufw status 2>/dev/null | head -1)
if echo "${UFW_STATUS}" | grep -q "Status: active"; then
    warn "ufw is already active — firewall module will add/verify rules, not reset"
else
    pass "ufw inactive — firewall module will configure from scratch"
fi

# need at least 500mb free to install packages
FREE_KB=$(df / --output=avail | tail -1 | tr -d ' ')
FREE_MB=$(( FREE_KB / 1024 ))
if [[ "${FREE_MB}" -ge 500 ]]; then
    pass "disk space: ${FREE_MB}mb free on /"
else
    fail "insufficient disk space: ${FREE_MB}mb free (need at least 500mb)"
fi

if [[ "${DRY_RUN}" == true ]]; then
    warn "dry-run mode: all subsequent checks are informational only"
fi

echo "  ──────────────────────────────────────────"
echo -e "  passed: ${GREEN}${PASS}${RESET}  failed: ${RED}${FAIL}${RESET}  warnings: ${YELLOW}${WARN_COUNT}${RESET}"
echo ""

log INFO "preflight: ${PASS} passed, ${FAIL} failed, ${WARN_COUNT} warnings"

if [[ "${FAIL}" -gt 0 ]]; then
    log ERROR "preflight failed — fix the issues above before continuing"
    exit 1
fi

echo "${PASS}" > /tmp/harden_preflight_pass
echo "${WARN_COUNT}" > /tmp/harden_preflight_warn

#!/usr/bin/env bash
# 02_firewall.sh — ufw configuration
# default-deny inbound, open only what we need
# ssh port is opened *before* ufw enable to avoid locking ourselves out
set -euo pipefail

run() {
    if [[ "${DRY_RUN}" == true ]]; then
        log DRY "would run: $*"
    else
        "$@"
    fi
}

if ! command -v ufw &>/dev/null; then
    log INFO "firewall: installing ufw..."
    run apt-get install -y ufw
else
    log INFO "firewall: ufw already installed"
fi

# reset to a clean slate so we don't accumulate stale rules on re-runs
if [[ "${DRY_RUN}" == false ]]; then
    ufw --force disable > /dev/null 2>&1 || true
    ufw --force reset  > /dev/null 2>&1
    log INFO "firewall: reset to clean state"
else
    log DRY "would reset ufw"
fi

run ufw default deny incoming
run ufw default allow outgoing
run ufw default deny forward || true  # may silently fail on kernels with forwarding disabled
log INFO "firewall: default policies set (deny in, allow out, deny forward)"

# open ssh port — if a source ip is specified, restrict to that
# using 'limit' instead of 'allow' gives us rate limiting (>6 connections/30s = banned)
# this replaces the plain allow rule — don't run both or you get duplicate entries
if [[ -n "${SSH_ALLOWED_IP:-}" ]]; then
    run ufw allow from "${SSH_ALLOWED_IP}" to any port "${SSH_PORT}" proto tcp \
        comment "ssh from ${SSH_ALLOWED_IP}"
    log INFO "firewall: ssh (port ${SSH_PORT}) restricted to ${SSH_ALLOWED_IP}"
else
    run ufw limit "${SSH_PORT}/tcp" comment "ssh rate-limited"
    log INFO "firewall: ssh (port ${SSH_PORT}) open with rate limiting"
fi

if [[ "${OPEN_HTTP:-true}" == true ]]; then
    run ufw allow 80/tcp comment "http"
    log INFO "firewall: http (80) open"
fi

if [[ "${OPEN_HTTPS:-true}" == true ]]; then
    run ufw allow 443/tcp comment "https"
    log INFO "firewall: https (443) open"
fi

if [[ -n "${EXTRA_OPEN_PORTS:-}" ]]; then
    for port in ${EXTRA_OPEN_PORTS}; do
        run ufw allow "${port}" comment "extra"
        log INFO "firewall: extra port ${port} open"
    done
fi

if [[ "${DRY_RUN}" == false ]]; then
    ufw --force enable
    log INFO "firewall: ufw enabled"

    ufw status verbose 2>&1 | while IFS= read -r line; do
        log INFO "  ${line}"
    done

    systemctl enable ufw > /dev/null 2>&1

    RULE_COUNT=$(ufw status | grep -c "ALLOW" || true)
    echo "${RULE_COUNT} rules active" > /tmp/harden_note_firewall
else
    log DRY "would enable ufw with ssh on ${SSH_PORT}, http, https"
fi

log INFO "firewall hardening complete"

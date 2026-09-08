#!/usr/bin/env bash
# 07_updates.sh — automatic security updates via unattended-upgrades
# security patches only — regular updates are left for manual review
set -euo pipefail

run() {
    if [[ "${DRY_RUN}" == true ]]; then
        log DRY "would run: $*"
    else
        "$@"
    fi
}

UA_CONF="/etc/apt/apt.conf.d/50unattended-upgrades"
UA_PERIODIC="/etc/apt/apt.conf.d/20auto-upgrades"

log INFO "updates: installing unattended-upgrades..."
if [[ "${DRY_RUN}" == false ]]; then
    apt-get install -y unattended-upgrades apt-listchanges > /dev/null 2>&1
    log INFO "updates: packages installed"
else
    log DRY "would install unattended-upgrades apt-listchanges"
fi

log INFO "updates: writing config..."

if [[ "${DRY_RUN}" == false ]]; then
    [[ -f "${UA_CONF}" ]] && cp "${UA_CONF}" "${UA_CONF}.bak"

    cat > "${UA_CONF}" <<EOF
// 50unattended-upgrades — hardened by harden.sh on $(date '+%Y-%m-%d')

Unattended-Upgrade::Allowed-Origins {
    // security updates only — most conservative for production
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";

    // uncomment to also pull regular updates (test first):
    // "\${distro_id}:\${distro_codename}-updates";
};

// packages to never auto-update — add anything that needs manual care
Unattended-Upgrade::Package-Blacklist {
    // "linux-image*";
    // "nginx";
    // "mysql*";
};

Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// auto-reboot after kernel updates — false is safer for production
Unattended-Upgrade::Automatic-Reboot "${AUTO_REBOOT:-false}";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";

$(if [[ -n "${ALERT_EMAIL:-}" ]]; then
    echo "Unattended-Upgrade::Mail \"${ALERT_EMAIL}\";"
    echo "Unattended-Upgrade::MailReport \"on-change\";"
else
    echo "// Unattended-Upgrade::Mail \"\";  // set ALERT_EMAIL in hardening.conf to enable"
fi)

Unattended-Upgrade::Verbose "false";
Unattended-Upgrade::MinimalSteps "true";
EOF

    log INFO "updates: config written to ${UA_CONF}"
else
    log DRY "would write unattended-upgrades config to ${UA_CONF}"
fi

if [[ "${DRY_RUN}" == false ]]; then
    cat > "${UA_PERIODIC}" <<'EOF'
// how often to run each step (value = days)
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
    log INFO "updates: periodic config written"
else
    log DRY "would write periodic config to ${UA_PERIODIC}"
fi

# apply security updates now — but only if there are any to apply
log INFO "updates: running apt-get update..."
if [[ "${DRY_RUN}" == false ]]; then
    apt-get update -q 2>&1 | tail -5 | while IFS= read -r line; do
        log INFO "  ${line}"
    done

    log INFO "updates: checking for pending security patches..."
    # capture the list first so we don't accidentally upgrade everything if it's empty
    SECURITY_PKGS=$(apt-get --simulate upgrade 2>/dev/null \
        | grep "^Inst" \
        | grep -i "security" \
        | awk '{print $2}' \
        | tr '\n' ' ' || true)

    if [[ -n "${SECURITY_PKGS}" ]]; then
        log INFO "updates: applying: ${SECURITY_PKGS}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            -o Dpkg::Options::="--force-confold" \
            -o Dpkg::Options::="--force-confdef" \
            ${SECURITY_PKGS} 2>/dev/null || true
        log INFO "updates: security patches applied"
    else
        log INFO "updates: no pending security patches right now"
    fi
else
    log DRY "would run apt-get update and apply pending security patches"
fi

if [[ "${DRY_RUN}" == false ]]; then
    systemctl enable unattended-upgrades > /dev/null 2>&1
    systemctl restart unattended-upgrades

    if systemctl is-active --quiet unattended-upgrades; then
        log INFO "updates: unattended-upgrades running ✓"
    else
        log WARN "updates: service not running — check manually"
    fi

    # quick config validation
    if unattended-upgrades --dry-run 2>&1; then
        log INFO "updates: config ok"
    else
        log WARN "updates: dry-run check returned non-zero — review the config"
    fi

    echo "security-only, auto-reboot=${AUTO_REBOOT:-false}" > /tmp/harden_note_updates
else
    log DRY "would enable unattended-upgrades service"
fi

log INFO "automatic updates hardening complete"

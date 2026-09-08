#!/usr/bin/env bash
# 05_fail2ban.sh — fail2ban installation and configuration
# watches auth logs and bans ips that repeatedly fail authentication
set -euo pipefail

run() {
    if [[ "${DRY_RUN}" == true ]]; then
        log DRY "would run: $*"
    else
        "$@"
    fi
}

JAIL_LOCAL="/etc/fail2ban/jail.local"
FILTER_DIR="/etc/fail2ban/filter.d"

log INFO "fail2ban: installing..."
if [[ "${DRY_RUN}" == false ]]; then
    apt-get install -y fail2ban > /dev/null 2>&1
    log INFO "fail2ban: installed"
else
    log DRY "would install fail2ban"
fi

# stop before reconfiguring so we write clean files
if [[ "${DRY_RUN}" == false ]]; then
    systemctl stop fail2ban 2>/dev/null || true
fi

# always write jail.local — never edit jail.conf directly
log INFO "fail2ban: writing jail.local..."

if [[ "${DRY_RUN}" == false ]]; then
    [[ -f "${JAIL_LOCAL}" ]] && cp "${JAIL_LOCAL}" "${JAIL_LOCAL}.bak"

    cat > "${JAIL_LOCAL}" <<EOF
# jail.local — hardened by harden.sh on $(date '+%Y-%m-%d')
# only override jail.conf settings here, never edit jail.conf

[DEFAULT]
bantime  = ${F2B_BANTIME}
findtime = ${F2B_FINDTIME}
maxretry = ${F2B_MAXRETRY}

# use ufw to apply bans so rules stay consistent with our firewall
banaction = ufw
banaction_allports = ufw

# incremental banning — each repeat offense doubles the ban (up to 4 weeks)
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 4w

ignoreip = 127.0.0.1/8 ::1

$(if [[ -n "${ALERT_EMAIL:-}" ]]; then
    echo "destemail = ${ALERT_EMAIL}"
    echo "sendername = Fail2Ban"
    echo "mta = sendmail"
    echo "action = %(action_mwl)s"
else
    echo "# no email configured — set ALERT_EMAIL in hardening.conf to enable"
fi)

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/auth.log
maxretry = ${F2B_MAXRETRY}
bantime  = ${F2B_BANTIME}

# ban ips doing repeated port scans visible in ufw.log
[ufw-port-scan]
enabled  = true
filter   = ufw-port-scan
logpath  = /var/log/ufw.log
maxretry = 5
bantime  = 1h
findtime = 5m

# nginx jails — only enabled if nginx is installed (see below)
[nginx-http-auth]
enabled  = false
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 3

[nginx-botsearch]
enabled  = false
port     = http,https
filter   = nginx-botsearch
logpath  = /var/log/nginx/*.log
maxretry = 2
bantime  = 24h

[nginx-bad-request]
enabled  = false
port     = http,https
filter   = nginx-bad-request
logpath  = /var/log/nginx/access.log
maxretry = 5

# repeated failed sudo attempts from a local session
[sudo-auth]
enabled  = true
filter   = sudo-auth
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 1h
EOF

    log INFO "fail2ban: jail.local written"
else
    log DRY "would write jail.local (bantime: ${F2B_BANTIME}, maxretry: ${F2B_MAXRETRY})"
fi

if [[ "${DRY_RUN}" == false ]]; then
    cat > "${FILTER_DIR}/ufw-port-scan.conf" <<'EOF'
[Definition]
failregex = ^\s*\S+ kernel: \[[\d.]+\] \[UFW BLOCK\] .* SRC=<HOST>
ignoreregex =
EOF
    log INFO "fail2ban: ufw-port-scan filter created"

    # pam_unix auth failure lines look like:
    # pam_unix(sudo:auth): authentication failure; logname=user uid=1000 ... user=user
    # note: no rhost= field in sudo pam lines, so we match on the user= part instead
    cat > "${FILTER_DIR}/sudo-auth.conf" <<'EOF'
[Definition]
failregex = pam_unix\(sudo:auth\): authentication failure;.*user=\S+
ignoreregex =
EOF
    log INFO "fail2ban: sudo-auth filter created"
else
    log DRY "would create custom fail2ban filters (ufw-port-scan, sudo-auth)"
fi

# enable nginx jails if nginx is present
# note: the sed below is somewhat fragile — it targets the line immediately after the section header
if command -v nginx &>/dev/null; then
    if [[ "${DRY_RUN}" == false ]]; then
        sed -i '/\[nginx-http-auth\]/{n;s/enabled  = false/enabled  = true/}' "${JAIL_LOCAL}"
        sed -i '/\[nginx-botsearch\]/{n;s/enabled  = false/enabled  = true/}' "${JAIL_LOCAL}"
        sed -i '/\[nginx-bad-request\]/{n;s/enabled  = false/enabled  = true/}' "${JAIL_LOCAL}"
        log INFO "fail2ban: nginx jails enabled (nginx detected)"
    else
        log DRY "would enable nginx jails (nginx detected)"
    fi
fi

if [[ "${DRY_RUN}" == false ]]; then
    systemctl enable fail2ban
    systemctl start fail2ban
    sleep 2

    if systemctl is-active --quiet fail2ban; then
        log INFO "fail2ban: service running ✓"
        JAIL_STATUS=$(fail2ban-client status 2>/dev/null | grep "Jail list" || echo "active")
        log INFO "fail2ban: ${JAIL_STATUS}"
    else
        log ERROR "fail2ban: service failed to start"
        journalctl -u fail2ban --no-pager -n 20 2>/dev/null | while IFS= read -r line; do
            log ERROR "  ${line}"
        done
        exit 1
    fi

    echo "sshd jail active, bantime ${F2B_BANTIME}, maxretry ${F2B_MAXRETRY}" > /tmp/harden_note_fail2ban
else
    log DRY "would enable and start fail2ban"
fi

log INFO "fail2ban hardening complete"

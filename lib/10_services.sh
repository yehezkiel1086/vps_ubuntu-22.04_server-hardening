#!/usr/bin/env bash
# 10_services.sh — attack surface reduction
# disables unnecessary services, audits open ports,
# and applies systemd sandboxing to services that are running
set -euo pipefail

run() {
    if [[ "${DRY_RUN}" == true ]]; then
        log DRY "would run: $*"
    else
        "$@"
    fi
}

DISABLED_COUNT=0

disable_service() {
    local service="$1"
    local reason="${2:-not needed on a server}"

    if systemctl list-unit-files "${service}" 2>/dev/null | grep -q "${service}"; then
        if [[ "${DRY_RUN}" == false ]]; then
            systemctl stop "${service}" 2>/dev/null || true
            systemctl disable "${service}" 2>/dev/null || true
            systemctl mask "${service}" 2>/dev/null || true
            log INFO "services: disabled ${service} (${reason})"
            (( DISABLED_COUNT++ )) || true
        else
            log DRY "would disable ${service} (${reason})"
        fi
    else
        log INFO "services: ${service} not installed — skipping"
    fi
}

# snapshot ports before we touch anything
if [[ "${DRY_RUN}" == false ]]; then
    log INFO "services: ports open before changes:"
    ss -tulpn 2>/dev/null | while IFS= read -r line; do
        log INFO "  ${line}"
    done
fi

log INFO "services: disabling unnecessary services..."

[[ "${DISABLE_SNAPD:-true}" == true ]] && \
    disable_service "snapd.service" "snap — not needed on a hardened server" && \
    disable_service "snapd.socket" "snap socket"

[[ "${DISABLE_AVAHI:-true}" == true ]] && \
    disable_service "avahi-daemon.service" "mdns discovery — not needed on a server"

[[ "${DISABLE_CUPS:-true}" == true ]] && \
    disable_service "cups.service" "printing" && \
    disable_service "cups-browsed.service" "print browser"

[[ "${DISABLE_MODEM_MANAGER:-true}" == true ]] && \
    disable_service "ModemManager.service" "mobile modem management"

[[ "${DISABLE_WHOOPSIE:-true}" == true ]] && \
    disable_service "whoopsie.service" "ubuntu crash reporter"

[[ "${DISABLE_APPORT:-true}" == true ]] && \
    disable_service "apport.service" "error reporting"

# these are always off on a vps — no hardware for them anyway
disable_service "bluetooth.service"          "no bluetooth on vps"
disable_service "wpa_supplicant.service"     "wifi — not needed on vps"
disable_service "speech-dispatcher.service"  "text-to-speech"
disable_service "saned.service"              "scanner daemon"

log INFO "services: ${DISABLED_COUNT} services disabled"

# snapshot ports after — flag anything unexpected
if [[ "${DRY_RUN}" == false ]]; then
    log INFO "services: ports open after changes:"
    ss -tulpn 2>/dev/null | while IFS= read -r line; do
        log INFO "  ${line}"
    done

    EXPECTED_PORTS=("${SSH_PORT}")
    [[ "${OPEN_HTTP:-true}" == true ]]  && EXPECTED_PORTS+=("80")
    [[ "${OPEN_HTTPS:-true}" == true ]] && EXPECTED_PORTS+=("443")

    UNEXPECTED_PORTS=()
    while IFS= read -r line; do
        PORT=$(echo "${line}" | awk '{print $5}' | rev | cut -d: -f1 | rev)
        if [[ "${PORT}" =~ ^[0-9]+$ ]]; then
            expected=false
            for ep in "${EXPECTED_PORTS[@]}"; do
                [[ "${PORT}" == "${ep}" ]] && expected=true && break
            done
            if [[ "${expected}" == false ]]; then
                UNEXPECTED_PORTS+=("${PORT}: ${line}")
            fi
        fi
    done < <(ss -tulpn 2>/dev/null | tail -n +2)

    if [[ ${#UNEXPECTED_PORTS[@]} -gt 0 ]]; then
        log WARN "services: unexpected open ports — investigate:"
        for p in "${UNEXPECTED_PORTS[@]}"; do
            log WARN "  ${p}"
        done
    else
        log INFO "services: all open ports are expected ✓"
    fi
fi

# apply systemd security directives to running services via drop-in configs
log INFO "services: applying systemd sandboxing overrides..."

apply_sandbox() {
    local service="$1"
    local override_dir="/etc/systemd/system/${service}.d"

    if ! systemctl list-unit-files "${service}" 2>/dev/null | grep -q "${service}"; then
        return 0
    fi

    if [[ "${DRY_RUN}" == false ]]; then
        mkdir -p "${override_dir}"
        cat > "${override_dir}/hardening.conf" <<EOF
[Service]
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
# MemoryDenyWriteExecute breaks nginx, php-fpm, and anything with a jit compiler.
# uncomment only for services you know don't use jit or shared memory writes.
# MemoryDenyWriteExecute=true
RestrictRealtime=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
EOF
        log INFO "services: sandboxing applied to ${service}"
    else
        log DRY "would apply systemd sandboxing to ${service}"
    fi
}

for svc in nginx.service apache2.service mysql.service postgresql.service \
           redis.service memcached.service rsync.service; do
    apply_sandbox "${svc}"
done

if [[ "${DRY_RUN}" == false ]]; then
    systemctl daemon-reload
    log INFO "services: systemd daemon reloaded"
fi

# disable core dumps — they can contain sensitive data and are rarely useful in production
log INFO "services: disabling core dumps..."

if [[ "${DRY_RUN}" == false ]]; then
    if ! grep -q "^fs.suid_dumpable" /etc/sysctl.conf 2>/dev/null; then
        echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    fi

    LIMITS_CONF="/etc/security/limits.conf"
    if ! grep -q "^* hard core" "${LIMITS_CONF}" 2>/dev/null; then
        cat >> "${LIMITS_CONF}" <<'EOF'

# disable core dumps — added by harden.sh
* soft core 0
* hard core 0
root soft core 0
root hard core 0
EOF
    fi

    if [[ -f /etc/systemd/coredump.conf ]]; then
        sed -i 's/^#Storage=.*/Storage=none/' /etc/systemd/coredump.conf
        sed -i 's/^#ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf
    fi

    log INFO "services: core dumps disabled ✓"
else
    log DRY "would disable core dumps (sysctl, limits.conf, systemd)"
fi

echo "${DISABLED_COUNT} services disabled, sandboxing applied" > /tmp/harden_note_services

log INFO "service isolation hardening complete"

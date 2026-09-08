#!/usr/bin/env bash
# 01_ssh.sh — ssh hardening
# backs up the original config, writes a hardened one from scratch,
# validates it before restarting, and rolls back if the port test fails
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BACKUP="${SSHD_CONFIG}.harden.bak"
SSHD_NEW="/tmp/sshd_config.new"
BANNER_FILE="/etc/ssh/login-banner"

run() {
    if [[ "${DRY_RUN}" == true ]]; then
        log DRY "would run: $*"
    else
        "$@"
    fi
}

# back up once — don't overwrite if we've already been here
if [[ ! -f "${SSHD_BACKUP}" ]]; then
    if [[ "${DRY_RUN}" == false ]]; then
        cp "${SSHD_CONFIG}" "${SSHD_BACKUP}"
        log INFO "ssh: backed up original config to ${SSHD_BACKUP}"
    else
        log DRY "would backup ${SSHD_CONFIG} → ${SSHD_BACKUP}"
    fi
else
    log INFO "ssh: backup already exists at ${SSHD_BACKUP}"
fi

log INFO "ssh: writing new sshd_config..."

if [[ "${DRY_RUN}" == false ]]; then
    cat > "${SSHD_NEW}" <<EOF
# sshd_config — hardened by harden.sh on $(date '+%Y-%m-%d')
# original backed up to: ${SSHD_BACKUP}

Port ${SSH_PORT}
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# ed25519 is preferred; rsa kept as fallback for older clients
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

LoginGraceTime ${SSH_LOGIN_GRACE_TIME}
PermitRootLogin no
StrictModes yes
MaxAuthTries ${SSH_MAX_AUTH_TRIES}
MaxSessions 5

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# keys only — all password-based auth off
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no

# usepam yes is required for account expiry and session accounting on ubuntu
UsePAM yes
KerberosAuthentication no
GSSAPIAuthentication no

# no forwarding of any kind
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PrintMotd no
Banner ${BANNER_FILE}

ClientAliveInterval ${SSH_CLIENT_ALIVE_INTERVAL}
ClientAliveCountMax ${SSH_CLIENT_ALIVE_COUNT_MAX}
TCPKeepAlive no

SyslogFacility AUTH
LogLevel VERBOSE

AllowUsers ${SSH_ALLOWED_USERS}

# modern ciphers only — anything below aes128 is dropped
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    log INFO "ssh: new config written to ${SSHD_NEW}"

    # validate before touching the live config
    if sshd -t -f "${SSHD_NEW}" 2>&1; then
        log INFO "ssh: config validated ok"
    else
        log ERROR "ssh: config validation failed — not applying, original untouched"
        rm -f "${SSHD_NEW}"
        exit 1
    fi

    cp "${SSHD_NEW}" "${SSHD_CONFIG}"
    chmod 600 "${SSHD_CONFIG}"
    rm -f "${SSHD_NEW}"
    log INFO "ssh: config applied"

else
    log DRY "would write hardened sshd_config (port ${SSH_PORT}, keys only, no root)"
fi

# create a legal notice banner shown before login
if [[ "${DRY_RUN}" == false ]]; then
    cat > "${BANNER_FILE}" <<'EOF'
*******************************************************************************
  unauthorized access to this system is prohibited and will be prosecuted.
  all connections are monitored and logged.
*******************************************************************************
EOF
    chmod 644 "${BANNER_FILE}"
    log INFO "ssh: login banner written to ${BANNER_FILE}"
else
    log DRY "would create login banner at ${BANNER_FILE}"
fi

# generate ed25519 host key if missing (fresh installs sometimes skip this)
if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
    run ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    log INFO "ssh: generated ed25519 host key"
fi

# restart and verify the new port is actually up before declaring success
if [[ "${DRY_RUN}" == false ]]; then
    log INFO "ssh: restarting sshd..."
    systemctl restart sshd

    sleep 3

    if ss -tlnp | grep -q ":${SSH_PORT} "; then
        log INFO "ssh: sshd listening on port ${SSH_PORT} ✓"
    else
        log ERROR "ssh: port ${SSH_PORT} not listening after restart — rolling back"
        cp "${SSHD_BACKUP}" "${SSHD_CONFIG}"
        systemctl restart sshd
        log ERROR "ssh: rolled back to original config"
        exit 1
    fi

    echo "port ${SSH_PORT}, keys-only, root login disabled" > /tmp/harden_note_ssh
else
    log DRY "would restart sshd and verify port ${SSH_PORT} is listening"
fi

log INFO "ssh hardening complete"

#!/usr/bin/env bash
# 03_users.sh — user account hardening
# creates the deploy user, installs the ssh key, locks root, sets password policy
set -euo pipefail

run() {
    if [[ "${DRY_RUN}" == true ]]; then
        log DRY "would run: $*"
    else
        "$@"
    fi
}

# create the deploy user if they don't exist yet
if id "${DEPLOY_USER}" &>/dev/null; then
    log INFO "users: ${DEPLOY_USER} already exists"
else
    log INFO "users: creating ${DEPLOY_USER}..."
    if [[ "${DRY_RUN}" == false ]]; then
        # --disabled-password means no password at all, key-only from the start
        adduser --disabled-password --gecos "" "${DEPLOY_USER}"
        log INFO "users: ${DEPLOY_USER} created"
    else
        log DRY "would create user: ${DEPLOY_USER}"
    fi
fi

if [[ "${DRY_RUN}" == false ]]; then
    usermod -aG sudo "${DEPLOY_USER}"
    log INFO "users: ${DEPLOY_USER} added to sudo group"
else
    log DRY "would add ${DEPLOY_USER} to sudo group"
fi

# install the deploy user's ssh public key
DEPLOY_HOME=$(getent passwd "${DEPLOY_USER}" | cut -d: -f6 2>/dev/null)
# fall back if getent returned nothing (shouldn't happen, but be safe)
DEPLOY_HOME="${DEPLOY_HOME:-/home/${DEPLOY_USER}}"
SSH_DIR="${DEPLOY_HOME}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

if [[ "${DRY_RUN}" == false ]]; then
    mkdir -p "${SSH_DIR}"
    chmod 700 "${SSH_DIR}"
    chown "${DEPLOY_USER}:${DEPLOY_USER}" "${SSH_DIR}"

    # idempotent — don't add the key twice
    if grep -qF "${DEPLOY_PUBKEY}" "${AUTH_KEYS}" 2>/dev/null; then
        log INFO "users: ssh key already in ${AUTH_KEYS}"
    else
        echo "${DEPLOY_PUBKEY}" >> "${AUTH_KEYS}"
        log INFO "users: ssh key installed to ${AUTH_KEYS}"
    fi

    chmod 600 "${AUTH_KEYS}"
    chown "${DEPLOY_USER}:${DEPLOY_USER}" "${AUTH_KEYS}"
else
    log DRY "would install ssh key to ${AUTH_KEYS}"
fi

if [[ "${LOCK_ROOT_PASSWORD:-true}" == true ]]; then
    if [[ "${DRY_RUN}" == false ]]; then
        passwd -l root
        log INFO "users: root password locked (sudo still works via key)"
    else
        log DRY "would lock root password"
    fi
fi

# password quality policy for any local accounts that do use passwords
log INFO "users: installing libpam-pwquality..."
if [[ "${DRY_RUN}" == false ]]; then
    apt-get install -y libpam-pwquality > /dev/null 2>&1
fi

PWQUALITY_CONF="/etc/security/pwquality.conf"
if [[ "${DRY_RUN}" == false ]]; then
    [[ -f "${PWQUALITY_CONF}" ]] && cp "${PWQUALITY_CONF}" "${PWQUALITY_CONF}.bak"

    cat > "${PWQUALITY_CONF}" <<'EOF'
minlen = 14
minclass = 3
maxrepeat = 3
maxsequence = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
gecoscheck = 1
EOF
    log INFO "users: password quality policy applied (min 14 chars, 3 classes)"
else
    log DRY "would set password quality policy in ${PWQUALITY_CONF}"
fi

# account lockout via pam_faillock
FAILLOCK_CONF="/etc/security/faillock.conf"
if [[ "${DRY_RUN}" == false ]]; then
    [[ -f "${FAILLOCK_CONF}" ]] || touch "${FAILLOCK_CONF}"

    set_faillock() {
        local key="$1" value="$2"
        # match only uncommented lines to avoid turning comments into settings
        if grep -q "^${key} " "${FAILLOCK_CONF}" 2>/dev/null; then
            sed -i "s/^${key} .*/${key} = ${value}/" "${FAILLOCK_CONF}"
        elif grep -q "^${key}=" "${FAILLOCK_CONF}" 2>/dev/null; then
            sed -i "s/^${key}=.*/${key} = ${value}/" "${FAILLOCK_CONF}"
        else
            echo "${key} = ${value}" >> "${FAILLOCK_CONF}"
        fi
    }

    set_faillock "deny"          "5"
    set_faillock "unlock_time"   "900"    # 15 min lockout
    set_faillock "fail_interval" "900"
    set_faillock "audit"         "true"

    log INFO "users: account lockout set (5 failures = 15-min lockout)"
else
    log DRY "would configure pam_faillock in ${FAILLOCK_CONF}"
fi

LOGIN_DEFS="/etc/login.defs"
if [[ "${DRY_RUN}" == false ]]; then
    [[ -f "${LOGIN_DEFS}" ]] && cp "${LOGIN_DEFS}" "${LOGIN_DEFS}.bak"

    set_login_def() {
        local key="$1" value="$2"
        if grep -q "^${key}" "${LOGIN_DEFS}" 2>/dev/null; then
            sed -i "s/^${key}\\s.*/${key} ${value}/" "${LOGIN_DEFS}"
        else
            echo "${key} ${value}" >> "${LOGIN_DEFS}"
        fi
    }

    set_login_def "PASS_MAX_DAYS" "90"   # force rotation every 90 days
    set_login_def "PASS_MIN_DAYS" "1"    # prevent immediate re-use
    set_login_def "PASS_WARN_AGE" "14"   # warn 2 weeks before expiry
    set_login_def "LOGIN_RETRIES" "3"
    set_login_def "LOGIN_TIMEOUT" "30"
    set_login_def "DEFAULT_HOME"  "yes"
    set_login_def "UMASK"         "027"

    log INFO "users: login.defs hardened (90-day expiry, umask 027)"
else
    log DRY "would harden /etc/login.defs"
fi

# set umask globally so new files aren't world-readable by default
if [[ "${DRY_RUN}" == false ]]; then
    for profile_file in /etc/profile /etc/bash.bashrc; do
        if ! grep -q "umask 027" "${profile_file}" 2>/dev/null; then
            echo -e "\numask 027" >> "${profile_file}"
            log INFO "users: umask 027 added to ${profile_file}"
        else
            log INFO "users: umask 027 already in ${profile_file}"
        fi
    done
else
    log DRY "would set umask 027 in /etc/profile and /etc/bash.bashrc"
fi

echo "${DEPLOY_USER} created, root locked, password policy set" > /tmp/harden_note_users

log INFO "user hardening complete"

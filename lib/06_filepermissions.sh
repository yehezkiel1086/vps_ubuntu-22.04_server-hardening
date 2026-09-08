#!/usr/bin/env bash
# 06_filepermissions.sh — file permission hardening
# tightens perms on sensitive system files, scans for world-writable files,
# and audits suid/sgid binaries against a known-good list
set -euo pipefail

run() {
    if [[ "${DRY_RUN}" == true ]]; then
        log DRY "would run: $*"
    else
        "$@"
    fi
}

apply_perm() {
    local mode="$1" owner="$2" path="$3"
    if [[ -e "${path}" ]]; then
        if [[ "${DRY_RUN}" == false ]]; then
            chmod "${mode}" "${path}"
            chown "${owner}" "${path}"
        else
            log DRY "would chmod ${mode} chown ${owner} ${path}"
        fi
        log INFO "permissions: ${mode} ${owner} → ${path}"
    else
        log WARN "permissions: ${path} not found — skipping"
    fi
}

# sensitive system files

log INFO "permissions: hardening sensitive system files..."

apply_perm 600 root:root /etc/ssh/sshd_config
apply_perm 644 root:root /etc/ssh/ssh_config
apply_perm 700 root:root /etc/ssh

apply_perm 644 root:root   /etc/passwd
apply_perm 644 root:root   /etc/group
apply_perm 640 root:shadow /etc/shadow
apply_perm 640 root:shadow /etc/gshadow
apply_perm 600 root:root   /etc/sudoers

apply_perm 600 root:root /etc/crontab
apply_perm 700 root:root /etc/cron.d
apply_perm 700 root:root /etc/cron.daily
apply_perm 700 root:root /etc/cron.weekly
apply_perm 700 root:root /etc/cron.monthly
apply_perm 700 root:root /etc/cron.hourly

# grub.cfg may not exist on all vps providers
if [[ -f /boot/grub/grub.cfg ]]; then
    apply_perm 600 root:root /boot/grub/grub.cfg
fi

apply_perm 600 root:root /etc/sysctl.conf

# world-writable files

log INFO "permissions: scanning for world-writable files..."

if [[ "${DRY_RUN}" == false ]]; then
    WW_FILE="/tmp/world_writable_report.txt"
    find / -xdev -type f -perm -0002 \
        ! -path "/proc/*" \
        ! -path "/sys/*" \
        ! -path "/dev/*" \
        ! -path "/tmp/*" \
        ! -path "/var/tmp/*" \
        ! -path "/run/*" \
        2>/dev/null > "${WW_FILE}" || true

    WW_COUNT=$(wc -l < "${WW_FILE}" | tr -d ' ')
    if [[ "${WW_COUNT}" -gt 0 ]]; then
        log WARN "permissions: ${WW_COUNT} world-writable files found — review: ${WW_FILE}"
        head -20 "${WW_FILE}" | while IFS= read -r line; do
            log WARN "  ${line}"
        done
    else
        log INFO "permissions: no unexpected world-writable files ✓"
    fi
else
    log DRY "would scan for world-writable files"
fi

# suid/sgid audit

log INFO "permissions: scanning for suid/sgid binaries..."

# standard ubuntu 22.04 suid binaries — anything not on this list gets flagged
KNOWN_SUID=(
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/passwd"
    "/usr/bin/newgrp"
    "/usr/bin/gpasswd"
    "/usr/bin/chfn"
    "/usr/bin/chsh"
    "/usr/bin/umount"
    "/usr/bin/mount"
    "/usr/bin/fusermount3"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/sbin/pppd"
    "/bin/ping"
    "/usr/bin/pkexec"
)

if [[ "${DRY_RUN}" == false ]]; then
    SUID_REPORT="/tmp/suid_report.txt"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
        ! -path "/proc/*" \
        ! -path "/sys/*" \
        2>/dev/null > "${SUID_REPORT}" || true

    UNEXPECTED=()
    while IFS= read -r binary; do
        found=false
        for known in "${KNOWN_SUID[@]}"; do
            if [[ "${binary}" == "${known}" ]]; then
                found=true
                break
            fi
        done
        if [[ "${found}" == false ]]; then
            UNEXPECTED+=("${binary}")
        fi
    done < "${SUID_REPORT}"

    if [[ ${#UNEXPECTED[@]} -gt 0 ]]; then
        log WARN "permissions: ${#UNEXPECTED[@]} unexpected suid/sgid binaries — review:"
        for b in "${UNEXPECTED[@]}"; do
            log WARN "  ${b}"
        done
        log WARN "permissions: to remove suid bit: chmod u-s /path/to/binary"
    else
        log INFO "permissions: all suid/sgid binaries are expected ✓"
    fi

    TOTAL_SUID=$(wc -l < "${SUID_REPORT}" | tr -d ' ')
    log INFO "permissions: ${TOTAL_SUID} total suid/sgid binaries"
    echo "unexpected suid: ${#UNEXPECTED[@]}" > /tmp/harden_note_filepermissions
else
    log DRY "would scan and audit suid/sgid binaries"
fi

# /tmp hardening

log INFO "permissions: securing temp directories..."

if [[ "${DRY_RUN}" == false ]]; then
    if mount | grep -q "on /tmp type"; then
        # /tmp is a separate mount — check for noexec
        if ! mount | grep "/tmp" | grep -q "noexec"; then
            log WARN "permissions: /tmp mounted without noexec — add noexec,nosuid,nodev to its fstab entry"
        else
            log INFO "permissions: /tmp already has noexec ✓"
        fi
    else
        # /tmp on root partition — add a tmpfs entry
        # note: takes effect on next reboot
        if ! grep -q "^tmpfs /tmp" /etc/fstab; then
            echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0" >> /etc/fstab
            mount -o remount /tmp 2>/dev/null || true
            log INFO "permissions: tmpfs /tmp entry added to fstab (noexec takes effect on reboot)"
        else
            log INFO "permissions: /tmp tmpfs already in fstab"
        fi
    fi

    chmod +t /tmp /var/tmp
    log INFO "permissions: sticky bit set on /tmp and /var/tmp"
else
    log DRY "would secure /tmp (noexec, sticky bit) and /var/tmp"
fi

log INFO "file permission hardening complete"

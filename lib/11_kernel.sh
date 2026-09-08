#!/usr/bin/env bash
# 11_kernel.sh — kernel parameter hardening via sysctl
# network stack hardening, memory protection, kernel exposure limits
set -euo pipefail

run() {
    if [[ "${DRY_RUN}" == true ]]; then
        log DRY "would run: $*"
    else
        "$@"
    fi
}

SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"

if [[ "${APPLY_SYSCTL_HARDENING:-true}" != true ]]; then
    log INFO "kernel: APPLY_SYSCTL_HARDENING=false — skipping"
    exit 0
fi

log INFO "kernel: writing sysctl hardening parameters..."

if [[ "${DRY_RUN}" == false ]]; then
    cat > "${SYSCTL_FILE}" <<'EOF'
# 99-hardening.conf — kernel hardening via sysctl
# applied by harden.sh

# ipv4 network 

# this is a server, not a router
net.ipv4.ip_forward = 0

# source routing lets packets specify their own path — easy to abuse for mitm
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# icmp redirects can silently change routing tables
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# drop packets arriving with spoofed source ips
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# log packets with impossible source addresses (martians)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# don't respond to broadcast pings (smurf amplification)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# syn cookies protect against syn flood without dropping legitimate connections
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 2048

# tcp timestamps leak system uptime — disable them
net.ipv4.tcp_timestamps = 0

net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_reuse = 1

# drop dead connections faster
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# protect against tcp time-wait assassination attacks (rfc 1337)
net.ipv4.tcp_rfc1337 = 1

# ipv6 network 

net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.forwarding = 0

# kernel memory and execution

# restrict kernel pointer exposure in dmesg and /proc/kallsyms
kernel.kptr_restrict = 2

# dmesg is read-only for non-root
kernel.dmesg_restrict = 1

# sysrq can trigger kernel panics or reboot — disable it
kernel.sysrq = 0

kernel.core_uses_pid = 1

# unprivileged bpf is a significant local privilege escalation vector
kernel.unprivileged_bpf_disabled = 1

# unprivileged user namespaces are a common container escape path.
# comment this out if you're running docker or lxc on this host.
kernel.unprivileged_userns_clone = 0

# aslr at max — makes it much harder to predict memory layout for exploits
kernel.randomize_va_space = 2

# protect against symlink/hardlink-based attacks in /tmp and similar
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# misc

fs.file-max = 65535

# reboot 60 seconds after a kernel panic instead of hanging forever
kernel.panic = 60
kernel.panic_on_oops = 60

kernel.perf_event_paranoid = 3
EOF

    log INFO "kernel: config written to ${SYSCTL_FILE}"

    log INFO "kernel: applying parameters..."
    APPLY_ERRORS=0
    while IFS= read -r line; do
        [[ "${line}" =~ ^# ]] && continue
        [[ -z "${line}" ]] && continue
        if ! sysctl -w "${line}" > /dev/null 2>&1; then
            log WARN "kernel: could not apply: ${line} (not supported on this kernel)"
            (( APPLY_ERRORS++ )) || true
        fi
    done < <(grep -v '^#' "${SYSCTL_FILE}" | grep '=')

    # reload the file as a whole (the official method)
    sysctl -p "${SYSCTL_FILE}" > /dev/null 2>&1 || true

    TOTAL=$(grep -c '=' "${SYSCTL_FILE}" | tr -d ' ')
    APPLIED=$(( TOTAL - APPLY_ERRORS ))
    log INFO "kernel: ${APPLIED}/${TOTAL} parameters applied ✓"

    if [[ "${APPLY_ERRORS}" -gt 0 ]]; then
        log WARN "kernel: ${APPLY_ERRORS} parameters skipped — normal on some vps kernels"
    fi

    # hidepid via sysctl doesn't work on modern kernels — use mount option instead
    if mount | grep -q "on /proc type"; then
        mount -o remount,hidepid=2 /proc 2>/dev/null || \
            log WARN "kernel: could not set hidepid=2 on /proc (some kernels require hidepid as a mount option in /etc/fstab)"
        # persist across reboots
        if ! grep -q "hidepid=2" /etc/fstab 2>/dev/null; then
            echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab
            log INFO "kernel: hidepid=2 added to /etc/fstab (takes effect on reboot)"
        fi
    fi

    echo "${APPLIED}/${TOTAL} sysctl params applied" > /tmp/harden_note_kernel

else
    log DRY "would write and apply ~30 kernel hardening parameters to ${SYSCTL_FILE}"
fi

if [[ "${DRY_RUN}" == false ]]; then
    log INFO "kernel: verifying key parameters:"
    for param in \
        kernel.randomize_va_space \
        kernel.kptr_restrict \
        net.ipv4.tcp_syncookies \
        net.ipv4.conf.all.rp_filter \
        fs.protected_symlinks; do
        VALUE=$(sysctl -n "${param}" 2>/dev/null || echo "n/a")
        log INFO "  ${param} = ${VALUE}"
    done
fi

log INFO "kernel hardening complete"

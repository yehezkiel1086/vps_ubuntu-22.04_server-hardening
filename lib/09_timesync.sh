#!/usr/bin/env bash
# 09_timesync.sh — time synchronization
# accurate time matters for log correlation, tls cert validation, and audit trails.
# installs chrony by default; falls back to systemd-timesyncd if chrony fails.
set -euo pipefail

run() {
    if [[ "${DRY_RUN}" == true ]]; then
        log DRY "would run: $*"
    else
        "$@"
    fi
}

log INFO "timesync: setting timezone to ${TIMEZONE}..."
run timedatectl set-timezone "${TIMEZONE}"
log INFO "timesync: timezone → ${TIMEZONE} ✓"

if [[ "${USE_CHRONY:-true}" == true ]]; then

    log INFO "timesync: installing chrony..."

    if [[ "${DRY_RUN}" == false ]]; then
        # chrony and systemd-timesyncd conflict — stop timesyncd first
        systemctl stop systemd-timesyncd 2>/dev/null || true
        systemctl disable systemd-timesyncd 2>/dev/null || true
        timedatectl set-ntp false 2>/dev/null || true

        apt-get install -y chrony > /dev/null 2>&1
        log INFO "timesync: chrony installed"

        CHRONY_CONF="/etc/chrony/chrony.conf"
        [[ -f "${CHRONY_CONF}" ]] && cp "${CHRONY_CONF}" "${CHRONY_CONF}.bak"

        cat > "${CHRONY_CONF}" <<'EOF'
# chrony.conf — hardened by harden.sh

# ubuntu pool + google ntp for redundancy
pool 0.ubuntu.pool.ntp.org iburst maxsources 4
pool 1.ubuntu.pool.ntp.org iburst maxsources 4
pool 2.ubuntu.pool.ntp.org iburst maxsources 4
pool 3.ubuntu.pool.ntp.org iburst maxsources 4

server time1.google.com iburst prefer
server time2.google.com iburst
server time3.google.com iburst
server time4.google.com iburst

driftfile /var/lib/chrony/chrony.drift

logdir /var/log/chrony
log measurements statistics tracking

# only listen on localhost — we're not a time server for the network
bindaddress 127.0.0.1

# minsources 1 so we sync even on vps hosts with limited ntp reach
# increase to 2 if you have reliable multi-source access
minsources 1

# step the clock if offset > 1 second during the first 3 syncs
makestep 1.0 3

rtcsync

# reject sources with too much dispersion
maxdistance 1.5

# limit how fast the clock can be slewed (security: prevents time yanking)
maxslewrate 83333.333
EOF

        systemctl enable chrony
        systemctl start chrony

        sleep 5

        if systemctl is-active --quiet chrony; then
            log INFO "timesync: chrony running ✓"

            chronyc tracking 2>/dev/null | while IFS= read -r line; do
                log INFO "  ${line}"
            done

            SOURCE_COUNT=$(chronyc sources 2>/dev/null | grep -c "^\^" || echo "0")
            log INFO "timesync: ${SOURCE_COUNT} ntp sources active"
        else
            log WARN "timesync: chrony failed to start — falling back to systemd-timesyncd"
            USE_CHRONY=false
        fi
    else
        log DRY "would install chrony with google ntp + ubuntu pool"
    fi
fi

if [[ "${USE_CHRONY:-true}" == false ]]; then
    log INFO "timesync: configuring systemd-timesyncd..."

    if [[ "${DRY_RUN}" == false ]]; then
        TIMESYNCD_CONF="/etc/systemd/timesyncd.conf"
        [[ -f "${TIMESYNCD_CONF}" ]] && cp "${TIMESYNCD_CONF}" "${TIMESYNCD_CONF}.bak"

        cat > "${TIMESYNCD_CONF}" <<'EOF'
[Time]
NTP=time1.google.com time2.google.com 0.ubuntu.pool.ntp.org
FallbackNTP=1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org
RootDistanceMaxSec=5
PollIntervalMinSec=32
PollIntervalMaxSec=2048
EOF
        timedatectl set-ntp true
        systemctl enable systemd-timesyncd
        systemctl restart systemd-timesyncd
        log INFO "timesync: systemd-timesyncd configured with google ntp"
    else
        log DRY "would configure systemd-timesyncd with google ntp"
    fi
fi

if [[ "${DRY_RUN}" == false ]]; then
    sleep 3
    SYNC_STATUS=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || echo "unknown")
    if [[ "${SYNC_STATUS}" == "yes" ]]; then
        log INFO "timesync: clock is synchronized ✓"
    else
        log WARN "timesync: not yet synchronized — may take a few minutes"
        log WARN "timesync: check with: timedatectl status"
    fi

    timedatectl status 2>/dev/null | while IFS= read -r line; do
        log INFO "  ${line}"
    done

    echo "tz=${TIMEZONE}, $(if [[ "${USE_CHRONY:-true}" == true ]]; then echo chrony; else echo timesyncd; fi)" \
        > /tmp/harden_note_timesync
else
    log DRY "would verify ntp sync and log timedatectl status"
fi

log INFO "time synchronization hardening complete"

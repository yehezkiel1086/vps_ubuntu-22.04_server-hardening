#!/usr/bin/env bash
# 99_report.sh — final hardening summary
# prints a module status table, key config values, open ports,
# and optionally runs a lynis audit for a hardening score
set -euo pipefail

RED='\\033[0;31m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'
CYAN='\\033[0;36m'; BOLD='\\033[1m'; RESET='\\033[0m'
DIM='\\033[2m'

read_note() {
    local file="/tmp/harden_note_$1"
    [[ -f "${file}" ]] && cat "${file}" || echo "—"
}

get_status() {
    local mod="$1"
    if [[ -n "${MODULE_STATUS[$mod]+_}" ]]; then
        echo "${MODULE_STATUS[$mod]}"
    else
        echo "DONE"
    fi
}

status_icon() {
    case "$1" in
        OK|DONE)    echo -e "${GREEN}✓ applied${RESET}" ;;
        SKIPPED)    echo -e "${YELLOW}⊘ skipped${RESET}" ;;
        FAILED)     echo -e "${RED}✗ failed${RESET}" ;;
        MISSING)    echo -e "${RED}? missing${RESET}" ;;
        *)          echo -e "${DIM}— unknown${RESET}" ;;
    esac
}

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}${BOLD}║           hardening complete — $(date '+%Y-%m-%d %H:%M:%S')            ║${RESET}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

if [[ "${DRY_RUN}" == true ]]; then
    echo -e "  ${YELLOW}${BOLD}*** dry-run — no changes were made ***${RESET}"
    echo ""
fi

printf "  %-22s %-16s %s\n" "module" "status" "notes"
echo "  ──────────────────────────────────────────────────────────────────────"

declare -A MODULE_LABELS=(
    ["00_preflight"]="preflight"
    ["01_ssh"]="ssh"
    ["02_firewall"]="firewall"
    ["03_users"]="users"
    ["04_sudo"]="sudo"
    ["05_fail2ban"]="fail2ban"
    ["06_filepermissions"]="file permissions"
    ["07_updates"]="auto-updates"
    ["08_logging"]="logging"
    ["09_timesync"]="time sync"
    ["10_services"]="services"
    ["11_kernel"]="kernel (sysctl)"
)

declare -A MODULE_NOTE_KEYS=(
    ["01_ssh"]="ssh"
    ["02_firewall"]="firewall"
    ["03_users"]="users"
    ["04_sudo"]="sudo"
    ["05_fail2ban"]="fail2ban"
    ["06_filepermissions"]="filepermissions"
    ["07_updates"]="updates"
    ["08_logging"]="logging"
    ["09_timesync"]="timesync"
    ["10_services"]="services"
    ["11_kernel"]="kernel"
)

MODULE_ORDER=(
    "00_preflight"
    "01_ssh"
    "02_firewall"
    "03_users"
    "04_sudo"
    "05_fail2ban"
    "06_filepermissions"
    "07_updates"
    "08_logging"
    "09_timesync"
    "10_services"
    "11_kernel"
)

for mod in "${MODULE_ORDER[@]}"; do
    label="${MODULE_LABELS[$mod]:-$mod}"
    note_key="${MODULE_NOTE_KEYS[$mod]:-}"
    note="$(read_note "${note_key}" 2>/dev/null || echo "—")"
    status="$(get_status "${mod}")"

    printf "  %-22s %-24b %s\n" "${label}" "$(status_icon "${status}")" "${note}"
done

echo "  ──────────────────────────────────────────────────────────────────────"
echo ""

echo -e "  ${BOLD}key configuration${RESET}"
echo "  ──────────────────────────────────────────────────────────────────────"
printf "  %-24s %s\n" "ssh port:"          "${SSH_PORT}"
printf "  %-24s %s\n" "deploy user:"       "${DEPLOY_USER}"
printf "  %-24s %s\n" "root password:"     "$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "unknown")"
printf "  %-24s %s\n" "timezone:"          "${TIMEZONE}"
printf "  %-24s %s\n" "fail2ban bantime:"  "${F2B_BANTIME}"
printf "  %-24s %s\n" "alert email:"       "${ALERT_EMAIL:-not configured}"
printf "  %-24s %s\n" "auto reboot:"       "${AUTO_REBOOT:-false}"
printf "  %-24s %s\n" "ufw status:"        "$(ufw status 2>/dev/null | head -1 | awk '{print $2}')"
printf "  %-24s %s\n" "ntp status:"        "$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || echo 'unknown')"
echo "  ──────────────────────────────────────────────────────────────────────"
echo ""

echo -e "  ${BOLD}listening ports${RESET}"
echo "  ──────────────────────────────────────────────────────────────────────"
ss -tulpn 2>/dev/null | tail -n +2 | while IFS= read -r line; do
    printf "  %s\n" "${line}"
done
echo "  ──────────────────────────────────────────────────────────────────────"
echo ""

if command -v fail2ban-client &>/dev/null && systemctl is-active --quiet fail2ban 2>/dev/null; then
    echo -e "  ${BOLD}fail2ban jails${RESET}"
    echo "  ──────────────────────────────────────────────────────────────────────"
    fail2ban-client status 2>/dev/null | grep -E "Jail list|Number" | while IFS= read -r line; do
        printf "  %s\n" "${line}"
    done
    echo "  ──────────────────────────────────────────────────────────────────────"
    echo ""
fi

# lynis audit

HARDENING_INDEX=""

if [[ "${ENABLE_LYNIS_AUDIT:-true}" == true ]]; then
    echo -e "  ${BOLD}running lynis security audit...${RESET}"
    echo "  (this takes 2–3 minutes)"
    echo ""

    if ! command -v lynis &>/dev/null; then
        log INFO "report: installing lynis..."
        apt-get install -y lynis > /dev/null 2>&1
    fi

    LYNIS_OUTPUT=$(lynis audit system --quiet --no-colors 2>&1 || true)
    HARDENING_INDEX=$(echo "${LYNIS_OUTPUT}" | grep "Hardening index" | grep -o '[0-9]*' | head -1)

    if [[ -n "${HARDENING_INDEX}" ]]; then
        if [[ "${HARDENING_INDEX}" -ge 80 ]]; then
            SCORE_COLOR="${GREEN}"
        elif [[ "${HARDENING_INDEX}" -ge 60 ]]; then
            SCORE_COLOR="${YELLOW}"
        else
            SCORE_COLOR="${RED}"
        fi

        echo -e "  ${BOLD}lynis hardening index: ${SCORE_COLOR}${HARDENING_INDEX}/100${RESET}"
        echo ""
        echo "  review with: sudo grep -E 'warning|suggestion' /var/log/lynis.log"

        log INFO "report: lynis score ${HARDENING_INDEX}/100"
    else
        log WARN "report: could not extract lynis score — check /var/log/lynis.log"
    fi

    echo ""
fi

# next steps

echo -e "  ${BOLD}${CYAN}next steps${RESET}"
echo "  ──────────────────────────────────────────────────────────────────────"
echo -e "  ${BOLD}1. test ssh in a new terminal before closing this session:${RESET}"
echo -e "     ssh -p ${SSH_PORT} -i ~/.ssh/your_key ${DEPLOY_USER}@$(hostname -I | awk '{print $1}')"
echo ""
echo -e "  ${BOLD}2. review the full log:${RESET}"
echo -e "     ${LOG_FILE}"
echo ""
echo -e "  ${BOLD}3. check lynis suggestions:${RESET}"
echo -e "     sudo grep -i suggestion /var/log/lynis.log | less"
echo ""
echo -e "  ${BOLD}4. monitor fail2ban:${RESET}"
echo -e "     sudo fail2ban-client status sshd"
echo ""
echo -e "  ${BOLD}5. re-run monthly to catch drift:${RESET}"
echo -e "     sudo bash ${SCRIPT_DIR}/harden.sh --dry-run"
echo ""
echo "  ──────────────────────────────────────────────────────────────────────"
echo -e "  ${DIM}full log: ${LOG_FILE}${RESET}"
echo ""

log INFO "report: complete. lynis index: ${HARDENING_INDEX:-n/a}. log: ${LOG_FILE}"

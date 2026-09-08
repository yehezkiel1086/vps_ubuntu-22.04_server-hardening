#!/usr/bin/env bash
# harden.sh — ubuntu 22.04 vps hardening entry point
#
# usage:
#   sudo bash harden.sh                          # interactive
#   sudo bash harden.sh --config my.conf --yes   # non-interactive
#   sudo bash harden.sh --dry-run                # preview only
#   sudo bash harden.sh --only ssh               # one module
#   sudo bash harden.sh --skip services          # skip one module

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
CONFIG_DIR="${SCRIPT_DIR}/config"
LOG_DIR="${SCRIPT_DIR}/logs"

CONFIG_FILE="${CONFIG_DIR}/hardening.conf"
DRY_RUN=false
AUTO_YES=false
ONLY_MODULE=""
SKIP_MODULE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# order matters — preflight always runs first, report always last
MODULES=(
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
    "99_report"
)

declare -A MODULE_STATUS
declare -A MODULE_NOTES

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --yes|-y)
                AUTO_YES=true
                shift
                ;;
            --only)
                ONLY_MODULE="$2"
                shift 2
                ;;
            --skip)
                SKIP_MODULE="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                echo "unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

usage() {
    cat <<EOF
${BOLD}ubuntu 22.04 vps hardening script${RESET}

usage:
  sudo bash harden.sh [options]

options:
  --config file     path to config file (default: config/hardening.conf)
  --dry-run         show what would change without applying anything
  --yes, -y         skip confirmation prompts
  --only module     run only one module (e.g. --only ssh)
  --skip module     skip one module (e.g. --skip services)
  --help, -h        show this help

available modules:
  preflight, ssh, firewall, users, sudo, fail2ban,
  filepermissions, updates, logging, timesync, services, kernel

examples:
  sudo bash harden.sh
  sudo bash harden.sh --config /root/my.conf --yes
  sudo bash harden.sh --dry-run
  sudo bash harden.sh --only ssh
  sudo bash harden.sh --skip services
EOF
}

mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/hardening-$(date +%Y-%m-%d_%H-%M-%S).log"

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "${timestamp} [${level}] ${message}" >> "${LOG_FILE}"

    case "${level}" in
        INFO)  echo -e "${GREEN}[INFO]${RESET}  ${message}" ;;
        WARN)  echo -e "${YELLOW}[WARN]${RESET}  ${message}" ;;
        ERROR) echo -e "${RED}[ERROR]${RESET} ${message}" ;;
        STEP)  echo -e "\n${CYAN}${BOLD}▶ ${message}${RESET}" ;;
        DRY)   echo -e "${YELLOW}[DRY-RUN]${RESET} ${message}" ;;
    esac
}

export LOG_FILE
export -f log

load_config() {
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log ERROR "config file not found: ${CONFIG_FILE}"
        log ERROR "copy config/hardening.conf and edit it before running"
        exit 1
    fi
    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"
    log INFO "config loaded: ${CONFIG_FILE}"
}

confirm() {
    local prompt="${1:-continue?}"
    if [[ "${AUTO_YES}" == true ]]; then
        log INFO "auto-yes: ${prompt}"
        return 0
    fi
    echo -e "\n${YELLOW}${prompt} [y/N]${RESET} "
    read -r answer
    [[ "${answer}" =~ ^[Yy]$ ]]
}

export AUTO_YES
export -f confirm

run_module() {
    local module_id="$1"
    local module_name
    module_name="$(echo "${module_id}" | sed 's/^[0-9]*_//')"
    local module_file="${LIB_DIR}/${module_id}.sh"

    # preflight and report always run regardless of --only
    if [[ -n "${ONLY_MODULE}" && "${module_name}" != "${ONLY_MODULE}" && "${module_id}" != "00_preflight" && "${module_id}" != "99_report" ]]; then
        MODULE_STATUS["${module_id}"]="SKIPPED"
        MODULE_NOTES["${module_id}"]="--only ${ONLY_MODULE}"
        return 0
    fi

    if [[ -n "${SKIP_MODULE}" && "${module_name}" == "${SKIP_MODULE}" ]]; then
        MODULE_STATUS["${module_id}"]="SKIPPED"
        MODULE_NOTES["${module_id}"]="--skip flag"
        log WARN "skipping module: ${module_id}"
        return 0
    fi

    if [[ ! -f "${module_file}" ]]; then
        log ERROR "module file not found: ${module_file}"
        MODULE_STATUS["${module_id}"]="MISSING"
        return 1
    fi

    log STEP "running module: ${module_id}"

    export DRY_RUN
    export SCRIPT_DIR
    export LIB_DIR

    if bash "${module_file}"; then
        MODULE_STATUS["${module_id}"]="OK"
        log INFO "module ${module_id} done"
    else
        local exit_code=$?
        MODULE_STATUS["${module_id}"]="FAILED"
        log ERROR "module ${module_id} failed (exit ${exit_code})"
        # preflight failure is always fatal
        if [[ "${module_id}" == "00_preflight" ]]; then
            log ERROR "preflight failed — aborting"
            exit 1
        fi
        if ! confirm "module ${module_id} failed. continue anyway?"; then
            log ERROR "aborted by user after module failure"
            exit 1
        fi
    fi
}

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat <<'EOF'
  ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗
  ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║
  ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║
  ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║
  ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
        ubuntu 22.04 vps hardening script v1.0
EOF
    echo -e "${RESET}"

    if [[ "${DRY_RUN}" == true ]]; then
        echo -e "${YELLOW}${BOLD}  *** dry-run mode — no changes will be made ***${RESET}\n"
    fi
}

main() {
    parse_args "$@"
    print_banner

    load_config

    log INFO "log: ${LOG_FILE}"
    log INFO "dry-run: ${DRY_RUN}"
    log INFO "auto-yes: ${AUTO_YES}"
    [[ -n "${ONLY_MODULE}" ]] && log INFO "only module: ${ONLY_MODULE}"
    [[ -n "${SKIP_MODULE}" ]] && log INFO "skipping module: ${SKIP_MODULE}"

    if [[ "${DRY_RUN}" == false ]]; then
        echo -e "${BOLD}this script will harden this server. review config/hardening.conf before proceeding.${RESET}"
        echo -e "  ssh port:    ${SSH_PORT}"
        echo -e "  deploy user: ${DEPLOY_USER}"
        echo -e "  timezone:    ${TIMEZONE}"
        echo ""
        if ! confirm "proceed with hardening?"; then
            echo "aborted."
            exit 0
        fi
    fi

    for module in "${MODULES[@]}"; do
        run_module "${module}"
    done

    echo ""
    log INFO "hardening run complete. full log: ${LOG_FILE}"
}

main "$@"

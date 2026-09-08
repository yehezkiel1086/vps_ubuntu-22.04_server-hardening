# Ubuntu 22.04 VPS Hardening Script

A modular, idempotent bash hardening suite for Ubuntu 22.04 LTS servers.

## What It Hardens

| Module | What It Does |
|---|---|
| `01_ssh` | Port change, keys-only auth, strong ciphers, login banner |
| `02_firewall` | UFW default-deny, rate limiting, port whitelist |
| `03_users` | Deploy user, SSH key install, root lock, password policy |
| `04_sudo` | Scoped rules, full audit logging, shell escalation blocked |
| `05_fail2ban` | Auto-bans, incremental banning, custom filters |
| `06_filepermissions` | Sensitive file modes, SUID audit, /tmp noexec |
| `07_updates` | Security-only unattended upgrades, no auto-reboot |
| `08_logging` | auditd rules, process accounting, journald persistence |
| `09_timesync` | chrony with Google NTP, verified sync |
| `10_services` | Disable snapd/avahi/cups/etc., systemd sandboxing |
| `11_kernel` | 30+ sysctl parameters (network, memory, kernel exposure) |

## Quick Start

### 1. Clone or upload to your server

```bash
scp -r vps-hardening/ root@your-server-ip:/root/
# or
git clone https://github.com/yourname/vps-hardening.git
```

### 2. Edit the config

```bash
nano config/hardening.conf
```

**Required:**
- `DEPLOY_PUBKEY` — paste your full SSH public key
- `SSH_PORT` — your chosen SSH port (default: 2299)
- `DEPLOY_USER` — the non-root user to create

**Optional:**
- `ALERT_EMAIL` — get emailed on update failures and fail2ban events
- `TIMEZONE` — default is UTC (recommended for servers)
- `OPEN_HTTP` / `OPEN_HTTPS` — set to false if not a web server

### 3. Dry run first

```bash
sudo bash harden.sh --dry-run
```

Review the output. Nothing is changed.

### 4. Run it

```bash
sudo bash harden.sh
```

**Keep your current SSH session open until you verify login on the new port.**

### 5. Verify the new SSH connection (in a second terminal)

```bash
ssh -p 2299 -i ~/.ssh/your_key deploy@your-server-ip
```

---

## Usage

```bash
# interactive (recommended for first run)
sudo bash harden.sh

# non-interactive (CI/automation)
sudo bash harden.sh --yes

# custom config file
sudo bash harden.sh --config /path/to/my.conf

# preview only — no changes
sudo bash harden.sh --dry-run

# run a single module only
sudo bash harden.sh --only ssh
sudo bash harden.sh --only fail2ban

# skip a module
sudo bash harden.sh --skip services

# run only specific module without preflight (direct)
sudo bash lib/05_fail2ban.sh
```

---

## File Structure

```
harden.sh                  Main entry point
config/
  hardening.conf           All user-tunable settings
lib/
  00_preflight.sh          Safety checks — runs first, blocks on failure
  01_ssh.sh                SSH hardening with rollback on failure
  02_firewall.sh           UFW setup (SSH port opened BEFORE enabling)
  03_users.sh              User creation, SSH key, password policy
  04_sudo.sh               Scoped sudoers, audit logging
  05_fail2ban.sh           Auto-banning with incremental penalties
  06_filepermissions.sh    File modes, SUID audit, /tmp security
  07_updates.sh            Unattended security upgrades
  08_logging.sh            auditd, acct, journald, logrotate
  09_timesync.sh           chrony NTP with verified sync
  10_services.sh           Disable daemons, systemd sandboxing
  11_kernel.sh             sysctl hardening (30+ parameters)
  99_report.sh             Summary table + optional lynis score
logs/
  hardening-YYYY-MM-DD.log Timestamped log of every run
```

---

## Safety Design

### Rollback on SSH failure
The SSH module writes a new config to a temp file, validates it with
`sshd -t`, applies it, waits 3 seconds, then checks the port is
actually listening. If it's not — it rolls back to the backup
automatically and restarts sshd on the original port.

### Idempotent
Every module checks before changing. Running twice is safe:
- Users are only created if they don't exist
- SSH keys are only added if not already present
- Config files are backed up only once (`.harden.bak`)
- `sysctl` values are set whether or not they were already set

### Backed up before touched
Every config file modified gets a `.bak` copy with the original
content before any changes are made.

### Preflight blocks the run
If the preflight fails (no root, wrong OS, no SSH key set, no internet)
the script exits before making any changes.

---

## After Hardening

### Check fail2ban bans
```bash
sudo fail2ban-client status sshd
```

### Unban an IP
```bash
sudo fail2ban-client set sshd unbanip 1.2.3.4
```

### Watch auth log in real time
```bash
sudo tail -f /var/log/auth.log
```

### Check audit trail
```bash
sudo ausearch -k passwd_changes
sudo ausearch -k sshd_config
```

### See who ran sudo
```bash
sudo cat /var/log/sudo.log
```

### Check NTP sync
```bash
chronyc tracking
timedatectl status
```

### Re-run lynis audit
```bash
sudo lynis audit system
```

### Re-run hardening (drift detection)
```bash
sudo bash harden.sh --dry-run
```

---

## Requirements

- Ubuntu 22.04 LTS (Debian 11/12 with minor adjustments)
- Root access
- Internet connectivity (for package installation)
- An SSH public key ready to paste into `hardening.conf`

---

## What This Doesn't Cover

This script gives you a solid foundation. For production environments,
also consider:

- **File integrity monitoring** — AIDE or Tripwire
- **AppArmor profiles** — per-application mandatory access control
- **Secrets management** — HashiCorp Vault, environment variable hygiene
- **Network segmentation** — private VPC, separate DB network
- **Backups** — and actually testing restore procedures
- **Intrusion detection** — OSSEC, Wazuh for real-time alerting
- **CIS Benchmark** — for PCI-DSS or HIPAA compliance requirements

---

## License

MIT

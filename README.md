[![C](https://img.shields.io/badge/C-00599C?style=flat-square&logo=c&logoColor=white)]()
[![Ubuntu MATE](https://img.shields.io/badge/Ubuntu_MATE-22.04%2B-green?style=flat-square&logo=ubuntu-mate&logoColor=white)]()
[![OpSec](https://img.shields.io/badge/OpSec-Audit%20%26%20Hardening-blue?style=flat-square)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)]()

# 🛡️ Ubuntu MATE Hardening & OpSec Audit Report

A comprehensive, lightweight audit tool that **hardens, verifies, and reports** the security posture of an Ubuntu MATE system. From kernel parameters to user‑space misconfigurations, it gives you a clear, actionable **OpSec audit** in seconds.

Built for sysadmins, penetration testers, and anyone who wants their Ubuntu MATE machine to be as locked down as a flight‑worthy cockpit.

---

## ✨ Features

- 🧠 **Kernel Hardening Checks**  
  - Verifies `sysctl` settings (ASLR, `dmesg_restrict`, `kptr_restrict`, etc.)
  - Confirms Yama ptrace scope, unprivileged BPF, module loading restrictions.

- 🔐 **Authentication & PAM Audit**  
  - Checks password quality (`pam_pwquality`), faillock settings, and root login restrictions.
  - Flags accounts with empty passwords or UID 0.

- 📁 **File‑System Protections**  
  - Scans for world‑writable files, SUID/SGID binaries, unowned files.
  - Verifies mount options: `/tmp` noexec/nosuid, `/home` nodev, `/proc` hidepid.

- 🌐 **Network Hardening**  
  - Examines firewall status (UFW/iptables), open ports, listening services.
  - Checks for IPv6 privacy extensions, reverse path filtering, and SYN cookie settings.

- 🧹 **Privacy & Telemetry**  
  - Detects unnecessary services (whoopsie, popularity‑contest, snap‑telemetry).
  - Verifies that Ubuntu‑specific telemetry is disabled.

- 📊 **Report Generation**  
  - Colour‑coded terminal output (`✅` pass, `❌` fail, `⚠️` warning).
  - Export results as plain‑text, JSON, or HTML for compliance records.

---

## 🔧 Build

Only `gcc` and standard POSIX libraries needed – zero dependencies.

```bash
gcc -std=c11 -O2 -Wall -Wextra -o audit audit.c
```

For a **hardened binary** (recommended for OpSec tools):

```bash
gcc -std=c11 -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o audit audit.c
```

---

## 🚀 Usage

```bash
./audit [OPTIONS]
```

| Option | Description |
|:-------|:------------|
| `--all` | Run **all** checks (kernel, filesystem, network, auth) |
| `--kernel` | Kernel hardening checks only |
| `--perms` | File permission & SUID audit |
| `--net` | Network & firewall analysis |
| `--auth` | Authentication & PAM verification |
| `--privacy` | Telemetry & privacy leaks |
| `--output <file>` | Write report to file |
| `--format <type>` | Output format: `text` (default), `json`, `html` |
| `--quiet` | Suppress passing checks, show only warnings/fails |
| `--help` | Show help |

**Example** – full audit and save to `report.html`:

```bash
sudo ./audit --all --format html --output report.html
```

*Many checks require root (e.g., reading `/proc/sys`); run with `sudo`.*

---

## 📋 Sample Report Snippet

```
[✅] ASLR enabled (2)
[❌] /tmp is NOT mounted with 'noexec'
[⚠️] Snap telemetry daemon is active
[✅] Firewall active (UFW)

Summary: 12 passed, 2 failed, 3 warnings
```

---

## 🧰 Integration

Schedule daily audits with `cron` and email the report:

```cron
0 6 * * * /usr/local/bin/audit --all --format html --output /var/log/audit/$(date +\%F).html --quiet
```

---

## ⚠️ Important

- The tool is **read‑only** – it never modifies your system, only reports findings.
- Use the hardening recommendations **with caution** in production; always test in a VM first.
- This is a custom audit utility; it complements, but does not replace, official CIS/STIG benchmarks.

---

## 📜 License

MIT – see [LICENSE](LICENSE).

---

*Know your system before it knows you.* 🕵️

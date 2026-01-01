# Aegis Ultra

**Aegis Ultra** is a single-file PowerShell engine designed to audit Windows systems with a focus on
security posture, system hygiene, and operational transparency.

> This project is NOT a cleaner, booster, or antivirus.
> It is an audit-first, safe-by-default Windows diagnostics and security visibility tool.

---

## 🔍 Features

- System health and performance auditing
- Disk and storage visibility
- Network diagnostics
- Windows security posture checks (Defender, Firewall, BitLocker)
- Startup & persistence inspection
- Privacy & telemetry visibility
- System integrity verification (SFC verify-only)
- Full audit logging
- Automation-ready (scheduled execution)

---

## ⚙️ Design Principles

- Single PowerShell file
- Safe-by-default (no destructive actions)
- Uses native Windows components only
- Transparent and auditable logic
- Built with a sysadmin / cybersecurity mindset

---

## 🚀 Usage

```powershell
powershell -ExecutionPolicy Bypass -File .\Aegis-Ultra.ps1


# Task 3 — WiFi Password Security Auditor

**Intern:** Aditya Jain
**Intern ID:** CITS2742
**Company:** CodTech IT Solutions
**Domain:** Cyber Security & Ethical Hacking

## Overview

This tool audits the strength of WiFi passwords **already saved on your own
Windows device**. It uses the built-in `netsh wlan` command to list saved
network profiles and reveal their stored passwords (the same info Windows
itself can show you), then scores each password against common security
criteria — length, character variety, common-password lists, sequential
patterns, and repeated characters — and estimates its entropy in bits.

**This tool does not access, scan, or attack any network other than the
ones already saved on the local machine.** It does not crack, brute-force,
or intercept WiFi traffic of any kind.

## How It Works

1. **WindowsWifiReader** — runs `netsh wlan show profiles` to list saved
   network names, then `netsh wlan show profile name=<X> key=clear` per
   profile to read its stored password and security type.
2. **PasswordAuditor** — scores each password (0–7) based on length,
   character classes used, membership in a common-password list, sequential
   patterns (`123`, `abc`), and repeated characters. Also computes Shannon
   entropy based on the character pool used.
3. **AuditReport** — renders a console report (passwords are masked, e.g.
   `S*********!`) with per-network ratings and an overall summary, and can
   save the full report to a `.txt` file.

## Requirements

- Windows 10/11 (uses the Windows-only `netsh wlan` command)
- Python 3.8+
- No external Python packages — standard library only

## Usage

```bash
python wifi_security_auditor.py
```

```
Options:
  [1] Scan & audit saved WiFi passwords
  [2] Show WiFi security best practices
  [3] Exit
```

### Sample Output

```
[1] SSID: HomeWifi_5G
     Security : WPA2-Personal / AES
     Password : S*********!
     Rating   : STRONG  (score 6/7)
     Entropy  : 72.1 bits

[2] SSID: OfficeGuest
     Security : WPA2-Personal / AES
     Password : g******3
     Rating   : WEAK  (score 2/7)
     Entropy  : 41.36 bits
     Weaknesses:
       - Missing uppercase letters
       - Missing special characters
       - Contains a sequential pattern (e.g. 123, abc)
```

## Rating Scale

| Score | Rating       |
|-------|--------------|
| 0–2   | Weak         |
| 3–4   | Moderate     |
| 5–6   | Strong       |
| 7     | Very Strong  |

## Disclaimer

This tool reads WiFi credentials **already stored on the device it runs
on**, the same way Windows' own network settings UI can. It is built for
educational purposes as part of a cyber security internship task and must
not be used to access credentials on devices/networks you do not own or
have explicit permission to audit.

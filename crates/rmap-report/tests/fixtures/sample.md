# rmap scan report

> Potential findings: CVEs are matched on the detected product version only, so backported fixes and configuration are not taken into account. Matches that need a platform rmap can't verify are listed as conditional, and client-only CVEs are not counted on listening ports. Verify each finding before acting on it.

## Summary

- **Targets:** 10.0.0.0/30
- **Ports:** 22,80,443 (3 ports)
- **Scan:** TCP connect, timing normal (T3), host discovery on, service detection on
- **Started:** 2025-11-17 14:30:05 UTC
- **Finished:** 2025-11-17 14:30:09 UTC
- **Duration:** 4.3 s
- **Status:** completed
- **Hosts up:** 2 of 2
- **Open ports:** 1
- **Potential CVEs:** 2 (high 1, medium 1)
- **CVE coverage:** 1 of 1 open ports checked
- **Vulnerability data:** built 2025-11-01, 245000 CVEs (NVD + CISA KEV)
- **rmap version:** 0.1.0

## Hosts

### 10.0.0.2 (db.lan)

| Port | State | Service | Version | CVE check |
|---|---|---|---|---|
| 22/tcp | open | ssh | OpenSSH 9.6p1 (Ubuntu Linux; protocol 2.0) | 2 potential CVEs (OpenSSH 9.6p1), worst: high |
| 161/udp | open\|filtered |  |  |  |

Potential findings:

- **CVE-2024-6387** (high, 8.1) on 22/tcp: Signal handler race condition (regreSSHion). · **actively exploited (CISA KEV, added 2024-07-15)**
- **CVE-2023-51385** (medium, 6.5) on 22/tcp: Shell metacharacters in user names may be expanded.

### ::1

No open ports found.

## Potential findings by product

### OpenSSH 9.6p1: 2 potential · 1 port

- **CVE-2024-6387** (high, 8.1) on 10.0.0.2 22/tcp: Signal handler race condition (regreSSHion). · **actively exploited (CISA KEV, added 2024-07-15)**
- **CVE-2023-51385** (medium, 6.5) on 10.0.0.2 22/tcp: Shell metacharacters in user names may be expanded.

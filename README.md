# rmap

> [!CAUTION]
> ## **THIS IS FOR EDUCATIONAL PURPOSES**
>
> **rmap is a network scanning and vulnerability-matching tool. Scanning or probing a computer system or network you do not own and do not have explicit, documented authorization to test is illegal in most jurisdictions (for example, the U.S. Computer Fraud and Abuse Act and equivalent laws elsewhere), even when no harm is intended or done.**
>
> - **You are solely responsible for how you use this software and for obtaining authorization before scanning any network or host that isn't yours.**
> - This project is provided **"AS IS", without warranty of any kind, express or implied** - including, without limitation, fitness for a particular purpose, accuracy, or non-infringement. See [`LICENSE-MIT`](LICENSE-MIT) / [`LICENSE-APACHE`](LICENSE-APACHE).
> - The authors and contributors **accept no liability** for damage, data loss, legal exposure, or any other consequence arising from the use or misuse of this software.
> - CVE matches are **potential** findings based on version strings, using data downloaded from NVD and CISA that can be incomplete, out of date, or wrong for vendor-patched builds - verify before acting, and do not rely on rmap alone for real risk decisions.
> - Nothing here is legal advice. If you're unsure whether you're authorized to scan something, **don't** - get written permission first.

## Contents

- [Status](#status)
- [Building on Linux](#building-on-linux)
  - [1. Install a C linker and git](#1-install-a-c-linker-and-git)
  - [2. Install Rust 1.88 or newer](#2-install-rust-188-or-newer)
  - [3. Clone and build](#3-clone-and-build)
  - [4. Run it](#4-run-it)
  - [5. Get the CVE data (optional)](#5-get-the-cve-data-optional)
  - [6. Run the tests (optional)](#6-run-the-tests-optional)
  - [Troubleshooting](#troubleshooting)
- [Getting CVE data](#getting-cve-data)
- [Running](#running)
  - [Privileged scans (SYN, UDP, ICMP/ARP discovery)](#privileged-scans-syn-udp-icmparp-discovery)
  - [Results screen keys](#results-screen-keys)
  - [Tabs: Hosts, Services, Vulns](#tabs-hosts-services-vulns)
  - [Filtering and sorting the host list](#filtering-and-sorting-the-host-list)
  - [Rescanning one host](#rescanning-one-host)
  - [Copying to the clipboard](#copying-to-the-clipboard)
  - [Colors](#colors)
  - [Settings](#settings)
- [Scan profiles and recent targets](#scan-profiles-and-recent-targets)
- [Saved scans, export and comparing](#saved-scans-export-and-comparing)
- [How it works](#how-it-works)
  - [Port states (TCP connect)](#port-states-tcp-connect)
  - [Raw scans](#raw-scans)
  - [Adaptive timeouts](#adaptive-timeouts)
  - [MAC vendor lookup](#mac-vendor-lookup)
  - [Host names](#host-names)
  - [Device grouping](#device-grouping)
- [Service detection](#service-detection)
  - [UDP detection](#udp-detection)
  - [Adding a probe or match rule](#adding-a-probe-or-match-rule)
- [Vulnerability matching](#vulnerability-matching)
  - [Was the port actually checked?](#was-the-port-actually-checked)
  - [The database file](#the-database-file)
  - [Updating vulnerability data](#updating-vulnerability-data)
  - [Building from NVD](#building-from-nvd)
  - [Vulnerability data (maintainers)](#vulnerability-data-maintainers)
- [Exposure findings](#exposure-findings)
  - [JSON summary](#json-summary)
- [Logs and crash reports](#logs-and-crash-reports)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Platform notes](#platform-notes)
- [License](#license)

[![CI](https://github.com/Hroberts1/rmap/actions/workflows/ci.yml/badge.svg)](https://github.com/Hroberts1/rmap/actions/workflows/ci.yml)

A network scanner written from scratch in Rust, driven by an interactive terminal UI.

rmap takes inspiration from Nmap's feature set but shares none of its code or data files. Scanning, packet handling, target parsing and probe databases are all written in this repository. The only outside dependencies are general-purpose infrastructure: [tokio](https://tokio.rs) for the async runtime, [ratatui](https://ratatui.rs) for the terminal, [libc](https://crates.io/crates/libc) for the Linux raw-socket syscalls, [serde](https://serde.rs)/serde_json for the JSON report format, [rusqlite](https://crates.io/crates/rusqlite) (with SQLite bundled) to read the CVE database file, and [ureq](https://crates.io/crates/ureq) (with rustls) to download that file, or the NVD and CISA data to build it from, when you ask.

> **Only scan networks you own or have written permission to test.** rmap asks for confirmation before it touches public addresses.

## Status

All five milestones are done: TCP connect, SYN and UDP scans, ICMP/ARP host discovery, service and version detection, vulnerability matching, export and diffing, and a live TUI. See the [roadmap](#roadmap).

## Building on Linux

rmap builds with the standard Rust toolchain. It needs no system libraries beyond a C linker: no OpenSSL, libpcap or pkg-config.

### 1. Install a C linker and git

Rust uses the system linker to produce the final binary.

```bash
# Debian, Ubuntu, Mint, Pop!_OS
sudo apt update && sudo apt install -y build-essential git curl

# Fedora, RHEL, Rocky, Alma
sudo dnf install -y gcc git curl

# Arch, Manjaro
sudo pacman -S --needed base-devel git curl

# openSUSE
sudo zypper install -y gcc git curl
```

### 2. Install Rust 1.88 or newer

Use [rustup](https://rustup.rs). Distribution-packaged `rustc` is often too old for this project.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version   # should report 1.88.0 or later
```

If Rust is already installed through rustup, run `rustup update stable`.

### 3. Clone and build

```bash
git clone https://github.com/Hroberts1/rmap.git
cd rmap
cargo build --release
```

The binary is written to `target/release/rmap`. The first build downloads dependencies from crates.io and takes a minute or two; later builds are incremental.

### 4. Run it

```bash
./target/release/rmap
```

Or install it into `~/.cargo/bin`, which rustup puts on your `PATH`:

```bash
cargo install --path .
rmap
```

### 5. Get the CVE data (optional)

Vulnerability matching needs a CVE database, which isn't built into the binary. Press `F2` in rmap and choose **Build from NVD** or **Download prebuilt**; [Getting CVE data](#getting-cve-data) explains the difference. Everything else in rmap works without it.

### 6. Run the tests (optional)

```bash
cargo test --workspace
```

The tests need no network access and no root.

### Troubleshooting

| Problem | Fix |
|---|---|
| `linker 'cc' not found` | Install the C toolchain from step 1. |
| `requires rustc 1.88` or edition 2024 errors | Your Rust is too old. Run `rustup update stable`, and check that `which cargo` points into `~/.cargo/bin`, not `/usr/bin`. |
| Garbled boxes or missing colors | Use a terminal with UTF-8 and 256-color support. Check that `echo $LANG` ends in `UTF-8`. |
| **Download prebuilt** fails with `the server answered HTTP 404` | Nothing is published at the Update URL. Use **Build from NVD** instead: it needs nothing from GitHub. With the default URL, the project hasn't published data yet; it appears after the first successful run of the **Vulnerability data** Action (see [Vulnerability data (maintainers)](#vulnerability-data-maintainers)). If you changed Update URL, check it points at a `vulns.json` manifest, or use **Reset URL to default**. |
| **Build from NVD** fails with `404 ... check the key` | NVD answers 404 to an API key it doesn't accept. Check the key in Settings (or `NVD_API_KEY`), or clear it to build without one. |
| Screen left in a bad state after a crash | Run `reset`. The crash report path is printed after the terminal is restored; see [Logs and crash reports](#logs-and-crash-reports). |

## Getting CVE data

rmap matches services against a local CVE database file, `vulns.db`. It isn't built into the binary, and nothing is downloaded unless you ask. Until you have one, the setup form's Vulns row says `no CVE data yet: F2 to set up`, and ticking Vulns opens a short pop-up that leads to Settings (`Enter` or `F2` opens it; `Esc` keeps Vulns ticked and scans without CVE checks, showing `no vulnerability data: not checked` on each port).

There are three ways to get the file. Most people only ever use the first two, both from the **Get data** row in [Settings](#settings) (`F2`), and both ask **y/n** first:

| | **Build from NVD** | **Download prebuilt** | **Your own copy** |
|---|---|---|---|
| Who it's for | Anyone who wants data straight from the source | Anyone who wants it working in seconds | Organisations, offline networks |
| Where the data comes from | The [NVD API](https://nvd.nist.gov/developers/vulnerabilities) and CISA's [KEV list](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), built on your computer | This project's monthly release, built the same way by a GitHub Action | Built by you with `tools/vulndb-build`, hosted wherever you like |
| First time | About 30 minutes without an API key, 10-15 with a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (Settings → NVD API key) | Seconds (a few MB) | As for Build from NVD |
| Later updates | Only the CVEs that changed, usually a minute or two | The whole file again | Your schedule |
| How fresh | Up to the minute | Up to a month old | Your schedule |
| Who you trust | NVD and CISA only | This project's build (each month's file is an [immutable release](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases), checked by size and SHA-256 over HTTPS) | Yourself |

You can mix them: download prebuilt to start quickly, then use Build from NVD to keep it fresh. Settings always shows where the current file came from (`built locally` or `prebuilt download`). Press the same button again whenever the results header warns that the data is old (30 days by default, adjustable in Settings). None of this needs a GitHub account or any setup beyond rmap.

**Your own copy**, for teams that don't want to depend on NVD's rate limits on every machine or on this project's release:

1. Build the file once: `OUT_DIR=/some/dir cargo run --release -p vulndb-build` (set `NVD_API_KEY` to make it faster). See [Vulnerability data (maintainers)](#vulnerability-data-maintainers).
2. Either copy `vulns.db` into each machine's [data folder](#the-database-file) (rmap opens any valid file there), or host `vulns.db` plus a `vulns.json` manifest on any HTTPS server and point each machine's Settings → Update URL at the manifest; **Download prebuilt** then fetches from your server.

Whichever way you choose, a match is a *potential* finding to verify, not proof: see [Vulnerability matching](#vulnerability-matching).

## Running

```bash
cargo run --release
```

Fill in the setup form and press **Enter**:

| Field | Examples |
|---|---|
| Targets | `192.168.1.0/24`, `10.0.0.1-50`, `10.0.0.5-10.0.0.40`, `10.1-2.0.1-254`, `router.lan`, `::1` |
| Ports | `22,80,443`, `1-1024`, `common` (about 100 frequently used ports), `all` |
| Scan type | TCP connect (no privileges), TCP SYN, UDP |
| Timing | T0 paranoid … T3 normal … T5 insane |
| Discovery | Probe hosts first and skip the ones that don't answer |
| Services | Identify the software and version behind each open port |
| Vulns | Flag potential CVEs for identified services (needs Services on too) |
| Exclude | Addresses never to probe, same syntax as Targets - for fragile gear such as PLCs, SCADA controllers and medical devices |
| Max rate | Probes per second, or empty for unlimited - for networks with fragile devices that fall over under load |

Press `Ctrl-S` to save the current form (everything except Targets) as a named profile, `Ctrl-P` to load or delete a saved one, and `Ctrl-R` to pick from the last 10 target strings that started a scan. Both persist as JSON next to the saved scans (see below); a missing or unreadable file falls back to the defaults with a warning.

Mouse support (`m` on the results screen toggles it) lets you click a host or port to select it, click a setup-form field to focus it, and scroll the host or port pane with the wheel. Turn it off to select and copy text with your terminal's own mouse handling instead - rmap's own `y`/`Y` (below) cover the common case of copying an address or CVE IDs without needing the mouse at all.

### Privileged scans (SYN, UDP, ICMP/ARP discovery)

SYN and UDP scans and ICMP/ARP discovery send hand-built packets over raw sockets. That needs Linux and either root or the `CAP_NET_RAW` capability. Granting the capability to the binary once is safer than running the whole TUI as root:

```bash
cargo build --release
sudo setcap cap_net_raw+ep target/release/rmap
./target/release/rmap
```

(`setcap` has to be repeated after every rebuild.) Without raw sockets, or on Windows and macOS, rmap still runs the scan and prints a warning in the log panel saying what it fell back to: a SYN scan becomes a TCP connect scan, a UDP scan uses ordinary connected UDP sockets, and discovery uses the TCP connect ping (on Windows raced against an unprivileged ICMP echo through the IP Helper API, so hosts that only answer ping are found; IPv4 only for now). The raw backend covers IPv4 and IPv6 (Linux 4.5 or later for IPv6). IPv6 packets are built by rmap but routed by the kernel, which also does neighbour discovery, so there is no IPv6 equivalent of the ARP ping: discovery uses ICMPv6 echo raced against the TCP connect ping. IPv6 targets fall back to unprivileged probes (with a warning) when the host has no IPv6, for link-local addresses (zone IDs like `fe80::1%eth0` aren't accepted yet) and for IPv4-mapped addresses.

### Results screen keys

| Keys | Does |
|---|---|
| `↑↓` `j` `k` | Move in the focused pane |
| `PgUp` `PgDn` | Move by 10 |
| `Home` `End` `g` `G` | First / last |
| `Tab` `←` `→` `h` `l` | Switch between the hosts pane and the ports pane |
| `1` `2` `3` `4` | Hosts / Services / Vulns / Findings tab (below) |
| `d` | Show or hide down hosts |
| `/` | Filter the host list (below) |
| `o` | Cycle sort order (below) |
| `s` | Stop the scan, or stop a rescan in progress |
| `r` | Rescan the selected host: every port, with service detection and vuln matching on (below) |
| `e` | Export |
| `c` | Compare with a saved scan |
| `L` | Full-screen scrollable log |
| `y` / `Y` | Copy the selected address (or `ip:port`) / the selected host's CVE IDs (below) |
| `m` | Toggle mouse capture on/off - off lets the terminal's own text selection work |
| `S` / `F2` | Settings, including updating the CVE data (below) |
| `n` / `Esc` | New scan |
| `q` / `Ctrl-C` | Quit (asks first on a running scan) / quit immediately |
| `?` | This list, as an overlay |

`n`, `Esc` and `q` ask **y/n** first if a scan is still running, so a stray keypress can't lose it; `Esc` on the setup form does too, once you've typed anything. `open?` in the port table means `open|filtered` (no reply; may be open), and a `!` by a host means it has at least one potential CVE.

### Tabs: Hosts, Services, Vulns

`1` (Hosts, the default) shows one host at a time with its ports, as described above. `2` (Services) groups every open port across the whole scan by port and protocol - "which hosts have 445 open?" - with the service name and a count. `3` (Vulns) starts with a coverage line (`CVE coverage: 4 of 65 open ports checked`), then lists every match grouped by product and version (`OpenSSH 10.2p1: 29 potential (upstream match; Ubuntu build) · 3 conditional (platform not verified) · 8 client-only, not counted · 2 ports`), worst group first, host and port alongside each finding. `Enter` or `Space` opens or closes the selected group; groups with plain potential findings start open, groups holding only distro-build, conditional or client-only matches start closed (see [Match tiers](#match-tiers)). Both rebuild from the live results every frame, so they fill in as the scan runs, and arrow keys move through whichever group or finding is selected. `4` (Findings) lists [exposure findings](#exposure-findings) such as Telnet on a printer or an expired certificate, worst first.

### Filtering and sorting the host list

`/` filters the host list to addresses, hostnames, an open port's service name or product, or an exact open port number - case-insensitive, substring match except the port number. `o` cycles the sort order: by address (default), by open-port count (most first), or by worst potential CVE (severity, then CVSS score). Both apply only to the Hosts tab's list; Services and Vulns have their own grouping.

### Rescanning one host

`r` on a host re-scans just that one address, every port (1-65535), with service detection and vulnerability matching on regardless of the main scan's settings - it keeps the original scan's type, timing and rate cap. Only one rescan runs at a time, and only once the main scan has finished. Its results replace that host's row when it completes; stopping it (`s`) or a failure leaves the earlier results exactly as they were, so a partial rescan never hides ports the first pass already found. The scan is auto-saved again afterward as a new file - the original stays on disk as a comparison baseline.

### Copying to the clipboard

`y` copies the selected host's address (or `ip:port` when the ports pane is focused); `Y` copies that host's CVE IDs. This uses the terminal's OSC 52 escape sequence, not a clipboard library - supported by most modern terminals (Windows Terminal, iTerm2, kitty, WezTerm, Alacritty, foot, xterm with `allowWindowOps`), though some disable it or ask first, in which case nothing visibly happens. Inside tmux it needs `set -g allow-passthrough on` (or `set-clipboard on`); GNU screen isn't supported. Copies over 8 KiB are refused rather than silently truncated.

### Colors

Set `NO_COLOR` (non-empty, per [no-color.org](https://no-color.org)) to draw every frame without foreground or background colors - bold, dim and reversed still apply, so the selected row and key labels still stand out. Useful over a monochrome connection or for screen readers.

### Settings

`F2` on the setup form, or `S` (or `F2`) on the results screen, opens Settings. `Tab`/`↑↓` move between rows, `Enter`/`Space` press a button or flip a checkbox, and `Esc` goes back. A change is saved as soon as you make it - for the text fields, when you press `Enter` or leave the field; an invalid value stays in the field with the reason shown and isn't saved (`Esc` discards it).

| Setting | Default | What it does |
|---|---|---|
| Build from NVD | - | Builds the CVE data on your computer from the NVD API and CISA KEV, after saying whether it will be a full build or a refresh and roughly how long it takes, and asking **y/n** (below). While it runs, the same button reads **Cancel build**. |
| Download prebuilt | - | Downloads the latest prebuilt CVE data, after showing what it will download and asking **y/n** (below). |
| NVD API key (`nvd_api_key`) | empty | Your own free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key), used only by Build from NVD; it raises NVD's rate limit so a full build takes 10-15 minutes instead of about 30. Shown masked (`••••••••-…-1a2b`) except while you edit it. Letters, digits, `-` and `_` only, at most 64. The environment variable `NVD_API_KEY`, if set, overrides it, and Settings says so. **Copy key request link** puts the request page's address on the clipboard (OSC 52, as `y` does), since clicking links in terminals varies. |
| Update URL (`vuln_update_url`) | `https://hroberts1.github.io/rmap/vulns.json` | Where Download prebuilt reads the manifest. A setting still holding the old default (`.../releases/download/vulndb/vulns.json`) is moved to the new one automatically. Must be `https://` (or `http://` to this computer); `Reset URL to default` puts it back. |
| Check for updates on startup (`vuln_check_on_startup`) | off | When on, rmap fetches the manifest each time it starts and, if newer data exists, says so (`newer CVE data is available ...`). It never downloads on its own. |
| Warn when data is older than N days (`vuln_stale_days`) | 30 | CVE data older than this is flagged in the results header and in Settings. 1-365. |
| Highlight actively exploited CVEs (`vuln_highlight_exploited`) | on | Shows the `actively exploited (CISA KEV, added ...)` line under such CVEs in the detail pane and the Vulns tab. Exploited CVEs are still listed first when it's off. |

The screen also shows where the CVE data lives and where it came from (`built 2026-11-01 (17 days ago) · 12,345 CVEs · NVD API 2.0 + CISA KEV (built locally)`, or `... (prebuilt download)`), or that there is none yet - in which case the setup form's Vulns row says `no CVE data yet: F2 to set up`, and ticking Vulns (or picking a profile that turns it on) shows a pop-up that leads here.

Only one build or download runs at a time, and neither starts while a scan or rescan is running (it reads the CVE data). Leaving Settings cancels a check or an unanswered question; a build or download already running finishes in the background and reports to the log panel. Results and errors are also written to rmap's log file.

**Network use:** rmap contacts nvd.nist.gov and cisa.gov only when you press Build from NVD, and the update URL only when you press Download prebuilt (or at startup, if you turned that on). Scanning never fetches anything.

**Build from NVD**, step by step: rmap asks first, e.g. `Build the CVE data from NVD? Full build (no CVE data yet): every CVE, about 30 minutes without an API key, 10-15 with one. Uses your NVD API key from Settings; ...` or `Refresh: fetches only CVEs changed since the last NVD sync (3 days ago), usually a minute or two.` On `y` it builds in the background with live progress (`NVD: 120,000 of 330,000 CVEs (36%) · about 14 min left`); press the button again (**Cancel build**) to stop after the current request. Cancelling or any failure leaves your current data exactly as it was. See [Building from NVD](#building-from-nvd) for how it works.

**Download prebuilt**, step by step: rmap fetches the manifest in the background (`checking github.com…`), then asks, e.g. `Download 4.2 MB of CVE data built 2026-11-15 (12,345 CVEs) from github.com?` - and says plainly if that build is **older** than the data you have, or the same one. On `y` it downloads with live progress, verifies and installs (see [Updating vulnerability data](#updating-vulnerability-data) for the checks).

Settings live in `settings.json`, in `%APPDATA%\rmap` on Windows, `~/Library/Application Support/rmap` on macOS, and `$XDG_CONFIG_HOME/rmap` (or `~/.config/rmap`) elsewhere. It's plain JSON with the field names above; missing fields take their defaults and unknown ones are ignored. A value that fails validation falls back to its default with a warning on the setup form; a file that isn't valid JSON is moved to `settings.json.bad` (and defaults are used) rather than being overwritten. Because it can hold your NVD API key, on Linux and macOS rmap writes it readable by you only (mode 0600); on Windows it sits in your per-user `%APPDATA%`, which other ordinary users can't read. The key is never written to logs, crash reports or exports, and is sent only to NVD, as the `apiKey` request header (never in a URL). Prefer `NVD_API_KEY` if you'd rather not store it at all.

## Scan profiles and recent targets

A profile is every setup-form field except Targets. Three are built in (quick TCP connect, a full service-and-vuln scan, and a fast SYN sweep); save your own with `Ctrl-S`, pick one with `Ctrl-P` (`Delete` or `d` removes a saved one - the built-ins can't be deleted), and pick from your last 10 target strings with `Ctrl-R`. Both lists persist as `profiles.json` and `recent.json` next to the saved scans (see below); a missing or unreadable file falls back to the defaults with a warning, and a corrupt one is moved aside so the next save can't silently destroy it.

## Saved scans, export and comparing

Every scan is saved automatically when it finishes, is stopped, or fails (and when you quit mid-scan). The log panel shows the file it went to. Stopped and failed scans are marked as partial.

| Platform | Saved scans | Exports (default) |
|---|---|---|
| Linux | `$XDG_DATA_HOME/rmap/scans`, or `~/.local/share/rmap/scans` | `.../rmap/exports` |
| macOS | `~/Library/Application Support/rmap/scans` | `.../rmap/exports` |
| Windows | `%LOCALAPPDATA%\rmap\scans` | `%LOCALAPPDATA%\rmap\exports` |

Set `RMAP_SCAN_DIR` to keep scans somewhere else; exports then default to `$RMAP_SCAN_DIR/exports`. Files are named `scan-YYYYMMDD-HHMMSS-mmm.json` (UTC start time), so they sort oldest to newest.

**Export (`e`).** Pick a format with `Tab`, edit the path if you like (`Ctrl-U` clears it), and press `Enter`:

- **JSON:** rmap's own report format, the same one used for saved scans. It carries a `format_version` so later versions of rmap can keep reading old files. It records the rmap version, start and end times, how the scan ended (`completed`, `stopped`, `failed`), the configuration, and every host with its open and open|filtered ports, detected services and CPEs, and closed/filtered counts. It also carries a [`summary` block and `findings`](#json-summary) for other tools to ingest.
- **Nmap XML:** the commonly used subset of Nmap's documented XML output (`nmaprun`, `scaninfo`, `host`, `status`, `address`, `hostnames`, `ports`, `extraports`, `port`, `state`, `service` with product/version/extrainfo/CPE, `times`, `runstats`), so tools that import Nmap results can read rmap scans. It's written by rmap's own small XML writer; times are in UTC, and CPEs are converted to the `cpe:/` form Nmap uses.
- **Markdown:** a readable summary for pasting into a ticket: scope, times, hosts up, open ports and potential CVE counts by severity, then a ports table and findings per host, then all matches grouped by product and version (distro-build, conditional and client-only matches as one collapsed line each).
- **CSV:** one row per open or open|filtered port (`ip, hostname, port, protocol, state, service, product, version, info, cves, worst_severity, cve_check, exploited, exposure_findings`). Every field is quoted per RFC 4180, and fields a spreadsheet would treat as a formula (starting with `=`, `+`, `-`, `@`, tab or CR) get a leading `'`, since banners and hostnames come from the scanned devices.
- **HTML:** one self-contained, printable page for handing to a client: inline CSS only, no JavaScript or external requests (a Content-Security-Policy blocks them), light and dark friendly.

Every scanned string is escaped for its format, and control characters (terminal escape sequences) and bidirectional overrides are replaced with `�`. CVE matches are version-based, so the Markdown and HTML reports call them *potential* findings to verify before acting.

**Compare (`c`).** Once a scan has finished or been stopped, press `c` to pick a saved scan to compare against. The list is newest first, with the most recent earlier scan of the same targets selected. The diff screen lists, color-coded:

- new hosts and hosts that are gone
- hosts that went up or down
- newly open ports, and ports that closed or vanished
- ports whose state changed (for example `open|filtered` → `open`)
- services whose name, product or version changed, such as `OpenSSH 8.9 → OpenSSH 9.6`

Hosts match by address and ports by port number and protocol, so ordering doesn't matter. A port that had no service identified in one of the scans isn't reported as a service change. Scroll with `↑↓`/`PgUp`/`PgDn` and press `Esc` to go back.

## How it works

```
crates/
├── rmap-core     targets, port lists, timing templates, result types
├── rmap-engine   async scan engine (tokio)
├── rmap-detect   service detection: probes, matcher, TLS, CPEs
├── rmap-log      local log files and crash reports (no dependencies)
├── rmap-oui      MAC address vendor lookup, hand-written table (no dependencies)
├── rmap-names    host names: reverse DNS, NetBIOS and mDNS lookups (tokio only)
├── rmap-packet   Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP/ICMPv6 building and parsing (no dependencies)
├── rmap-report   scan reports: JSON, Nmap XML, Markdown, CSV and HTML export, saved scans, diffs
├── rmap-vuln     vulnerability matching: CPE -> CVE lookup in a local SQLite database file and its verified download (rusqlite, ureq)
├── rmap-nvd      builds that database from the NVD API 2.0 and CISA KEV, in full or as a refresh (ureq)
└── rmap-tui      ratatui front end
src/main.rs       starts logging, the runtime and the UI
```

The engine runs a scan as a tree of tasks: one coordinator, one task per host (limited by the timing template's host parallelism), and one task per probe (limited by a global semaphore). Results stream to the UI over a channel. Progress is shared through atomics, so a scan of 65,535 ports doesn't send 65,535 messages. Closed and filtered ports are counted, not stored, so memory stays flat on large ranges.

Stopping a scan aborts the coordinator. Every level owns its children in a `JoinSet`, so cancellation reaches every in-flight probe.

### Port states (TCP connect)

| Result of `connect()` | State |
|---|---|
| Handshake completes | open |
| Connection refused (RST) | closed |
| No answer after retries, or unreachable | filtered |

Host discovery without root works the same way: a host counts as up if any of ports 80, 443, 22, 445 or 3389 accepts or refuses a connection.

### Raw scans

The raw backend (`crates/rmap-engine/src/raw`) sends packets built by `rmap-packet` over an `IP_HDRINCL` socket and reads replies on raw TCP and ICMP sockets. A SYN's sequence number is a keyed hash of the target address, target port and source port, with a random key per scan, so replies are matched without keeping state and unrelated traffic is ignored. Probes leave from the address the kernel's routing table picks for each target. A per-template packet rate limit keeps fast templates from flooding the link.

| SYN scan reply | State |
|---|---|
| SYN-ACK (the kernel then resets the half-open connection) | open |
| RST | closed |
| ICMP unreachable, or nothing after retries | filtered |

| UDP scan reply | State |
|---|---|
| Any UDP datagram | open |
| ICMP port unreachable (type 3, code 3) | closed |
| Other ICMP unreachable codes | filtered |
| Nothing after retries | open\|filtered |

UDP probes carry real requests for DNS, NTP, SNMPv1 (`public`, see [UDP detection](#udp-detection)), NetBIOS name service and SSDP, so those services answer instead of staying silent; other ports get an empty datagram. Linux limits how fast it sends ICMP errors, so on fast templates some closed UDP ports can show as open|filtered.

Privileged discovery uses ARP for targets on a directly connected Ethernet subnet (an unanswered ARP request means the host is down) and, elsewhere, ICMP echo raced against the TCP connect ping.

### Adaptive timeouts

Each host keeps a smoothed round-trip time and its variation (SRTT/RTTVAR, as in RFC 6298), updated from every answered probe, so a LAN host that replies in a millisecond isn't waited on for the whole template timeout and a slow WAN host gets longer before its ports are called filtered. The adapted timeout never drops below the template's `min_rtt_timeout` (100-400 ms) - tens to hundreds of times a real LAN RTT, so a scheduling hiccup can't turn an open port filtered - and never rises above `max_rtt_timeout`. T0 and T1 fix both bounds to `connect_timeout`, so paranoid/sneaky timing is unaffected. Unanswered probes never feed the estimate, since a filtered port's timeout says nothing about the path.

### MAC vendor lookup

When ARP discovers a host's hardware address, the host detail pane shows it with the vendor, if known: `mac 00:11:32:aa:bb:cc · Synology`. The table (`crates/rmap-oui`) is small and hand-written - vendors common on small-business and home networks, only prefixes rmap is sure of - not the IEEE registry, so an unlisted prefix means "not in this table," not "unregistered." A locally administered address (randomised Wi-Fi MACs, most VMs and containers) is reported as "random MAC" instead of guessed, since its prefix isn't a real vendor's. A host with no hostname but a recognised vendor shows the vendor name in the host list in its place.

### Host names

With **Names** ticked on the setup form (the default), rmap looks up every live host's names while its ports are scanned, from three sources at once: reverse DNS (a PTR query), the host's NetBIOS name table (UDP 137) and its own mDNS responder (UDP 5353). No single one names everything: DNS covers domain-joined and DHCP-registered machines, NetBIOS covers Windows PCs, Samba, NAS boxes and many printers, and mDNS covers Macs, phones, Linux, printers and IoT. The best name fills the host list (DNS first, then NetBIOS, then mDNS); the detail pane lists all of them with their source, e.g. `names frontdesk.corp.lan (DNS) · FRONTDESK (NetBIOS)`, which makes a stale DNS record easy to spot. A name typed as the target is kept.

Reverse DNS uses the **DNS server** field if set, otherwise the system resolver (`/etc/resolv.conf` on Linux, the first IPv4 DNS server Windows reports on Windows). Set the field to override it, for example to the client's domain controller when your machine isn't using it; NetBIOS and mDNS work either way. Each lookup is one small UDP packet that waits its turn under the rate cap, loopback targets skip reverse DNS, and names from the network are cleaned of control characters before they're shown or saved. Names go into every export, and the scan diff reports a host whose name changed.

### Device grouping

One device often answers at several addresses: a server wired and on Wi-Fi, a NAS with two NICs, a gateway's decoy address. rmap links them so they aren't counted, or their CVEs listed, twice. Two up hosts are one device when they have:

- **the same MAC address** (strongest; this also links a decoy or proxy-ARP address to the device behind it, which is worth seeing), or
- **the same SSH host key or TLS certificate** - unless more than 4 hosts share it, which means a vendor default or a cloned image, not one device (logged and ignored), or
- **neighbouring burned-in MACs** (same vendor prefix, 1-2 apart, like a multi-port NIC) **and** the same short hostname or the same vendor. Neighbouring MACs alone aren't enough: machines from one batch can have them too.

Links are transitive. The Hosts tab shows a device's other addresses right under its first one, marked `↳`, and the detail pane says `same device as …` with the reason for each link. The Vulns tab and the Markdown and HTML reports list a CVE found on the same product version at several addresses of one device once, with every address, and count it once. The scan diff doesn't call a device's new address a new host when the device was already up. JSON reports carry each grouped host's `device_group` (`id`, `members`, `reasons`) and a top-level `devices` count; both are recomputed whenever a report is loaded, so older saved scans gain them too. CSV and XML stay one row per address.

## Service detection

Tick **Services** on the setup form and rmap identifies the software behind each open TCP port, and each open or open|filtered UDP port. The port table shows the service and version, and the details pane adds a line per port with extra information, the OS the service revealed, and a [CPE 2.3](https://nvd.nist.gov/products/cpe) name:

> **Printers are safe to scan.** Raw-print ports (JetDirect/AppSocket 9100-9107) and LPD (515) print whatever bytes arrive, so a probe sent there comes out of the printer as a page of garbage. rmap only *listens* on those ports and never sends them a byte; they show as `jetdirect` or `printer` with `not probed: data sent here would print`. IPP (631) is HTTP and is probed normally.

```
22/tcp  open  ssh   OpenSSH 8.9p1
                    └ protocol 2.0; Ubuntu-3ubuntu0.6 · os: Ubuntu Linux · cpe:2.3:a:openbsd:openssh:8.9:p1
```

How it works (`crates/rmap-detect`):

1. **Choose probes.** Probes that list the port go first, then the generic ones: wait for a banner, `GET / HTTP/1.0`, a TLS ClientHello, and blank lines. So HTTP on port 8443 or SSH on port 2200 is still found.
2. **Send and read.** Each probe uses a fresh connection and reads until the server closes, goes quiet for half a second, has sent 16 KiB, or the probe's wait runs out. Each port gets a time budget of ten connect timeouts (5-30 s). Detection runs at most `concurrency / 8` ports at once (1-64), separately from port probes, so it can't slow the scan down.
3. **Match.** The reply is checked against the probe's rules, then against the rules of its `fallback` probes (an SSH server answering an HTTP probe still sends its banner). TLS replies are decoded in code: protocol version, and the certificate's common name, alternative names, issuer and expiry, read with a small DER parser. rmap offers TLS 1.2 at most, so the certificate arrives unencrypted. Plain HTTP replies also give the page's `<title>` (entities decoded, control and bidi characters removed, at most 80 characters) as `title "…"` in `info`; when the page has none, rmap follows one redirect to the same address and port. Many printers, NAS boxes and controllers only name themselves there. Titles are not read over TLS yet.
4. **Report.** Matches get a CPE from rmap's product table, with versions split the way NVD records them (`8.9p1` becomes version `8.9`, update `p1`). If nothing matches, rmap reports the port-table name with low confidence, plus the start of any reply it didn't recognise.

`Service::method` says how the result was reached (`banner`, `probe`, or `port_table`), and `confidence` runs from 0 (guess) to 10. On screen and in the Markdown and HTML reports, a name guessed from the port number alone ends in `?` (`weblogic?`); JSON, XML and CSV keep the plain name next to the method. A TCP port that accepts connections but never sends a byte to any probe (or closes at once) keeps its `?` guess with the note `connection accepted, no response` at confidence 1 - what Nmap calls `tcpwrapped`. When every one of five or more open ports on a host behaves like that, the details pane says a firewall or IPS is likely answering for the host.

Covered today: OpenSSH, Dropbear, nginx, Apache httpd, Microsoft IIS and HTTPAPI, lighttpd, Caddy, Tomcat Coyote, Elasticsearch, Postfix, Exim, Sendmail, Microsoft Exchange, vsftpd, ProFTPD, Pure-FTPd, FileZilla Server, Microsoft FTP, Dovecot, Courier, MySQL, MariaDB, PostgreSQL, Redis, Valkey, MongoDB, Memcached, RabbitMQ, Asterisk and Apple Remote Desktop, plus the protocols SSH, HTTP (any `Server:` header), FTP, SMTP, POP3, IMAP, TLS, SMB, RDP, VNC, telnet, SIP, RTSP, AMQP and MQTT. Over UDP: DNS (`version.bind`: BIND, dnsmasq, Unbound, PowerDNS, Knot, Microsoft DNS), NTP (ntpd and NTPsec versions over mode 6 control queries, otherwise stratum and reference from a mode 3 request), SNMP v2c and v1 (the sysDescr: Cisco IOS version, Windows, Linux or FreeBSD), NetBIOS name service (host name, workgroup, MAC), mDNS / DNS-SD (the advertised service types) and SSDP / UPnP (MiniUPnPd, libupnp, any `SERVER:` header).

### UDP detection

UDP probes are `protocol udp` blocks in `probes.txt`, tried only on the ports they list; there are no generic UDP probes, so unknown UDP ports cost nothing. Each probe sends one datagram on a connected socket and reads the first reply. DNS, NTP, SNMP, NetBIOS and mDNS replies are binary and decoded in code (`crates/rmap-detect/src/udp.rs`), which checks that the reply really answers rmap's request; the probe's match rules then read the text the decoder pulled out (the `version.bind` string, NTP system variables, the SNMP sysDescr) to name the product and version, so vulnerability matching works for them too. All text taken from a reply is escaped before it is shown.

A port the UDP scan left as open|filtered is reported as **open** if any detection probe gets a reply. For UDP ports, detection therefore runs before the `Port` event is sent, which carries the final state; the `Service` event still follows it.

**SNMP community guessing.** Both the UDP port scan (SNMPv1) and detection (SNMPv2c, then v1) send a GetRequest for sysDescr with the community string `public`. A reply means the agent accepts that community, which is reported in the port's info. Some intrusion detection systems and SNMP agents log or alert on requests with a guessed community, and a few lock out the source after failed attempts. Only scan UDP 161 on networks you are authorised to test, or leave 161 out of the port list.

### Adding a probe or match rule

The database is [`crates/rmap-detect/src/probes.txt`](crates/rmap-detect/src/probes.txt), in a format specific to rmap. It is not Nmap's format and must not contain Nmap data.

```text
probe memcached
  send     "version\r\n"          # quoted bytes with \r \n \t \0 \ \" \xHH, or @builtin
  ports    11211                  # tried first on these ports
  wait     5s                     # optional, default 5s
  fallback banner                 # also apply these probes' rules

match memcached ^VERSION ([\d.]+)\r\n
  product  Memcached
  version  $1                     # $1-$9 insert capture groups
  info     ...                    # optional: info, os, confidence (0-10)
```

A probe without `send` waits for a banner, and `generic` runs it on every port. Rules are tried top to bottom and the first match wins, so put specific rules first. A pattern is the rest of its `match` line, written in a small regex-like language that runs in linear time on raw bytes (no backtracking): literals, `.`, classes like `[^\r\n]`, `\d \w \s`, `\xHH`, groups `( )` and `(?: )`, `|`, `* + ?` and their lazy forms, `{n,m}`, `^` (start of reply), `$` (end of line), and leading `(?i)` / `(?s)` flags. [`pattern.rs`](crates/rmap-detect/src/pattern.rs) documents the full syntax.

When you add a rule:

1. Add a realistic reply for it to `rule_tests.rs`. The test fails if any rule has no test.
2. If it names a new product, add the product's NVD vendor and product to the table in `cpe.rs` with a test case, or list it as having no CPE.
3. Run `cargo test -p rmap-detect`.

## Vulnerability matching

Tick **Services** and **Vulns** on the setup form and rmap checks every identified service's CPEs against a local CVE database, showing a colored line per potential match under the port it applies to:

```
22/tcp  open  ssh   OpenSSH 9.6p1
              └ CVE-2024-6387 (high 8.1): regreSSHion: signal handler race condition in sshd allows unauthenticated remote code execution
```

A match is **potentially** vulnerable, not certain: a vendor backport can fix the real bug while leaving the version string unchanged, and a version with no entry in the database is not evidence it's safe. This is an offline lookup against a local database file, not a live query - nothing is sent anywhere during a scan.

### Match tiers

A version match alone over-reports (a field review of four OpenSSH ports found 120 matches and no real server-side finding), so rmap sorts every match into one of four tiers and only the first two count:

| Tier | When | Shown |
|---|---|---|
| potential | The version is in range and the CVE needs nothing else. | Listed in full, worst first; CISA KEV entries get the red marker and sort first. |
| upstream only | As above, but the banner names a distro package (`Ubuntu-*`, `Debian-*`, `+deb*`, `.el<N>`, `FreeBSD-*`), so the port's status is `checked_upstream_only` and the distro may have backported the fix without changing the upstream version. | Counted, but folded into one line: `29 potential CVEs (OpenSSH 10.2p1): upstream version; Ubuntu may have backported fixes`. Check the distro's security tracker for the package version. |
| conditional | NVD says the CVE needs a platform too ("OpenSSH **with** musl libc", "**on** RHEL 5"), which a network scan can't verify. The JSON export keeps it as `condition`. | Apart from the counts, with `conditional: only with musl-libc:musl (not verified)`; never the KEV marker, never sorted first. |
| client-only | The CVE is in a client program (`ssh`, `scp`, `sftp`, `ssh-keygen`, `ssh-agent`), not reachable through a listening port. The JSON export marks it `client_only`. | Not counted; only a count on the group's line. |

**How client-only is decided.** At database build time, from the CVE's English description, for CVEs whose every match is OpenSSH: a description starting `In ssh `, `ssh in OpenSSH`, `In sftp `, `sftp in OpenSSH`, `In scp `, `scp in OpenSSH`, `In ssh-keygen `, `ssh-keygen in OpenSSH`, `In ssh-agent ` or `ssh-agent in OpenSSH`, or containing `client side`, is client-only - unless it mentions `sshd` anywhere, since server wording wins. It is a deliberately small, conservative list (`OPENSSH_CLIENT_OPENINGS` in `crates/rmap-nvd/src/convert.rs`): a client CVE worded some other way (`a file downloaded by scp ...`) stays counted rather than risk hiding a server bug. Other products get rules as their noise shows up.

### Was the port actually checked?

"No CVEs listed" must never be confused with "safe", so every port with a detected service gets a CVE check status. It shows as a dim line under the port in the detail pane, and in every export:

| Status | Shown as | What it means for you |
|---|---|---|
| checked | `no known CVEs for nginx 1.24.0` / `2 potential CVEs (nginx 1.24.0)` | The product and version were looked up. No matches means the database knows of nothing for that version, not that the service is secure. The count leaves out conditional and client-only matches. |
| checked upstream only | `29 potential CVEs (OpenSSH 10.2p1): upstream version; Ubuntu may have backported fixes` | As checked, for a distro build (see [Match tiers](#match-tiers)). |
| version hidden | `nginx detected, version unknown: can't check` | The product was identified but not its version (banner hidden or unversioned). rmap does **not** guess: a hidden version is never matched against "before version X" CVEs. Check the version on the device. |
| no product | `product not identified: can't check` | The service is known only by its protocol or port number, so there is nothing to look up. |
| not covered | `no CVE data for vsftpd: not checked` | The product was identified, but the CVE database (or rmap's product-to-CPE table) has nothing on it. |
| no database | `no vulnerability data: not checked` | Matching was on but no usable database was found. |

Everything except "checked" counts as **unchecked**: the header's bottom border shows how many (`4 unchecked`), the Vulns tab and the Markdown and HTML reports open with a "CVE coverage: N of M open ports checked" line, and `/` with the filter text `unchecked` lists the hosts that have any. When a service carries several CPEs, the port gets the best outcome among them (checked, else version hidden, else not covered).

**Actively exploited.** CVEs on CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list carry a bold red `actively exploited (CISA KEV, added YYYY-MM-DD)` marker in the detail pane and the Vulns tab, where they sort first, and the same text in the Markdown and HTML exports - but only on potential and upstream-only matches, never on a conditional or client-only one. These are being used in real attacks: fix them first.

**Data age.** The header's bottom border also shows when the CVE data was built (`CVE data 2026-11-01`); once it is more than 30 days old that turns into a warning (`CVE data 45 days old`), since anything published after that date can't be matched. Reports record the same thing ("Vulnerability data: built 2026-11-01, 245000 CVEs").

### The database file

The CVE data is a SQLite file, `vulns.db`, in rmap's data directory (next to the saved scans):

| Platform | Path |
|---|---|
| Linux | `$XDG_DATA_HOME/rmap/vulns.db`, or `~/.local/share/rmap/vulns.db` |
| macOS | `~/Library/Application Support/rmap/vulns.db` |
| Windows | `%LOCALAPPDATA%\rmap\vulns.db` |

rmap doesn't ship CVE data in the binary. If the file is missing or unreadable, the scan runs normally with one warning (`no vulnerability data at <path>; CVE matching skipped`) and no CVE lines. Building or downloading it from inside rmap is covered [below](#updating-vulnerability-data).

The schema (`rmap_vuln::SCHEMA_SQL`, version 2) is rmap's own - not Nmap's `nmap-vulners` or any other scanner's database:

- `meta`: `schema_version`, `built_at` (RFC 3339 UTC), `source`, `cve_count`, plus the NVD builder's `nvd_last_modified` and `nvd_products` (used only to decide whether a refresh is possible). rmap refuses a file whose `schema_version` it doesn't know. A version 1 file (before match tiers) is reported as `in an older format (v1, this rmap reads v2): rebuild it or download a new copy in Settings`, both in the scan warning and on the Settings screen, and the next **Build from NVD** is a full build; it is never read with the new columns missing.
- `cve`: one row per CVE - `id`, `summary`, `severity` (`low`/`medium`/`high`/`critical`), optional CVSS `score`, `published` date, `kev_added`, the date it joined CISA's Known Exploited Vulnerabilities list, and `client_only` (1 for a client-program CVE).
- `cpe_match`: which versions of which product each CVE affects - lowercase `vendor` and `product` as `crates/rmap-detect/src/cpe.rs` produces them, then either `version_exact` or a range (`start`/`end`, each inclusive or exclusive, missing = open-ended). A CVE can have several rows, for disjoint ranges across branches; a row with no version at all matches every version. `condition`, when set, is the platform an NVD AND configuration also needs, as text (`musl-libc:musl and linux:linux_kernel`).

`rmap_vuln::Writer` builds a file in this format. The file will come from the internet, so rmap treats it as untrusted: it opens it read-only, uses only bound query parameters, refuses views in place of its tables, skips rows that don't fit the schema, and replaces control characters in CVE text before it can reach the terminal.

How matching works (`crates/rmap-vuln`):

1. Each detected service's CPE 2.3 strings give a vendor, a product, and the version + update combined (e.g. `9.7p1`). The database's rows for that vendor and product are fetched by index.
2. Each row's range is checked in Rust, comparing versions the way dpkg/rpm do: split into alternating digit and text runs, compare each run in order, and treat a side that runs out of runs first as smaller - so `9.7` sorts before `9.7p1`, and that before `9.7p2`. Versions are stored in that same combined form.
3. Matches are deduplicated by CVE id (an unconditional row wins over a conditional one) and reported newest first.

### Updating vulnerability data

There are two ways, and you pick in Settings: **Build from NVD** builds `vulns.db` on your computer ([below](#building-from-nvd)); **Download prebuilt** fetches a file the maintainers publish monthly. Both write the new file to `vulns.db.part` next to the real one, check it, and only then rename it over `vulns.db` in one step; any failure (or a cancelled build) deletes the `.part` file and leaves the old database untouched. On Windows the old file can't be replaced while a scan has it open; close running scans and try again. Nothing is fetched unless you ask.

#### Download prebuilt

`rmap_vuln::update` downloads a fresh `vulns.db`; the Settings screen's "Download prebuilt" calls it, after asking (see [Settings](#settings)). By default it reads the manifest `vulns.json` from this project's GitHub Pages site (`rmap_vuln::DEFAULT_MANIFEST_URL`, `https://hroberts1.github.io/rmap/vulns.json`), whose `db` field names the current month's release file; you can change it in Settings (Update URL) to host the files yourself, or to use a fork's data. The manifest gives the database's schema version, build time, CVE count, size and SHA-256.

Before anything replaces your current database, rmap checks that:

- every URL, including each redirect, is `https://` (plain `http://` only to `localhost`/`127.0.0.1`/`[::1]`), with no user name or password in it;
- the manifest is under 64 KiB, well-formed, and in a schema this rmap reads (a newer one asks you to update rmap);
- the download, streamed to `vulns.db.part` next to the real file, is exactly the manifest's size (at most 512 MiB) and SHA-256;
- the downloaded file opens as a valid database whose CVE count matches the manifest.

The SHA-256 protects against corrupt or truncated downloads; authenticity rests on HTTPS to the release host (Mozilla's CA list via webpki-roots, rustls). The standard `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` and `NO_PROXY` environment variables are honored (for building from NVD too).

### Building from NVD

`rmap_nvd::build` (crate `crates/rmap-nvd`) builds `vulns.db` straight from the sources, on your computer, with your own NVD API key if you set one. Settings → **Build from NVD** runs it on a background thread; the maintainers' monthly prebuilt file is made by the same code.

1. Downloads CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list, then CVEs from the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities), 2000 per page, within NVD's rate limits (one request per 6 s without an API key, one per second with one), retrying rate-limit (403/429) and server errors with backoff. Cancelling stops before the next request or retry wait.
2. Keeps only CVEs that affect a product rmap can detect (the vendor/product pairs in `crates/rmap-detect/src/cpe.rs`, via `rmap_detect::cpe::nvd_products`), which keeps the file to a few MB. Rejected CVEs are dropped.
3. Writes `vulns.db.part`, checks that it opens as a valid database with the expected CVE count, and refuses to replace your data if fewer than 500 CVEs (or 500 KEV entries) came back, so a broken response never replaces good data. Then renames it over `vulns.db`.

**Full build or refresh.** The file records NVD's newest `lastModified` time it has seen (`meta.nvd_last_modified`) and which product table it was built for (`meta.nvd_products`). If that sync time is less than 118 days old (NVD allows at most a 120-day `lastModStartDate`/`lastModEndDate` window) and the product table matches this rmap, the next build is a **refresh**: it copies the current file to `.part`, fetches only CVEs modified since (starting a day early, to cover clock differences and changes made during a long sync), deletes each changed CVE and re-adds it as NVD now has it (a rejected CVE, or one that no longer affects a detected product, stays deleted), re-applies the current KEV dates to every CVE, then checks and replaces the file as above. Otherwise - no data yet, a file without a sync time, an older sync, a different rmap version's product table, or a file with anything besides rmap's own tables - it does a full build. A prebuilt download made by the same rmap version can be refreshed too.

Network use and privacy: only `services.nvd.nist.gov` and `www.cisa.gov` over HTTPS, no redirects followed (so the key can't be forwarded elsewhere), and the key goes only in NVD's `apiKey` request header.

How NVD data is converted:

- Each vulnerable `cpeMatch` becomes a `cpe_match` row: `versionStart*`/`versionEnd*` become range bounds; a CPE with a concrete version and no range becomes an exact version, with `update` appended the way rmap-detect splits it (`9.7` + `p1` → `9.7p1`). Versions keep CPE 2.3 escaping exactly as rmap-detect writes them, so they compare equal.
- A CPE with version `*` and no range means NVD lists every version as affected, and is stored as a row with no bounds, which matches any version. Version `-` (not applicable) is skipped.
- Severity and score come from CVSS v3.1, else v3.0, else v4.0, else v2 (NVD's primary metric first; v2's low/medium/high kept as NVD rated them). A CVE with no CVSS data yet is kept with no score and severity `medium`, or `high` if it is on the KEV list.
- Summary: the English description, whitespace collapsed, at most 1000 characters. `published` is the date part of NVD's timestamp; `kev_added` is the KEV `dateAdded`.
- **AND configurations** ("X running on / with Y"): X's matches keep the configuration's non-vulnerable CPEs as their `condition` - a node's choices joined by `or`, nodes by `and`, a negated node as `not ...`, an unreadable CPE as `an unrecognised platform` (never dropped, which would make the match unconditional).
- `client_only` comes from the description, as described under [Match tiers](#match-tiers).

Limitations:

- **Conditions aren't checked.** A scan can't see a host's libc or PAM setup, so every conditional match stays conditional, even when the OS hint makes the platform unlikely.
- **Distro builds aren't resolved.** rmap doesn't read the Ubuntu/Debian/Red Hat security trackers, so an upstream-only match may already be fixed in the package.
- **NVD's backlog.** Many recent CVEs have no CPE data yet (NVD enrichment lags publication), so they can't be matched to a product and aren't in the file until NVD analyses them; the next build or refresh picks them up once NVD updates them.
- **KEV on unscored CVEs.** A CVE with no CVSS data gets its placeholder severity when it is fetched; if it joins the KEV list later, a refresh updates its KEV date (and its marker) but its severity only once NVD next modifies it.

### Vulnerability data (maintainers)

Ordinary users never need GitHub Actions: Build from NVD works on its own. The **Vulnerability data** Action only publishes the optional prebuilt file behind **Download prebuilt**.

> **New repository or fork? One-time setup** (ordinary users never need this; it only publishes the optional prebuilt file):
> 1. Settings → **Pages** → Build and deployment → Source: **GitHub Actions**.
> 2. Optional: Settings → Secrets and variables → Actions → add `NVD_API_KEY` (a full keyless build takes about 25 minutes).
> 3. Actions → **Vulnerability data** → **Run workflow** on `main`. When it's green, Releases shows `vulndb-YYYY-MM-DD` with `vulns.db` and `vulns.json`, and `https://<owner>.github.io/<repo>/vulns.json` serves the manifest.
>
> A fork that doesn't publish its own data can leave Update URL on the default and use the upstream data. Turning on **release immutability** (Settings → General → Releases) is supported and recommended.

The Action (`.github/workflows/vulndb.yml`) runs `tools/vulndb-build`, a thin wrapper around `rmap_nvd::build` that always does a full build, on the 1st of every month and on demand (Actions → Vulnerability data → Run workflow, on `main`; other branches skip the job). It writes `vulns.db` and `vulns.meta.json`, then publishes them:

1. A new release tagged `vulndb-YYYY-MM-DD` (a second run on the same day adds the run number) is created as a **draft** with `vulns.db` and the manifest `vulns.json` (`schema_version`, `built_at`, `cve_count`, `source`, `size`, `sha256`, and `db`, the full URL of that release's `vulns.db`) attached, then published. Attaching before publishing is what makes it work with GitHub's [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases): once published, a month's file can't be replaced, so a compromised token can't quietly swap the data people already downloaded. Each month adds a release; old ones stay as a record.
2. The job downloads the published `vulns.db` back and checks its SHA-256, and only then deploys `vulns.json` to GitHub Pages, so the manifest never points at a missing or different file. Pages is the one place that changes each month; the deploy runs in its own job, the only one with Pages permissions.

Earlier versions used a single release tagged `vulndb` whose files were replaced each month. That breaks once release immutability is on (`HTTP 422: Cannot upload assets to an immutable release`), and an immutable release's tag can never be reused, so that tag is retired.

Run the builder locally (it writes into `OUT_DIR`, which must not already contain `vulns.db` or `vulns.meta.json`):

```sh
OUT_DIR=/tmp/vulndb cargo run --release -p vulndb-build
# A quick trial with one NVD page, which skips the minimum-size check:
NVD_MAX_PAGES=1 OUT_DIR=/tmp/vulndb-trial cargo run -p vulndb-build
```

A full keyless run takes about 25 minutes. An NVD API key ([request one free](https://nvd.nist.gov/developers/request-an-api-key)) makes it faster: set `NVD_API_KEY` locally, or add it as the repository secret `NVD_API_KEY` for the Action. Without the secret the Action still works, just slower.

Data sources and terms: NVD data is a work of the US government and in the public domain; CISA's KEV catalog is public. *This product uses the NVD API but is not endorsed or certified by the NVD.*

## Exposure findings

CVEs aren't the only thing worth fixing. After a scan, rmap also checks the results against a small set of exposure rules: services that are risky just by being reachable, certificates that have expired, and hosts that expose more than their peers. Rules only read the finished results (no extra traffic), and certificate dates are judged against the scan's start time, so a saved scan reads the same next year. Findings show in the `4` Findings tab, in the Markdown, HTML and CSV exports, and in the JSON `findings` array.

| Rule id | Severity | Flags |
|---|---|---|
| `telnet` | high | Telnet (23, or detected anywhere) |
| `ftp` | medium | FTP (21) |
| `pop3`, `imap` | low | POP3 (110) and IMAP (143) without TLS |
| `snmp-v1-v2c` | medium | SNMP v1/v2c answering a community string (detection must have seen the reply) |
| `rdp`, `vnc` | medium | Remote Desktop (3389), VNC (5900-5903) |
| `winrm-http` | low | WinRM over HTTP (5985) |
| `mssql`, `mysql`, `postgresql` | medium | SQL Server (1433), MySQL (3306), PostgreSQL (5432) |
| `redis`, `mongodb`, `memcached`, `elasticsearch` | high | Redis (6379), MongoDB (27017), Memcached (11211), Elasticsearch (9200): no authentication by default |
| `cert-expired` | medium, low if self-signed | A TLS certificate whose `not_after` is before the scan date |
| `cert-expiring` | low, info if self-signed | A certificate expiring within 30 days of the scan |
| `cert-self-signed` | info | A self-signed certificate that isn't expired or expiring |
| `peer-outlier` | medium if SMB/RPC/remote admin, else low | A host with open ports most of its peers don't have |

A port matches when detection identified the service by name, or, when detection couldn't tell, by its usual port number. Ports that accepted a connection but answered nothing (tarpits, honeypots) don't count, and a database port-number guess on a printer is ignored (Zebra printers use 9200 for their own web services).

**Peer outliers.** Hosts are peers when their first hostname label starts the same up to the first digit (`OFFICE-PC014` and `office-pc022.corp.lan` are both `office-pc`). A host is flagged for each open port that fewer than half the group has and at least 3 peers don't, so the one workstation with 135/139/445 open stands out while two odd machines never flag each other. Only hosts whose scan completed count, and the finding names the peer group it was compared with.

### JSON summary

Every JSON export and saved scan has a top-level `summary` block for feeding into other tools. It is recomputed whenever the file is written and ignored when rmap reads one, as is `findings`, so files from older versions load unchanged. Fields are only ever added, never renamed.

| Field | Meaning |
|---|---|
| `hosts_scanned` | Addresses in the scan |
| `hosts_up` | Hosts up, or assumed up when discovery was off |
| `open_ports` | Ports in state `open` (not `open\|filtered`) |
| `open_ports_by_protocol.tcp`, `.udp` | The same, by protocol |
| `cve_check.checked`, `.checked_upstream_only`, `.version_hidden`, `.no_product`, `.not_covered`, `.no_database` | Ports per CVE check status (see [Was the port actually checked?](#was-the-port-actually-checked)) |
| `cve_check.not_run` | Open ports matching never looked at (matching off, or no service detected) |
| `cves_by_severity.total`, `.critical`, `.high`, `.medium`, `.low` | Potential CVE matches, one per CVE per port; potential and upstream-only [tiers](#match-tiers) only |
| `cves_by_severity.upstream_only` | Of `total`, matches on distro builds |
| `cves_by_severity.conditional`, `.client_only` | Matches not in `total`: platform not verified, or client programs only |
| `cves_by_severity.kev` | Counted matches on CISA's Known Exploited Vulnerabilities list |
| `findings_by_severity.total`, `.high`, `.medium`, `.low`, `.info` | Exposure findings |

Each entry in `findings` has `id` (the rule id above), `severity` (`info`, `low`, `medium` or `high`), `ip`, `port` and `protocol` (left out for host-wide findings), `title` and `detail`.

## Logs and crash reports

rmap keeps local diagnostic logs so bugs can be reproduced. **Nothing is sent anywhere**: there is no network telemetry.

Each run writes one log file, and its path is shown at the bottom of the setup screen:

| Platform | Default location |
|---|---|
| Linux | `$XDG_STATE_HOME/rmap/logs`, or `~/.local/state/rmap/logs` |
| macOS | `~/Library/Logs/rmap` |
| Windows | `%LOCALAPPDATA%\rmap\logs` |

| Variable | Effect |
|---|---|
| `RMAP_LOG` | `off`, `error`, `warn`, `info` (default), `debug`, or `trace` (every probe; very large) |
| `RMAP_LOG_DIR` | Write logs somewhere else |

What gets logged:
- **info:** session start (version, OS, arguments), each scan's full configuration, user decisions such as confirming public targets, and an end-of-scan summary with unexpected connect errors tallied by kind
- **debug:** host up/down results, open ports, name resolution, the first 20 unexpected connect errors in full, and which detection probes ran and which rule matched
- **trace:** every probe attempt and keypress, and the first 160 bytes of each detection reply, escaped

If rmap panics, it writes `crash-<time>-<pid>.txt` next to the log. The report holds the panic message, location, a backtrace, and the last 500 log lines at debug level, even when the log file itself is at info. A panic inside a scan worker doesn't crash the app: the scan shows **failed** and the report is written in the background.

The newest 20 logs and 20 crash reports are kept; older ones are deleted. Logs contain the addresses you scanned, so review them before attaching one to a public issue.

## Testing

```bash
cargo test --workspace
```

The suite runs real scans against loopback listeners and the reserved, never-routed `192.0.2.0/24` block, so it needs no network access or privileges. It includes randomized parser tests that feed 100,000 generated strings through target and port parsing, and 200,000 random and mutated packets through the packet parsers, to catch inputs that could panic. If one fails, it prints the seed and the input that broke it. Service detection is tested the same way: fake SSH, HTTP, SMTP, FTP, Redis and TLS servers on loopback, a realistic reply for every match rule, and randomized garbage fed through the pattern matcher, the probe database parser and the TLS and certificate parsers. Vulnerability matching is checked against a test database built with `Writer` from nine real, NVD-verified CVEs and real CPEs, against corrupt, truncated, hostile and wrong-version database files, and end to end through the real engine: a fake OpenSSH banner on loopback, detected for real and matched against a test database, confirms a `Vulnerabilities` event actually arrives after its `Service` event, and a missing database gives one warning while the scan still completes.

SYN and UDP scan tests run everywhere and accept the unprivileged fallback. Tests that insist on raw sockets are `#[ignore]`d; on Linux, run them as root or inside a user and network namespace, which grants `CAP_NET_RAW` over its own loopback without root:

```bash
cargo test -p rmap-engine --no-run    # note the test binary path it prints
unshare -rn sh -c 'ip link set lo up && target/debug/deps/rmap_engine-<hash> --ignored raw_'
```

`raw_veth_peer` also checks ARP and SYN over a real link when given a veth peer; its doc comment has the setup.

## Roadmap

- [x] **M1: engine + TUI shell.** Target parsing, TCP connect scan, unprivileged discovery, live results.
- [x] **M2: raw scans.** Hand-built IPv4/TCP/UDP/ICMP/ARP packets, SYN and UDP scans, ICMP and ARP discovery, rate-limited timing. Needs root or `CAP_NET_RAW`; falls back without. IPv6 SYN and UDP scans and ICMPv6 echo discovery too. RTT-adaptive timeouts, per RFC 6298.
- [x] **M3: service detection.** rmap's own probe and match database, version strings, TLS certificate names, CPE identifiers.
- [x] **M4: vulnerability matching.** Offline CPE → CVE lookup against a local SQLite CVE database, flagged as *potentially* vulnerable to allow for vendor backports.
- [x] **M5: export and diffing.** JSON and XML export from the TUI, saved scans, and comparing two scans.

## Platform notes

rmap is developed for **Linux first**. Milestone 1 also runs on macOS and Windows because it uses only ordinary sockets. On Windows, a connection to a closed port can take about 2 seconds to be refused, so with fast timing templates closed ports may show as filtered. Raw-socket features from M2 onward are Linux-only; elsewhere rmap falls back to unprivileged probes with a warning. Host discovery on Windows sends an ICMP echo (no admin rights needed) alongside the TCP connect ping, and whichever answers first marks the host up.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

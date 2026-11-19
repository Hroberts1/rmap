# rmap

[![CI](https://github.com/Hroberts1/rmap/actions/workflows/ci.yml/badge.svg)](https://github.com/Hroberts1/rmap/actions/workflows/ci.yml)

A network scanner written from scratch in Rust, driven by an interactive terminal UI.

rmap takes inspiration from Nmap's feature set but shares none of its code or data files. Scanning, packet handling, target parsing and probe databases are all written in this repository. The only outside dependencies are general-purpose infrastructure: [tokio](https://tokio.rs) for the async runtime, [ratatui](https://ratatui.rs) for the terminal, [libc](https://crates.io/crates/libc) for the Linux raw-socket syscalls, [serde](https://serde.rs)/serde_json for the JSON report format, and [rusqlite](https://crates.io/crates/rusqlite) (with SQLite bundled) to read the CVE database file.

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

### 5. Run the tests (optional)

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
| Screen left in a bad state after a crash | Run `reset`. The crash report path is printed after the terminal is restored; see [Logs and crash reports](#logs-and-crash-reports). |

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

(`setcap` has to be repeated after every rebuild.) Without raw sockets, or on Windows and macOS, rmap still runs the scan and prints a warning in the log panel saying what it fell back to: a SYN scan becomes a TCP connect scan, a UDP scan uses ordinary connected UDP sockets, and discovery uses the TCP connect ping. The raw backend covers IPv4 and IPv6 (Linux 4.5 or later for IPv6). IPv6 packets are built by rmap but routed by the kernel, which also does neighbour discovery, so there is no IPv6 equivalent of the ARP ping: discovery uses ICMPv6 echo raced against the TCP connect ping. IPv6 targets fall back to unprivileged probes (with a warning) when the host has no IPv6, for link-local addresses (zone IDs like `fe80::1%eth0` aren't accepted yet) and for IPv4-mapped addresses.

### Results screen keys

| Keys | Does |
|---|---|
| `↑↓` `j` `k` | Move in the focused pane |
| `PgUp` `PgDn` | Move by 10 |
| `Home` `End` `g` `G` | First / last |
| `Tab` `←` `→` `h` `l` | Switch between the hosts pane and the ports pane |
| `1` `2` `3` | Hosts / Services / Vulns tab (below) |
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
| `n` / `Esc` | New scan |
| `q` / `Ctrl-C` | Quit (asks first on a running scan) / quit immediately |
| `?` | This list, as an overlay |

`n`, `Esc` and `q` ask **y/n** first if a scan is still running, so a stray keypress can't lose it; `Esc` on the setup form does too, once you've typed anything. `open?` in the port table means `open|filtered` (no reply; may be open), and a `!` by a host means it has at least one potential CVE.

### Tabs: Hosts, Services, Vulns

`1` (Hosts, the default) shows one host at a time with its ports, as described above. `2` (Services) groups every open port across the whole scan by port and protocol - "which hosts have 445 open?" - with the service name and a count. `3` (Vulns) lists every potential finding in the scan, worst severity first, host and port alongside each one. Both rebuild from the live results every frame, so they fill in as the scan runs, and arrow keys move through whichever group or finding is selected.

### Filtering and sorting the host list

`/` filters the host list to addresses, hostnames, an open port's service name or product, or an exact open port number - case-insensitive, substring match except the port number. `o` cycles the sort order: by address (default), by open-port count (most first), or by worst potential CVE (severity, then CVSS score). Both apply only to the Hosts tab's list; Services and Vulns have their own grouping.

### Rescanning one host

`r` on a host re-scans just that one address, every port (1-65535), with service detection and vulnerability matching on regardless of the main scan's settings - it keeps the original scan's type, timing and rate cap. Only one rescan runs at a time, and only once the main scan has finished. Its results replace that host's row when it completes; stopping it (`s`) or a failure leaves the earlier results exactly as they were, so a partial rescan never hides ports the first pass already found. The scan is auto-saved again afterward as a new file - the original stays on disk as a comparison baseline.

### Copying to the clipboard

`y` copies the selected host's address (or `ip:port` when the ports pane is focused); `Y` copies that host's CVE IDs. This uses the terminal's OSC 52 escape sequence, not a clipboard library - supported by most modern terminals (Windows Terminal, iTerm2, kitty, WezTerm, Alacritty, foot, xterm with `allowWindowOps`), though some disable it or ask first, in which case nothing visibly happens. Inside tmux it needs `set -g allow-passthrough on` (or `set-clipboard on`); GNU screen isn't supported. Copies over 8 KiB are refused rather than silently truncated.

### Colors

Set `NO_COLOR` (non-empty, per [no-color.org](https://no-color.org)) to draw every frame without foreground or background colors - bold, dim and reversed still apply, so the selected row and key labels still stand out. Useful over a monochrome connection or for screen readers.

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

- **JSON:** rmap's own report format, the same one used for saved scans. It carries a `format_version` so later versions of rmap can keep reading old files. It records the rmap version, start and end times, how the scan ended (`completed`, `stopped`, `failed`), the configuration, and every host with its open and open|filtered ports, detected services and CPEs, and closed/filtered counts.
- **Nmap XML:** the commonly used subset of Nmap's documented XML output (`nmaprun`, `scaninfo`, `host`, `status`, `address`, `hostnames`, `ports`, `extraports`, `port`, `state`, `service` with product/version/extrainfo/CPE, `times`, `runstats`), so tools that import Nmap results can read rmap scans. It's written by rmap's own small XML writer; times are in UTC, and CPEs are converted to the `cpe:/` form Nmap uses.
- **Markdown:** a readable summary for pasting into a ticket: scope, times, hosts up, open ports and potential CVE counts by severity, then a ports table and findings per host, then all findings by severity.
- **CSV:** one row per open or open|filtered port (`ip, hostname, port, protocol, state, service, product, version, cves, worst_severity`). Every field is quoted per RFC 4180, and fields a spreadsheet would treat as a formula (starting with `=`, `+`, `-`, `@`, tab or CR) get a leading `'`, since banners and hostnames come from the scanned devices.
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
├── rmap-vuln     vulnerability matching: CPE -> CVE lookup in a local SQLite database file (rmap-core and rusqlite only)
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

Reverse DNS uses the **DNS server** field if set, otherwise the system resolver from `/etc/resolv.conf`. Windows keeps its resolver where rmap can't read it without extra dependencies, so there reverse DNS needs the field set (for example to the client's domain controller); NetBIOS and mDNS work either way. Each lookup is one small UDP packet that waits its turn under the rate cap, loopback targets skip reverse DNS, and names from the network are cleaned of control characters before they're shown or saved. Names go into every export, and the scan diff reports a host whose name changed.

## Service detection

Tick **Services** on the setup form and rmap identifies the software behind each open TCP port, and each open or open|filtered UDP port. The port table shows the service and version, and the details pane adds a line per port with extra information, the OS the service revealed, and a [CPE 2.3](https://nvd.nist.gov/products/cpe) name:

```
22/tcp  open  ssh   OpenSSH 8.9p1
                    └ protocol 2.0; Ubuntu-3ubuntu0.6 · os: Ubuntu Linux · cpe:2.3:a:openbsd:openssh:8.9:p1
```

How it works (`crates/rmap-detect`):

1. **Choose probes.** Probes that list the port go first, then the generic ones: wait for a banner, `GET / HTTP/1.0`, a TLS ClientHello, and blank lines. So HTTP on port 8443 or SSH on port 2200 is still found.
2. **Send and read.** Each probe uses a fresh connection and reads until the server closes, goes quiet for half a second, has sent 16 KiB, or the probe's wait runs out. Each port gets a time budget of ten connect timeouts (5-30 s). Detection runs at most `concurrency / 8` ports at once (1-64), separately from port probes, so it can't slow the scan down.
3. **Match.** The reply is checked against the probe's rules, then against the rules of its `fallback` probes (an SSH server answering an HTTP probe still sends its banner). TLS replies are decoded in code: protocol version, and the certificate's common name, alternative names, issuer and expiry, read with a small DER parser. rmap offers TLS 1.2 at most, so the certificate arrives unencrypted.
4. **Report.** Matches get a CPE from rmap's product table, with versions split the way NVD records them (`8.9p1` becomes version `8.9`, update `p1`). If nothing matches, rmap reports the port-table name with low confidence, plus the start of any reply it didn't recognise.

`Service::method` says how the result was reached (`banner`, `probe`, or `port_table`), and `confidence` runs from 0 (guess) to 10.

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

### The database file

The CVE data is a SQLite file, `vulns.db`, in rmap's data directory (next to the saved scans):

| Platform | Path |
|---|---|
| Linux | `$XDG_DATA_HOME/rmap/vulns.db`, or `~/.local/share/rmap/vulns.db` |
| macOS | `~/Library/Application Support/rmap/vulns.db` |
| Windows | `%LOCALAPPDATA%\rmap\vulns.db` |

rmap doesn't ship CVE data in the binary. If the file is missing or unreadable, the scan runs normally with one warning (`no vulnerability data at <path>; CVE matching skipped`) and no CVE lines. Downloading and updating the file from inside rmap is coming in a later change.

The schema (`rmap_vuln::SCHEMA_SQL`, version 1) is rmap's own - not Nmap's `nmap-vulners` or any other scanner's database:

- `meta`: `schema_version`, `built_at` (RFC 3339 UTC), `source`, `cve_count`. rmap refuses a file whose `schema_version` it doesn't know.
- `cve`: one row per CVE - `id`, `summary`, `severity` (`low`/`medium`/`high`/`critical`), optional CVSS `score`, `published` date, and `kev_added`, the date it joined CISA's Known Exploited Vulnerabilities list.
- `cpe_match`: which versions of which product each CVE affects - lowercase `vendor` and `product` as `crates/rmap-detect/src/cpe.rs` produces them, then either `version_exact` or a range (`start`/`end`, each inclusive or exclusive, missing = open-ended). A CVE can have several rows, for disjoint ranges across branches; a row with no version at all matches every version.

`rmap_vuln::Writer` builds a file in this format. The file will come from the internet, so rmap treats it as untrusted: it opens it read-only, uses only bound query parameters, refuses views in place of its tables, skips rows that don't fit the schema, and replaces control characters in CVE text before it can reach the terminal.

How matching works (`crates/rmap-vuln`):

1. Each detected service's CPE 2.3 strings give a vendor, a product, and the version + update combined (e.g. `9.7p1`). The database's rows for that vendor and product are fetched by index.
2. Each row's range is checked in Rust, comparing versions the way dpkg/rpm do: split into alternating digit and text runs, compare each run in order, and treat a side that runs out of runs first as smaller - so `9.7` sorts before `9.7p1`, and that before `9.7p2`. Versions are stored in that same combined form.
3. Matches are deduplicated by CVE id and reported newest first.

### Vulnerability data (maintainers)

`vulns.db` is built by `tools/vulndb-build` and published by the **Vulnerability data** GitHub Action (`.github/workflows/vulndb.yml`), on the 1st of every month and on demand (Actions → Vulnerability data → Run workflow, on `main`; other branches skip the job). It:

1. Downloads CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list, then every CVE from the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities), 2000 per page, within NVD's rate limits (one request per 6 s without an API key, one per second with one), retrying rate-limit and server errors with backoff.
2. Keeps only CVEs that affect a product rmap can detect (the vendor/product pairs in `crates/rmap-detect/src/cpe.rs`, via `rmap_detect::cpe::nvd_products`), which keeps the file to a few MB. Rejected CVEs are dropped.
3. Writes `vulns.db` and `vulns.meta.json`, and refuses to finish if fewer than 500 CVEs (or 500 KEV entries) came back, so a broken response is never published.
4. Uploads `vulns.db`, then the manifest `vulns.json` (`schema_version`, `built_at`, `cve_count`, `source`, `size`, `sha256`, `db`), to the release tagged `vulndb`, replacing the previous month's files.

How NVD data is converted:

- Each vulnerable `cpeMatch` becomes a `cpe_match` row: `versionStart*`/`versionEnd*` become range bounds; a CPE with a concrete version and no range becomes an exact version, with `update` appended the way rmap-detect splits it (`9.7` + `p1` → `9.7p1`). Versions keep CPE 2.3 escaping exactly as rmap-detect writes them, so they compare equal.
- A CPE with version `*` and no range means NVD lists every version as affected, and is stored as a row with no bounds, which matches any version. Version `-` (not applicable) is skipped.
- Severity and score come from CVSS v3.1, else v3.0, else v4.0, else v2 (NVD's primary metric first; v2's low/medium/high kept as NVD rated them). A CVE with no CVSS data yet is kept with no score and severity `medium`, or `high` if it is on the KEV list.
- Summary: the English description, whitespace collapsed, at most 1000 characters. `published` is the date part of NVD's timestamp; `kev_added` is the KEV `dateAdded`.

Limitations:

- **AND configurations.** NVD often says "product X is vulnerable when running on platform Y". rmap keeps X's match and ignores Y, since a scan can't verify the platform, so such CVEs can be over-reported.
- **NVD's backlog.** Many recent CVEs have no CPE data yet (NVD enrichment lags publication), so they can't be matched to a product and aren't in the file until NVD analyses them; the next monthly build picks them up.

Run the builder locally (it writes into `OUT_DIR`, which must not already contain `vulns.db` or `vulns.meta.json`):

```sh
OUT_DIR=/tmp/vulndb cargo run --release -p vulndb-build
# A quick trial with one NVD page, which skips the minimum-size check:
NVD_MAX_PAGES=1 OUT_DIR=/tmp/vulndb-trial cargo run -p vulndb-build
```

A full keyless run takes about 25 minutes. An NVD API key ([request one free](https://nvd.nist.gov/developers/request-an-api-key)) makes it faster: set `NVD_API_KEY` locally, or add it as the repository secret `NVD_API_KEY` for the Action. Without the secret the Action still works, just slower.

Data sources and terms: NVD data is a work of the US government and in the public domain; CISA's KEV catalog is public. *This product uses the NVD API but is not endorsed or certified by the NVD.*

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

rmap is developed for **Linux first**. Milestone 1 also runs on macOS and Windows because it uses only ordinary sockets. On Windows, a connection to a closed port can take about 2 seconds to be refused, so with fast timing templates closed ports may show as filtered. Raw-socket features from M2 onward are Linux-only; elsewhere rmap falls back to unprivileged probes with a warning.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

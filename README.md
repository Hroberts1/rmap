# rmap

A network scanner written from scratch in Rust, driven by an interactive terminal UI.

rmap takes inspiration from Nmap's feature set but shares none of its code or data files. Scanning, packet handling, target parsing and probe databases are all written in this repository. The only outside dependencies are general-purpose infrastructure: [tokio](https://tokio.rs) for the async runtime and [ratatui](https://ratatui.rs) for the terminal.

> **Only scan networks you own or have written permission to test.** rmap asks for confirmation before it touches public addresses.

## Status

Milestones 1 and 3 are done: unprivileged TCP connect scanning with a live TUI, and service and version detection. See the [roadmap](#roadmap).

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
| Timing | T0 paranoid … T3 normal … T5 insane |
| Discovery | Probe hosts first and skip the ones that don't answer |

Results keys: `↑↓`/`jk` select a host · `d` show/hide down hosts · `s` stop · `n` new scan · `q` quit.

## How it works

```
crates/
├── rmap-core     targets, port lists, timing templates, result types
├── rmap-engine   async scan engine (tokio)
├── rmap-detect   service detection: probes, matcher, TLS, CPEs
├── rmap-log      local log files and crash reports (no dependencies)
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

## Service detection

Tick **Services** on the setup form and rmap identifies the software behind each open TCP port. The port table shows the service and version, and the details pane adds a line per port with extra information, the OS the service revealed, and a [CPE 2.3](https://nvd.nist.gov/products/cpe) name:

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

Covered today: OpenSSH, Dropbear, nginx, Apache httpd, Microsoft IIS and HTTPAPI, lighttpd, Caddy, Tomcat Coyote, Elasticsearch, Postfix, Exim, Sendmail, Microsoft Exchange, vsftpd, ProFTPD, Pure-FTPd, FileZilla Server, Microsoft FTP, Dovecot, Courier, MySQL, MariaDB, PostgreSQL, Redis, Valkey, MongoDB, Memcached, RabbitMQ, Asterisk and Apple Remote Desktop, plus the protocols SSH, HTTP (any `Server:` header), FTP, SMTP, POP3, IMAP, TLS, SMB, RDP, VNC, telnet, SIP, RTSP, AMQP and MQTT. UDP detection isn't done yet; the database and API already take a protocol.

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

The suite runs real scans against loopback listeners and the reserved, never-routed `192.0.2.0/24` block, so it needs no network access or privileges. It includes randomized parser tests that feed 100,000 generated strings through target and port parsing to catch inputs that could panic. If one fails, it prints the seed and the input that broke it. Service detection is tested the same way: fake SSH, HTTP, SMTP, FTP, Redis and TLS servers on loopback, a realistic reply for every match rule, and randomized garbage fed through the pattern matcher, the probe database parser and the TLS and certificate parsers.

## Roadmap

- [x] **M1: engine + TUI shell.** Target parsing, TCP connect scan, unprivileged discovery, live results.
- [ ] **M2: raw scans.** Hand-built IPv4/TCP/UDP/ICMP/ARP packets, SYN and UDP scans, ICMP and ARP discovery, adaptive timing. Needs root or `CAP_NET_RAW`.
- [x] **M3: service detection.** rmap's own probe and match database, version strings, TLS certificate names, CPE identifiers.
- [ ] **M4: vulnerability matching.** Offline CPE → CVE lookup against locally cached public feeds, flagged as *potentially* vulnerable to allow for vendor backports.
- [ ] **M5: export and diffing.** JSON and XML export from the TUI, and comparing two saved scans.

## Platform notes

rmap is developed for **Linux first**. Milestone 1 also runs on macOS and Windows because it uses only ordinary sockets. On Windows, a connection to a closed port can take about 2 seconds to be refused, so with fast timing templates closed ports may show as filtered. Raw-socket features from M2 onward target Linux.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

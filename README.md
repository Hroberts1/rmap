# rmap

A network scanner written from scratch in Rust, driven by an interactive terminal UI.

rmap takes inspiration from Nmap's feature set but shares none of its code or data files. Scanning, packet handling, target parsing and probe databases are all written in this repository. The only outside dependencies are general-purpose infrastructure: [tokio](https://tokio.rs) for the async runtime and [ratatui](https://ratatui.rs) for the terminal.

> **Only scan networks you own or have written permission to test.** rmap asks for confirmation before it touches public addresses.

## Status

Milestone 1 is done: unprivileged TCP connect scanning with a live TUI. See the [roadmap](#roadmap).

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
- **debug:** host up/down results, open ports, name resolution, and the first 20 unexpected connect errors in full
- **trace:** every probe attempt and keypress

If rmap panics, it writes `crash-<time>-<pid>.txt` next to the log. The report holds the panic message, location, a backtrace, and the last 500 log lines at debug level, even when the log file itself is at info. A panic inside a scan worker doesn't crash the app: the scan shows **failed** and the report is written in the background.

The newest 20 logs and 20 crash reports are kept; older ones are deleted. Logs contain the addresses you scanned, so review them before attaching one to a public issue.

## Testing

```bash
cargo test --workspace
```

The suite runs real scans against loopback listeners and the reserved, never-routed `192.0.2.0/24` block, so it needs no network access or privileges. It includes randomized parser tests that feed 100,000 generated strings through target and port parsing to catch inputs that could panic. If one fails, it prints the seed and the input that broke it.

## Roadmap

- [x] **M1: engine + TUI shell.** Target parsing, TCP connect scan, unprivileged discovery, live results.
- [ ] **M2: raw scans.** Hand-built IPv4/TCP/UDP/ICMP/ARP packets, SYN and UDP scans, ICMP and ARP discovery, adaptive timing. Needs root or `CAP_NET_RAW`.
- [ ] **M3: service detection.** rmap's own probe and match database, version strings, CPE identifiers.
- [ ] **M4: vulnerability matching.** Offline CPE → CVE lookup against locally cached public feeds, flagged as *potentially* vulnerable to allow for vendor backports.
- [ ] **M5: export and diffing.** JSON and XML export from the TUI, and comparing two saved scans.

## Platform notes

rmap is developed for **Linux first**. Milestone 1 also runs on macOS and Windows because it uses only ordinary sockets. On Windows, a connection to a closed port can take about 2 seconds to be refused, so with fast timing templates closed ports may show as filtered. Raw-socket features from M2 onward target Linux.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

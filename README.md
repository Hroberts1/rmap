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
└── rmap-tui      ratatui front end
src/main.rs       starts the runtime and the UI
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

# rmap — working notes for agents

A from-scratch network scanner in Rust with an interactive TUI. Read README.md for the architecture and roadmap.

## Non-negotiables

- **From scratch.** Scanning logic, packet building/parsing, target parsing, probe/match databases, fingerprints and CVE matching are written in this repo. No pnet, etherparse, ipnetwork, nmap bindings, or other domain crates. Don't copy Nmap source or data files (`nmap-service-probes`, `nmap-os-db`, `nmap-services`): they are NPSL-licensed and this project is MIT/Apache-2.0.
- **Approved dependencies only:** `tokio`, `ratatui` (use its re-exported `ratatui::crossterm`), `libc` (raw-socket syscalls only), `serde` + `serde_json`. Anything else needs the maintainer's approval first; say why it isn't "the scanner part".
- **TUI only.** No flag-driven CLI mode.
- **Linux first** for raw-socket features. Gate platform code with `cfg`, and keep the workspace building and testing on Windows and macOS (raw features may return a clear "not supported on this platform" error there).

## Layout

| Crate | Owns |
|---|---|
| `rmap-core` | Shared types: `Target`, `PortList`, `Timing`, `ScanType`, `Protocol`, `PortState`, `PortResult`, `Service`, `Vulnerability`, `VulnSeverity`, `ScanEvent`. Optional `serde` feature. |
| `rmap-engine` | Async scan engine. `Scan::start(handle, ScanConfig)` streams `ScanEvent`s. |
| `rmap-detect` | Service detection: probe database (`probes.txt`), pattern matcher, TLS/DER parsing, CPE table. `detect(ip, port, protocol, timing)`. |
| `rmap-vuln` | Vulnerability matching: CPE version-range matcher, CVE database (`cves.txt`). `Database::builtin().find(cpe)`. Depends only on `rmap-core`. |
| `rmap-log` | Local logs and crash reports. Use `rmap_log::{error,warn,info,debug,trace}!`. |
| `rmap-packet` | Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMPv4/ICMPv6 building and parsing, RFC 1071 checksums over both pseudo-headers. No dependencies; parsers never panic. |
| `rmap-report` | `ScanReport` model, `ReportBuilder` (events → report), JSON and Nmap XML export, saved scans (`ScanStore`), and `diff`. |
| `rmap-tui` | Setup form (`app.rs` state, `ui.rs` drawing) and live results. |

New milestone work should live in **its own crate** where possible (for example `rmap-packet`, `rmap-detect`, `rmap-vuln`, `rmap-report`) and plug into the engine/TUI through small, well-named hooks. Parallel milestone branches then touch shared files as little as possible.

## Shared contract types (keep stable)

These in `rmap-core` exist so parallel milestones agree on shapes. Extend them; don't rename or remove fields without a good reason, and note any change in your PR/commit message:

- `ScanType { Connect, Syn, Udp }`, `Protocol { Tcp, Udp }`, `PortState::OpenFiltered`
- `PortResult { port, protocol, state, rtt, service: Option<Service> }`, built with `PortResult::new`
- `Service { name, product, version, info, os_hint, cpes, method, confidence }`
- `ScanEvent::Service { ip, protocol, port, service }`: detection results sent after the `Port` event
- `Vulnerability { id, summary, severity, score, published }`
- `ScanEvent::Vulnerabilities { ip, protocol, port, findings }`: sent after the `Service` event for that port, never sent when `findings` would be empty
- `MacAddr` and `ScanEvent::Mac { ip, mac }`: the host's hardware address from its ARP reply, sent right after its `Host` event; only raw-socket discovery on a local Ethernet subnet learns one. Vendor lookup lives in `rmap-oui` (hand-written table, no IEEE registry)
- `ScanConfig { .., scan_type, service_detection, vuln_matching }` in `rmap-engine`. SYN/UDP are implemented (raw backend in `rmap-engine/src/raw`, chosen in `backend.rs`, with unprivileged fallbacks). Service detection is implemented (`rmap-detect`, wired in via `rmap-engine/src/service.rs`). Vulnerability matching is implemented (`rmap-vuln`, wired in via `rmap-engine/src/vuln.rs`; has no effect without `service_detection`, since it needs that layer's CPEs). No placeholder warnings remain for any of the three in `rmap_engine::run`.

## Conventions

- Run before committing: `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features` (no warnings), and `cargo test --workspace`.
- Tests must not need network access or root. Use loopback listeners and the never-routed `192.0.2.0/24` block (see `crates/rmap-engine/src/tests.rs`). Raw-socket tests that need privileges go behind `#[ignore]`, with a comment explaining how to run them (for example inside `unshare -rn` on Linux).
- Log what would help reproduce a bug: configuration at `info`, per-host detail at `debug`, per-packet at `trace`. Never log on hot paths above `trace`.
- User input must never panic. Parsers get edge-case tests, and randomized tests like `crates/rmap-core/tests/edge_cases.rs`.
- Commit messages: imperative summary line, a body explaining what and why, and a `Co-Authored-By` trailer if you're an AI agent.

## Branches

Each milestone is developed on its own branch (`milestone-N-short-name`) and merged into `main` when done. If `main` moves while you work, merge it into your branch (`git merge main`) and resolve conflicts before continuing.

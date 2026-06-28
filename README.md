# netpeek

[![CI](https://github.com/lucasdaddiego/netpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/lucasdaddiego/netpeek/actions/workflows/ci.yml)
![platform](https://img.shields.io/badge/platform-macOS%2013%2B-black?logo=apple)
![language](https://img.shields.io/badge/Rust-2021-orange?logo=rust)
![dependencies](https://img.shields.io/badge/runtime%20deps-none-brightgreen)
![license](https://img.shields.io/badge/license-MIT-blue)

A live terminal UI showing **which processes on *this* machine are talking to the
network, and how fast** — the inward-facing counterpart to a LAN scanner. One
screen: every process with its **down/up rate, cumulative bytes and open-connection
count**, sortable and filterable, with up/down **sparklines** and a detail pane
that expands a process to its individual flows (remote host, port → service,
protocol, TCP state, per-flow throughput).

It reads the data the accurate way: by binding the private
**`com.apple.network.statistics`** kernel-control socket directly — the *exact*
interface `nettop(1)` uses — for real, pid-attributed, per-flow byte counters.
**No `sudo`, no packet capture, no scraping `nettop` output.** Unprivileged for
your own user's flows.

A single self-contained Rust binary. No Homebrew formulae at runtime, no Python,
no helper processes.

```
 netpeek   142 procs  613 flows   sort rate↓   every 1s   [your flows]   upd 19:44
┌ processes ─────────────────────────────────────────────────────────────────────┐
│   PID  PROCESS              DOWN     ↓        UP     ↑       TOTAL  CONNS         │
│ ▾ 5821  Google Chrome H  4.6 MB/s ▂▃▅█  812 KB/s ▁▂▃▅   1.9 GB     38            │
│   698  WiFiAgent          120 KB/s ▁▁▂▂   88 KB/s ▁▁▂▂   44 MB      6            │
│   311  trustd             2.1 KB/s ▁▁▁▂    9 KB/s ▁▂▁▁   3.1 MB     3            │
│   596  mDNSResponder         0 B/s ▁▁▁▁    0 B/s ▁▁▁▁    299 MB     2            │
│   1   launchd               0 B/s ▁▁▁▁    0 B/s ▁▁▁▁     0 B        5            │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Google Chrome Helper (pid 5821) — 38 flows ──────────────────────────────────────┐
│ PROTO  STATE         REMOTE                          DOWN        UP               │
│ TCP    ESTABLISHED   lhr25s34.1e100.net:443 (https)  4.1 MB/s   720 KB/s          │
│ TCP    ESTABLISHED   server-18-66.r.cloudfront:443   480 KB/s    64 KB/s          │
│ UDP    —             dns.google:443 (https)           18 KB/s    22 KB/s          │
└──────────────────────────────────────────────────────────────────────────────┘
 q quit  ↑↓ move  enter expand  / filter  p pause  r/t/n/c/i sort  ? help
```

<!-- asciinema demo: replace ID after recording with `asciinema rec` -->
[![asciinema demo](https://asciinema.org/a/REPLACE_ME.svg)](https://asciinema.org/a/REPLACE_ME)

## Contents

- [Features](#features)
- [Why a custom tool?](#why-a-custom-tool)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Keyboard shortcuts](#keyboard-shortcuts)
- [Reading the table](#reading-the-table)
- [JSON / scripting output](#json--scripting-output)
- [How it works](#how-it-works)
- [Accuracy & honest limitations](#accuracy--honest-limitations)
- [Project layout](#project-layout)
- [Development](#development)
- [License](#license)

## Features

- **Per-process table** — one row per pid: down rate, up rate, cumulative total,
  and open-connection count, all live.
- **Real pid attribution** — straight from the kernel's flow accounting, so a
  byte counted against a process *was* that process's byte. No heuristics.
- **Expand to flows** — press <kbd>enter</kbd> on a process to open a detail pane
  listing each connection: remote host, port → service name, TCP/UDP, TCP state
  and per-flow throughput.
- **Async reverse DNS** — remote IPs resolve to hostnames on a background thread
  with a cache, so the lookup never blocks or stutters the UI (`--no-resolve`
  to skip it).
- **Up/down sparklines** per process — a glance shows a burst from a steady
  trickle.
- **Sort any way** — by rate, total bytes, name, connection count or pid; press
  the same key again to reverse.
- **Filter** by process name or pid as you type (`/`).
- **Pause / freeze** (`p`) to inspect a moment without the table moving under you.
- **Scriptable** — `--once` (text snapshot), `--json` (pipe into `jq`), `--diag`
  (connectivity + permission check).
- **Single static binary**, no runtime dependencies, no root.

## Why a custom tool?

`nettop` shows this data but isn't scriptable, isn't sortable/filterable the way
you want, and clears the screen on every refresh. Activity Monitor aggregates
per-process bytes but has no live rates, no flows, no terminal. Packet-capture
tools (`tcpdump`, `wireshark`) need root and don't attribute to a pid. netpeek
reads the **same kernel source `nettop` does** and puts it behind a proper,
sortable, expandable TUI — unprivileged, in one binary.

## Requirements

- **macOS** (built & tested on **macOS 26 / Apple Silicon**; targets macOS 13+ —
  see [limitations](#accuracy--honest-limitations) for why 13 is the floor).
- A **Rust toolchain** to build (`brew install rust`, or rustup). That's it —
  no crates fetched at runtime, no system libraries beyond what macOS ships.

## Install

```sh
make            # build an optimised release binary + symlink `netpeek` into ~/.bin
make clean      # remove the binary and the launcher
```

Make sure `~/.bin` is on your `PATH`:

```sh
echo 'export PATH="$HOME/.bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
```

Then run `netpeek` from any terminal. (Or just `cargo run --release`.)

## Usage

```sh
netpeek                   # interactive TUI (default)
netpeek --once            # one snapshot as a text table, then exit
netpeek --json            # one snapshot as a JSON array on stdout (pipe into jq)
netpeek --diag            # connectivity + permission diagnostics
netpeek --interval 0.5    # faster refresh / sampling (default 1.0s, min 0.2)
netpeek --no-resolve      # don't reverse-DNS remote hosts
netpeek --help            # usage summary
```

| Flag | Description |
|------|-------------|
| `--once` | Single text-table snapshot (two samples for a real rate), then exit. |
| `--json` | Single snapshot as a JSON array, sorted by rate, keys alphabetised. |
| `--diag` | Print socket connectivity, privilege, flow/process counts and top talkers. |
| `--interval SECS` | Refresh and rate-sampling interval (default `1.0`, minimum `0.2`). |
| `--no-resolve` | Skip reverse DNS; the detail pane shows raw IPs. |
| `--version`, `-V` | Print version. |
| `--help`, `-h` | Show usage. |

Everything else is a **live** control — see the keys below.

## Keyboard shortcuts

| Key | Action | | Key | Action |
|-----|--------|-|-----|--------|
| <kbd>q</kbd> / <kbd>Ctrl-C</kbd> | quit | | <kbd>r</kbd> | sort by **r**ate (down+up) |
| <kbd>↑</kbd>/<kbd>↓</kbd> or <kbd>k</kbd>/<kbd>j</kbd> | move selection | | <kbd>t</kbd> | sort by **t**otal bytes |
| <kbd>PgUp</kbd>/<kbd>PgDn</kbd> | page | | <kbd>n</kbd> | sort by **n**ame |
| <kbd>g</kbd>/<kbd>G</kbd> | top / bottom | | <kbd>c</kbd> | sort by **c**onnections |
| <kbd>enter</kbd>/<kbd>space</kbd> | expand a process to its flows | | <kbd>i</kbd> | sort by p**i**d |
| <kbd>/</kbd> | filter by name or pid | | | (repeat a sort key to reverse) |
| <kbd>p</kbd> | pause / freeze | | <kbd>?</kbd> | help |

The mouse wheel scrolls the list too.

## Reading the table

| Column | Meaning |
|--------|---------|
| **PID** | Process id. `▸`/`▾` marks whether its flows are expanded. |
| **PROCESS** | Process name from the kernel; falls back to the executable name for unnamed flows. |
| **DOWN** / **UP** | Receive / transmit **rate** (bytes/sec), derived from the change in the kernel's cumulative counters over the interval. Dimmed when idle. |
| **↓** / **↑** | Sparkline of recent down / up rates (last ~60 samples), scaled to that process's own peak. |
| **TOTAL** | Cumulative bytes (down + up) the kernel has counted for the process's current flows. |
| **CONNS** | Number of open flows (sockets) the process currently has. |

In the expanded **detail pane**, each flow shows protocol, TCP state, the remote
`host:port (service)` and its own down/up rate. Remote hosts are reverse-DNS'd
in the background; until a name resolves (or if it has no PTR record) the raw IP
is shown.

## JSON / scripting output

`netpeek --json` prints one object per process, sorted by current rate, keys
alphabetised:

```jsonc
[
  {"conns": 38, "name": "Google Chrome Helper", "pid": 5821,
   "rx_bytes": 1932735012, "rx_rate": 4823117, "tx_bytes": 211238, "tx_rate": 831488},
  {"conns": 6,  "name": "WiFiAgent", "pid": 698,
   "rx_bytes": 46137344, "rx_rate": 122880, "tx_bytes": 9216, "tx_rate": 90112}
]
```

`rx_rate`/`tx_rate` are bytes/sec; `rx_bytes`/`tx_bytes` are cumulative. Example —
the five processes pulling the most down right now:

```sh
netpeek --json | jq -r 'sort_by(-.rx_rate) | .[:5][] | "\(.rx_rate)\t\(.name)"'
```

## How it works

netpeek speaks the **`com.apple.network.statistics`** kernel-control protocol —
the private, undocumented interface behind `nettop`. The exchange:

1. **Open** — `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`, then
   `ioctl(CTLIOCGINFO)` with the control name to resolve its id, then `connect()`
   via a `sockaddr_ctl`. A roomy `SO_RCVBUF` is requested so bursty count polls
   don't overrun the socket.
2. **Subscribe** — send `nstat_msg_add_all_srcs` for the TCP and UDP providers
   (both the in-kernel BSD-socket flows and the userland Network.framework ones).
   The kernel then streams a `nstat_msg_src_added` for every current and future
   flow.
3. **Describe** — for each added source we send `nstat_msg_get_src_description`
   and parse the returned `nstat_msg_src_description`: pid, process name, local
   and remote `sockaddr`, and (for TCP) connection state. These requests are
   **paced** — firing one for all ~100+ sources at once overruns the kernel's
   reply queue (`ENOBUFS`) and starves the counters, so netpeek drips them out a
   batch at a time. Descriptions are cached; a flow is described once.
4. **Poll counts** — once per interval, one `nstat_msg_query_src` for
   `NSTAT_SRC_REF_ALL` asks the kernel for fresh `nstat_counts` (cumulative rx/tx
   bytes) for *every* source in a single request; **rates are the delta between
   successive polls** divided by the elapsed time.
5. **Parse** — the socket delivers a stream of `nstat_msg_hdr`-prefixed messages,
   several packed into one datagram ("aggregate"); netpeek walks each datagram by
   header length and decodes the messages by type. `nstat_msg_src_removed`
   retires a flow.

The `#[repr(C)]` request structs are cast to/from bytes with
[`bytemuck`](https://docs.rs/bytemuck) (checked, no `unsafe` transmutes); the
syscalls go through [`libc`](https://docs.rs/libc). Reverse DNS is `getnameinfo`
on a background thread. Process-name fallback for unnamed flows uses
`proc_pidpath`.

## Accuracy & honest limitations

- **It uses a private, undocumented interface.** `com.apple.network.statistics`
  is not in any SDK header and Apple can change it without notice. netpeek
  transcribes the layouts from Apple's open-source XNU (`bsd/net/ntstat.h`,
  `__NSTAT_REVISION__ 9`) and cross-checks them between the macOS 14 and current
  headers. This is the *correct* source nonetheless — the same one `nettop` uses
  — and the brief here is accuracy over convenience, so netpeek does **not** fall
  back to scraping `nettop` text.
- **The struct layouts have shifted across macOS releases**, which is the real
  fragility. The descriptor layout netpeek models matches **macOS 13 through 26**
  (the `rx/tx_transfer_size` fields it depends on were added in macOS 13). On a
  layout it doesn't recognise it **validates before it trusts**: a flow is only
  shown if it decodes to a plausible pid *and* a known address family — otherwise
  it's skipped, never rendered wrong. So on a future macOS that moves fields,
  netpeek degrades to showing fewer flows rather than garbage. `netpeek --diag`
  tells you what it's actually seeing.
- **Unprivileged = your own user's flows.** Run by your user, the kernel shows
  the flows your user owns — which is the point of an inward-facing tool. Run with
  `sudo` to see *every* process on the machine. `--diag` reports which mode you're
  in.
- **Counters are per current flow.** "Total" is the cumulative bytes of a
  process's currently-open flows; when a flow closes the kernel retires it, so
  totals reflect live connections, not all-time history.
- **No on-wire inspection.** This is byte accounting, not packet capture — there
  are no payloads, no DPI, no protocol decoding beyond port → service naming.
- **Linux: planned, out of scope for v1.** The equivalent there is a different
  implementation entirely (`/proc/net/*` plus an eBPF program for per-pid
  attribution), not a port of this code. Stated honestly: there is **no** Linux
  support today.

## Project layout

```
src/
  main.rs          arg parsing · TUI event loop · --once/--json/--diag · entrypoint
  lib.rs           library root (so the binary, tests and examples share one impl)
  app.rs           UI state machine — sort/filter/selection/expand/pause (pure, tested)
  model.rs         Engine: flows → per-process rows, rate deltas, history (pure, tested)
  format.rs        byte/rate formatting, TCP-state names, sparklines (pure, tested)
  services.rs      port → service name (curated + /etc/services) (pure, tested)
  dns.rs           async cached reverse DNS (getnameinfo on a worker thread)
  ui.rs            ratatui rendering (table · detail pane · help overlay)
  ntstat/
    mod.rs         Monitor: owns the socket + Engine, drains the message stream
    wire.rs        the kernel protocol: #[repr(C)] structs, constants, parsers (pure, tested)
    sys.rs         the raw PF_SYSTEM control socket: socket/ioctl/connect/recv
```

The split is deliberate, the same way `wifiscan` separates `Core` from the
framework-bound code: everything branchy — the wire parsing, rate maths,
aggregation, sorting, filtering, formatting and UI-state transitions — is pure
and unit-tested with synthetic data (no socket, no terminal, no root), while
`sys.rs` / `dns.rs` / `ui.rs` / the socket loop are thin plumbing.

## Development

```sh
make test        # cargo test — the pure-logic unit tests (no root, no network)
make lint        # cargo fmt --check + cargo clippy -D warnings
make coverage    # llvm-cov over the pure core; fails under the threshold
cargo run        # debug build of the TUI
cargo run -- --diag   # verify the kernel control connects + what it sees
```

The wire protocol is tested by feeding the parsers **synthetic kernel datagrams**
(hand-built byte buffers matching the C layout) and asserting the decoded pid /
addresses / counts — so the riskiest code is covered without needing a live
socket. GitHub Actions runs fmt, clippy, the tests and the coverage gate on
macOS on every push and PR.

## License

[MIT](LICENSE) © 2026 Lucas Daddiego.

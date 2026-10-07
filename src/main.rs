//! netpeek — a live, per-process network-bandwidth TUI for macOS, driven
//! straight off the private `com.apple.network.statistics` kernel control (the
//! same interface `nettop(1)` uses), unprivileged for your own user's flows.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::widgets::TableState;
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

use netpeek::app::{App, Cmd, Mode};
use netpeek::dns::Resolver;
use netpeek::model::{Filter, ProcRow, SortKey, sort_rows};
use netpeek::ntstat::Monitor;
use netpeek::services::Services;
use netpeek::{export, format, ui};

const HIST_LEN: usize = 60;
const DEFAULT_INTERVAL: f64 = 1.0;
/// Accepted `--interval` range. The floor keeps the sampling window meaningful;
/// the ceiling is what stops `Duration::from_secs_f64` — which panics on a
/// non-finite or out-of-range value — from ever seeing one ("inf" and "1e20"
/// both parse as perfectly good `f64`s).
const MIN_INTERVAL: f64 = 0.2;
const MAX_INTERVAL: f64 = 3600.0;

struct Opts {
    interval: f64,
    resolve: bool,
    /// Capture the mouse for wheel-scroll. Off by default so the terminal's own
    /// text selection / copy keeps working (you can still scroll with the keys).
    mouse: bool,
    /// Row order for the one-shot modes (`--sort`), in the key's default
    /// direction — the same keys and directions the TUI's r/t/n/c/i use.
    sort: SortKey,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("netpeek {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let opts = match parse_opts(&args) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("netpeek: {msg}");
            std::process::exit(2);
        }
    };

    let result = if args.iter().any(|a| a == "--diag") {
        run_diag(&opts).map(|()| 0)
    } else if args.iter().any(|a| a == "--json") {
        run_oneshot(&opts, true).map(|()| 0)
    } else if args.iter().any(|a| a == "--once") {
        run_oneshot(&opts, false).map(|()| 0)
    } else {
        run_tui(&opts)
    };

    match result {
        Ok(0) => {}
        Ok(status) => std::process::exit(status),
        Err(e) => {
            eprintln!("netpeek: {e}");
            if e.kind() == io::ErrorKind::PermissionDenied {
                eprintln!("  the network-statistics control rejected the connection.");
            }
            std::process::exit(1);
        }
    }
}

/// Process exit status once the TUI has ended: 0 for a normal quit, or the
/// shell convention `128 + signal` when a signal ended it — so `timeout 10
/// netpeek` reports a failure and a supervisor can tell the two apart.
fn exit_status(signal: usize) -> i32 {
    if signal == 0 { 0 } else { 128 + signal as i32 }
}

/// Parse the option flags into [`Opts`]; `Err` carries the message `main` prints
/// before exiting 2. `--help` / `--version` are handled by the caller.
fn parse_opts(args: &[String]) -> Result<Opts, String> {
    // Mode flags consumed later via `args.iter().any(..)`; accepted as no-ops here.
    let known_flags = ["--once", "--json", "--diag"];
    let mut opts = Opts {
        interval: DEFAULT_INTERVAL,
        resolve: true,
        mouse: false,
        sort: SortKey::Rate,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--interval" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse::<f64>().ok()) {
                    // The range check is also what rejects `inf` / `NaN`, which
                    // parse fine and then panic inside `Duration::from_secs_f64`.
                    Some(v) if (MIN_INTERVAL..=MAX_INTERVAL).contains(&v) => opts.interval = v,
                    _ => {
                        return Err(format!(
                            "--interval needs a number of seconds between {MIN_INTERVAL} and {MAX_INTERVAL}"
                        ));
                    }
                }
            }
            "--sort" => {
                i += 1;
                match args.get(i).and_then(|s| SortKey::parse(s)) {
                    Some(key) => opts.sort = key,
                    None => return Err("--sort needs one of rate, total, name, conns, pid".into()),
                }
            }
            "--no-resolve" => opts.resolve = false,
            "--mouse" => opts.mouse = true,
            a if known_flags.contains(&a) => {}
            a => return Err(format!("unknown argument '{a}' (try --help)")),
        }
        i += 1;
    }
    Ok(opts)
}

fn elevated() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

fn load_services() -> Services {
    let mut s = Services::builtin();
    if let Ok(content) = std::fs::read_to_string("/etc/services") {
        s.merge_etc_services(&content);
    }
    s
}

/// How long the one-shot modes will wait for every flow to be described before
/// sampling anyway (a bound, not a delay — the settle ends as soon as the
/// descriptor queue is empty).
const SETTLE_MAX: Duration = Duration::from_secs(5);

/// Run a handful of collection cycles on an already-open monitor so rates are
/// populated. Shared by the one-shot (`--once`/`--json`/`--diag`) modes.
fn collect_snapshot(mon: &mut Monitor, opts: &Opts) -> io::Result<()> {
    let dt = opts.interval;
    let sleep = Duration::from_secs_f64(dt);
    // Settle: descriptor requests are paced (a batch per drain), so keep
    // draining until none are queued — a fixed number of drains would name only
    // the first few batches' worth of flows on a busy machine and silently drop
    // the rest from the snapshot. A few extra drains let the last replies land.
    let settle_start = Instant::now();
    let mut idle_drains = 0;
    while idle_drains < 4 && settle_start.elapsed() < SETTLE_MAX {
        mon.drain()?;
        idle_drains = if mon.pending_desc() == 0 {
            idle_drains + 1
        } else {
            0
        };
        std::thread::sleep(Duration::from_millis(60));
    }
    // Two count samples spaced by the interval gives a real rate.
    for _ in 0..2 {
        mon.poll_counts()?;
        std::thread::sleep(sleep);
        mon.drain()?;
        mon.tick(dt);
    }
    Ok(())
}

fn sorted_rows(mon: &Monitor, key: SortKey) -> Vec<ProcRow> {
    let mut rows: Vec<ProcRow> = mon.engine().rows().to_vec();
    sort_rows(&mut rows, key, key.descending_by_default());
    rows
}

fn run_oneshot(opts: &Opts, json: bool) -> io::Result<()> {
    let mut mon = Monitor::new(HIST_LEN)?;
    collect_snapshot(&mut mon, opts)?;
    let rows = sorted_rows(&mon, opts.sort);
    if json {
        print_json(&rows);
    } else {
        print!("{}", export::text_table(&rows));
    }
    Ok(())
}

fn run_diag(opts: &Opts) -> io::Result<()> {
    println!("netpeek --diag");
    let mut mon = match Monitor::new(HIST_LEN) {
        Ok(m) => {
            println!("  control socket   : connected (com.apple.network.statistics)");
            m
        }
        Err(e) => {
            println!("  control socket   : FAILED — {e}");
            return Err(e);
        }
    };
    collect_snapshot(&mut mon, opts)?;
    let rows = sorted_rows(&mon, SortKey::Rate); // top talkers, whatever --sort says
    let total: f64 = rows.iter().map(|r| r.total_rate()).sum();
    println!(
        "  privilege        : {}",
        if elevated() {
            "root (all processes)"
        } else {
            "user (your flows)"
        }
    );
    println!("  tracked flows    : {}", mon.engine().flow_count());
    println!("  named processes  : {}", rows.len());
    println!("  aggregate rate   : {}", format::rate(total));
    match mon.last_error() {
        Some(code) => println!("  last kernel error: {code}"),
        None => println!("  last kernel error: none"),
    }
    if rows.is_empty() {
        println!("\n  no per-process flows seen — generate some traffic (e.g. curl) and retry.");
    } else {
        println!("\n  top talkers:");
        for r in rows.iter().take(5) {
            println!(
                "    {:>6}  {}  ↓{:>10}  ↑{:>10}",
                r.pid,
                export::pad(&export::trunc(&r.name, 22), 22),
                format::rate(r.rx_rate),
                format::rate(r.tx_rate)
            );
        }
    }
    Ok(())
}

/// Minimal JSON array writer (keys alphabetised), no serde dependency.
fn print_json(rows: &[ProcRow]) {
    println!("[");
    for (idx, r) in rows.iter().enumerate() {
        let comma = if idx + 1 < rows.len() { "," } else { "" };
        println!(
            "  {{\"conns\": {}, \"name\": \"{}\", \"pid\": {}, \"rx_bytes\": {}, \"rx_rate\": {:.0}, \"tx_bytes\": {}, \"tx_rate\": {:.0}}}{comma}",
            r.conns,
            json_escape(&r.name),
            r.pid,
            r.rx_total,
            r.rx_rate,
            r.tx_total,
            r.tx_rate,
        );
    }
    println!("]");
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn run_tui(opts: &Opts) -> io::Result<i32> {
    let mut mon = Monitor::new(HIST_LEN)?;
    let services = load_services();
    let resolver = opts.resolve.then(Resolver::new);
    let mut app = App::default();

    // SIGTERM / SIGHUP / SIGINT (`kill`, a closed terminal tab, `timeout`) set
    // this flag to the signal number and the poll loop returns on its next
    // pass (≤120 ms), so the TUI unwinds through the normal restore path —
    // raw mode, the alternate screen and mouse capture all come back — instead
    // of the default action killing the process mid-frame and leaving the
    // shell needing `reset`. Raw mode turns Ctrl-C into a key event, so the
    // SIGINT caught here is only ever an external one.
    let signal = Arc::new(AtomicUsize::new(0));
    for sig in [SIGTERM, SIGHUP, SIGINT] {
        signal_hook::flag::register_usize(sig, Arc::clone(&signal), sig as usize)?;
    }

    let mut terminal = ratatui::init();

    // init() installs a panic hook that restores raw mode and the alternate
    // screen, but it knows nothing about mouse capture: a panic under --mouse
    // would leave the terminal reporting every wheel and click into the shell
    // as escape garbage. Chain a hook that releases the mouse first.
    if opts.mouse {
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = execute!(io::stdout(), DisableMouseCapture);
            hook(info);
        }));
    }

    // Everything after ratatui::init() runs inside this closure so that the
    // restore below is reached however it ends. init() turns on raw mode and the
    // alternate screen but installs only a *panic* hook — an early `?` out here
    // (EnableMouseCapture, or an ENOBUFS from the priming drain/poll) would drop
    // the user back into a raw-mode shell needing `reset`.
    let res = (|| -> io::Result<()> {
        // Mouse capture is opt-in: enabling it lets the wheel scroll the list but
        // takes over the mouse, disabling the terminal's own text selection / copy.
        if opts.mouse {
            execute!(io::stdout(), EnableMouseCapture)?;
        }
        run_loop(
            &mut terminal,
            &mut mon,
            &services,
            resolver.as_ref(),
            &mut app,
            opts,
            &signal,
        )
    })();

    if opts.mouse {
        let _ = execute!(io::stdout(), DisableMouseCapture);
    }
    ratatui::restore();
    res?;
    Ok(exit_status(signal.load(Ordering::Relaxed)))
}

fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    mon: &mut Monitor,
    services: &Services,
    resolver: Option<&Resolver>,
    app: &mut App,
    opts: &Opts,
    signal: &AtomicUsize,
) -> io::Result<()> {
    let interval = Duration::from_secs_f64(opts.interval);
    let elevated = elevated();

    // Prime the pump: collect initial sources and request the first counts.
    mon.drain()?;
    mon.poll_counts()?;
    let mut last_tick = Instant::now();
    let mut last_update = clock_hms();

    // Persisted across frames so the table's scroll offset survives (a fresh
    // state each frame would reset it and pin the selection to the bottom).
    let mut table_state = TableState::default();
    let mut needs_redraw = true;
    // Pids of the rows on screen, top to bottom, from the last rendered frame.
    // Input is interpreted against what's on screen, so idle loops (no tick, no
    // key) can skip the rebuild+redraw entirely instead of busy-redrawing ~8×/sec.
    let mut shown_pids: Vec<u32> = Vec::new();
    // Pause freezes sampling, so on resume we re-prime rather than measure a
    // delta that spans the whole pause (which would render as a rate spike).
    let mut was_paused = false;

    loop {
        // Ingest whatever the kernel has sent since last loop.
        mon.drain()?;

        // Recompute rates / aggregates once per interval (unless frozen).
        let now = Instant::now();
        if was_paused && !app.paused {
            // Resume edge: fetch fresh counters now and re-baseline every flow on
            // the next tick (same priming the engine does at startup), so the
            // paused interval isn't divided into a single tick as a spike.
            mon.poll_counts()?;
            mon.reprime();
            last_tick = now;
        }
        was_paused = app.paused;

        if !app.paused && now.duration_since(last_tick) >= interval {
            let dt = now.duration_since(last_tick).as_secs_f64();
            mon.tick(dt);
            mon.poll_counts()?;
            last_tick = now;
            last_update = clock_hms();
            needs_redraw = true; // fresh counters
        }

        if needs_redraw {
            // Build the visible (filtered + sorted) row set — borrowed, so a
            // redraw doesn't clone every row and its sparkline history.
            let all = mon.engine().rows();
            let filter = Filter::new(&app.filter);
            let mut rows: Vec<&ProcRow> = all.iter().filter(|r| filter.matches(r)).collect();
            sort_rows(&mut rows, app.sort, app.sort_desc);

            shown_pids.clear();
            shown_pids.extend(rows.iter().map(|r| r.pid));
            // Follow the process under the cursor to wherever the sort put it.
            app.sync_selection(&shown_pids);

            let flows = app
                .expanded
                .map(|pid| mon.engine().flows_for(pid))
                .unwrap_or_default();
            let (rx_rate, tx_rate) = all
                .iter()
                .fold((0.0, 0.0), |(rx, tx), r| (rx + r.rx_rate, tx + r.tx_rate));

            let view = ui::View {
                rows: &rows,
                flows: &flows,
                services,
                resolver,
                status: ui::StatusInfo {
                    shown_procs: rows.len(),
                    total_procs: all.len(),
                    flow_count: mon.engine().flow_count(),
                    rx_rate,
                    tx_rate,
                    interval_secs: opts.interval,
                    last_update: &last_update,
                    elevated,
                },
            };

            terminal.draw(|f| {
                app.page = (f.area().height as usize).saturating_sub(6).max(1);
                ui::draw(f, app, &view, &mut table_state);
            })?;
            needs_redraw = false;
        }

        // Wait briefly for input. A key / mouse / resize asks for a redraw on the
        // next loop; with none we stay idle (just draining the socket). Whatever
        // else is already queued (a held key arrives as a burst) is applied in
        // the same pass, so it costs one rebuild+redraw rather than one each.
        if event::poll(Duration::from_millis(120))? {
            loop {
                match event::read()? {
                    Event::Key(k) if k.kind != KeyEventKind::Release => {
                        if let Some(cmd) = key_to_cmd(k.code, k.modifiers, app.mode) {
                            app.handle(cmd, &shown_pids);
                        }
                    }
                    Event::Mouse(m) => match m.kind {
                        MouseEventKind::ScrollDown => app.handle(Cmd::Down, &shown_pids),
                        MouseEventKind::ScrollUp => app.handle(Cmd::Up, &shown_pids),
                        _ => {}
                    },
                    _ => {}
                }
                needs_redraw = true;
                if app.should_quit || !event::poll(Duration::ZERO)? {
                    break;
                }
            }
        }

        // A signal ends the loop like `q` does; the caller restores the
        // terminal and turns the signal into the exit status.
        if app.should_quit || signal.load(Ordering::Relaxed) != 0 {
            return Ok(());
        }
    }
}

/// Translate a key event into a logical [`Cmd`], honouring the current mode.
fn key_to_cmd(code: KeyCode, mods: KeyModifiers, mode: Mode) -> Option<Cmd> {
    // Ctrl-C / Ctrl-D always quit, regardless of mode.
    if mods.contains(KeyModifiers::CONTROL)
        && matches!(code, KeyCode::Char('c') | KeyCode::Char('d'))
    {
        return Some(Cmd::Quit);
    }
    if mode == Mode::Filter {
        return match code {
            // A Ctrl chord is not text: Ctrl-U must not type a 'u'.
            KeyCode::Char(_) if mods.contains(KeyModifiers::CONTROL) => None,
            KeyCode::Char(c) => Some(Cmd::FilterChar(c)),
            KeyCode::Backspace => Some(Cmd::FilterBackspace),
            KeyCode::Enter => Some(Cmd::FilterAccept),
            KeyCode::Esc => Some(Cmd::FilterCancel),
            _ => None,
        };
    }
    match code {
        KeyCode::Char('q') => Some(Cmd::Quit),
        KeyCode::Esc => Some(Cmd::Escape),
        KeyCode::Up | KeyCode::Char('k') => Some(Cmd::Up),
        KeyCode::Down | KeyCode::Char('j') => Some(Cmd::Down),
        KeyCode::PageUp => Some(Cmd::PageUp),
        KeyCode::PageDown => Some(Cmd::PageDown),
        KeyCode::Home | KeyCode::Char('g') => Some(Cmd::Home),
        KeyCode::End | KeyCode::Char('G') => Some(Cmd::End),
        KeyCode::Enter | KeyCode::Char(' ') => Some(Cmd::ToggleExpand),
        KeyCode::Char('/') => Some(Cmd::FilterStart),
        KeyCode::Char('p') => Some(Cmd::Pause),
        KeyCode::Char('r') => Some(Cmd::Sort(SortKey::Rate)),
        KeyCode::Char('t') => Some(Cmd::Sort(SortKey::Total)),
        KeyCode::Char('n') => Some(Cmd::Sort(SortKey::Name)),
        KeyCode::Char('c') => Some(Cmd::Sort(SortKey::Conns)),
        KeyCode::Char('i') => Some(Cmd::Sort(SortKey::Pid)),
        KeyCode::Char('?') | KeyCode::Char('h') => Some(Cmd::Help),
        _ => None,
    }
}

/// Local wall-clock `HH:MM:SS` via libc, so there's no chrono dependency.
fn clock_hms() -> String {
    // SAFETY: time/localtime_r with a local tm output buffer.
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

fn print_help() {
    print!(
        "\
netpeek — live per-process network bandwidth for macOS

USAGE:
    netpeek [OPTIONS]

Without options it launches the interactive TUI. It reads the private
com.apple.network.statistics kernel control (the same source as nettop),
unprivileged for your own user's flows; run with sudo to see every process.

OPTIONS:
    --once            One snapshot as a text table, then exit
    --json            One snapshot as a JSON array on stdout (pipe into jq)
    --diag            Connectivity + permission diagnostics
    --interval SECS   Refresh / sampling interval (default 1.0, 0.2 to 3600)
    --sort KEY        Row order for --once / --json: rate (default), total,
                      name, conns or pid — the TUI's r/t/n/c/i, same directions
    --no-resolve      Skip reverse-DNS of remote hosts (TUI)
    --mouse           Capture the mouse for wheel-scroll (off by default, so
                      terminal text selection keeps working; keys still scroll)
    --version, -V     Print version
    --help, -h        This help

TUI KEYS:
    ↑/↓ k/j move   PgUp/PgDn page   g/G top/bottom   enter expand a process
    / filter   p pause   r/t/n/c/i sort (repeat to reverse)   ? help
    q quit   esc back out (help → filter → quit)
"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escaping() {
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("tab\there"), "tab\\u0009here");
    }

    #[test]
    fn exit_status_follows_the_shell_convention() {
        assert_eq!(exit_status(0), 0);
        assert_eq!(exit_status(SIGHUP as usize), 129);
        assert_eq!(exit_status(SIGINT as usize), 130);
        assert_eq!(exit_status(SIGTERM as usize), 143);
    }

    fn opts_from(args: &[&str]) -> Result<Opts, String> {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse_opts(&owned)
    }

    #[test]
    fn parses_flags_and_defaults() {
        let o = opts_from(&[]).unwrap();
        assert_eq!(o.interval, DEFAULT_INTERVAL);
        assert!(o.resolve);
        assert!(!o.mouse);

        let o = opts_from(&["--once", "--no-resolve", "--mouse", "--interval", "2.5"]).unwrap();
        assert_eq!(o.interval, 2.5);
        assert!(!o.resolve);
        assert!(o.mouse);
        assert_eq!(o.sort, SortKey::Rate);

        assert!(opts_from(&["--nope"]).is_err());
    }

    #[test]
    fn sort_flag_takes_the_tui_key_names() {
        assert_eq!(opts_from(&["--sort", "name"]).unwrap().sort, SortKey::Name);
        assert_eq!(
            opts_from(&["--json", "--sort", "conns"]).unwrap().sort,
            SortKey::Conns
        );
        for bad in ["--sort", "--sort x", "--sort Rate"] {
            let args: Vec<&str> = bad.split(' ').collect();
            assert!(opts_from(&args).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn interval_rejects_values_duration_cannot_hold() {
        // Every accepted interval is handed to Duration::from_secs_f64, which
        // panics on a non-finite or out-of-range value; "inf"/"1e20" parse as
        // valid f64s and used to sail past a bare `>= 0.2` check.
        for bad in ["inf", "-inf", "nan", "1e20", "3601", "0.1", "-1", "abc", ""] {
            let r = opts_from(&["--interval", bad]);
            assert!(r.is_err(), "--interval {bad} should be rejected");
        }
        // a missing value is still an error, not a panic
        assert!(opts_from(&["--interval"]).is_err());

        for good in ["0.2", "1", "1.5", "3600"] {
            let o = opts_from(&["--interval", good]).unwrap();
            // the accepted range is exactly what Duration can represent
            let _ = Duration::from_secs_f64(o.interval);
        }
    }

    #[test]
    fn keymap_normal_mode() {
        assert_eq!(
            key_to_cmd(KeyCode::Char('q'), KeyModifiers::NONE, Mode::Normal),
            Some(Cmd::Quit)
        );
        assert_eq!(
            key_to_cmd(KeyCode::Char('j'), KeyModifiers::NONE, Mode::Normal),
            Some(Cmd::Down)
        );
        assert_eq!(
            key_to_cmd(KeyCode::Char('/'), KeyModifiers::NONE, Mode::Normal),
            Some(Cmd::FilterStart)
        );
        assert_eq!(
            key_to_cmd(KeyCode::Char('r'), KeyModifiers::NONE, Mode::Normal),
            Some(Cmd::Sort(SortKey::Rate))
        );
        assert_eq!(
            key_to_cmd(KeyCode::Enter, KeyModifiers::NONE, Mode::Normal),
            Some(Cmd::ToggleExpand)
        );
        assert_eq!(
            key_to_cmd(KeyCode::Char('z'), KeyModifiers::NONE, Mode::Normal),
            None
        );
        // Esc is the stepwise back-out, not a hard quit
        assert_eq!(
            key_to_cmd(KeyCode::Esc, KeyModifiers::NONE, Mode::Normal),
            Some(Cmd::Escape)
        );
    }

    #[test]
    fn keymap_ctrl_c_always_quits() {
        assert_eq!(
            key_to_cmd(KeyCode::Char('c'), KeyModifiers::CONTROL, Mode::Filter),
            Some(Cmd::Quit)
        );
        assert_eq!(
            key_to_cmd(KeyCode::Char('d'), KeyModifiers::CONTROL, Mode::Normal),
            Some(Cmd::Quit)
        );
    }

    #[test]
    fn keymap_filter_mode() {
        assert_eq!(
            key_to_cmd(KeyCode::Char('x'), KeyModifiers::NONE, Mode::Filter),
            Some(Cmd::FilterChar('x'))
        );
        assert_eq!(
            key_to_cmd(KeyCode::Esc, KeyModifiers::NONE, Mode::Filter),
            Some(Cmd::FilterCancel)
        );
        assert_eq!(
            key_to_cmd(KeyCode::Enter, KeyModifiers::NONE, Mode::Filter),
            Some(Cmd::FilterAccept)
        );
        // 'c' in filter mode is a literal character, not quit
        assert_eq!(
            key_to_cmd(KeyCode::Char('c'), KeyModifiers::NONE, Mode::Filter),
            Some(Cmd::FilterChar('c'))
        );
        // shifted letters still type
        assert_eq!(
            key_to_cmd(KeyCode::Char('X'), KeyModifiers::SHIFT, Mode::Filter),
            Some(Cmd::FilterChar('X'))
        );
    }

    #[test]
    fn keymap_filter_mode_ignores_ctrl_letters() {
        // Ctrl-U, Ctrl-W, Ctrl-A ... are not text: they must not type 'u', 'w',
        // 'a' into the query.
        for c in ['u', 'w', 'a', 'k'] {
            assert_eq!(
                key_to_cmd(KeyCode::Char(c), KeyModifiers::CONTROL, Mode::Filter),
                None,
                "Ctrl-{c} typed into the filter"
            );
        }
    }
}

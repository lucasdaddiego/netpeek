//! netpeek — a live, per-process network-bandwidth TUI for macOS, driven
//! straight off the private `com.apple.network.statistics` kernel control (the
//! same interface `nettop(1)` uses), unprivileged for your own user's flows.

use std::io;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::widgets::TableState;

use netpeek::app::{App, Cmd, Mode};
use netpeek::dns::Resolver;
use netpeek::model::{matches_filter, sort_rows, ProcRow, SortKey};
use netpeek::ntstat::Monitor;
use netpeek::services::Services;
use netpeek::{format, ui};

const HIST_LEN: usize = 60;
const DEFAULT_INTERVAL: f64 = 1.0;

struct Opts {
    interval: f64,
    resolve: bool,
    /// Capture the mouse for wheel-scroll. Off by default so the terminal's own
    /// text selection / copy keeps working (you can still scroll with the keys).
    mouse: bool,
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

    // Mode flags consumed later via `args.iter().any(..)`; accepted as no-ops here.
    let known_flags = ["--once", "--json", "--diag"];
    let mut opts = Opts {
        interval: DEFAULT_INTERVAL,
        resolve: true,
        mouse: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--interval" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse::<f64>().ok()) {
                    Some(v) if v >= 0.2 => opts.interval = v,
                    _ => {
                        eprintln!("netpeek: --interval needs a number of seconds >= 0.2");
                        std::process::exit(2);
                    }
                }
            }
            "--no-resolve" => opts.resolve = false,
            "--mouse" => opts.mouse = true,
            a if known_flags.contains(&a) => {}
            a => {
                eprintln!("netpeek: unknown argument '{a}' (try --help)");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let result = if args.iter().any(|a| a == "--diag") {
        run_diag(&opts)
    } else if args.iter().any(|a| a == "--json") {
        run_oneshot(&opts, true)
    } else if args.iter().any(|a| a == "--once") {
        run_oneshot(&opts, false)
    } else {
        run_tui(&opts)
    };

    if let Err(e) = result {
        eprintln!("netpeek: {e}");
        if e.kind() == io::ErrorKind::PermissionDenied {
            eprintln!("  the network-statistics control rejected the connection.");
        }
        std::process::exit(1);
    }
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

/// Run a handful of collection cycles on an already-open monitor so rates are
/// populated. Shared by the one-shot (`--once`/`--json`/`--diag`) modes.
fn collect_snapshot(mon: &mut Monitor, opts: &Opts) -> io::Result<()> {
    let dt = opts.interval;
    let sleep = Duration::from_secs_f64(dt);
    // Settle: descriptor requests are paced, so drain repeatedly to let every
    // SRC_ADDED be seen and named before we sample.
    for _ in 0..12 {
        mon.drain()?;
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

fn sorted_rows(mon: &Monitor) -> Vec<ProcRow> {
    let mut rows: Vec<ProcRow> = mon.engine().rows().to_vec();
    sort_rows(&mut rows, SortKey::Rate, true);
    rows
}

fn run_oneshot(opts: &Opts, json: bool) -> io::Result<()> {
    let mut mon = Monitor::new(HIST_LEN)?;
    collect_snapshot(&mut mon, opts)?;
    let rows = sorted_rows(&mon);
    if json {
        print_json(&rows);
    } else {
        print_table(&rows);
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
    let rows = sorted_rows(&mon);
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
                "    {:>6}  {:<22}  ↓{:>10}  ↑{:>10}",
                r.pid,
                trunc(&r.name, 22),
                format::rate(r.rx_rate),
                format::rate(r.tx_rate)
            );
        }
    }
    Ok(())
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n.saturating_sub(1)).chain(['…']).collect()
    }
}

fn print_table(rows: &[ProcRow]) {
    println!(
        "{:>6}  {:<24}  {:>11}  {:>11}  {:>10}  {:>5}",
        "PID", "PROCESS", "DOWN/s", "UP/s", "TOTAL", "CONNS"
    );
    for r in rows {
        println!(
            "{:>6}  {:<24}  {:>11}  {:>11}  {:>10}  {:>5}",
            r.pid,
            trunc(&r.name, 24),
            format::rate(r.rx_rate),
            format::rate(r.tx_rate),
            format::bytes(r.total_bytes()),
            r.conns
        );
    }
    if rows.is_empty() {
        println!("(no per-process network flows seen)");
    }
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

fn run_tui(opts: &Opts) -> io::Result<()> {
    let mut mon = Monitor::new(HIST_LEN)?;
    let services = load_services();
    let resolver = if opts.resolve {
        Some(Resolver::new())
    } else {
        None
    };
    let mut app = App::default();
    let interval = Duration::from_secs_f64(opts.interval);

    let mut terminal = ratatui::init();
    // Mouse capture is opt-in: enabling it lets the wheel scroll the list but
    // takes over the mouse, disabling the terminal's own text selection / copy.
    if opts.mouse {
        execute!(io::stdout(), EnableMouseCapture)?;
    }

    // Prime the pump: collect initial sources and request the first counts.
    mon.drain()?;
    mon.poll_counts()?;
    let mut last_tick = Instant::now();
    let mut last_update = clock_hms();

    let res = run_loop(
        &mut terminal,
        &mut mon,
        &services,
        resolver.as_ref(),
        &mut app,
        opts,
        interval,
        &mut last_tick,
        &mut last_update,
    );

    if opts.mouse {
        let _ = execute!(io::stdout(), DisableMouseCapture);
    }
    ratatui::restore();
    res
}

#[allow(clippy::too_many_arguments)]
fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    mon: &mut Monitor,
    services: &Services,
    resolver: Option<&Resolver>,
    app: &mut App,
    opts: &Opts,
    interval: Duration,
    last_tick: &mut Instant,
    last_update: &mut String,
) -> io::Result<()> {
    // Persisted across frames so the table's scroll offset survives (a fresh
    // state each frame would reset it and pin the selection to the bottom).
    let mut table_state = TableState::default();
    let mut needs_redraw = true;
    // Row count + cursor pid from the last rendered frame. Input is interpreted
    // against what's on screen, so idle loops (no tick, no key) can skip the
    // rebuild+redraw entirely instead of busy-redrawing ~8×/sec.
    let mut shown_len = 0usize;
    let mut shown_pid: Option<u32> = None;
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
            *last_tick = now;
        }
        was_paused = app.paused;

        if !app.paused && now.duration_since(*last_tick) >= interval {
            let dt = now.duration_since(*last_tick).as_secs_f64();
            mon.tick(dt);
            mon.poll_counts()?;
            *last_tick = now;
            *last_update = clock_hms();
            needs_redraw = true; // fresh counters
        }

        if needs_redraw {
            // Build the visible (filtered + sorted) row set.
            let mut rows: Vec<ProcRow> = mon
                .engine()
                .rows()
                .iter()
                .filter(|r| matches_filter(r, &app.filter))
                .cloned()
                .collect();
            sort_rows(&mut rows, app.sort, app.sort_desc);
            app.clamp_selection(rows.len());

            shown_len = rows.len();
            shown_pid = rows.get(app.selected).map(|r| r.pid);
            let flows = app
                .expanded
                .map(|pid| mon.engine().flows_for(pid))
                .unwrap_or_default();

            let status = ui::StatusInfo {
                proc_count: rows.len(),
                flow_count: mon.engine().flow_count(),
                interval_secs: opts.interval,
                last_update: last_update.clone(),
                elevated: elevated(),
            };

            terminal.draw(|f| {
                app.page = (f.area().height as usize).saturating_sub(6).max(1);
                ui::draw(
                    f,
                    app,
                    &rows,
                    &flows,
                    services,
                    resolver,
                    &status,
                    &mut table_state,
                );
            })?;
            needs_redraw = false;
        }

        // Wait briefly for input. A key / mouse / resize asks for a redraw on the
        // next loop; with none we stay idle (just draining the socket).
        if event::poll(Duration::from_millis(120))? {
            match event::read()? {
                Event::Key(k) if k.kind != KeyEventKind::Release => {
                    if let Some(cmd) = key_to_cmd(k.code, k.modifiers, app.mode) {
                        app.handle(cmd, shown_len, shown_pid);
                    }
                    needs_redraw = true;
                }
                Event::Mouse(m) => {
                    match m.kind {
                        MouseEventKind::ScrollDown => app.handle(Cmd::Down, shown_len, shown_pid),
                        MouseEventKind::ScrollUp => app.handle(Cmd::Up, shown_len, shown_pid),
                        _ => {}
                    }
                    needs_redraw = true;
                }
                Event::Resize(_, _) => needs_redraw = true,
                _ => {}
            }
        }

        if app.should_quit {
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
            KeyCode::Char(c) => Some(Cmd::FilterChar(c)),
            KeyCode::Backspace => Some(Cmd::FilterBackspace),
            KeyCode::Enter => Some(Cmd::FilterAccept),
            KeyCode::Esc => Some(Cmd::FilterCancel),
            _ => None,
        };
    }
    match code {
        KeyCode::Char('q') | KeyCode::Esc => Some(Cmd::Quit),
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
    --interval SECS   Refresh / sampling interval (default 1.0, min 0.2)
    --no-resolve      Skip reverse-DNS of remote hosts (TUI)
    --mouse           Capture the mouse for wheel-scroll (off by default, so
                      terminal text selection keeps working; keys still scroll)
    --version, -V     Print version
    --help, -h        This help

TUI KEYS:
    ↑/↓ k/j move   PgUp/PgDn page   g/G top/bottom   enter expand a process
    / filter   p pause   r/t/n/c/i sort (repeat to reverse)   ? help   q quit
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
    fn truncation_helper() {
        assert_eq!(trunc("short", 10), "short");
        assert_eq!(trunc("a-very-long-process-name", 8), "a-very-…");
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
    }
}

//! ratatui rendering. All terminal-bound; the logic it draws (sorting,
//! filtering, formatting, sparklines) lives in the tested pure modules.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::app::{App, Mode};
use crate::dns::Resolver;
use crate::format;
use crate::model::{Flow, ProcRow, SortKey};
use crate::services::Services;

/// Status-line facts the render loop hands in each frame.
pub struct StatusInfo {
    pub proc_count: usize,
    pub flow_count: usize,
    pub interval_secs: f64,
    pub last_update: String,
    pub elevated: bool,
}

const C_DOWN: Color = Color::Green;
const C_UP: Color = Color::Cyan;
const C_DIM: Color = Color::DarkGray;
const C_ACCENT: Color = Color::Yellow;

/// Draw the whole UI for one frame.
pub fn draw(
    f: &mut Frame,
    app: &App,
    rows: &[ProcRow],
    flows: &[Flow],
    services: &Services,
    resolver: Option<&Resolver>,
    status: &StatusInfo,
) {
    let show_detail = app.expanded.is_some() && !flows.is_empty();
    let mut constraints = vec![Constraint::Length(1), Constraint::Min(3)];
    if show_detail {
        let h = (flows.len() as u16 + 3).clamp(5, 14);
        constraints.push(Constraint::Length(h));
    }
    constraints.push(Constraint::Length(1));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(f.area());

    draw_status(f, chunks[0], app, status);
    draw_table(f, chunks[1], app, rows);
    if show_detail {
        draw_detail(f, chunks[2], app, flows, services, resolver);
        draw_footer(f, chunks[3], app);
    } else {
        draw_footer(f, chunks[2], app);
    }

    if app.show_help {
        draw_help(f);
    }
}

fn draw_status(f: &mut Frame, area: Rect, app: &App, status: &StatusInfo) {
    let arrow = if app.sort_desc { "↓" } else { "↑" };
    let mut spans = vec![
        Span::styled(
            "netpeek",
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{} procs", status.proc_count),
            Style::default().fg(Color::White),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{} flows", status.flow_count),
            Style::default().fg(C_DIM),
        ),
        Span::raw("  sort "),
        Span::styled(
            format!("{}{arrow}", app.sort.label()),
            Style::default().fg(C_ACCENT),
        ),
        Span::raw(format!("  every {:.0}s", status.interval_secs)),
    ];
    if app.paused {
        spans.push(Span::styled(
            "  PAUSED",
            Style::default()
                .fg(Color::Black)
                .bg(C_ACCENT)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if status.elevated {
        spans.push(Span::styled(
            "  [root: all procs]",
            Style::default().fg(Color::Magenta),
        ));
    } else {
        spans.push(Span::styled("  [your flows]", Style::default().fg(C_DIM)));
    }
    spans.push(Span::styled(
        format!("  upd {}", status.last_update),
        Style::default().fg(C_DIM),
    ));

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Whether the terminal is wide enough to show the inline sparkline columns.
fn wide(area: Rect) -> bool {
    area.width >= 92
}

fn draw_table(f: &mut Frame, area: Rect, app: &App, rows: &[ProcRow]) {
    let show_spark = wide(area);

    let mark = |key: SortKey, base: &str| -> String {
        if app.sort == key {
            format!("{base}{}", if app.sort_desc { "↓" } else { "↑" })
        } else {
            base.to_string()
        }
    };

    let mut headers = vec![
        Cell::from(mark(SortKey::Pid, "PID")),
        Cell::from(mark(SortKey::Name, "PROCESS")),
        Cell::from(right(mark(SortKey::Rate, "DOWN"))),
    ];
    if show_spark {
        headers.push(Cell::from("  ↓"));
    }
    headers.push(Cell::from(right("UP".to_string())));
    if show_spark {
        headers.push(Cell::from("  ↑"));
    }
    headers.push(Cell::from(right(mark(SortKey::Total, "TOTAL"))));
    headers.push(Cell::from(right(mark(SortKey::Conns, "CONNS"))));

    let header = Row::new(headers).style(Style::default().fg(C_DIM).add_modifier(Modifier::BOLD));

    let body: Vec<Row> = rows
        .iter()
        .map(|r| {
            let name = format!(
                "{} {}",
                if app.expanded == Some(r.pid) {
                    "▾"
                } else {
                    "▸"
                },
                r.name
            );
            let mut cells = vec![
                Cell::from(right(r.pid.to_string())),
                Cell::from(name),
                Cell::from(rate_cell(r.rx_rate, C_DOWN)),
            ];
            if show_spark {
                cells.push(Cell::from(Span::styled(
                    format::spark(&r.rx_hist, 6),
                    Style::default().fg(C_DOWN),
                )));
            }
            cells.push(Cell::from(rate_cell(r.tx_rate, C_UP)));
            if show_spark {
                cells.push(Cell::from(Span::styled(
                    format::spark(&r.tx_hist, 6),
                    Style::default().fg(C_UP),
                )));
            }
            cells.push(Cell::from(right(format::bytes(r.total_bytes()))));
            cells.push(Cell::from(right(r.conns.to_string())));
            Row::new(cells)
        })
        .collect();

    let mut widths = vec![
        Constraint::Length(7),
        Constraint::Min(14),
        Constraint::Length(11),
    ];
    if show_spark {
        widths.push(Constraint::Length(6));
    }
    widths.push(Constraint::Length(11));
    if show_spark {
        widths.push(Constraint::Length(6));
    }
    widths.push(Constraint::Length(9));
    widths.push(Constraint::Length(6));

    let title = if app.filter.is_empty() && app.mode != Mode::Filter {
        " processes ".to_string()
    } else {
        let cursor = if app.mode == Mode::Filter { "_" } else { "" };
        format!(" filter: {}{cursor} ", app.filter)
    };

    let table = Table::new(body, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 44, 52))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("");

    let mut state = TableState::default();
    if !rows.is_empty() {
        state.select(Some(app.selected.min(rows.len() - 1)));
    }
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_detail(
    f: &mut Frame,
    area: Rect,
    app: &App,
    flows: &[Flow],
    services: &Services,
    resolver: Option<&Resolver>,
) {
    let pid = app.expanded.unwrap_or(0);
    let name = flows.first().map(|fl| fl.pname.as_str()).unwrap_or("");
    let title = format!(" {name} (pid {pid}) — {} flows ", flows.len());

    let header = Row::new(vec![
        Cell::from("PROTO"),
        Cell::from("STATE"),
        Cell::from("REMOTE"),
        Cell::from(right("DOWN".to_string())),
        Cell::from(right("UP".to_string())),
    ])
    .style(Style::default().fg(C_DIM).add_modifier(Modifier::BOLD));

    let body: Vec<Row> = flows
        .iter()
        .map(|fl| {
            let state = if fl.proto == crate::model::Proto::Tcp {
                format::tcp_state(fl.tcp_state).to_string()
            } else {
                "—".to_string()
            };
            let remote = match fl.remote {
                Some(ep) => {
                    let host = resolver
                        .and_then(|r| r.lookup(ep.ip))
                        .unwrap_or_else(|| ep.ip.to_string());
                    format!("{host}:{}", services.label(ep.port, fl.proto))
                }
                None => "—".to_string(),
            };
            Row::new(vec![
                Cell::from(fl.proto.as_str()),
                Cell::from(state),
                Cell::from(remote),
                Cell::from(rate_cell(fl.rx_rate, C_DOWN)),
                Cell::from(rate_cell(fl.tx_rate, C_UP)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(5),
        Constraint::Length(12),
        Constraint::Min(20),
        Constraint::Length(11),
        Constraint::Length(11),
    ];
    let table = Table::new(body, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(table, area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let text = if app.mode == Mode::Filter {
        "type to filter   enter accept   esc clear".to_string()
    } else {
        "q quit  ↑↓ move  enter expand  / filter  p pause  r/t/n/c/i sort  ? help".to_string()
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(text, Style::default().fg(C_DIM)))),
        area,
    );
}

fn draw_help(f: &mut Frame) {
    let area = centered(60, 60, f.area());
    f.render_widget(Clear, area);
    let lines = vec![
        Line::from(Span::styled(
            "netpeek — keys",
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  ↑ / ↓ / k / j     move selection"),
        Line::from("  PgUp / PgDn       jump a page"),
        Line::from("  g / G             top / bottom"),
        Line::from("  enter / space     expand a process to its flows"),
        Line::from("  /                 filter by name or pid"),
        Line::from("  p                 pause / freeze updates"),
        Line::from("  r                 sort by rate (down+up)"),
        Line::from("  t                 sort by total bytes"),
        Line::from("  n                 sort by process name"),
        Line::from("  c                 sort by connection count"),
        Line::from("  i                 sort by pid"),
        Line::from("                    (press a sort key again to reverse)"),
        Line::from("  ? / h             toggle this help"),
        Line::from("  q / Ctrl-C        quit"),
        Line::from(""),
        Line::from(Span::styled(
            "  data: com.apple.network.statistics (same as nettop)",
            Style::default().fg(C_DIM),
        )),
    ];
    let p = Paragraph::new(Text::from(lines))
        .block(Block::default().borders(Borders::ALL).title(" help "));
    f.render_widget(p, area);
}

// ---- small cell helpers -----------------------------------------------------

fn right(s: String) -> Line<'static> {
    Line::from(s).alignment(Alignment::Right)
}

fn rate_cell(rate: f64, color: Color) -> Line<'static> {
    let style = if rate < 1.0 {
        Style::default().fg(C_DIM)
    } else {
        Style::default().fg(color)
    };
    Line::from(Span::styled(format::rate(rate), style)).alignment(Alignment::Right)
}

fn centered(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(v[1])[1]
}

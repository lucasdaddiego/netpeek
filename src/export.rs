//! Output for the one-shot modes (`--once`, `--json`, `--diag`): a text table
//! whose column fitting counts terminal *columns*, not chars (so a CJK process
//! name does not push the rest of its row out of line), and a hand-rolled JSON
//! document with no serde dependency. Pure string building — it sits under the
//! coverage gate and `main` only prints the result.

use std::fmt::Write;

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::format;
use crate::model::{Flow, ProcRow, Proto};
use crate::ntstat::wire::Endpoint;

/// Fit `s` into `n` terminal columns: unchanged when it fits, else cut to
/// `n - 1` columns plus `…`. A double-width (CJK) character that would
/// straddle the cut is dropped, so the result never exceeds `n` columns.
pub fn trunc(s: &str, n: usize) -> String {
    if s.width() <= n {
        return s.to_string();
    }
    let budget = n.saturating_sub(1);
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let w = c.width().unwrap_or(0);
        if used + w > budget {
            break;
        }
        out.push(c);
        used += w;
    }
    out.push('…');
    out
}

/// Left-align `s` in `n` terminal columns (what `{:<n}` would do if it counted
/// columns instead of chars). Longer input is returned as is.
pub fn pad(s: &str, n: usize) -> String {
    let fill = n.saturating_sub(s.width());
    format!("{s}{}", " ".repeat(fill))
}

/// The `--once` table: one line per process, names fitted to the PROCESS
/// column by display width, numeric columns right-aligned.
pub fn text_table(rows: &[ProcRow]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:>6}  {}  {:>11}  {:>11}  {:>10}  {:>5}",
        "PID",
        pad("PROCESS", 24),
        "DOWN/s",
        "UP/s",
        "TOTAL",
        "CONNS"
    );
    for r in rows {
        let _ = writeln!(
            out,
            "{:>6}  {}  {:>11}  {:>11}  {:>10}  {:>5}",
            r.pid,
            pad(&trunc(&r.name, 24), 24),
            format::rate(r.rx_rate),
            format::rate(r.tx_rate),
            format::bytes(r.total_bytes()),
            r.conns
        );
    }
    if rows.is_empty() {
        out.push_str("(no per-process network flows seen)\n");
    }
    out
}

/// The `--json` document. Keys are alphabetised at every level:
///
/// - `interval`: the sampling window the rates were measured over, seconds;
/// - `processes`: one object per process in the requested order — `conns`,
///   `name`, `pid`, cumulative `rx_bytes`/`tx_bytes`, current `rx_rate`/
///   `tx_rate` (bytes/sec) — plus, when `flows` is given, a `flows` array with
///   one object per socket: `local_ip`/`local_port`, `proto` (`tcp`/`udp`),
///   `remote_ip`/`remote_port` (`null` for a LISTEN or unconnected socket),
///   its own bytes and rates, and the TCP `state` (`null` for UDP);
/// - `ts`: when the snapshot was taken, UTC ISO-8601;
/// - `version`: the netpeek version that produced it.
///
/// `flows[i]` belongs to `rows[i]`; a missing entry prints as `[]`.
pub fn json_document(
    rows: &[ProcRow],
    flows: Option<&[Vec<&Flow>]>,
    interval: f64,
    ts: &str,
) -> String {
    let mut out = String::from("{\n");
    let _ = writeln!(out, "  \"interval\": {interval},");
    if rows.is_empty() {
        out.push_str("  \"processes\": [],\n");
    } else {
        out.push_str("  \"processes\": [\n");
        for (idx, r) in rows.iter().enumerate() {
            let comma = if idx + 1 < rows.len() { "," } else { "" };
            let _ = write!(out, "    {{\"conns\": {}, ", r.conns);
            if let Some(per_proc) = flows {
                let list = per_proc.get(idx).map(Vec::as_slice).unwrap_or(&[]);
                out.push_str("\"flows\": [");
                for (j, fl) in list.iter().enumerate() {
                    let c = if j + 1 < list.len() { "," } else { "" };
                    let _ = write!(out, "\n      {}{c}", json_flow(fl));
                }
                if !list.is_empty() {
                    out.push_str("\n    ");
                }
                out.push_str("], ");
            }
            let _ = writeln!(
                out,
                "\"name\": \"{}\", \"pid\": {}, \"rx_bytes\": {}, \"rx_rate\": {:.0}, \"tx_bytes\": {}, \"tx_rate\": {:.0}}}{comma}",
                json_escape(&r.name),
                r.pid,
                r.rx_total,
                r.rx_rate,
                r.tx_total,
                r.tx_rate,
            );
        }
        out.push_str("  ],\n");
    }
    let _ = writeln!(out, "  \"ts\": \"{}\",", json_escape(ts));
    let _ = writeln!(out, "  \"version\": \"{}\"", env!("CARGO_PKG_VERSION"));
    out.push_str("}\n");
    out
}

fn json_flow(fl: &Flow) -> String {
    let (local_ip, local_port) = json_endpoint(fl.local);
    let (remote_ip, remote_port) = json_endpoint(fl.remote);
    let state = match fl.proto {
        Proto::Tcp => format!("\"{}\"", format::tcp_state(fl.tcp_state)),
        Proto::Udp => "null".to_string(),
    };
    format!(
        "{{\"local_ip\": {local_ip}, \"local_port\": {local_port}, \"proto\": \"{}\", \"remote_ip\": {remote_ip}, \"remote_port\": {remote_port}, \"rx_bytes\": {}, \"rx_rate\": {:.0}, \"state\": {state}, \"tx_bytes\": {}, \"tx_rate\": {:.0}}}",
        fl.proto.as_str().to_ascii_lowercase(),
        fl.rx_bytes,
        fl.rx_rate,
        fl.tx_bytes,
        fl.tx_rate,
    )
}

/// `("\"ip\"", "port")` for an endpoint, or two `null`s when there is none.
fn json_endpoint(ep: Option<Endpoint>) -> (String, String) {
    match ep {
        Some(ep) => (format!("\"{}\"", ep.ip), ep.port.to_string()),
        None => ("null".to_string(), "null".to_string()),
    }
}

/// Escape a string for a JSON literal: quote, backslash and the C0 controls
/// (as `\uXXXX`). Everything else is valid raw UTF-8 inside a JSON string.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Engine;
    use crate::ntstat::wire::{Counts, FlowDesc};
    use std::net::{IpAddr, Ipv4Addr};

    fn row(pid: u32, name: &str) -> ProcRow {
        ProcRow {
            pid,
            name: name.to_string(),
            rx_rate: 1536.0,
            tx_rate: 0.0,
            rx_total: 2048,
            tx_total: 1024,
            conns: 2,
            rx_hist: vec![],
            tx_hist: vec![],
        }
    }

    #[test]
    fn trunc_counts_columns_not_chars() {
        assert_eq!(trunc("short", 10), "short");
        assert_eq!(trunc("a-very-long-process-name", 8), "a-very-…");
        assert_eq!(trunc("日本語の名前", 12), "日本語の名前"); // 12 columns: fits exactly
        assert_eq!(trunc("日本語の名前", 8), "日本語…"); // a 4th CJK char would straddle the cut
        assert_eq!(trunc("日本", 1), "…");
        assert_eq!(trunc("", 0), "");
    }

    #[test]
    fn pad_counts_columns_not_chars() {
        assert_eq!(pad("ab", 4), "ab  ");
        assert_eq!(pad("日本", 6), "日本  ");
        assert_eq!(pad("toolong", 3), "toolong");
    }

    #[test]
    fn table_keeps_wide_names_aligned() {
        let t = text_table(&[row(1, "curl"), row(22, "日本語のプロセス名はとても長い")]);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("   PID  PROCESS"));
        assert!(lines[1].starts_with("     1  curl"));
        let numbers = format!(
            "{:>11}  {:>11}  {:>10}  {:>5}",
            "1.5 KB/s", "0 B/s", "3.0 KB", 2
        );
        assert!(lines[1].ends_with(&numbers));
        assert!(lines[2].contains('…'));
        // Both rows occupy the same number of terminal columns, so the numeric
        // columns line up under the header even though row 2 has fewer chars.
        assert_eq!(lines[1].width(), lines[2].width());
        assert_eq!(lines[0].width(), lines[2].width());
    }

    #[test]
    fn empty_table_says_so() {
        let t = text_table(&[]);
        assert_eq!(t.lines().count(), 2);
        assert!(t.ends_with("(no per-process network flows seen)\n"));
    }

    #[test]
    fn json_escaping() {
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("tab\there"), "tab\\u0009here");
        assert_eq!(json_escape("日本 ✓ \u{fffd}"), "日本 ✓ \u{fffd}"); // raw UTF-8 is valid JSON
    }

    #[test]
    fn json_document_without_flows() {
        let mut quoted = row(7, "a \"quoted\" name");
        quoted.rx_rate = 1234.6;
        let doc = json_document(&[row(1, "curl"), quoted], None, 0.5, "2026-10-06T12:00:00Z");
        let expected = format!(
            "{{\n  \"interval\": 0.5,\n  \"processes\": [\n    \
             {{\"conns\": 2, \"name\": \"curl\", \"pid\": 1, \"rx_bytes\": 2048, \"rx_rate\": 1536, \"tx_bytes\": 1024, \"tx_rate\": 0}},\n    \
             {{\"conns\": 2, \"name\": \"a \\\"quoted\\\" name\", \"pid\": 7, \"rx_bytes\": 2048, \"rx_rate\": 1235, \"tx_bytes\": 1024, \"tx_rate\": 0}}\n  \
             ],\n  \"ts\": \"2026-10-06T12:00:00Z\",\n  \"version\": \"{}\"\n}}\n",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(doc, expected);
    }

    #[test]
    fn json_document_with_no_processes() {
        let doc = json_document(&[], Some(&[]), 1.0, "t");
        assert_eq!(
            doc,
            format!(
                "{{\n  \"interval\": 1,\n  \"processes\": [],\n  \"ts\": \"t\",\n  \"version\": \"{}\"\n}}\n",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    fn ep(ip: [u8; 4], port: u16) -> Endpoint {
        Endpoint {
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            port,
        }
    }

    /// An engine with one curl process owning a TCP flow to 1.1.1.1:443 and
    /// an unconnected UDP socket, ticked twice so the rates are real.
    fn engine_with_flows() -> Engine {
        let mut e = Engine::new(4);
        e.on_added(1, Proto::Tcp);
        e.on_desc(
            1,
            Proto::Tcp,
            FlowDesc {
                pid: 100,
                pname: "curl".to_string(),
                local: Some(ep([192, 168, 1, 2], 50000)),
                remote: Some(ep([1, 1, 1, 1], 443)),
                tcp_state: 4,
            },
        );
        e.on_added(2, Proto::Udp);
        e.on_desc(
            2,
            Proto::Udp,
            FlowDesc {
                pid: 100,
                pname: "curl".to_string(),
                local: Some(ep([0, 0, 0, 0], 5353)),
                remote: None,
                tcp_state: 0,
            },
        );
        for srcref in [1, 2] {
            e.on_counts(
                srcref,
                Counts {
                    rx_bytes: 0,
                    tx_bytes: 0,
                },
            );
        }
        e.tick(1.0);
        e.on_counts(
            1,
            Counts {
                rx_bytes: 10_000,
                tx_bytes: 2_000,
            },
        );
        e.on_counts(
            2,
            Counts {
                rx_bytes: 300,
                tx_bytes: 0,
            },
        );
        e.tick(2.0);
        e
    }

    #[test]
    fn json_document_with_flows() {
        let e = engine_with_flows();
        let rows = e.rows().to_vec();
        let flows: Vec<Vec<&Flow>> = rows.iter().map(|r| e.flows_for(r.pid)).collect();
        let doc = json_document(&rows, Some(&flows), 1.0, "t");
        let lines: Vec<&str> = doc.lines().collect();
        assert_eq!(lines[2], "  \"processes\": [");
        assert_eq!(lines[3], "    {\"conns\": 2, \"flows\": [");
        // TCP flow first (higher rate): both endpoints, the FSM state name.
        assert_eq!(
            lines[4],
            "      {\"local_ip\": \"192.168.1.2\", \"local_port\": 50000, \"proto\": \"tcp\", \
             \"remote_ip\": \"1.1.1.1\", \"remote_port\": 443, \"rx_bytes\": 10000, \"rx_rate\": 5000, \
             \"state\": \"ESTABLISHED\", \"tx_bytes\": 2000, \"tx_rate\": 1000},"
        );
        // Unconnected UDP socket: no remote, no TCP state.
        assert_eq!(
            lines[5],
            "      {\"local_ip\": \"0.0.0.0\", \"local_port\": 5353, \"proto\": \"udp\", \
             \"remote_ip\": null, \"remote_port\": null, \"rx_bytes\": 300, \"rx_rate\": 150, \
             \"state\": null, \"tx_bytes\": 0, \"tx_rate\": 0}"
        );
        assert_eq!(
            lines[6],
            "    ], \"name\": \"curl\", \"pid\": 100, \"rx_bytes\": 10300, \"rx_rate\": 5150, \
             \"tx_bytes\": 2000, \"tx_rate\": 1000}"
        );
        assert_eq!(lines[7], "  ],");
    }

    #[test]
    fn json_document_prints_missing_or_empty_flow_lists_as_empty() {
        // flows[0] is empty, flows[1] is absent: both print as `[]`.
        let doc = json_document(&[row(1, "a"), row(2, "b")], Some(&[vec![]]), 1.0, "t");
        assert!(doc.contains("{\"conns\": 2, \"flows\": [], \"name\": \"a\""));
        assert!(doc.contains("{\"conns\": 2, \"flows\": [], \"name\": \"b\""));
    }
}

//! Output for the one-shot modes (`--once`, `--diag`): column fitting that
//! counts terminal *columns*, not chars, so a CJK process name does not push
//! the rest of its row out of line. Pure string building — it sits under the
//! coverage gate and `main` only prints the result.

use std::fmt::Write;

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::format;
use crate::model::ProcRow;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}

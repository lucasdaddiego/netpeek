//! Pure formatting helpers: human-readable byte rates / totals, TCP state
//! names, and string fitting for table cells. No I/O, fully unit-tested.

/// Format a throughput in bytes/sec as a compact `"1.2 MB/s"` style string.
/// 1024-based units (what `nettop` and most monitors show), padded so columns
/// line up: always 3 significant-ish chars + unit.
pub fn rate(bytes_per_sec: f64) -> String {
    format!("{}/s", bytes(bytes_per_sec.max(0.0) as u64))
}

/// Format a cumulative byte total as `"1.2 MB"` (1024-based).
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    // one decimal below 10, none above — keeps the field narrow
    if v < 10.0 {
        format!("{v:.1} {}", UNITS[u])
    } else {
        format!("{v:.0} {}", UNITS[u])
    }
}

/// `nstat_tcp_descriptor.state` → the BSD TCP FSM name (`netinet/tcp_fsm.h`).
pub fn tcp_state(state: u32) -> &'static str {
    match state {
        0 => "CLOSED",
        1 => "LISTEN",
        2 => "SYN_SENT",
        3 => "SYN_RCVD",
        4 => "ESTABLISHED",
        5 => "CLOSE_WAIT",
        6 => "FIN_WAIT_1",
        7 => "CLOSING",
        8 => "LAST_ACK",
        9 => "FIN_WAIT_2",
        10 => "TIME_WAIT",
        _ => "—",
    }
}

/// Render `samples` as a right-aligned Unicode block sparkline `width` columns
/// wide, scaled to the window's own max. The newest sample sits at the right
/// edge; a short history is left-padded with spaces.
pub fn spark(samples: &[u64], width: usize) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if width == 0 {
        return String::new();
    }
    let start = samples.len().saturating_sub(width);
    let slice = &samples[start..];
    let max = slice.iter().copied().max().unwrap_or(0);
    let mut s = String::with_capacity(width);
    for _ in 0..width.saturating_sub(slice.len()) {
        s.push(' ');
    }
    for &v in slice {
        if max == 0 {
            s.push('▁');
        } else {
            let idx = ((v as f64 / max as f64) * (BARS.len() - 1) as f64).round() as usize;
            s.push(BARS[idx.min(BARS.len() - 1)]);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_units() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1024), "1.0 KB");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(10 * 1024), "10 KB");
        assert_eq!(bytes(1024 * 1024), "1.0 MB");
        assert_eq!(bytes(5 * 1024 * 1024 * 1024), "5.0 GB");
        // huge value saturates at the top unit rather than overflowing
        assert!(bytes(u64::MAX).ends_with(" PB"));
    }

    #[test]
    fn rate_appends_per_second() {
        assert_eq!(rate(0.0), "0 B/s");
        assert_eq!(rate(2048.0), "2.0 KB/s");
        // negative (shouldn't happen) clamps to zero
        assert_eq!(rate(-5.0), "0 B/s");
    }

    #[test]
    fn tcp_states() {
        let names = [
            "CLOSED",
            "LISTEN",
            "SYN_SENT",
            "SYN_RCVD",
            "ESTABLISHED",
            "CLOSE_WAIT",
            "FIN_WAIT_1",
            "CLOSING",
            "LAST_ACK",
            "FIN_WAIT_2",
            "TIME_WAIT",
        ];
        for (state, name) in names.iter().enumerate() {
            assert_eq!(tcp_state(state as u32), *name);
        }
        assert_eq!(tcp_state(999), "—");
    }

    #[test]
    fn sparkline() {
        assert_eq!(spark(&[], 0), "");
        // empty samples, width 4 → all padding spaces
        assert_eq!(spark(&[], 4), "    ");
        // all-zero history → flat low bars (no NaN from /0)
        assert_eq!(spark(&[0, 0, 0], 3), "▁▁▁");
        // increasing series → ascending bars, max at the right
        let s = spark(&[1, 2, 4, 8], 4);
        assert_eq!(s.chars().count(), 4);
        assert_eq!(s.chars().last(), Some('█'));
        // short history is left-padded to the requested width
        let s = spark(&[5], 4);
        assert_eq!(s.chars().count(), 4);
        assert!(s.starts_with(' '));
        // long history keeps only the most recent `width` samples
        let s = spark(&[1, 1, 1, 1, 1, 9], 2);
        assert_eq!(s.chars().count(), 2);
    }
}

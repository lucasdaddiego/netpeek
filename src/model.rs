//! The data model and aggregation engine — pure, no syscalls.
//!
//! The kernel hands us per-*flow* cumulative byte counters keyed by an opaque
//! `srcref`. [`Engine`] turns that stream of messages into the two views the UI
//! wants: a per-process table (rates derived from counter deltas, plus up/down
//! history for sparklines) and, on demand, the flows belonging to a process.

use std::collections::{HashMap, VecDeque};

use crate::ntstat::wire::{Counts, Endpoint, FlowDesc};

/// Transport protocol of a flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
}

/// One kernel flow (one socket / connection).
#[derive(Clone, Debug)]
pub struct Flow {
    pub pid: u32,
    pub pname: String,
    pub proto: Proto,
    pub local: Option<Endpoint>,
    pub remote: Option<Endpoint>,
    pub tcp_state: u32,
    /// Cumulative counters as last reported by the kernel.
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Counter snapshot at the previous tick (for delta → rate).
    prev_rx: u64,
    prev_tx: u64,
    /// Instantaneous throughput in bytes/sec, recomputed each tick.
    pub rx_rate: f64,
    pub tx_rate: f64,
    /// Set once a descriptor has named the flow (pid / addrs known).
    described: bool,
}

impl Flow {
    fn new(proto: Proto) -> Self {
        Flow {
            pid: 0,
            pname: String::new(),
            proto,
            local: None,
            remote: None,
            tcp_state: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            prev_rx: 0,
            prev_tx: 0,
            rx_rate: 0.0,
            tx_rate: 0.0,
            described: false,
        }
    }
}

/// An aggregated per-process row for the main table.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcRow {
    pub pid: u32,
    pub name: String,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub rx_total: u64,
    pub tx_total: u64,
    pub conns: usize,
    /// Recent down/up rates (bytes/sec) for the sparklines, oldest → newest.
    pub rx_hist: Vec<u64>,
    pub tx_hist: Vec<u64>,
}

impl ProcRow {
    /// Combined throughput (down + up), the default sort weight.
    pub fn total_rate(&self) -> f64 {
        self.rx_rate + self.tx_rate
    }
    /// Combined cumulative bytes.
    pub fn total_bytes(&self) -> u64 {
        self.rx_total.saturating_add(self.tx_total)
    }
}

/// Columns the table can be sorted by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {
    Rate,
    Total,
    Name,
    Conns,
    Pid,
}

impl SortKey {
    pub fn label(self) -> &'static str {
        match self {
            SortKey::Rate => "rate",
            SortKey::Total => "total",
            SortKey::Name => "name",
            SortKey::Conns => "conns",
            SortKey::Pid => "pid",
        }
    }
}

struct ProcHist {
    rx: VecDeque<u64>,
    tx: VecDeque<u64>,
}

impl ProcHist {
    fn new() -> Self {
        ProcHist {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }
    fn push(&mut self, rx: u64, tx: u64, cap: usize) {
        self.rx.push_back(rx);
        self.tx.push_back(tx);
        while self.rx.len() > cap {
            self.rx.pop_front();
        }
        while self.tx.len() > cap {
            self.tx.pop_front();
        }
    }
}

/// Folds the message stream into flows and per-process rows.
pub struct Engine {
    flows: HashMap<u64, Flow>,
    hist: HashMap<u32, ProcHist>,
    /// Per-pid (rx, tx) bytes from already-closed flows, so a process's TOTAL
    /// doesn't drop when one of its connections ends. Carried only while the pid
    /// still has a live flow and pruned the moment it has none — that bounds the
    /// map and stops one pid's bytes bleeding into a later, reused pid.
    retired: HashMap<u32, (u64, u64)>,
    rows: Vec<ProcRow>,
    hist_len: usize,
}

impl Engine {
    pub fn new(hist_len: usize) -> Self {
        Engine {
            flows: HashMap::new(),
            hist: HashMap::new(),
            retired: HashMap::new(),
            rows: Vec::new(),
            hist_len: hist_len.max(1),
        }
    }

    fn flow_mut(&mut self, srcref: u64, proto: Proto) -> &mut Flow {
        self.flows.entry(srcref).or_insert_with(|| Flow::new(proto))
    }

    /// A new source appeared; remember its protocol so it's right even if counts
    /// arrive before the descriptor.
    pub fn on_added(&mut self, srcref: u64, proto: Proto) {
        self.flow_mut(srcref, proto).proto = proto;
    }

    /// A descriptor named the flow (pid, process name, endpoints, TCP state).
    pub fn on_desc(&mut self, srcref: u64, proto: Proto, desc: FlowDesc) {
        let f = self.flow_mut(srcref, proto);
        f.proto = proto;
        f.pid = desc.pid;
        f.pname = desc.pname;
        f.local = desc.local;
        f.remote = desc.remote;
        f.tcp_state = desc.tcp_state;
        f.described = true;
    }

    /// Fresh cumulative counters for a flow.
    pub fn on_counts(&mut self, srcref: u64, counts: Counts) {
        // proto unknown here; default is corrected by on_added/on_desc.
        let f = self.flow_mut(srcref, Proto::Tcp);
        f.rx_bytes = counts.rx_bytes;
        f.tx_bytes = counts.tx_bytes;
    }

    /// A bundled update (counts + optional descriptor) — defensive path.
    pub fn on_update(&mut self, srcref: u64, proto: Proto, counts: Counts, desc: Option<FlowDesc>) {
        if let Some(desc) = desc {
            self.on_desc(srcref, proto, desc);
        }
        self.on_counts(srcref, counts);
    }

    /// A source went away. Its final byte counts are carried onto the owning pid
    /// so the process's TOTAL stays monotonic while it still has other flows.
    pub fn on_removed(&mut self, srcref: u64) {
        if let Some(f) = self.flows.remove(&srcref) {
            if f.described && f.pid != 0 {
                let carry = self.retired.entry(f.pid).or_insert((0, 0));
                carry.0 = carry.0.saturating_add(f.rx_bytes);
                carry.1 = carry.1.saturating_add(f.tx_bytes);
            }
        }
    }

    /// Recompute per-flow rates from the counter deltas over `dt` seconds, then
    /// rebuild the aggregated per-process rows and push a sample into each
    /// process's sparkline history. Call once per refresh interval.
    pub fn tick(&mut self, dt: f64) {
        for f in self.flows.values_mut() {
            if dt > 0.0 {
                f.rx_rate = f.rx_bytes.saturating_sub(f.prev_rx) as f64 / dt;
                f.tx_rate = f.tx_bytes.saturating_sub(f.prev_tx) as f64 / dt;
            } else {
                f.rx_rate = 0.0;
                f.tx_rate = 0.0;
            }
            f.prev_rx = f.rx_bytes;
            f.prev_tx = f.tx_bytes;
        }

        // Aggregate described flows by pid.
        struct Agg {
            name: String,
            rx_rate: f64,
            tx_rate: f64,
            rx_total: u64,
            tx_total: u64,
            conns: usize,
        }
        let mut by_pid: HashMap<u32, Agg> = HashMap::new();
        for f in self.flows.values() {
            if !f.described || f.pid == 0 {
                continue;
            }
            let e = by_pid.entry(f.pid).or_insert_with(|| Agg {
                name: String::new(),
                rx_rate: 0.0,
                tx_rate: 0.0,
                rx_total: 0,
                tx_total: 0,
                conns: 0,
            });
            if e.name.is_empty() && !f.pname.is_empty() {
                e.name = f.pname.clone();
            }
            e.rx_rate += f.rx_rate;
            e.tx_rate += f.tx_rate;
            e.rx_total = e.rx_total.saturating_add(f.rx_bytes);
            e.tx_total = e.tx_total.saturating_add(f.tx_bytes);
            e.conns += 1;
        }

        // Fold in bytes from each pid's already-closed flows, then forget the
        // carry for any pid that no longer has a live flow — so it leaves with
        // the row rather than lingering or bleeding into a reused pid.
        for (pid, agg) in by_pid.iter_mut() {
            if let Some(&(rx, tx)) = self.retired.get(pid) {
                agg.rx_total = agg.rx_total.saturating_add(rx);
                agg.tx_total = agg.tx_total.saturating_add(tx);
            }
        }
        self.retired.retain(|pid, _| by_pid.contains_key(pid));

        // Update history, dropping pids that no longer have flows.
        self.hist.retain(|pid, _| by_pid.contains_key(pid));
        for (&pid, a) in &by_pid {
            let h = self.hist.entry(pid).or_insert_with(ProcHist::new);
            h.push(a.rx_rate as u64, a.tx_rate as u64, self.hist_len);
        }

        // Build rows.
        self.rows = by_pid
            .into_iter()
            .map(|(pid, a)| {
                let h = self.hist.get(&pid);
                ProcRow {
                    pid,
                    name: if a.name.is_empty() {
                        format!("pid {pid}")
                    } else {
                        a.name
                    },
                    rx_rate: a.rx_rate,
                    tx_rate: a.tx_rate,
                    rx_total: a.rx_total,
                    tx_total: a.tx_total,
                    conns: a.conns,
                    rx_hist: h
                        .map(|h| h.rx.iter().copied().collect())
                        .unwrap_or_default(),
                    tx_hist: h
                        .map(|h| h.tx.iter().copied().collect())
                        .unwrap_or_default(),
                }
            })
            .collect();
    }

    /// The current per-process rows (unsorted; caller sorts/filters).
    pub fn rows(&self) -> &[ProcRow] {
        &self.rows
    }

    /// All described flows belonging to `pid`, sorted by combined rate desc then
    /// remote port — for the expanded detail view.
    pub fn flows_for(&self, pid: u32) -> Vec<Flow> {
        let mut v: Vec<Flow> = self
            .flows
            .values()
            .filter(|f| f.described && f.pid == pid)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            (b.rx_rate + b.tx_rate)
                .total_cmp(&(a.rx_rate + a.tx_rate))
                .then_with(|| {
                    let ap = a.remote.map(|e| e.port).unwrap_or(0);
                    let bp = b.remote.map(|e| e.port).unwrap_or(0);
                    ap.cmp(&bp)
                })
        });
        v
    }

    /// Total number of tracked flows (for the status line / `--diag`).
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

/// Sort rows in place by `key`. `descending` flips the order; `Name` sorts
/// case-insensitively. Ties always break by pid for a stable, jitter-free table.
pub fn sort_rows(rows: &mut [ProcRow], key: SortKey, descending: bool) {
    rows.sort_by(|a, b| {
        let ord = match key {
            SortKey::Rate => a.total_rate().total_cmp(&b.total_rate()),
            SortKey::Total => a.total_bytes().cmp(&b.total_bytes()),
            SortKey::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            SortKey::Conns => a.conns.cmp(&b.conns),
            SortKey::Pid => a.pid.cmp(&b.pid),
        };
        let ord = if descending { ord.reverse() } else { ord };
        ord.then_with(|| a.pid.cmp(&b.pid))
    });
}

/// Case-insensitive match of a process row against a filter string (matches the
/// name or the pid). An empty filter matches everything.
pub fn matches_filter(row: &ProcRow, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    let f = filter.to_lowercase();
    row.name.to_lowercase().contains(&f) || row.pid.to_string().contains(&f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntstat::wire::Endpoint;
    use std::net::{IpAddr, Ipv4Addr};

    fn ep(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
        Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            port,
        }
    }

    fn desc(pid: u32, name: &str, remote_port: u16) -> FlowDesc {
        FlowDesc {
            pid,
            pname: name.to_string(),
            local: Some(ep(192, 168, 1, 2, 50000)),
            remote: Some(ep(1, 1, 1, 1, remote_port)),
            tcp_state: 4,
        }
    }

    #[test]
    fn rate_is_delta_over_dt() {
        let mut e = Engine::new(8);
        e.on_added(1, Proto::Tcp);
        e.on_desc(1, Proto::Tcp, desc(100, "curl", 443));
        e.on_counts(
            1,
            Counts {
                rx_bytes: 0,
                tx_bytes: 0,
            },
        );
        e.tick(1.0); // establishes baseline at 0
        e.on_counts(
            1,
            Counts {
                rx_bytes: 10_000,
                tx_bytes: 2_000,
            },
        );
        e.tick(2.0); // 10000 over 2s = 5000 B/s down, 1000 B/s up
        let rows = e.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 100);
        assert_eq!(rows[0].rx_rate, 5_000.0);
        assert_eq!(rows[0].tx_rate, 1_000.0);
        assert_eq!(rows[0].rx_total, 10_000);
        assert_eq!(rows[0].conns, 1);
    }

    #[test]
    fn counter_reset_yields_zero_not_negative() {
        let mut e = Engine::new(8);
        e.on_added(1, Proto::Tcp);
        e.on_desc(1, Proto::Tcp, desc(1, "x", 80));
        e.on_counts(
            1,
            Counts {
                rx_bytes: 5_000,
                tx_bytes: 0,
            },
        );
        e.tick(1.0);
        // srcref reused with a smaller cumulative value
        e.on_counts(
            1,
            Counts {
                rx_bytes: 100,
                tx_bytes: 0,
            },
        );
        e.tick(1.0);
        assert_eq!(e.rows()[0].rx_rate, 0.0);
    }

    #[test]
    fn zero_dt_is_safe() {
        let mut e = Engine::new(8);
        e.on_added(1, Proto::Tcp);
        e.on_desc(1, Proto::Tcp, desc(1, "x", 80));
        e.on_counts(
            1,
            Counts {
                rx_bytes: 5_000,
                tx_bytes: 0,
            },
        );
        e.tick(0.0);
        assert_eq!(e.rows()[0].rx_rate, 0.0);
    }

    #[test]
    fn aggregates_multiple_flows_per_pid() {
        let mut e = Engine::new(8);
        e.on_added(1, Proto::Tcp);
        e.on_added(2, Proto::Udp);
        e.on_desc(1, Proto::Tcp, desc(42, "firefox", 443));
        e.on_desc(2, Proto::Udp, desc(42, "firefox", 53));
        e.on_counts(
            1,
            Counts {
                rx_bytes: 0,
                tx_bytes: 0,
            },
        );
        e.on_counts(
            2,
            Counts {
                rx_bytes: 0,
                tx_bytes: 0,
            },
        );
        e.tick(1.0);
        e.on_counts(
            1,
            Counts {
                rx_bytes: 1_000,
                tx_bytes: 0,
            },
        );
        e.on_counts(
            2,
            Counts {
                rx_bytes: 500,
                tx_bytes: 0,
            },
        );
        e.tick(1.0);
        let rows = e.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].conns, 2);
        assert_eq!(rows[0].rx_rate, 1_500.0);
        assert_eq!(e.flows_for(42).len(), 2);
    }

    #[test]
    fn undescribed_flow_is_not_shown_until_named() {
        let mut e = Engine::new(8);
        e.on_added(1, Proto::Tcp);
        e.on_counts(
            1,
            Counts {
                rx_bytes: 1_000,
                tx_bytes: 0,
            },
        );
        e.tick(1.0);
        assert!(e.rows().is_empty()); // no descriptor yet
        e.on_desc(1, Proto::Tcp, desc(7, "ssh", 22));
        e.tick(1.0);
        assert_eq!(e.rows().len(), 1);
    }

    #[test]
    fn removed_flow_disappears_and_history_pruned() {
        let mut e = Engine::new(8);
        e.on_added(1, Proto::Tcp);
        e.on_desc(1, Proto::Tcp, desc(9, "x", 80));
        e.on_counts(
            1,
            Counts {
                rx_bytes: 1,
                tx_bytes: 1,
            },
        );
        e.tick(1.0);
        assert_eq!(e.rows().len(), 1);
        e.on_removed(1);
        e.tick(1.0);
        assert!(e.rows().is_empty());
        assert_eq!(e.flow_count(), 0);
    }

    #[test]
    fn total_includes_closed_flows_while_process_stays_active() {
        let mut e = Engine::new(8);
        e.on_added(1, Proto::Tcp);
        e.on_added(2, Proto::Tcp);
        e.on_desc(1, Proto::Tcp, desc(50, "x", 80));
        e.on_desc(2, Proto::Tcp, desc(50, "x", 443));
        e.on_counts(
            1,
            Counts {
                rx_bytes: 1_000,
                tx_bytes: 100,
            },
        );
        e.on_counts(
            2,
            Counts {
                rx_bytes: 2_000,
                tx_bytes: 200,
            },
        );
        e.tick(1.0);
        assert_eq!(e.rows()[0].rx_total, 3_000);
        assert_eq!(e.rows()[0].tx_total, 300);
        // flow 1 closes but flow 2 is still live → TOTAL must not drop
        e.on_removed(1);
        e.tick(1.0);
        let r = &e.rows()[0];
        assert_eq!(r.conns, 1); // only the live flow is counted as a connection
        assert_eq!(r.rx_total, 3_000); // 2_000 live + 1_000 carried from the closed flow
        assert_eq!(r.tx_total, 300);
    }

    #[test]
    fn retired_carry_is_dropped_once_a_pid_has_no_flows() {
        let mut e = Engine::new(8);
        e.on_added(1, Proto::Tcp);
        e.on_desc(1, Proto::Tcp, desc(50, "x", 80));
        e.on_counts(
            1,
            Counts {
                rx_bytes: 5_000,
                tx_bytes: 0,
            },
        );
        e.tick(1.0);
        e.on_removed(1);
        e.tick(1.0);
        assert!(e.rows().is_empty()); // no live flows → process leaves the table
                                      // a fresh flow for the same pid starts from zero, not 5_000 (no stale carry)
        e.on_added(2, Proto::Tcp);
        e.on_desc(2, Proto::Tcp, desc(50, "x", 443));
        e.on_counts(
            2,
            Counts {
                rx_bytes: 10,
                tx_bytes: 0,
            },
        );
        e.tick(1.0);
        assert_eq!(e.rows()[0].rx_total, 10);
    }

    #[test]
    fn history_capped_at_hist_len() {
        let mut e = Engine::new(3);
        e.on_added(1, Proto::Tcp);
        e.on_desc(1, Proto::Tcp, desc(1, "x", 80));
        for i in 1..=10u64 {
            e.on_counts(
                1,
                Counts {
                    rx_bytes: i * 1000,
                    tx_bytes: 0,
                },
            );
            e.tick(1.0);
        }
        assert!(e.rows()[0].rx_hist.len() <= 3);
    }

    #[test]
    fn on_update_path_sets_desc_and_counts() {
        let mut e = Engine::new(8);
        e.on_update(
            5,
            Proto::Udp,
            Counts {
                rx_bytes: 0,
                tx_bytes: 0,
            },
            Some(desc(11, "mdns", 5353)),
        );
        e.tick(1.0);
        e.on_update(
            5,
            Proto::Udp,
            Counts {
                rx_bytes: 800,
                tx_bytes: 0,
            },
            None,
        );
        e.tick(1.0);
        assert_eq!(e.rows()[0].rx_rate, 800.0);
        assert_eq!(e.rows()[0].name, "mdns");
    }

    fn row(pid: u32, name: &str, rate: f64, total: u64, conns: usize) -> ProcRow {
        ProcRow {
            pid,
            name: name.to_string(),
            rx_rate: rate,
            tx_rate: 0.0,
            rx_total: total,
            tx_total: 0,
            conns,
            rx_hist: vec![],
            tx_hist: vec![],
        }
    }

    #[test]
    fn sorting_by_each_key() {
        let mut rows = vec![
            row(3, "Zsh", 100.0, 50, 1),
            row(1, "apple", 300.0, 10, 5),
            row(2, "Brave", 200.0, 99, 2),
        ];
        sort_rows(&mut rows, SortKey::Rate, true);
        assert_eq!(
            rows.iter().map(|r| r.pid).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        sort_rows(&mut rows, SortKey::Total, false);
        assert_eq!(
            rows.iter().map(|r| r.pid).collect::<Vec<_>>(),
            vec![1, 3, 2]
        );

        sort_rows(&mut rows, SortKey::Name, false);
        // case-insensitive: apple, Brave, Zsh
        assert_eq!(
            rows.iter().map(|r| r.pid).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        sort_rows(&mut rows, SortKey::Conns, true);
        assert_eq!(
            rows.iter().map(|r| r.pid).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        sort_rows(&mut rows, SortKey::Pid, false);
        assert_eq!(
            rows.iter().map(|r| r.pid).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn tie_breaks_by_pid() {
        let mut rows = vec![row(9, "a", 0.0, 0, 0), row(2, "b", 0.0, 0, 0)];
        sort_rows(&mut rows, SortKey::Rate, true);
        assert_eq!(rows[0].pid, 2);
    }

    #[test]
    fn filtering_by_name_and_pid() {
        let r = row(1234, "Firefox", 0.0, 0, 0);
        assert!(matches_filter(&r, ""));
        assert!(matches_filter(&r, "fire"));
        assert!(matches_filter(&r, "FOX"));
        assert!(matches_filter(&r, "123"));
        assert!(!matches_filter(&r, "chrome"));
    }

    #[test]
    fn proto_and_sortkey_labels() {
        assert_eq!(Proto::Tcp.as_str(), "TCP");
        assert_eq!(Proto::Udp.as_str(), "UDP");
        for (k, l) in [
            (SortKey::Rate, "rate"),
            (SortKey::Total, "total"),
            (SortKey::Name, "name"),
            (SortKey::Conns, "conns"),
            (SortKey::Pid, "pid"),
        ] {
            assert_eq!(k.label(), l);
        }
        let r = row(1, "x", 1.0, 2, 1);
        assert_eq!(r.total_rate(), 1.0);
        assert_eq!(r.total_bytes(), 2);
    }

    #[test]
    fn unnamed_process_falls_back_to_pid_label() {
        let mut e = Engine::new(8);
        e.on_added(1, Proto::Tcp);
        // described, valid pid, but the kernel gave no process name
        e.on_desc(
            1,
            Proto::Tcp,
            FlowDesc {
                pid: 4242,
                pname: String::new(),
                local: None,
                remote: Some(ep(1, 1, 1, 1, 80)),
                tcp_state: 4,
            },
        );
        e.on_counts(
            1,
            Counts {
                rx_bytes: 1,
                tx_bytes: 1,
            },
        );
        e.tick(1.0);
        assert_eq!(e.rows()[0].name, "pid 4242");
    }

    #[test]
    fn flows_for_breaks_rate_ties_by_remote_port() {
        let mut e = Engine::new(8);
        // two flows, same pid, identical (zero) rate, different remote ports
        e.on_added(1, Proto::Tcp);
        e.on_added(2, Proto::Tcp);
        e.on_desc(1, Proto::Tcp, desc(50, "x", 8443));
        e.on_desc(2, Proto::Tcp, desc(50, "x", 443));
        e.tick(1.0);
        let flows = e.flows_for(50);
        assert_eq!(flows.len(), 2);
        // equal rate → lower remote port first
        assert_eq!(flows[0].remote.unwrap().port, 443);
        assert_eq!(flows[1].remote.unwrap().port, 8443);
    }
}

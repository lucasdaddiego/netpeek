//! The ntstat client: owns the control socket and the [`Engine`], subscribes to
//! the TCP/UDP providers, and drains the kernel's message stream into per-process
//! state.
//!
//! Protocol, per the brief and Apple's headers:
//! 1. [`sys::ControlSocket::open`] does `socket`/`ioctl(CTLIOCGINFO)`/`connect`.
//! 2. We send `ADD_ALL_SRCS` for each TCP/UDP provider to subscribe.
//! 3. The kernel streams `SRC_ADDED`; for each we send `GET_SRC_DESC` and get a
//!    `SRC_DESC` (pid, process name, local/remote addr+port, TCP state).
//! 4. Each interval we send one `QUERY_SRC` for `NSTAT_SRC_REF_ALL` and read the
//!    `SRC_COUNTS` (cumulative rx/tx bytes) the kernel returns.
//! 5. `SRC_REMOVED` retires a flow.

pub mod sys;
pub mod wire;

use std::collections::{HashSet, VecDeque};
use std::io;

use crate::model::{Engine, Proto};
use sys::ControlSocket;
use wire::{
    is_tcp_provider, is_udp_provider, parse_datagram, Msg, NstatMsgAddAllSrcs, NstatMsgSrcRefReq,
    NSTAT_MSG_TYPE_GET_SRC_DESC, NSTAT_MSG_TYPE_QUERY_SRC, NSTAT_SRC_REF_ALL, SUBSCRIBED_PROVIDERS,
};

/// Descriptor requests sent per drain. Subscribing yields a burst of 100+
/// SRC_ADDED; firing a GET_SRC_DESC for every one at once overruns the kernel
/// control's reply queue (ENOBUFS) and starves the count poll, so we pace them.
const DESC_BATCH: usize = 16;

/// `ENOBUFS` — transient backpressure when a poll burst outruns the socket
/// buffer. We recover on the next poll, so it isn't surfaced as a real error.
const ENOBUFS: u32 = 55;

fn proto_of(provider: u32) -> Option<Proto> {
    if is_tcp_provider(provider) {
        Some(Proto::Tcp)
    } else if is_udp_provider(provider) {
        Some(Proto::Udp)
    } else {
        None
    }
}

/// A live network-statistics monitor.
pub struct Monitor {
    sock: ControlSocket,
    engine: Engine,
    buf: Vec<u8>,
    /// srcrefs we've already asked the kernel to describe (once each).
    requested: HashSet<u64>,
    /// srcrefs awaiting a (paced) descriptor request.
    pending_desc: VecDeque<u64>,
    last_error: Option<u32>,
}

impl Monitor {
    /// Open the control socket and subscribe to TCP + UDP sources.
    pub fn new(hist_len: usize) -> io::Result<Self> {
        let sock = ControlSocket::open()?;
        let mut m = Monitor {
            sock,
            engine: Engine::new(hist_len),
            // Generous datagram buffer: aggregate responses can be many KB.
            buf: vec![0u8; 1 << 16],
            requested: HashSet::new(),
            pending_desc: VecDeque::new(),
            last_error: None,
        };
        m.subscribe()?;
        Ok(m)
    }

    fn subscribe(&mut self) -> io::Result<()> {
        for (i, &provider) in SUBSCRIBED_PROVIDERS.iter().enumerate() {
            let req = NstatMsgAddAllSrcs::new(0x1000 + i as u64, provider);
            self.sock.send_bytes(bytemuck::bytes_of(&req))?;
        }
        Ok(())
    }

    fn request_desc(&self, srcref: u64) -> io::Result<()> {
        let req = NstatMsgSrcRefReq::new(srcref, NSTAT_MSG_TYPE_GET_SRC_DESC, srcref);
        self.sock.send_bytes(bytemuck::bytes_of(&req))
    }

    /// Ask the kernel for fresh counters on every source at once.
    pub fn poll_counts(&self) -> io::Result<()> {
        let req = NstatMsgSrcRefReq::new(0xC0, NSTAT_MSG_TYPE_QUERY_SRC, NSTAT_SRC_REF_ALL);
        self.sock.send_bytes(bytemuck::bytes_of(&req))
    }

    /// Read and apply every datagram currently pending (non-blocking), then
    /// send the next paced batch of descriptor requests.
    pub fn drain(&mut self) -> io::Result<()> {
        loop {
            match self.sock.recv_into(&mut self.buf)? {
                None => break,
                Some(n) => {
                    for msg in parse_datagram(&self.buf[..n]) {
                        self.apply(msg);
                    }
                }
            }
        }
        self.pump_desc_requests()?;
        Ok(())
    }

    /// Fire up to [`DESC_BATCH`] queued descriptor requests.
    fn pump_desc_requests(&mut self) -> io::Result<()> {
        for _ in 0..DESC_BATCH {
            match self.pending_desc.pop_front() {
                Some(srcref) => self.request_desc(srcref)?,
                None => break,
            }
        }
        Ok(())
    }

    fn apply(&mut self, msg: Msg) {
        match msg {
            Msg::SrcAdded { srcref, provider } => {
                if let Some(proto) = proto_of(provider) {
                    self.engine.on_added(srcref, proto);
                }
                if self.requested.insert(srcref) {
                    self.pending_desc.push_back(srcref);
                }
            }
            Msg::SrcDesc {
                srcref,
                provider,
                mut desc,
            } => {
                if let Some(proto) = proto_of(provider) {
                    if desc.pname.is_empty() {
                        if let Some(name) = sys::proc_name(desc.pid) {
                            desc.pname = name;
                        }
                    }
                    self.engine.on_desc(srcref, proto, desc);
                }
            }
            Msg::SrcCounts { srcref, counts } => self.engine.on_counts(srcref, counts),
            Msg::SrcUpdate {
                srcref,
                provider,
                counts,
                desc,
            } => {
                let proto = proto_of(provider).unwrap_or(Proto::Tcp);
                self.engine.on_update(srcref, proto, counts, desc);
            }
            Msg::SrcRemoved { srcref } => {
                self.engine.on_removed(srcref);
                self.requested.remove(&srcref);
            }
            Msg::Error { code } if code == ENOBUFS => {} // transient, recovered next poll
            Msg::Error { code } => self.last_error = Some(code),
            Msg::Success | Msg::Other { .. } => {}
        }
    }

    /// Recompute rates and aggregates over `dt` seconds.
    pub fn tick(&mut self, dt: f64) {
        self.engine.tick(dt);
    }

    /// Re-baseline every flow's rate reference on the next `tick`. Pair with a
    /// fresh [`Monitor::poll_counts`] when resuming from a pause so the gap isn't
    /// rendered as a one-tick rate spike.
    pub fn reprime(&mut self) {
        self.engine.reprime();
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// The last kernel-reported error code, if any (surfaced in `--diag`).
    pub fn last_error(&self) -> Option<u32> {
        self.last_error
    }
}

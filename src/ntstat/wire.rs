//! The `com.apple.network.statistics` ("ntstat") kernel-control wire protocol.
//!
//! This is the *exact* private interface `nettop(1)` speaks. It is undocumented
//! and the binary struct layouts have shifted across macOS releases, so this
//! module is deliberately split from the syscalls (`sys.rs`) and the socket loop
//! (`mod.rs`): everything here is **pure** — constants, `#[repr(C)]` request
//! structs, and bounds-checked parsers over `&[u8]` — so it is unit-tested with
//! synthetic buffers and carries the project's coverage gate.
//!
//! Layouts are transcribed from Apple's open-source XNU `bsd/net/ntstat.h`
//! (`__NSTAT_REVISION__ 9`) and `bsd/netinet/in_stat.h`, cross-checked between the
//! macOS 14 (`xnu-10063`) and current `main` headers — the providers, message
//! types and the leading TCP/UDP descriptor fields are identical across both.
//! Where a field's offset depends on a struct that grew over time, the parsers
//! **validate before they trust**: a flow is only surfaced if it decodes to a
//! plausible pid and a known address family. On a layout we don't recognise the
//! flow is skipped, never shown wrong — see [`parse_tcp_desc`]/[`parse_udp_desc`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytemuck::{Pod, Zeroable};

// ---- kernel control name (passed in `ctl_info.ctl_name`) -------------------

/// The control name resolved via `ioctl(CTLIOCGINFO)`.
pub const CONTROL_NAME: &[u8] = b"com.apple.network.statistics";

// ---- provider ids (nstat_provider_id_t) ------------------------------------
// XNU split the old TCP=2/UDP=3 providers into kernel + userland variants long
// ago; these values match macOS 13 through 26.

pub const NSTAT_PROVIDER_TCP_KERNEL: u32 = 2;
pub const NSTAT_PROVIDER_TCP_USERLAND: u32 = 3;
pub const NSTAT_PROVIDER_UDP_KERNEL: u32 = 4;
pub const NSTAT_PROVIDER_UDP_USERLAND: u32 = 5;

/// Providers we subscribe to: TCP and UDP, both the in-kernel BSD-socket flows
/// and the userland (Network.framework / NECP) flows.
pub const SUBSCRIBED_PROVIDERS: [u32; 4] = [
    NSTAT_PROVIDER_TCP_KERNEL,
    NSTAT_PROVIDER_TCP_USERLAND,
    NSTAT_PROVIDER_UDP_KERNEL,
    NSTAT_PROVIDER_UDP_USERLAND,
];

/// True for the two TCP providers (controls which descriptor parser to use).
pub fn is_tcp_provider(p: u32) -> bool {
    p == NSTAT_PROVIDER_TCP_KERNEL || p == NSTAT_PROVIDER_TCP_USERLAND
}

/// True for the two UDP providers.
pub fn is_udp_provider(p: u32) -> bool {
    p == NSTAT_PROVIDER_UDP_KERNEL || p == NSTAT_PROVIDER_UDP_USERLAND
}

// ---- message types (nstat_msg_hdr.type) ------------------------------------

pub const NSTAT_MSG_TYPE_SUCCESS: u32 = 0;
pub const NSTAT_MSG_TYPE_ERROR: u32 = 1;
pub const NSTAT_MSG_TYPE_ADD_ALL_SRCS: u32 = 1002;
pub const NSTAT_MSG_TYPE_QUERY_SRC: u32 = 1004;
pub const NSTAT_MSG_TYPE_GET_SRC_DESC: u32 = 1005;

pub const NSTAT_MSG_TYPE_SRC_ADDED: u32 = 10001;
pub const NSTAT_MSG_TYPE_SRC_REMOVED: u32 = 10002;
pub const NSTAT_MSG_TYPE_SRC_DESC: u32 = 10003;
pub const NSTAT_MSG_TYPE_SRC_COUNTS: u32 = 10004;
pub const NSTAT_MSG_TYPE_SRC_UPDATE: u32 = 10006;

// ---- well-known values -----------------------------------------------------

/// Poll/describe every source the kernel will show us in one request.
pub const NSTAT_SRC_REF_ALL: u64 = u64::MAX;

/// `NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE` — we cope with several sub-messages
/// packed into a single datagram (now mandatory; we set it to be explicit).
pub const NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE: u16 = 1 << 0;

/// `NSTAT_FILTER_FLAGS_V1_USAGE`: accept every interface class (loopback, wifi,
/// wired, cellular, …). Without these accept bits a non-trivial filter would
/// drop flows by interface type; this is the documented v1-client filter.
pub const NSTAT_FILTER_FLAGS_V1_USAGE: u64 = 0x1   // ACCEPT_UNKNOWN
    | 0x2     // ACCEPT_LOOPBACK
    | 0x4     // ACCEPT_CELLULAR
    | 0x8     // ACCEPT_WIFI
    | 0x10    // ACCEPT_WIRED
    | 0x20    // ACCEPT_AWDL
    | 0x40    // ACCEPT_EXPENSIVE
    | 0x100   // ACCEPT_CELLFALLBACK
    | 0x200   // ACCEPT_COMPANIONLINK
    | 0x400   // ACCEPT_IS_CONSTRAINED
    | 0x800   // ACCEPT_IS_LOCAL
    | 0x1000; // ACCEPT_IS_NON_LOCAL

// Darwin address families.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;

// ---- request structs (we build and send these) -----------------------------

/// `nstat_msg_hdr` — 16 bytes, prefixes every message in both directions.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct NstatMsgHdr {
    /// Echoed back on replies; we use it as a request id / type tag.
    pub context: u64,
    pub msg_type: u32,
    pub length: u16,
    pub flags: u16,
}

/// `nstat_msg_add_all_srcs` — subscribe to every source of one provider.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct NstatMsgAddAllSrcs {
    pub hdr: NstatMsgHdr,
    pub filter: u64,
    pub events: u64,
    pub provider: u32,
    pub target_pid: i32,
    pub target_uuid: [u8; 16],
}

/// `nstat_msg_query_src` / `nstat_msg_get_src_description` — both are just the
/// header plus a `srcref` (use `NSTAT_SRC_REF_ALL` to mean "all").
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct NstatMsgSrcRefReq {
    pub hdr: NstatMsgHdr,
    pub srcref: u64,
}

impl NstatMsgAddAllSrcs {
    /// Build a subscribe-to-all request for one provider.
    pub fn new(context: u64, provider: u32) -> Self {
        Self {
            hdr: NstatMsgHdr {
                context,
                msg_type: NSTAT_MSG_TYPE_ADD_ALL_SRCS,
                length: std::mem::size_of::<Self>() as u16,
                flags: NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE,
            },
            filter: NSTAT_FILTER_FLAGS_V1_USAGE,
            events: 0,
            provider,
            target_pid: -1,
            target_uuid: [0; 16],
        }
    }
}

impl NstatMsgSrcRefReq {
    /// Build a `QUERY_SRC` or `GET_SRC_DESC` for a srcref (or `NSTAT_SRC_REF_ALL`).
    pub fn new(context: u64, msg_type: u32, srcref: u64) -> Self {
        Self {
            hdr: NstatMsgHdr {
                context,
                msg_type,
                length: std::mem::size_of::<Self>() as u16,
                flags: NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE,
            },
            srcref,
        }
    }
}

// ---- reply field offsets ----------------------------------------------------
// Offsets into a single message (from the start of its nstat_msg_hdr).

/// `nstat_msg_src_added`: srcref @16, provider @24.
const SRC_ADDED_SRCREF: usize = 16;
const SRC_ADDED_PROVIDER: usize = 24;

/// `nstat_msg_src_counts`: hdr(16) srcref(8) event_flags(8) then `nstat_counts`.
const SRC_COUNTS_SRCREF: usize = 16;
const SRC_COUNTS_COUNTS: usize = 32;

/// `nstat_msg_src_description`: hdr(16) srcref(8) event_flags(8) provider(4)
/// reserved(4) then the descriptor payload at offset 40.
const SRC_DESC_SRCREF: usize = 16;
const SRC_DESC_PROVIDER: usize = 32;
const SRC_DESC_DATA: usize = 40;

/// `nstat_msg_src_update`: hdr(16) srcref(8) event_flags(8) counts(112)
/// provider(4) reserved(4) then the descriptor payload at offset 152. The
/// update bundles counts *and* descriptor — we harvest both if it ever arrives.
const SRC_UPDATE_SRCREF: usize = 16;
const SRC_UPDATE_COUNTS: usize = 32;
const SRC_UPDATE_PROVIDER: usize = 144;
const SRC_UPDATE_DATA: usize = 152;

/// Within `nstat_counts`: rxbytes @8, txbytes @24 (each u64).
const COUNTS_RXBYTES: usize = 8;
const COUNTS_TXBYTES: usize = 24;

// `nstat_tcp_descriptor` field offsets (rev 9). Leading layout:
//   upid,eupid,start_ts,timestamp (4×u64) rx_xfer,tx_xfer (2×u64)
//   activity_bitmap (24) ifindex,state, sndbuf*, rcvbuf*, tx*, traffic*,
//   pid,epid, local(28), remote(28), cc_algo[16], pname[64], ...
const TCP_STATE: usize = 76;
const TCP_PID: usize = 116;
const TCP_LOCAL: usize = 124;
const TCP_REMOTE: usize = 152;
const TCP_PNAME: usize = 196;
/// Smallest TCP descriptor we will parse (through the end of pname).
const TCP_MIN_LEN: usize = TCP_PNAME + PNAME_LEN;

// `nstat_udp_descriptor` field offsets (rev 9):
//   upid,eupid,start_ts,timestamp (4×u64) activity_bitmap(24)
//   local(28) remote(28) ifindex, rcvbuf*, traffic_class, pid, pname[64], ...
const UDP_LOCAL: usize = 56;
const UDP_REMOTE: usize = 84;
const UDP_PID: usize = 128;
const UDP_PNAME: usize = 132;
const UDP_MIN_LEN: usize = UDP_PNAME + PNAME_LEN;

const PNAME_LEN: usize = 64;
/// `sockaddr_in6` (the larger arm of the local/remote union) is 28 bytes.
const SOCKADDR_LEN: usize = 28;

// ---- little-endian readers (Apple ARM/Intel are both LE) --------------------

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

// ---- parsed results ---------------------------------------------------------

/// A network endpoint decoded from a `sockaddr_in`/`sockaddr_in6` union.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

/// A flow's identity, parsed from a TCP/UDP descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowDesc {
    pub pid: u32,
    pub pname: String,
    pub local: Option<Endpoint>,
    pub remote: Option<Endpoint>,
    /// TCP connection state (`nstat_tcp_descriptor.state`); 0 for UDP.
    pub tcp_state: u32,
}

/// Counters lifted from an `nstat_counts` (cumulative rx/tx byte totals).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// One decoded message from the control socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    SrcAdded {
        srcref: u64,
        provider: u32,
    },
    SrcRemoved {
        srcref: u64,
    },
    SrcDesc {
        srcref: u64,
        provider: u32,
        desc: FlowDesc,
    },
    SrcCounts {
        srcref: u64,
        counts: Counts,
    },
    /// A bundled update (counts + descriptor) — harvested defensively.
    SrcUpdate {
        srcref: u64,
        provider: u32,
        counts: Counts,
        desc: Option<FlowDesc>,
    },
    Success,
    Error {
        code: u32,
    },
    /// A recognised header whose body we don't model (route/ifnet/sysinfo/…).
    Other {
        msg_type: u32,
    },
}

/// Decode a `sockaddr` union (`sockaddr_in`/`sockaddr_in6`) at `off`.
///
/// Returns `None` for an unspecified family (`0.0.0.0:0` unconnected UDP, etc.).
pub fn parse_sockaddr(buf: &[u8], off: usize) -> Option<Endpoint> {
    let sa = buf.get(off..off + SOCKADDR_LEN)?;
    // sa_len @0, sa_family @1, port @2 (network/BE), addr @4 (v4) or @8 (v6).
    let family = sa[1];
    let port = u16::from_be_bytes([sa[2], sa[3]]);
    match family {
        AF_INET => {
            let o = [sa[4], sa[5], sa[6], sa[7]];
            let ip = IpAddr::V4(Ipv4Addr::from(o));
            if ip.is_unspecified() && port == 0 {
                None
            } else {
                Some(Endpoint { ip, port })
            }
        }
        AF_INET6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&sa[8..24]);
            let ip = IpAddr::V6(Ipv6Addr::from(o));
            if ip.is_unspecified() && port == 0 {
                None
            } else {
                Some(Endpoint { ip, port })
            }
        }
        _ => None,
    }
}

/// Decode a NUL-terminated, fixed-width process name field, stripping control
/// bytes so a hostile name can't smuggle terminal escapes into the UI.
fn parse_pname(buf: &[u8], off: usize) -> String {
    let raw = match buf.get(off..off + PNAME_LEN) {
        Some(b) => b,
        None => buf.get(off..).unwrap_or(&[]),
    };
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end])
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// True if a decoded descriptor looks real: a plausible pid and at least one
/// endpoint with a known address family. Guards against a shifted layout
/// (different macOS) feeding us garbage offsets — better to drop a flow than
/// show wrong data.
fn looks_valid(desc: &FlowDesc) -> bool {
    desc.pid > 0 && desc.pid < 0x0040_0000 && (desc.local.is_some() || desc.remote.is_some())
}

/// Parse an `nstat_tcp_descriptor`. `data` is the descriptor payload only
/// (i.e. starting at [`SRC_DESC_DATA`]). Returns `None` if too short to trust
/// or if it fails validation.
pub fn parse_tcp_desc(data: &[u8]) -> Option<FlowDesc> {
    if data.len() < TCP_MIN_LEN {
        return None;
    }
    let desc = FlowDesc {
        pid: read_u32(data, TCP_PID)?,
        pname: parse_pname(data, TCP_PNAME),
        local: parse_sockaddr(data, TCP_LOCAL),
        remote: parse_sockaddr(data, TCP_REMOTE),
        tcp_state: read_u32(data, TCP_STATE)?,
    };
    looks_valid(&desc).then_some(desc)
}

/// Parse an `nstat_udp_descriptor` (payload starting at [`SRC_DESC_DATA`]).
pub fn parse_udp_desc(data: &[u8]) -> Option<FlowDesc> {
    if data.len() < UDP_MIN_LEN {
        return None;
    }
    let desc = FlowDesc {
        pid: read_u32(data, UDP_PID)?,
        pname: parse_pname(data, UDP_PNAME),
        local: parse_sockaddr(data, UDP_LOCAL),
        remote: parse_sockaddr(data, UDP_REMOTE),
        tcp_state: 0,
    };
    looks_valid(&desc).then_some(desc)
}

/// Pick the descriptor parser for a provider id.
fn parse_desc(provider: u32, data: &[u8]) -> Option<FlowDesc> {
    if is_tcp_provider(provider) {
        parse_tcp_desc(data)
    } else if is_udp_provider(provider) {
        parse_udp_desc(data)
    } else {
        None
    }
}

fn parse_counts(buf: &[u8], base: usize) -> Option<Counts> {
    Some(Counts {
        rx_bytes: read_u64(buf, base + COUNTS_RXBYTES)?,
        tx_bytes: read_u64(buf, base + COUNTS_TXBYTES)?,
    })
}

/// Decode a single message given its `nstat_msg_hdr.type` and the full message
/// bytes (header included). Unknown / unmodelled types map to [`Msg::Other`].
pub fn parse_message(msg_type: u32, msg: &[u8]) -> Option<Msg> {
    match msg_type {
        NSTAT_MSG_TYPE_SUCCESS => Some(Msg::Success),
        NSTAT_MSG_TYPE_ERROR => Some(Msg::Error {
            code: read_u32(msg, 16).unwrap_or(0),
        }),
        NSTAT_MSG_TYPE_SRC_ADDED => Some(Msg::SrcAdded {
            srcref: read_u64(msg, SRC_ADDED_SRCREF)?,
            provider: read_u32(msg, SRC_ADDED_PROVIDER)?,
        }),
        NSTAT_MSG_TYPE_SRC_REMOVED => Some(Msg::SrcRemoved {
            srcref: read_u64(msg, SRC_ADDED_SRCREF)?,
        }),
        NSTAT_MSG_TYPE_SRC_COUNTS => Some(Msg::SrcCounts {
            srcref: read_u64(msg, SRC_COUNTS_SRCREF)?,
            counts: parse_counts(msg, SRC_COUNTS_COUNTS)?,
        }),
        NSTAT_MSG_TYPE_SRC_DESC => {
            let srcref = read_u64(msg, SRC_DESC_SRCREF)?;
            let provider = read_u32(msg, SRC_DESC_PROVIDER)?;
            let data = msg.get(SRC_DESC_DATA..)?;
            let desc = parse_desc(provider, data)?;
            Some(Msg::SrcDesc {
                srcref,
                provider,
                desc,
            })
        }
        NSTAT_MSG_TYPE_SRC_UPDATE => {
            let srcref = read_u64(msg, SRC_UPDATE_SRCREF)?;
            let counts = parse_counts(msg, SRC_UPDATE_COUNTS)?;
            let provider = read_u32(msg, SRC_UPDATE_PROVIDER)?;
            let desc = msg
                .get(SRC_UPDATE_DATA..)
                .and_then(|d| parse_desc(provider, d));
            Some(Msg::SrcUpdate {
                srcref,
                provider,
                counts,
                desc,
            })
        }
        _ => Some(Msg::Other { msg_type }),
    }
}

/// Walk a datagram that may pack several `nstat_msg_hdr`-prefixed messages
/// back-to-back (the kernel "aggregates"), decoding each in turn. A truncated
/// or zero-length trailing message stops the walk cleanly.
pub fn parse_datagram(buf: &[u8]) -> Vec<Msg> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + std::mem::size_of::<NstatMsgHdr>() <= buf.len() {
        // pod_read_unaligned copies the 16 header bytes into an aligned struct,
        // so the walk doesn't depend on `off` happening to be 8-aligned.
        let hdr: NstatMsgHdr = bytemuck::pod_read_unaligned(&buf[off..off + 16]);
        let len = hdr.length as usize;
        if len < std::mem::size_of::<NstatMsgHdr>() || off + len > buf.len() {
            break;
        }
        if let Some(m) = parse_message(hdr.msg_type, &buf[off..off + len]) {
            out.push(m);
        }
        off += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sizes must match the C structs exactly or the kernel rejects our requests.
    #[test]
    fn request_struct_sizes() {
        assert_eq!(std::mem::size_of::<NstatMsgHdr>(), 16);
        assert_eq!(std::mem::size_of::<NstatMsgAddAllSrcs>(), 56);
        assert_eq!(std::mem::size_of::<NstatMsgSrcRefReq>(), 24);
    }

    #[test]
    fn add_all_srcs_request_is_well_formed() {
        let m = NstatMsgAddAllSrcs::new(7, NSTAT_PROVIDER_TCP_KERNEL);
        assert_eq!(m.hdr.msg_type, NSTAT_MSG_TYPE_ADD_ALL_SRCS);
        assert_eq!(m.hdr.length, 56);
        assert_eq!(m.hdr.context, 7);
        assert_eq!(m.provider, NSTAT_PROVIDER_TCP_KERNEL);
        assert_eq!(m.target_pid, -1);
        assert_ne!(m.filter & NSTAT_FILTER_FLAGS_V1_USAGE, 0);
        // round-trips through bytes
        let bytes = bytemuck::bytes_of(&m);
        assert_eq!(bytes.len(), 56);
    }

    #[test]
    fn srcref_req_request_is_well_formed() {
        let q = NstatMsgSrcRefReq::new(1, NSTAT_MSG_TYPE_QUERY_SRC, NSTAT_SRC_REF_ALL);
        assert_eq!(q.hdr.msg_type, NSTAT_MSG_TYPE_QUERY_SRC);
        assert_eq!(q.hdr.length, 24);
        assert_eq!(q.srcref, u64::MAX);
    }

    #[test]
    fn provider_classification() {
        assert!(is_tcp_provider(NSTAT_PROVIDER_TCP_KERNEL));
        assert!(is_tcp_provider(NSTAT_PROVIDER_TCP_USERLAND));
        assert!(!is_tcp_provider(NSTAT_PROVIDER_UDP_KERNEL));
        assert!(is_udp_provider(NSTAT_PROVIDER_UDP_KERNEL));
        assert!(is_udp_provider(NSTAT_PROVIDER_UDP_USERLAND));
        assert!(!is_udp_provider(NSTAT_PROVIDER_TCP_KERNEL));
    }

    fn v4_sockaddr(ip: [u8; 4], port: u16) -> [u8; SOCKADDR_LEN] {
        let mut b = [0u8; SOCKADDR_LEN];
        b[0] = 16; // sin_len
        b[1] = AF_INET;
        b[2..4].copy_from_slice(&port.to_be_bytes());
        b[4..8].copy_from_slice(&ip);
        b
    }

    fn v6_sockaddr(ip: [u8; 16], port: u16) -> [u8; SOCKADDR_LEN] {
        let mut b = [0u8; SOCKADDR_LEN];
        b[0] = 28;
        b[1] = AF_INET6;
        b[2..4].copy_from_slice(&port.to_be_bytes());
        b[8..24].copy_from_slice(&ip);
        b
    }

    #[test]
    fn sockaddr_v4_v6_and_unspecified() {
        let v4 = v4_sockaddr([93, 184, 216, 34], 443);
        let ep = parse_sockaddr(&v4, 0).unwrap();
        assert_eq!(ep.ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(ep.port, 443);

        let mut ip6 = [0u8; 16];
        ip6[0] = 0x20;
        ip6[1] = 0x01;
        ip6[15] = 0x01;
        let v6 = v6_sockaddr(ip6, 53);
        let ep = parse_sockaddr(&v6, 0).unwrap();
        assert_eq!(ep.port, 53);
        assert!(matches!(ep.ip, IpAddr::V6(_)));

        // unspecified 0.0.0.0:0 → None
        assert!(parse_sockaddr(&v4_sockaddr([0, 0, 0, 0], 0), 0).is_none());
        // unspecified [::]:0 → None
        assert!(parse_sockaddr(&v6_sockaddr([0u8; 16], 0), 0).is_none());
        // unknown family → None
        let mut bad = v4;
        bad[1] = 99;
        assert!(parse_sockaddr(&bad, 0).is_none());
        // too short → None
        assert!(parse_sockaddr(&[0u8; 4], 0).is_none());
    }

    #[test]
    fn parse_pname_handles_short_buffer() {
        // a buffer shorter than PNAME_LEN starting at off → fallback slice, no panic
        let buf = b"curl\0".to_vec();
        assert_eq!(parse_pname(&buf, 0), "curl");
        // offset past the end → empty string
        assert_eq!(parse_pname(&buf, 999), "");
    }

    #[test]
    fn parse_desc_rejects_unknown_provider() {
        // a provider that's neither TCP nor UDP yields no descriptor
        assert!(parse_desc(999, &[0u8; TCP_MIN_LEN]).is_none());
    }

    #[test]
    fn pname_strips_control_bytes_and_nul_terminates() {
        let mut buf = vec![0u8; UDP_MIN_LEN];
        let name = b"firefox\x1b[31m\x00ignored-after-nul";
        buf[UDP_PNAME..UDP_PNAME + name.len()].copy_from_slice(name);
        let s = parse_pname(&buf, UDP_PNAME);
        assert!(s.starts_with("firefox"));
        assert!(!s.contains('\x1b'));
        assert!(!s.contains("ignored"));
    }

    /// Build a synthetic SRC_DESC datagram for a TCP descriptor.
    fn tcp_desc_msg(srcref: u64, pid: u32, state: u32, remote: [u8; 4], port: u16) -> Vec<u8> {
        let total = SRC_DESC_DATA + TCP_MIN_LEN;
        let mut m = vec![0u8; total];
        // header
        m[0..8].copy_from_slice(&0u64.to_le_bytes()); // context
        m[8..12].copy_from_slice(&NSTAT_MSG_TYPE_SRC_DESC.to_le_bytes());
        m[12..14].copy_from_slice(&(total as u16).to_le_bytes());
        // srcref + provider
        m[SRC_DESC_SRCREF..SRC_DESC_SRCREF + 8].copy_from_slice(&srcref.to_le_bytes());
        m[SRC_DESC_PROVIDER..SRC_DESC_PROVIDER + 4]
            .copy_from_slice(&NSTAT_PROVIDER_TCP_KERNEL.to_le_bytes());
        // descriptor payload
        let d = SRC_DESC_DATA;
        m[d + TCP_PID..d + TCP_PID + 4].copy_from_slice(&pid.to_le_bytes());
        m[d + TCP_STATE..d + TCP_STATE + 4].copy_from_slice(&state.to_le_bytes());
        m[d + TCP_REMOTE..d + TCP_REMOTE + SOCKADDR_LEN]
            .copy_from_slice(&v4_sockaddr(remote, port));
        let name = b"curl";
        m[d + TCP_PNAME..d + TCP_PNAME + name.len()].copy_from_slice(name);
        m
    }

    #[test]
    fn parse_tcp_desc_message() {
        let m = tcp_desc_msg(0xABCD, 4321, 4 /*ESTABLISHED*/, [1, 1, 1, 1], 443);
        let msgs = parse_datagram(&m);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::SrcDesc {
                srcref,
                provider,
                desc,
            } => {
                assert_eq!(*srcref, 0xABCD);
                assert_eq!(*provider, NSTAT_PROVIDER_TCP_KERNEL);
                assert_eq!(desc.pid, 4321);
                assert_eq!(desc.pname, "curl");
                assert_eq!(desc.tcp_state, 4);
                assert_eq!(desc.remote.unwrap().port, 443);
            }
            other => panic!("expected SrcDesc, got {other:?}"),
        }
    }

    #[test]
    fn tcp_desc_with_bogus_pid_is_dropped() {
        // pid 0 fails validation → parse returns None → no SrcDesc emitted.
        let m = tcp_desc_msg(1, 0, 4, [1, 1, 1, 1], 443);
        let msgs = parse_datagram(&m);
        assert!(msgs.is_empty());
    }

    #[test]
    fn short_descriptor_is_rejected() {
        assert!(parse_tcp_desc(&[0u8; 8]).is_none());
        assert!(parse_udp_desc(&[0u8; 8]).is_none());
    }

    #[test]
    fn parse_src_added_counts_removed() {
        // SRC_ADDED
        let mut added = vec![0u8; 32];
        added[8..12].copy_from_slice(&NSTAT_MSG_TYPE_SRC_ADDED.to_le_bytes());
        added[12..14].copy_from_slice(&32u16.to_le_bytes());
        added[SRC_ADDED_SRCREF..SRC_ADDED_SRCREF + 8].copy_from_slice(&5u64.to_le_bytes());
        added[SRC_ADDED_PROVIDER..SRC_ADDED_PROVIDER + 4]
            .copy_from_slice(&NSTAT_PROVIDER_UDP_KERNEL.to_le_bytes());

        // SRC_COUNTS (144 bytes total)
        let mut counts = vec![0u8; 144];
        counts[8..12].copy_from_slice(&NSTAT_MSG_TYPE_SRC_COUNTS.to_le_bytes());
        counts[12..14].copy_from_slice(&144u16.to_le_bytes());
        counts[SRC_COUNTS_SRCREF..SRC_COUNTS_SRCREF + 8].copy_from_slice(&5u64.to_le_bytes());
        counts[SRC_COUNTS_COUNTS + COUNTS_RXBYTES..SRC_COUNTS_COUNTS + COUNTS_RXBYTES + 8]
            .copy_from_slice(&1000u64.to_le_bytes());
        counts[SRC_COUNTS_COUNTS + COUNTS_TXBYTES..SRC_COUNTS_COUNTS + COUNTS_TXBYTES + 8]
            .copy_from_slice(&250u64.to_le_bytes());

        // SRC_REMOVED
        let mut removed = vec![0u8; 24];
        removed[8..12].copy_from_slice(&NSTAT_MSG_TYPE_SRC_REMOVED.to_le_bytes());
        removed[12..14].copy_from_slice(&24u16.to_le_bytes());
        removed[SRC_ADDED_SRCREF..SRC_ADDED_SRCREF + 8].copy_from_slice(&5u64.to_le_bytes());

        // concatenate into one aggregate datagram
        let mut dg = Vec::new();
        dg.extend_from_slice(&added);
        dg.extend_from_slice(&counts);
        dg.extend_from_slice(&removed);

        let msgs = parse_datagram(&dg);
        assert_eq!(msgs.len(), 3);
        assert_eq!(
            msgs[0],
            Msg::SrcAdded {
                srcref: 5,
                provider: NSTAT_PROVIDER_UDP_KERNEL
            }
        );
        assert_eq!(
            msgs[1],
            Msg::SrcCounts {
                srcref: 5,
                counts: Counts {
                    rx_bytes: 1000,
                    tx_bytes: 250
                }
            }
        );
        assert_eq!(msgs[2], Msg::SrcRemoved { srcref: 5 });
    }

    #[test]
    fn parse_error_success_and_other() {
        let mut err = vec![0u8; 24];
        err[8..12].copy_from_slice(&NSTAT_MSG_TYPE_ERROR.to_le_bytes());
        err[12..14].copy_from_slice(&24u16.to_le_bytes());
        err[16..20].copy_from_slice(&13u32.to_le_bytes()); // EACCES-ish
        assert_eq!(parse_datagram(&err), vec![Msg::Error { code: 13 }]);

        let mut ok = vec![0u8; 16];
        ok[8..12].copy_from_slice(&NSTAT_MSG_TYPE_SUCCESS.to_le_bytes());
        ok[12..14].copy_from_slice(&16u16.to_le_bytes());
        assert_eq!(parse_datagram(&ok), vec![Msg::Success]);

        // an unmodelled type (e.g. SYSINFO) → Other
        let mut other = vec![0u8; 16];
        other[8..12].copy_from_slice(&10005u32.to_le_bytes());
        other[12..14].copy_from_slice(&16u16.to_le_bytes());
        assert_eq!(parse_datagram(&other), vec![Msg::Other { msg_type: 10005 }]);
    }

    #[test]
    fn datagram_walk_stops_on_garbage_length() {
        // a message claiming a length smaller than the header → walk stops
        let mut bad = vec![0u8; 16];
        bad[8..12].copy_from_slice(&NSTAT_MSG_TYPE_SUCCESS.to_le_bytes());
        bad[12..14].copy_from_slice(&4u16.to_le_bytes()); // < 16
        assert!(parse_datagram(&bad).is_empty());

        // length running past the buffer → walk stops
        let mut over = vec![0u8; 16];
        over[8..12].copy_from_slice(&NSTAT_MSG_TYPE_SUCCESS.to_le_bytes());
        over[12..14].copy_from_slice(&999u16.to_le_bytes());
        assert!(parse_datagram(&over).is_empty());

        // trailing bytes shorter than a header are ignored
        let mut ok = vec![0u8; 16];
        ok[8..12].copy_from_slice(&NSTAT_MSG_TYPE_SUCCESS.to_le_bytes());
        ok[12..14].copy_from_slice(&16u16.to_le_bytes());
        ok.extend_from_slice(&[0u8; 4]);
        assert_eq!(parse_datagram(&ok), vec![Msg::Success]);
    }

    #[test]
    fn parse_src_update_bundles_counts_and_desc() {
        let total = SRC_UPDATE_DATA + UDP_MIN_LEN;
        let mut m = vec![0u8; total];
        m[8..12].copy_from_slice(&NSTAT_MSG_TYPE_SRC_UPDATE.to_le_bytes());
        m[12..14].copy_from_slice(&(total as u16).to_le_bytes());
        m[SRC_UPDATE_SRCREF..SRC_UPDATE_SRCREF + 8].copy_from_slice(&9u64.to_le_bytes());
        m[SRC_UPDATE_COUNTS + COUNTS_RXBYTES..SRC_UPDATE_COUNTS + COUNTS_RXBYTES + 8]
            .copy_from_slice(&42u64.to_le_bytes());
        m[SRC_UPDATE_PROVIDER..SRC_UPDATE_PROVIDER + 4]
            .copy_from_slice(&NSTAT_PROVIDER_UDP_KERNEL.to_le_bytes());
        let d = SRC_UPDATE_DATA;
        m[d + UDP_PID..d + UDP_PID + 4].copy_from_slice(&777u32.to_le_bytes());
        m[d + UDP_REMOTE..d + UDP_REMOTE + SOCKADDR_LEN]
            .copy_from_slice(&v4_sockaddr([8, 8, 8, 8], 53));
        let name = b"mDNSResponder";
        m[d + UDP_PNAME..d + UDP_PNAME + name.len()].copy_from_slice(name);

        match &parse_datagram(&m)[0] {
            Msg::SrcUpdate {
                srcref,
                counts,
                desc,
                ..
            } => {
                assert_eq!(*srcref, 9);
                assert_eq!(counts.rx_bytes, 42);
                let desc = desc.as_ref().unwrap();
                assert_eq!(desc.pid, 777);
                assert_eq!(desc.pname, "mDNSResponder");
                assert_eq!(desc.remote.unwrap().port, 53);
            }
            other => panic!("expected SrcUpdate, got {other:?}"),
        }
    }
}

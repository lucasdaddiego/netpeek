//! Asynchronous, cached reverse DNS.
//!
//! The UI asks for a hostname with [`Resolver::lookup`]; it returns instantly
//! from cache or `None` while a background thread does the blocking
//! `getnameinfo(3)` PTR lookup. Results (including "no name") are cached so a
//! host is only ever looked up once, and the render loop never stalls on DNS.

use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::net::{IpAddr, SocketAddr};
use std::os::raw::c_char;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

type Cache = Arc<Mutex<HashMap<IpAddr, Option<String>>>>;
type InFlight = Arc<Mutex<HashSet<IpAddr>>>;

pub struct Resolver {
    cache: Cache,
    inflight: InFlight,
    tx: Sender<IpAddr>,
}

impl Resolver {
    pub fn new() -> Self {
        let cache: Cache = Arc::new(Mutex::new(HashMap::new()));
        let inflight: InFlight = Arc::new(Mutex::new(HashSet::new()));
        let (tx, rx) = mpsc::channel::<IpAddr>();

        let worker_cache = Arc::clone(&cache);
        let worker_inflight = Arc::clone(&inflight);
        thread::Builder::new()
            .name("netpeek-dns".into())
            .spawn(move || {
                for ip in rx {
                    let name = reverse_dns(ip);
                    worker_cache.lock().unwrap().insert(ip, name);
                    worker_inflight.lock().unwrap().remove(&ip);
                }
            })
            .expect("spawn dns worker");

        Resolver {
            cache,
            inflight,
            tx,
        }
    }

    /// Cached hostname for `ip`. `Some(name)` once resolved; `None` while pending
    /// *or* when the host has no PTR record (the UI falls back to the IP either
    /// way). The first call for an address schedules the lookup.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        if let Some(v) = self.cache.lock().unwrap().get(&ip) {
            return v.clone();
        }
        // Schedule once.
        if self.inflight.lock().unwrap().insert(ip) {
            let _ = self.tx.send(ip);
        }
        None
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocking PTR lookup via `getnameinfo` with `NI_NAMEREQD` (so a missing PTR
/// returns an error rather than the numeric form, which we map to `None`).
fn reverse_dns(ip: IpAddr) -> Option<String> {
    let sock = SocketAddr::new(ip, 0);
    let (sa, len): (libc::sockaddr_storage, libc::socklen_t) = socketaddr_to_c(&sock);
    let mut host = [0 as c_char; libc::NI_MAXHOST as usize];
    // SAFETY: sa is a valid sockaddr_storage of `len` bytes; host is sized
    // NI_MAXHOST; service buffer is null with length 0.
    let rc = unsafe {
        libc::getnameinfo(
            &sa as *const libc::sockaddr_storage as *const libc::sockaddr,
            len,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if rc != 0 {
        return None;
    }
    // SAFETY: getnameinfo NUL-terminates within the buffer on success.
    let s = unsafe { CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Marshal a `SocketAddr` into a C `sockaddr_storage` + length.
fn socketaddr_to_c(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: zeroed sockaddr_storage is a valid all-zero POD value.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in fits within sockaddr_storage.
            unsafe {
                *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in) = sin;
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: sockaddr_in6 fits within sockaddr_storage.
            unsafe {
                *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6) = sin6;
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

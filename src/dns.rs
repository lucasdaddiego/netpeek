//! Asynchronous, cached reverse DNS.
//!
//! The UI asks for a hostname with [`Resolver::lookup`]; it returns instantly
//! from cache or `None` while a background thread does the blocking
//! `getnameinfo(3)` PTR lookup. Results (including "no name") are cached so a
//! host is looked up once while it stays in view, and the render loop never
//! stalls on DNS. The cache is a bounded LRU and the lookup queue is capped,
//! so a long session on a CDN-heavy box holds a fixed amount of memory.

use std::collections::HashSet;
use std::ffi::CStr;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::os::raw::c_char;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use lru::LruCache;

use crate::ntstat::wire::sanitize_name;

type Cache = Arc<Mutex<LruCache<IpAddr, Option<String>>>>;
type InFlight = Arc<Mutex<HashSet<IpAddr>>>;
/// The blocking lookup a worker runs; `new` uses [`reverse_dns`], tests a fake.
type LookupFn = fn(IpAddr) -> Option<String>;

/// Reverse-DNS worker threads. A small pool, so one slow or timing-out PTR
/// lookup (`getnameinfo` has no timeout) can't stall every other hostname
/// queued behind it.
const DNS_WORKERS: usize = 4;

/// Upper bound on cached answers (one per distinct remote address, name or
/// "no name"). The least-recently *shown* entry is evicted first, so the hosts
/// on screen stay cached and an evicted one is simply looked up again.
pub const CACHE_CAPACITY: usize = 4096;

/// Upper bound on lookups queued but unanswered. `getnameinfo` has no timeout,
/// so a burst of fresh addresses must not pile an unbounded channel up behind
/// four stuck workers; an address refused here is scheduled on a later frame.
pub const MAX_INFLIGHT: usize = 1024;

pub struct Resolver {
    cache: Cache,
    inflight: InFlight,
    tx: Sender<IpAddr>,
}

impl Resolver {
    pub fn new() -> Self {
        Self::with(CACHE_CAPACITY, reverse_dns)
    }

    /// Build with a given cache capacity and lookup function (tests inject a
    /// fake, so no name is ever resolved over the network).
    fn with(capacity: usize, lookup: LookupFn) -> Self {
        let capacity = NonZeroUsize::new(capacity.max(1)).expect("non-zero capacity");
        let cache: Cache = Arc::new(Mutex::new(LruCache::new(capacity)));
        let inflight: InFlight = Arc::new(Mutex::new(HashSet::new()));
        let (tx, rx) = mpsc::channel::<IpAddr>();
        let rx = Arc::new(Mutex::new(rx));

        for n in 0..DNS_WORKERS {
            let worker_cache = Arc::clone(&cache);
            let worker_inflight = Arc::clone(&inflight);
            let worker_rx: Arc<Mutex<Receiver<IpAddr>>> = Arc::clone(&rx);
            thread::Builder::new()
                .name(format!("netpeek-dns-{n}"))
                .spawn(move || {
                    loop {
                        // Hold the lock only for the blocking recv handoff; resolve
                        // outside it so the workers run getnameinfo concurrently and
                        // a slow lookup occupies just one of them.
                        let ip = {
                            let guard = worker_rx.lock().unwrap();
                            guard.recv()
                        };
                        let Ok(ip) = ip else { break }; // sender dropped → shut down
                        let name = lookup(ip);
                        worker_cache.lock().unwrap().put(ip, name);
                        worker_inflight.lock().unwrap().remove(&ip);
                    }
                })
                .expect("spawn dns worker");
        }

        Resolver {
            cache,
            inflight,
            tx,
        }
    }

    /// Cached hostname for `ip`. `Some(name)` once resolved; `None` while pending
    /// *or* when the host has no PTR record (the UI falls back to the IP either
    /// way). The first call for an address schedules the lookup, unless the
    /// queue already holds [`MAX_INFLIGHT`] addresses — then a later call will.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        if let Some(v) = self.cache.lock().unwrap().get(&ip) {
            return v.clone();
        }
        // Schedule once, and only while the queue is bounded.
        let mut inflight = self.inflight.lock().unwrap();
        if inflight.len() < MAX_INFLIGHT && inflight.insert(ip) {
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
/// The answer is whatever the remote side's DNS operator put in the PTR
/// record, so it is sanitized like a process name before it is cached.
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
    let s = unsafe { CStr::from_ptr(host.as_ptr()) }.to_string_lossy();
    if s.is_empty() {
        None
    } else {
        Some(sanitize_name(&s))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    /// Fake lookup: `.0` hosts have no PTR, everything else is `host-<ip>`.
    fn fake(ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v4) if v4.octets()[3] == 0 => None,
            _ => Some(format!("host-{ip}")),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Block until the workers have answered `ip`, then return the cached value.
    fn settled(r: &Resolver, ip: IpAddr) -> Option<String> {
        let t0 = Instant::now();
        loop {
            if !r.inflight.lock().unwrap().contains(&ip) && r.cache.lock().unwrap().contains(&ip) {
                return r.lookup(ip);
            }
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "lookup of {ip} never completed"
            );
            thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn answers_and_missing_names_are_both_cached() {
        let r = Resolver::with(8, fake);
        assert_eq!(r.lookup(ip("10.0.0.1")), None); // first call schedules
        assert_eq!(settled(&r, ip("10.0.0.1")), Some("host-10.0.0.1".into()));
        assert_eq!(r.lookup(ip("10.0.0.0")), None);
        assert_eq!(settled(&r, ip("10.0.0.0")), None); // "no PTR", cached so never retried
        assert!(r.cache.lock().unwrap().contains(&ip("10.0.0.0")));
        assert!(r.inflight.lock().unwrap().is_empty());
    }

    #[test]
    fn evicts_the_least_recently_shown_entry() {
        let (a, b, c) = (ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3"));
        let r = Resolver::with(2, fake);
        r.lookup(a);
        settled(&r, a);
        r.lookup(b);
        settled(&r, b);
        assert_eq!(r.lookup(a), Some("host-10.0.0.1".into())); // a shown again: b is now LRU
        r.lookup(c);
        settled(&r, c);
        let cache = r.cache.lock().unwrap();
        assert!(cache.contains(&a) && cache.contains(&c) && !cache.contains(&b));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn the_lookup_queue_is_bounded() {
        fn slow(ip: IpAddr) -> Option<String> {
            thread::sleep(Duration::from_millis(100));
            Some(ip.to_string())
        }
        let r = Resolver::with(16, slow);
        for n in 0..(MAX_INFLIGHT as u32 + 64) {
            r.lookup(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n)));
        }
        assert!(r.inflight.lock().unwrap().len() <= MAX_INFLIGHT);
    }
}

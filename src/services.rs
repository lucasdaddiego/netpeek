//! Port → service-name resolution.
//!
//! A small curated table of the ports you actually see on a personal machine,
//! overlaid (best-effort) with the system `/etc/services` so the long tail still
//! resolves. The parse takes a `&str`, so it's tested hermetically.

use std::collections::HashMap;

use crate::model::Proto;

/// Curated common ports — accurate names for the traffic that dominates a
/// developer's box, independent of `/etc/services` being present or complete.
const COMMON: &[(u16, &str)] = &[
    (53, "dns"),
    (67, "dhcp"),
    (68, "dhcp"),
    (80, "http"),
    (123, "ntp"),
    (143, "imap"),
    (179, "bgp"),
    (443, "https"),
    (465, "smtps"),
    (587, "submission"),
    (993, "imaps"),
    (995, "pop3s"),
    (5223, "apns"), // Apple Push Notification service
    (3478, "stun"),
    (3479, "stun"),
    (5060, "sip"),
    (5061, "sips"),
    (8080, "http-alt"),
    (8443, "https-alt"),
    (1900, "ssdp"),
    (5353, "mdns"),
    (22, "ssh"),
    (3306, "mysql"),
    (5432, "postgres"),
    (6379, "redis"),
    (27017, "mongodb"),
    (11211, "memcached"),
    (9418, "git"),
    (2049, "nfs"),
    (548, "afp"),
    (445, "smb"),
    (631, "ipp"),
    (5228, "gcm"), // Google services
    (853, "dns-tls"),
    (4500, "ipsec-nat-t"),
    (500, "isakmp"),
    (1194, "openvpn"),
    (51820, "wireguard"),
];

/// A resolver: curated names plus any `/etc/services` entries layered under them.
#[derive(Clone, Default)]
pub struct Services {
    tcp: HashMap<u16, String>,
    udp: HashMap<u16, String>,
}

impl Services {
    /// Build from the curated table only (no system file).
    pub fn builtin() -> Self {
        let mut s = Services::default();
        for &(port, name) in COMMON {
            s.tcp.entry(port).or_insert_with(|| name.to_string());
            s.udp.entry(port).or_insert_with(|| name.to_string());
        }
        s
    }

    /// Overlay entries parsed from `/etc/services` content. Curated names win,
    /// so this only fills gaps (it `or_insert`s).
    pub fn merge_etc_services(&mut self, content: &str) {
        for line in content.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut it = line.split_whitespace();
            let (Some(name), Some(port_proto)) = (it.next(), it.next()) else {
                continue;
            };
            let Some((port, proto)) = port_proto.split_once('/') else {
                continue;
            };
            let Ok(port) = port.parse::<u16>() else {
                continue;
            };
            match proto {
                "tcp" => {
                    self.tcp.entry(port).or_insert_with(|| name.to_string());
                }
                "udp" => {
                    self.udp.entry(port).or_insert_with(|| name.to_string());
                }
                _ => {}
            }
        }
    }

    /// Best-effort name for a port; `None` if unknown.
    pub fn name(&self, port: u16, proto: Proto) -> Option<&str> {
        let map = match proto {
            Proto::Tcp => &self.tcp,
            Proto::Udp => &self.udp,
        };
        map.get(&port).map(|s| s.as_str())
    }

    /// `"443 (https)"` or just `"7777"` when unknown — for the detail pane.
    pub fn label(&self, port: u16, proto: Proto) -> String {
        match self.name(port, proto) {
            Some(n) => format!("{port} ({n})"),
            None => port.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_ports_resolve() {
        let s = Services::builtin();
        assert_eq!(s.name(443, Proto::Tcp), Some("https"));
        assert_eq!(s.name(53, Proto::Udp), Some("dns"));
        assert_eq!(s.name(5353, Proto::Udp), Some("mdns"));
        assert_eq!(s.name(7777, Proto::Tcp), None);
    }

    #[test]
    fn label_formats() {
        let s = Services::builtin();
        assert_eq!(s.label(443, Proto::Tcp), "443 (https)");
        assert_eq!(s.label(7777, Proto::Tcp), "7777");
    }

    #[test]
    fn etc_services_fills_gaps_without_overriding_curated() {
        let mut s = Services::builtin();
        s.merge_etc_services(
            "# a comment\n\
             https 443/tcp www\n\
             whois 43/tcp nicname  # who is\n\
             ntp 123/udp\n\
             garbage line\n\
             bad port/tcp\n\
             weird 99/sctp\n",
        );
        // curated https name is preserved (not overwritten by 'https' here anyway)
        assert_eq!(s.name(443, Proto::Tcp), Some("https"));
        // new tcp entry from the file
        assert_eq!(s.name(43, Proto::Tcp), Some("whois"));
        // udp-only entry doesn't leak into tcp
        assert_eq!(s.name(43, Proto::Udp), None);
        // unparseable / non-tcp-udp lines are skipped, no panic
        assert_eq!(s.name(99, Proto::Tcp), None);
    }
}

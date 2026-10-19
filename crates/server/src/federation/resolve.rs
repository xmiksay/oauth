//! Outbound requests to identity providers reach public addresses only: an
//! administrator picks the URLs, and must not be able to point our server at
//! its own network (blind SSRF). Host names are checked after resolution
//! (a DNS resolver for the federation client), IP literals in `urls`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Whether `ip` is a globally routable unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let blocked = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        || a >= 240
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19));
    !blocked
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let seg = ip.segments();
    let [first, second, ..] = seg;
    // NAT64 (64:ff9b::/96) carries an IPv4 address in its low 32 bits.
    if first == 0x64 && second == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        let low = u128::from(ip) as u32;
        return public_v4(Ipv4Addr::from(low));
    }
    // 6to4 (2002::/16) carries an IPv4 address in bits 16-47.
    if first == 0x2002 {
        let [_, hi, lo, ..] = seg;
        return public_v4(Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo)));
    }
    let blocked = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (first & 0xffc0) == 0xfe80
        || (first & 0xffc0) == 0xfec0
        || (first & 0xfe00) == 0xfc00
        || (first == 0x2001 && second == 0x0db8)
        // Teredo (2001::/32): the IPv4 server and client are obfuscated
        // inside; and local-use NAT64 (64:ff9b:1::/48).
        || (first == 0x2001 && second == 0)
        || (first == 0x64 && second == 0xff9b && seg[2] == 1)
        // IPv4-compatible (deprecated) ::a.b.c.d
        || seg[..6] == [0, 0, 0, 0, 0, 0];
    !blocked
}

/// System DNS with every non-public answer dropped; no public answer is an
/// error, so the connection never starts.
pub struct PublicOnly;

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let found: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|addr| is_public(addr.ip()))
                .collect();
            if found.is_empty() {
                return Err("the identity provider resolves to no public address".into());
            }
            let addrs: Addrs = Box::new(found.into_iter());
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(raw: &str) -> bool {
        is_public(raw.parse().unwrap())
    }

    #[test]
    fn non_public_addresses_are_refused() {
        for blocked in [
            "0.0.0.0",
            "127.0.0.1",
            "127.9.9.9",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.169.254",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
            "198.18.0.1",
            "192.0.0.8",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "ff02::1",
            "2001:db8::1",
            "fec0::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a00:1",
            "::7f00:1",
            "64:ff9b:1::a00:1",
            "64:ff9b:1::808:808",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2002:a00:1::1",
            "2002:7f00:1::1",
            "2002:c0a8:101::1",
        ] {
            assert!(!public(blocked), "{blocked}");
        }
    }

    #[test]
    fn public_addresses_pass() {
        for ok in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "2001:4860:4860::8888",
        ] {
            assert!(public(ok), "{ok}");
        }
    }
}

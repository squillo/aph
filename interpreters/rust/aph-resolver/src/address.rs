//! Pure address classification — control 1 of the PRD-700 7 A2 table.
//!
//! A `did:web` identifier is chosen by whoever wrote the envelope being
//! verified, so its host is attacker-supplied input that this process is
//! about to connect to. Without a deny table, a verifier is a general
//! purpose request forger: `did:web:localhost%3A8443`, `did:web:169.254.169.254`
//! (cloud instance metadata) and `did:web:10.0.0.7` are all well-formed DIDs
//! that would make the verifier fetch from inside its own trust boundary and
//! report what it found — or, given a timing difference, report that a host
//! merely exists.
//!
//! **Everything in this module is a pure function of an address.** No socket,
//! no clock, no resolver. That is deliberate: the whole table is then
//! exercised by ordinary unit tests, which is the only way a deny list stays
//! honest — an SSRF control that can only be tested against a live network is
//! a control nobody re-tests after the first review.
//!
//! The table is a DENY list evaluated against an ALREADY-RESOLVED address,
//! never against a hostname. Names are not the unit of this decision: one
//! name can resolve to several addresses, and a name that resolved publicly a
//! millisecond ago can resolve to loopback now. The fetch adapter therefore
//! classifies the FULL resolved set and pins it before connecting.

/// The verdict of the deny table for one address.
///
/// Two states on purpose. A richer enum naming WHICH class refused would be
/// a convenient log line and a disclosure channel: the refusal reason is
/// derived from an address the requester chose, so reporting it turns a
/// verifier into an address-space oracle (control 5). The caller collapses
/// this to one opaque error either way.
#[derive(std::fmt::Debug, std::clone::Clone, std::marker::Copy, std::cmp::PartialEq, std::cmp::Eq)]
pub(crate) enum AddressClass {
  /// Ordinary public unicast — the connect may proceed.
  Public,
  /// Anything else. Refuse before any socket is opened.
  Refused,
}

/// Classifies any address by dispatching to the family table.
pub(crate) fn classify_ip(address: std::net::IpAddr) -> AddressClass {
  match address {
    std::net::IpAddr::V4(v4) => classify_ipv4(v4),
    std::net::IpAddr::V6(v6) => classify_ipv6(v6),
  }
}

/// The IPv4 deny table.
///
/// Written as explicit octet arithmetic rather than as calls to
/// `Ipv4Addr::is_private` and friends: several of the predicates this table
/// needs (`100.64/10`, `192.0.0/24`, `198.18/15`, `240/4`) have no stable
/// std equivalent, and mixing "some classes via std, some by hand" is how a
/// row goes missing. One shape, one place to audit.
pub(crate) fn classify_ipv4(address: std::net::Ipv4Addr) -> AddressClass {
  let o = address.octets();
  let refused =
    // "This network" — 0.0.0.0/8. Includes the unspecified address, which
    // several stacks route to localhost.
    o[0] == 0
    // Loopback — 127.0.0.0/8. Note the whole /8, not just 127.0.0.1:
    // 127.1 and 127.0.0.53 reach the same stack.
    || o[0] == 127
    // RFC 1918 private space.
    || o[0] == 10
    || (o[0] == 172 && (o[1] & 0xf0) == 16)
    || (o[0] == 192 && o[1] == 168)
    // Link-local — 169.254.0.0/16. This is the row that matters most in a
    // cloud: 169.254.169.254 is the instance metadata service, and reading
    // it yields credentials.
    || (o[0] == 169 && o[1] == 254)
    // Carrier-grade NAT — 100.64.0.0/10.
    || (o[0] == 100 && (o[1] & 0xc0) == 64)
    // IETF protocol assignments — 192.0.0.0/24.
    || (o[0] == 192 && o[1] == 0 && o[2] == 0)
    // Benchmarking — 198.18.0.0/15.
    || (o[0] == 198 && (o[1] & 0xfe) == 18)
    // TEST-NET-1/2/3 — documentation ranges that reach nothing real.
    || (o[0] == 192 && o[1] == 0 && o[2] == 2)
    || (o[0] == 198 && o[1] == 51 && o[2] == 100)
    || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    // Multicast — 224.0.0.0/4.
    || (o[0] & 0xf0) == 224
    // Reserved — 240.0.0.0/4, which also covers the broadcast address.
    || (o[0] & 0xf0) == 240
    // Limited broadcast, stated in its own right so removing the /4 row
    // above could never silently permit it.
    || o == [255, 255, 255, 255];
  if refused {
    AddressClass::Refused
  } else {
    AddressClass::Public
  }
}

/// The IPv6 deny table, plus the embedded-IPv4 re-check.
///
/// The re-check comes FIRST and is the reason this function is not a mirror
/// image of the v4 one. IPv6 can carry a v4 address inside it in at least
/// four shapes, and a v6-only table would wave through `::ffff:127.0.0.1`
/// and `64:ff9b::a9fe:a9fe` — both of which reach exactly the destinations
/// the v4 table exists to refuse. Running the embedded address back through
/// [`classify_ipv4`] means there is ONE v4 table, so a row added there is
/// automatically enforced on every tunnelling form.
pub(crate) fn classify_ipv6(address: std::net::Ipv6Addr) -> AddressClass {
  if let std::option::Option::Some(embedded) = embedded_ipv4(address) {
    if classify_ipv4(embedded) == AddressClass::Refused {
      return AddressClass::Refused;
    }
  }
  let s = address.segments();
  let refused =
    // Unspecified `::` and loopback `::1`.
    address == std::net::Ipv6Addr::UNSPECIFIED
    || address == std::net::Ipv6Addr::LOCALHOST
    // Multicast — ff00::/8.
    || (s[0] & 0xff00) == 0xff00
    // Unique local addresses — fc00::/7.
    || (s[0] & 0xfe00) == 0xfc00
    // Link-local unicast — fe80::/10.
    || (s[0] & 0xffc0) == 0xfe80
    // Site-local, deprecated but still configured on real networks —
    // fec0::/10.
    || (s[0] & 0xffc0) == 0xfec0
    // Documentation — 2001:db8::/32.
    || (s[0] == 0x2001 && s[1] == 0x0db8)
    // IETF protocol assignments — 2001::/23, which contains Teredo
    // (2001:0::/32) and ORCHID.
    || (s[0] == 0x2001 && (s[1] & 0xfe00) == 0x0000)
    // Discard-only — 100::/64.
    || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
    // 6to4 — 2002::/16. Refused as a class as well as by the embedded-v4
    // re-check above, because a 6to4 address with a public embedded v4
    // still routes through a relay this verifier did not choose.
    || s[0] == 0x2002;
  if refused {
    AddressClass::Refused
  } else {
    AddressClass::Public
  }
}

/// Extracts the IPv4 address an IPv6 address embeds, in any of the four
/// forms that reach a v4 destination.
///
/// Returns `None` for a native IPv6 address, which is the common case.
pub(crate) fn embedded_ipv4(
  address: std::net::Ipv6Addr,
) -> std::option::Option<std::net::Ipv4Addr> {
  let s = address.segments();
  // The three /96-prefixed forms all carry the v4 address in the low 32
  // bits, so the value is computed once.
  let tail = std::net::Ipv4Addr::from(((s[6] as u32) << 16) | (s[7] as u32));
  let leading_zero = s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0;
  // IPv4-mapped — ::ffff:a.b.c.d.
  if leading_zero && s[5] == 0xffff {
    return std::option::Option::Some(tail);
  }
  // IPv4-compatible — ::a.b.c.d. Deprecated by RFC 4291, which is exactly
  // why it is checked: a deprecated form is one nobody's deny list covers.
  if leading_zero && s[5] == 0 {
    return std::option::Option::Some(tail);
  }
  // NAT64 well-known prefix — 64:ff9b::/96.
  if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
    return std::option::Option::Some(tail);
  }
  // 6to4 — 2002::/16 embeds the v4 address in the NEXT 32 bits, not the
  // last 32.
  if s[0] == 0x2002 {
    return std::option::Option::Some(std::net::Ipv4Addr::from(
      ((s[1] as u32) << 16) | (s[2] as u32),
    ));
  }
  std::option::Option::None
}

#[cfg(test)]
mod tests {
  /// Parses a literal, panicking on a typo in the test itself.
  fn v4(text: &str) -> std::net::Ipv4Addr {
    <std::net::Ipv4Addr as std::str::FromStr>::from_str(text).expect("test literal is not IPv4")
  }

  /// Parses a literal, panicking on a typo in the test itself.
  fn v6(text: &str) -> std::net::Ipv6Addr {
    <std::net::Ipv6Addr as std::str::FromStr>::from_str(text).expect("test literal is not IPv6")
  }

  #[test]
  fn every_denied_ipv4_family_is_refused() {
    // One row per family in the A2 control-1 table, because the table is
    // the control: a family silently dropped during a refactor is not a
    // style regression, it is an SSRF hole that a `did:web` identifier
    // reaches directly. 169.254.169.254 is called out by name — it is the
    // cloud instance metadata service, and a verifier that fetches it and
    // reports the body has handed over credentials.
    for address in [
      "0.0.0.0", "0.1.2.3",                        // this-network 0/8
      "127.0.0.1", "127.0.0.53", "127.1.2.3",      // loopback 127/8
      "10.0.0.7", "172.16.0.1", "172.31.255.254", "192.168.1.1", // RFC 1918
      "169.254.1.1", "169.254.169.254",            // link-local + metadata
      "100.64.0.1", "100.127.255.254",             // CGNAT 100.64/10
      "192.0.0.1",                                 // IETF protocol 192.0.0/24
      "198.18.0.1", "198.19.255.254",              // benchmark 198.18/15
      "192.0.2.1", "198.51.100.1", "203.0.113.1",  // TEST-NET-1/2/3
      "224.0.0.1", "239.255.255.250",              // multicast 224/4
      "240.0.0.1",                                 // reserved 240/4
      "255.255.255.255",                           // limited broadcast
    ] {
      std::assert_eq!(
        super::classify_ipv4(v4(address)),
        super::AddressClass::Refused,
        "{} was permitted",
        address
      );
    }
  }

  #[test]
  fn near_miss_ipv4_addresses_stay_public() {
    // A deny table that is too WIDE is also a defect — it takes real
    // notaries offline, and an outage caused by a security control is the
    // kind that gets the control deleted. These addresses sit one bit
    // outside a denied range (172.15/172.32 straddle the /12, 100.63/100.128
    // straddle the /10, 198.17/198.20 straddle the /15) and must resolve
    // normally.
    for address in [
      "93.184.216.34", "8.8.8.8", "1.1.1.1", "172.15.0.1", "172.32.0.1", "100.63.255.255",
      "100.128.0.0", "198.17.255.255", "198.20.0.0", "192.0.1.1", "203.0.114.1",
    ] {
      std::assert_eq!(
        super::classify_ipv4(v4(address)),
        super::AddressClass::Public,
        "{} was refused",
        address
      );
    }
  }

  #[test]
  fn every_denied_ipv6_family_is_refused() {
    // The v6 half of the same table. fec0::/10 is deprecated and still
    // present because deprecation removes a range from new deployments, not
    // from the networks already running it.
    for address in [
      "::",                                  // unspecified
      "::1",                                 // loopback
      "ff02::1", "ff05::1:3",                // multicast ff00::/8
      "fc00::1", "fd00::1",                  // unique local fc00::/7
      "fe80::1",                             // link-local fe80::/10
      "fec0::1",                             // site-local fec0::/10
      "2001:db8::1",                         // documentation
      "2001::1", "2001:1ff::1",              // IETF protocol 2001::/23
      "100::1",                              // discard-only 100::/64
      "2002::1",                             // 6to4 2002::/16
    ] {
      std::assert_eq!(
        super::classify_ipv6(v6(address)),
        super::AddressClass::Refused,
        "{} was permitted",
        address
      );
    }
  }

  #[test]
  fn a_public_ipv6_address_is_permitted() {
    // The accept case for v6, so the table above cannot be satisfied by a
    // function that refuses everything.
    std::assert_eq!(
      super::classify_ipv6(v6("2606:2800:220:1:248:1893:25c8:1946")),
      super::AddressClass::Public
    );
    std::assert_eq!(
      super::classify_ipv6(v6("2620:fe::fe")),
      super::AddressClass::Public
    );
  }

  #[test]
  fn embedded_ipv4_forms_are_re_checked_through_the_v4_table() {
    // THE tunnelling test. Each of these is a legal IPv6 address whose
    // v6-level prefix says nothing suspicious, and each reaches a
    // destination the v4 table refuses. A classifier that only consulted
    // the v6 table would permit all four — and `did:web` identifiers are
    // free to spell a host in any of these forms.
    for address in [
      "::ffff:127.0.0.1",      // IPv4-mapped loopback
      "::ffff:169.254.169.254",// IPv4-mapped cloud metadata
      "::10.0.0.7",            // IPv4-compatible (deprecated) RFC 1918
      "64:ff9b::7f00:1",       // NAT64 well-known prefix, 127.0.0.1
      "64:ff9b::a9fe:a9fe",    // NAT64, cloud metadata
      "2002:7f00:1::1",        // 6to4 wrapping 127.0.0.1
    ] {
      std::assert_eq!(
        super::classify_ipv6(v6(address)),
        super::AddressClass::Refused,
        "{} was permitted",
        address
      );
    }
  }

  #[test]
  fn embedded_extraction_reads_the_right_32_bits() {
    // 6to4 puts the v4 address in the second and third segments while the
    // /96 forms put it in the last two; reading the wrong pair yields
    // 0.0.0.0 for a 6to4 address, which the table happens to refuse — so
    // the bug would be invisible in the refusal tests above and would
    // silently stop re-checking 6to4 addresses with real embedded hosts.
    std::assert_eq!(
      super::embedded_ipv4(v6("::ffff:192.0.2.128")),
      std::option::Option::Some(v4("192.0.2.128"))
    );
    std::assert_eq!(
      super::embedded_ipv4(v6("2002:c000:0280::1")),
      std::option::Option::Some(v4("192.0.2.128"))
    );
    std::assert_eq!(
      super::embedded_ipv4(v6("64:ff9b::c000:280")),
      std::option::Option::Some(v4("192.0.2.128"))
    );
    // A native address embeds nothing; returning Some here would push an
    // arbitrary 32-bit slice of a public v6 address through the v4 table
    // and refuse legitimate notaries at random.
    std::assert_eq!(
      super::embedded_ipv4(v6("2606:2800:220:1:248:1893:25c8:1946")),
      std::option::Option::None
    );
  }

  #[test]
  fn the_family_dispatch_agrees_with_the_family_tables() {
    // classify_ip is what the fetch path actually calls; a dispatch that
    // sent v6 to the v4 table (or vice versa) would compile and would
    // permit everything of the mis-routed family.
    std::assert_eq!(
      super::classify_ip(std::net::IpAddr::V4(v4("127.0.0.1"))),
      super::AddressClass::Refused
    );
    std::assert_eq!(
      super::classify_ip(std::net::IpAddr::V6(v6("::1"))),
      super::AddressClass::Refused
    );
    std::assert_eq!(
      super::classify_ip(std::net::IpAddr::V4(v4("93.184.216.34"))),
      super::AddressClass::Public
    );
    std::assert_eq!(
      super::classify_ip(std::net::IpAddr::V6(v6("2606:2800:220:1:248:1893:25c8:1946"))),
      super::AddressClass::Public
    );
  }
}

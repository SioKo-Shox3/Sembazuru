use sembazuru_gui::net::{is_usable_lan_ipv4, lan_ipv4_candidates};
use std::net::Ipv4Addr;

#[test]
fn filters_loopback_and_linklocal() {
    assert!(!is_usable_lan_ipv4(Ipv4Addr::LOCALHOST));
    assert!(!is_usable_lan_ipv4(Ipv4Addr::new(169, 254, 1, 5))); // APIPA link-local
    assert!(!is_usable_lan_ipv4(Ipv4Addr::UNSPECIFIED)); // 0.0.0.0
    assert!(is_usable_lan_ipv4(Ipv4Addr::new(192, 168, 1, 10)));
    assert!(is_usable_lan_ipv4(Ipv4Addr::new(10, 0, 0, 4)));
}

#[test]
fn candidates_never_include_loopback() {
    for ip in lan_ipv4_candidates() {
        assert!(
            is_usable_lan_ipv4(ip),
            "candidate {ip} must pass the usable filter"
        );
    }
}

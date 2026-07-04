//! LAN IPv4 discovery for the join flow (M11). The GUI never auto-detected its own
//! address before; this offers candidate LAN IPs so the operator does not run `ipconfig`.

use std::net::Ipv4Addr;

/// A LAN IPv4 usable as an advertise / coordinator address: not loopback,
/// not link-local (APIPA 169.254/16), not unspecified, not broadcast.
pub fn is_usable_lan_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() && !ip.is_broadcast()
}

/// Enumerate usable LAN IPv4 addresses of this machine (best-effort; empty on failure).
#[cfg(windows)]
pub fn lan_ipv4_candidates() -> Vec<Ipv4Addr> {
    imp::enumerate()
        .into_iter()
        .filter(|ip| is_usable_lan_ipv4(*ip))
        .collect()
}

#[cfg(not(windows))]
pub fn lan_ipv4_candidates() -> Vec<Ipv4Addr> {
    Vec::new()
}

#[cfg(windows)]
mod imp {
    use std::net::Ipv4Addr;

    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    const GAA_BUFFER_SIZE: usize = 15 * 1024;

    pub fn enumerate() -> Vec<Ipv4Addr> {
        let mut buffer = vec![0u8; GAA_BUFFER_SIZE];
        let mut size = buffer.len() as u32;
        let addresses = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut ips = Vec::new();

        // SAFETY: `addresses` points to a writable buffer of `size` bytes for the
        // single GetAdaptersAddresses call. On success, Windows initializes an
        // IP_ADAPTER_ADDRESSES linked list inside that buffer; the buffer remains
        // alive while we walk `Next` and each adapter's `FirstUnicastAddress` list.
        unsafe {
            let result =
                GetAdaptersAddresses(AF_INET as u32, 0, std::ptr::null(), addresses, &mut size);
            if result != ERROR_SUCCESS {
                return Vec::new();
            }

            let mut adapter = addresses;
            while !adapter.is_null() {
                let adapter_ref = &*adapter;
                if adapter_ref.OperStatus == IfOperStatusUp {
                    let mut unicast = adapter_ref.FirstUnicastAddress;
                    while !unicast.is_null() {
                        let socket_address = (*unicast).Address;
                        if !socket_address.lpSockaddr.is_null()
                            && socket_address.iSockaddrLength
                                >= std::mem::size_of::<SOCKADDR_IN>() as i32
                        {
                            let sockaddr = &*socket_address.lpSockaddr.cast::<SOCKADDR_IN>();
                            if sockaddr.sin_family == AF_INET {
                                let octets = sockaddr.sin_addr.S_un.S_addr.to_ne_bytes();
                                ips.push(Ipv4Addr::from(octets));
                            }
                        }
                        unicast = (*unicast).Next;
                    }
                }
                adapter = adapter_ref.Next;
            }
        }

        ips
    }
}

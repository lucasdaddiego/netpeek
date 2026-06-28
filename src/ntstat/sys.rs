//! The raw kernel-control socket: `socket(PF_SYSTEM, SOCK_DGRAM,
//! SYSPROTO_CONTROL)`, `ioctl(CTLIOCGINFO)` to resolve the control id, then
//! `connect()` via `sockaddr_ctl`. Thin libc plumbing — the wire encoding and
//! all parsing live in [`super::wire`] (and are tested there).

use std::io;
use std::os::unix::io::RawFd;

use libc::{c_void, close, connect, fcntl, ioctl, recv, send, socket};

use super::wire::CONTROL_NAME;

// PF_SYSTEM / AF_SYSTEM domain for kernel control sockets.
const PF_SYSTEM: libc::c_int = 32;
const SYSPROTO_CONTROL: libc::c_int = 2;
const AF_SYS_CONTROL: u16 = 2;
const MAX_KCTL_NAME: usize = 96;

// CTLIOCGINFO = _IOWR('N', 3, struct ctl_info).
//   _IOWR(g,n,t) = IOC_INOUT | ((sizeof(t) & IOCPARM_MASK) << 16) | (g<<8) | n
// with IOC_INOUT = 0xC0000000, IOCPARM_MASK = 0x1fff, 'N' = 0x4e, and
// sizeof(struct ctl_info) = 4 + 96 = 100 → 0xC0644E03.
const CTLIOCGINFO: libc::c_ulong = 0xC064_4E03;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; MAX_KCTL_NAME],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

/// An owned, connected, non-blocking ntstat control socket.
pub struct ControlSocket {
    fd: RawFd,
}

impl ControlSocket {
    /// Open and connect to `com.apple.network.statistics`. Unprivileged for the
    /// current user's own flows (run with `sudo` to see every process's).
    pub fn open() -> io::Result<Self> {
        // SAFETY: standard socket(2); we check the return value.
        let fd = unsafe { socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let sock = ControlSocket { fd };

        // A QUERY_SRC over *all* sources can return a large burst of count
        // messages; without a roomy receive buffer the kernel control drops
        // them and replies ENOBUFS. Ask for 8 MiB (best-effort).
        sock.set_rcvbuf(8 * 1024 * 1024);

        // Resolve the control id by name.
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0u8; MAX_KCTL_NAME],
        };
        let name = CONTROL_NAME;
        info.ctl_name[..name.len()].copy_from_slice(name);
        // SAFETY: ioctl with a correctly-sized in/out struct for CTLIOCGINFO.
        if unsafe { ioctl(fd, CTLIOCGINFO, &mut info as *mut CtlInfo) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // connect() via sockaddr_ctl with the resolved id.
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: PF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        // SAFETY: connect with a sockaddr_ctl of the declared length.
        let rc = unsafe {
            connect(
                fd,
                &addr as *const SockaddrCtl as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        sock.set_nonblocking()?;
        Ok(sock)
    }

    /// Best-effort enlarge the receive buffer (ignored if the system caps it).
    fn set_rcvbuf(&self, bytes: libc::c_int) {
        // SAFETY: setsockopt with a c_int option value of the declared size.
        unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &bytes as *const libc::c_int as *const c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    fn set_nonblocking(&self) -> io::Result<()> {
        // SAFETY: F_GETFL/F_SETFL on our own fd.
        let flags = unsafe { fcntl(self.fd, libc::F_GETFL, 0) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { fcntl(self.fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send one request datagram.
    pub fn send_bytes(&self, buf: &[u8]) -> io::Result<()> {
        // SAFETY: send from a valid slice on a connected socket.
        let n = unsafe { send(self.fd, buf.as_ptr() as *const c_void, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Receive one datagram. Returns `Ok(None)` when the socket would block
    /// (nothing pending) — the caller drains in a loop until it sees `None`.
    pub fn recv_into(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        // SAFETY: recv into a valid mutable slice.
        let n = unsafe { recv(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            // On Darwin EWOULDBLOCK == EAGAIN, so matching EAGAIN covers both.
            return match err.raw_os_error() {
                Some(libc::EAGAIN) => Ok(None),
                _ => Err(err),
            };
        }
        Ok(Some(n as usize))
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        // SAFETY: closing our own fd exactly once.
        unsafe { close(self.fd) };
    }
}

extern "C" {
    // libproc (part of libSystem, no extra link flag): full executable path.
    fn proc_pidpath(pid: libc::c_int, buf: *mut c_void, size: u32) -> libc::c_int;
}

/// The executable's file name for `pid` via `proc_pidpath`, used to name a flow
/// when the kernel's own (≤16-char) `pname` field comes back empty. `None` if the
/// process is gone or not introspectable.
pub fn proc_name(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let mut buf = [0u8; 4096];
    // SAFETY: proc_pidpath writes at most `size` bytes into buf and returns the
    // length (0 on failure).
    let n = unsafe {
        proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
        )
    };
    if n <= 0 {
        return None;
    }
    let path = String::from_utf8_lossy(&buf[..n as usize]);
    path.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

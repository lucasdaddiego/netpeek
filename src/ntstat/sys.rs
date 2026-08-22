//! The raw kernel-control socket: `socket(PF_SYSTEM, SOCK_DGRAM,
//! SYSPROTO_CONTROL)`, `ioctl(CTLIOCGINFO)` to resolve the control id, then
//! `connect()` via `sockaddr_ctl`. Thin libc plumbing — the wire encoding and
//! all parsing live in [`super::wire`] (and are tested there).

use std::io;
use std::os::unix::io::RawFd;

// The kernel-control types and constants (`ctl_info`, `sockaddr_ctl`,
// `CTLIOCGINFO`, `PF_SYSTEM`, `SYSPROTO_CONTROL`, `AF_SYS_CONTROL`) and
// `proc_pidpath` all come from the libc crate's Apple bindings — nothing is
// hand-transcribed here.
use libc::{
    AF_SYS_CONTROL, CTLIOCGINFO, MAX_KCTL_NAME, PF_SYSTEM, PROC_PIDPATHINFO_MAXSIZE,
    SYSPROTO_CONTROL, c_void, close, connect, ctl_info, fcntl, ioctl, proc_pidpath, recv, send,
    sockaddr_ctl, socket,
};

use super::wire::CONTROL_NAME;

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
        // SAFETY: zeroed ctl_info is a valid all-zero POD value.
        let mut info: ctl_info = unsafe { std::mem::zeroed() };
        const _: () = assert!(CONTROL_NAME.len() < MAX_KCTL_NAME, "control name must fit");
        for (dst, &src) in info.ctl_name.iter_mut().zip(CONTROL_NAME) {
            *dst = src as libc::c_char;
        }
        // SAFETY: ioctl with a correctly-sized in/out struct for CTLIOCGINFO.
        if unsafe { ioctl(fd, CTLIOCGINFO, &mut info as *mut ctl_info) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // connect() via sockaddr_ctl with the resolved id.
        // SAFETY: zeroed sockaddr_ctl is a valid all-zero POD value.
        let mut addr: sockaddr_ctl = unsafe { std::mem::zeroed() };
        addr.sc_len = std::mem::size_of::<sockaddr_ctl>() as u8;
        addr.sc_family = PF_SYSTEM as u8;
        addr.ss_sysaddr = AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        // SAFETY: connect with a sockaddr_ctl of the declared length.
        let rc = unsafe {
            connect(
                fd,
                &addr as *const sockaddr_ctl as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_ctl>() as libc::socklen_t,
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

    /// Send one request datagram. A signal (e.g. `SIGWINCH` on a terminal
    /// resize) can interrupt the syscall with `EINTR`; we retry rather than fail.
    pub fn send_bytes(&self, buf: &[u8]) -> io::Result<()> {
        loop {
            // SAFETY: send from a valid slice on a connected socket.
            let n = unsafe { send(self.fd, buf.as_ptr() as *const c_void, buf.len(), 0) };
            if n >= 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
    }

    /// Receive one datagram. Returns `Ok(None)` when the socket would block
    /// (nothing pending) — the caller drains in a loop until it sees `None`. A
    /// signal-interrupted (`EINTR`) recv is retried, not surfaced as an error.
    pub fn recv_into(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        loop {
            // SAFETY: recv into a valid mutable slice.
            let n = unsafe { recv(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
            if n >= 0 {
                return Ok(Some(n as usize));
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                // On Darwin EWOULDBLOCK == EAGAIN, so matching EAGAIN covers both.
                Some(libc::EAGAIN) => return Ok(None),
                _ => return Err(err),
            }
        }
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        // SAFETY: closing our own fd exactly once.
        unsafe { close(self.fd) };
    }
}

/// The executable's file name for `pid` via `proc_pidpath`, used to name a flow
/// when the kernel's own `pname` field (a 64-byte slot, filled from the process's
/// short name) comes back empty. `None` if the process is gone or not
/// introspectable.
pub fn proc_name(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let mut buf = [0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: proc_pidpath (libproc, part of libSystem) writes at most `size`
    // bytes into buf and returns the length (0 on failure).
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

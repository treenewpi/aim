//! Host calls whose libc shape differs. On macOS each item is the system
//! call. On Linux it is the same operation: an xattr that does not follow
//! the final symlink, a process's start time and parent, a byte copy that
//! fails when the destination exists.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_void};

#[cfg(target_os = "macos")]
pub use libc::{
    EV_DISPATCH, IP_BOUND_IF, IPV6_BOUND_IF, MAP_JIT, MINCORE_INCORE, MINCORE_REFERENCED,
    MINCORE_REFERENCED_OTHER, MNT_NOSUID, MNT_RDONLY, NET_RT_IFLIST2, O_EXLOCK, O_SHLOCK, O_SYMLINK,
    POSIX_SPAWN_CLOEXEC_DEFAULT, PRIO_DARWIN_BG, PRIO_DARWIN_THREAD, RENAME_EXCL, RENAME_SWAP,
    RTM_IFINFO2, RTM_VERSION, SIGEMT, SIGINFO, SOL_LOCAL, SO_NREAD, TCP_KEEPALIVE, arc4random,
    if_msghdr2, pthread_jit_write_protect_np, pthread_threadid_np, renamex_np, vnode_info_path,
};

#[cfg(target_os = "macos")]
pub use libc::{
    EVFILT_PROC, EVFILT_READ, EVFILT_USER, EV_ADD, EV_CLEAR, EV_EOF, EV_ERROR, EV_ONESHOT,
    EV_RECEIPT, LOCAL_PEERPID, NOTE_EXIT, NOTE_TRIGGER, O_EVTONLY, PROC_PIDLISTFDS,
    PROC_PIDTBSDINFO, SF_APPEND, SF_IMMUTABLE, SO_NOSIGPIPE, SZOMB, UF_APPEND,
    UF_HIDDEN, UF_IMMUTABLE, UF_NODUMP, UF_OPAQUE, UF_TRACKED, XATTR_NOFOLLOW, __error,
    arc4random_buf, chflags, clonefile, fchflags, getpeereid, getxattr, kevent, kqueue, listxattr,
    proc_bsdinfo, proc_fdinfo, proc_pidinfo, removexattr, setxattr,
};

#[cfg(target_os = "macos")]
pub fn file_flags(stat: &libc::stat) -> u32 {
    stat.st_flags
}

#[cfg(target_os = "macos")]
pub unsafe fn fgetxattr(
    fd: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
    position: u32,
    options: c_int,
) -> isize {
    unsafe { libc::fgetxattr(fd, name, value, size, position, options) }
}

#[cfg(target_os = "macos")]
pub unsafe fn fremovexattr(fd: c_int, name: *const c_char, options: c_int) -> c_int {
    unsafe { libc::fremovexattr(fd, name, options) }
}

#[cfg(target_os = "macos")]
pub unsafe fn flistxattr(
    fd: c_int,
    namebuf: *mut c_char,
    size: usize,
    options: c_int,
) -> isize {
    unsafe { libc::flistxattr(fd, namebuf, size, options) }
}

#[cfg(target_os = "macos")]
pub unsafe fn fsetxattr(
    fd: c_int,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    position: u32,
    options: c_int,
) -> c_int {
    unsafe { libc::fsetxattr(fd, name, value, size, position, options) }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CStr;
    use std::io;

    pub const XATTR_NOFOLLOW: c_int = 0x0001;
    pub const O_EVTONLY: c_int = 0x0000_8000;
    pub const PROC_PIDTBSDINFO: c_int = 3;
    pub const PROC_PIDLISTFDS: c_int = 1;
    pub const SZOMB: u32 = 5;
    pub const SOL_LOCAL: c_int = 0;
    pub const LOCAL_PEERPID: c_int = 0;
    pub const SO_NOSIGPIPE: c_int = 0;
    pub const EVFILT_READ: i16 = -1;
    pub const EVFILT_PROC: i16 = -5;
    pub const EVFILT_USER: i16 = -10;
    pub const EV_ADD: u16 = 0x1;
    pub const EV_CLEAR: u16 = 0x20;
    pub const EV_ONESHOT: u16 = 0x10;
    pub const EV_RECEIPT: u16 = 0x40;
    pub const EV_ERROR: u16 = 0x4000;
    pub const EV_EOF: u16 = 0x8000;
    pub const NOTE_EXIT: u32 = 0x8000_0000;
    pub const NOTE_TRIGGER: u32 = 0x0100_0000;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct proc_bsdinfo {
        pub pbi_flags: u32,
        pub pbi_status: u32,
        pub pbi_pid: u32,
        pub pbi_ppid: u32,
        pub pbi_pgid: u32,
        pub pbi_start_tvsec: u64,
        pub pbi_start_tvusec: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct proc_fdinfo {
        pub proc_fd: i32,
        pub proc_fdtype: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct kevent {
        pub ident: usize,
        pub filter: i16,
        pub flags: u16,
        pub fflags: u32,
        pub data: isize,
        pub udata: *mut c_void,
    }

    pub unsafe fn __error() -> *mut c_int {
        unsafe { libc::__errno_location() }
    }

    fn fail(err: c_int) -> c_int {
        unsafe { *__error() = err };
        -1
    }

    pub unsafe fn getxattr(
        path: *const c_char,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
        _position: u32,
        _options: c_int,
    ) -> isize {
        unsafe { libc::lgetxattr(path, name, value, size) }
    }

    pub unsafe fn setxattr(
        path: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        _position: u32,
        _options: c_int,
    ) -> c_int {
        unsafe { libc::lsetxattr(path, name, value, size, 0) }
    }

    pub unsafe fn fgetxattr(
        fd: c_int,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
        _position: u32,
        _options: c_int,
    ) -> isize {
        unsafe { libc::fgetxattr(fd, name, value, size) }
    }

    pub unsafe fn fremovexattr(fd: c_int, name: *const c_char, _options: c_int) -> c_int {
        unsafe { libc::fremovexattr(fd, name) }
    }

    pub unsafe fn flistxattr(
        fd: c_int,
        namebuf: *mut c_char,
        size: usize,
        _options: c_int,
    ) -> isize {
        unsafe { libc::flistxattr(fd, namebuf, size) }
    }

    pub unsafe fn fsetxattr(
        fd: c_int,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        _position: u32,
        _options: c_int,
    ) -> c_int {
        unsafe { libc::fsetxattr(fd, name, value, size, 0) }
    }

    pub unsafe fn listxattr(path: *const c_char, namebuf: *mut c_char, size: usize, _options: c_int) -> isize {
        unsafe { libc::llistxattr(path, namebuf, size) }
    }

    pub unsafe fn removexattr(path: *const c_char, name: *const c_char, _options: c_int) -> c_int {
        unsafe { libc::lremovexattr(path, name) }
    }

    pub unsafe fn arc4random_buf(buf: *mut c_void, mut size: usize) {
        let mut at = buf.cast::<u8>();
        while size > 0 {
            let n = unsafe { libc::getrandom(at.cast(), size, 0) };
            if n < 0 {
                if unsafe { *__error() } == libc::EINTR {
                    continue;
                }
                return;
            }
            size -= n as usize;
            at = unsafe { at.add(n as usize) };
        }
    }

    pub unsafe fn getpeereid(fd: c_int, uid: *mut u32, gid: *mut u32) -> c_int {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } != 0
        {
            return -1;
        }
        unsafe {
            *uid = cred.uid;
            *gid = cred.gid;
        }
        0
    }

    /// `kqueue` is not a Linux file. Callers treat `-1` as the absence of a
    /// queue; the Darwin call is unchanged.
    pub unsafe fn kqueue() -> c_int {
        fail(libc::ENOSYS)
    }

    pub unsafe fn kevent(
        _kq: c_int,
        _changelist: *const kevent,
        _nchanges: c_int,
        _eventlist: *mut kevent,
        _nevents: c_int,
        _timeout: *const libc::timespec,
    ) -> c_int {
        fail(libc::ENOSYS)
    }

    pub unsafe fn clonefile(from: *const c_char, to: *const c_char, _flags: u32) -> c_int {
        let (from, to) = unsafe { (CStr::from_ptr(from), CStr::from_ptr(to)) };
        match copy_clone(from, to) {
            Ok(()) => 0,
            Err(err) => fail(err),
        }
    }

    fn copy_clone(from: &CStr, to: &CStr) -> Result<(), c_int> {
        use std::fs::OpenOptions;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::path::Path;
        let from = Path::new(std::ffi::OsStr::from_bytes(from.to_bytes()));
        let to = Path::new(std::ffi::OsStr::from_bytes(to.to_bytes()));
        let src = std::fs::File::open(from).map_err(errno)?;
        let mut dst = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(to)
            .map_err(errno)?;
        let mut src = src;
        std::io::copy(&mut src, &mut dst).map_err(errno)?;
        copy_xattrs(from, to)
    }

    fn errno(error: io::Error) -> c_int {
        error.raw_os_error().unwrap_or(libc::EIO)
    }

    fn copy_xattrs(from: &std::path::Path, to: &std::path::Path) -> Result<(), c_int> {
        use std::os::unix::ffi::OsStrExt;
        let from = std::ffi::CString::new(from.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
        let to = std::ffi::CString::new(to.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
        let len = unsafe { libc::llistxattr(from.as_ptr(), std::ptr::null_mut(), 0) };
        if len < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
        }
        let mut names = vec![0u8; len as usize];
        let len = unsafe {
            libc::llistxattr(from.as_ptr(), names.as_mut_ptr().cast(), names.len())
        };
        if len < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
        }
        for name in names[..len as usize].split(|b| *b == 0).filter(|n| !n.is_empty()) {
            let name = std::ffi::CString::new(name).map_err(|_| libc::EINVAL)?;
            let size = unsafe { libc::lgetxattr(from.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
            if size < 0 {
                return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
            }
            let mut value = vec![0u8; size as usize];
            let size = unsafe {
                libc::lgetxattr(
                    from.as_ptr(),
                    name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            if size < 0
                || unsafe {
                    libc::lsetxattr(
                        to.as_ptr(),
                        name.as_ptr(),
                        value.as_ptr().cast(),
                        size as usize,
                        0,
                    )
                } != 0
            {
                return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
            }
        }
        Ok(())
    }

    pub unsafe fn proc_pidinfo(
        pid: i32,
        flavor: c_int,
        _arg: u64,
        buffer: *mut c_void,
        buffersize: i32,
    ) -> c_int {
        if buffer.is_null() || buffersize < 0 {
            return fail(libc::EINVAL);
        }
        if flavor == PROC_PIDLISTFDS {
            return unsafe { list_fds(buffer, buffersize) };
        }
        let Some(info) = bsd(pid) else {
            return fail(libc::ESRCH);
        };
        if flavor == PROC_PIDTBSDINFO {
            if buffersize < std::mem::size_of::<proc_bsdinfo>() as i32 {
                return fail(libc::ENOMEM);
            }
            unsafe { std::ptr::write(buffer.cast(), info) };
            return std::mem::size_of::<proc_bsdinfo>() as i32;
        }
        // `proc_uniqidentifierinfo`: unique id at 16, id version at 32.
        if flavor == 17 {
            if buffersize < 56 {
                return fail(libc::ENOMEM);
            }
            let Some((unique, version)) = identity(pid) else {
                return fail(libc::ESRCH);
            };
            unsafe {
                std::ptr::write_bytes(buffer, 0, 56);
                std::ptr::write_unaligned(buffer.cast::<u8>().add(16).cast(), unique);
                std::ptr::write_unaligned(buffer.cast::<u8>().add(32).cast(), version);
            }
            return 56;
        }
        // `PROC_PIDT_BSDINFOWITHUNIQID`: BSD info, then 32 bytes, then the
        // id version. The caller checks the byte count it asked for.
        if flavor == 18 {
            let version_at = std::mem::size_of::<proc_bsdinfo>() + 32;
            if buffersize < version_at as i32 + 4 {
                return fail(libc::ENOMEM);
            }
            let Some((_, version)) = identity(pid) else {
                return fail(libc::ESRCH);
            };
            unsafe {
                std::ptr::write(buffer.cast(), info);
                std::ptr::write_unaligned(buffer.cast::<u8>().add(version_at).cast(), version);
            }
            return buffersize;
        }
        fail(libc::ENOTSUP)
    }

    unsafe fn list_fds(buffer: *mut c_void, buffersize: i32) -> c_int {
        let stride = std::mem::size_of::<proc_fdinfo>();
        let cap = buffersize as usize / stride;
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        let max = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            limit.rlim_cur.min(65_536) as i32
        } else {
            1024
        };
        let mut n = 0usize;
        let mut fd = 0i32;
        while fd < max && n < cap {
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
                unsafe {
                    std::ptr::write(
                        buffer.cast::<proc_fdinfo>().add(n),
                        proc_fdinfo {
                            proc_fd: fd,
                            proc_fdtype: 0,
                        },
                    );
                }
                n += 1;
            }
            fd += 1;
        }
        (n * stride) as i32
    }

    fn bsd(pid: i32) -> Option<proc_bsdinfo> {
        let bytes = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
        let close = bytes.iter().rposition(|b| *b == b')')?;
        let rest = bytes.get(close + 2..)?;
        let fields: Vec<&[u8]> = rest.split(|b| *b == b' ').collect();
        let state = *fields.first()?;
        let ppid: u32 = std::str::from_utf8(fields.get(1)?).ok()?.parse().ok()?;
        let pgid: u32 = std::str::from_utf8(fields.get(2)?).ok()?.parse().ok()?;
        let ticks: u64 = std::str::from_utf8(fields.get(19)?).ok()?.parse().ok()?;
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        let boot = btime()?;
        let sec = boot + ticks / hz;
        let usec = (ticks % hz) * 1_000_000 / hz;
        let zombie = state == b"Z" || state == b"X";
        Some(proc_bsdinfo {
            pbi_flags: u32::from(zombie) * 4,
            pbi_status: if zombie { SZOMB } else { 2 },
            pbi_pid: pid as u32,
            pbi_ppid: ppid,
            pbi_pgid: pgid,
            pbi_start_tvsec: sec,
            pbi_start_tvusec: usec,
        })
    }

    fn btime() -> Option<u64> {
        let text = std::fs::read_to_string("/proc/stat").ok()?;
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            if parts.next() == Some("btime") {
                return parts.next()?.parse().ok();
            }
        }
        None
    }

    /// Start time in ticks, and the inode of the executed file. An exec
    /// replaces that inode; the start time does not.
    fn identity(pid: i32) -> Option<(u64, i32)> {
        let bytes = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
        let close = bytes.iter().rposition(|b| *b == b')')?;
        let rest = bytes.get(close + 2..)?;
        let fields: Vec<&[u8]> = rest.split(|b| *b == b' ').collect();
        let ticks: u64 = std::str::from_utf8(fields.get(19)?).ok()?.parse().ok()?;
        let meta = std::fs::metadata(format!("/proc/{pid}/exe")).ok()?;
        use std::os::unix::fs::MetadataExt;
        Some((ticks, meta.ino() as i32))
    }

    pub const MNT_RDONLY: u32 = 1;
    pub const MNT_NOSUID: u32 = 2;
    pub const MAP_JIT: c_int = 0;
    pub const EV_DISPATCH: u16 = 0x80;
    pub const RENAME_SWAP: u32 = 0x2;
    pub const RENAME_EXCL: u32 = 0x4;
    pub const O_SYMLINK: c_int = 0;
    pub const O_EXLOCK: c_int = 0;
    pub const SO_NREAD: c_int = 0;
    pub const RTM_VERSION: c_int = 5;
    pub const RTM_IFINFO2: c_int = 0x12;
    pub const SIGINFO: c_int = 29;
    pub const SIGEMT: c_int = 7;
    pub const POSIX_SPAWN_CLOEXEC_DEFAULT: i16 = 0x4000;
    pub const TCP_KEEPALIVE: c_int = 0x10;
    pub const IPV6_BOUND_IF: c_int = 125;
    pub const IP_BOUND_IF: c_int = 25;
    pub const NET_RT_IFLIST2: c_int = 6;
    pub const PRIO_DARWIN_THREAD: c_int = 3;
    pub const PRIO_DARWIN_BG: c_int = 0x1000;
    pub const O_SHLOCK: c_int = 0x10;
    pub const MINCORE_INCORE: c_int = 0x1;
    pub const MINCORE_REFERENCED: c_int = 0x2;
    pub const MINCORE_REFERENCED_OTHER: c_int = 0x4;

    pub unsafe fn arc4random() -> u32 {
        let mut buf = [0u8; 4];
        unsafe {
            let n = libc::getrandom(buf.as_mut_ptr().cast(), 4, 0);
            if n == 4 {
                return u32::from_ne_bytes(buf);
            }
        }
        0
    }

    pub unsafe fn pthread_threadid_np(thread: libc::pthread_t, id: *mut u64) -> c_int {
        unsafe {
            if id.is_null() {
                return libc::EINVAL;
            }
            if thread == libc::pthread_self() {
                *id = libc::syscall(libc::SYS_gettid) as u64;
                0
            } else {
                *id = 0;
                libc::ENOTSUP
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct if_data64 {
        pub ifi_ibytes: u64,
        pub ifi_ipackets: u64,
        pub ifi_ierrors: u64,
        pub ifi_iqdrops: u64,
        pub ifi_imcasts: u64,
        pub ifi_obytes: u64,
        pub ifi_opackets: u64,
        pub ifi_oerrors: u64,
        pub ifi_collisions: u64,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct if_msghdr2 {
        pub ifm_msglen: u16,
        pub ifm_version: u8,
        pub ifm_type: u8,
        pub ifm_index: u16,
        pub ifm_data: if_data64,
        pub ifm_snd_drops: u32,
    }
    #[repr(C)]
    pub struct vnode_stat {
        pub vst_dev: u32,
        pub vst_ino: u64,
    }
    pub struct vnode_info {
        pub vi_stat: vnode_stat,
    }
    #[repr(C)]
    pub struct vnode_info_path {
        pub vip_vi: vnode_info,
        pub vip_path: [c_char; 1024],
    }

    pub unsafe fn pthread_jit_write_protect_np(_enable: c_int) {}

    pub unsafe fn renamex_np(from: *const c_char, to: *const c_char, flags: u32) -> c_int {
        let mut mapped = 0;
        if flags & RENAME_EXCL != 0 {
            mapped |= libc::RENAME_NOREPLACE;
        }
        if flags & RENAME_SWAP != 0 {
            mapped |= libc::RENAME_EXCHANGE;
        }
        unsafe { libc::renameat2(libc::AT_FDCWD, from, libc::AT_FDCWD, to, mapped) }
    }

    pub const UF_NODUMP: u32 = 0x0000_0001;
    pub const UF_IMMUTABLE: u32 = 0x0000_0002;
    pub const UF_APPEND: u32 = 0x0000_0004;
    pub const UF_OPAQUE: u32 = 0x0000_0008;
    pub const UF_TRACKED: u32 = 0x0000_0040;
    pub const UF_HIDDEN: u32 = 0x0000_8000;
    pub const SF_IMMUTABLE: u32 = 0x0002_0000;
    pub const SF_APPEND: u32 = 0x0004_0000;

    pub fn file_flags(_stat: &libc::stat) -> u32 {
        0
    }

    /// Linux has no file flags. The call fails, so a caller does not treat
    /// the flag as stored.
    pub unsafe fn fchflags(_fd: c_int, _flags: u32) -> c_int {
        unsafe { *__error() = libc::ENOTSUP };
        -1
    }

    pub unsafe fn chflags(_path: *const c_char, _flags: u32) -> c_int {
        unsafe { *__error() = libc::ENOTSUP };
        -1
    }
}

/// `st_gen`. Linux `stat` has none; the identity is the device and inode.
pub fn generation(stat: &libc::stat) -> u32 {
    #[cfg(target_os = "macos")]
    {
        stat.st_gen
    }
    #[cfg(target_os = "linux")]
    {
        let _ = stat;
        0
    }
}

pub unsafe fn punch_hole(fd: c_int, offset: i64, length: i64) -> c_int {
    #[cfg(target_os = "macos")]
    unsafe {
        let hole = libc::fpunchhole_t {
            fp_flags: 0,
            reserved: 0,
            fp_offset: offset,
            fp_length: length,
        };
        libc::fcntl(fd, libc::F_PUNCHHOLE, &hole)
    }
    #[cfg(not(target_os = "macos"))]
    unsafe {
        libc::fallocate(
            fd,
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset,
            length,
        )
    }
}

pub fn set_sun_len(addr: &mut libc::sockaddr_un, len: u8) {
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = len;
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (addr, len);
    }
}

pub fn sun_len(addr: &libc::sockaddr_un) -> u8 {
    #[cfg(target_os = "macos")]
    {
        addr.sun_len
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = addr;
        0
    }
}

pub unsafe fn mcontext_ptr(uc: *mut libc::ucontext_t) -> *mut libc::c_void {
    #[cfg(target_os = "macos")]
    unsafe {
        (*uc).uc_mcontext as *mut libc::c_void
    }
    #[cfg(not(target_os = "macos"))]
    unsafe {
        &raw mut (*uc).uc_mcontext as *mut libc::c_void
    }
}

pub unsafe fn set_thread_name(name: *const libc::c_char) -> libc::c_int {
    #[cfg(target_os = "macos")]
    unsafe {
        libc::pthread_setname_np(name);
        0
    }
    #[cfg(not(target_os = "macos"))]
    unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name)
    }
}

pub fn si_status(info: &libc::siginfo_t) -> i32 {
    #[cfg(target_os = "macos")]
    {
        info.si_status
    }
    #[cfg(not(target_os = "macos"))]
    unsafe {
        info.si_status()
    }
}

pub fn si_pid(info: &libc::siginfo_t) -> i32 {
    #[cfg(target_os = "macos")]
    {
        info.si_pid
    }
    #[cfg(not(target_os = "macos"))]
    unsafe {
        info.si_pid()
    }
}

pub fn si_addr(info: &libc::siginfo_t) -> u64 {
    #[cfg(target_os = "macos")]
    {
        info.si_addr as u64
    }
    #[cfg(not(target_os = "macos"))]
    unsafe {
        info.si_addr() as u64
    }
}

pub fn statfs_flags(statfs: &libc::statfs) -> u32 {
    #[cfg(target_os = "macos")]
    {
        statfs.f_flags as u32
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = statfs;
        0
    }
}

/// Birth time. Linux `stat` has none.
pub fn birth(stat: &libc::stat) -> (i64, i64) {
    #[cfg(target_os = "macos")]
    {
        (stat.st_birthtime, stat.st_birthtime_nsec)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = stat;
        (0, 0)
    }
}

//! `/dev/random` and `/dev/urandom` opened for writing. On Linux both are
//! mode 0666 and any process may write them: the bytes are mixed into the
//! input pool without entropy credit (random(4)), so a write returns its
//! length and changes nothing a reader can tell. Darwin's random device
//! takes writes from root only, and its pool is the kernel's own; the
//! layer takes the guest's write as Linux does, counting the bytes, and
//! leaves the host pool to seed itself. Reads stay the host device's.

use std::sync::LazyLock;

use super::fdtab::{self, Kind};
use crate::errno::EINVAL;

/// The device numbers of the host's random devices.
static DEVICES: LazyLock<Vec<libc::dev_t>> = LazyLock::new(|| {
    [c"/dev/random", c"/dev/urandom"]
        .iter()
        .filter_map(|path| {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: NUL-terminated path, local buffer.
            (unsafe { libc::stat(path.as_ptr(), &mut st) } == 0).then_some(st.st_rdev)
        })
        .collect()
});

/// Gives `fd` Linux's write semantics if it is a random device open for
/// writing (at open, and for an fd that arrived from elsewhere).
pub fn adopt(fd: i32) {
    // SAFETY: plain fcntl and fstat on a guest fd.
    let writable = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE != libc::O_RDONLY;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if writable
        && unsafe { libc::fstat(fd, &mut st) } == 0
        && st.st_mode & libc::S_IFMT == libc::S_IFCHR
        && DEVICES.contains(&st.st_rdev)
    {
        fdtab::insert(fd, Kind::Random);
    }
}

/// write/writev/pwrite: the whole write is taken.
pub fn write(iov: &[libc::iovec]) -> i64 {
    iov.iter()
        .try_fold(0u64, |t, v| t.checked_add(v.iov_len as u64))
        .filter(|&t| t <= isize::MAX as u64)
        .map_or(-(EINVAL as i64), |t| t as i64)
}

const HWRNG_MINOR: u64 = 183;

fn hwrng_path(guest: &str) -> bool {
    guest == "/dev/hw_random" || guest == "/dev/hwrng"
}

/// `/dev/hw_random` (misc 10:183). Reads are the host `getentropy`, the
/// same source as `getrandom`. None for any other path.
pub fn open_hwrng(guest: &str, flags: u64) -> Option<i64> {
    if !hwrng_path(guest) {
        return None;
    }
    if flags & 0o40000 != 0 {
        return Some(-(crate::errno::ENOTDIR as i64));
    }
    let mut host = libc::O_RDONLY;
    if flags & 0o2000000 != 0 {
        host |= libc::O_CLOEXEC;
    }
    // SAFETY: the carrier is always readable. The bytes come from getentropy.
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), host) };
    if fd < 0 {
        return Some(-(crate::errno::last() as i64));
    }
    fdtab::insert(fd, Kind::HwRng);
    Some(fd as i64)
}

pub fn stat_hwrng(guest: &str) -> Option<libc::stat> {
    if !hwrng_path(guest) {
        return None;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    st.st_mode = libc::S_IFCHR | 0o666;
    st.st_nlink = 1;
    st.st_rdev = ((10 as libc::dev_t) << 24) | HWRNG_MINOR as libc::dev_t;
    st.st_blksize = 4096;
    Some(st)
}

pub fn fstat_hwrng(fd: i32) -> Option<libc::stat> {
    matches!(fdtab::get(fd), Some(Kind::HwRng)).then(|| stat_hwrng("/dev/hw_random").unwrap())
}

/// A read of `/dev/hw_random`. `getentropy` fills at most 256 bytes per call.
pub fn read_hwrng(iov: &[libc::iovec]) -> i64 {
    let mut total = 0usize;
    for vector in iov {
        let mut done = 0;
        while done < vector.iov_len {
            let n = (vector.iov_len - done).min(256);
            let mut bytes = [0u8; 256];
            // SAFETY: getentropy writes only this buffer.
            if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), n) } < 0 {
                return if total + done > 0 {
                    (total + done) as i64
                } else {
                    -(crate::errno::last() as i64)
                };
            }
            let address = (vector.iov_base as u64).wrapping_add(done as u64);
            if let Err(error) = super::user_memory::write_exact(address, &bytes[..n]) {
                return if total + done > 0 {
                    (total + done) as i64
                } else {
                    -(error as i64)
                };
            }
            done += n;
        }
        total += vector.iov_len;
    }
    total as i64
}

#[cfg(test)]
mod tests {
    #[test]
    fn hw_random_is_misc_10_183() {
        assert!(super::open_hwrng("/dev/null", 0).is_none());
        let fd = super::open_hwrng("/dev/hw_random", 0).unwrap();
        assert!(fd >= 0);
        let st = super::fstat_hwrng(fd as i32).unwrap();
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFCHR);
        assert_eq!(st.st_rdev as u64 >> 24, 10);
        assert_eq!(st.st_rdev as u64 & 0xff_ffff, 183);
        let mut bytes = [0u8; 16];
        assert_eq!(
            unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) },
            0
        );
        unsafe { libc::close(fd as i32) };
    }
}

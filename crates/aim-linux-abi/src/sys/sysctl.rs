//! Integer `/proc/sys` files init reads back after writing.
//!
//! `kptr_restrict`, `mmap_rnd_bits` and `mmap_rnd_compat_bits` are
//! `proc_dointvec_minmax` files, mode 0644. A write outside the range is
//! `EINVAL` and leaves the stored value. A write needs `CAP_SYS_ADMIN`;
//! opening for write needs the mode (root or `CAP_DAC_OVERRIDE`). The value
//! lives in the runtime kernfs, one for every guest of that runtime, and a
//! read of any open fd copies it again so an ifstream opened before the
//! write sees the new text.

use crate::errno::{self, Errno};
use crate::sys::cred::{self, CAP_DAC_OVERRIDE, CAP_SYS_ADMIN};

struct Spec {
    path: &'static str,
    min: i64,
    max: i64,
    default: i64,
}

/// `kernel.kptr_restrict`: 0..=2, default 0.
const KPTR: Spec = Spec {
    path: "/proc/sys/kernel/kptr_restrict",
    min: 0,
    max: 2,
    default: 0,
};
/// arm64, 4 KiB pages, 39-bit VA: `mmap_rnd_bits` is 18..=24. Init walks
/// 33 down to 24 and keeps the first value that reads back.
const MMAP_RND: Spec = Spec {
    path: "/proc/sys/vm/mmap_rnd_bits",
    min: 18,
    max: 24,
    default: 24,
};
/// `mmap_rnd_compat_bits` for a 32-bit ABI: 0..=16. Init writes 16 when
/// `ro.product.cpu.abilist32` is set.
const MMAP_RND_COMPAT: Spec = Spec {
    path: "/proc/sys/vm/mmap_rnd_compat_bits",
    min: 0,
    max: 16,
    default: 16,
};

const SPECS: &[Spec] = &[KPTR, MMAP_RND, MMAP_RND_COMPAT];

fn spec(path: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|spec| spec.path == path)
}

pub(super) fn known(path: &str) -> bool {
    spec(path).is_some()
}

pub(super) fn static_path(path: &str) -> Option<&'static str> {
    spec(path).map(|spec| spec.path)
}

pub(super) fn text(path: &str) -> Result<Vec<u8>, Errno> {
    let spec = spec(path).ok_or(errno::ENOENT)?;
    Ok(format!("{}\n", value(spec)?).into_bytes())
}

fn value(spec: &Spec) -> Result<i64, Errno> {
    let (host, area) = crate::vfs::lookup(spec.path);
    if area != crate::vfs::Area::Kernfs {
        return Ok(spec.default);
    }
    match std::fs::read(host) {
        Ok(bytes) => parse_stored(&bytes, spec),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(spec.default),
        Err(error) => Err(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO))),
    }
}

fn parse_stored(bytes: &[u8], spec: &Spec) -> Result<i64, Errno> {
    let text = std::str::from_utf8(bytes).map_err(|_| errno::EIO)?;
    let parsed = text.trim().parse::<i64>().map_err(|_| errno::EIO)?;
    if (spec.min..=spec.max).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(errno::EIO)
    }
}

/// `proc_dointvec`: optional surrounding space, one integer, nothing else.
/// Out of range is `EINVAL` and the caller does not store it.
fn parse_write(bytes: &[u8], spec: &Spec) -> Result<i64, Errno> {
    let text = std::str::from_utf8(bytes).map_err(|_| errno::EINVAL)?;
    let parsed = text.trim().parse::<i64>().map_err(|_| errno::EINVAL)?;
    if (spec.min..=spec.max).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(errno::EINVAL)
    }
}

pub fn open(path: &str, write: bool, cloexec: bool) -> Option<i64> {
    let spec = spec(path)?;
    let id = cred::current();
    if write && id.uid[super::attrs::FS] != 0 && !cred::capable(CAP_DAC_OVERRIDE) {
        return Some(-(errno::EACCES as i64));
    }
    let bytes = match text(path) {
        Ok(bytes) => bytes,
        Err(error) => return Some(-(error as i64)),
    };
    let fd = super::knob::open(&bytes, cloexec, super::knob::Knob::Sysctl(spec.path));
    if fd >= 0 {
        // SAFETY: the fd is the one just published.
        unsafe {
            libc::fchmod(fd as i32, 0o644);
        }
    }
    Some(fd)
}

pub(super) fn write(path: &str, bytes: &[u8]) -> Result<Option<Vec<u8>>, Errno> {
    let spec = spec(path).ok_or(errno::ENOENT)?;
    if !cred::capable(CAP_SYS_ADMIN) {
        return Err(errno::EPERM);
    }
    let parsed = parse_write(bytes, spec)?;
    let (host, area) = crate::vfs::lookup(spec.path);
    if area != crate::vfs::Area::Kernfs {
        return Err(errno::EACCES);
    }
    let store = || -> std::io::Result<()> {
        if let Some(parent) = host.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&host, format!("{parsed}\n"))
    };
    store().map_err(|error| errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)))?;
    Ok(Some(format!("{parsed}\n").into_bytes()))
}

/// Copy the live value into `fd` and put the offset back, so a read sees
/// a write another fd made.
pub(super) fn refresh(fd: i32, path: &str) {
    let Ok(bytes) = text(path) else {
        return;
    };
    // SAFETY: the descriptor is a content file this process opened.
    unsafe {
        let pos = libc::lseek(fd, 0, libc::SEEK_CUR);
        if pos < 0 {
            return;
        }
        libc::ftruncate(fd, 0);
        libc::pwrite(fd, bytes.as_ptr().cast(), bytes.len(), 0);
        libc::lseek(fd, pos.min(bytes.len() as i64), libc::SEEK_SET);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_fd(fd: i64) -> String {
        let mut bytes = vec![0u8; 32];
        let n = crate::sys::fs::read([fd as u64, bytes.as_mut_ptr() as u64, bytes.len() as u64, 0, 0, 0]);
        assert!(n > 0, "{n}");
        bytes.truncate(n as usize);
        String::from_utf8(bytes).unwrap()
    }

    fn write_fd(fd: i64, text: &str) -> i64 {
        crate::sys::fs::write([
            fd as u64,
            text.as_ptr() as u64,
            text.len() as u64,
            0,
            0,
            0,
        ])
    }

    /// Init opens `kptr_restrict` for read, then writes 4, 3 and 2 and
    /// accepts the first value the still-open read fd returns.
    #[test]
    fn kptr_restrict_persists_only_zero_through_two() {
        let _view = crate::vfs::test_view();
        struct Cred(crate::sys::cred::Identity);
        impl Drop for Cred {
            fn drop(&mut self) {
                crate::sys::cred::init(self.0.clone(), None);
            }
        }
        let cred = Cred(crate::sys::cred::current());
        let path = "/proc/sys/kernel/kptr_restrict";
        let read = super::procfs::open(path, 0, libc::O_RDONLY).unwrap();
        assert!(read >= 0);
        assert_eq!(read_fd(read), "0\n");
        let write = super::procfs::open(path, libc::O_WRONLY as u64, libc::O_WRONLY).unwrap();
        assert!(write >= 0);
        assert_eq!(write_fd(write, "4\n"), -(errno::EINVAL as i64));
        assert_eq!(write_fd(write, "3\n"), -(errno::EINVAL as i64));
        assert_eq!(
            crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(read_fd(read), "0\n");
        assert_eq!(write_fd(write, "2\n"), 2);
        assert_eq!(
            crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(read_fd(read), "2\n");
        assert_eq!(write_fd(write, "9"), -(errno::EINVAL as i64));
        assert_eq!(write_fd(write, "\n"), -(errno::EINVAL as i64));
        assert_eq!(
            crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(read_fd(read), "2\n");
        let mut weak = cred.0.clone();
        weak.cap_eff &= !(1 << CAP_SYS_ADMIN);
        crate::sys::cred::init(weak, None);
        assert_eq!(write_fd(write, "0\n"), -(errno::EPERM as i64));
        crate::sys::cred::init(cred.0.clone(), None);
        assert_eq!(
            crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(read_fd(read), "2\n");
        let mut user = cred.0.clone();
        user.uid[super::attrs::FS] = 1;
        user.cap_eff &= !(1 << CAP_DAC_OVERRIDE);
        crate::sys::cred::init(user, None);
        assert_eq!(
            super::procfs::open(path, libc::O_WRONLY as u64, libc::O_WRONLY).unwrap(),
            -(errno::EACCES as i64)
        );
        crate::sys::cred::init(cred.0.clone(), None);
        assert_eq!(
            super::procfs::open("/proc/sys/kernel/not_a_sysctl", 0, libc::O_RDONLY).unwrap(),
            -(errno::ENOENT as i64)
        );
        for fd in [read, write] {
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
    }

    #[test]
    fn mmap_rnd_bits_keeps_the_arm64_range() {
        let _view = crate::vfs::test_view();
        let path = "/proc/sys/vm/mmap_rnd_bits";
        let read = super::procfs::open(path, 0, libc::O_RDONLY).unwrap();
        let write = super::procfs::open(path, libc::O_WRONLY as u64, libc::O_WRONLY).unwrap();
        assert_eq!(read_fd(read), "24\n");
        assert_eq!(write_fd(write, "33\n"), -(errno::EINVAL as i64));
        assert_eq!(write_fd(write, "17\n"), -(errno::EINVAL as i64));
        assert_eq!(
            crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(read_fd(read), "24\n");
        assert_eq!(write_fd(write, "18\n"), 3);
        assert_eq!(
            crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(read_fd(read), "18\n");
        let compat = "/proc/sys/vm/mmap_rnd_compat_bits";
        let compat_write =
            super::procfs::open(compat, libc::O_RDWR as u64, libc::O_RDWR).unwrap();
        assert_eq!(write_fd(compat_write, "17\n"), -(errno::EINVAL as i64));
        assert_eq!(write_fd(compat_write, "16\n"), 3);
        assert_eq!(
            crate::sys::fs::lseek([compat_write as u64, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(read_fd(compat_write), "16\n");
        for fd in [read, write, compat_write] {
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
    }
}

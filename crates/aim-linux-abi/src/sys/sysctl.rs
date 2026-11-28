//! Integer `/proc/sys` files init reads back after writing.
//!
//! `kptr_restrict`, `mmap_rnd_bits`, `mmap_rnd_compat_bits`,
//! `unprivileged_bpf_disabled`, `bpf_jit_enable` and `bpf_jit_kallsyms`
//! are `proc_dointvec_minmax` files, mode 0644. A write outside the range
//! is `EINVAL` and leaves the stored value. A write needs `CAP_SYS_ADMIN`
//! (`proc_dointvec_minmax_sysadmin` and `bpf_unpriv_handler` return
//! `EPERM` without it). Opening for write needs the mode (root or
//! `CAP_DAC_OVERRIDE`), which is `EACCES`. A write on a descriptor opened
//! read-only is `EBADF`. The value lives in the runtime kernfs, one for
//! every guest of that runtime, whether or not the path lookup currently
//! reports the kernfs area. A read of any open fd copies it again so an
//! ifstream opened before the write sees the new text.
//!
//! `unprivileged_bpf_disabled` is 0 (allowed), 1 (disabled and locked
//! until this boot ends) or 2 (disabled, and a later write may change
//! it). The 6.12 kernel this layer reports ships
//! `CONFIG_BPF_UNPRIV_DEFAULT_OFF`, so the boot value is 2.
//! `bpf_unpriv_handler` refuses a write away from 1 with `EPERM` and
//! leaves the 1. `bpf_jit_enable` is 1 only (`CONFIG_BPF_JIT_ALWAYS_ON`);
//! `bpf_jit_kallsyms` is 0 or 1.

use std::path::PathBuf;

use crate::errno::{self, Errno};
use crate::sys::cred::{self, CAP_DAC_OVERRIDE, CAP_SYS_ADMIN};

struct Spec {
    path: &'static str,
    min: i64,
    max: i64,
    default: i64,
    /// Once the stored value is this, a different write is `EPERM` and
    /// the stored value stays. `unprivileged_bpf_disabled` locks at 1.
    lock: Option<i64>,
}

/// `kernel.kptr_restrict`: 0..=2, default 0.
const KPTR: Spec = Spec {
    path: "/proc/sys/kernel/kptr_restrict",
    min: 0,
    max: 2,
    default: 0,
    lock: None,
};
/// `kernel.unprivileged_bpf_disabled`: 0..=2, default 2, locked at 1.
const BPF_UNPRIV: Spec = Spec {
    path: "/proc/sys/kernel/unprivileged_bpf_disabled",
    min: 0,
    max: 2,
    default: 2,
    lock: Some(1),
};
/// arm64, 4 KiB pages, 39-bit VA: `mmap_rnd_bits` is 18..=24. Init walks
/// 33 down to 24 and keeps the first value that reads back.
const MMAP_RND: Spec = Spec {
    path: "/proc/sys/vm/mmap_rnd_bits",
    min: 18,
    max: 24,
    default: 24,
    lock: None,
};
/// `mmap_rnd_compat_bits` for a 32-bit ABI: 0..=16. Init writes 16 when
/// `ro.product.cpu.abilist32` is set.
const MMAP_RND_COMPAT: Spec = Spec {
    path: "/proc/sys/vm/mmap_rnd_compat_bits",
    min: 0,
    max: 16,
    default: 16,
    lock: None,
};
/// `net.core.bpf_jit_enable` with `CONFIG_BPF_JIT_ALWAYS_ON`: only 1.
const BPF_JIT: Spec = Spec {
    path: "/proc/sys/net/core/bpf_jit_enable",
    min: 1,
    max: 1,
    default: 1,
    lock: None,
};
/// `net.core.bpf_jit_kallsyms`: 0 or 1, default 0.
const BPF_JIT_KALLSYMS: Spec = Spec {
    path: "/proc/sys/net/core/bpf_jit_kallsyms",
    min: 0,
    max: 1,
    default: 0,
    lock: None,
};

const SPECS: &[Spec] = &[
    KPTR,
    BPF_UNPRIV,
    MMAP_RND,
    MMAP_RND_COMPAT,
    BPF_JIT,
    BPF_JIT_KALLSYMS,
];

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

/// Host file for `spec`. A kernfs mount of the path is that mount's file.
/// Otherwise the runtime kernfs holds it: a covering mount must not turn
/// an in-range write into `EACCES`.
fn store_path(spec: &Spec) -> PathBuf {
    let (host, area) = crate::vfs::lookup(spec.path);
    if area == crate::vfs::Area::Kernfs {
        return host;
    }
    match crate::vfs::runtime_dir() {
        Some(runtime) => runtime.join("kernfs").join(spec.path.trim_start_matches('/')),
        None => host,
    }
}

fn value(spec: &Spec) -> Result<i64, Errno> {
    match std::fs::read(store_path(spec)) {
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

pub fn open(path: &str, accmode: u64, cloexec: bool) -> Option<i64> {
    let spec = spec(path)?;
    let accmode = (accmode & 0o3) as i32;
    let id = cred::current();
    if accmode != libc::O_RDONLY
        && id.uid[super::attrs::FS] != 0
        && !cred::capable(CAP_DAC_OVERRIDE)
    {
        return Some(-(errno::EACCES as i64));
    }
    let bytes = match text(path) {
        Ok(bytes) => bytes,
        Err(error) => return Some(-(error as i64)),
    };
    let fd = super::knob::open(&bytes, cloexec, super::knob::Knob::Sysctl(spec.path));
    if fd >= 0 {
        super::knob::set_access(fd as i32, accmode);
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
    if let Some(locked) = spec.lock {
        let current = value(spec)?;
        if current == locked && parsed != locked {
            return Err(errno::EPERM);
        }
    }
    let host = store_path(spec);
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
        let read = super::super::procfs::open(path, 0, libc::O_RDONLY).unwrap();
        assert!(read >= 0);
        assert_eq!(read_fd(read), "0\n");
        // The host file is O_RDWR. The guest open was read-only, so a
        // write is EBADF, not the handler's EACCES or EPERM.
        assert_eq!(write_fd(read, "2\n"), -(errno::EBADF as i64));
        let write = super::super::procfs::open(path, libc::O_WRONLY as u64, libc::O_WRONLY).unwrap();
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
        user.uid[super::super::attrs::FS] = 1;
        user.cap_eff &= !(1 << CAP_DAC_OVERRIDE);
        crate::sys::cred::init(user, None);
        assert_eq!(
            super::super::procfs::open(path, libc::O_WRONLY as u64, libc::O_WRONLY).unwrap(),
            -(errno::EACCES as i64)
        );
        crate::sys::cred::init(cred.0.clone(), None);
        assert_eq!(
            super::super::procfs::open("/proc/sys/kernel/not_a_sysctl", 0, libc::O_RDONLY).unwrap(),
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
        let read = super::super::procfs::open(path, 0, libc::O_RDONLY).unwrap();
        let write = super::super::procfs::open(path, libc::O_WRONLY as u64, libc::O_WRONLY).unwrap();
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
            super::super::procfs::open(compat, libc::O_RDWR as u64, libc::O_RDWR).unwrap();
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

    /// A mount that hides `/proc` is not the sysctl. Init's write of `2`
    /// still persists, and a missing `CAP_SYS_ADMIN` is still `EPERM`.
    #[test]
    fn kptr_restrict_persists_when_proc_is_not_the_kernfs_mount() {
        let (_view, root) = crate::vfs::test_view();
        let path = "/proc/sys/kernel/kptr_restrict";
        let cover = root.join("cover-proc-sys");
        std::fs::create_dir_all(&cover).unwrap();
        crate::vfs::add_mount(
            "/proc/sys",
            cover,
            crate::vfs::Area::Image,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        assert_ne!(
            crate::vfs::lookup(path).1,
            crate::vfs::Area::Kernfs
        );
        let host = super::store_path(super::spec(path).unwrap());
        let previous = std::fs::read(&host).ok();
        let read = super::super::procfs::open(path, 0, libc::O_RDONLY).unwrap();
        let write = super::super::procfs::open(path, libc::O_WRONLY as u64, libc::O_WRONLY).unwrap();
        assert!(read >= 0 && write >= 0, "{read} {write}");
        assert_eq!(write_fd(write, "4\n"), -(errno::EINVAL as i64));
        assert_eq!(write_fd(write, "2\n"), 2);
        assert_eq!(crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(read_fd(read), "2\n");
        let mut weak = crate::sys::cred::current();
        weak.cap_eff &= !(1 << CAP_SYS_ADMIN);
        let saved = crate::sys::cred::current();
        crate::sys::cred::init(weak, None);
        assert_eq!(write_fd(write, "0\n"), -(errno::EPERM as i64));
        crate::sys::cred::init(saved, None);
        assert_eq!(crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(read_fd(read), "2\n");
        for fd in [read, write] {
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
        match previous {
            Some(bytes) => std::fs::write(&host, bytes).unwrap(),
            None => {
                let _ = std::fs::remove_file(&host);
            }
        }
        let _ = crate::vfs::remove_mount("/proc/sys");
    }

    /// NetBpfLoad opens `unprivileged_bpf_disabled` `O_WRONLY|O_CLOEXEC`
    /// and writes `0`. 1 stays until this process drops the file. A uid
    /// other than root, without `CAP_DAC_OVERRIDE`, cannot open it for
    /// write. The two JIT knobs it writes next take the same open.
    #[test]
    fn unprivileged_bpf_disabled_locks_at_one() {
        let _view = crate::vfs::test_view();
        struct Cred(crate::sys::cred::Identity);
        impl Drop for Cred {
            fn drop(&mut self) {
                crate::sys::cred::init(self.0.clone(), None);
            }
        }
        let cred = Cred(crate::sys::cred::current());
        let path = "/proc/sys/kernel/unprivileged_bpf_disabled";
        let store = crate::vfs::runtime_dir()
            .unwrap()
            .join("kernfs/proc/sys/kernel/unprivileged_bpf_disabled");
        let _ = std::fs::remove_file(&store);
        let flags = libc::O_WRONLY as u64 | libc::O_CLOEXEC as u64;
        let write = super::super::procfs::open(path, flags, libc::O_WRONLY | libc::O_CLOEXEC)
            .unwrap();
        assert!(write >= 0, "{write}");
        let cloexec = unsafe { libc::fcntl(write as i32, libc::F_GETFD) };
        assert!(cloexec & libc::FD_CLOEXEC != 0, "{cloexec}");
        let read = super::super::procfs::open(path, 0, libc::O_RDONLY).unwrap();
        assert_eq!(read_fd(read), "2\n");
        assert_eq!(write_fd(write, "0\n"), 2);
        assert_eq!(crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(read_fd(read), "0\n");
        assert_eq!(write_fd(write, "3\n"), -(errno::EINVAL as i64));
        assert_eq!(crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(read_fd(read), "0\n");
        assert_eq!(write_fd(write, "1\n"), 2);
        assert_eq!(write_fd(write, "0\n"), -(errno::EPERM as i64));
        assert_eq!(write_fd(write, "2\n"), -(errno::EPERM as i64));
        assert_eq!(write_fd(write, "1\n"), 2);
        assert_eq!(crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(read_fd(read), "1\n");
        let mut weak = cred.0.clone();
        weak.cap_eff &= !(1 << CAP_SYS_ADMIN);
        crate::sys::cred::init(weak, None);
        assert_eq!(write_fd(write, "0\n"), -(errno::EPERM as i64));
        crate::sys::cred::init(cred.0.clone(), None);
        assert_eq!(crate::sys::fs::lseek([read as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(read_fd(read), "1\n");
        let mut user = cred.0.clone();
        user.uid[super::super::attrs::FS] = 1;
        user.cap_eff &= !(1 << CAP_DAC_OVERRIDE);
        crate::sys::cred::init(user, None);
        assert_eq!(
            super::super::procfs::open(path, flags, libc::O_WRONLY).unwrap(),
            -(errno::EACCES as i64)
        );
        let user_read = super::super::procfs::open(path, 0, libc::O_RDONLY).unwrap();
        assert!(user_read >= 0, "{user_read}");
        assert_eq!(read_fd(user_read), "1\n");
        crate::sys::cred::init(cred.0.clone(), None);
        let both = libc::O_RDWR as u64 | libc::O_CLOEXEC as u64;
        for jit in [
            "/proc/sys/net/core/bpf_jit_enable",
            "/proc/sys/net/core/bpf_jit_kallsyms",
        ] {
            let fd = super::super::procfs::open(jit, both, libc::O_RDWR).unwrap();
            assert!(fd >= 0, "{jit} {fd}");
            assert_eq!(write_fd(fd, "1\n"), 2, "{jit}");
            assert_eq!(crate::sys::fs::lseek([fd as u64, 0, 0, 0, 0, 0]), 0);
            assert_eq!(read_fd(fd), "1\n", "{jit}");
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
        let jit = super::super::procfs::open(
            "/proc/sys/net/core/bpf_jit_enable",
            flags,
            libc::O_WRONLY,
        )
        .unwrap();
        assert_eq!(write_fd(jit, "0\n"), -(errno::EINVAL as i64));
        assert_eq!(crate::sys::fs::close([jit as u64, 0, 0, 0, 0, 0]), 0);
        for fd in [read, write, user_read] {
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
        let _ = std::fs::remove_file(&store);
        for name in ["bpf_jit_enable", "bpf_jit_kallsyms"] {
            let _ = std::fs::remove_file(
                crate::vfs::runtime_dir()
                    .unwrap()
                    .join(format!("kernfs/proc/sys/net/core/{name}")),
            );
        }
    }
}

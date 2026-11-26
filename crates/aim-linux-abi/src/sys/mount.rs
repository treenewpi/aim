//! Mount namespaces: `unshare(CLONE_NEWNS)`, `setns`, `mount` and `umount2`.
//!
//! zygote unshares its mount namespace and mounts storage views for each
//! child (`MountEmulatedStorage`, app data isolation): bind mounts and
//! tmpfs. `MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE` and `MS_REC` change the
//! mount they name. `unshare(CLONE_NEWNS)` keeps a shared mount in that
//! peer group. A later mount or unmount under a shared mount is applied
//! in the peers and the slaves of that group, at each peer's own path.
//! A private mount is not. Android's `/apex` is private before the
//! bootstrap namespace is copied, so a mount under the bootstrap bind of
//! `/bootstrap-apex` lands on `/bootstrap-apex` in the default namespace.
//! The other namespaces are answered "unsupported" (ADR 0012 appendix).
//! A plain fork after `setns` into the default namespace keeps that
//! journal. The child walks the shared root; `/apex` there stays the
//! private tmpfs. `mount` of fstype `sysfs` installs a kernfs whose
//! host directory has the kernel's top-level mount points, including
//! `/sys/fs`. Userspace mkdirs `/sys/fs/bpf` there, then `mount` of
//! fstype `bpf` installs an empty bpffs on that existing directory.
//! A path that is not a directory is `ENOTDIR`, and a missing path is
//! `ENOENT`. A remount names the filesystem that is already mounted.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

use crate::errno::{EBUSY, EINVAL, ENODEV, ENOENT, ENOTDIR, EPERM};
use crate::vfs::{self, Area, LINUX_AT_FDCWD};

const CLONE_FILES: u64 = 0x400;
const CLONE_FS: u64 = 0x200;
const CLONE_NEWNS: u64 = 0x20000;
const CLONE_SYSVSEM: u64 = 0x40000;

const MS_RDONLY: u64 = 1;
const MS_REMOUNT: u64 = 32;
const MS_BIND: u64 = 4096;
const MS_MOVE: u64 = 8192;
const MS_UNBINDABLE: u64 = 1 << 17;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SLAVE: u64 = 1 << 19;
const MS_SHARED: u64 = 1 << 20;
const PROPAGATION: u64 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;

const MNT_DETACH: u64 = 2;
const UMOUNT_NOFOLLOW: u64 = 8;

const CAP_SYS_ADMIN: u32 = 21;

fn remove_mount(guest: &str, flags: u64) -> Result<bool, crate::errno::Errno> {
    if flags & MNT_DETACH != 0 {
        vfs::detach_mount(guest)
    } else if vfs::mount_has_children(guest)? {
        Err(EBUSY)
    } else {
        vfs::remove_mount(guest)
    }
}

pub fn unshare(a: [u64; 6]) -> i64 {
    // Files and the SysV undo list are already this process's. `CLONE_FS`
    // gives the caller a private `fs_struct`. `CLONE_NEWNS` implies that,
    // then copies the mount namespace for this thread only.
    if a[0] & !(CLONE_FILES | CLONE_FS | CLONE_SYSVSEM | CLONE_NEWNS) != 0 {
        return -(EINVAL as i64);
    }
    if a[0] & CLONE_NEWNS != 0 && !super::cred::capable(CAP_SYS_ADMIN) {
        return -(EPERM as i64);
    }
    if a[0] & (CLONE_FS | CLONE_NEWNS) != 0 {
        vfs::unshare_fs();
    }
    if a[0] & CLONE_NEWNS != 0 {
        if let Err(error) = vfs::split_mount_namespace() {
            return -(error as i64);
        }
    }
    0
}

const CAP_SYS_CHROOT: u32 = 18;

/// `setns(2)`. A mount-namespace fd joins that namespace. `nstype` 0 takes
/// the fd's type. A fd of another kind is `EINVAL`. A closed fd is `EBADF`.
pub fn setns(a: [u64; 6]) -> i64 {
    let fd = a[0] as i32;
    let nstype = a[1];
    if fd < 0 {
        return -(crate::errno::EBADF as i64);
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat into a local buffer. A bad fd is EBADF, not EINVAL.
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return -(crate::errno::EBADF as i64);
    }
    let Some(ns) = super::procfs::mount_namespace_of(fd) else {
        return -(EINVAL as i64);
    };
    if nstype != 0 && nstype != CLONE_NEWNS {
        return -(EINVAL as i64);
    }
    // setns(2) for a mount namespace: CAP_SYS_ADMIN and CAP_SYS_CHROOT.
    // `mntns_install` returns EINVAL when `current->fs->users != 1`.
    // Another thread in the group is not that check: `unshare(CLONE_NEWNS)`
    // has already unshared `fs`, so this thread can switch while it lives.
    if !super::cred::capable(CAP_SYS_ADMIN) || !super::cred::capable(CAP_SYS_CHROOT) {
        return -(EPERM as i64);
    }
    if vfs::fs_is_shared() {
        return -(EINVAL as i64);
    }
    match vfs::switch_mount_namespace(&ns) {
        Ok(()) => 0,
        Err(error) => -(error as i64),
    }
}

/// Top-level directories `sysfs_fill_super` creates. `/sys/fs` is
/// `fs_kobj`. `bpf`, `pstore` and `selinux` are not among them:
/// userspace mkdirs `/sys/fs/bpf`, and the others stay missing.
fn sysfs_dir() -> Result<PathBuf, i64> {
    let dir = tmpfs_dir(&[])?;
    for name in [
        "block", "bus", "class", "dev", "devices", "firmware", "fs", "kernel", "module", "power",
    ] {
        std::fs::create_dir(dir.join(name)).map_err(|error| {
            -(crate::errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64)
        })?;
    }
    Ok(dir)
}

fn resolve(path: u64, follow: bool) -> Result<vfs::Resolved, i64> {
    // SAFETY: guest string.
    let owned_path = super::guest_cstr(path).map_err(|error| -(error as i64))?;
    let path = owned_path.as_slice();
    vfs::resolve(LINUX_AT_FDCWD, path, follow).map_err(|e| -(e as i64))
}

fn is_dir(r: &vfs::Resolved) -> Result<bool, i64> {
    if let Some(route) = vfs::fuse_route(&r.guest) {
        let stat = super::fuse_client::stat(&route, None, None).map_err(|error| -(error as i64))?;
        return Ok(stat.st_mode & libc::S_IFMT == libc::S_IFDIR);
    }
    // SAFETY: host path, local buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(r.host.as_ptr(), &mut st) } != 0 {
        return Err(-(ENOENT as i64));
    }
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

/// A fresh host directory for a tmpfs mount, under the runtime directory
/// (per boot) or the host's temporary directory.
fn tmpfs_dir(data: &[u8]) -> Result<PathBuf, i64> {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let base = vfs::runtime_dir()
        .map(|r| r.join("tmpfs"))
        .unwrap_or_else(std::env::temp_dir);
    // SAFETY: trivial.
    let pid = unsafe { libc::getpid() };
    let dir = base.join(format!("{pid}.{}", SEQ.fetch_add(1, Relaxed)));
    std::fs::create_dir_all(&dir).map_err(|_| -(ENOENT as i64))?;
    let mode = String::from_utf8_lossy(data)
        .split(',')
        .find_map(|o| o.strip_prefix("mode="))
        .and_then(|m| u32::from_str_radix(m, 8).ok())
        .unwrap_or(0o1777);
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode & 0o7777));
    Ok(dir)
}

pub fn mount(a: [u64; 6]) -> i64 {
    match do_mount(a) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

fn do_mount(a: [u64; 6]) -> Result<(), i64> {
    let flags = a[3];
    if !super::cred::capable(CAP_SYS_ADMIN) {
        return Err(-(EPERM as i64));
    }
    let target = resolve(a[1], true)?;
    if !is_dir(&target)? && flags & (MS_BIND | MS_MOVE) == 0 {
        return Err(-(ENOTDIR as i64));
    }
    if flags & MS_REMOUNT != 0 {
        if vfs::remount_fuse(&target.guest, flags & MS_RDONLY != 0)
            .map_err(|error| -(error as i64))?
        {
            return Ok(());
        }
        // A directory of another filesystem is not that filesystem's
        // mount. Linux returns EINVAL when the path is not a mount
        // root. A named fstype has to be the one mounted there: reporting
        // success for `sysfs` while `/sys` is still the image leaves
        // every later lookup on the image.
        if !vfs::is_mountpoint(&target.guest) {
            return Err(-(EINVAL as i64));
        }
        if a[2] != 0 {
            let asked = super::guest_cstr(a[2]).map_err(|error| -(error as i64))?;
            let asked = std::str::from_utf8(&asked).map_err(|_| -(EINVAL as i64))?;
            if vfs::fstype(&target.guest).as_deref() != Some(asked) {
                return Err(-(EINVAL as i64));
            }
        }
        // Mount options (read-only, nosuid, ...) are not enforced.
        return Ok(());
    }
    if flags & PROPAGATION != 0 {
        return vfs::set_mount_propagation(&target.guest, flags).map_err(|error| -(error as i64));
    }
    if flags & MS_BIND != 0 {
        let source = resolve(a[0], true)?;
        if is_dir(&source)? != is_dir(&target)? {
            return Err(-(ENOTDIR as i64));
        }
        // A new bind has its source's mount options, whatever else the
        // flags ask (mount(2)): MS_RDONLY makes a bind read-only only by a
        // later remount, so the bind keeps its source's area.
        let area = source.area;
        // Linux recursive bind clones visible submounts, including virtual
        // FUSE routes whose nodes do not exist in the host anchor tree.
        let host = PathBuf::from(OsStr::from_bytes(source.host.as_bytes()));
        vfs::bind_mount_recursive(
            &source.guest,
            &target.guest,
            host,
            area,
            flags & 0x4000 != 0,
        )
        .map_err(|error| -(error as i64))?;
        return Ok(());
    }
    if flags & MS_MOVE != 0 {
        let source = resolve(a[0], true)?;
        return if vfs::move_mount(&source.guest, &target.guest).map_err(|error| -(error as i64))? {
            Ok(())
        } else {
            Err(-(EINVAL as i64))
        };
    }
    // SAFETY: guest strings.
    let fstype = super::guest_cstr(a[2]).map_err(|error| -(error as i64))?;
    match fstype.as_slice() {
        b"fuse" | b"fuse.media" => {
            let data = if a[4] == 0 {
                Vec::new()
            } else {
                super::user_memory::read_cstr(a[4], 16384).map_err(|error| -(error as i64))?
            };
            let options = super::fuse_mount::parse(&data).map_err(|error| -(error as i64))?;
            let session =
                super::fuse::session_for_fd(options.fd).map_err(|error| -(error as i64))?;
            super::fuse::Client::from_key(&session)
                .and_then(|client| client.mount())
                .map_err(|error| -(error as i64))?;
            let source = super::guest_cstr(a[0]).map_err(|error| -(error as i64))?;
            let source = std::str::from_utf8(&source).map_err(|_| -(EINVAL as i64))?;
            vfs::add_fuse_mount(
                &target.guest,
                session.transport().to_path_buf(),
                PathBuf::from(OsStr::from_bytes(target.host.as_bytes())),
                source,
                &options,
                flags & MS_RDONLY != 0,
            )
            .map_err(|error| -(error as i64))?;
            match super::fuse_sysfs::mounted(&session) {
                Ok(_) => Ok(()),
                Err(error) => {
                    vfs::remove_mount(&target.guest).map_err(|error| -(error as i64))?;
                    Err(-(error as i64))
                }
            }
        }
        b"tmpfs" => {
            // SAFETY: guest string (options), may be null.
            let data = if a[4] == 0 {
                Vec::new()
            } else {
                super::user_memory::read_cstr(a[4], 16384).map_err(|error| -(error as i64))?
            };
            let dir = tmpfs_dir(&data)?;
            let area = if flags & MS_RDONLY != 0 {
                Area::Image
            } else {
                Area::Writable
            };
            vfs::add_mount(&target.guest, dir, area, "tmpfs", "tmpfs")
                .map_err(|error| -(error as i64))?;
            Ok(())
        }
        b"binder" => {
            let data = if a[4] == 0 {
                Vec::new()
            } else {
                super::user_memory::read_cstr(a[4], 4096).map_err(|error| -(error as i64))?
            };
            super::binder::mount_fs(&target.guest, &data)?;
            Ok(())
        }
        b"sysfs" => {
            let dir = sysfs_dir()?;
            vfs::add_mount(&target.guest, dir, Area::Kernfs, "sysfs", "sysfs")
                .map_err(|error| -(error as i64))?;
            Ok(())
        }
        b"bpf" => {
            // `bpf_fill_super`: a new bpffs root is mode 01777. The
            // directory is the superblock. Pins are files in it. The
            // mount point is the directory userspace already created.
            let dir = tmpfs_dir(&[])?;
            vfs::add_mount(&target.guest, dir, Area::Writable, "bpf", "bpf")
                .map_err(|error| -(error as i64))?;
            Ok(())
        }
        b"ext4" => {
            let source = super::guest_cstr(a[0]).map_err(|error| -(error as i64))?;
            let source = std::str::from_utf8(&source).map_err(|_| -(EINVAL as i64))?;
            super::loopdev::mount_ext4(source, &target.guest, flags & MS_RDONLY != 0)
                .map_err(|error| -(error as i64))?;
            Ok(())
        }
        _ => Err(-(ENODEV as i64)),
    }
}

pub fn umount2(a: [u64; 6]) -> i64 {
    if a[1] & !(MNT_DETACH | UMOUNT_NOFOLLOW | 1 | 4) != 0 {
        return -(EINVAL as i64);
    }
    if !super::cred::capable(CAP_SYS_ADMIN) {
        return -(EPERM as i64);
    }
    // A disconnected FUSE mount can no longer resolve children, but Linux
    // still unmounts an exact mountpoint from the namespace's mount table.
    // Try the canonical absolute spelling directly before walking the
    // filesystem; relative paths and paths needing dot normalization keep the
    // ordinary resolver semantics below.
    let owned_path = match super::guest_cstr(a[0]) {
        Ok(path) => path,
        Err(error) => return -(error as i64),
    };
    if let Ok(path) = std::str::from_utf8(&owned_path)
        && path.starts_with('/')
        && (path == "/"
            || path
                .split('/')
                .skip(1)
                .all(|component| !component.is_empty() && component != "." && component != ".."))
    {
        match remove_mount(path, a[1]) {
            Ok(true) => return 0,
            Ok(false) => {}
            Err(error) => return -(error as i64),
        }
    }
    let target = match resolve(a[0], a[1] & UMOUNT_NOFOLLOW == 0) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let removed = match remove_mount(&target.guest, a[1]) {
        Ok(removed) => removed,
        Err(error) => return -(error as i64),
    };
    if removed {
        0
    } else if target.guest == "/" {
        -(EBUSY as i64)
    } else {
        -(EINVAL as i64)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;
    use crate::sys::{attrs, fsops};

    fn p(s: &CString) -> u64 {
        s.as_ptr() as u64
    }

    fn at(path: &str) -> CString {
        CString::new(path).unwrap()
    }

    fn owner(path: &str) -> Option<u32> {
        let r = vfs::resolve(LINUX_AT_FDCWD, path.as_bytes(), true).unwrap();
        attrs::lookup(attrs::Host::Path(&r.host), || r.guest.clone()).uid
    }

    fn host(path: &str) -> PathBuf {
        let r = vfs::resolve(LINUX_AT_FDCWD, path.as_bytes(), true).unwrap();
        PathBuf::from(OsStr::from_bytes(r.host.as_bytes()))
    }

    fn mkdir(path: &str, mode: u64, uid: u64) {
        let c = at(path);
        let fd = LINUX_AT_FDCWD as u64;
        assert_eq!(
            fsops::mkdirat([fd, p(&c), mode, 0, 0, 0]),
            0,
            "mkdir {path}"
        );
        assert_eq!(
            fsops::fchownat([fd, p(&c), uid, uid, 0, 0]),
            0,
            "chown {path}"
        );
    }

    fn bind(source: &str, target: &str) {
        let (s, t) = (at(source), at(target));
        assert_eq!(
            mount([p(&s), p(&t), 0, MS_BIND | 0x4000, 0, 0]),
            0,
            "bind {target}"
        );
    }

    /// A bind asking MS_RDONLY has its source's area, as Linux ignores
    /// the flag on a new bind: a change below it is seen by the next walk.
    #[test]
    fn a_read_only_bind_keeps_its_sources_area() {
        let (_view, _) = vfs::test_view();
        let sub = host("/data/robind-source/sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(host("/data/robind-source/other")).unwrap();
        std::fs::create_dir_all(host("/data/robind-target")).unwrap();
        let (source, target) = (at("/data/robind-source"), at("/data/robind-target"));
        assert_eq!(
            mount([p(&source), p(&target), 0, MS_BIND | MS_RDONLY, 0, 0]),
            0
        );
        let walked = vfs::resolve(LINUX_AT_FDCWD, b"/data/robind-target/sub", true).unwrap();
        assert_eq!(walked.area, Area::Writable);
        std::fs::remove_dir(&sub).unwrap();
        std::os::unix::fs::symlink("other", &sub).unwrap();
        assert_eq!(
            vfs::resolve(LINUX_AT_FDCWD, b"/data/robind-target/sub", true)
                .unwrap()
                .guest,
            "/data/robind-target/other"
        );
    }

    /// Zygote's `isolateAppData` for one app of user 0, as the original
    /// runs it in the app's child (Zygote.cpp, Android 16), after installd
    /// made the app's data directories.
    #[test]
    fn zygote_isolates_app_data() {
        let (_view, _) = vfs::test_view();
        const APP: u64 = 10123;
        // installd: create_app_data through /data/data (a directory).
        // init.rc and vold made these.
        for dir in ["/data/data", "/data/user", "/data/user_de/0"] {
            std::fs::create_dir_all(host(dir)).unwrap();
        }
        mkdir("/data/data/com.example", 0o700, APP);
        mkdir("/data/user_de/0/com.example", 0o700, APP);
        mkdir("/data/data/com.other", 0o700, APP + 1);
        // The same directory, whichever mount reaches it.
        assert_eq!(owner("/data/user/0/com.example"), Some(APP as u32));
        assert_eq!(
            owner("/data_mirror/data_ce/null/0/com.example"),
            Some(APP as u32)
        );

        assert_eq!(unshare([CLONE_NEWNS, 0, 0, 0, 0, 0]), 0);
        let (tmpfs, opts) = (at("tmpfs"), at("uid=0,gid=0,mode=0751"));
        for dir in ["/data/data", "/data/user", "/data/user_de"] {
            let t = at(dir);
            let flags = 0x2 | 0x4 | 0x8; // MS_NOSUID | MS_NODEV | MS_NOEXEC
            assert_eq!(mount([p(&tmpfs), p(&t), p(&tmpfs), flags, p(&opts), 0]), 0);
        }
        // The tmpfs over /data/user hides the path map's /data/user/0.
        let (target, link) = (at("/data/data"), at("/data/user/0"));
        let fd = LINUX_AT_FDCWD as u64;
        assert_eq!(fsops::symlinkat([p(&target), fd, p(&link), 0, 0, 0]), 0);
        mkdir("/data/user_de/0", 0o711, 0);
        // DE, then CE (getAppDataDirName finds the directory by name).
        mkdir("/data/user_de/0/com.example", 0o700, 0);
        bind(
            "/data_mirror/data_de/null/0/com.example",
            "/data/user_de/0/com.example",
        );
        assert!(host("/data_mirror/data_ce/null/0/com.example").is_dir());
        mkdir("/data/data/com.example", 0o700, 0);
        bind(
            "/data_mirror/data_ce/null/0/com.example",
            "/data/data/com.example",
        );

        // The app: its data directory is ApplicationInfo.dataDir, and its
        // databases are SQLite files created there.
        let data = host("/data_mirror/data_ce/null/0/com.example");
        assert_eq!(host("/data/user/0/com.example"), data);
        assert_eq!(owner("/data/user/0/com.example"), Some(APP as u32));
        assert_eq!(owner("/data/user_de/0/com.example"), Some(APP as u32));
        mkdir("/data/user/0/com.example/databases", 0o771, APP);
        let db = at("/data/user/0/com.example/databases/contacts2.db");
        let flags = 0o2 | 0o100 | 0o2000000; // O_RDWR | O_CREAT | O_CLOEXEC
        let fd = super::super::fs::openat([fd, p(&db), flags, 0o660, 0, 0]);
        assert!(fd >= 0, "open: {fd}");
        // Through the layer, which forgets its description (#2113).
        assert_eq!(super::super::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        assert!(data.join("databases/contacts2.db").is_file());
        // Other apps' directories are hidden.
        assert!(!host("/data/user/0/com.other").exists());
        assert!(!host("/data/data/com.other").exists());

        for dir in [
            "/data/data/com.example",
            "/data/user_de/0/com.example",
            "/data/user_de",
            "/data/user",
            "/data/data",
        ] {
            let t = at(dir);
            assert_eq!(umount2([p(&t), MNT_DETACH, 0, 0, 0, 0]), 0, "umount {dir}");
        }
        // The stubs zygote gave root's owner did not change the app's.
        assert_eq!(owner("/data/data/com.example"), Some(APP as u32));
        assert_eq!(owner("/data/user/0/com.example"), Some(APP as u32));
    }

    fn propagation_line(guest: &str) -> String {
        vfs::own_mounts_text()
            .lines()
            .find(|line| *line == format!("propagation\t{guest}\tshared")
                || *line == format!("propagation\t{guest}\tslave")
                || *line == format!("propagation\t{guest}\tprivate")
                || line.starts_with(&format!("propagation\t{guest}\t")))
            .unwrap_or("(no propagation rule)")
            .to_owned()
    }

    fn mount_line(guest: &str) -> Option<String> {
        vfs::own_mounts_text()
            .lines()
            .find(|line| {
                let mut fields = line.split('\t');
                let _kind = fields.next();
                fields.next() == Some(guest)
            })
            .map(str::to_owned)
    }

    fn journal_events() -> Vec<String> {
        let text = vfs::own_mounts_text();
        let id = text
            .lines()
            .find_map(|line| line.strip_prefix("namespace-owner\t"))
            .unwrap();
        let runtime = text
            .lines()
            .find_map(|line| line.strip_prefix("namespace-runtime\t"))
            .unwrap();
        aim_storage::mount_namespace::Namespace::open(std::path::Path::new(runtime), id)
            .unwrap()
            .read()
            .unwrap()
            .events
    }

    fn shared_id(guest: &str) -> u64 {
        vfs::mount_points()
            .unwrap_or_else(|error| panic!("mount_points errno={error}"))
            .into_iter()
            .filter(|point| point.guest == guest)
            .map(|point| point.shared)
            .max()
            .unwrap_or(0)
    }

    /// `SetupMountNamespaces` then apexd-bootstrap, as Android init runs it.
    ///
    /// `/` is made slave and then shared. The `/apex` tmpfs is mounted and
    /// made `MS_SHARED|MS_REC`. `unshare(CLONE_NEWNS)` copies that peer
    /// group into the default namespace. A later mount under `/apex` in
    /// the bootstrap namespace is visible in the default namespace, and
    /// unmounting it removes it from both. A mount whose parent was made
    /// private stays in the namespace that created it.
    #[test]
    fn apex_mounts_propagate_from_the_bootstrap_namespace() {
        let (_view, root) = vfs::test_view();
        std::fs::create_dir_all(root.join("root/apex")).unwrap();
        std::fs::create_dir_all(host("/data/peer")).unwrap();
        let boot = super::super::procfs::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        let slave = MS_SLAVE | 0x4000;
        let shared = MS_SHARED | 0x4000;
        let private = MS_PRIVATE | 0x4000;
        let slash = at("/");
        let apex = at("/apex");
        let tmpfs = at("tmpfs");
        let mode = at("mode=0755");
        assert_eq!(mount([0, p(&slash), 0, slave, 0, 0]), 0, "MS_SLAVE|MS_REC /");
        assert_eq!(
            mount([0, p(&slash), 0, shared, 0, 0]),
            0,
            "MS_SHARED|MS_REC /"
        );
        assert_eq!(
            mount([p(&tmpfs), p(&apex), p(&tmpfs), 0, p(&mode), 0]),
            0,
            "mount tmpfs /apex"
        );
        assert_eq!(
            mount([0, p(&apex), 0, shared, 0, 0]),
            0,
            "MS_SHARED|MS_REC /apex ({})",
            propagation_line("/apex")
        );
        assert!(
            propagation_line("/apex").ends_with("\tshared")
                || (propagation_line("/").ends_with("\tshared")
                    && !propagation_line("/apex").ends_with("\tprivate")
                    && !propagation_line("/apex").ends_with("\tslave")),
            "journal recorded /apex private: {}\n{}",
            propagation_line("/apex"),
            vfs::own_mounts_text()
        );
        let apex_group = shared_id("/apex");
        assert_ne!(apex_group, 0, "MS_SHARED left /apex with no peer group");

        assert_eq!(unshare([CLONE_NEWNS, 0, 0, 0, 0, 0]), 0);
        let default_ns =
            super::super::procfs::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        assert_eq!(
            shared_id("/apex"),
            apex_group,
            "unshare dropped /apex out of its peer group\n{}",
            vfs::own_mounts_text()
        );
        assert_eq!(setns([boot as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);

        let runtime = at("/apex/com.android.runtime");
        assert_eq!(
            fsops::mkdirat([LINUX_AT_FDCWD as u64, p(&runtime), 0o755, 0, 0, 0]),
            0,
            "mkdir /apex/com.android.runtime"
        );
        assert_eq!(
            mount([p(&tmpfs), p(&runtime), p(&tmpfs), 0, p(&mode), 0]),
            0,
            "mount under /apex"
        );
        let marker = host("/apex/com.android.runtime");
        assert_ne!(
            marker,
            host("/apex").join("com.android.runtime"),
            "creating namespace does not walk the new mount\n{}",
            vfs::own_mounts_text()
        );
        let marker = marker.join("linker64");
        std::fs::write(&marker, b"runtime").unwrap();
        let child_group = shared_id("/apex/com.android.runtime");
        assert_ne!(
            child_group, 0,
            "a mount under shared /apex got no peer group\n{}",
            vfs::own_mounts_text()
        );

        assert_eq!(setns([default_ns as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        let propagated = journal_events();
        assert!(
            propagated.iter().any(|event| {
                event.starts_with(&format!("propagated\t{child_group}\t"))
                    && event.contains("\t/apex/com.android.runtime\t")
            }),
            "default journal has no peer of the apex mount\n{propagated:?}"
        );
        let seen = host("/apex/com.android.runtime/linker64");
        assert_eq!(
            std::fs::read(&seen).ok(),
            Some(b"runtime".to_vec()),
            "default namespace did not receive the /apex mount\n{}",
            vfs::own_mounts_text()
        );
        // A fork child reloads the namespace journal rather than the
        // parent's in-memory table. The propagated mount has to be in
        // that journal, or the child sees the empty /apex tmpfs.
        let inherited = vfs::fork_mounts_text(false).unwrap();
        vfs::load_own_mounts(&inherited).unwrap();
        let reloaded = vfs::own_mounts_text();
        assert!(
            reloaded.contains("/apex/com.android.runtime"),
            "child reload dropped the propagated mount\n{reloaded}"
        );
        let child = vfs::resolve(LINUX_AT_FDCWD, b"/apex/com.android.runtime/linker64", true)
            .unwrap_or_else(|error| {
                panic!(
                    "child linker64 errno={error} ({})\n{reloaded}",
                    super::super::names::errno_name(error)
                )
            });
        assert_eq!(
            std::fs::read(OsStr::from_bytes(child.host.as_bytes())).ok(),
            Some(b"runtime".to_vec()),
            "child reload walks {} rather than the propagated mount\n{reloaded}",
            child.host.to_string_lossy()
        );
        assert_eq!(
            shared_id("/apex/com.android.runtime"),
            child_group,
            "propagated mount is not in the creating mount's peer group"
        );

        assert_eq!(setns([boot as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        assert_eq!(umount2([p(&runtime), 0, 0, 0, 0, 0]), 0, "umount apex child");
        assert_eq!(setns([default_ns as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        assert!(
            mount_line("/apex/com.android.runtime").is_none(),
            "umount did not propagate\n{}",
            vfs::own_mounts_text()
        );
        let again = vfs::resolve(LINUX_AT_FDCWD, b"/apex/com.android.runtime/linker64", true)
            .expect("lookup");
        assert!(
            std::fs::read(OsStr::from_bytes(again.host.as_bytes())).is_err(),
            "default namespace still reads the unmounted apex at {}\n{}",
            again.host.to_string_lossy(),
            vfs::own_mounts_text()
        );

        assert_eq!(setns([boot as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        let peer = at("/data/peer");
        assert_eq!(mount([p(&tmpfs), p(&peer), p(&tmpfs), 0, p(&mode), 0]), 0);
        assert_eq!(mount([0, p(&peer), 0, private, 0, 0]), 0, "MS_PRIVATE|MS_REC");
        let hidden = at("/data/peer/hidden");
        assert_eq!(
            fsops::mkdirat([LINUX_AT_FDCWD as u64, p(&hidden), 0o755, 0, 0, 0]),
            0
        );
        assert_eq!(mount([p(&tmpfs), p(&hidden), p(&tmpfs), 0, p(&mode), 0]), 0);
        std::fs::write(host("/data/peer/hidden").join("secret"), b"no").unwrap();
        assert_eq!(setns([default_ns as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        assert!(
            mount_line("/data/peer/hidden").is_none(),
            "a private mount propagated\n{}",
            vfs::own_mounts_text()
        );
        let secret =
            vfs::resolve(LINUX_AT_FDCWD, b"/data/peer/hidden/secret", true).expect("lookup");
        assert!(
            std::fs::read(OsStr::from_bytes(secret.host.as_bytes())).is_err(),
            "a private mount's file is visible at {}\n{}",
            secret.host.to_string_lossy(),
            vfs::own_mounts_text()
        );

        assert_eq!(setns([boot as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        for dir in ["/data/peer/hidden", "/data/peer", "/apex"] {
            let t = at(dir);
            assert_eq!(umount2([p(&t), MNT_DETACH, 0, 0, 0, 0]), 0, "cleanup {dir}");
        }
        assert_eq!(
            super::super::fs::close([default_ns as u64, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(super::super::fs::close([boot as u64, 0, 0, 0, 0, 0]), 0);
    }

    /// Android 16: `/apex` is `MS_PRIVATE` in the only namespace, then
    /// `/bootstrap-apex` is bound onto `/apex` in the bootstrap namespace.
    /// A later ext4 mount under that bind is `/bootstrap-apex/...` in the
    /// default namespace. The default `/apex` stays the private tmpfs.
    /// Dropping the loop table does not stop a read: the tree belongs to
    /// the mount.
    #[test]
    fn private_apex_reads_the_bootstrap_ext4_superblock() {
        let (_view, root) = vfs::test_view();
        std::fs::create_dir_all(root.join("root/apex")).unwrap();
        std::fs::create_dir_all(root.join("root/bootstrap-apex")).unwrap();
        let (image, manifest) = super::super::ext4ro::manifest_fixture();
        let dir = std::env::temp_dir().join(format!(
            "aim-apex-private-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let payload = dir.join("payload.img");
        std::fs::write(&payload, &image).unwrap();
        let backing = std::ffi::CString::new(payload.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(backing.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(fd >= 0, "open payload");
        let minor = super::super::loopdev::ctl_free().unwrap() as u32;
        super::super::loopdev::configure(minor, fd, 4096, &[0; 232]).unwrap();
        unsafe { libc::close(fd) };
        let source = format!("/dev/block/loop{minor}");

        let boot = super::super::procfs::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        let shared = MS_SHARED | 0x4000;
        let slash = at("/");
        let apex = at("/apex");
        let bootstrap = at("/bootstrap-apex");
        let tmpfs = at("tmpfs");
        let mode = at("mode=0755");
        assert_eq!(mount([0, p(&slash), 0, shared, 0, 0]), 0, "MS_SHARED|MS_REC /");
        assert_eq!(
            mount([p(&tmpfs), p(&apex), p(&tmpfs), 0, p(&mode), 0]),
            0,
            "tmpfs /apex"
        );
        assert_eq!(
            mount([p(&tmpfs), p(&bootstrap), p(&tmpfs), 0, p(&mode), 0]),
            0,
            "tmpfs /bootstrap-apex"
        );
        assert_eq!(
            mount([0, p(&apex), 0, MS_PRIVATE, 0, 0]),
            0,
            "MS_PRIVATE /apex"
        );
        assert_eq!(shared_id("/apex"), 0, "MS_PRIVATE left /apex shared");
        assert_ne!(
            shared_id("/bootstrap-apex"),
            0,
            "/bootstrap-apex lost its peer group"
        );

        assert_eq!(unshare([CLONE_NEWNS, 0, 0, 0, 0, 0]), 0);
        let default_ns =
            super::super::procfs::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        assert_eq!(
            shared_id("/apex"),
            0,
            "default /apex is a peer\n{}",
            vfs::own_mounts_text()
        );
        assert_eq!(setns([boot as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);

        let bind = MS_BIND | 0x4000;
        assert_eq!(
            mount([p(&bootstrap), p(&apex), 0, bind, 0, 0]),
            0,
            "bind /bootstrap-apex /apex"
        );
        let runtime = at("/apex/com.android.runtime");
        assert_eq!(
            fsops::mkdirat([LINUX_AT_FDCWD as u64, p(&runtime), 0o755, 0, 0, 0]),
            0,
            "mkdir runtime"
        );
        super::super::loopdev::mount_ext4(&source, "/apex/com.android.runtime", true)
            .unwrap_or_else(|error| panic!("mount_ext4 errno={error}"));

        assert_eq!(setns([default_ns as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        assert!(
            mount_line("/apex/com.android.runtime").is_none(),
            "private /apex received the bootstrap mount\n{}",
            vfs::own_mounts_text()
        );
        assert!(
            mount_line("/bootstrap-apex/com.android.runtime").is_some(),
            "default /bootstrap-apex has no ext4\n{}",
            vfs::own_mounts_text()
        );
        let events = journal_events();
        assert!(
            events
                .iter()
                .any(|event| event.contains("\t/bootstrap-apex/com.android.runtime\t")),
            "default journal did not rewrite the path\n{events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| event.contains("\t/apex/com.android.runtime\t")),
            "default journal still names /apex/com.android.runtime\n{events:?}"
        );

        super::super::loopdev::detach_all_backings();
        assert!(
            super::super::loopdev::superblock_sources()
                .iter()
                .any(|held| held == &source),
            "detaching the device dropped the ext4 superblock"
        );
        let reader = super::super::loopdev::source_reader_errno(&source);
        assert_ne!(reader, 0, "the device table still opens {source}");

        let guest = "/bootstrap-apex/com.android.runtime/apex_manifest.pb";
        let found = vfs::resolve(LINUX_AT_FDCWD, guest.as_bytes(), true).unwrap_or_else(|error| {
            panic!(
                "default stat errno={error} ({})\n{}",
                super::super::names::errno_name(error),
                vfs::own_mounts_text()
            )
        });
        let bytes = std::fs::read(OsStr::from_bytes(found.host.as_bytes())).unwrap_or_else(|error| {
            panic!(
                "default read errno={} host={}\n{}",
                error.raw_os_error().unwrap_or(0),
                found.host.to_string_lossy(),
                vfs::own_mounts_text()
            )
        });
        assert!(
            bytes.len() >= manifest.len(),
            "short read {} bytes",
            bytes.len()
        );
        assert_eq!(&bytes[..manifest.len()], manifest);
        let page = std::fs::File::open(OsStr::from_bytes(found.host.as_bytes())).unwrap();
        use std::io::Read;
        let mut buf = [0u8; 4096];
        let n = page.take(4096).read(&mut buf).unwrap();
        assert!(n > 0, "first page was empty");
        assert_eq!(&buf[..manifest.len().min(n)], &manifest[..manifest.len().min(n)]);

        let hidden = "/apex/com.android.runtime/apex_manifest.pb";
        let hidden = vfs::resolve(LINUX_AT_FDCWD, hidden.as_bytes(), true).expect("lookup");
        assert!(
            std::fs::read(OsStr::from_bytes(hidden.host.as_bytes())).is_err(),
            "default /apex reads the bootstrap payload at {}\n{}",
            hidden.host.to_string_lossy(),
            vfs::own_mounts_text()
        );

        assert_eq!(setns([boot as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        assert_eq!(umount2([p(&runtime), 0, 0, 0, 0, 0]), 0, "umount bootstrap ext4");
        assert_eq!(setns([default_ns as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        assert!(
            mount_line("/bootstrap-apex/com.android.runtime").is_none(),
            "umount did not leave the default namespace\n{}",
            vfs::own_mounts_text()
        );
        assert_eq!(setns([boot as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        for dir in [
            "/apex/com.android.runtime",
            "/bootstrap-apex/com.android.runtime",
            "/apex",
            "/bootstrap-apex",
        ] {
            let t = at(dir);
            let _ = umount2([p(&t), MNT_DETACH, 0, 0, 0, 0]);
        }
        assert_eq!(
            super::super::fs::close([default_ns as u64, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(super::super::fs::close([boot as u64, 0, 0, 0, 0, 0]), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The inode a process hands out first. A fork child starts there too,
    /// which is the parent's bootstrap namespace.
    const FIRST_NS: u64 = 0x1000_0001;

    fn open_guest(path: &str) -> i64 {
        let path = at(path);
        super::super::fs::openat([LINUX_AT_FDCWD as u64, p(&path), 0, 0, 0, 0])
    }

    fn assert_default_namespace_walks() {
        let fd = open_guest("/system/bin/vdc");
        assert!(
            fd >= 0,
            "open /system/bin/vdc errno {} ({})\n{}",
            -fd,
            super::super::names::errno_name((-fd) as i32),
            vfs::own_mounts_text()
        );
        assert_eq!(super::super::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        let found = vfs::resolve(LINUX_AT_FDCWD, b"/system/bin/vdc", true).unwrap_or_else(|error| {
            panic!(
                "resolve /system/bin/vdc errno={error} ({})\n{}",
                super::super::names::errno_name(error),
                vfs::own_mounts_text()
            )
        });
        let bytes = std::fs::read(OsStr::from_bytes(found.host.as_bytes())).unwrap_or_else(|error| {
            panic!(
                "read /system/bin/vdc errno={} host={}\n{}",
                error.raw_os_error().unwrap_or(0),
                found.host.to_string_lossy(),
                vfs::own_mounts_text()
            )
        });
        assert_eq!(bytes, b"vdc-stand-in");

        let fd = open_guest("/dev/null");
        assert!(
            fd >= 0,
            "open /dev/null errno {} ({})\n{}",
            -fd,
            super::super::names::errno_name((-fd) as i32),
            vfs::own_mounts_text()
        );
        assert_eq!(super::super::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);

        let fd = open_guest("/proc/self/ns/mnt");
        assert!(
            fd >= 0,
            "open /proc/self/ns/mnt errno {} ({})\n{}",
            -fd,
            super::super::names::errno_name((-fd) as i32),
            vfs::own_mounts_text()
        );
        assert_eq!(super::super::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);

        let apex = vfs::resolve(LINUX_AT_FDCWD, b"/apex/marker", true).unwrap_or_else(|error| {
            panic!(
                "resolve /apex/marker errno={error}\n{}",
                vfs::own_mounts_text()
            )
        });
        assert!(
            std::fs::read(OsStr::from_bytes(apex.host.as_bytes())).is_err(),
            "default /apex has the bootstrap marker at {}\n{}",
            apex.host.to_string_lossy(),
            vfs::own_mounts_text()
        );
        let peer = std::fs::read(host("/bootstrap-apex/marker")).unwrap_or_else(|error| {
            panic!(
                "read /bootstrap-apex/marker errno={} host={}\n{}",
                error.raw_os_error().unwrap_or(0),
                host("/bootstrap-apex/marker").display(),
                vfs::own_mounts_text()
            )
        });
        assert_eq!(peer, b"bootstrap");
        let text = vfs::own_mounts_text();
        assert!(
            text.lines().any(|line| line.contains("\t/apex\t") && line.contains("tmpfs")),
            "default /apex is not the private tmpfs\n{text}"
        );
        assert!(
            text.lines().any(|line| line == "propagation\t/apex\tprivate"),
            "default /apex is not private\n{text}"
        );
        assert!(
            !text.lines().any(|line| line.contains("\t/apex/marker\t")),
            "default /apex received the bootstrap marker mount\n{text}"
        );
    }

    fn area_name(area: vfs::Area) -> &'static str {
        match area {
            vfs::Area::Image => "ro",
            vfs::Area::Writable => "rw",
            vfs::Area::Kernfs => "kernfs",
            vfs::Area::HostDevice => "host-device",
            vfs::Area::Input => "input",
        }
    }

    fn write_namespace_image(path: &std::path::Path, image: &vfs::ForkNamespaces) {
        let mut out = format!(
            "current\t{}\t{}\n",
            image.current,
            u8::from(image.new_namespace)
        );
        for ns in &image.namespaces {
            out.push_str(&format!(
                "ns\t{}\t{}\t{}\t{}\n",
                ns.ino,
                ns.event,
                ns.journal_id.as_deref().unwrap_or("-"),
                u8::from(ns.private_mounts)
            ));
            for (root, code) in &ns.propagation {
                out.push_str(&format!("prop\t{}\t{}\t{}\n", ns.ino, root, code));
            }
            for mount in &ns.mounts {
                let (session, relative, uid, gid, allow, perm, read_only) = match &mount.fuse {
                    Some(route) => (
                        route.session.display().to_string(),
                        route.relative.clone(),
                        route.uid.to_string(),
                        route.gid.to_string(),
                        u8::from(route.allow_other).to_string(),
                        u8::from(route.default_permissions).to_string(),
                        u8::from(route.read_only).to_string(),
                    ),
                    None => (
                        "-".into(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ),
                };
                out.push_str(&format!(
                    "mount\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                    ns.ino,
                    area_name(mount.area),
                    mount.guest,
                    mount.host.display(),
                    mount.source.as_deref().unwrap_or(""),
                    mount.fstype.as_deref().unwrap_or(""),
                    u8::from(mount.own),
                    mount.seq,
                    u8::from(mount.shared_fuse),
                    u8::from(mount.projected_fuse),
                    mount.bind_source.as_deref().unwrap_or(""),
                    session,
                    relative,
                    uid,
                    gid,
                    allow,
                    perm,
                    read_only
                ));
            }
        }
        std::fs::write(path, out).unwrap();
    }

    fn read_namespace_image(text: &str) -> vfs::ForkNamespaces {
        let mut current = 0;
        let mut new_namespace = false;
        let mut namespaces: Vec<vfs::ForkNamespace> = Vec::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            match f.as_slice() {
                ["current", ino, flag] => {
                    current = ino.parse().unwrap();
                    new_namespace = *flag == "1";
                }
                ["ns", ino, event, journal, private] => namespaces.push(vfs::ForkNamespace {
                    ino: ino.parse().unwrap(),
                    event: event.parse().unwrap(),
                    journal_id: (*journal != "-").then(|| (*journal).to_owned()),
                    private_mounts: *private == "1",
                    propagation: Vec::new(),
                    mounts: Vec::new(),
                }),
                ["prop", ino, root, code] => {
                    let ino: u64 = ino.parse().unwrap();
                    namespaces
                        .iter_mut()
                        .find(|ns| ns.ino == ino)
                        .unwrap()
                        .propagation
                        .push(((*root).to_owned(), code.parse().unwrap()));
                }
                ["mount", ino, area, guest, host, source, fstype, own, seq, shared, projected, bind, session, relative, uid, gid, allow, perm, read_only] =>
                {
                    let ino: u64 = ino.parse().unwrap();
                    let area = match *area {
                        "ro" => vfs::Area::Image,
                        "rw" => vfs::Area::Writable,
                        "kernfs" => vfs::Area::Kernfs,
                        "host-device" => vfs::Area::HostDevice,
                        "input" => vfs::Area::Input,
                        other => panic!("area {other}"),
                    };
                    let fuse = (*session != "-").then(|| vfs::FuseRoute {
                        session: PathBuf::from(*session),
                        relative: (*relative).to_owned(),
                        uid: uid.parse().unwrap(),
                        gid: gid.parse().unwrap(),
                        allow_other: *allow == "1",
                        default_permissions: *perm == "1",
                        read_only: *read_only == "1",
                    });
                    namespaces
                        .iter_mut()
                        .find(|ns| ns.ino == ino)
                        .unwrap()
                        .mounts
                        .push(vfs::ForkMount {
                            guest: (*guest).to_owned(),
                            host: PathBuf::from(*host),
                            area,
                            source: (!source.is_empty()).then(|| (*source).to_owned()),
                            fstype: (!fstype.is_empty()).then(|| (*fstype).to_owned()),
                            own: *own == "1",
                            seq: seq.parse().unwrap(),
                            shared_fuse: *shared == "1",
                            projected_fuse: *projected == "1",
                            bind_source: (!bind.is_empty()).then(|| (*bind).to_owned()),
                            fuse,
                        });
                }
                _ => panic!("namespace image line {line}"),
            }
        }
        vfs::ForkNamespaces {
            new_namespace,
            current,
            namespaces,
        }
    }

    /// Android 16's namespace switch, then a plain fork. The child is a new
    /// process: it reloads the default journal and installs the inherited
    /// namespaces, whose bootstrap inode collides with the child's first
    /// inode. It must still open the image root, `/dev/null` and `/proc`,
    /// and `/apex` must still be the empty private tmpfs.
    #[test]
    fn default_namespace_fork_walks_shared_root() {
        let (_view, root) = vfs::test_view();
        let image_root = root.join("root");
        std::fs::create_dir_all(image_root.join("system/bin")).unwrap();
        std::fs::write(image_root.join("system/bin/vdc"), b"vdc-stand-in").unwrap();
        std::fs::create_dir_all(image_root.join("apex")).unwrap();
        std::fs::create_dir_all(image_root.join("bootstrap-apex")).unwrap();

        let boot = super::super::procfs::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        let shared = MS_SHARED | 0x4000;
        let slash = at("/");
        let apex = at("/apex");
        let bootstrap = at("/bootstrap-apex");
        let tmpfs = at("tmpfs");
        let mode = at("mode=0755");
        assert_eq!(mount([0, p(&slash), 0, shared, 0, 0]), 0, "MS_SHARED|MS_REC /");
        assert_eq!(mount([p(&tmpfs), p(&apex), p(&tmpfs), 0, p(&mode), 0]), 0);
        assert_eq!(
            mount([p(&tmpfs), p(&bootstrap), p(&tmpfs), 0, p(&mode), 0]),
            0
        );
        assert_eq!(mount([0, p(&apex), 0, MS_PRIVATE, 0, 0]), 0, "MS_PRIVATE /apex");
        assert_eq!(unshare([CLONE_NEWNS, 0, 0, 0, 0, 0]), 0);
        let default_ns =
            super::super::procfs::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        assert_eq!(setns([boot as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        let bind = MS_BIND | 0x4000;
        assert_eq!(mount([p(&bootstrap), p(&apex), 0, bind, 0, 0]), 0);
        std::fs::write(host("/apex").join("marker"), b"bootstrap").unwrap();
        assert_eq!(setns([default_ns as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        assert_default_namespace_walks();

        let text = vfs::fork_mounts_text(false).unwrap();
        let image = vfs::capture_fork_namespaces(false);
        assert!(
            image
                .namespaces
                .iter()
                .any(|ns| ns.ino == FIRST_NS && ns.ino != image.current),
            "the inherited bootstrap inode is not the child's first inode; current={} inos={:?}",
            image.current,
            image.namespaces.iter().map(|ns| ns.ino).collect::<Vec<_>>()
        );
        let scratch = std::env::temp_dir().join(format!(
            "aim-ns-fork-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&scratch).unwrap();
        let mounts_path = scratch.join("mounts");
        let image_path = scratch.join("namespaces");
        std::fs::write(&mounts_path, &text).unwrap();
        write_namespace_image(&image_path, &image);

        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                }
                let _ = self.0.wait();
            }
        }
        use std::io::Write;
        // The mount syscalls install the guest signal forwarder. A child
        // exit must not be delivered through that Darwin frame on Linux.
        unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "sys::mount::tests::default_namespace_child_walks",
                    "--ignored",
                    "--nocapture",
                ])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        writeln!(
            child.0.stdin.take().unwrap(),
            "{}\n{}\n{}\n{}",
            image_root.display(),
            root.join("run/path-map").display(),
            mounts_path.display(),
            image_path.display()
        )
        .unwrap();
        let status = child.0.wait().unwrap();
        assert!(status.success(), "fork child walk failed: {status}");
        let _ = std::fs::remove_dir_all(&scratch);

        assert_eq!(setns([boot as u64, CLONE_NEWNS, 0, 0, 0, 0]), 0);
        for dir in ["/apex", "/bootstrap-apex"] {
            let t = at(dir);
            let _ = umount2([p(&t), MNT_DETACH, 0, 0, 0, 0]);
        }
        assert_eq!(
            super::super::fs::close([default_ns as u64, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(super::super::fs::close([boot as u64, 0, 0, 0, 0, 0]), 0);
    }

    /// Subprocess of [`default_namespace_fork_walks_shared_root`].
    #[test]
    #[ignore = "subprocess of default_namespace_fork_walks_shared_root"]
    fn default_namespace_child_walks() {
        use std::io::BufRead;
        let mut input = std::io::BufReader::new(std::io::stdin());
        let mut lines = Vec::new();
        for _ in 0..4 {
            let mut line = String::new();
            input.read_line(&mut line).unwrap();
            lines.push(line.trim_end().to_owned());
        }
        vfs::init(std::path::Path::new(&lines[0]), Some(std::path::Path::new(&lines[1]))).unwrap();
        let text = std::fs::read_to_string(&lines[2]).unwrap();
        vfs::load_own_mounts(&text).unwrap();
        let image = read_namespace_image(&std::fs::read_to_string(&lines[3]).unwrap());
        assert!(
            vfs::install_fork_namespaces(&image),
            "fork namespaces did not install\n{}",
            vfs::own_mounts_text()
        );
        assert_default_namespace_walks();
    }

    /// `mount` of fstype `bpf` needs a directory that is already there.
    /// A missing path stays `ENOENT`. An existing directory is covered
    /// by a new empty bpffs.
    #[test]
    fn bpf_mount_creates_the_sysfs_mount_point() {
        let (_view, root) = vfs::test_view();
        let sys = root.join("kernfs-sys");
        std::fs::create_dir_all(sys.join("fs/bpf")).unwrap();
        vfs::add_mount(
            "/sys",
            sys,
            Area::Kernfs,
            "sysfs",
            "sysfs",
        )
        .unwrap();
        let (source, target, fstype) = (at("bpf"), at("/sys/fs/bpf"), at("bpf"));
        let flags = 2 | 4 | 8;
        assert_eq!(
            mount([p(&source), p(&target), p(&fstype), flags, 0, 0]),
            0
        );
        assert_eq!(vfs::fstype("/sys/fs/bpf").as_deref(), Some("bpf"));
        let (host, area) = vfs::lookup("/sys/fs/bpf");
        assert_eq!(area, Area::Writable);
        assert!(std::fs::read_dir(&host).unwrap().next().is_none());
        mkdir("/sys/fs/bpf/netd_shared", 0o755, 0);
        assert!(host.join("netd_shared").is_dir());
        let pstore = at("/sys/fs/pstore");
        assert_eq!(
            mount([p(&source), p(&pstore), p(&fstype), flags, 0, 0]),
            -(ENOENT as i64)
        );
        let elsewhere = root.join("bpf-elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        vfs::add_mount(
            "/data/bpf-host",
            elsewhere.clone(),
            Area::Writable,
            "bpf",
            "bpf",
        )
        .unwrap();
        std::fs::write(elsewhere.join("marker"), b"old").unwrap();
        let again = at("/data/bpf-host");
        assert_eq!(
            mount([p(&source), p(&again), p(&fstype), flags, 0, 0]),
            0
        );
        let (now, _) = vfs::lookup("/data/bpf-host");
        assert_ne!(now, elsewhere);
        assert!(!now.join("marker").exists());
        assert_eq!(vfs::fstype("/data/bpf-host").as_deref(), Some("bpf"));
        assert_eq!(vfs::remove_mount("/sys/fs/bpf"), Ok(true));
        assert_eq!(vfs::remove_mount("/data/bpf-host"), Ok(true));
        assert_eq!(vfs::remove_mount("/sys"), Ok(true));
    }

    /// Init mounts sysfs on the image's `/sys`, mkdirs `/sys/fs/bpf`,
    /// then mounts bpffs there. A remount while `/sys` is still the
    /// image is `EINVAL`. A bpf mount on a directory that was not
    /// created stays `ENOENT`.
    #[test]
    fn sysfs_then_mkdir_then_bpf_mount() {
        let (_view, _root) = vfs::test_view();
        let image_sys = vfs::root().join("sys");
        std::fs::create_dir_all(&image_sys).unwrap();
        std::fs::write(image_sys.join("marker"), b"image").unwrap();
        let (_, area) = vfs::lookup("/sys");
        assert_eq!(area, Area::Image);
        let (source, sys, sysfs) = (at("sysfs"), at("/sys"), at("sysfs"));
        let remount = 4 | 32;
        assert_eq!(
            mount([p(&source), p(&sys), p(&sysfs), remount, 0, 0]),
            -(EINVAL as i64)
        );
        let (_, area) = vfs::lookup("/sys");
        assert_eq!(area, Area::Image);
        assert_eq!(mount([p(&source), p(&sys), p(&sysfs), 0, 0, 0]), 0);
        let (_, area) = vfs::lookup("/sys");
        assert_eq!(area, Area::Kernfs);
        assert_eq!(vfs::fstype("/sys").as_deref(), Some("sysfs"));
        assert_eq!(mount([p(&source), p(&sys), p(&sysfs), remount, 0, 0]), 0);
        assert!(!image_sys.join("fs").exists());
        mkdir("/sys/fs/bpf", 0o755, 0);
        assert!(!image_sys.join("fs/bpf").exists());
        let (bpf_host, area) = vfs::lookup("/sys/fs/bpf");
        assert_eq!(area, Area::Kernfs);
        assert!(bpf_host.is_dir());
        assert!(!bpf_host.starts_with(&image_sys));
        let (bpf, target, fstype) = (at("bpf"), at("/sys/fs/bpf"), at("bpf"));
        let flags = 2 | 4 | 8;
        let missing = at("/sys/fs/bpf-not-yet");
        assert_eq!(
            mount([p(&bpf), p(&missing), p(&fstype), flags, 0, 0]),
            -(ENOENT as i64)
        );
        assert_eq!(mount([p(&bpf), p(&target), p(&fstype), flags, 0, 0]), 0);
        assert_eq!(vfs::fstype("/sys/fs/bpf").as_deref(), Some("bpf"));
        let (host, area) = vfs::lookup("/sys/fs/bpf");
        assert_eq!(area, Area::Writable);
        assert!(std::fs::read_dir(&host).unwrap().next().is_none());
        mkdir("/sys/fs/bpf/tethering", 0o755, 0);
        assert!(host.join("tethering").is_dir());
        assert_eq!(std::fs::read(image_sys.join("marker")).unwrap(), b"image");
        for path in ["/sys/fs/pstore", "/sys/fs/selinux"] {
            let at_path = at(path);
            assert_eq!(
                mount([p(&bpf), p(&at_path), p(&fstype), flags, 0, 0]),
                -(ENOENT as i64),
                "{path}"
            );
        }
        assert_eq!(vfs::remove_mount("/sys/fs/bpf"), Ok(true));
        assert_eq!(vfs::remove_mount("/sys"), Ok(true));
        let _ = std::fs::remove_dir_all(&image_sys);
    }
}

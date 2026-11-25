//! Mount namespaces: `unshare(CLONE_NEWNS)`, `setns`, `mount` and `umount2`.
//!
//! zygote unshares its mount namespace and mounts storage views for each
//! child (`MountEmulatedStorage`, app data isolation): bind mounts and
//! tmpfs. `MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE` and `MS_REC` change the
//! mount they name. `unshare(CLONE_NEWNS)` keeps a shared mount in that
//! peer group. A later mount or unmount under a shared mount is applied
//! in the peers and the slaves of that group. A private mount is not.
//! The other namespaces are answered "unsupported" (ADR 0012 appendix).

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
}

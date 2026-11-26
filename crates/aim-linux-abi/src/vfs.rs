//! Guest path view: the guest's `/` is a host directory (`--root`), with
//! writable areas mapped over it by a path map (`--path-map`,
//! `docs/guest-init-contract.md` section 2).
//!
//! - The longest matching guest prefix wins, on whole components; the host
//!   device nodes in [`HOST_DEVICES`] and the pty slaves `/dev/pts/N`
//!   (`sys::tty`) take precedence over any `/dev` entry.
//! - Paths are resolved component by component with symlinks interpreted
//!   relative to the guest root, the way a chroot would, so absolute links
//!   inside the image (for example `/bin -> /system/bin`) stay inside it.
//!   Each intermediate result goes through the map again. Links under
//!   `/proc` are synthesized and not followed here.
//! - The inverse map (host path -> guest path) uses the same table.
//! - With a path map, the image root is read-only to the guest.
//! - `/dev/input` is the display server's device directory
//!   ([`set_input_dir`], `sys::evdev`).
//! - The process's own mounts (`mount(2)` with `MS_BIND` or `tmpfs`,
//!   `sys/mount.rs`) are entries over the calling thread's mount namespace.
//!   Threads share that namespace until `unshare(CLONE_NEWNS)`, which also
//!   unshares the caller's `fs_struct`. A mount hides the older ones at and
//!   below its mount point, as mounting over a directory does (zygote's
//!   tmpfs over `/data/user` hides the path map's `/data/user/0`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use crate::errno::{self, Errno};
use crate::sys::fscrypt::Lock;

pub const LINUX_AT_FDCWD: i32 = -100;
const MAX_SYMLINKS: usize = 40;

/// Host device nodes the guest sees at the same path.
pub const HOST_DEVICES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/ptmx",
];

/// Where a guest path lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Area {
    /// The image root: read-only when a path map is in use.
    Image,
    /// A writable host directory or file (`rw`).
    Writable,
    /// `/proc` or `/sys`: synthesized; the host tree holds values init wrote.
    Kernfs,
    /// A host device node passed through.
    HostDevice,
    /// `/dev/input`: the display server's input devices.
    Input,
}

#[derive(Clone, PartialEq)]
pub struct MountOrigin {
    pub namespace: String,
    pub id: u64,
    pub parent_shared: u64,
    pub shared: u64,
    pub master: u64,
}
#[derive(Clone, PartialEq)]
struct Mount {
    /// Normalized absolute guest path, no trailing `/`.
    guest: String,
    host: PathBuf,
    area: Area,
    /// What `/proc/mounts` shows; None for a plain directory of the path
    /// map (procfs names those).
    source: Option<String>,
    fstype: Option<String>,
    /// A mount this process made (not a path map entry).
    own: bool,
    /// Mount order: 0 for the path map, then increasing.
    seq: u64,
    fuse: Option<FuseRoute>,
    shared_fuse: bool,
    bind_source: Option<String>,
    projected_fuse: bool,
    origin: Option<MountOrigin>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Propagation {
    Private,
    Slave,
    Shared,
}
static PROPAGATION_RULES: Mutex<Vec<(String, Propagation)>> = Mutex::new(Vec::new());
fn mount_propagation(guest: &str) -> Propagation {
    PROPAGATION_RULES
        .lock()
        .unwrap()
        .iter()
        .filter(|(root, _)| root == "/" || below(root, guest).is_some())
        .max_by_key(|(root, _)| root.len())
        .map(|(_, kind)| *kind)
        .unwrap_or(if PRIVATE_MOUNTS.load(Ordering::Acquire) {
            Propagation::Private
        } else {
            Propagation::Shared
        })
}
pub fn set_mount_propagation(guest: &str, flags: u64) -> Result<(), Errno> {
    if !REPLAYING_NAMESPACE.with(std::cell::Cell::get) && mount_namespace_id().is_some() {
        namespace_event(&format!("propagation-flags\t{guest}\t{flags}"))?;
        // Propagation is not a mount-vec field. Linux still advances
        // `ns->event`, so a mounts file wakes even when its text does not.
        note_mount_table();
        return Ok(());
    }
    let kind = if flags & (1 << 19) != 0 {
        Propagation::Slave
    } else if flags & (1 << 20) != 0 {
        Propagation::Shared
    } else {
        Propagation::Private
    };
    let mut rules = PROPAGATION_RULES.lock().unwrap();
    rules.retain(|(root, _)| {
        root != guest && (!(flags & 0x4000 != 0) || (guest != "/" && below(guest, root).is_none()))
    });
    rules.push((guest.into(), kind));
    drop(rules);
    refresh_fuse_mounts()?;
    note_mount_table();
    Ok(())
}
static PRIVATE_MOUNTS: AtomicBool = AtomicBool::new(false);
fn fuse_table() -> Option<PathBuf> {
    runtime_dir().map(|runtime| runtime.join("fuse-mounts"))
}
struct FuseTableLock(std::fs::File);
impl Drop for FuseTableLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN);
        }
    }
}
fn fuse_table_lock() -> Result<FuseTableLock, Errno> {
    let path = fuse_table().ok_or(errno::ENODEV)?.with_extension("lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(path)
        .map_err(|error| errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)))?;
    lock_mount_table(std::os::fd::AsRawFd::as_raw_fd(&file))?;
    Ok(FuseTableLock(file))
}
// This lock belongs to the kernel's namespace journal. A guest signal must
// not interrupt it and turn an unrelated path lookup into an I/O error.
fn lock_mount_table(fd: i32) -> Result<(), Errno> {
    loop {
        if unsafe { libc::flock(fd, libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let error = errno::last();
        if error != errno::EINTR {
            return Err(error);
        }
    }
}
fn fuse_table_lines() -> Result<Vec<String>, Errno> {
    match std::fs::read_to_string(fuse_table().ok_or(errno::ENODEV)?) {
        Ok(text) => Ok(text.lines().map(str::to_owned).collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(errno::EIO),
    }
}
fn published_mount(guest: &str, host: &Path) -> Result<MountOrigin, Errno> {
    let owner = NAMESPACE_VIEW
        .lock()
        .unwrap()
        .as_ref()
        .map(|view| view.owner.clone())
        .ok_or(errno::ENODEV)?;
    let state = owner.read().map_err(namespace_error)?;
    let record = state
        .mounts
        .iter()
        .filter(|mount| mount.guest == guest && Path::new(&mount.host) == host)
        .max_by_key(|mount| mount.id)
        .ok_or(errno::ENOENT)?;
    let parent = state
        .mounts
        .iter()
        .find(|mount| mount.id == record.parent)
        .ok_or(errno::EIO)?;
    Ok(MountOrigin {
        namespace: owner.id().into(),
        id: record.id,
        parent_shared: parent.shared,
        shared: record.shared,
        master: record.master,
    })
}
fn journal_fields(line: &str) -> Result<(Vec<&str>, Option<MountOrigin>), Errno> {
    let mut fields = line.split('\t').collect::<Vec<_>>();
    if !matches!(fields.len(), 11 | 12) {
        return Err(errno::EIO);
    }
    let mut number = || fields.pop().unwrap().parse::<u64>().map_err(|_| errno::EIO);
    let master = number()?;
    let shared = number()?;
    let parent_shared = number()?;
    let id = number()?;
    let namespace = fields.pop().unwrap();
    if id == 0
        || [id, shared, master, parent_shared]
            .iter()
            .any(|id| *id > i32::MAX as u64)
    {
        return Err(errno::EIO);
    }
    Ok((
        fields,
        Some(MountOrigin {
            namespace: namespace.into(),
            id,
            parent_shared,
            shared,
            master,
        }),
    ))
}
fn origin_visible(
    id: &str,
    receiving: &[aim_storage::mount_namespace::MountRecord],
    guest: &str,
    origin: &Option<MountOrigin>,
) -> Result<bool, Errno> {
    let Some(origin) = origin else {
        return Err(errno::EIO);
    };
    if origin.namespace == id {
        return Ok(receiving
            .iter()
            .any(|mount| mount.id == origin.id && mount.guest == guest));
    }
    let target = receiving
        .iter()
        .filter(|mount| {
            mount.guest != guest && (mount.guest == "/" || below(&mount.guest, guest).is_some())
        })
        .max_by_key(|mount| (mount.guest.len(), mount.id))
        .ok_or(errno::EIO)?;
    Ok(origin.parent_shared != 0
        && (target.shared == origin.parent_shared || target.master == origin.parent_shared))
}
/// The mount table lives in the boot's runtime directory, which no boot
/// outlives: the rename publishes it whole and nothing is flushed to disk.
fn publish_fuse_route(
    guest: &str,
    host: &Path,
    source: &str,
    route: Option<&FuseRoute>,
) -> Result<(), Errno> {
    // Unmount propagation belongs to the containing mount, even when the
    // detached mount itself has become slave/private (mount_namespaces(7)).
    let propagation_path = if route.is_some() {
        guest
    } else {
        guest.rsplit_once('/').map_or(
            "/",
            |(parent, _)| {
                if parent.is_empty() { "/" } else { parent }
            },
        )
    };
    if mount_propagation(propagation_path) != Propagation::Shared {
        return Ok(());
    }
    let _lock = fuse_table_lock()?;
    let lines = fuse_table_lines()?;
    let namespace = mount_namespace_id().ok_or(errno::ENODEV)?;
    let mut retained = Vec::new();
    for line in lines {
        let (fields, origin) = journal_fields(&line)?;
        if fields[0] != guest
            || route.is_none()
                && origin
                    .as_ref()
                    .is_none_or(|origin| origin.namespace != namespace)
        {
            retained.push(line);
        }
    }
    let mut lines = retained;
    if let Some(route) = route {
        let origin = published_mount(guest, host)?;
        let fields = [
            guest.to_owned(),
            host.display().to_string(),
            source.to_owned(),
            route.session.display().to_string(),
            route.relative.clone(),
            format!(
                "{},{},{},{},{}",
                route.uid,
                route.gid,
                u8::from(route.allow_other),
                u8::from(route.default_permissions),
                u8::from(route.read_only)
            ),
            origin.namespace,
            origin.id.to_string(),
            origin.parent_shared.to_string(),
            origin.shared.to_string(),
            origin.master.to_string(),
        ];
        if fields.iter().any(|field| field.contains(['\t', '\n'])) {
            return Err(errno::EINVAL);
        }
        lines.push(fields.join("\t"));
    }
    let path = fuse_table().ok_or(errno::ENODEV)?;
    let temporary = path.with_extension(format!("{}.new", std::process::id()));
    use std::io::Write as _;
    let mut output = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| errno::EIO)?;
    output
        .write_all(lines.join("\n").as_bytes())
        .map_err(|_| errno::EIO)?;
    std::fs::rename(&temporary, &path).map_err(|_| errno::EIO)
}
fn publish_plain_mount(
    guest: &str,
    host: &Path,
    area: Area,
    source: &str,
    fstype: &str,
    bind_source: Option<&str>,
) -> Result<(), Errno> {
    if mount_propagation(guest) != Propagation::Shared {
        return Ok(());
    }
    let origin = published_mount(guest, host)?;
    let fields = [
        guest.to_owned(),
        host.display().to_string(),
        source.to_owned(),
        "plain".into(),
        match area {
            Area::Image => "ro",
            Area::Writable => "rw",
            Area::Kernfs => "kernfs",
            Area::HostDevice => "host-device",
            Area::Input => "input",
        }
        .into(),
        fstype.to_owned(),
        bind_source.unwrap_or("").to_owned(),
        origin.namespace,
        origin.id.to_string(),
        origin.parent_shared.to_string(),
        origin.shared.to_string(),
        origin.master.to_string(),
    ];
    if fields.iter().any(|field| field.contains(['\t', '\n'])) {
        return Err(errno::EINVAL);
    }
    let _lock = fuse_table_lock()?;
    let mut lines = fuse_table_lines()?;
    lines.retain(|line| line.split('\t').next() != Some(guest));
    lines.push(fields.join("\t"));
    let path = fuse_table().ok_or(errno::ENODEV)?;
    let temporary = path.with_extension(format!("{}.new", std::process::id()));
    use std::io::Write as _;
    let mut output = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| errno::EIO)?;
    output
        .write_all(lines.join("\n").as_bytes())
        .map_err(|_| errno::EIO)?;
    std::fs::rename(&temporary, &path).map_err(|_| errno::EIO)
}
/// What the last refresh read and made: while the shared table (replaced
/// whole by rename), the namespace records and this process's mounts and
/// propagation are unchanged, a refresh would make the same mounts again.
struct FuseRefresh {
    table: Option<(u64, i64, i64, i64, i64)>,
    records: std::sync::Arc<Vec<aim_storage::mount_namespace::MountRecord>>,
    rules: Vec<(String, Propagation)>,
    private: bool,
    mounts: Vec<Mount>,
    /// The generation of the mount table found to hold `mounts`.
    generation: Option<u64>,
}
static LAST_FUSE_REFRESH: Mutex<Option<FuseRefresh>> = Mutex::new(None);
fn fuse_table_identity() -> Result<Option<(u64, i64, i64, i64, i64)>, Errno> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(fuse_table().ok_or(errno::ENODEV)?) {
        Ok(stat) => Ok(Some((
            stat.ino(),
            stat.size() as i64,
            stat.mtime(),
            stat.mtime_nsec(),
            stat.ctime_nsec(),
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(errno::EIO),
    }
}
pub fn refresh_fuse_mounts() -> Result<(), Errno> {
    let _hold = journal_enter()?;
    refresh_namespace()?;
    if fuse_table().is_none() {
        return Ok(());
    }
    let namespace = NAMESPACE_VIEW
        .lock()
        .unwrap()
        .as_ref()
        .map(|view| view.owner.clone())
        .ok_or(errno::ENODEV)?;
    let receiving = NAMESPACE_VIEW
        .lock()
        .unwrap()
        .as_ref()
        .map(|view| view.records.clone())
        .ok_or(errno::ENODEV)?;
    let mut last = LAST_FUSE_REFRESH.lock().unwrap();
    let table = fuse_table_identity()?;
    if last.as_mut().is_some_and(|last| {
        last.table == table
            && std::sync::Arc::ptr_eq(&last.records, &receiving)
            && last.private == PRIVATE_MOUNTS.load(Ordering::Acquire)
            && *PROPAGATION_RULES.lock().unwrap() == last.rules
            && {
                // The same generation is the same table; another one may
                // still hold the same mounts.
                let mounts = vfs().mounts.read().unwrap();
                let same = last.generation == Some(mounts.generation()) || *mounts == last.mounts;
                if same {
                    last.generation = Some(mounts.generation());
                }
                same
            }
    }) {
        return Ok(());
    }
    *last = None;
    let _lock = fuse_table_lock()?;
    let table = fuse_table_identity()?;
    let lines = fuse_table_lines()?;
    let mut mounts = vfs().mounts.write().unwrap();
    let old = mounts
        .iter()
        .filter(|mount| mount.shared_fuse)
        .map(|mount| (mount.guest.clone(), mount.seq))
        .collect::<HashMap<_, _>>();
    mounts.retain(|mount| {
        (!mount.shared_fuse && !mount.projected_fuse)
            || mount_propagation(&mount.guest) == Propagation::Private
    });
    let mut seq = mounts.iter().map(|mount| mount.seq).max().unwrap_or(0);
    for line in lines {
        let (fields, origin) = journal_fields(&line)?;
        if !fields[0].starts_with('/') {
            return Err(errno::EIO);
        }
        if mount_propagation(fields[0]) == Propagation::Private
            || !origin_visible(namespace.id(), receiving.as_slice(), fields[0], &origin)?
            || mounts.iter().any(|mount| {
                mount.guest == fields[0] && !mount.shared_fuse && !hidden(&mounts, mount)
            })
        {
            continue;
        }
        let mount_seq = match old.get(fields[0]) {
            Some(seq) => *seq,
            None => {
                seq += 1;
                seq
            }
        };
        if fields.len() == 7 {
            if fields[3] != "plain" {
                return Err(errno::EIO);
            }
            mounts.push(Mount {
                guest: fields[0].into(),
                host: PathBuf::from(fields[1]),
                area: match fields[4] {
                    "ro" => Area::Image,
                    "rw" => Area::Writable,
                    "kernfs" => Area::Kernfs,
                    "host-device" => Area::HostDevice,
                    "input" => Area::Input,
                    _ => return Err(errno::EIO),
                },
                source: Some(fields[2].into()),
                fstype: Some(fields[5].into()),
                own: true,
                seq: mount_seq,
                fuse: None,
                shared_fuse: true,
                bind_source: (!fields[6].is_empty()).then(|| fields[6].into()),
                projected_fuse: false,
                origin: origin.clone(),
            });
        } else {
            let policy = fields[5]
                .split(',')
                .map(|value| value.parse::<u32>().map_err(|_| errno::EIO))
                .collect::<Result<Vec<_>, _>>()?;
            if policy.len() != 5 {
                return Err(errno::EIO);
            }
            mounts.push(Mount {
                guest: fields[0].into(),
                host: PathBuf::from(fields[1]),
                area: Area::Writable,
                source: Some(fields[2].into()),
                fstype: Some("fuse".into()),
                own: true,
                seq: mount_seq,
                fuse: Some(FuseRoute {
                    session: PathBuf::from(fields[3]),
                    relative: fields[4].into(),
                    uid: policy[0],
                    gid: policy[1],
                    allow_other: policy[2] != 0,
                    default_permissions: policy[3] != 0,
                    read_only: policy[4] != 0,
                }),
                shared_fuse: true,
                bind_source: None,
                projected_fuse: false,
                origin: origin.clone(),
            });
        }
    }
    project_mounts(&mut mounts, mount_propagation);
    mounts.sort_by(|a, b| b.guest.len().cmp(&a.guest.len()).then(b.seq.cmp(&a.seq)));
    *last = Some(FuseRefresh {
        table,
        records: receiving,
        rules: PROPAGATION_RULES.lock().unwrap().clone(),
        private: PRIVATE_MOUNTS.load(Ordering::Acquire),
        mounts: mounts.clone(),
        generation: None,
    });
    Ok(())
}
fn project_mounts(mounts: &mut Vec<Mount>, propagation: impl Fn(&str) -> Propagation) {
    let mut seq = mounts.iter().map(|mount| mount.seq).max().unwrap_or(0);
    // Propagated parent events retain the bind mount's actual source subtree.
    // Iterate to cover installer -> storage aliases; no host path inference.
    for _ in 0..16 {
        let aliases = mounts
            .iter()
            .filter(|mount| mount.bind_source.is_some() && !hidden(&mounts, mount))
            .cloned()
            .collect::<Vec<_>>();
        let routes = mounts
            .iter()
            .filter(|mount| mount.own && !hidden(&mounts, mount))
            .cloned()
            .collect::<Vec<_>>();
        let mut added = false;
        for alias in aliases {
            let source = alias.bind_source.as_ref().unwrap();
            if propagation(&alias.guest) == Propagation::Private {
                continue;
            }
            for route in &routes {
                if below(&alias.guest, &route.guest).is_some() {
                    continue;
                }
                let Some(relative) = below(source, &route.guest) else {
                    continue;
                };
                if relative.is_empty() {
                    continue;
                }
                let guest = format!("{}/{relative}", alias.guest.trim_end_matches('/'));
                if mounts
                    .iter()
                    .any(|mount| mount.guest == guest && !hidden(&mounts, mount))
                {
                    continue;
                }
                // A newer explicit child mount hides inherited events beneath it.
                if mounts.iter().any(|mount| {
                    mount.seq > alias.seq
                        && !mount.projected_fuse
                        && mount.guest != alias.guest
                        && below(&alias.guest, &mount.guest).is_some()
                        && below(&mount.guest, &guest).is_some()
                }) {
                    continue;
                }
                seq += 1;
                let mut projected = route.clone();
                projected.guest = guest;
                projected.seq = seq;
                projected.shared_fuse = false;
                projected.projected_fuse = true;
                projected.bind_source = None;
                if alias.area == Area::Image {
                    if let Some(route) = projected.fuse.as_mut() {
                        route.read_only = true;
                    }
                    projected.area = Area::Image;
                }
                mounts.push(projected);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
}
pub fn private_mount_namespace() -> Result<(), Errno> {
    refresh_fuse_mounts()?;
    // CLONE_NEWNS copies propagation relationships; MS_PRIVATE/MS_SLAVE
    // subsequently changes them at the guest's explicit mount operation.
    if PROPAGATION_RULES.lock().unwrap().is_empty() {
        PROPAGATION_RULES
            .lock()
            .unwrap()
            .push(("/".into(), Propagation::Shared));
    }
    let inherited = NAMESPACE_VIEW
        .lock()
        .unwrap()
        .as_ref()
        .map(|view| view.owner.clone());
    if let Some(owner) = inherited {
        let id = namespace_id("ns")?;
        let owner = owner.clone_to(&id).map_err(namespace_error)?;
        let mut inheritance = "namespace\tprivate\n".to_owned();
        for (root, kind) in PROPAGATION_RULES.lock().unwrap().iter() {
            inheritance.push_str(&format!(
                "propagation\t{root}\t{}\n",
                match kind {
                    Propagation::Private => "private",
                    Propagation::Slave => "slave",
                    Propagation::Shared => "shared",
                }
            ));
        }
        let state = owner.append(&inheritance).map_err(namespace_error)?;
        let generation = state.generation;
        *NAMESPACE_VIEW.lock().unwrap() = Some(NamespaceView {
            page: owner.generation().map_err(namespace_error)?,
            owner,
            generation,
            records: std::sync::Arc::new(state.mounts.clone()),
        });
        publish_process_namespace()?;
    }
    PRIVATE_MOUNTS.store(true, Ordering::Release);
    if let Some(id) = mount_namespace_id_locked() {
        *current_mount_namespace().journal_id.lock().unwrap() = Some(id);
    }
    Ok(())
}

struct NamespaceView {
    owner: aim_storage::mount_namespace::Namespace,
    generation: u64,
    page: aim_storage::mount_namespace::Generation,
    records: std::sync::Arc<Vec<aim_storage::mount_namespace::MountRecord>>,
}
static NAMESPACE_VIEW: Mutex<Option<NamespaceView>> = Mutex::new(None);
static NAMESPACE_REFRESH: Mutex<()> = Mutex::new(());
thread_local! {static REPLAYING_NAMESPACE:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};}
/// A new mount namespace's id: the process, the time, and a count of this
/// process's own, so two clones made within the clock's resolution (a
/// microsecond) differ, as do those of a later process with the same pid
/// (#2117).
fn namespace_id(kind: &str) -> Result<String, Errno> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    Ok(format!(
        "{kind}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| errno::EIO)?
            .as_nanos(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}
fn namespace_error(error: std::io::Error) -> Errno {
    errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO))
}

/// One mount namespace a thread can name with `/proc/<pid>/ns/mnt`.
/// The open fd holds this `Arc` from the moment of `open`. `table` stays
/// with the namespace; it is not looked up again from the calling thread
/// at `setns`. `parked` is the propagation journal while another namespace
/// owns the process-wide journal slot.
pub(crate) struct MountNs {
    ino: u64,
    table: RwLock<Table>,
    event: AtomicU64,
    parked: Mutex<Option<ParkedJournal>>,
    journal_id: Mutex<Option<String>>,
}

struct ParkedView {
    owner: aim_storage::mount_namespace::Namespace,
    records: std::sync::Arc<Vec<aim_storage::mount_namespace::MountRecord>>,
    generation: u64,
}

struct ParkedJournal {
    propagation: Vec<(String, Propagation)>,
    private_mounts: bool,
    view: Option<ParkedView>,
}

/// `fs_struct`. `users` is Linux `fs->users`: `CLONE_FS` shares one, and
/// `unshare(CLONE_FS)` (implied by `CLONE_NEWNS`) gives the caller a private
/// one. `mntns_install` returns `EINVAL` while `users != 1`.
struct SharedFs {
    users: AtomicU32,
    cwd: Mutex<String>,
}

#[derive(Clone)]
struct TaskState {
    fs: Arc<SharedFs>,
    ns: Arc<MountNs>,
}

thread_local! {
    static TASK: std::cell::RefCell<Option<TaskState>> = const { std::cell::RefCell::new(None) };
    static JOURNAL_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static JOURNAL_GUARD: std::cell::RefCell<Option<std::sync::MutexGuard<'static, ()>>> =
        const { std::cell::RefCell::new(None) };
}

static TASKS: Mutex<BTreeMap<i32, TaskState>> = Mutex::new(BTreeMap::new());
static JOURNAL: Mutex<()> = Mutex::new(());
static JOURNAL_OWNER: AtomicU64 = AtomicU64::new(0);
static BOOT_NS: Mutex<Option<Arc<MountNs>>> = Mutex::new(None);
static BOOT_TABLE: Mutex<Option<Table>> = Mutex::new(None);
static NAMESPACES: Mutex<BTreeMap<u64, Arc<MountNs>>> = Mutex::new(BTreeMap::new());
static NEXT_NS_INO: AtomicU64 = AtomicU64::new(0x1000_0001);

fn next_ns_ino() -> u64 {
    NEXT_NS_INO.fetch_add(1, Ordering::Relaxed)
}

fn mount_namespace_id_locked() -> Option<String> {
    NAMESPACE_VIEW
        .lock()
        .unwrap()
        .as_ref()
        .map(|view| view.owner.id().to_owned())
}

fn boot_namespace() -> Arc<MountNs> {
    let mut slot = BOOT_NS.lock().unwrap();
    if let Some(ns) = slot.as_ref() {
        return Arc::clone(ns);
    }
    let table = BOOT_TABLE.lock().unwrap().take().unwrap_or(Table {
        mounts: Vec::new(),
        visible: OnceLock::new(),
        generation: 0,
        poll_stamp: 0,
    });
    let ns = Arc::new(MountNs {
        ino: next_ns_ino(),
        table: RwLock::new(table),
        event: AtomicU64::new(0),
        parked: Mutex::new(None),
        journal_id: Mutex::new(mount_namespace_id_locked()),
    });
    NAMESPACES
        .lock()
        .unwrap()
        .insert(ns.ino, Arc::clone(&ns));
    JOURNAL_OWNER.store(ns.ino, Ordering::Release);
    *slot = Some(Arc::clone(&ns));
    ns
}

fn fresh_task() -> TaskState {
    let cwd = VFS
        .get()
        .map(|vfs| vfs.cwd.lock().unwrap().clone())
        .unwrap_or_else(|| "/".to_owned());
    TaskState {
        fs: Arc::new(SharedFs {
            users: AtomicU32::new(1),
            cwd: Mutex::new(cwd),
        }),
        ns: boot_namespace(),
    }
}

fn current_task() -> TaskState {
    if let Some(tid) = crate::sys::current_guest_tid()
        && let Some(task) = TASKS.lock().unwrap().get(&tid).cloned()
    {
        return task;
    }
    TASK.with(|slot| {
        if slot.borrow().is_none() {
            *slot.borrow_mut() = Some(fresh_task());
        }
        slot.borrow().as_ref().unwrap().clone()
    })
}

fn store_task(task: TaskState) {
    if let Some(tid) = crate::sys::current_guest_tid() {
        TASKS.lock().unwrap().insert(tid, task.clone());
    }
    TASK.with(|slot| *slot.borrow_mut() = Some(task));
}

fn current_mount_namespace() -> Arc<MountNs> {
    current_task().ns
}

fn set_current_ns(ns: Arc<MountNs>) {
    let mut task = current_task();
    task.ns = ns;
    store_task(task);
}

/// The main thread's mount namespace, so `/proc/self` names the leader
/// after `register_current`.
pub(crate) fn note_leader(tid: i32) {
    let task = current_task();
    TASKS.lock().unwrap().insert(tid, task);
}

/// A new guest thread. `share_fs` is `CLONE_FS`: one `fs_struct`, and the
/// same mount namespace until this thread `unshare`s or `setns`s.
pub(crate) fn bind_spawned_thread(tid: i32, share_fs: bool) {
    let parent = current_task();
    let fs = if share_fs {
        parent.fs.users.fetch_add(1, Ordering::AcqRel);
        Arc::clone(&parent.fs)
    } else {
        Arc::new(SharedFs {
            users: AtomicU32::new(1),
            cwd: Mutex::new(parent.fs.cwd.lock().unwrap().clone()),
        })
    };
    TASKS.lock().unwrap().insert(
        tid,
        TaskState {
            fs,
            ns: Arc::clone(&parent.ns),
        },
    );
}

/// The child host thread adopts the `TaskState` `spawn` stored for it.
pub(crate) fn adopt_thread_task(tid: i32) {
    if let Some(task) = TASKS.lock().unwrap().get(&tid).cloned() {
        TASK.with(|slot| *slot.borrow_mut() = Some(task));
    }
}

/// `exit` drops this thread's `CLONE_FS` hold.
pub(crate) fn unbind_thread(tid: i32) {
    if let Some(task) = TASKS.lock().unwrap().remove(&tid) {
        task.fs.users.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `true` when `current->fs->users != 1`: `setns` of a mount namespace
/// returns `EINVAL`.
pub(crate) fn fs_is_shared() -> bool {
    current_task().fs.users.load(Ordering::Acquire) != 1
}

/// `unshare(CLONE_FS)`. `CLONE_NEWNS` implies it. A private `fs_struct`
/// (`users == 1`) is unchanged.
pub fn unshare_fs() {
    let task = current_task();
    loop {
        let users = task.fs.users.load(Ordering::Acquire);
        if users <= 1 {
            return;
        }
        if task
            .fs
            .users
            .compare_exchange(users, users - 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }
        let cwd = task.fs.cwd.lock().unwrap().clone();
        let mut updated = task;
        updated.fs = Arc::new(SharedFs {
            users: AtomicU32::new(1),
            cwd: Mutex::new(cwd),
        });
        store_task(updated);
        return;
    }
}

fn task_namespace(tid: i32) -> Option<Arc<MountNs>> {
    TASKS
        .lock()
        .unwrap()
        .get(&tid)
        .map(|task| Arc::clone(&task.ns))
}

/// Mount namespace named by `/proc/<pid>/ns/mnt` or `task/<tid>/ns/mnt`.
/// `None` is the thread-group leader (`/proc/self`).
pub(crate) fn proc_mount_namespace(thread: Option<i32>) -> Arc<MountNs> {
    let tid = thread.unwrap_or_else(crate::sys::main_guest_tid);
    task_namespace(tid).unwrap_or_else(current_mount_namespace)
}

pub(crate) fn proc_namespace_link(thread: Option<i32>) -> String {
    format!("mnt:[{}]", proc_mount_namespace(thread).ino)
}

/// `readlink` text of the leader's mount namespace (`/proc/self/ns/mnt`).
pub fn mount_namespace_link() -> String {
    proc_namespace_link(None)
}

pub(crate) fn mount_namespace(ino: u64) -> Option<Arc<MountNs>> {
    NAMESPACES.lock().unwrap().get(&ino).map(Arc::clone)
}

pub(crate) fn mount_namespace_ino(ns: &MountNs) -> u64 {
    ns.ino
}

pub(crate) fn mount_namespace_event(ns: &MountNs) -> u64 {
    ns.event.load(Ordering::Acquire)
}

/// Journal id captured for this namespace, so an open mounts file keeps
/// reading the namespace it named at `open`.
pub(crate) fn mount_points_of(ns: &MountNs) -> Result<Vec<MountPoint>, Errno> {
    if let Some(id) = ns.journal_id.lock().unwrap().clone() {
        return namespace_mount_points(&id);
    }
    mount_points()
}

struct JournalEntered;

impl Drop for JournalEntered {
    fn drop(&mut self) {
        JOURNAL_DEPTH.with(|depth| {
            let next = depth.get().saturating_sub(1);
            depth.set(next);
            if next == 0 {
                JOURNAL_GUARD.with(|guard| *guard.borrow_mut() = None);
            }
        });
    }
}

fn journal_enter() -> Result<JournalEntered, Errno> {
    let depth = JOURNAL_DEPTH.with(|depth| depth.get());
    if depth == 0 {
        let guard = JOURNAL.lock().unwrap_or_else(|error| error.into_inner());
        // SAFETY: `JOURNAL` is static. The guard stays in this thread until
        // the outermost `journal_enter` drops it.
        let guard: std::sync::MutexGuard<'static, ()> = unsafe { std::mem::transmute(guard) };
        JOURNAL_GUARD.with(|slot| *slot.borrow_mut() = Some(guard));
        // Depth is raised before `align` so a nested enter (publish, refresh)
        // does not lock `JOURNAL` again on this thread.
        JOURNAL_DEPTH.with(|depth| depth.set(1));
        if let Err(error) = align_locked() {
            JOURNAL_DEPTH.with(|depth| depth.set(0));
            JOURNAL_GUARD.with(|slot| *slot.borrow_mut() = None);
            return Err(error);
        }
        return Ok(JournalEntered);
    }
    JOURNAL_DEPTH.with(|depth| depth.set(depth.get() + 1));
    Ok(JournalEntered)
}

fn copy_journal() -> ParkedJournal {
    let view = NAMESPACE_VIEW.lock().unwrap();
    ParkedJournal {
        propagation: PROPAGATION_RULES.lock().unwrap().clone(),
        private_mounts: PRIVATE_MOUNTS.load(Ordering::Acquire),
        view: view.as_ref().map(|view| ParkedView {
            owner: view.owner.clone(),
            records: Arc::clone(&view.records),
            generation: view.generation,
        }),
    }
}

fn take_journal() -> ParkedJournal {
    let view = NAMESPACE_VIEW.lock().unwrap().take();
    ParkedJournal {
        propagation: std::mem::take(&mut *PROPAGATION_RULES.lock().unwrap()),
        private_mounts: PRIVATE_MOUNTS.swap(false, Ordering::AcqRel),
        view: view.map(|view| ParkedView {
            owner: view.owner,
            records: view.records,
            generation: view.generation,
        }),
    }
}

fn install_parked(parked: ParkedJournal) -> Result<(), Errno> {
    *PROPAGATION_RULES.lock().unwrap() = parked.propagation;
    PRIVATE_MOUNTS.store(parked.private_mounts, Ordering::Release);
    if let Some(view) = parked.view {
        let page = view.owner.generation().map_err(namespace_error)?;
        *NAMESPACE_VIEW.lock().unwrap() = Some(NamespaceView {
            page,
            owner: view.owner,
            generation: view.generation,
            records: view.records,
        });
        publish_process_namespace()?;
    } else {
        *NAMESPACE_VIEW.lock().unwrap() = None;
    }
    Ok(())
}

fn park_owner(ns: &MountNs) {
    if JOURNAL_OWNER.load(Ordering::Acquire) != ns.ino {
        return;
    }
    *ns.parked.lock().unwrap() = Some(take_journal());
    JOURNAL_OWNER.store(0, Ordering::Release);
}

fn unpark(ns: &MountNs) -> Result<(), Errno> {
    if let Some(parked) = ns.parked.lock().unwrap().take() {
        install_parked(parked)?;
    }
    JOURNAL_OWNER.store(ns.ino, Ordering::Release);
    if ns.journal_id.lock().unwrap().is_none()
        && let Some(id) = mount_namespace_id_locked()
    {
        *ns.journal_id.lock().unwrap() = Some(id);
    }
    Ok(())
}

fn align_locked() -> Result<(), Errno> {
    let ns = current_mount_namespace();
    let owner = JOURNAL_OWNER.load(Ordering::Acquire);
    if owner == ns.ino {
        if ns.journal_id.lock().unwrap().is_none()
            && let Some(id) = mount_namespace_id_locked()
        {
            *ns.journal_id.lock().unwrap() = Some(id);
        }
        return Ok(());
    }
    if owner != 0 {
        if let Some(previous) = NAMESPACES.lock().unwrap().get(&owner).cloned() {
            park_owner(&previous);
        } else {
            JOURNAL_OWNER.store(0, Ordering::Release);
        }
    }
    unpark(&ns)
}

fn duplicate_table(table: &Table) -> Table {
    Table {
        mounts: table.mounts.clone(),
        visible: OnceLock::new(),
        generation: table.generation,
        poll_stamp: table.poll_stamp,
    }
}

/// `unshare(CLONE_NEWNS)`: the caller's new namespace is a copy. Fds and
/// other threads keep the namespace from before the call.
pub fn split_mount_namespace() -> Result<(), Errno> {
    let _hold = journal_enter()?;
    refresh_fuse_mounts()?;
    let old = current_mount_namespace();
    let old_id = old.journal_id.lock().unwrap().clone();
    *old.parked.lock().unwrap() = Some(copy_journal());
    if let Err(error) = private_mount_namespace() {
        *old.parked.lock().unwrap() = None;
        return Err(error);
    }
    let new_id = old.journal_id.lock().unwrap().clone();
    *old.journal_id.lock().unwrap() = old_id;
    let table = {
        let guard = old.table.read().unwrap_or_else(|error| error.into_inner());
        duplicate_table(&guard)
    };
    let ns = Arc::new(MountNs {
        ino: next_ns_ino(),
        table: RwLock::new(table),
        event: AtomicU64::new(old.event.load(Ordering::Acquire)),
        parked: Mutex::new(None),
        journal_id: Mutex::new(new_id),
    });
    NAMESPACES.lock().unwrap().insert(ns.ino, Arc::clone(&ns));
    set_current_ns(Arc::clone(&ns));
    JOURNAL_OWNER.store(ns.ino, Ordering::Release);
    Ok(())
}

/// `setns` into `target` for this thread only. `fs->users != 1` is
/// `EINVAL`. The same namespace still sets the caller's cwd to `/`.
pub(crate) fn switch_mount_namespace(target: &Arc<MountNs>) -> Result<(), Errno> {
    if fs_is_shared() {
        return Err(errno::EINVAL);
    }
    let _hold = journal_enter()?;
    let current = current_mount_namespace();
    if Arc::ptr_eq(&current, target) {
        *current_task().fs.cwd.lock().unwrap() = "/".to_owned();
        return Ok(());
    }
    park_owner(&current);
    set_current_ns(Arc::clone(target));
    if let Err(error) = unpark(target) {
        set_current_ns(Arc::clone(&current));
        let _ = unpark(&current);
        return Err(error);
    }
    // A peer may have appended mounts while this namespace was parked.
    // The walking table is this process's, so entering the namespace
    // replays its journal before the next lookup.
    if let Err(error) = refresh_namespace() {
        set_current_ns(Arc::clone(&current));
        let _ = unpark(&current);
        return Err(error);
    }
    *current_task().fs.cwd.lock().unwrap() = "/".to_owned();
    Ok(())
}

/// One mount, as a forked child reconstructs it. `origin` stays unset: the
/// child keeps this snapshot and pins the journal generation so a refresh
/// does not replay over it.
#[derive(Clone)]
pub(crate) struct ForkMount {
    pub guest: String,
    pub host: PathBuf,
    pub area: Area,
    pub source: Option<String>,
    pub fstype: Option<String>,
    pub own: bool,
    pub seq: u64,
    pub shared_fuse: bool,
    pub projected_fuse: bool,
    pub bind_source: Option<String>,
    pub fuse: Option<FuseRoute>,
}

/// A mount namespace the child must be able to name. The parent's current
/// namespace is included so a `CLONE_NEWNS` child can still `setns` back to
/// it through an inherited fd.
#[derive(Clone)]
pub(crate) struct ForkNamespace {
    pub ino: u64,
    pub event: u64,
    pub journal_id: Option<String>,
    pub private_mounts: bool,
    pub propagation: Vec<(String, u8)>,
    pub mounts: Vec<ForkMount>,
}

/// Namespaces and the parent's current inode, captured while the parent
/// still holds them. `new_namespace` is the child's `CLONE_NEWNS`.
pub(crate) struct ForkNamespaces {
    pub new_namespace: bool,
    pub current: u64,
    pub namespaces: Vec<ForkNamespace>,
}

fn propagation_code(kind: Propagation) -> u8 {
    match kind {
        Propagation::Private => 0,
        Propagation::Slave => 1,
        Propagation::Shared => 2,
    }
}

fn propagation_kind(code: u8) -> Option<Propagation> {
    match code {
        0 => Some(Propagation::Private),
        1 => Some(Propagation::Slave),
        2 => Some(Propagation::Shared),
        _ => None,
    }
}

fn snapshot_mount(mount: &Mount) -> ForkMount {
    ForkMount {
        guest: mount.guest.clone(),
        host: mount.host.clone(),
        area: mount.area,
        source: mount.source.clone(),
        fstype: mount.fstype.clone(),
        own: mount.own,
        seq: mount.seq,
        shared_fuse: mount.shared_fuse,
        projected_fuse: mount.projected_fuse,
        bind_source: mount.bind_source.clone(),
        fuse: mount.fuse.clone(),
    }
}

fn restore_mount(saved: &ForkMount) -> Mount {
    Mount {
        guest: saved.guest.clone(),
        host: saved.host.clone(),
        area: saved.area,
        source: saved.source.clone(),
        fstype: saved.fstype.clone(),
        own: saved.own,
        seq: saved.seq,
        shared_fuse: saved.shared_fuse,
        projected_fuse: saved.projected_fuse,
        bind_source: saved.bind_source.clone(),
        fuse: saved.fuse.clone(),
        origin: None,
    }
}

/// The namespaces this process holds, including the current one. A guest
/// fork is a new host process (`docs/fork.md`), so the child cannot see
/// these `Arc`s unless the image carries them.
pub(crate) fn capture_fork_namespaces(new_namespace: bool) -> ForkNamespaces {
    let current = current_mount_namespace().ino;
    let held: Vec<Arc<MountNs>> = NAMESPACES.lock().unwrap().values().cloned().collect();
    let mut namespaces = Vec::with_capacity(held.len());
    for ns in held {
        let parked = ns.parked.lock().unwrap();
        let (private_mounts, rules) = if JOURNAL_OWNER.load(Ordering::Relaxed) == ns.ino {
            (
                PRIVATE_MOUNTS.load(Ordering::Relaxed),
                PROPAGATION_RULES.lock().unwrap().clone(),
            )
        } else if let Some(parked) = parked.as_ref() {
            (parked.private_mounts, parked.propagation.clone())
        } else {
            (false, Vec::new())
        };
        let table = ns.table.read().unwrap();
        namespaces.push(ForkNamespace {
            ino: ns.ino,
            event: ns.event.load(Ordering::Relaxed),
            journal_id: ns.journal_id.lock().unwrap().clone(),
            private_mounts,
            propagation: rules
                .into_iter()
                .map(|(root, kind)| (root, propagation_code(kind)))
                .collect(),
            mounts: table.mounts.iter().map(snapshot_mount).collect(),
        });
    }
    ForkNamespaces {
        new_namespace,
        current,
        namespaces,
    }
}

fn claim_inode(ino: u64) {
    let mut next = NEXT_NS_INO.load(Ordering::Relaxed);
    while next <= ino {
        match NEXT_NS_INO.compare_exchange_weak(
            next,
            ino + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => next = actual,
        }
    }
}

/// Replace the calling task's namespace with the same table under `ino`.
/// `MountNs::ino` is fixed at construction.
fn retarget_namespace(old: Arc<MountNs>, ino: u64) {
    claim_inode(ino);
    if old.ino == ino {
        return;
    }
    let table = duplicate_table(&old.table.read().unwrap());
    let ns = Arc::new(MountNs {
        ino,
        table: RwLock::new(table),
        event: AtomicU64::new(old.event.load(Ordering::Relaxed)),
        parked: Mutex::new(old.parked.lock().unwrap().take()),
        journal_id: Mutex::new(old.journal_id.lock().unwrap().clone()),
    });
    let journal_owner = JOURNAL_OWNER.load(Ordering::Acquire) == old.ino;
    {
        let mut map = NAMESPACES.lock().unwrap();
        map.remove(&old.ino);
        map.insert(ino, Arc::clone(&ns));
    }
    // A fork child starts its inode counter where the parent did. The inode
    // just removed is the one an inherited namespace is materialized under.
    // Leaving the journal owner on it parks the live view onto that
    // namespace at the next lookup, and every walk returns ENODEV.
    if journal_owner {
        JOURNAL_OWNER.store(ino, Ordering::Release);
    }
    if BOOT_NS
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|boot| boot.ino == old.ino)
    {
        *BOOT_NS.lock().unwrap() = Some(Arc::clone(&ns));
    }
    set_current_ns(ns);
}

fn park_saved(saved: &ForkNamespace) -> Option<ParkedJournal> {
    let propagation = saved
        .propagation
        .iter()
        .filter_map(|(root, code)| Some((root.clone(), propagation_kind(*code)?)))
        .collect();
    let id = saved.journal_id.as_deref()?;
    let runtime = runtime_dir()?;
    let owner = aim_storage::mount_namespace::Namespace::open(runtime, id).ok()?;
    // `origin_visible` searches these records. An empty list makes the next
    // path walk return EIO when a fuse line names another namespace
    // (`refresh_fuse_mounts`): that was the child's `readlink` of
    // `/proc/self/exe` after `setns`. The generation stays on the page so
    // an unchanged table is not rebuilt. An ext4 host the journal no longer
    // records is still replayed (`ext4_journal_diverged`): the snapshot
    // must not keep `apex-mounts/1` after the journal has moved that path.
    let records = owner.read().ok()?.mounts;
    let generation = owner.generation().ok()?.current();
    Some(ParkedJournal {
        propagation,
        private_mounts: saved.private_mounts,
        view: Some(ParkedView {
            owner,
            records: Arc::new(records),
            generation,
        }),
    })
}

fn materialize_namespace(saved: &ForkNamespace) -> bool {
    if NAMESPACES.lock().unwrap().contains_key(&saved.ino) {
        claim_inode(saved.ino);
        return true;
    }
    if saved
        .propagation
        .iter()
        .any(|(_, code)| propagation_kind(*code).is_none())
    {
        return false;
    }
    let mounts: Vec<Mount> = saved.mounts.iter().map(restore_mount).collect();
    let poll_stamp = mount_stamp(&mounts);
    let ns = Arc::new(MountNs {
        ino: saved.ino,
        table: RwLock::new(Table {
            mounts,
            visible: OnceLock::new(),
            generation: 0,
            poll_stamp,
        }),
        event: AtomicU64::new(saved.event),
        parked: Mutex::new(park_saved(saved)),
        journal_id: Mutex::new(saved.journal_id.clone()),
    });
    NAMESPACES.lock().unwrap().insert(saved.ino, ns);
    claim_inode(saved.ino);
    true
}

/// Install captured namespaces into this process and give the calling task
/// its own `fs_struct` (`users == 1`). Fork without `CLONE_FS` does that;
/// the image never copies the parent's user count or its other threads.
///
/// Without `CLONE_NEWNS` the child's current namespace keeps the parent's
/// current inode (the table `load_own_mounts` already filled). With
/// `CLONE_NEWNS` that inode stays a separate namespace the inherited fds
/// can still name, and the child's own namespace takes an inode that does
/// not collide with any of them.
pub(crate) fn install_fork_namespaces(image: &ForkNamespaces) -> bool {
    let cwd = current_task().fs.cwd.lock().unwrap().clone();
    let private = TaskState {
        fs: Arc::new(SharedFs {
            users: AtomicU32::new(1),
            cwd: Mutex::new(cwd),
        }),
        ns: current_mount_namespace(),
    };
    store_task(private);
    if image.new_namespace {
        let boot = current_mount_namespace();
        if image.namespaces.iter().any(|ns| ns.ino == boot.ino) {
            let fresh = image
                .namespaces
                .iter()
                .map(|ns| ns.ino)
                .max()
                .unwrap_or(boot.ino)
                + 1;
            retarget_namespace(boot, fresh);
        }
        for ns in &image.namespaces {
            if !materialize_namespace(ns) {
                return false;
            }
        }
        return true;
    }
    let boot = current_mount_namespace();
    if boot.ino != image.current {
        retarget_namespace(boot, image.current);
    } else {
        claim_inode(image.current);
    }
    for ns in &image.namespaces {
        if ns.ino == image.current {
            claim_inode(ns.ino);
            continue;
        }
        if !materialize_namespace(ns) {
            return false;
        }
    }
    true
}

#[cfg(test)]
pub(crate) struct FsShare {
    fs: Arc<SharedFs>,
    ns: Arc<MountNs>,
}

#[cfg(test)]
impl Drop for FsShare {
    fn drop(&mut self) {
        self.fs.users.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
impl FsShare {
    pub(crate) fn namespace_link(&self) -> String {
        format!("mnt:[{}]", self.ns.ino)
    }

    pub(crate) fn mounts_contain(&self, guest: &str) -> bool {
        self.ns
            .table
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .mounts
            .iter()
            .any(|mount| mount.guest == guest)
    }
}

/// One extra `fs->users` and a hold on the namespace at this moment, the
/// way a `CLONE_FS` sibling still lives in the pre-`unshare` namespace.
#[cfg(test)]
pub(crate) fn testing_share_fs() -> FsShare {
    let task = current_task();
    task.fs.users.fetch_add(1, Ordering::AcqRel);
    FsShare {
        fs: Arc::clone(&task.fs),
        ns: Arc::clone(&task.ns),
    }
}

/// Drop every namespace except the caller's, as a new process would before
/// `install_fork_namespaces` rebuilds the ones an inherited fd names.
#[cfg(test)]
pub(crate) fn testing_forget_other_namespaces() {
    let current = current_mount_namespace().ino;
    NAMESPACES
        .lock()
        .unwrap()
        .retain(|ino, _| *ino == current);
}

fn namespace_event(event: &str) -> Result<(), Errno> {
    let _hold = journal_enter()?;
    if REPLAYING_NAMESPACE.with(std::cell::Cell::get) {
        return Ok(());
    }
    let owner = NAMESPACE_VIEW
        .lock()
        .unwrap()
        .as_ref()
        .map(|view| view.owner.clone());
    if let Some(owner) = owner {
        owner.append(event).map_err(namespace_error)?;
        refresh_namespace()?;
    }
    Ok(())
}
fn apply_namespace_state(state: aim_storage::mount_namespace::State) -> Result<(), Errno> {
    struct Replay;
    impl Drop for Replay {
        fn drop(&mut self) {
            REPLAYING_NAMESPACE.with(|value| value.set(false));
        }
    }
    REPLAYING_NAMESPACE.with(|value| value.set(true));
    let _replay = Replay;
    PROPAGATION_RULES.lock().unwrap().clear();
    PRIVATE_MOUNTS.store(false, Ordering::Release);
    let (_, base) = parse_map(&state.base).map_err(|_| errno::EIO)?;
    *PROPAGATION_RULES.lock().unwrap() = map_propagation(&state.base)?;
    let mut base = base;
    base.extend(input_mount());
    base.sort_by(|a, b| b.guest.len().cmp(&a.guest.len()));
    *vfs().mounts.write().unwrap() = base;
    for event in state.events {
        if let Some(guest) = event.strip_prefix("remove\t") {
            remove_mount(guest)?;
        } else if let Some(guest) = event.strip_prefix("detach\t") {
            detach_mount(guest)?;
        } else if let Some(rest) = event.strip_prefix("propagation-flags\t") {
            let (guest, flags) = rest.rsplit_once('\t').ok_or(errno::EIO)?;
            set_mount_propagation(guest, flags.parse().map_err(|_| errno::EIO)?)?;
        } else if let Some(rest) = event.strip_prefix("propagated\t") {
            let line = rest.lines().next().unwrap_or(rest);
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 7 {
                return Err(errno::EINVAL);
            }
            let area = match fields[2] {
                "ro" => Area::Image,
                "rw" => Area::Writable,
                "kernfs" => Area::Kernfs,
                "host-device" => Area::HostDevice,
                "input" => Area::Input,
                _ => return Err(errno::EINVAL),
            };
            add_mount(
                fields[3],
                PathBuf::from(fields[4]),
                area,
                fields[5],
                fields[6],
            )?;
            if let Some((_, rest)) = event.split_once('\n') {
                load_own_mounts(rest)?;
            }
        } else if let Some(rest) = event.strip_prefix("move\t") {
            let (from, to) = rest.split_once('\t').ok_or(errno::EIO)?;
            move_mount(from, to)?;
        } else if let Some(rest) = event.strip_prefix("policy\t") {
            let fields = rest.split('\t').collect::<Vec<_>>();
            if fields.len() != 7 {
                return Err(errno::EINVAL);
            }
            let mut mounts = vfs().mounts.write().unwrap();
            let mount = mounts
                .iter_mut()
                .find(|mount| mount.guest == fields[0] && mount.own)
                .ok_or(errno::ENOENT)?;
            mount.bind_source = (!fields[1].is_empty()).then(|| fields[1].into());
            if !fields[2].is_empty() {
                let policy = fields[4]
                    .split(',')
                    .map(str::parse::<u32>)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| errno::EINVAL)?;
                if policy.len() != 5 {
                    return Err(errno::EINVAL);
                }
                mount.fuse = Some(FuseRoute {
                    session: fields[2].into(),
                    relative: fields[3].into(),
                    uid: policy[0],
                    gid: policy[1],
                    allow_other: policy[2] != 0,
                    default_permissions: policy[3] != 0,
                    read_only: policy[4] != 0,
                });
            }
            mount.shared_fuse = fields[5] == "1";
            mount.projected_fuse = fields[6] == "1";
        } else {
            load_own_mounts(&event)?;
        }
    }
    // Propagation replay can already have lost a detached parent from the
    // live table. The owner records still determine its surviving attachments.
    vfs().mounts.write().unwrap().retain(|mount| {
        !mount.own
            || mount.origin.is_some()
            || mount.projected_fuse
            || state
                .mounts
                .iter()
                .any(|record| record.guest == mount.guest && Path::new(&record.host) == mount.host)
    });
    Ok(())
}
fn publish_mount_policy(guest: &str) -> Result<(), Errno> {
    if REPLAYING_NAMESPACE.with(std::cell::Cell::get) || mount_namespace_id().is_none() {
        return Ok(());
    }
    let mount = vfs()
        .mounts
        .read()
        .unwrap()
        .iter()
        .find(|mount| mount.guest == guest && mount.own)
        .cloned()
        .ok_or(errno::ENOENT)?;
    let (route, relative, policy) = mount
        .fuse
        .as_ref()
        .map(|route| {
            (
                route.session.display().to_string(),
                route.relative.clone(),
                format!(
                    "{},{},{},{},{}",
                    route.uid,
                    route.gid,
                    u8::from(route.allow_other),
                    u8::from(route.default_permissions),
                    u8::from(route.read_only)
                ),
            )
        })
        .unwrap_or_default();
    namespace_event(&format!(
        "policy\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        mount.guest,
        mount.bind_source.as_deref().unwrap_or(""),
        route,
        relative,
        policy,
        u8::from(mount.shared_fuse),
        u8::from(mount.projected_fuse)
    ))
}

/// An ext4 mount this process walks. A bind is one when it still carries
/// the ext4 stamp, the same set [`ext4_host_gone`] skips.
fn tracked_ext4(fstype: Option<&str>, host: &Path) -> bool {
    match fstype {
        Some("ext4") => true,
        Some("bind") => ext4_stamp_path(host).is_file(),
        _ => false,
    }
}

/// The walking table's ext4 hosts are not the journal's. A fork snapshot
/// can name `apex-mounts/1` while the journal has already moved that guest
/// path to the activated host. The generation is then pinned to the
/// journal's current value, so a generation check alone keeps the snapshot.
fn ext4_journal_diverged(records: &[aim_storage::mount_namespace::MountRecord]) -> bool {
    let mounts = vfs().mounts.read().unwrap();
    let table = mounts
        .iter()
        .filter(|mount| mount.own && tracked_ext4(mount.fstype.as_deref(), &mount.host))
        .map(|mount| (mount.guest.as_str(), mount.host.as_path()))
        .collect::<Vec<_>>();
    let journal = records
        .iter()
        .filter(|record| {
            record.own && tracked_ext4(Some(record.fstype.as_str()), Path::new(&record.host))
        })
        .map(|record| (record.guest.as_str(), record.host.as_str()))
        .collect::<Vec<_>>();
    if table.len() != journal.len() {
        return true;
    }
    table.iter().any(|(guest, host)| {
        !journal
            .iter()
            .any(|(recorded, recorded_host)| recorded == guest && Path::new(recorded_host) == *host)
    })
}

fn refresh_namespace() -> Result<(), Errno> {
    let _hold = journal_enter()?;
    if REPLAYING_NAMESPACE.with(std::cell::Cell::get) {
        return Ok(());
    }
    let _refresh = NAMESPACE_REFRESH.lock().unwrap();
    let pending = {
        let view = NAMESPACE_VIEW.lock().unwrap();
        view.as_ref().map(|view| {
            (
                view.owner.clone(),
                view.generation,
                view.page.current() != view.generation,
                std::sync::Arc::clone(&view.records),
            )
        })
    };
    let Some((owner, generation, generation_moved, records)) = pending else {
        return Ok(());
    };
    if !generation_moved && !ext4_journal_diverged(&records) {
        return Ok(());
    }
    let state = owner.read().map_err(namespace_error)?;
    if state.generation != generation || ext4_journal_diverged(&state.mounts) {
        let next = state.generation;
        let mounts = vfs().mounts.read().unwrap().clone();
        let rules = PROPAGATION_RULES.lock().unwrap().clone();
        let private = PRIVATE_MOUNTS.load(Ordering::Acquire);
        let previous = {
            let mut view = NAMESPACE_VIEW.lock().unwrap();
            let view = view.as_mut().ok_or(errno::ENODEV)?;
            std::mem::replace(&mut view.records, std::sync::Arc::new(state.mounts.clone()))
        };
        // Replay can import shared routes while applying propagation flags.
        // Authenticate them against this same complete owner generation.
        if let Err(error) = apply_namespace_state(state) {
            *vfs().mounts.write().unwrap() = mounts;
            *PROPAGATION_RULES.lock().unwrap() = rules;
            PRIVATE_MOUNTS.store(private, Ordering::Release);
            if let Some(view) = NAMESPACE_VIEW.lock().unwrap().as_mut() {
                view.records = previous;
            }
            return Err(error);
        }
        if let Some(view) = NAMESPACE_VIEW.lock().unwrap().as_mut() {
            if view.owner.id() == owner.id() {
                view.generation = next;
            }
        }
    }
    Ok(())
}
pub fn mount_namespace_id() -> Option<String> {
    let _hold = journal_enter().ok()?;
    mount_namespace_id_locked()
}

pub(crate) fn publish_process_namespace() -> Result<(), Errno> {
    if let (Some(id), Some(table)) = (mount_namespace_id(), crate::sys::cred::by_pid_dir()) {
        let process =
            aim_storage::process_namespace::ProcessIdentity::running(unsafe { libc::getpid() })
                .map_err(namespace_error)?;
        aim_storage::process_namespace::register_mount_namespace(table, process, &id)
            .map_err(namespace_error)?;
    }
    Ok(())
}

/// A FUSE mount owns a daemon session transport, never a raw-media path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuseRoute {
    pub session: PathBuf,
    pub relative: String,
    pub uid: u32,
    pub gid: u32,
    pub allow_other: bool,
    pub default_permissions: bool,
    pub read_only: bool,
}
/// The cgroup filesystem owning `guest`: a v1 controller or the unified
/// hierarchy. Select the holding mount, so nested ordinary mounts stay out.
pub fn cgroup(guest: &str) -> Option<(Option<aim_storage::cgroup_v1::Controller>, PathBuf)> {
    let mounts = VFS.get()?.mounts.read().unwrap();
    let (mount, _) = holder(&mounts, guest)?;
    let fstype = mount.fstype.as_deref()?;
    if fstype == "cgroup2" {
        return Some((None, mount.host.clone()));
    }
    Some((
        Some(aim_storage::cgroup_v1::Controller::from_map_kind(fstype)?),
        mount.host.clone(),
    ))
}

/// The host directory of the root of the mounted kernel filesystem
/// `fstype` (`cgroup2`, `bpf`).
pub fn kernel_fs_root(fstype: &str) -> Option<PathBuf> {
    let mounts = VFS.get()?.mounts.read().unwrap();
    mounts
        .iter()
        .enumerate()
        .find(|(index, m)| mounts.visible(*index) && m.fstype.as_deref() == Some(fstype))
        .map(|(_, m)| m.host.clone())
}

/// The cgroup v1 hierarchies mounted: each one's controller and the host
/// directory of its root.
pub fn cgroup_v1_hierarchies() -> Vec<(aim_storage::cgroup_v1::Controller, PathBuf)> {
    let Some(v) = VFS.get() else {
        return Vec::new();
    };
    let mounts = v.mounts.read().unwrap();
    let mut out: Vec<_> = mounts
        .iter()
        .enumerate()
        .filter(|(index, _)| mounts.visible(*index))
        .filter_map(|(_, m)| {
            let c = aim_storage::cgroup_v1::Controller::from_map_kind(m.fstype.as_deref()?)?;
            Some((c, m.host.clone()))
        })
        .collect();
    out.sort_by_key(|(c, _)| *c);
    out.dedup_by_key(|(c, _)| *c);
    out
}

pub fn fuse_route(guest: &str) -> Option<FuseRoute> {
    let mounts = vfs().mounts.read().unwrap();
    let (mount, rest) = holder(&mounts, guest)?;
    let mut route = mount.fuse.clone()?;
    route.relative = if rest.is_empty() {
        route.relative
    } else if route.relative.is_empty() {
        rest.to_owned()
    } else {
        format!("{}/{rest}", route.relative)
    };
    Some(route)
}
pub fn add_fuse_mount(
    guest: &str,
    session: PathBuf,
    host_anchor: PathBuf,
    source: &str,
    options: &crate::sys::fuse_mount::Options,
    read_only: bool,
) -> Result<(), Errno> {
    let route = FuseRoute {
        session,
        relative: String::new(),
        uid: options.uid,
        gid: options.gid,
        allow_other: options.allow_other,
        default_permissions: options.default_permissions,
        read_only,
    };
    install_mount(
        guest,
        host_anchor,
        Area::Writable,
        source,
        "fuse",
        Some(route),
        None,
    )
}
pub fn fuse_route_for_session(session: &Path) -> Option<(String, FuseRoute)> {
    let mounts = vfs().mounts.read().unwrap();
    mounts
        .iter()
        .filter(|mount| !hidden(&mounts, mount))
        .find_map(|mount| {
            mount
                .fuse
                .as_ref()
                .filter(|route| route.session == session)
                .map(|route| (mount.guest.clone(), route.clone()))
        })
}
/// A bind aliases the same FUSE session and mount-relative node tree.
pub fn bind_mount(
    source_guest: &str,
    target_guest: &str,
    host: PathBuf,
    area: Area,
    source: &str,
    fstype: &str,
) -> Result<(), Errno> {
    refresh_fuse_mounts()?;
    let mut route = fuse_route(source_guest);
    if area == Area::Image {
        if let Some(route) = &mut route {
            route.read_only = true;
        }
    }
    install_mount(
        target_guest,
        host,
        area,
        source,
        fstype,
        route,
        Some(source_guest.into()),
    )?;
    Ok(())
}

/// MS_REC clones the currently visible mount tree, not its host directories.
/// Nonrecursive bind clones only the source mount's selected subtree.
pub fn bind_mount_recursive(
    source_guest: &str,
    target_guest: &str,
    host: PathBuf,
    area: Area,
    recursive: bool,
) -> Result<(), Errno> {
    refresh_fuse_mounts()?;
    let children = if recursive {
        let mounts = vfs().mounts.read().unwrap();
        let mut children = mounts
            .iter()
            .filter(|mount| {
                mount.guest != source_guest
                    && below(source_guest, &mount.guest).is_some()
                    && !hidden(&mounts, mount)
            })
            .cloned()
            .collect::<Vec<_>>();
        children.sort_by_key(|mount| (mount.guest.len(), mount.seq));
        children
    } else {
        Vec::new()
    };
    bind_mount(source_guest, target_guest, host, area, source_guest, "bind")?;
    {
        let mut mounts = vfs().mounts.write().unwrap();
        if let Some(mount) = mounts
            .iter_mut()
            .find(|mount| mount.guest == target_guest && mount.own)
        {
            mount.bind_source = Some(source_guest.into());
        }
    }
    for child in children {
        let relative = below(source_guest, &child.guest).ok_or(errno::EINVAL)?;
        let guest = format!("{}/{relative}", target_guest.trim_end_matches('/'));
        let child_area = if area == Area::Image {
            Area::Image
        } else {
            child.area
        };
        let mut route = child.fuse.clone();
        if child_area == Area::Image {
            if let Some(route) = &mut route {
                route.read_only = true;
            }
        }
        install_mount(
            &guest,
            child.host,
            child_area,
            child.source.as_deref().unwrap_or("bind"),
            child.fstype.as_deref().unwrap_or("bind"),
            route,
            child.bind_source,
        )?;
    }
    Ok(())
}

struct Vfs {
    root: PathBuf,
    /// Whether a path map is in use (the image is then read-only).
    mapped: bool,
    /// The device of the root when it is a read-only mount (the image's).
    read_only_dev: Option<libc::dev_t>,
    /// Longest guest prefix first; among equal prefixes the latest mount.
    mounts: MountTable,
    /// Directory holding the path map (the guest-init runtime directory).
    runtime: Option<PathBuf>,
    cwd: Mutex<String>,
}

/// The mount table, with which of its mounts no later one hides (found
/// at the first lookup after a change) and a count of its changes:
/// lookups ask visibility for every path, and the table changes far less
/// often.
struct MountTable;
struct Table {
    mounts: Vec<Mount>,
    visible: OnceLock<Vec<bool>>,
    generation: u64,
    /// Identity of the mounts a proc mount file's poll last published.
    /// `mounts_poll` reports one priority edge per real change, so a write
    /// that leaves the table the same is not one.
    poll_stamp: u64,
}
impl MountTable {
    fn new(mounts: Vec<Mount>) -> Self {
        let poll_stamp = mount_stamp(&mounts);
        let table = Table {
            mounts,
            visible: OnceLock::new(),
            generation: 0,
            poll_stamp,
        };
        if let Some(ns) = BOOT_NS.lock().unwrap().as_ref().cloned() {
            *ns.table.write().unwrap_or_else(|error| error.into_inner()) = table;
        } else {
            *BOOT_TABLE.lock().unwrap() = Some(table);
        }
        Self
    }
    fn read(&self) -> std::sync::LockResult<MountsRead<'static>> {
        let ns = current_mount_namespace();
        match detach_read(&ns) {
            Ok(guard) => Ok(MountsRead { guard, _ns: ns }),
            Err(error) => {
                let guard = error.into_inner();
                Err(std::sync::PoisonError::new(MountsRead { guard, _ns: ns }))
            }
        }
    }
    fn write(&self) -> std::sync::LockResult<MountsWrite<'static>> {
        let ns = current_mount_namespace();
        match detach_write(&ns) {
            Ok(guard) => Ok(MountsWrite { guard, _ns: ns }),
            Err(error) => {
                let guard = error.into_inner();
                Err(std::sync::PoisonError::new(MountsWrite { guard, _ns: ns }))
            }
        }
    }
}

fn detach_read(
    ns: &MountNs,
) -> std::sync::LockResult<std::sync::RwLockReadGuard<'static, Table>> {
    match ns.table.read() {
        // SAFETY: the caller keeps `ns`'s `Arc` alive until the guard drops.
        Ok(guard) => Ok(unsafe { std::mem::transmute(guard) }),
        Err(error) => {
            let guard = error.into_inner();
            // SAFETY: same as the unpoisoned path.
            Err(std::sync::PoisonError::new(unsafe {
                std::mem::transmute(guard)
            }))
        }
    }
}

fn detach_write(
    ns: &MountNs,
) -> std::sync::LockResult<std::sync::RwLockWriteGuard<'static, Table>> {
    match ns.table.write() {
        // SAFETY: the caller keeps `ns`'s `Arc` alive until the guard drops.
        Ok(guard) => Ok(unsafe { std::mem::transmute(guard) }),
        Err(error) => {
            let guard = error.into_inner();
            // SAFETY: same as the unpoisoned path.
            Err(std::sync::PoisonError::new(unsafe {
                std::mem::transmute(guard)
            }))
        }
    }
}
impl Table {
    /// A write ended: what was derived from the table is found again when
    /// next asked, so a write that changed nothing costs nothing more.
    fn changed(&mut self) {
        self.visible = OnceLock::new();
        self.generation += 1;
    }
}
struct MountsRead<'a> {
    // Fields drop in declaration order. Unlock before the `Arc` can free the
    // `RwLock`.
    guard: std::sync::RwLockReadGuard<'a, Table>,
    _ns: Arc<MountNs>,
}
impl MountsRead<'_> {
    /// Whether no later mount hides the `index`th.
    fn visible(&self, index: usize) -> bool {
        let table = &*self.guard;
        table.visible.get_or_init(|| {
            table
                .mounts
                .iter()
                .map(|m| !hidden(&table.mounts, m))
                .collect()
        })[index]
    }
    fn generation(&self) -> u64 {
        self.guard.generation
    }
}
impl std::ops::Deref for MountsRead<'_> {
    type Target = Vec<Mount>;
    fn deref(&self) -> &Vec<Mount> {
        &self.guard.mounts
    }
}
struct MountsWrite<'a> {
    // Fields drop in declaration order. Unlock before the `Arc` can free the
    // `RwLock`.
    guard: std::sync::RwLockWriteGuard<'a, Table>,
    _ns: Arc<MountNs>,
}
impl std::ops::Deref for MountsWrite<'_> {
    type Target = Vec<Mount>;
    fn deref(&self) -> &Vec<Mount> {
        &self.guard.mounts
    }
}
impl std::ops::DerefMut for MountsWrite<'_> {
    fn deref_mut(&mut self) -> &mut Vec<Mount> {
        &mut self.guard.mounts
    }
}
impl Drop for MountsWrite<'_> {
    fn drop(&mut self) {
        let stamp = mount_stamp(&self.guard.mounts);
        let changed = stamp != self.guard.poll_stamp;
        self.guard.poll_stamp = stamp;
        self.guard.changed();
        if changed {
            note_mount_table();
        }
    }
}

static MOUNT_WAKE: Mutex<Option<(i32, i32)>> = Mutex::new(None);
static MOUNT_WAKE_ERRNO: AtomicI32 = AtomicI32::new(0);
/// Tests force the wake pipe closed. A failure is not remembered: the next
/// call creates the pipe again.
#[cfg(test)]
static FAIL_MOUNT_WAKE: AtomicBool = AtomicBool::new(false);

/// The mount generation of the calling thread's namespace (`ns->event`).
pub fn mount_event() -> u64 {
    current_mount_namespace().event.load(Ordering::Acquire)
}

/// A fork child starts from the parent's generation, so a copied `p->event`
/// does not become a new edge.
pub(crate) fn restore_mount_event(event: u64) {
    current_mount_namespace()
        .event
        .store(event, Ordering::Release);
}

/// Read end of the pipe `note_mount_table` writes. Hidden from the guest.
/// Negative when the pipe cannot be created; the errno is
/// [`mount_wake_errno`]. A failed attempt is not cached.
pub fn mount_wake_fd() -> i32 {
    match mount_wake() {
        Ok((read, _)) => read,
        Err(error) => {
            MOUNT_WAKE_ERRNO.store(error, Ordering::Release);
            -1
        }
    }
}

/// Errno from the last failed [`mount_wake_fd`].
pub fn mount_wake_errno() -> i32 {
    MOUNT_WAKE_ERRNO.load(Ordering::Acquire)
}

/// Drop bytes left by a generation a waiter has already observed.
pub fn drain_mount_wake() {
    let Ok((fd, _)) = mount_wake() else {
        return;
    };
    let mut buf = [0u8; 64];
    // SAFETY: our nonblocking pipe, local buffer.
    unsafe {
        while libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) > 0 {}
    }
}

fn mount_wake() -> Result<(i32, i32), i32> {
    #[cfg(test)]
    if FAIL_MOUNT_WAKE.load(Ordering::Relaxed) {
        return Err(crate::errno::EMFILE);
    }
    let mut slot = MOUNT_WAKE.lock().unwrap();
    if let Some(fds) = *slot {
        return Ok(fds);
    }
    let mut fds = [0; 2];
    // SAFETY: a private pipe, then moved out of the guest fd range.
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return Err(crate::errno::last());
        }
        for fd in fds {
            libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    let pair = (
        crate::sys::fdtab::hide(fds[0]),
        crate::sys::fdtab::hide(fds[1]),
    );
    *slot = Some(pair);
    Ok(pair)
}

/// Make `mount_wake` fail with `EMFILE` until cleared. The generation still
/// moves; only the wake pipe is absent.
#[cfg(test)]
pub(crate) fn testing_fail_mount_wake(fail: bool) {
    FAIL_MOUNT_WAKE.store(fail, Ordering::Relaxed);
}

/// Bump `ns->event` and wake mount-file pollers. Several notes before a
/// poll are one edge: the file stores the generation it observes. The
/// generation moves even when the pipe cannot be written.
fn note_mount_table() {
    current_mount_namespace()
        .event
        .fetch_add(1, Ordering::Release);
    let Ok((_, fd)) = mount_wake() else {
        return;
    };
    let byte = [1u8];
    // SAFETY: our nonblocking pipe. A full buffer already has a wake pending.
    unsafe {
        libc::write(fd, byte.as_ptr().cast(), 1);
    }
}

fn mount_stamp(mounts: &[Mount]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    let mut mix = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x100000001b3);
    };
    for mount in mounts {
        mix(mount.guest.as_bytes());
        mix(mount.host.as_os_str().as_encoded_bytes());
        mix(mount.source.as_deref().unwrap_or("").as_bytes());
        mix(mount.fstype.as_deref().unwrap_or("").as_bytes());
        mix(mount.bind_source.as_deref().unwrap_or("").as_bytes());
        mix(&mount.seq.to_le_bytes());
        let area = match mount.area {
            Area::Image => 1,
            Area::Writable => 2,
            Area::Kernfs => 3,
            Area::HostDevice => 4,
            Area::Input => 5,
        };
        mix(&[
            area,
            u8::from(mount.own),
            u8::from(mount.shared_fuse),
            u8::from(mount.projected_fuse),
            u8::from(mount.fuse.as_ref().is_some_and(|route| route.read_only)),
        ]);
    }
    hash
}

static VFS: OnceLock<Vfs> = OnceLock::new();
static INPUT: OnceLock<PathBuf> = OnceLock::new();

/// Show host directory `dir` as the guest's `/dev/input`. Before [`init`].
pub fn set_input_dir(dir: &Path) {
    let _ = INPUT.set(dir.to_owned());
}

/// The host directory behind `/dev/input`, if any.
pub fn input_dir() -> Option<&'static Path> {
    INPUT.get().map(PathBuf::as_path)
}

/// The window's input devices at /dev/input (`--display`): this process's,
/// whatever namespace state it applies.
fn input_mount() -> Option<Mount> {
    let dir = input_dir()?;
    Some(Mount {
        guest: "/dev/input".into(),
        host: dir.to_owned(),
        area: Area::Input,
        source: None,
        fstype: None,
        own: false,
        seq: 0,
        fuse: None,
        shared_fuse: false,
        bind_source: None,
        projected_fuse: false,
        origin: None,
    })
}

/// Parse a path map file: `kind<TAB>guest<TAB>host` lines, kinds `root`,
/// `ro`, `rw` and `kernfs`; `#` starts a comment line.
fn map_propagation(text: &str) -> Result<Vec<(String, Propagation)>, Errno> {
    text.lines()
        .filter_map(|line| line.strip_prefix("propagation\t"))
        .map(|line| {
            let (guest, kind) = line.split_once('\t').ok_or(errno::EINVAL)?;
            let kind = match kind {
                "private" => Propagation::Private,
                "slave" => Propagation::Slave,
                "shared" => Propagation::Shared,
                _ => return Err(errno::EINVAL),
            };
            Ok((guest.into(), kind))
        })
        .collect()
}

fn parse_map(text: &str) -> Result<(Option<PathBuf>, Vec<Mount>), String> {
    let mut root = None;
    let mut mounts: Vec<Mount> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if let ["bind-source", guest, source] = f.as_slice() {
            let mount: &mut Mount = mounts
                .iter_mut()
                .find(|mount| mount.guest == *guest)
                .ok_or_else(|| format!("line {}: bind source has no map owner", n + 1))?;
            if !source.starts_with('/') || source.contains(['\n', '\t']) {
                return Err(format!("line {}: invalid bind source", n + 1));
            }
            mount.bind_source = Some((*source).into());
            continue;
        }
        if let ["propagation", _guest, kind] = f.as_slice() {
            let propagation = match *kind {
                "slave" => Propagation::Slave,
                "private" => Propagation::Private,
                "shared" => Propagation::Shared,
                _ => return Err(format!("line {}: invalid propagation", n + 1)),
            };
            let _ = propagation;
            continue;
        }
        let [kind, guest, host] = f[..] else {
            return Err(format!("line {}: expected 3 tab-separated fields", n + 1));
        };
        let area = match kind {
            "root" => {
                root = Some(PathBuf::from(host));
                continue;
            }
            "ro" => Area::Image,
            "rw" | "cgroup2" | "bpf" => Area::Writable,
            "kernfs" => Area::Kernfs,
            other if aim_storage::cgroup_v1::Controller::from_map_kind(other).is_some() => {
                Area::Writable
            }
            other => return Err(format!("line {}: unknown kind '{other}'", n + 1)),
        };
        let guest = guest.trim_end_matches('/');
        if !guest.starts_with('/') {
            return Err(format!("line {}: guest path must be absolute", n + 1));
        }
        // Cgroup filesystems are served by sys::cgroup; v1's fstype names
        // its controller, and cgroup2 is the unified membership hierarchy.
        let fstype = (matches!(kind, "cgroup2" | "bpf") || kind.starts_with("cgroup:"))
            .then(|| kind.to_string());
        mounts.push(Mount {
            guest: guest.to_string(),
            host: PathBuf::from(host),
            area,
            source: fstype
                .as_deref()
                .map(|t| if t == "bpf" { "bpf" } else { "none" }.to_string()),
            fstype,
            own: false,
            seq: 0,
            fuse: None,
            shared_fuse: false,
            bind_source: None,
            projected_fuse: false,
            origin: None,
        });
    }
    mounts.sort_by(|a, b| b.guest.len().cmp(&a.guest.len()));
    Ok((root, mounts))
}

/// Explicit external entry, equivalent to selecting an authenticated namespace
/// handle before loading guest code. Path-map access alone grants no membership.
pub(crate) fn enter_init_namespace(
    map: Option<&Path>,
    by_pid: Option<&Path>,
) -> Result<aim_storage::mount_namespace::Namespace, String> {
    let map = map.ok_or("--mount-namespace-from-init requires --path-map")?;
    let map = map
        .canonicalize()
        .map_err(|error| format!("mount namespace path-map: {error}"))?;
    let runtime = map
        .parent()
        .ok_or("mount namespace path-map has no runtime")?;
    let table = runtime.join("identity/by-pid");
    if let Some(requested) = by_pid {
        if requested
            .canonicalize()
            .map_err(|error| error.to_string())?
            != table.canonicalize().map_err(|error| error.to_string())?
        {
            return Err("mount namespace PID table belongs to another runtime".into());
        }
    }
    std::fs::read_to_string(&map)
        .and_then(|text| parse_map(&text).map(|_| ()).map_err(std::io::Error::other))
        .map_err(|error| error.to_string())?;
    let process =
        aim_storage::process_namespace::ProcessIdentity::running(unsafe { libc::getpid() })
            .map_err(|error| error.to_string())?;
    aim_storage::process_namespace::InitNamespaceEntry::capture(&table, process)
        .map_err(|error| format!("mount namespace init entry: {error}"))
}

/// Native fork startup precedes VM restore. Inherit only the actual XNU
/// parent's authenticated current namespace, never the init origin fallback.
pub(crate) fn inherit_fork_namespace(map: Option<&Path>) -> Result<(), String> {
    let Some(runtime) = map.and_then(Path::parent) else {
        return Ok(());
    };
    let table = runtime.join("identity/by-pid");
    match std::fs::symlink_metadata(table.join("namespace-init")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
        Ok(_) => {}
    }
    aim_storage::process_namespace::InitRegistration::read(&table)
        .map_err(|error| error.to_string())?;
    let child = aim_storage::process_namespace::ProcessIdentity::running(unsafe { libc::getpid() })
        .map_err(|error| error.to_string())?;
    match std::fs::symlink_metadata(table.join(format!("{}.mount-namespace", child.host_pid))) {
        Ok(_) => {
            return aim_storage::process_namespace::mount_namespace_of(&table, child)
                .map(|_| ())
                .map_err(|error| error.to_string());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let parent =
        aim_storage::process_namespace::ProcessIdentity::running(unsafe { libc::getppid() })
            .map_err(|error| error.to_string())?;
    let namespace = aim_storage::process_namespace::mount_namespace_of(&table, parent)
        .map_err(|error| error.to_string())?;
    aim_storage::process_namespace::register_mount_namespace(&table, child, &namespace)
        .map_err(|error| error.to_string())
}

/// Without a path map, the processes of one run share a runtime directory
/// in the temporary directory, as the processes of one boot share
/// guest-init's: the first makes it and passes it on with `--runtime`.
static STANDALONE_RUNTIME: OnceLock<PathBuf> = OnceLock::new();
const STANDALONE_PREFIX: &str = "aim-mount-";
/// Use `dir` as this run's runtime directory (`--runtime`).
pub fn use_runtime(dir: PathBuf) {
    let _ = STANDALONE_RUNTIME.set(dir);
}
/// The run's runtime directory to pass on, when there is no path map.
pub fn standalone_runtime() -> Option<&'static Path> {
    STANDALONE_RUNTIME.get().map(PathBuf::as_path)
}
/// Every process of a run holds a shared lock on its directory's `holders`
/// for its lifetime; the kernel drops it however the process ends.
fn hold_standalone_runtime(directory: &Path) -> Result<(), String> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(directory.join("holders"))
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_SH) } < 0 {
        return Err(format!(
            "{}: {}",
            directory.display(),
            std::io::Error::last_os_error()
        ));
    }
    crate::sys::fdtab::hide(std::os::fd::IntoRawFd::into_raw_fd(file));
    Ok(())
}
/// Remove the runtime directories of runs that have ended: nothing holds
/// their `holders` lock any more.
fn sweep_standalone_runtimes() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(STANDALONE_PREFIX)
        {
            continue;
        }
        let directory = entry.path();
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(directory.join("holders"))
        else {
            // Made before runs held their directory: stale once its maker,
            // named pid-seconds-microseconds, is gone.
            let name = entry.file_name().to_string_lossy().into_owned();
            let fields = name[STANDALONE_PREFIX.len()..]
                .split('-')
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_default();
            if let [pid, start_seconds, start_microseconds] = fields[..]
                && !(aim_storage::process_namespace::ProcessIdentity {
                    host_pid: pid as i32,
                    start_seconds,
                    start_microseconds,
                })
                .is_live()
            {
                let _ = std::fs::remove_dir_all(&directory);
            }
            continue;
        };
        if unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } == 0
        {
            let _ = std::fs::remove_dir_all(&directory);
        }
    }
}

/// Initialize from `--root` and, when given, a `--path-map` file (whose
/// `root` line overrides `root`).
pub fn init(root: &Path, map: Option<&Path>) -> Result<(), String> {
    let (map_root, mut mounts, mut runtime) = match map {
        Some(map) => {
            let text =
                std::fs::read_to_string(map).map_err(|e| format!("{}: {e}", map.display()))?;
            let (r, m) = parse_map(&text).map_err(|e| format!("{}: {e}", map.display()))?;
            *PROPAGATION_RULES.lock().unwrap() = map_propagation(&text)
                .map_err(|error| format!("mount propagation: errno {error}"))?;
            (r, m, map.parent().map(Path::to_path_buf))
        }
        None => (None, Vec::new(), None),
    };
    mounts.extend(input_mount());
    mounts.sort_by(|a, b| b.guest.len().cmp(&a.guest.len()));
    let root = map_root.as_deref().unwrap_or(root);
    let root = root
        .canonicalize()
        .map_err(|e| format!("--root {}: {e}", root.display()))?;
    if runtime.is_none() {
        let directory = match STANDALONE_RUNTIME.get() {
            Some(directory) => directory.clone(),
            None => {
                sweep_standalone_runtimes();
                let process = aim_storage::process_namespace::ProcessIdentity::running(unsafe {
                    libc::getpid()
                })
                .map_err(|error| error.to_string())?;
                let directory = std::env::temp_dir().join(format!(
                    "{STANDALONE_PREFIX}{}-{}-{}",
                    process.host_pid, process.start_seconds, process.start_microseconds
                ));
                std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
                let _ = STANDALONE_RUNTIME.set(directory.clone());
                directory
            }
        };
        hold_standalone_runtime(&directory)?;
        runtime = Some(directory);
    }
    let read_only_dev = read_only_dev(&root);
    let _ = VFS.set(Vfs {
        root,
        mapped: map.is_some(),
        read_only_dev,
        mounts: MountTable::new(mounts),
        runtime,
        cwd: Mutex::new("/".into()),
    });
    if let Some(runtime) = runtime_dir() {
        let table = crate::sys::cred::by_pid_dir()
            .cloned()
            .unwrap_or_else(|| runtime.join("identity/by-pid"));
        if let Ok(_init) = aim_storage::process_namespace::InitRegistration::read(&table) {
            let process =
                aim_storage::process_namespace::ProcessIdentity::running(unsafe { libc::getpid() })
                    .map_err(|error| error.to_string())?;
            let id = aim_storage::process_namespace::mount_namespace_of(&table, process)
                .map_err(|error| format!("current process mount owner: {error}"))?;
            let owner = aim_storage::mount_namespace::Namespace::open(runtime, &id)
                .map_err(|error| error.to_string())?;
            *NAMESPACE_VIEW.lock().unwrap() = Some(NamespaceView {
                page: owner.generation().map_err(|error| error.to_string())?,
                owner,
                generation: 0,
                records: Default::default(),
            });
            refresh_namespace().map_err(|error| format!("mount namespace: errno {error}"))?;
        } else if !matches!(std::fs::symlink_metadata(table.join("namespace-init")),Err(error)if error.kind()==std::io::ErrorKind::NotFound)
        {
            return Err("invalid native init registration".into());
        } else {
            let process =
                aim_storage::process_namespace::ProcessIdentity::running(unsafe { libc::getpid() })
                    .map_err(|error| error.to_string())?;
            let id = format!(
                "standalone-{}-{}-{}",
                process.host_pid, process.start_seconds, process.start_microseconds
            );
            let owner = aim_storage::mount_namespace::Namespace::open(runtime, &id)
                .map_err(|error| error.to_string())?;
            let mut base = match map {
                Some(path) => std::fs::read_to_string(path).map_err(|error| error.to_string())?,
                None => String::new(),
            };
            if !base.lines().any(|line| line.starts_with("root\t")) {
                base = format!("root\t/\t{}\n{base}", vfs().root.display());
            }
            // The kernel's mounts start private; a path map is Android's
            // view, whose init makes the root shared.
            if !base
                .lines()
                .any(|line| line.starts_with("propagation\t/\t"))
            {
                base.push_str(if map.is_some() {
                    "propagation\t/\tshared\n"
                } else {
                    "propagation\t/\tprivate\n"
                });
            }
            owner.initialize(&base).map_err(|error| error.to_string())?;
            *NAMESPACE_VIEW.lock().unwrap() = Some(NamespaceView {
                page: owner.generation().map_err(|error| error.to_string())?,
                owner,
                generation: 0,
                records: Default::default(),
            });
            refresh_namespace()
                .map_err(|error| format!("standalone mount namespace: errno {error}"))?;
        }
    }
    Ok(())
}

/// The device of the filesystem holding `root`, if it is mounted read-only.
fn read_only_dev(root: &Path) -> Option<libc::dev_t> {
    let c = CString::new(root.as_os_str().as_bytes()).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated path, local buffers.
    if unsafe { libc::stat(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        let read_only = unsafe { libc::statfs(c.as_ptr(), &mut fs) == 0 }
            && fs.f_flags as u64 & libc::MNT_RDONLY as u64 != 0;
        read_only.then_some(st.st_dev)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut fs: libc::statvfs = unsafe { std::mem::zeroed() };
        let read_only = unsafe { libc::statvfs(c.as_ptr(), &mut fs) == 0 }
            && fs.f_flag & libc::ST_RDONLY as u64 != 0;
        read_only.then_some(st.st_dev)
    }
}

/// Whether host device `dev` is the read-only volume of the root: nothing
/// on it can have been changed by a guest.
pub fn on_read_only_root(dev: libc::dev_t) -> bool {
    VFS.get().and_then(|v| v.read_only_dev) == Some(dev)
}

/// Whether the root is the read-only image: a path map's root, or a
/// read-only volume, rather than a writable directory given as `--root`.
pub fn read_only_root() -> bool {
    VFS.get()
        .is_some_and(|v| v.mapped || v.read_only_dev.is_some())
}

/// Whether the guest's view has been set up.
pub fn initialized() -> bool {
    VFS.get().is_some()
}

fn vfs() -> &'static Vfs {
    VFS.get().expect("vfs not initialized")
}

pub fn root() -> &'static Path {
    &vfs().root
}

/// The guest-init runtime directory (`<runtime>/fs-attrs`, `sockets`,
/// `identity`), when running under a path map.
pub fn runtime_dir() -> Option<&'static Path> {
    VFS.get()?.runtime.as_deref()
}

/// A new file of the layer's own with no name, its descriptor: made as
/// `<prefix>.XXXXXX` and removed at once, in `<runtime>/scratch` (which
/// nothing else fills, so a name is found and removed quickly), or in
/// `$TMPDIR` without a runtime directory.
pub(crate) fn unnamed_file(prefix: &str) -> Result<i32, Errno> {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    let directory = match (SCRATCH.get(), runtime_dir()) {
        (Some(scratch), _) => scratch.clone(),
        (None, Some(runtime)) => {
            let scratch = runtime.join("scratch");
            make_scratch(&scratch)
                .map_err(|error| errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)))?;
            SCRATCH.get_or_init(|| scratch).clone()
        }
        (None, None) => std::env::temp_dir(),
    };
    let mut template = directory
        .join(format!("{prefix}.XXXXXX"))
        .into_os_string()
        .into_vec();
    template.push(0);
    // SAFETY: mkstemp fills in the template; the name goes at once.
    let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
    if fd < 0 {
        return Err(errno::last());
    }
    // SAFETY: the name mkstemp just made.
    unsafe { libc::unlink(template.as_ptr().cast()) };
    Ok(fd)
}

/// The scratch directory of a runtime guest-init did not prepare it in:
/// the layer's own (0700) whatever the umask a guest thread has set,
/// which is the process's.
fn make_scratch(scratch: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(scratch) {
        Ok(()) => std::fs::set_permissions(scratch, std::fs::Permissions::from_mode(0o700)),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

/// A mount as `/proc/mounts` lists it.
pub struct MountPoint {
    pub id: u64,
    pub parent: u64,
    pub shared: u64,
    pub master: u64,
    pub root: String,
    pub host: PathBuf,
    pub origin: Option<MountOrigin>,
    pub guest: String,
    pub area: Area,
    /// None for a plain directory of the path map.
    pub source: Option<String>,
    pub fstype: Option<String>,
}

/// The path map's directory entries (its "mounts"), shortest guest path
/// first (single-file entries are left out), then this process's own
/// mounts in mount order.
fn record_points(records: &[aim_storage::mount_namespace::MountRecord]) -> Vec<MountPoint> {
    records
        .iter()
        .map(|record| MountPoint {
            id: record.id,
            parent: record.parent,
            shared: record.shared,
            master: record.master,
            root: record.root.clone(),
            host: PathBuf::from(&record.host),
            origin: None,
            guest: record.guest.clone(),
            area: match record.kind.as_str() {
                "root" | "ro" => Area::Image,
                "kernfs" => Area::Kernfs,
                "input" => Area::Input,
                "host-device" => Area::HostDevice,
                _ => Area::Writable,
            },
            source: if record.kind == "root" {
                Some("/dev/root".into())
            } else if record.source.is_empty() {
                // Three-field path-map records carry the filesystem in
                // kind. Preserve parse_map's source as well as its type,
                // or procfs reports these kernel mounts as tmpfs/ext4.
                match record.kind.as_str() {
                    "bpf" => Some("bpf".into()),
                    "cgroup2" => Some("none".into()),
                    _ => None,
                }
            } else {
                Some(record.source.clone())
            },
            fstype: if record.kind == "root" {
                Some("erofs".into())
            } else if matches!(record.kind.as_str(), "bpf" | "cgroup2")
                || record.kind.starts_with("cgroup:")
            {
                Some(record.kind.clone())
            } else if record.fstype.is_empty() {
                None
            } else {
                Some(record.fstype.clone())
            },
        })
        .collect()
}
pub fn mount_points() -> Result<Vec<MountPoint>, Errno> {
    let id = mount_namespace_id().ok_or(errno::ENODEV)?;
    namespace_mount_points(&id)
}

/// Read another authenticated process's actual mount object inventory.
pub fn namespace_mount_points(id: &str) -> Result<Vec<MountPoint>, Errno> {
    let runtime = NAMESPACE_VIEW
        .lock()
        .unwrap()
        .as_ref()
        .map(|view| view.owner.runtime().to_path_buf())
        .or_else(|| runtime_dir().map(Path::to_path_buf))
        .ok_or(errno::ENODEV)?;
    let owner =
        aim_storage::mount_namespace::Namespace::open(&runtime, id).map_err(namespace_error)?;
    let backend = namespace_backend_points(id)?;
    let receiving = owner.read().map_err(namespace_error)?;
    let mut projected = Vec::new();
    for point in backend {
        let (mut origin, mut shared, mut master) = (0, 0, 0);
        if let Some(source) = &point.origin {
            let receiving_parent = receiving
                .mounts
                .iter()
                .filter(|candidate| {
                    candidate.guest != point.guest
                        && (candidate.guest == "/"
                            || below(&candidate.guest, &point.guest).is_some())
                })
                .max_by_key(|candidate| (candidate.guest.len(), candidate.id))
                .ok_or(errno::EIO)?;
            origin = source.id;
            if source.namespace == id
                || receiving_parent.shared != 0 && receiving_parent.shared == source.parent_shared
            {
                shared = source.shared;
                master = source.master;
            } else if source.parent_shared != 0 && receiving_parent.master == source.parent_shared {
                master = source.shared;
                if receiving_parent.shared != 0 {
                    shared = owner
                        .propagated_group(source.id, receiving_parent.shared)
                        .map_err(namespace_error)?;
                }
            } else {
                continue;
            }
        }
        projected.push(aim_storage::mount_namespace::MountRecord {
            id: 0,
            origin,
            parent: 0,
            shared,
            master,
            kind: "projected".into(),
            guest: point.guest.clone(),
            host: point.host.display().to_string(),
            source: point.source.clone().unwrap_or_default(),
            fstype: point.fstype.clone().unwrap_or_default(),
            root: point.root.clone(),
            own: true,
        });
    }
    let state = owner
        .sync_projections(&projected)
        .map_err(namespace_error)?;
    Ok(record_points(&state.mounts))
}
fn namespace_backend_points(id: &str) -> Result<Vec<MountPoint>, Errno> {
    let runtime = NAMESPACE_VIEW
        .lock()
        .unwrap()
        .as_ref()
        .map(|view| view.owner.runtime().to_path_buf())
        .or_else(|| runtime_dir().map(Path::to_path_buf))
        .ok_or(errno::ENODEV)?;
    let owner =
        aim_storage::mount_namespace::Namespace::open(&runtime, id).map_err(namespace_error)?;
    let state = owner.read().map_err(namespace_error)?;
    let receiving = state.clone();
    let (_, mut mounts) = parse_map(&state.base).map_err(|_| errno::EIO)?;
    let mut rules = map_propagation(&state.base)?;
    let mut private = false;
    for event in state.events {
        if let Some(guest) = event.strip_prefix("remove\t") {
            if let Some(index) = mounts
                .iter()
                .position(|mount| mount.own && mount.guest == guest)
            {
                mounts.remove(index);
            }
        } else if let Some(guest) = event.strip_prefix("detach\t") {
            if let Some(target) = mounts
                .iter()
                .find(|mount| mount.own && mount.guest == guest)
                .cloned()
            {
                mounts.retain(|mount| {
                    !mount.own
                        || (mount.seq != target.seq
                            && (mount.seq <= target.seq || below(guest, &mount.guest).is_none()))
                });
            }
        } else if let Some(rest) = event.strip_prefix("move\t") {
            let (from, to) = rest.split_once('\t').ok_or(errno::EINVAL)?;
            for mount in mounts.iter_mut().filter(|mount| {
                mount.own && (mount.guest == from || below(from, &mount.guest).is_some())
            }) {
                mount.guest = format!("{to}{}", &mount.guest[from.len()..]);
            }
        } else if let Some(rest) = event.strip_prefix("propagation-flags\t") {
            let (guest, flags) = rest.rsplit_once('\t').ok_or(errno::EINVAL)?;
            let flags = flags.parse::<u64>().map_err(|_| errno::EINVAL)?;
            let kind = if flags & (1 << 19) != 0 {
                Propagation::Slave
            } else if flags & (1 << 20) != 0 {
                Propagation::Shared
            } else {
                Propagation::Private
            };
            rules.retain(|(root, _)| {
                root != guest
                    && (flags & 0x4000 == 0 || guest != "/" && below(guest, root).is_none())
            });
            rules.push((guest.into(), kind));
        } else if event.starts_with("policy\t") {
            continue;
        } else {
            for line in event.lines() {
                if line == "namespace\tprivate" {
                    private = true;
                    continue;
                }
                if let Some(rest) = line.strip_prefix("propagation\t") {
                    let (guest, kind) = rest.split_once('\t').ok_or(errno::EINVAL)?;
                    rules.push((
                        guest.into(),
                        match kind {
                            "private" => Propagation::Private,
                            "slave" => Propagation::Slave,
                            "shared" => Propagation::Shared,
                            _ => return Err(errno::EINVAL),
                        },
                    ));
                    continue;
                }
                if let Some(guest) = line.strip_prefix("mount-shared\t") {
                    if let Some(mount) = mounts
                        .iter_mut()
                        .find(|mount| mount.guest == guest && mount.own)
                    {
                        mount.shared_fuse = true;
                    }
                    continue;
                }
                let propagated = line.strip_prefix("propagated\t");
                let fields = if let Some(rest) = propagated {
                    let extra = rest.split('\t').collect::<Vec<_>>();
                    if extra.len() != 7 {
                        return Err(errno::EINVAL);
                    }
                    vec![extra[2], extra[3], extra[4], extra[5], extra[6]]
                } else {
                    line.split('\t').collect::<Vec<_>>()
                };
                if fields.len() == 3 && fields[0] == "bind-source" {
                    if let Some(mount) = mounts
                        .iter_mut()
                        .find(|mount| mount.guest == fields[1] && mount.own)
                    {
                        mount.bind_source = Some(fields[2].into());
                    }
                    continue;
                }
                if !matches!(fields.len(), 5 | 8) {
                    return Err(errno::EINVAL);
                }
                let area = match fields[0] {
                    "ro" => Area::Image,
                    "rw" => Area::Writable,
                    "kernfs" => Area::Kernfs,
                    "host-device" => Area::HostDevice,
                    "input" => Area::Input,
                    _ => return Err(errno::EINVAL),
                };
                let seq = mounts.iter().map(|mount| mount.seq).max().unwrap_or(0) + 1;
                let mount = Mount {
                    guest: fields[1].into(),
                    host: fields[2].into(),
                    area,
                    source: Some(fields[3].into()),
                    fstype: Some(fields[4].into()),
                    own: true,
                    seq,
                    fuse: None,
                    shared_fuse: false,
                    bind_source: None,
                    projected_fuse: false,
                    origin: None,
                };
                let at = mounts
                    .iter()
                    .position(|known| known.guest.len() <= mount.guest.len())
                    .unwrap_or(mounts.len());
                mounts.insert(at, mount);
            }
        }
    }
    let propagation = |guest: &str| {
        rules
            .iter()
            .filter(|(root, _)| root == "/" || below(root, guest).is_some())
            .max_by_key(|(root, _)| root.len())
            .map(|(_, kind)| *kind)
            .unwrap_or(if private {
                Propagation::Private
            } else {
                Propagation::Shared
            })
    };
    mounts.retain(|mount| !mount.shared_fuse || propagation(&mount.guest) == Propagation::Private);
    for line in fuse_table_lines()? {
        let (fields, origin) = journal_fields(&line)?;
        if propagation(fields[0]) == Propagation::Private
            || !origin_visible(id, &receiving.mounts, fields[0], &origin)?
        {
            continue;
        }
        let (area, fstype) = if fields.len() == 7 {
            (
                match fields[4] {
                    "ro" => Area::Image,
                    "rw" => Area::Writable,
                    "kernfs" => Area::Kernfs,
                    "host-device" => Area::HostDevice,
                    "input" => Area::Input,
                    _ => return Err(errno::EIO),
                },
                fields[5],
            )
        } else {
            (Area::Writable, "fuse")
        };
        let seq = mounts.iter().map(|mount| mount.seq).max().unwrap_or(0) + 1;
        mounts.push(Mount {
            guest: fields[0].into(),
            host: fields[1].into(),
            area,
            source: Some(fields[2].into()),
            fstype: Some(fstype.into()),
            own: true,
            seq,
            fuse: None,
            shared_fuse: true,
            bind_source: if fields.len() == 7 && !fields[6].is_empty() {
                Some(fields[6].into())
            } else {
                None
            },
            projected_fuse: false,
            origin: origin.clone(),
        });
    }
    project_mounts(&mut mounts, propagation);
    mounts.sort_by(|a, b| b.guest.len().cmp(&a.guest.len()).then(b.seq.cmp(&a.seq)));
    let (mut map, mut own): (Vec<_>, Vec<_>) = mounts
        .iter()
        .filter(|mount| mount.own || mount.host.is_dir())
        .partition(|mount| !mount.own);
    map.reverse();
    own.reverse();
    Ok(map
        .into_iter()
        .chain(own)
        .map(|mount| MountPoint {
            id: 0,
            parent: 0,
            shared: 0,
            master: 0,
            root: "/".into(),
            host: mount.host.clone(),
            origin: mount.origin.clone(),
            guest: mount.guest.clone(),
            area: mount.area,
            source: mount.source.clone(),
            fstype: mount.fstype.clone(),
        })
        .collect())
}

/// Active guest mount roots, including file binds and mapped directory roots.
pub fn is_mountpoint(guest: &str) -> bool {
    let mounts = vfs().mounts.read().unwrap();
    mounts.iter().any(|mount| {
        mount.guest == guest && !hidden(&mounts, mount) && (mount.own || mount.host.is_dir())
    })
}

/// Fail when a host directory the guest can create files in is on a
/// case-folding volume. That is the path map's writable and kernfs
/// directories (`/data`, `/cache`, and the other writable layers), the
/// tmpfs backing directory `<runtime>/tmpfs`, socket directories, scratch,
/// and `$TMPDIR`. A path that does not exist yet is judged by the
/// directory that will hold it. Call after [`init`].
pub fn require_case_sensitive_backing() -> Result<(), String> {
    let v = vfs();
    let mut entries = Vec::new();
    if !v.mapped {
        entries.push(crate::case_volume::VolumeCheck {
            role: "root".to_string(),
            path: v.root.clone(),
        });
    }
    let mounts: Vec<(String, PathBuf, bool)> = {
        let mounts = v.mounts.read().unwrap();
        mounts
            .iter()
            .filter(|m| !m.own && matches!(m.area, Area::Writable | Area::Kernfs))
            .map(|m| {
                let role = if m.area == Area::Kernfs {
                    format!("kernfs {}", m.guest)
                } else {
                    format!("writable {}", m.guest)
                };
                (role, m.host.clone(), m.guest == "/dev")
            })
            .collect()
    };
    for (role, host, dev_socket) in mounts {
        if dev_socket {
            entries.push(crate::case_volume::VolumeCheck {
                role: "socket directory".to_string(),
                path: host.join("socket"),
            });
        }
        entries.push(crate::case_volume::VolumeCheck {
            role,
            path: host_backing(&host),
        });
    }
    if let Some(runtime) = v.runtime.as_deref() {
        entries.push(crate::case_volume::VolumeCheck {
            role: "tmpfs backing".to_string(),
            path: runtime.join("tmpfs"),
        });
        entries.push(crate::case_volume::VolumeCheck {
            role: "socket directory".to_string(),
            path: runtime.join("dev").join("socket"),
        });
        entries.push(crate::case_volume::VolumeCheck {
            role: "scratch".to_string(),
            path: runtime.join("scratch"),
        });
    }
    entries.push(crate::case_volume::VolumeCheck {
        role: "TMPDIR".to_string(),
        path: std::env::temp_dir(),
    });
    crate::case_volume::require(&entries)
}

fn host_backing(host: &Path) -> PathBuf {
    match std::fs::metadata(host) {
        Ok(meta) if meta.is_dir() => host.to_path_buf(),
        Ok(_) => host
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| host.to_path_buf()),
        Err(_) => host.to_path_buf(),
    }
}

/// The host paths the guest writes to: the path map's writable entries,
/// or the root without a path map. None before [`init`].
pub fn writable_hosts() -> Option<Vec<PathBuf>> {
    let v = VFS.get()?;
    if !v.mapped {
        return Some(vec![v.root.clone()]);
    }
    let mounts = v.mounts.read().unwrap();
    Some(
        mounts
            .iter()
            .filter(|m| !m.own && m.area == Area::Writable)
            .map(|m| m.host.clone())
            .collect(),
    )
}

pub fn cwd() -> String {
    current_task().fs.cwd.lock().unwrap().clone()
}

pub fn set_cwd(guest: String) {
    *current_task().fs.cwd.lock().unwrap() = guest;
}

/// The rest of `path` below the mount point `at`, if it is there.
fn below<'a>(at: &str, path: &'a str) -> Option<&'a str> {
    if path == at {
        Some("")
    } else {
        path.strip_prefix(at).and_then(|r| r.strip_prefix('/'))
    }
}

/// Whether a later mount at or above the mount point of `m` hides it.
fn hidden(mounts: &[Mount], m: &Mount) -> bool {
    mounts
        .iter()
        .any(|n| n.seq > m.seq && below(&n.guest, &m.guest).is_some())
}

/// Sidecar beside an ext4 host directory. The same bytes are written inside
/// the directory. Removing and creating the directory again drops the inner
/// copy; an inode number can be reused, so the bytes are the record.
pub(crate) fn ext4_stamp_path(host: &Path) -> PathBuf {
    let mut name = host.file_name().unwrap_or_default().to_os_string();
    name.push(".stamp");
    host.with_file_name(name)
}

fn ext4_stamp_file(host: &Path) -> PathBuf {
    host.join(".aim-ext4-stamp")
}

/// Remember the directory `host` that an ext4 mount just installed.
///
/// A later install must not reuse this path. If something replaces the
/// directory anyway, the copy of this record inside it is gone and the
/// mount stops covering the guest path.
pub(crate) fn note_ext4_host(host: &Path) -> Result<(), Errno> {
    let meta = std::fs::metadata(host).map_err(|error| {
        errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO))
    })?;
    if !meta.is_dir() {
        return Err(errno::ENOTDIR);
    }
    let text = format!("{}\n", std::process::id());
    let write = |path: &Path| {
        std::fs::write(path, &text).map_err(|error| {
            errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO))
        })
    };
    write(&ext4_stamp_file(host))?;
    write(&ext4_stamp_path(host))
}

/// The recorded directory was removed and created again. The path exists,
/// but it is not the tree this mount installed. A failed read other than
/// a missing file keeps the mount.
fn ext4_identity_replaced(host: &Path) -> bool {
    let expected = match std::fs::read(ext4_stamp_path(host)) {
        Ok(text) => text,
        Err(_) => return false,
    };
    if expected.is_empty() {
        return false;
    }
    match std::fs::read(ext4_stamp_file(host)) {
        Ok(found) => found != expected,
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

/// An ext4 mount whose host directory is gone, or no longer the directory
/// that was installed. The directory is the superblock filled when the
/// mount was created. A later payload used to remove that directory and
/// create it again, so the mount still named a path whose `linker64` was
/// missing and hid the activated tree. A bind of the same host does too.
/// The entry does not cover the guest path. A directory that is still the
/// installed one keeps covering the path. `EACCES` does not.
fn ext4_host_gone(mount: &Mount) -> bool {
    let stamped = ext4_stamp_path(&mount.host).is_file();
    let ext4 = mount.fstype.as_deref() == Some("ext4");
    let bind_of_ext4 = mount.fstype.as_deref() == Some("bind") && stamped;
    if !ext4 && !bind_of_ext4 {
        return false;
    }
    match std::fs::metadata(&mount.host) {
        Ok(meta) => !meta.is_dir() || ext4_identity_replaced(&mount.host),
        // A missing directory does not cover the path. Any other error,
        // including EACCES, leaves the mount in place so the caller's
        // open returns that errno.
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Whether a later mount whose host is still there covers `m`.
fn covered_by_live(mounts: &[Mount], m: &Mount) -> bool {
    mounts.iter().any(|n| {
        n.seq > m.seq && below(&n.guest, &m.guest).is_some() && !ext4_host_gone(n)
    })
}

/// The mount that holds the normalized guest path, and the path below it:
/// the deepest one that is not hidden by a mount whose host is still there.
/// `mounts` is ordered longest mount point first, the latest first among
/// equal ones. The visible-bit cache is not enough: removing a host
/// directory does not change the mount generation.
fn holder<'a, 'p>(mounts: &'a MountsRead<'_>, guest: &'p str) -> Option<(&'a Mount, &'p str)> {
    mounts.iter().find_map(|m| {
        let rest = below(&m.guest, guest)?;
        if ext4_host_gone(m) || covered_by_live(mounts, m) {
            None
        } else {
            Some((m, rest))
        }
    })
}

/// Host path and area of a normalized absolute guest path, without
/// following symlinks.
pub fn lookup(guest: &str) -> (PathBuf, Area) {
    if HOST_DEVICES.contains(&guest) {
        return (PathBuf::from(guest), Area::HostDevice);
    }
    if let Some(host) = crate::sys::tty::pts_host(guest) {
        return (PathBuf::from(host), Area::HostDevice);
    }
    let v = vfs();
    if let Some((m, rest)) = holder(&v.mounts.read().unwrap(), guest) {
        let host = if rest.is_empty() {
            m.host.clone()
        } else {
            m.host.join(rest)
        };
        return (host, m.area);
    }
    (v.root.join(guest.trim_start_matches('/')), Area::Image)
}

/// The path fs-attrs knows a normalized guest path by, so that a file has
/// one owner and mode through whichever mount it is reached (a bind shows
/// its source's): its path through the path map entry with the shortest
/// host prefix (the area itself rather than a bind into it), or through
/// the image root; in a tmpfs of this process, the host path (private to
/// the process and its children).
/// `path` below `prefix`, as `Path::strip_prefix`; a byte comparison first
/// rules out most of the mounts a lookup goes through.
fn strip_host_prefix<'p>(path: &'p Path, prefix: &Path) -> Option<&'p Path> {
    let bytes = prefix.as_os_str().as_bytes();
    let trimmed = if bytes.len() > 1 {
        bytes.strip_suffix(b"/").unwrap_or(bytes)
    } else {
        bytes
    };
    if !path.as_os_str().as_bytes().starts_with(trimmed) {
        return None;
    }
    path.strip_prefix(prefix).ok()
}

pub fn attr_key(guest: &str) -> String {
    if !guest.starts_with('/') {
        return guest.to_string();
    }
    let (host, _) = lookup(guest);
    let v = vfs();
    let mounts = v.mounts.read().unwrap();
    let area = mounts
        .iter()
        .filter(|m| !m.own)
        .filter_map(|m| Some((m, strip_host_prefix(&host, &m.host)?)))
        .min_by_key(|(m, _)| (m.host.as_os_str().len(), m.guest.len()));
    if let Some((m, rest)) = area {
        return if rest.as_os_str().is_empty() {
            m.guest.clone()
        } else {
            format!("{}/{}", m.guest, rest.display())
        };
    }
    match host.strip_prefix(&v.root) {
        Ok(rel) => format!("/{}", rel.display()),
        Err(_) => host.display().to_string(),
    }
}

/// Mount `host` (with `area`) at the normalized guest path `guest`, over
/// whatever is there. `source` and `fstype` are what `/proc/mounts` shows.
pub fn add_mount(
    guest: &str,
    host: PathBuf,
    area: Area,
    source: &str,
    fstype: &str,
) -> Result<(), Errno> {
    install_mount(guest, host, area, source, fstype, None, None)
}
fn install_mount(
    guest: &str,
    host: PathBuf,
    area: Area,
    source: &str,
    fstype: &str,
    route: Option<FuseRoute>,
    bind_source: Option<String>,
) -> Result<(), Errno> {
    if !REPLAYING_NAMESPACE.with(std::cell::Cell::get) && mount_namespace_id().is_some() {
        let kind = match area {
            Area::Image => "ro",
            Area::Writable => "rw",
            Area::Kernfs => "kernfs",
            Area::HostDevice => "host-device",
            Area::Input => "input",
        };
        let shared = mount_propagation(guest) == Propagation::Shared;
        let mut event = format!("{kind}\t{guest}\t{}\t{source}\t{fstype}", host.display());
        if let Some(route) = &route {
            event.push_str(&format!(
                "\t{}\t{}\t{},{},{},{},{}",
                route.session.display(),
                route.relative,
                route.uid,
                route.gid,
                u8::from(route.allow_other),
                u8::from(route.default_permissions),
                u8::from(route.read_only)
            ));
        }
        event.push('\n');
        if shared {
            event.push_str(&format!("mount-shared\t{guest}\n"));
        }
        if let Some(source) = &bind_source {
            event.push_str(&format!("bind-source\t{guest}\t{source}\n"));
        }
        namespace_event(&event)?;
        propagate_created(guest)?;
        if let Some(route) = &route {
            publish_fuse_route(guest, &host, source, Some(route))?;
        } else {
            publish_plain_mount(guest, &host, area, source, fstype, bind_source.as_deref())?;
        }
        return Ok(());
    }
    let guest = if guest == "/" {
        guest
    } else {
        guest.trim_end_matches('/')
    };
    let mut mounts = vfs().mounts.write().unwrap();
    let seq = mounts.iter().map(|m| m.seq).max().unwrap_or(0) + 1;
    let at = mounts
        .iter()
        .position(|m| m.guest.len() <= guest.len())
        .unwrap_or(mounts.len());
    mounts.insert(
        at,
        Mount {
            guest: guest.to_string(),
            host,
            area,
            source: Some(source.to_string()),
            fstype: Some(fstype.to_string()),
            own: true,
            seq,
            fuse: route.clone(),
            shared_fuse: (route.is_some() || bind_source.is_some())
                && mount_propagation(guest) == Propagation::Shared,
            bind_source: bind_source.clone(),
            projected_fuse: false,
            origin: None,
        },
    );
    drop(mounts);
    if !REPLAYING_NAMESPACE.with(std::cell::Cell::get) {
        if let Some(route) = &route {
            let mount = vfs()
                .mounts
                .read()
                .unwrap()
                .iter()
                .find(|mount| mount.guest == guest && mount.own)
                .cloned()
                .ok_or(errno::ENOENT)?;
            publish_fuse_route(guest, &mount.host, source, Some(route))?;
        } else if bind_source.is_some() {
            let mount = vfs()
                .mounts
                .read()
                .unwrap()
                .iter()
                .find(|mount| mount.guest == guest && mount.own)
                .cloned()
                .ok_or(errno::ENOENT)?;
            publish_plain_mount(
                guest,
                &mount.host,
                area,
                source,
                fstype,
                bind_source.as_deref(),
            )?;
        }
    }
    Ok(())
}

/// The host file of `guest` on the mount that covers it, with that mount's
/// source and filesystem type.
///
/// An ext4 mount's host directory is the superblock installed when the
/// mount was created. A namespace copy names the same directory. Reading
/// it does not open the loop or dm device again.
pub(crate) fn mounted_backend(guest: &str) -> Option<(PathBuf, String, String)> {
    let mounts = vfs().mounts.read().ok()?;
    let mount = mounts
        .iter()
        .filter(|mount| {
            mount.own
                && (mount.guest == guest || below(&mount.guest, guest).is_some())
                && !ext4_host_gone(mount)
        })
        .max_by_key(|mount| (mount.guest.len(), mount.seq))?;
    let relative = if guest == mount.guest {
        ""
    } else {
        below(&mount.guest, guest)?
    };
    Some((
        mount.host.join(relative),
        mount.source.clone().unwrap_or_default(),
        mount.fstype.clone().unwrap_or_default(),
    ))
}

/// The filesystem type of the mount that holds the normalized guest path.
pub fn fstype(guest: &str) -> Option<String> {
    let mounts = VFS.get()?.mounts.read().unwrap();
    holder(&mounts, guest).and_then(|(m, _)| m.fstype.clone())
}

/// The kernel filesystem `guest` is on, and the path below its root, for
/// the mounts that name one (bpffs, cgroup2).
pub fn fs_path(guest: &str) -> Option<(String, String)> {
    let mounts = vfs().mounts.read().unwrap();
    mounts
        .iter()
        .filter(|m| m.fstype.is_some())
        .filter_map(|m| {
            let rest = guest.strip_prefix(m.guest.as_str())?;
            (rest.is_empty() || rest.starts_with('/')).then_some((m, rest))
        })
        .max_by_key(|(m, _)| m.guest.len())
        .map(|(m, rest)| {
            let rest = if rest.is_empty() { "/" } else { rest };
            // A cgroup v1 hierarchy is a `cgroup` filesystem.
            let fstype = m.fstype.clone().unwrap();
            let fstype = if fstype.starts_with("cgroup:") {
                "cgroup".to_string()
            } else {
                fstype
            };
            (fstype, rest.to_string())
        })
}

pub fn remount_fuse(guest: &str, read_only: bool) -> Result<bool, Errno> {
    refresh_fuse_mounts()?;
    let mount = {
        let mounts = vfs().mounts.read().unwrap();
        mounts
            .iter()
            .find(|mount| mount.guest == guest && mount.fuse.is_some())
            .cloned()
    };
    let Some(mount) = mount else { return Ok(false) };
    let seq = mount.seq;
    let mut route = mount.fuse.unwrap();
    route.read_only = read_only;
    publish_fuse_route(
        guest,
        &mount.host,
        mount.source.as_deref().unwrap_or("fuse"),
        Some(&route),
    )?;
    let mut mounts = vfs().mounts.write().unwrap();
    if let Some(mount) = mounts
        .iter_mut()
        .find(|mount| mount.guest == guest && mount.seq == seq)
    {
        mount.fuse = Some(route);
    }
    drop(mounts);
    publish_mount_policy(guest)?;
    Ok(true)
}

/// Where a mount event at `child` lands on one peer of its parent.
///
/// The peer keeps its own path. A bind of `/bootstrap-apex` onto a private
/// `/apex` joins `/bootstrap-apex`'s peer group, so a later mount under
/// `/apex` is `/bootstrap-apex/...` in the default namespace, not another
/// `/apex`.
fn peer_path(parent: &str, child: &str, receiver: &str) -> Option<String> {
    let relative = if parent == "/" {
        child.strip_prefix('/')?
    } else if child == parent {
        ""
    } else {
        child.strip_prefix(parent)?.strip_prefix('/')?
    };
    if relative.is_empty() {
        return Some(receiver.to_string());
    }
    if receiver == "/" {
        Some(format!("/{relative}"))
    } else {
        Some(format!("{}/{relative}", receiver.trim_end_matches('/')))
    }
}

struct PropCopy {
    namespace: aim_storage::mount_namespace::Namespace,
    /// The path of this event on the receiving peer.
    guest: String,
    receiver: String,
    shared: u64,
    master: u64,
    same: bool,
}

/// Peers that receive a mount or unmount at `guest`, including another
/// peer in this namespace (a bind of a shared mount).
///
/// The containing mount is the parent. A shared parent propagates to its
/// peers and to its slaves. A private or slave parent sends nothing. The
/// copy's path is the receiver's path plus the path below the parent, not
/// the source path.
fn propagation_copies(guest: &str) -> Result<Vec<PropCopy>, Errno> {
    if REPLAYING_NAMESPACE.with(std::cell::Cell::get) {
        return Ok(Vec::new());
    }
    let Some(owner) = NAMESPACE_VIEW
        .lock()
        .unwrap()
        .as_ref()
        .map(|view| view.owner.clone())
    else {
        return Ok(Vec::new());
    };
    let state = owner.read().map_err(namespace_error)?;
    let Some(record) = state
        .mounts
        .iter()
        .filter(|mount| mount.guest == guest)
        .max_by_key(|mount| mount.id)
        .cloned()
    else {
        return Ok(Vec::new());
    };
    let Some(parent) = state
        .mounts
        .iter()
        .find(|mount| mount.id == record.parent)
        .cloned()
    else {
        return Ok(Vec::new());
    };
    if parent.shared == 0 || parent.id == record.id {
        return Ok(Vec::new());
    }
    let runtime = owner.runtime().to_path_buf();
    let mut namespaces = vec![(owner.clone(), true)];
    for id in aim_storage::mount_namespace::Namespace::ids(&runtime).map_err(namespace_error)? {
        if id == owner.id() {
            continue;
        }
        namespaces.push((
            aim_storage::mount_namespace::Namespace::open(&runtime, &id).map_err(namespace_error)?,
            false,
        ));
    }
    drop(state);
    let mut copies = Vec::new();
    for (namespace, same) in namespaces {
        let state = if same {
            owner.read().map_err(namespace_error)?
        } else {
            namespace.read().map_err(namespace_error)?
        };
        let mut newest: Vec<aim_storage::mount_namespace::MountRecord> = Vec::new();
        for mount in &state.mounts {
            if mount.shared != parent.shared && mount.master != parent.shared {
                continue;
            }
            if same && mount.id == parent.id {
                continue;
            }
            if let Some(slot) = newest.iter_mut().find(|kept| kept.guest == mount.guest) {
                if mount.id > slot.id {
                    *slot = mount.clone();
                }
            } else {
                newest.push(mount.clone());
            }
        }
        for mount in newest {
            let Some(dest) = peer_path(&parent.guest, guest, &mount.guest) else {
                continue;
            };
            if same && dest == guest {
                continue;
            }
            let (shared, master) = if mount.shared == parent.shared {
                (record.shared, record.master)
            } else if mount.shared == 0 {
                (0, record.shared)
            } else {
                (
                    namespace
                        .propagated_group(record.id, mount.shared)
                        .map_err(namespace_error)?,
                    record.shared,
                )
            };
            copies.push(PropCopy {
                namespace: namespace.clone(),
                guest: dest,
                receiver: mount.guest,
                shared,
                master,
                same,
            });
        }
    }
    Ok(copies)
}

fn write_propagation(copy: &PropCopy, event: &str) -> Result<(), Errno> {
    if copy.same {
        namespace_event(event)
    } else {
        copy.namespace.append(event).map_err(namespace_error)?;
        Ok(())
    }
}

/// Copy the mount just created at `guest` into every peer of its parent.
///
/// A FUSE route already reaches peers through the shared route table.
/// A second plain copy at the same path would hide that route. The copy
/// uses the peer's path: a mount made under `/apex` after that directory
/// was bound over a shared `/bootstrap-apex` is created at
/// `/bootstrap-apex` in every peer, including this namespace.
fn propagate_created(guest: &str) -> Result<(), Errno> {
    if vfs().mounts.read().unwrap().iter().any(|mount| {
        mount.guest == guest && mount.own && mount.fuse.is_some()
    }) {
        return Ok(());
    }
    let copies = propagation_copies(guest)?;
    if copies.is_empty() {
        return Ok(());
    }
    let owner = NAMESPACE_VIEW
        .lock()
        .unwrap()
        .as_ref()
        .map(|view| view.owner.clone())
        .ok_or(errno::ENODEV)?;
    let state = owner.read().map_err(namespace_error)?;
    let record = state
        .mounts
        .iter()
        .filter(|mount| mount.guest == guest)
        .max_by_key(|mount| mount.id)
        .ok_or(errno::ENOENT)?
        .clone();
    drop(state);
    let mut same = false;
    for copy in &copies {
        write_propagation(
            copy,
            &format!(
                "propagated\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                copy.shared, copy.master, record.kind, copy.guest, record.host, record.source,
                record.fstype
            ),
        )?;
        same |= copy.same;
    }
    if same {
        refresh_namespace()?;
    }
    Ok(())
}

/// Remove the latest mount this process made at `guest`.
pub fn remove_mount(guest: &str) -> Result<bool, Errno> {
    refresh_namespace()?;
    if !REPLAYING_NAMESPACE.with(std::cell::Cell::get) && mount_namespace_id().is_some() {
        if !vfs()
            .mounts
            .read()
            .unwrap()
            .iter()
            .any(|mount| mount.guest == guest && mount.own)
        {
            return Ok(false);
        }
        let copies = propagation_copies(guest)?;
        namespace_event(&format!("remove\t{guest}"))?;
        for copy in &copies {
            write_propagation(copy, &format!("remove\t{}", copy.guest))?;
        }
        publish_fuse_route(guest, Path::new(""), "", None)?;
        return Ok(true);
    }
    if !REPLAYING_NAMESPACE.with(std::cell::Cell::get)
        && vfs()
            .mounts
            .read()
            .unwrap()
            .iter()
            .any(|mount| mount.guest == guest && mount.shared_fuse)
    {
        publish_fuse_route(guest, Path::new(""), "", None)?;
    }
    let mut mounts = vfs().mounts.write().unwrap();
    match mounts.iter().position(|m| m.guest == guest && m.own) {
        Some(i) => {
            mounts.remove(i);
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Whether the latest visible mount at `guest` has mounts attached below it.
pub fn mount_has_children(guest: &str) -> Result<bool, Errno> {
    refresh_namespace()?;
    let mounts = vfs().mounts.read().unwrap();
    let Some(target) = mounts
        .iter()
        .find(|mount| mount.guest == guest && mount.own)
    else {
        return Ok(false);
    };
    Ok(mounts
        .iter()
        .any(|mount| mount.own && mount.seq > target.seq && below(guest, &mount.guest).is_some()))
}

/// Detach the latest mount at `guest` and every mount attached below that
/// visible mount. Older descendants hidden before the target was mounted stay
/// with the underlying mount tree.
pub fn detach_mount(guest: &str) -> Result<bool, Errno> {
    refresh_namespace()?;
    let detached = {
        let mounts = vfs().mounts.read().unwrap();
        let Some(target) = mounts
            .iter()
            .find(|mount| mount.guest == guest && mount.own)
        else {
            return Ok(false);
        };
        mounts
            .iter()
            .filter(|mount| {
                mount.own
                    && (mount.guest == target.guest && mount.seq == target.seq
                        || mount.seq > target.seq && below(guest, &mount.guest).is_some())
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    if !REPLAYING_NAMESPACE.with(std::cell::Cell::get) && mount_namespace_id().is_some() {
        let copies = propagation_copies(guest)?;
        namespace_event(&format!("detach\t{guest}"))?;
        for copy in &copies {
            write_propagation(copy, &format!("detach\t{}", copy.guest))?;
        }
        for mount in detached.iter().filter(|mount| mount.shared_fuse) {
            publish_fuse_route(&mount.guest, Path::new(""), "", None)?;
        }
        return Ok(true);
    }
    if !REPLAYING_NAMESPACE.with(std::cell::Cell::get) {
        for mount in detached.iter().filter(|mount| mount.shared_fuse) {
            publish_fuse_route(&mount.guest, Path::new(""), "", None)?;
        }
    }
    let identities = detached
        .iter()
        .map(|mount| (mount.guest.as_str(), mount.seq))
        .collect::<Vec<_>>();
    vfs().mounts.write().unwrap().retain(|mount| {
        !identities
            .iter()
            .any(|(guest, seq)| mount.guest == *guest && mount.seq == *seq)
    });
    Ok(true)
}

/// Move the latest mount at `from`, and this process's mounts below it, to
/// `to`.
pub fn move_mount(from: &str, to: &str) -> Result<bool, Errno> {
    refresh_namespace()?;
    if !REPLAYING_NAMESPACE.with(std::cell::Cell::get) && mount_namespace_id().is_some() {
        let moved = vfs()
            .mounts
            .read()
            .unwrap()
            .iter()
            .filter(|mount| {
                mount.own && (mount.guest == from || below(from, &mount.guest).is_some())
            })
            .cloned()
            .collect::<Vec<_>>();
        if !moved.iter().any(|mount| mount.guest == from) {
            return Ok(false);
        }
        let copies = propagation_copies(from)?;
        namespace_event(&format!("move\t{from}\t{to}"))?;
        for copy in &copies {
            let dest = if copy.guest == from {
                to.to_string()
            } else if let Some(rest) = to.strip_prefix(from) {
                format!("{}{rest}", copy.guest.trim_end_matches('/'))
            } else {
                peer_path(&copy.receiver, to, &copy.receiver).unwrap_or_else(|| to.to_string())
            };
            write_propagation(copy, &format!("move\t{}\t{dest}", copy.guest))?;
        }
        for mount in moved {
            if mount.shared_fuse {
                publish_fuse_route(&mount.guest, Path::new(""), "", None)?;
            }
            let guest = format!("{to}{}", &mount.guest[from.len()..]);
            if let Some(route) = &mount.fuse {
                publish_fuse_route(
                    &guest,
                    &mount.host,
                    mount.source.as_deref().unwrap_or("fuse"),
                    Some(route),
                )?;
            } else {
                publish_plain_mount(
                    &guest,
                    &mount.host,
                    mount.area,
                    mount.source.as_deref().unwrap_or(""),
                    mount.fstype.as_deref().unwrap_or(""),
                    mount.bind_source.as_deref(),
                )?;
            }
        }
        return Ok(true);
    }
    let mut mounts = vfs().mounts.write().unwrap();
    let Some(i) = mounts.iter().position(|m| m.guest == from && m.own) else {
        return Ok(false);
    };
    let mut moved = vec![mounts.remove(i)];
    let below = format!("{from}/");
    while let Some(j) = mounts
        .iter()
        .position(|m| m.own && m.guest.starts_with(&below))
    {
        moved.push(mounts.remove(j));
    }
    drop(mounts);
    for m in moved {
        let guest = format!("{to}{}", &m.guest[from.len()..]);
        let (source, fstype) = (m.source.unwrap_or_default(), m.fstype.unwrap_or_default());
        let shared = m.shared_fuse;
        let projected = m.projected_fuse;
        install_mount(
            &guest,
            m.host,
            m.area,
            &source,
            &fstype,
            m.fuse,
            m.bind_source,
        )?;
        let mut mounts = vfs().mounts.write().unwrap();
        if let Some(mount) = mounts
            .iter_mut()
            .find(|mount| mount.guest == guest && mount.own)
        {
            mount.shared_fuse = shared;
            mount.projected_fuse = projected;
        }
    }
    Ok(true)
}

/// This process's own mounts, oldest first, as `--mounts` text for the
/// program it execs: `ro|rw<TAB>guest<TAB>host<TAB>source<TAB>fstype`
/// lines.
pub(crate) fn fork_mounts_text(private: bool) -> Result<String, Errno> {
    let text = own_mounts_text();
    if !private {
        return Ok(text);
    }
    let owner = NAMESPACE_VIEW
        .lock()
        .unwrap()
        .as_ref()
        .map(|view| view.owner.clone())
        .ok_or(errno::ENODEV)?;
    let id = namespace_id("fork")?;
    let child = owner.clone_to(&id).map_err(namespace_error)?;
    child
        .append("namespace\tprivate\n")
        .map_err(namespace_error)?;
    Ok(text.replace(
        &format!("namespace-owner\t{}\n", owner.id()),
        &format!("namespace-owner\t{id}\n"),
    ))
}
pub(crate) fn publish_fork_mounts(pid: i32, text: &str) -> Result<(), Errno> {
    let Some(table) = crate::sys::cred::by_pid_dir() else {
        return Ok(());
    };
    let Some(id) = text
        .lines()
        .find_map(|line| line.strip_prefix("namespace-owner\t"))
    else {
        return Err(errno::ENODEV);
    };
    let process =
        aim_storage::process_namespace::ProcessIdentity::running(pid).map_err(namespace_error)?;
    aim_storage::process_namespace::register_mount_namespace(table, process, id)
        .map_err(namespace_error)
}

pub fn own_mounts_text() -> String {
    let mounts = vfs().mounts.read().unwrap();
    let namespace = mount_namespace_id();
    let mut out = if PRIVATE_MOUNTS.load(Ordering::Acquire) {
        "namespace\tprivate\n".to_owned()
    } else {
        String::new()
    };
    if let Some(id) = namespace {
        out.push_str(&format!("namespace-owner\t{id}\n"));
        if let Some(runtime) = runtime_dir() {
            out.push_str(&format!("namespace-runtime\t{}\n", runtime.display()));
        }
    }
    for (root, kind) in PROPAGATION_RULES.lock().unwrap().iter() {
        out.push_str(&format!(
            "propagation\t{root}\t{}\n",
            match kind {
                Propagation::Private => "private",
                Propagation::Slave => "slave",
                Propagation::Shared => "shared",
            }
        ));
    }
    let mut own: Vec<&Mount> = mounts.iter().filter(|m| m.own).collect();
    own.reverse();
    for m in own {
        let area = match m.area {
            Area::Image => "ro",
            Area::Writable => "rw",
            Area::Kernfs => "kernfs",
            Area::HostDevice => "host-device",
            Area::Input => "input",
        };
        out.push_str(&format!(
            "{area}\t{}\t{}\t{}\t{}",
            m.guest,
            m.host.display(),
            m.source.as_deref().unwrap_or_default(),
            m.fstype.as_deref().unwrap_or_default()
        ));
        if let Some(route) = &m.fuse {
            out.push_str(&format!(
                "\t{}\t{}\t{},{},{},{},{}",
                route.session.display(),
                route.relative,
                route.uid,
                route.gid,
                u8::from(route.allow_other),
                u8::from(route.default_permissions),
                u8::from(route.read_only)
            ));
        }
        out.push('\n');
        if m.shared_fuse {
            out.push_str(&format!("mount-shared\t{}\n", m.guest));
        }
        if m.projected_fuse {
            out.push_str(&format!("mount-projected\t{}\n", m.guest));
        }
        if let Some(source) = &m.bind_source {
            out.push_str(&format!("bind-source\t{}\t{}\n", m.guest, source));
        }
    }
    out
}

/// Restore the mounts [`own_mounts_text`] described.
pub fn load_own_mounts(text: &str) -> Result<(), Errno> {
    if !REPLAYING_NAMESPACE.with(std::cell::Cell::get) {
        if let Some(id) = text
            .lines()
            .find_map(|line| line.strip_prefix("namespace-owner\t"))
        {
            if let Some(runtime) = text
                .lines()
                .find_map(|line| line.strip_prefix("namespace-runtime\t"))
                .map(PathBuf::from)
                .or_else(|| runtime_dir().map(Path::to_path_buf))
            {
                let owner = aim_storage::mount_namespace::Namespace::open(&runtime, id)
                    .map_err(namespace_error)?;
                let page = owner.generation().map_err(namespace_error)?;
                *NAMESPACE_VIEW.lock().unwrap() = Some(NamespaceView {
                    owner,
                    generation: 0,
                    page,
                    records: Default::default(),
                });
                *current_mount_namespace().journal_id.lock().unwrap() = Some(id.to_owned());
                refresh_namespace()?;
                publish_process_namespace()?;
                return Ok(());
            }
        }
    }
    if text.lines().any(|line| line == "namespace\tprivate") {
        PRIVATE_MOUNTS.store(true, Ordering::Release);
    }
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if let ["propagation", root, kind] = f.as_slice() {
            let kind = match *kind {
                "slave" => Propagation::Slave,
                "shared" => Propagation::Shared,
                _ => Propagation::Private,
            };
            PROPAGATION_RULES
                .lock()
                .unwrap()
                .push(((*root).into(), kind));
            continue;
        }
        if let ["mount-shared", guest] = f.as_slice() {
            let mut mounts = vfs().mounts.write().unwrap();
            if let Some(mount) = mounts
                .iter_mut()
                .find(|mount| mount.guest == *guest && mount.own)
            {
                mount.shared_fuse = true;
            }
            continue;
        }
        if let ["mount-projected", guest] = f.as_slice() {
            let mut mounts = vfs().mounts.write().unwrap();
            if let Some(mount) = mounts
                .iter_mut()
                .find(|mount| mount.guest == *guest && mount.own)
            {
                mount.projected_fuse = true;
            }
            continue;
        }
        if let ["bind-source", guest, source] = f.as_slice() {
            let mut mounts = vfs().mounts.write().unwrap();
            if let Some(mount) = mounts
                .iter_mut()
                .find(|mount| mount.guest == *guest && mount.own)
            {
                mount.bind_source = Some((*source).into());
            }
            continue;
        }
        if f.len() == 5 || f.len() == 8 {
            let (area, guest, host, source, fstype) = (f[0], f[1], f[2], f[3], f[4]);
            let area = match area {
                "ro" => Area::Image,
                "rw" => Area::Writable,
                "kernfs" => Area::Kernfs,
                "host-device" => Area::HostDevice,
                "input" => Area::Input,
                _ => return Err(errno::EINVAL),
            };
            add_mount(guest, PathBuf::from(host), area, source, fstype)?;
            if f.len() == 8 {
                let policy = f[7]
                    .split(',')
                    .map(str::parse::<u32>)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| errno::EINVAL)?;
                if policy.len() != 5 || policy[2..].iter().any(|value| *value > 1) {
                    return Err(errno::EINVAL);
                }
                let mut mounts = vfs().mounts.write().unwrap();
                if let Some(mount) = mounts
                    .iter_mut()
                    .find(|mount| mount.guest == guest && mount.own)
                {
                    mount.fuse = Some(FuseRoute {
                        session: PathBuf::from(f[5]),
                        relative: f[6].into(),
                        uid: policy[0],
                        gid: policy[1],
                        allow_other: policy[2] != 0,
                        default_permissions: policy[3] != 0,
                        read_only: policy[4] != 0,
                    });
                }
            }
        }
    }
    Ok(())
}

/// One inverse namespace view for a generated procfs read. Host aliases are
/// resolved once per view; a later read observes mount and symlink changes.
pub(crate) struct HostPathView {
    visible: Arc<Visible>,
    root: PathBuf,
    canonical_mounts: std::cell::OnceCell<Vec<(String, PathBuf)>>,
    canonical_root: std::cell::OnceCell<PathBuf>,
}

/// The visible mounts of a mount table, by guest and host path.
struct Visible {
    mounts: Vec<(String, PathBuf)>,
    /// Those whose host path is not canonical when the table is first
    /// seen (an alias through a symlink, or not there yet): each view
    /// resolves them again. A canonical one stays so (`canonical_host`).
    aliases: Vec<(String, PathBuf)>,
}

impl HostPathView {
    pub(crate) fn capture() -> Option<Self> {
        /// The visible mounts of the last mount table seen, by its
        /// generation: the table changes far less often than a stat asks.
        static VISIBLE: Mutex<Option<(u64, Arc<Visible>)>> = Mutex::new(None);
        let v = VFS.get()?;
        let mounts = v.mounts.read().unwrap();
        let mut visible = VISIBLE.lock().unwrap();
        let current = match visible.as_ref() {
            Some((generation, current)) if *generation == mounts.generation() => current.clone(),
            _ => {
                let all: Vec<_> = mounts
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| mounts.visible(*index))
                    .map(|(_, m)| (m.guest.clone(), m.host.clone()))
                    .collect();
                let aliases = all
                    .iter()
                    .filter(|(_, host)| canonical_host(host).as_ref() != Some(host))
                    .cloned()
                    .collect();
                let current = Arc::new(Visible {
                    mounts: all,
                    aliases,
                });
                *visible = Some((mounts.generation(), current.clone()));
                current
            }
        };
        drop(visible);
        Some(Self {
            visible: current,
            root: v.root.clone(),
            canonical_mounts: std::cell::OnceCell::new(),
            canonical_root: std::cell::OnceCell::new(),
        })
    }

    pub(crate) fn guest_path(&self, host: &Path) -> Option<String> {
        let s = host.to_str()?;
        if HOST_DEVICES.contains(&s) {
            return Some(s.to_owned());
        }
        if let Some(guest) = crate::sys::tty::pts_guest(s) {
            return Some(guest);
        }
        let mut best: Option<(usize, usize, String)> = None;
        let canonical = self.canonical_mounts.get_or_init(|| {
            self.visible
                .aliases
                .iter()
                .filter_map(|(guest, path)| canonical_host(path).map(|path| (guest.clone(), path)))
                .collect()
        });
        // The implicit root competes with bind aliases of the same host tree;
        // a later alias cannot rename ordinary paths already rooted at `/`.
        let root = self
            .canonical_root
            .get_or_init(|| canonical_host(&self.root).unwrap_or_else(|| self.root.clone()));
        let roots = [
            ("/".to_owned(), self.root.clone()),
            ("/".to_owned(), root.clone()),
        ];
        for (guest, prefix) in self
            .visible
            .mounts
            .iter()
            .chain(canonical.iter())
            .chain(roots.iter())
        {
            let Some(rest) = strip_host_prefix(host, prefix) else {
                continue;
            };
            let len = prefix.as_os_str().len();
            if best
                .as_ref()
                .is_none_or(|b| len > b.0 || (len == b.0 && guest.len() < b.1))
            {
                let path = if rest.as_os_str().is_empty() {
                    guest.clone()
                } else {
                    format!("{}/{}", guest.trim_end_matches('/'), rest.display())
                };
                best = Some((len, guest.len(), path));
            }
        }
        best.map(|(_, _, guest)| guest)
    }
}

/// The canonical form of a mount's host path. A path that was already
/// canonical stays so and is resolved once per process; one through a
/// symlink is resolved again each time, so a retargeted alias is seen.
fn canonical_host(path: &Path) -> Option<PathBuf> {
    // Hashed as bytes: Path's own ordering compares component by component.
    static CANONICAL: std::sync::LazyLock<Mutex<HashSet<std::ffi::OsString>>> =
        std::sync::LazyLock::new(Default::default);
    if CANONICAL.lock().unwrap().contains(path.as_os_str()) {
        return Some(path.to_path_buf());
    }
    let canonical = path.canonicalize().ok()?;
    if canonical == path {
        CANONICAL
            .lock()
            .unwrap()
            .insert(canonical.clone().into_os_string());
    }
    Some(canonical)
}

/// Guest path of a host path, if it lies inside the root or a mapped area.
pub fn guest_path_of_host(host: &Path) -> Option<String> {
    HostPathView::capture()?.guest_path(host)
}

/// Guest path of an open directory fd, and whether it is by host names
/// (one the host knows it by, which [`visible`] maps), not as the guest
/// names it already (a FUSE file's, a synthesized directory's).
fn guest_path_of_fd(fd: i32) -> Result<(String, bool), Errno> {
    use std::os::fd::AsRawFd;
    let pin = crate::sys::fdtab::pin_guest(fd)?;
    let fd = pin.descriptor().as_raw_fd();
    if let Some(file) = crate::sys::fuse_client::get(fd) {
        if !file.directory {
            return Err(errno::ENOTDIR);
        }
        return Ok((file.guest.clone(), false));
    }
    if crate::sys::fdtab::character_reference(fd).is_some() {
        return Err(errno::ENOTDIR);
    }
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } < 0 {
        return Err(errno::last());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(errno::ENOTDIR);
    }
    if let Some(p) = crate::sys::synthesized_dir_path(fd) {
        return Ok((p, false));
    }
    let mut buf = [0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes.
    if unsafe { crate::sys::fgetpath(fd, buf.as_mut_ptr()) } < 0 {
        return Err(errno::last());
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let host = Path::new(OsStr::from_bytes(&buf[..len]));
    Ok((
        guest_path_of_host(host).unwrap_or_else(|| host.display().to_string()),
        true,
    ))
}

/// `guest`, a path of host names, as the guest names it: an entry of a
/// locked directory by its no-key name (fscrypt).
pub(crate) fn visible(guest: String) -> Result<String, Errno> {
    if !crate::sys::fscrypt::locking()? {
        return Ok(guest);
    }
    Ok(join_guest(&Walk::of(&guest, true)?.guest))
}

fn join_guest(components: &[Vec<u8>]) -> String {
    let mut guest = String::new();
    for c in components {
        guest.push('/');
        guest.push_str(&String::from_utf8_lossy(c));
    }
    if guest.is_empty() {
        guest.push('/');
    }
    guest
}

pub struct Resolved {
    pub host: CString,
    pub guest: String,
    pub area: Area,
    /// Whether the walk passed an encrypted directory whose key is present
    /// that holds it, so that it is not locked (fscrypt, [`dir_lock`]).
    pub unlocked: bool,
}

impl Resolved {
    /// Whether the guest may not modify this path (the image under a path
    /// map): writes fail with EROFS.
    pub fn read_only(&self) -> bool {
        self.area == Area::Image && vfs().mapped
    }
}

/// [`link_target`]'s answers for the read-only image (a symlink's target,
/// else the lstat of what is there), which never change: resolving walks
/// every component, and the image's paths are the most walked.
type ImageNode = (Option<PathBuf>, Option<libc::stat>);
static IMAGE_LINKS: Mutex<Option<HashMap<PathBuf, ImageNode>>> = Mutex::new(None);
const IMAGE_LINKS_MAX: usize = 1 << 14;

/// The target of `host` if it is a symlink, else (where an lstat found it)
/// its stat: a walk's check of the directory it is then needs no stat of
/// its own.
/// `host` is inside an ext4 payload directory. That tree is replaced when
/// a later payload is mounted; the immutable image root is not.
fn under_ext4_host(host: &Path) -> bool {
    let mut cursor = Some(host);
    while let Some(path) = cursor {
        if ext4_stamp_path(path).is_file() {
            return true;
        }
        cursor = path.parent().filter(|parent| *parent != path);
    }
    false
}

fn link_target(host: PathBuf, area: Area) -> ImageNode {
    let node = |host: &PathBuf| {
        let Ok(name) = host_cstring(host.clone()) else {
            return (None, None);
        };
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::lstat(name.as_ptr(), &mut stat) } < 0 {
            return (None, None);
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFLNK {
            return (None, Some(stat));
        }
        (std::fs::read_link(host).ok(), None)
    };
    if area != Area::Image || !vfs().mapped || under_ext4_host(&host) {
        return node(&host);
    }
    if let Some(known) = IMAGE_LINKS
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&host))
    {
        return known.clone();
    }
    let known = node(&host);
    let mut links = IMAGE_LINKS.lock().unwrap();
    let map = links.get_or_insert_with(HashMap::new);
    if map.len() >= IMAGE_LINKS_MAX {
        map.clear();
    }
    map.insert(host, known.clone());
    known
}

/// Resolve a guest path relative to a Linux dirfd into a host path.
pub fn resolve(dirfd: i32, path: &[u8], follow_last: bool) -> Result<Resolved, Errno> {
    resolve_inner(dirfd, path, follow_last, false, false, |_, _| Ok(()))
}
/// [`resolve`] of a path whose last component is to be created: in a
/// locked directory (fscrypt) that is ENOKEY, unless it names an entry.
pub fn resolve_new(dirfd: i32, path: &[u8]) -> Result<Resolved, Errno> {
    resolve_inner(dirfd, path, false, false, true, |_, _| Ok(()))
}
/// Resolve from the actual cwd/dirfd and check each searched directory, including
/// directories visited before a symlink or dot-dot changes the resolved path.
/// `check` gets the directory's path by its host names, as [`lookup`] maps
/// it ([`visible`] gives the guest's).
pub fn resolve_checked(
    dirfd: i32,
    path: &[u8],
    follow_last: bool,
    check: impl FnMut(&str, Option<&libc::stat>) -> Result<(), Errno>,
) -> Result<Resolved, Errno> {
    resolve_inner(dirfd, path, follow_last, true, false, check)
}
/// [`resolve_checked`] of a path whose last component may be created, as
/// [`resolve_new`].
pub fn resolve_checked_new(
    dirfd: i32,
    path: &[u8],
    follow_last: bool,
    check: impl FnMut(&str, Option<&libc::stat>) -> Result<(), Errno>,
) -> Result<Resolved, Errno> {
    resolve_inner(dirfd, path, follow_last, true, true, check)
}

/// The lock (fscrypt) of the directory with the guest path `dir` (by its
/// host names). Nothing off the data filesystem
/// ([`off_data`](crate::sys::fscrypt::off_data)) or below an encrypted
/// directory whose key is present is locked: `unlocked` keeps the host
/// path of the last such directory a walk passed, so that the directories
/// below it are not asked.
/// `stat` is the directory's host lstat where the walk took one. Returns
/// the lock and the directory's host path.
fn dir_lock(
    dir: &str,
    unlocked: &mut Option<PathBuf>,
    stat: Option<&libc::stat>,
) -> Result<(Lock, CString), Errno> {
    let (host, area) = lookup(dir);
    let path = host_cstring(host.clone())?;
    if unlocked.as_ref().is_some_and(|root| host.starts_with(root))
        || crate::sys::fscrypt::off_data(&host, area)?
    {
        return Ok((Lock::Plain, path));
    }
    let lock = crate::sys::fscrypt::path_lock(&path, stat)?;
    if let Lock::Unlocked = lock {
        *unlocked = Some(host);
    }
    Ok((lock, path))
}

/// The components a walk has passed: as the guest names them and, once a
/// locked directory's no-key name stands for an entry (fscrypt), as the
/// host does.
struct Walk {
    guest: Vec<Vec<u8>>,
    host: Option<Vec<Vec<u8>>>,
    /// The host path of the last encrypted directory passed whose key is
    /// present ([`dir_lock`]).
    unlocked: Option<PathBuf>,
}

impl Walk {
    /// The walk that passed `dir`, a path of host names, naming its
    /// components as the guest does ([`visible`]).
    fn of(dir: &str, locking: bool) -> Result<Self, Errno> {
        let mut walk = Walk {
            guest: Vec::new(),
            host: None,
            unlocked: None,
        };
        for name in dir.split('/').filter(|name| !name.is_empty()) {
            let name = name.as_bytes().to_vec();
            let shown = if locking {
                let (lock, _) = dir_lock(&walk.host_path(), &mut walk.unlocked, None)?;
                crate::sys::fscrypt::guest_name(&lock, &name)
            } else {
                name.clone()
            };
            if shown != name && walk.host.is_none() {
                walk.host = Some(walk.guest.clone());
            }
            if let Some(names) = &mut walk.host {
                names.push(name);
            }
            walk.guest.push(shown);
        }
        Ok(walk)
    }
    /// Adds `name`, looked up in the directory walked so far (whose host
    /// lstat `directory` is, where the walk took one); `new` when it is to
    /// be created.
    fn push(
        &mut self,
        name: Vec<u8>,
        locking: bool,
        new: bool,
        directory: Option<&libc::stat>,
    ) -> Result<(), Errno> {
        let host = if locking {
            let (lock, dir) = dir_lock(&self.host_path(), &mut self.unlocked, directory)?;
            crate::sys::fscrypt::host_name(&lock, &dir, &name, new)?
        } else {
            None
        };
        if host.is_some() && self.host.is_none() {
            self.host = Some(self.guest.clone());
        }
        if let Some(names) = &mut self.host {
            names.push(host.unwrap_or_else(|| name.clone()));
        }
        self.guest.push(name);
        Ok(())
    }
    fn pop(&mut self) {
        self.guest.pop();
        if let Some(names) = &mut self.host {
            names.pop();
        }
    }
    fn clear(&mut self) {
        self.guest.clear();
        self.host = None;
    }
    /// The guest path that names the walk's host path.
    fn host_path(&self) -> String {
        join_guest(self.host.as_ref().unwrap_or(&self.guest))
    }
}

fn host_cstring(path: PathBuf) -> Result<CString, Errno> {
    CString::new(path.into_os_string().into_vec()).map_err(|_| errno::EINVAL)
}

fn resolve_inner(
    dirfd: i32,
    path: &[u8],
    follow_last: bool,
    relative_base: bool,
    new: bool,
    mut check: impl FnMut(&str, Option<&libc::stat>) -> Result<(), Errno>,
) -> Result<Resolved, Errno> {
    refresh_fuse_mounts()?;
    if path.is_empty() {
        return Err(errno::ENOENT);
    }
    let locking = crate::sys::fscrypt::locking()?;
    // A checked walk relative to a directory fd starts where that
    // directory's path, by host names, leaves it: it is walked once.
    let mut start = None;
    let base = if path[0] == b'/' {
        String::from("/")
    } else if dirfd == LINUX_AT_FDCWD {
        cwd()
    } else {
        match guest_path_of_fd(dirfd)? {
            (base, true) if relative_base => {
                let walk = Walk::of(&base, locking)?;
                let base = join_guest(&walk.guest);
                start = Some(walk);
                base
            }
            (base, true) => visible(base)?,
            (base, false) => base,
        }
    };
    let mut pending: Vec<Vec<u8>> = Vec::new();
    let mut joined = base.as_bytes().to_vec();
    joined.push(b'/');
    joined.extend_from_slice(path);
    for c in joined.split(|&b| b == b'/').rev() {
        if !c.is_empty() {
            pending.push(c.to_vec());
        }
    }
    let mut done = Walk {
        guest: Vec::new(),
        host: None,
        unlocked: None,
    };
    if relative_base && path[0] != b'/' {
        match start {
            Some(walk) => done = walk,
            None => {
                for part in base.split('/').filter(|part| !part.is_empty()) {
                    done.push(part.as_bytes().to_vec(), locking, false, None)?;
                }
            }
        }
        pending = path
            .split(|&byte| byte == b'/')
            .filter(|part| !part.is_empty())
            .rev()
            .map(<[u8]>::to_vec)
            .collect();
    }
    let mut links = 0;
    let mut fuse_walk = None;
    // The host lstat of the walk's last component, where one was taken;
    // for a checked walk's start, its directory's (on the image, kept).
    let mut known = if relative_base {
        let (host, area) = lookup(&done.host_path());
        link_target(host, area).1
    } else {
        None
    };
    while let Some(c) = pending.pop() {
        // The checks stat the directory by its host names.
        check(&done.host_path(), known.as_ref())?;
        match c.as_slice() {
            b"." => continue,
            b".." => {
                fuse_walk = None;
                known = None;
                done.pop();
                continue;
            }
            _ => {}
        }
        let directory = known.take();
        let is_last = pending.is_empty();
        done.push(c, locking, new && is_last, directory.as_ref())?;
        if is_last && !follow_last {
            break;
        }
        if done.guest[0] == b"proc" {
            continue;
        }
        let current = join_guest(&done.guest);
        if let Some(route) = fuse_route(&current) {
            let next = match crate::sys::fuse_client::Walk::advance(&route, fuse_walk.as_ref()) {
                Ok(next) => next,
                Err(errno::ENOENT) if is_last => {
                    fuse_walk = None;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if next.mode & libc::S_IFMT as u32 != libc::S_IFLNK as u32 {
                if !is_last && next.mode & libc::S_IFMT as u32 != libc::S_IFDIR as u32 {
                    return Err(errno::ENOTDIR);
                }
                fuse_walk = Some(next);
                continue;
            }
            fuse_walk = None;
            links += 1;
            if links > MAX_SYMLINKS {
                return Err(errno::ELOOP);
            }
            done.pop();
            let target = crate::sys::fuse_client::readlink_node(&route, next.node())?;
            if target.first() == Some(&b'/') {
                done.clear();
            }
            for part in target.split(|byte| *byte == b'/').rev() {
                if !part.is_empty() {
                    pending.push(part.to_vec());
                }
            }
            continue;
        }
        fuse_walk = None;
        let named = done.host.as_ref().map(|names| join_guest(names));
        let (host, area) = lookup(named.as_deref().unwrap_or(&current));
        // A symlink off the data filesystem or below an encrypted directory
        // whose key is present is not locked ([`dir_lock`]).
        let link = (locking
            && !done
                .unlocked
                .as_ref()
                .is_some_and(|root| host.starts_with(root))
            && !crate::sys::fscrypt::off_data(&host, area)?)
        .then(|| host_cstring(host.clone()))
        .transpose()?;
        let (target, stat) = link_target(host, area);
        let Some(mut target) = target else {
            known = stat;
            continue;
        };
        if let Some(link) = link {
            let bytes =
                crate::sys::fscrypt::link_target(&link, target.into_os_string().into_vec())?;
            target = PathBuf::from(OsStr::from_bytes(&bytes));
        }
        links += 1;
        if links > MAX_SYMLINKS {
            return Err(errno::ELOOP);
        }
        done.pop();
        let t = target.as_os_str().as_bytes();
        if t.first() == Some(&b'/') {
            done.clear();
        }
        for part in t.split(|&b| b == b'/').rev() {
            if !part.is_empty() {
                pending.push(part.to_vec());
            }
        }
    }
    let guest = join_guest(&done.guest);
    let named = done.host.as_ref().map(|names| join_guest(names));
    let (host, area) = lookup(named.as_deref().unwrap_or(&guest));
    Ok(Resolved {
        unlocked: done
            .unlocked
            .as_ref()
            .is_some_and(|root| host.starts_with(root)),
        host: CString::new(host.as_os_str().as_bytes()).map_err(|_| errno::EINVAL)?,
        guest,
        area,
    })
}

#[cfg(test)]
static TEST_VIEW: OnceLock<PathBuf> = OnceLock::new();

/// The process-wide view the unit tests share (it is initialized once):
/// `/data` and the data mirrors as guest-init maps them. The guard keeps
/// tests that mount from running at the same time. Its directory goes
/// when the test process exits.
#[cfg(test)]
pub(crate) fn test_view() -> (std::sync::MutexGuard<'static, ()>, &'static Path) {
    static LOCK: Mutex<()> = Mutex::new(());
    // Only the process that made it: a fork child's exit leaves it.
    extern "C" fn remove_test_view() {
        if let Some(dir) = TEST_VIEW.get()
            && dir.ends_with(format!("vfs-view-{}", std::process::id()))
            && let Err(error) = std::fs::remove_dir_all(dir)
        {
            eprintln!("{}: {error}", dir.display());
        }
    }
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TEST_VIEW.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("vfs-view-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // SAFETY: registering a function of this process for its exit.
        unsafe { libc::atexit(remove_test_view) };
        let (root, data) = (dir.join("root"), dir.join("data"));
        for d in [&root, &data, &dir.join("run/data_mirror")] {
            std::fs::create_dir_all(d).unwrap();
        }
        let map = dir.join("run/path-map");
        let d = data.display();
        std::fs::write(
            &map,
            format!(
                "rw\t/data\t{d}\n\
                 rw\t/data/user/0\t{d}/data\n\
                 rw\t/data_mirror\t{}\n\
                 rw\t/data_mirror/data_ce/null\t{d}/user\n\
                 rw\t/data_mirror/data_ce/null/0\t{d}/data\n\
                 rw\t/data_mirror/data_de/null\t{d}/user_de\n",
                dir.join("run/data_mirror").display()
            ),
        )
        .unwrap();
        let proofs = dir.join("fs-verity");
        std::fs::create_dir(&proofs).unwrap();
        let proofs = std::fs::canonicalize(proofs).unwrap();
        let mut locator = b"AIMVRTROOT01\0".to_vec();
        locator.extend_from_slice(proofs.as_os_str().as_bytes());
        std::fs::write(dir.join("run/fs-verity-root"), locator).unwrap();
        aim_storage::fscrypt::Owner::prepare(&dir.join("run"), &dir).unwrap();
        init(&root, Some(&map)).unwrap();
        dir
    });
    (guard, dir)
}

#[cfg(test)]
mod tests {
    /// The layer's unnamed files are made in the runtime directory's
    /// scratch directory, not $TMPDIR, and leave no name behind.
    #[test]
    fn unnamed_files_are_made_in_the_runtime_scratch_directory() {
        let (_view, _) = super::test_view();
        let scratch = super::runtime_dir().unwrap().join("scratch");
        let fd = super::unnamed_file("vfs-test").unwrap();
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(fd, &mut stat) }, 0);
        assert_eq!(stat.st_nlink, 0);
        let mut directory: libc::stat = unsafe { std::mem::zeroed() };
        let path = std::ffi::CString::new(scratch.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::stat(path.as_ptr(), &mut directory) }, 0);
        assert_eq!(stat.st_dev, directory.st_dev);
        assert!(std::fs::read_dir(&scratch).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("vfs-test")
        }));
        unsafe { libc::close(fd) };
    }

    /// A scratch directory made under a guest's umask is still the
    /// layer's to make files in.
    #[test]
    fn the_scratch_directory_does_not_take_the_guest_umask() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::tests::the_scratch_directory_does_not_take_the_guest_umask",
        ) {
            return;
        }
        let root = aim_paths::Scratch::new("vfs-scratch-umask");
        let scratch = root.join("scratch");
        let previous = unsafe { libc::umask(0o777) };
        let made = super::make_scratch(&scratch);
        unsafe { libc::umask(previous) };
        made.unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&scratch).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o700);
        std::fs::write(scratch.join("file"), b"").unwrap();
    }

    /// The table's visibility of each mount and its generation follow
    /// every write.
    #[test]
    fn mount_visibility_follows_each_change() {
        let (_view, dir) = super::test_view();
        let (first, second) = (dir.join("visibility-first"), dir.join("visibility-second"));
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let before = super::vfs().mounts.read().unwrap().generation();
        for host in [&first, &second] {
            super::add_mount(
                "/visibility",
                host.clone(),
                super::Area::Writable,
                "tmpfs",
                "tmpfs",
            )
            .unwrap();
        }
        let mounts = super::vfs().mounts.read().unwrap();
        assert!(mounts.generation() >= before + 2);
        for (index, mount) in mounts.iter().enumerate() {
            assert_eq!(mounts.visible(index), !super::hidden(&mounts, mount));
        }
        drop(mounts);
        assert_eq!(super::lookup("/visibility/file").0, second.join("file"));
    }
    /// A walk through the image hands its checks the image's lstat it
    /// keeps with the image's symlink answers, the first time and after.
    #[test]
    fn checks_get_the_images_kept_lstat() {
        use std::os::unix::fs::MetadataExt;
        let (_view, dir) = super::test_view();
        let image = dir.join("root/walk-image");
        std::fs::create_dir_all(image.join("sub")).unwrap();
        for _ in 0..2 {
            let mut seen = Vec::new();
            super::resolve_checked(
                super::LINUX_AT_FDCWD,
                b"/walk-image/sub/file",
                false,
                |directory, known| {
                    if let Some(known) = known {
                        let host =
                            std::fs::metadata(dir.join("root").join(&directory[1..])).unwrap();
                        assert_eq!(known.st_ino, host.ino());
                    }
                    seen.push((directory.to_owned(), known.is_some()));
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                seen,
                [
                    ("/", true),
                    ("/walk-image", true),
                    ("/walk-image/sub", true)
                ]
                .map(|(directory, known)| (directory.to_string(), known))
            );
        }
    }

    /// A walk hands each directory's check the lstat it took of that
    /// directory as a component, and none after a symlink or `..`.
    #[test]
    fn checks_get_the_walks_lstat_of_each_component() {
        use std::os::unix::fs::MetadataExt;
        let (_view, root) = super::test_view();
        let base = root.join("data/walk-known");
        std::fs::create_dir_all(base.join("a/b")).unwrap();
        let _ = std::fs::remove_file(base.join("link"));
        std::os::unix::fs::symlink("a", base.join("link")).unwrap();
        let mut seen = Vec::new();
        super::resolve_checked(
            super::LINUX_AT_FDCWD,
            b"/data/walk-known/link/b/../b/file",
            false,
            |directory, known| {
                if let Some(known) = known
                    && directory != "/"
                {
                    let host = std::fs::metadata(root.join(&directory[1..])).unwrap();
                    assert_eq!(
                        (known.st_dev as u64, known.st_ino),
                        (host.dev(), host.ino())
                    );
                }
                seen.push((directory.to_owned(), known.is_some()));
                Ok(())
            },
        )
        .unwrap();
        let expected = [
            ("/", true),
            ("/data", true),
            ("/data/walk-known", true),
            ("/data/walk-known", false),
            ("/data/walk-known/a", true),
            ("/data/walk-known/a/b", true),
            ("/data/walk-known/a", false),
            ("/data/walk-known/a/b", true),
        ];
        assert_eq!(
            seen,
            expected
                .iter()
                .map(|(directory, known)| (directory.to_string(), *known))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn relative_dirfd_requires_a_published_directory_and_absolute_path_ignores_it() {
        const MARKER: &str = "aim-dirfd-publication-owned-child";
        if !std::env::args().any(|argument| argument == MARKER) {
            let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","vfs::tests::relative_dirfd_requires_a_published_directory_and_absolute_path_ignores_it","--nocapture","--skip",MARKER]).stdout(std::process::Stdio::piped()).spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("owned dirfd fixture exceeded deadline");
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            };
            use std::io::Read;
            let mut output = String::new();
            child
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut output)
                .unwrap();
            assert!(status.success(), "{output}");
            assert!(output.contains("DIRFD_PUBLICATION_EXECUTED"));
            return;
        }
        println!("DIRFD_PUBLICATION_EXECUTED");
        use std::os::fd::AsRawFd;
        let (_view, root) = super::test_view();
        let dir = std::fs::File::open(root.join("data")).unwrap();
        assert!(matches!(
            super::resolve(dir.as_raw_fd(), b"item", false),
            Err(crate::errno::EBADF)
        ));
        crate::sys::fdtab::publish_guest(dir.as_raw_fd()).unwrap();
        assert_eq!(
            super::resolve(dir.as_raw_fd(), b"item", false)
                .unwrap()
                .guest,
            "/data/item"
        );
        crate::sys::fdtab::withdraw_guest(dir.as_raw_fd()).unwrap();
        let path = root.join("data/plain");
        std::fs::write(&path, b"data").unwrap();
        let file = std::fs::File::open(path).unwrap();
        crate::sys::fdtab::publish_guest(file.as_raw_fd()).unwrap();
        assert!(matches!(
            super::resolve(file.as_raw_fd(), b"item", false),
            Err(crate::errno::ENOTDIR)
        ));
        assert_eq!(
            super::resolve(file.as_raw_fd(), b"/data/item", false)
                .unwrap()
                .guest,
            "/data/item"
        );
        crate::sys::fdtab::withdraw_guest(file.as_raw_fd()).unwrap();
    }
    use super::*;

    #[test]
    #[ignore = "real upstream mutation helper exercised by namespace_process_probe"]
    fn namespace_upstream_probe() {
        use std::io::BufRead;
        let mut input = std::io::BufReader::new(std::io::stdin());
        let mut lines = Vec::new();
        for _ in 0..4 {
            let mut line = String::new();
            input.read_line(&mut line).unwrap();
            lines.push(line.trim_end().to_owned());
        }
        init(Path::new(&lines[0]), Some(Path::new(&lines[1]))).unwrap();
        load_own_mounts(&format!("namespace-owner\t{}\n", lines[2])).unwrap();
        add_mount(
            "/data/live-upstream-owner",
            PathBuf::from(&lines[3]),
            Area::Writable,
            "actual-upstream-child",
            "tmpfs",
        )
        .unwrap();
    }

    #[test]
    #[ignore = "subprocess helper exercised by separate_process_mount_owner_preserves_shared_and_private_state"]
    fn namespace_process_probe() {
        use std::io::BufRead;
        let mut input = std::io::BufReader::new(std::io::stdin());
        let mut lines = Vec::new();
        for _ in 0..4 {
            let mut line = String::new();
            input.read_line(&mut line).unwrap();
            lines.push(line.trim_end().to_owned());
        }
        init(Path::new(&lines[0]), Some(Path::new(&lines[1]))).unwrap();
        load_own_mounts(&format!("namespace-owner\t{}\n", lines[2])).unwrap();
        let host = PathBuf::from(&lines[3]);
        add_mount(
            "/data/live-shared-owner",
            host.clone(),
            Area::Writable,
            "actual-child",
            "tmpfs",
        )
        .unwrap();
        let inherited = own_mounts_text();
        private_mount_namespace().unwrap();
        set_mount_propagation("/", (1 << 19) | 0x4000).unwrap();
        use std::io::Write;
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                }
                let _ = self.0.wait();
            }
        }
        let mut upstream = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "vfs::tests::namespace_upstream_probe",
                    "--ignored",
                    "--nocapture",
                ])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        writeln!(
            upstream.0.stdin.take().unwrap(),
            "{}\n{}\n{}\n{}",
            lines[0],
            lines[1],
            lines[2],
            lines[3]
        )
        .unwrap();
        assert!(upstream.0.wait().unwrap().success());
        refresh_fuse_mounts().unwrap();
        assert_eq!(
            lookup("/data/live-upstream-owner/file").0,
            host.join("file")
        );
        add_mount(
            "/data/live-slave-only",
            host.clone(),
            Area::Writable,
            "actual-slave-child",
            "tmpfs",
        )
        .unwrap();
        set_mount_propagation("/", (1 << 18) | 0x4000).unwrap();
        add_mount(
            "/data/live-private-owner",
            host.clone(),
            Area::Writable,
            "actual-private-child",
            "tmpfs",
        )
        .unwrap();
        refresh_fuse_mounts().unwrap();
        assert_eq!(lookup("/data/live-private-owner/file").0, host.join("file"));
        // Exec restores the shared owner, rather than a stale mount snapshot.
        load_own_mounts(&inherited).unwrap();
        refresh_fuse_mounts().unwrap();
        assert_ne!(lookup("/data/live-private-owner/file").0, host.join("file"));
        assert_eq!(lookup("/data/live-shared-owner/file").0, host.join("file"));
    }

    #[test]
    fn separate_process_mount_owner_preserves_shared_and_private_state() {
        use std::io::Write;
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                }
                let _ = self.0.wait();
            }
        }
        let (_guard, root) = test_view();
        let runtime = runtime_dir().unwrap();
        let old_rules = PROPAGATION_RULES.lock().unwrap().clone();
        let old_private = PRIVATE_MOUNTS.load(Ordering::Acquire);
        let old_view = NAMESPACE_VIEW.lock().unwrap().take();
        let table = fuse_table().unwrap();
        let old_table = std::fs::read(&table).ok();
        let id = format!("live-process-{}", std::process::id());
        let owner = aim_storage::mount_namespace::Namespace::open(runtime, &id).unwrap();
        owner
            .initialize(&format!(
                "root\t/\t{}\npropagation\t/\tshared\n{}",
                crate::vfs::root().display(),
                std::fs::read_to_string(runtime.join("path-map")).unwrap()
            ))
            .unwrap();
        owner.append("propagation-flags\t/\t1064960").unwrap();
        *NAMESPACE_VIEW.lock().unwrap() = Some(NamespaceView {
            page: owner.generation().unwrap(),
            owner: owner.clone(),
            generation: 0,
            records: Default::default(),
        });
        refresh_namespace().unwrap();
        let host = root.join("live-process-host");
        std::fs::create_dir_all(&host).unwrap();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "vfs::tests::namespace_process_probe",
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
            crate::vfs::root().display(),
            runtime.join("path-map").display(),
            id,
            host.display()
        )
        .unwrap();
        assert!(child.0.wait().unwrap().success());
        refresh_fuse_mounts().unwrap();
        assert_eq!(lookup("/data/live-shared-owner/file").0, host.join("file"));
        assert_ne!(lookup("/data/live-private-owner/file").0, host.join("file"));
        assert_ne!(lookup("/data/live-slave-only/file").0, host.join("file"));
        assert_eq!(
            lookup("/data/live-upstream-owner/file").0,
            host.join("file")
        );
        let inventory = namespace_mount_points(&id).unwrap();
        assert!(
            inventory
                .iter()
                .any(|mount| mount.guest == "/data/live-shared-owner")
        );
        assert!(
            !inventory
                .iter()
                .any(|mount| mount.guest == "/data/live-private-owner")
        );
        *NAMESPACE_VIEW.lock().unwrap() = old_view;
        *PROPAGATION_RULES.lock().unwrap() = old_rules;
        PRIVATE_MOUNTS.store(old_private, Ordering::Release);
        let (_, base) =
            parse_map(&std::fs::read_to_string(runtime.join("path-map")).unwrap()).unwrap();
        *vfs().mounts.write().unwrap() = base;
        if let Some(bytes) = old_table {
            std::fs::write(table, bytes).unwrap();
        } else {
            let _ = std::fs::remove_file(table);
        }
        std::fs::remove_dir_all(host).unwrap();
    }

    #[test]
    fn shared_namespace_generation_refreshes_mounts_and_unshare_keeps_private_owner() {
        let (_guard, root) = test_view();
        let runtime = runtime_dir().unwrap();
        let id = format!("test-namespace-{}", std::process::id());
        let owner = aim_storage::mount_namespace::Namespace::open(runtime, &id).unwrap();
        owner
            .initialize(&format!(
                "root\t/\t{}\npropagation\t/\tshared\n{}",
                crate::vfs::root().display(),
                std::fs::read_to_string(runtime.join("path-map")).unwrap()
            ))
            .unwrap();
        let old_rules = PROPAGATION_RULES.lock().unwrap().clone();
        let old_private = PRIVATE_MOUNTS.load(Ordering::Acquire);
        let previous = NAMESPACE_VIEW.lock().unwrap().take();
        *NAMESPACE_VIEW.lock().unwrap() = Some(NamespaceView {
            page: owner.generation().unwrap(),
            owner: owner.clone(),
            generation: 0,
            records: Default::default(),
        });
        refresh_namespace().unwrap();
        set_mount_propagation("/", (1 << 18) | 0x4000).unwrap();
        let host = root.join("shared-real-mount");
        std::fs::create_dir_all(&host).unwrap();
        add_mount(
            "/data/shared-owner-test",
            host.clone(),
            Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        assert_eq!(lookup("/data/shared-owner-test/file").0, host.join("file"));
        let external = aim_storage::mount_namespace::Namespace::open(runtime, &id).unwrap();
        external.append("remove\t/data/shared-owner-test").unwrap();
        refresh_fuse_mounts().unwrap();
        assert_ne!(lookup("/data/shared-owner-test/file").0, host.join("file"));
        let inherited = own_mounts_text();
        private_mount_namespace().unwrap();
        let private = mount_namespace_id().unwrap();
        assert_ne!(private, id);
        add_mount(
            "/data/private-owner-test",
            host.clone(),
            Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        load_own_mounts(&inherited).unwrap();
        assert_eq!(mount_namespace_id().as_deref(), Some(id.as_str()));
        assert_ne!(lookup("/data/private-owner-test/file").0, host.join("file"));
        let clone = aim_storage::mount_namespace::Namespace::open(runtime, &private).unwrap();
        assert!(
            clone
                .read()
                .unwrap()
                .events
                .iter()
                .any(|event| event.contains("private-owner-test"))
        );
        *NAMESPACE_VIEW.lock().unwrap() = previous;
        *PROPAGATION_RULES.lock().unwrap() = old_rules;
        PRIVATE_MOUNTS.store(old_private, Ordering::Release);
        let (_, base) =
            parse_map(&std::fs::read_to_string(runtime.join("path-map")).unwrap()).unwrap();
        *vfs().mounts.write().unwrap() = base;
        std::fs::remove_dir_all(host).unwrap();
    }

    #[test]
    fn interrupted_mount_journal_lock_waits_for_its_owner() {
        const CHILD: &str = "__isolated_mount_lock_fork";
        if !std::env::args().any(|argument| argument == CHILD) {
            use std::os::unix::process::CommandExt;
            struct ChildGroup(std::process::Child);
            impl Drop for ChildGroup {
                fn drop(&mut self) {
                    if self.0.try_wait().ok().flatten().is_none() {
                        unsafe {
                            libc::killpg(self.0.id() as i32, libc::SIGKILL);
                        }
                        let _ = self.0.wait();
                    }
                }
            }
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "vfs::tests::interrupted_mount_journal_lock_waits_for_its_owner",
                    "--skip",
                    CHILD,
                    "--nocapture",
                ])
                .process_group(0)
                .spawn()
                .unwrap();
            let mut child = ChildGroup(child);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success(), "isolated raw-fork fixture: {status}");
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    unsafe {
                        libc::killpg(child.0.id() as i32, libc::SIGKILL);
                    }
                    child.0.wait().unwrap();
                    panic!("isolated raw-fork fixture exceeded ten seconds");
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            return;
        }
        use std::os::fd::AsRawFd;
        let (_view, dir) = test_view();
        let path = dir.join("interrupted-mount-lock");
        let owner = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let waiter = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_EX) }, 0);
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        static SIGNALS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        extern "C" fn caught(_: i32) {
            SIGNALS.fetch_add(1, Ordering::Relaxed);
        }
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // Only async-signal-safe libc calls after fork. The handler has no
            // SA_RESTART: the first contended flock must return EINTR.
            unsafe {
                libc::close(owner.as_raw_fd());
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = caught as *const () as usize;
                libc::sigemptyset(&mut action.sa_mask);
                if libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()) != 0 {
                    libc::_exit(2);
                }
                libc::write(pipe[1], b"r".as_ptr().cast(), 1);
                let first = libc::flock(waiter.as_raw_fd(), libc::LOCK_EX);
                if first != -1 || errno::last() != errno::EINTR {
                    libc::_exit(3);
                }
                libc::write(pipe[1], b"i".as_ptr().cast(), 1);
                let result = lock_mount_table(waiter.as_raw_fd());
                libc::_exit(if result.is_ok() && SIGNALS.load(Ordering::Relaxed) == 2 {
                    0
                } else {
                    4
                });
            }
        }
        let mut ready = 0u8;
        assert_eq!(
            unsafe { libc::read(pipe[0], (&mut ready as *mut u8).cast(), 1) },
            1
        );
        // Wait until the child is blocked, then deliver an ordinary signal.
        unsafe {
            libc::usleep(20_000);
        }
        assert_eq!(unsafe { libc::kill(child, libc::SIGUSR1) }, 0);
        assert_eq!(
            unsafe { libc::read(pipe[0], (&mut ready as *mut u8).cast(), 1) },
            1
        );
        assert_eq!(ready, b'i');
        unsafe {
            libc::usleep(20_000);
        }
        assert_eq!(unsafe { libc::kill(child, libc::SIGUSR1) }, 0);
        unsafe {
            libc::usleep(20_000);
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) },
            0
        );
        assert_eq!(unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_UN) }, 0);
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        std::fs::remove_file(path).unwrap();
        assert_eq!(lock_mount_table(-1), Err(errno::EBADF));
    }

    #[test]
    fn default_apex_module_mount_keeps_actual_proc_fd_canonical_path() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::tests::default_apex_module_mount_keeps_actual_proc_fd_canonical_path",
        ) {
            return;
        }
        let (_view, _dir) = test_view();
        let module = vfs().root.join("apex/actual.module");
        std::fs::create_dir_all(module.join("lib64")).unwrap();
        std::fs::write(module.join("lib64/library.so"), b"actual readonly module").unwrap();
        add_mount(
            "/bootstrap-apex/actual.module",
            module.clone(),
            Area::Image,
            "apex",
            "erofs",
        )
        .unwrap();
        add_mount(
            "/apex/actual.module",
            module.clone(),
            Area::Image,
            "apex",
            "erofs",
        )
        .unwrap();
        let path = CString::new("/apex/actual.module/lib64/library.so").unwrap();
        let mut context: crate::context::GuestContext = unsafe { std::mem::zeroed() };
        context.x[8] = 56;
        context.x[..4].copy_from_slice(&[LINUX_AT_FDCWD as u64, path.as_ptr() as u64, 0, 0]);
        crate::sys::dispatch(&mut context);
        let fd = context.x[0] as i64;
        assert!(fd >= 0, "module open: {fd}");
        let link = CString::new(format!("/proc/self/fd/{fd}")).unwrap();
        let mut answer = [0u8; 4096];
        context.x[8] = 78;
        context.x[..4].copy_from_slice(&[
            LINUX_AT_FDCWD as u64,
            link.as_ptr() as u64,
            answer.as_mut_ptr() as u64,
            answer.len() as u64,
        ]);
        crate::sys::dispatch(&mut context);
        let count = context.x[0] as i64;
        assert!(count > 0, "module readlink: {count}");
        assert_eq!(
            &answer[..count as usize],
            b"/apex/actual.module/lib64/library.so"
        );
        context.x[8] = 57;
        context.x[0] = fd as u64;
        crate::sys::dispatch(&mut context);
        assert_eq!(context.x[0], 0);
        context.x[8] = 56;
        context.x[..4].copy_from_slice(&[LINUX_AT_FDCWD as u64, path.as_ptr() as u64, 1, 0]);
        crate::sys::dispatch(&mut context);
        assert_eq!(context.x[0] as i64, -(errno::EROFS as i64));
        assert_eq!(
            std::fs::read(module.join("lib64/library.so")).unwrap(),
            b"actual readonly module"
        );
    }

    #[test]
    fn inverse_root_bind_keeps_library_path_and_more_specific_mount() {
        use std::os::fd::{AsRawFd, IntoRawFd};
        let (_view, dir) = test_view();
        let root = vfs().root.clone();
        let library = root.join("system/lib64/inverse-root-library.so");
        std::fs::create_dir_all(library.parent().unwrap()).unwrap();
        std::fs::write(&library, b"actual library path owner").unwrap();
        let file = std::fs::File::open(&library).unwrap();
        let mut path = [0u8; libc::PATH_MAX as usize];
        assert_eq!(
            unsafe { crate::sys::fgetpath(file.as_raw_fd(), path.as_mut_ptr()) },
            0
        );
        let host = PathBuf::from(std::ffi::OsStr::from_bytes(
            &path[..path.iter().position(|byte| *byte == 0).unwrap()],
        ));
        assert_eq!(
            guest_path_of_host(&host).as_deref(),
            Some("/system/lib64/inverse-root-library.so")
        );
        let alias = "/inverse-reboot-root/mount_tmp";
        bind_mount_recursive("/", alias, root.clone(), Area::Image, false).unwrap();
        assert_eq!(
            lookup(&format!("{alias}/system/lib64/inverse-root-library.so")).0,
            library
        );
        assert_eq!(
            guest_path_of_host(&host).as_deref(),
            Some("/system/lib64/inverse-root-library.so")
        );
        assert_eq!(guest_path_of_host(&root).as_deref(), Some("/"));
        let fd = file.into_raw_fd();
        crate::sys::fdtab::publish_guest(fd).unwrap();
        let link = CString::new(format!("/proc/self/fd/{fd}")).unwrap();
        let mut answer = [0u8; libc::PATH_MAX as usize];
        let mut context: crate::context::GuestContext = unsafe { std::mem::zeroed() };
        context.x[8] = 78;
        context.x[..4].copy_from_slice(&[
            LINUX_AT_FDCWD as u64,
            link.as_ptr() as u64,
            answer.as_mut_ptr() as u64,
            answer.len() as u64,
        ]);
        crate::sys::dispatch(&mut context);
        let count = context.x[0] as i64;
        assert!(count > 0, "actual proc-fd readlink: {count}");
        assert_eq!(
            &answer[..count as usize],
            b"/system/lib64/inverse-root-library.so"
        );
        context.x[8] = 57;
        context.x[0] = fd as u64;
        crate::sys::dispatch(&mut context);
        assert_eq!(context.x[0] as i64, 0);
        let nested = dir.join("inverse-specific-library");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("library.so"), b"actual nested mount").unwrap();
        add_mount(
            "/system/lib64/inverse-specific",
            nested.clone(),
            Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        assert_eq!(
            guest_path_of_host(&nested.canonicalize().unwrap().join("library.so")).as_deref(),
            Some("/system/lib64/inverse-specific/library.so")
        );
        assert!(remove_mount("/system/lib64/inverse-specific").unwrap());
        assert!(remove_mount(alias).unwrap());
        std::fs::remove_file(library).unwrap();
        std::fs::remove_dir_all(nested).unwrap();
    }

    #[test]
    fn canonical_host_aliases_preserve_deepest_shortest_and_hidden_mounts() {
        let (_view, dir) = test_view();
        let data = dir.join("data");
        let nested = data.join("inverse-alias");
        std::fs::create_dir_all(&nested).unwrap();
        let alias = dir.join("inverse-host-alias");
        std::os::unix::fs::symlink(&data, &alias).unwrap();
        let canonical = nested.canonicalize().unwrap();
        add_mount(
            "/inverse-parent",
            data.canonicalize().unwrap(),
            Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        add_mount(
            "/inverse-short",
            alias.join("inverse-alias"),
            Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        add_mount(
            "/inverse-long-name",
            alias.join("inverse-alias"),
            Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        assert_eq!(
            guest_path_of_host(&canonical.join("file")).as_deref(),
            Some("/inverse-short/file")
        );
        let read = HostPathView::capture().unwrap();
        assert_eq!(
            read.guest_path(&canonical.join("file")).as_deref(),
            Some("/inverse-short/file")
        );
        let hidden_host = dir.join("inverse-hidden");
        std::fs::create_dir_all(&hidden_host).unwrap();
        add_mount(
            "/inverse-short",
            hidden_host,
            Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        assert_eq!(
            guest_path_of_host(&canonical.join("file")).as_deref(),
            Some("/inverse-long-name/file")
        );
        assert_eq!(
            read.guest_path(&canonical.join("file")).as_deref(),
            Some("/inverse-short/file")
        );
        let next_read = HostPathView::capture().unwrap();
        assert_eq!(
            next_read.guest_path(&canonical.join("file")).as_deref(),
            Some("/inverse-long-name/file")
        );
        assert!(remove_mount("/inverse-short").unwrap());
        assert!(remove_mount("/inverse-short").unwrap());
        assert!(remove_mount("/inverse-long-name").unwrap());
        assert!(remove_mount("/inverse-parent").unwrap());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir_all(nested).unwrap();
    }
    #[test]
    fn inverse_procfs_read_resolves_aliases_once_and_new_reads_see_retargeting() {
        let (_view, dir) = test_view();
        let before = dir.join("inverse-before");
        let after = dir.join("inverse-after");
        let alias = dir.join("inverse-changing-alias");
        std::fs::create_dir_all(&before).unwrap();
        std::fs::create_dir_all(&after).unwrap();
        std::os::unix::fs::symlink(&before, &alias).unwrap();
        add_mount(
            "/inverse-changing",
            alias.clone(),
            Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        let read = HostPathView::capture().unwrap();
        let before_file = before.canonicalize().unwrap().join("file");
        assert_eq!(
            read.guest_path(&before_file).as_deref(),
            Some("/inverse-changing/file")
        );
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&after, &alias).unwrap();
        assert_eq!(
            read.guest_path(&before_file).as_deref(),
            Some("/inverse-changing/file")
        );
        assert_eq!(
            guest_path_of_host(&after.canonicalize().unwrap().join("file")).as_deref(),
            Some("/inverse-changing/file")
        );
        assert!(guest_path_of_host(&before_file).is_none());
        assert!(remove_mount("/inverse-changing").unwrap());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir(before).unwrap();
        std::fs::remove_dir(after).unwrap();
    }

    #[test]
    fn inverse_view_resolves_again_only_mounts_not_canonical() {
        let (_view, dir) = test_view();
        let canonical = dir.join("inverse-canonical");
        std::fs::create_dir_all(&canonical).unwrap();
        let canonical = canonical.canonicalize().unwrap();
        let alias = dir.join("inverse-canonical-alias");
        std::os::unix::fs::symlink(&canonical, &alias).unwrap();
        for (guest, host) in [
            ("/inverse-canonical", &canonical),
            ("/inverse-through-alias", &alias),
        ] {
            add_mount(guest, host.clone(), Area::Writable, "tmpfs", "tmpfs").unwrap();
        }
        let read = HostPathView::capture().unwrap();
        let aliases: Vec<&str> = read
            .visible
            .aliases
            .iter()
            .map(|(g, _)| g.as_str())
            .collect();
        assert!(aliases.contains(&"/inverse-through-alias"));
        assert!(!aliases.contains(&"/inverse-canonical"));
        assert!(remove_mount("/inverse-canonical").unwrap());
        assert!(remove_mount("/inverse-through-alias").unwrap());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir(canonical).unwrap();
    }

    #[test]
    fn map_parses_and_orders_longest_first() {
        let (root, m) = parse_map(
            "# aim-guest-init path map v1\nroot\t/\t/img\nrw\t/dev\t/r/dev\nrw\t/apex/apex-info-list.xml\t/r/a.xml\nkernfs\t/proc\t/r/kernfs/proc\n",
        )
        .unwrap();
        assert_eq!(root, Some(PathBuf::from("/img")));
        assert_eq!(m[0].guest, "/apex/apex-info-list.xml");
        assert_eq!(m.last().unwrap().guest, "/dev");
        assert!(parse_map("bogus\t/\t/x\n").is_err());
        assert!(parse_map("rw\t/x\n").is_err());
        let (_, m) = parse_map("cgroup2\t/sys/fs/cgroup\t/r/cgroup\n").unwrap();
        assert_eq!(
            (m[0].area, m[0].fstype.as_deref()),
            (Area::Writable, Some("cgroup2"))
        );
    }

    #[test]
    fn own_mounts_shadow_the_map_until_unmounted() {
        let (_view, dir) = test_view();
        let (data, tmp) = (dir.join("data"), dir.join("tmp"));
        std::fs::create_dir_all(&tmp).unwrap();

        add_mount("/data/app", tmp.clone(), Area::Writable, "tmpfs", "tmpfs").unwrap();
        assert_eq!(lookup("/data/app/x").0, tmp.join("x"));
        assert_eq!(lookup("/data/other").0, data.join("other"));
        assert!(
            mount_points()
                .unwrap()
                .iter()
                .any(|m| m.guest == "/data/app" && m.fstype.as_deref() == Some("tmpfs"))
        );
        // Test explicit mount reconstruction, not a shared namespace handle
        // (which must observe its live removals rather than rewind them).
        let text = own_mounts_text()
            .lines()
            .filter(|line| {
                !line.starts_with("namespace-owner\t") && !line.starts_with("namespace-runtime\t")
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(move_mount("/data/app", "/data/moved").unwrap());
        assert_eq!(lookup("/data/moved").0, tmp);
        assert!(remove_mount("/data/moved").unwrap());
        assert!(!remove_mount("/data/moved").unwrap());
        assert!(
            !remove_mount("/data").unwrap(),
            "path map entries are not unmounted"
        );

        load_own_mounts(&text).unwrap();
        assert_eq!(lookup("/data/app").0, tmp);
        assert!(remove_mount("/data/app").unwrap());
    }

    #[test]
    fn a_mount_hides_the_older_ones_below_it() {
        let (_view, dir) = test_view();
        let (data, tmp) = (dir.join("data"), dir.join("hide"));
        std::fs::create_dir_all(&tmp).unwrap();
        // The path map's /data/user/0 is /data/data, and so is its mirror.
        assert_eq!(lookup("/data/user/0/p").0, data.join("data/p"));
        assert_eq!(attr_key("/data/user/0/p"), "/data/data/p");
        assert_eq!(attr_key("/data_mirror/data_ce/null/0/p"), "/data/data/p");
        assert_eq!(attr_key("/data_mirror/data_ce/null"), "/data/user");
        assert_eq!(
            guest_path_of_host(&data.join("data/p")).as_deref(),
            Some("/data/user/0/p")
        );

        add_mount("/data/user", tmp.clone(), Area::Writable, "tmpfs", "tmpfs").unwrap();
        assert_eq!(lookup("/data/user/0").0, tmp.join("0"));
        assert_eq!(fstype("/data/user/0").as_deref(), Some("tmpfs"));
        assert_eq!(attr_key("/data/user/0"), format!("{}/0", tmp.display()));
        // A mount made later below the tmpfs is seen again.
        add_mount(
            "/data/user/0",
            data.join("data"),
            Area::Writable,
            "/data/data",
            "bind",
        )
        .unwrap();
        assert_eq!(lookup("/data/user/0/p").0, data.join("data/p"));
        assert!(remove_mount("/data/user/0").unwrap());
        assert!(remove_mount("/data/user").unwrap());
        assert_eq!(lookup("/data/user/0/p").0, data.join("data/p"));
    }

    /// Bootstrap ext4 at `/apex/com.android.runtime`, then the official
    /// tree at `/apex/com.android.runtime@1`. `/system/bin/linker64` is the
    /// image symlink bionic names as `PT_INTERP`. While the bootstrap
    /// directory is there, the walk reads it. Once that directory is gone,
    /// the walk follows the tmpfs symlink onto the activated tree. It does
    /// not keep the removed host path, and it does not invent a directory
    /// when the activated tree is gone too.
    #[test]
    fn a_gone_ext4_host_yields_the_activated_runtime() {
        use std::os::unix::ffi::OsStrExt;
        let (_view, dir) = test_view();
        struct Unmount(&'static str);
        impl Drop for Unmount {
            fn drop(&mut self) {
                let _ = remove_mount(self.0);
            }
        }
        let _apex = Unmount("/apex");
        let _old = Unmount("/apex/com.android.runtime");
        let _new = Unmount("/apex/com.android.runtime@1");
        let image = vfs().root.join("system/bin/linker64");
        std::fs::create_dir_all(image.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(&image);
        std::os::unix::fs::symlink("/apex/com.android.runtime/bin/linker64", &image).unwrap();
        let old_host = dir.join("runtime-old-linker");
        let new_host = dir.join("runtime-new-linker");
        let tmp = dir.join("runtime-apex-tmp");
        let _ = std::fs::remove_dir_all(&old_host);
        let _ = std::fs::remove_dir_all(&new_host);
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(old_host.join("bin")).unwrap();
        std::fs::write(old_host.join("bin/linker64"), b"bootstrap-linker").unwrap();
        std::fs::create_dir_all(new_host.join("bin")).unwrap();
        std::fs::write(new_host.join("bin/linker64"), b"activated-linker").unwrap();
        std::fs::create_dir_all(&tmp).unwrap();
        std::os::unix::fs::symlink("com.android.runtime@1", tmp.join("com.android.runtime"))
            .unwrap();
        add_mount("/apex", tmp, Area::Writable, "tmpfs", "tmpfs").unwrap();
        add_mount(
            "/apex/com.android.runtime",
            old_host.clone(),
            Area::Image,
            "/dev/block/loop-bootstrap",
            "ext4",
        )
        .unwrap();
        add_mount(
            "/apex/com.android.runtime@1",
            new_host.clone(),
            Area::Image,
            "/system/apex/com.android.runtime.apex",
            "ext4",
        )
        .unwrap();
        let live = resolve(LINUX_AT_FDCWD, b"/system/bin/linker64", true).unwrap();
        let live_host = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(live.host.as_bytes()));
        assert_eq!(std::fs::read(&live_host).unwrap(), b"bootstrap-linker");
        std::fs::remove_dir_all(&old_host).unwrap();
        let after = resolve(LINUX_AT_FDCWD, b"/system/bin/linker64", true).unwrap();
        let after_host =
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(after.host.as_bytes()));
        assert!(
            after_host.starts_with(&new_host),
            "resolve kept {}",
            after_host.display()
        );
        assert_eq!(std::fs::read(&after_host).unwrap(), b"activated-linker");
        std::fs::remove_dir_all(&new_host).unwrap();
        let missed = resolve(LINUX_AT_FDCWD, b"/system/bin/linker64", true).unwrap();
        let missed_host =
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(missed.host.as_bytes()));
        assert!(
            std::fs::read(&missed_host).is_err(),
            "missing interpreter opened {}",
            missed_host.display()
        );
        assert!(!old_host.exists());
        assert!(!new_host.exists());
        let _ = std::fs::remove_file(&image);
    }

    /// The bootstrap directory still exists, but it is not the directory
    /// that was mounted: it was removed and created again, and `linker64`
    /// is gone. A bind of that host is the mount a walk would select. Both
    /// yield the activated tree. The replaced directory is not recreated
    /// when the activated tree is gone too.
    #[test]
    fn a_replaced_ext4_host_yields_the_activated_runtime() {
        use std::os::unix::ffi::OsStrExt;
        let (_view, dir) = test_view();
        struct Unmount(&'static str);
        impl Drop for Unmount {
            fn drop(&mut self) {
                let _ = remove_mount(self.0);
            }
        }
        let _apex = Unmount("/apex");
        let _old = Unmount("/apex/com.android.runtime");
        let _bind = Unmount("/apex/com.android.runtime");
        let _new = Unmount("/apex/com.android.runtime@1");
        let image = vfs().root.join("system/bin/linker64");
        std::fs::create_dir_all(image.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(&image);
        std::os::unix::fs::symlink("/apex/com.android.runtime/bin/linker64", &image).unwrap();
        let old_host = dir.join("runtime-replaced-linker");
        let new_host = dir.join("runtime-replaced-activated");
        let tmp = dir.join("runtime-replaced-tmp");
        let _ = std::fs::remove_dir_all(&old_host);
        let _ = std::fs::remove_dir_all(&new_host);
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_file(ext4_stamp_path(&old_host));
        std::fs::create_dir_all(old_host.join("bin")).unwrap();
        std::fs::write(old_host.join("bin/linker64"), b"bootstrap-linker").unwrap();
        std::fs::create_dir_all(new_host.join("bin")).unwrap();
        std::fs::write(new_host.join("bin/linker64"), b"activated-linker").unwrap();
        std::fs::create_dir_all(&tmp).unwrap();
        std::os::unix::fs::symlink("com.android.runtime@1", tmp.join("com.android.runtime"))
            .unwrap();
        note_ext4_host(&old_host).unwrap();
        add_mount("/apex", tmp, Area::Writable, "tmpfs", "tmpfs").unwrap();
        add_mount(
            "/apex/com.android.runtime",
            old_host.clone(),
            Area::Image,
            "/dev/block/loop-bootstrap",
            "ext4",
        )
        .unwrap();
        add_mount(
            "/apex/com.android.runtime@1",
            new_host.clone(),
            Area::Image,
            "/system/apex/com.android.runtime.apex",
            "ext4",
        )
        .unwrap();
        let live = resolve(LINUX_AT_FDCWD, b"/system/bin/linker64", true).unwrap();
        let live_host = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(live.host.as_bytes()));
        assert_eq!(std::fs::read(&live_host).unwrap(), b"bootstrap-linker");
        std::fs::remove_dir_all(&old_host).unwrap();
        std::fs::create_dir_all(&old_host).unwrap();
        add_mount(
            "/apex/com.android.runtime",
            old_host.clone(),
            Area::Image,
            "/dev/block/loop-bootstrap",
            "bind",
        )
        .unwrap();
        let after = resolve(LINUX_AT_FDCWD, b"/system/bin/linker64", true).unwrap();
        let after_host =
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(after.host.as_bytes()));
        assert!(
            after_host.starts_with(&new_host),
            "resolve kept {}",
            after_host.display()
        );
        assert_eq!(std::fs::read(&after_host).unwrap(), b"activated-linker");
        std::fs::remove_dir_all(&new_host).unwrap();
        let missed = resolve(LINUX_AT_FDCWD, b"/system/bin/linker64", true).unwrap();
        let missed_host =
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(missed.host.as_bytes()));
        assert!(
            std::fs::read(&missed_host).is_err(),
            "missing interpreter opened {}",
            missed_host.display()
        );
        assert!(old_host.exists());
        assert!(!new_host.exists());
        let _ = std::fs::remove_dir_all(&old_host);
        let _ = std::fs::remove_file(ext4_stamp_path(&old_host));
        let _ = std::fs::remove_file(&image);
    }

    /// A fork snapshot still names the bootstrap ext4 host, and its journal
    /// generation is already current, which is how `park_saved` leaves a
    /// namespace. The journal itself has the activated host. The next walk
    /// follows the journal, not the snapshot.
    #[test]
    fn a_pinned_ext4_snapshot_follows_the_journal() {
        use std::os::unix::ffi::OsStrExt;
        use std::sync::atomic::Ordering;
        let (_view, dir) = test_view();
        let runtime = runtime_dir().unwrap().to_path_buf();
        let id = format!("ext4-pin-{}", std::process::id());
        let owner = aim_storage::mount_namespace::Namespace::open(&runtime, &id).unwrap();
        owner
            .initialize(&format!(
                "root\t/\t{}\npropagation\t/\tshared\n{}",
                vfs().root.display(),
                std::fs::read_to_string(runtime.join("path-map")).unwrap()
            ))
            .unwrap();
        struct Restore {
            rules: Vec<(String, Propagation)>,
            private: bool,
            view: Option<NamespaceView>,
            mounts: Vec<Mount>,
        }
        impl Drop for Restore {
            fn drop(&mut self) {
                *NAMESPACE_VIEW.lock().unwrap() = self.view.take();
                *PROPAGATION_RULES.lock().unwrap() = std::mem::take(&mut self.rules);
                PRIVATE_MOUNTS.store(self.private, Ordering::Release);
                *vfs().mounts.write().unwrap() = std::mem::take(&mut self.mounts);
            }
        }
        let restore = Restore {
            rules: PROPAGATION_RULES.lock().unwrap().clone(),
            private: PRIVATE_MOUNTS.load(Ordering::Acquire),
            view: NAMESPACE_VIEW.lock().unwrap().take(),
            mounts: vfs().mounts.read().unwrap().clone(),
        };
        *NAMESPACE_VIEW.lock().unwrap() = Some(NamespaceView {
            page: owner.generation().unwrap(),
            owner: owner.clone(),
            generation: 0,
            records: Default::default(),
        });
        refresh_namespace().unwrap();
        let old_host = dir.join("pin-old-linker");
        let new_host = dir.join("pin-new-linker");
        let _ = std::fs::remove_dir_all(&old_host);
        let _ = std::fs::remove_dir_all(&new_host);
        std::fs::create_dir_all(old_host.join("bin")).unwrap();
        std::fs::create_dir_all(new_host.join("bin")).unwrap();
        std::fs::write(old_host.join("bin/linker64"), b"bootstrap-linker").unwrap();
        std::fs::write(new_host.join("bin/linker64"), b"activated-linker").unwrap();
        note_ext4_host(&old_host).unwrap();
        note_ext4_host(&new_host).unwrap();
        add_mount(
            "/apex/com.android.runtime",
            old_host.clone(),
            Area::Image,
            "/dev/block/loop-pin-old",
            "ext4",
        )
        .unwrap();
        let snapshot = vfs().mounts.read().unwrap().clone();
        owner
            .append("remove\t/apex/com.android.runtime")
            .unwrap();
        owner
            .append(&format!(
                "ro\t/apex/com.android.runtime\t{}\t/dev/block/loop-pin-new\text4\n",
                new_host.display()
            ))
            .unwrap();
        *vfs().mounts.write().unwrap() = snapshot;
        {
            let state = owner.read().unwrap();
            let mut slot = NAMESPACE_VIEW.lock().unwrap();
            let view = slot.as_mut().unwrap();
            view.generation = view.page.current();
            view.records = std::sync::Arc::new(state.mounts);
        }
        let found = resolve(
            LINUX_AT_FDCWD,
            b"/apex/com.android.runtime/bin/linker64",
            true,
        )
        .unwrap_or_else(|error| panic!("resolve errno={error}"));
        let host = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(found.host.as_bytes()));
        assert!(
            host.starts_with(&new_host),
            "pinned snapshot kept {}",
            host.display()
        );
        assert_eq!(std::fs::read(&host).unwrap(), b"activated-linker");
        let again = resolve(
            LINUX_AT_FDCWD,
            b"/apex/com.android.runtime/bin/linker64",
            true,
        )
        .unwrap();
        let again = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(again.host.as_bytes()));
        assert_eq!(again, host);
        drop(restore);
        let _ = std::fs::remove_dir_all(&old_host);
        let _ = std::fs::remove_dir_all(&new_host);
        let _ = std::fs::remove_file(ext4_stamp_path(&old_host));
        let _ = std::fs::remove_file(ext4_stamp_path(&new_host));
    }
}

#[cfg(test)]
mod fuse_route_tests {
    use super::*;
    fn mount_test_syscall(number: u64, args: [u64; 6]) -> i64 {
        let mut context: crate::context::GuestContext = unsafe { std::mem::zeroed() };
        context.x[8] = number;
        context.x[..6].copy_from_slice(&args);
        crate::sys::dispatch(&mut context);
        context.x[0] as i64
    }
    fn assert_namespace_mounts(
        owner: &aim_storage::mount_namespace::Namespace,
        expected: &[(&str, bool)],
    ) {
        load_own_mounts(&format!("namespace-owner\t{}\n", owner.id())).unwrap();
        refresh_fuse_mounts().unwrap();
        let path = CString::new("/proc/self/mountinfo").unwrap();
        let fd = mount_test_syscall(
            56,
            [LINUX_AT_FDCWD as u64, path.as_ptr() as u64, 0, 0, 0, 0],
        );
        assert!(fd >= 0, "mountinfo open: {fd}");
        let mut bytes = vec![0; 65536];
        let n = mount_test_syscall(
            63,
            [
                fd as u64,
                bytes.as_mut_ptr() as u64,
                bytes.len() as u64,
                0,
                0,
                0,
            ],
        );
        assert!(n > 0, "mountinfo read: {n}");
        assert_eq!(mount_test_syscall(57, [fd as u64, 0, 0, 0, 0, 0]), 0);
        let text = std::str::from_utf8(&bytes[..n as usize]).unwrap();
        let state = owner.read().unwrap();
        for (path, present) in expected {
            let ids: Vec<_> = state
                .mounts
                .iter()
                .filter(|mount| mount.guest == *path)
                .map(|mount| mount.id)
                .collect();
            assert_eq!(!ids.is_empty(), *present, "{} record {path}", owner.id());
            let listed: Vec<_> = text
                .lines()
                .filter_map(|line| {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    (fields[4] == *path).then(|| fields[0].parse::<u64>().unwrap())
                })
                .collect();
            assert_eq!(listed, ids, "{} mountinfo {path}", owner.id());
            assert_eq!(is_mountpoint(path), *present, "{} route {path}", owner.id());
        }
    }

    fn pre_reboot_tmp_cleanup(detach: bool) {
        let (_guard, root) = test_view();
        const TMP: &str = "/mnt/pre_reboot_dexopt/mount_tmp";
        const ALIAS: &str = "/mnt/pre_reboot_dexopt/chroot/foo";
        const CHILD: &str = "/mnt/pre_reboot_dexopt/mount_tmp/child";
        let owner =
            aim_storage::mount_namespace::Namespace::open(runtime_dir().unwrap(), "dexopt-source")
                .unwrap();
        let host = root.join("dexopt-source");
        std::fs::create_dir_all(&host).unwrap();
        owner
            .initialize(&format!(
                "root\t/\t{}\nrw\t/foo\t{}\npropagation\t/\tshared\n",
                crate::vfs::root().display(),
                host.display()
            ))
            .unwrap();
        let slave = owner.clone_to("dexopt-slave").unwrap();
        slave.append("propagation-flags\t/\t540672").unwrap(); // MS_SLAVE | MS_REC
        let private = owner.clone_to("dexopt-private").unwrap();
        private.append("propagation-flags\t/\t278528").unwrap(); // MS_PRIVATE | MS_REC
        load_own_mounts(&format!("namespace-owner\t{}\n", owner.id())).unwrap();
        // ART android-16.0.0_r1 dexopt_chroot_setup.cc, BindMount steps 1–4:
        // bind /foo to mount_tmp, make it slave, bind it to chroot, unmount tmp.
        bind_mount_recursive("/foo", TMP, host.clone(), Area::Writable, false).unwrap();
        let retained = owner.clone_to("dexopt-private-snapshot").unwrap();
        retained.append("propagation-flags\t/\t278528").unwrap();
        set_mount_propagation(TMP, 1 << 19).unwrap();
        bind_mount_recursive(TMP, ALIAS, host.clone(), Area::Writable, false).unwrap();
        if detach {
            add_mount(CHILD, host.clone(), Area::Writable, "tmpfs", "tmpfs").unwrap();
        }
        assert_namespace_mounts(&slave, &[(TMP, true), (ALIAS, true)]);
        assert_namespace_mounts(&private, &[(TMP, false), (ALIAS, false)]);
        assert_namespace_mounts(&retained, &[(TMP, true), (ALIAS, false)]);
        assert_namespace_mounts(&owner, &[(TMP, true), (ALIAS, true)]);
        let target = CString::new(TMP).unwrap();
        let args = [target.as_ptr() as u64, 8, 0, 0, 0, 0]; // UMOUNT_NOFOLLOW
        let result = mount_test_syscall(39, args);
        if detach {
            assert_eq!(result, -(errno::EBUSY as i64));
            assert_eq!(mount_test_syscall(39, [args[0], 8 | 2, 0, 0, 0, 0]), 0);
        } else {
            assert_eq!(result, 0);
        }
        assert!(
            !owner.read().unwrap().mounts.iter().any(|mount| {
                mount.guest == TMP || detach && below(TMP, &mount.guest).is_some()
            })
        );
        assert_namespace_mounts(
            &owner,
            &[(TMP, false), (CHILD, false), (ALIAS, true), ("/foo", true)],
        );
        assert_namespace_mounts(
            &slave,
            &[(TMP, false), (CHILD, false), (ALIAS, true), ("/foo", true)],
        );
        assert_namespace_mounts(&private, &[(TMP, false), (ALIAS, false), ("/foo", true)]);
        assert_namespace_mounts(&retained, &[(TMP, true), (ALIAS, false), ("/foo", true)]);
        assert!(
            !fuse_table_lines()
                .unwrap()
                .iter()
                .any(|line| line.split('\t').next() == Some(TMP))
        );
    }

    #[test]
    fn pre_reboot_tmp_unmount_reaches_slave_but_not_private_namespace() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::fuse_route_tests::pre_reboot_tmp_unmount_reaches_slave_but_not_private_namespace",
        ) {
            return;
        }
        pre_reboot_tmp_cleanup(false);
    }

    #[test]
    fn pre_reboot_tmp_detach_drops_subtree_and_reaches_slave_namespace() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::fuse_route_tests::pre_reboot_tmp_detach_drops_subtree_and_reaches_slave_namespace",
        ) {
            return;
        }
        pre_reboot_tmp_cleanup(true);
    }

    #[test]
    fn pre_reboot_private_root_bind_detach_does_not_propagate_to_slave() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::fuse_route_tests::pre_reboot_private_root_bind_detach_does_not_propagate_to_slave",
        ) {
            return;
        }
        let (_guard, _) = test_view();
        const TMP: &str = "/mnt/pre_reboot_dexopt/mount_tmp";
        let owner = NAMESPACE_VIEW
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .owner
            .clone();
        bind_mount_recursive("/", TMP, crate::vfs::root().into(), Area::Image, false).unwrap();
        let slave = owner.clone_to("private-parent-slave").unwrap();
        slave.append("propagation-flags\t/\t540672").unwrap();
        assert_namespace_mounts(&slave, &[(TMP, true)]);
        assert_namespace_mounts(&owner, &[(TMP, true)]);
        set_mount_propagation("/", (1 << 18) | 0x4000).unwrap();
        let target = CString::new(TMP).unwrap();
        assert_eq!(
            mount_test_syscall(39, [target.as_ptr() as u64, 8 | 2, 0, 0, 0, 0]),
            0
        );
        assert_namespace_mounts(&owner, &[(TMP, false)]);
        assert_namespace_mounts(&slave, &[(TMP, true)]);
    }

    fn actual_fuse_publication(
        guest: &str,
        host: &Path,
        source: &str,
        route: Option<&FuseRoute>,
    ) -> Result<(), Errno> {
        match route {
            Some(route) => install_mount(
                guest,
                host.into(),
                Area::Writable,
                source,
                "fuse",
                Some(route.clone()),
                None,
            ),
            None => remove_mount(guest).map(|_| ()),
        }
    }
    fn actual_plain_publication(
        guest: &str,
        host: &Path,
        area: Area,
        source: &str,
        fstype: &str,
        bind: Option<&str>,
    ) -> Result<(), Errno> {
        install_mount(
            guest,
            host.into(),
            area,
            source,
            fstype,
            None,
            bind.map(str::to_owned),
        )
    }

    #[test]
    fn init_path_map_alias_receives_late_mount_and_exec_import_does_not_duplicate_shared_entries() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::fuse_route_tests::init_path_map_alias_receives_late_mount_and_exec_import_does_not_duplicate_shared_entries",
        ) {
            return;
        }
        let (_guard, root) = test_view();
        let old_private = PRIVATE_MOUNTS.swap(false, Ordering::AcqRel);
        let old_rules = std::mem::take(&mut *PROPAGATION_RULES.lock().unwrap());
        let parent = root.join("init-map-parent");
        let lower = root.join("init-map-lower");
        for path in [&parent, &lower] {
            std::fs::create_dir_all(path).unwrap();
        }
        let text = format!(
            "root\t/\t{}\nrw\t/storage/aim-init-alias\t{}\nbind-source\t/storage/aim-init-alias\t/mnt/aim-init-user\npropagation\t/storage/aim-init-alias\tslave\n",
            root.display(),
            parent.display()
        );
        let (_, entries) = parse_map(&text).unwrap();
        assert_eq!(
            entries[0].bind_source.as_deref(),
            Some("/mnt/aim-init-user")
        );
        add_mount(
            "/mnt/aim-init-user",
            parent.clone(),
            Area::Writable,
            "parent",
            "bind",
        )
        .unwrap();
        let owner = NAMESPACE_VIEW
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .owner
            .clone();
        let prior = owner.read().unwrap();
        owner
            .update_base(&format!(
                "{}{}",
                prior.base,
                text.lines()
                    .filter(|line| !line.starts_with("root\t"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
            .unwrap();
        refresh_namespace().unwrap();
        actual_plain_publication(
            "/mnt/aim-init-user/emulated",
            &lower,
            Area::Writable,
            "lower",
            "bind",
            None,
        )
        .unwrap();
        refresh_fuse_mounts().unwrap();
        assert_eq!(
            lookup("/storage/aim-init-alias/emulated/0").0,
            lower.join("0")
        );
        let inherited = own_mounts_text();
        load_own_mounts(&inherited).unwrap();
        refresh_fuse_mounts().unwrap();
        assert_eq!(
            vfs()
                .mounts
                .read()
                .unwrap()
                .iter()
                .filter(|mount| mount.guest == "/mnt/aim-init-user/emulated" && mount.shared_fuse)
                .count(),
            1
        );
        assert_eq!(
            lookup("/storage/aim-init-alias/emulated/0").0,
            lower.join("0")
        );
        // An imported projection must remain an inherited event, not turn
        // into an explicit child mount hiding the next parent event.
        let retargeted = root.join("init-map-retargeted");
        std::fs::create_dir_all(&retargeted).unwrap();
        actual_plain_publication(
            "/mnt/aim-init-user/emulated",
            &retargeted,
            Area::Writable,
            "retargeted",
            "bind",
            None,
        )
        .unwrap();
        refresh_fuse_mounts().unwrap();
        assert_eq!(
            lookup("/storage/aim-init-alias/emulated/0").0,
            retargeted.join("0")
        );
        assert_eq!(
            vfs()
                .mounts
                .read()
                .unwrap()
                .iter()
                .filter(|mount| mount.guest == "/storage/aim-init-alias/emulated"
                    && mount.projected_fuse)
                .count(),
            1
        );
        actual_fuse_publication("/mnt/aim-init-user/emulated", &lower, "", None).unwrap();
        refresh_fuse_mounts().unwrap();
        *PROPAGATION_RULES.lock().unwrap() = old_rules;
        PRIVATE_MOUNTS.store(old_private, Ordering::Release);
    }
    #[test]
    fn late_plain_pass_through_bind_propagates_actual_lower_into_slave_alias() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::fuse_route_tests::late_plain_pass_through_bind_propagates_actual_lower_into_slave_alias",
        ) {
            return;
        }
        let (_guard, root) = test_view();
        let old_private = PRIVATE_MOUNTS.swap(false, Ordering::AcqRel);
        let old_rules = std::mem::take(&mut *PROPAGATION_RULES.lock().unwrap());
        let parent = root.join("plain-parent");
        let lower = root.join("plain-lower");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::create_dir_all(lower.join("0/Android/data")).unwrap();
        add_mount(
            "/mnt/aim-pass",
            parent.clone(),
            Area::Writable,
            "parent",
            "bind",
        )
        .unwrap();
        bind_mount_recursive(
            "/mnt/aim-pass",
            "/storage/aim-pass-slave",
            parent.clone(),
            Area::Writable,
            true,
        )
        .unwrap();
        bind_mount_recursive(
            "/mnt/aim-pass",
            "/storage/aim-pass-private",
            parent.clone(),
            Area::Writable,
            true,
        )
        .unwrap();
        set_mount_propagation("/storage/aim-pass-slave", (1 << 19) | 0x4000).unwrap();
        set_mount_propagation("/storage/aim-pass-private", (1 << 18) | 0x4000).unwrap();
        actual_plain_publication(
            "/mnt/aim-pass/emulated",
            &lower,
            Area::Writable,
            "/data/media",
            "bind",
            Some("/data/media"),
        )
        .unwrap();
        refresh_fuse_mounts().unwrap();
        assert_eq!(
            lookup("/storage/aim-pass-slave/emulated/0/Android/data").0,
            lower.join("0/Android/data")
        );
        assert!(fuse_route("/storage/aim-pass-slave/emulated/0/Android/data").is_none());
        assert_ne!(
            lookup("/storage/aim-pass-private/emulated/0/Android/data").0,
            lower.join("0/Android/data")
        );
        actual_fuse_publication("/mnt/aim-pass/emulated", &lower, "", None).unwrap();
        refresh_fuse_mounts().unwrap();
        assert_ne!(
            lookup("/storage/aim-pass-slave/emulated/0/Android/data").0,
            lower.join("0/Android/data")
        );
        for path in [
            "/storage/aim-pass-private",
            "/storage/aim-pass-slave",
            "/mnt/aim-pass",
        ] {
            assert!(remove_mount(path).unwrap());
        }
        *PROPAGATION_RULES.lock().unwrap() = old_rules;
        PRIVATE_MOUNTS.store(old_private, Ordering::Release);
    }
    #[test]
    fn early_parent_alias_projects_late_fuse_event_into_slave_but_not_private_view() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::fuse_route_tests::early_parent_alias_projects_late_fuse_event_into_slave_but_not_private_view",
        ) {
            return;
        }
        let (_guard, root) = test_view();
        let old_private = PRIVATE_MOUNTS.swap(false, Ordering::AcqRel);
        let old_rules = std::mem::take(&mut *PROPAGATION_RULES.lock().unwrap());
        let parent = root.join("late-source");
        std::fs::create_dir_all(&parent).unwrap();
        add_mount(
            "/mnt/aim-late-user",
            parent.clone(),
            Area::Writable,
            "user",
            "bind",
        )
        .unwrap();
        bind_mount_recursive(
            "/mnt/aim-late-user",
            "/mnt/aim-late-installer",
            parent.clone(),
            Area::Writable,
            true,
        )
        .unwrap();
        bind_mount_recursive(
            "/mnt/aim-late-installer",
            "/storage/aim-late-slave",
            parent.clone(),
            Area::Writable,
            true,
        )
        .unwrap();
        bind_mount_recursive(
            "/mnt/aim-late-installer",
            "/storage/aim-late-private",
            parent.clone(),
            Area::Writable,
            true,
        )
        .unwrap();
        set_mount_propagation("/storage/aim-late-slave", (1 << 19) | 0x4000).unwrap();
        set_mount_propagation("/storage/aim-late-private", (1 << 18) | 0x4000).unwrap();
        let route = FuseRoute {
            session: root.join("late-session.sock"),
            relative: String::new(),
            uid: 0,
            gid: 0,
            allow_other: true,
            default_permissions: false,
            read_only: false,
        };
        actual_fuse_publication("/mnt/aim-late-user/emulated", &parent, "fuse", Some(&route))
            .unwrap();
        refresh_fuse_mounts().unwrap();
        assert_eq!(
            fuse_route("/storage/aim-late-slave/emulated/0/Pictures")
                .unwrap()
                .relative,
            "0/Pictures"
        );
        assert!(fuse_route("/storage/aim-late-private/emulated/0/Pictures").is_none());
        assert!(
            own_mounts_text().contains("bind-source\t/mnt/aim-late-installer\t/mnt/aim-late-user")
        );
        actual_fuse_publication("/mnt/aim-late-user/emulated", &parent, "", None).unwrap();
        refresh_fuse_mounts().unwrap();
        assert!(fuse_route("/storage/aim-late-slave/emulated/0/Pictures").is_none());
        for path in [
            "/storage/aim-late-private",
            "/storage/aim-late-slave",
            "/mnt/aim-late-installer",
            "/mnt/aim-late-user",
        ] {
            assert!(remove_mount(path).unwrap());
        }
        *PROPAGATION_RULES.lock().unwrap() = old_rules;
        PRIVATE_MOUNTS.store(old_private, Ordering::Release);
    }
    #[test]
    fn recursive_bind_clones_fuse_and_android_submounts_nonrecursive_excludes_them() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::fuse_route_tests::recursive_bind_clones_fuse_and_android_submounts_nonrecursive_excludes_them",
        ) {
            return;
        }
        let (_guard, root) = test_view();
        let parent = root.join("recursive-source");
        let anchor = root.join("recursive-fuse-anchor");
        let android = root.join("recursive-android");
        for path in [&parent, &anchor, &android] {
            std::fs::create_dir_all(path).unwrap();
        }
        let options = crate::sys::fuse_mount::parse(
            b"fd=17,rootmode=40000,user_id=0,group_id=0,allow_other,",
        )
        .unwrap();
        add_mount(
            "/mnt/aim-rec-source",
            parent.clone(),
            Area::Writable,
            "source",
            "bind",
        )
        .unwrap();
        let session = root.join("recursive-session.sock");
        add_fuse_mount(
            "/mnt/aim-rec-source/emulated",
            session.clone(),
            anchor,
            "fuse",
            &options,
            false,
        )
        .unwrap();
        add_mount(
            "/mnt/aim-rec-source/emulated/0/Android/data",
            android.clone(),
            Area::Writable,
            "android-data",
            "bind",
        )
        .unwrap();
        bind_mount_recursive(
            "/mnt/aim-rec-source",
            "/mnt/aim-nonrec",
            parent.clone(),
            Area::Writable,
            false,
        )
        .unwrap();
        assert!(fuse_route("/mnt/aim-nonrec/emulated/0/Documents").is_none());
        assert_ne!(
            lookup("/mnt/aim-nonrec/emulated/0/Android/data/pkg").0,
            android.join("pkg")
        );
        bind_mount_recursive(
            "/mnt/aim-rec-source",
            "/mnt/aim-rec-target",
            parent,
            Area::Writable,
            true,
        )
        .unwrap();
        let route = fuse_route("/mnt/aim-rec-target/emulated/0/Documents").unwrap();
        assert_eq!(route.session, session);
        assert_eq!(route.relative, "0/Documents");
        assert!(route.allow_other);
        assert_eq!(
            lookup("/mnt/aim-rec-target/emulated/0/Android/data/pkg").0,
            android.join("pkg")
        );
        assert!(fuse_route("/mnt/aim-rec-target/emulated/0/Android/data/pkg").is_none());
        for path in [
            "/mnt/aim-rec-target/emulated/0/Android/data",
            "/mnt/aim-rec-target/emulated",
            "/mnt/aim-rec-target",
            "/mnt/aim-nonrec",
            "/mnt/aim-rec-source/emulated/0/Android/data",
            "/mnt/aim-rec-source/emulated",
            "/mnt/aim-rec-source",
        ] {
            assert!(remove_mount(path).unwrap());
        }
    }
    #[test]
    fn fresh_namespace_replays_flags_with_authenticated_shared_fuse_route() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::fuse_route_tests::fresh_namespace_replays_flags_with_authenticated_shared_fuse_route",
        ) {
            return;
        }
        let (_guard, root) = test_view();
        let source = NAMESPACE_VIEW
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .owner
            .clone();
        let receiving = source.clone_to("fresh-receiving").unwrap();
        receiving.append("propagation-flags\t/\t1048576").unwrap();
        let lower = root.join("fresh-fuse-lower");
        std::fs::create_dir_all(&lower).unwrap();
        let route = FuseRoute {
            session: root.join("real-route-session.sock"),
            relative: "actual/subtree".into(),
            uid: 1000,
            gid: 1000,
            allow_other: true,
            default_permissions: true,
            read_only: false,
        };
        actual_fuse_publication("/mnt/fresh-replay", &lower, "fuse", Some(&route)).unwrap();
        *NAMESPACE_VIEW.lock().unwrap() = Some(NamespaceView {
            page: receiving.generation().unwrap(),
            owner: receiving.clone(),
            generation: 0,
            records: Default::default(),
        });
        refresh_namespace().unwrap();
        let imported = fuse_route("/mnt/fresh-replay/file").unwrap();
        assert_eq!(imported.session, route.session);
        assert_eq!(imported.relative, "actual/subtree/file");
        assert_eq!(imported.uid, 1000);
        assert!(imported.default_permissions);
        assert!(
            !fuse_table_lines()
                .unwrap()
                .iter()
                .any(|line| line.contains("fresh-receiving")),
            "receiver must not republish source provenance"
        );
        let table = fuse_table().unwrap();
        let valid = std::fs::read(&table).unwrap();
        let before = NAMESPACE_VIEW.lock().unwrap().as_ref().unwrap().generation;
        let records = NAMESPACE_VIEW
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .records
            .clone();
        let rules = PROPAGATION_RULES.lock().unwrap().clone();
        let private = PRIVATE_MOUNTS.load(Ordering::Acquire);
        std::fs::write(&table, b"malformed provenance").unwrap();
        receiving.append("propagation-flags\t/\t1048576").unwrap();
        assert_eq!(refresh_namespace(), Err(errno::EIO));
        {
            let view = NAMESPACE_VIEW.lock().unwrap();
            let view = view.as_ref().unwrap();
            assert_eq!(view.generation, before);
            assert!(std::sync::Arc::ptr_eq(&view.records, &records));
        }
        assert!(PROPAGATION_RULES.lock().unwrap().iter().eq(rules.iter()));
        assert_eq!(PRIVATE_MOUNTS.load(Ordering::Acquire), private);
        assert_eq!(
            vfs()
                .mounts
                .read()
                .unwrap()
                .iter()
                .find(|mount| mount.guest == "/mnt/fresh-replay")
                .unwrap()
                .fuse
                .as_ref()
                .unwrap()
                .session,
            route.session
        );
        std::fs::write(&table, valid).unwrap();
        refresh_namespace().unwrap();
        assert!(NAMESPACE_VIEW.lock().unwrap().as_ref().unwrap().generation > before);
    }

    #[test]
    fn slave_namespace_imports_future_parent_fuse_routes_without_publishing_child_mounts() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::fuse_route_tests::slave_namespace_imports_future_parent_fuse_routes_without_publishing_child_mounts",
        ) {
            return;
        }
        let (_guard, root) = test_view();
        let old_private = PRIVATE_MOUNTS.swap(false, Ordering::AcqRel);
        let old_rules = std::mem::take(&mut *PROPAGATION_RULES.lock().unwrap());
        let parent = "/mnt/aim-slave-parent";
        let child = "/mnt/aim-slave-child";
        let anchor = root.join("slave-anchor");
        std::fs::create_dir_all(&anchor).unwrap();
        let route = FuseRoute {
            session: root.join("slave-session.sock"),
            relative: String::new(),
            uid: 0,
            gid: 0,
            allow_other: true,
            default_permissions: false,
            read_only: false,
        };
        let upstream = NAMESPACE_VIEW
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .owner
            .clone();
        private_mount_namespace().unwrap();
        set_mount_propagation("/", (1 << 19) | 0x4000).unwrap();
        // Parent publication is represented by its actual shared namespace table.
        let slave = NAMESPACE_VIEW.lock().unwrap().take().unwrap();
        *NAMESPACE_VIEW.lock().unwrap() = Some(NamespaceView {
            page: upstream.generation().unwrap(),
            owner: upstream.clone(),
            generation: 0,
            records: Default::default(),
        });
        refresh_namespace().unwrap();
        actual_fuse_publication(parent, &anchor, "fuse", Some(&route)).unwrap();
        *NAMESPACE_VIEW.lock().unwrap() = Some(slave);
        refresh_namespace().unwrap();
        refresh_fuse_mounts().unwrap();
        assert_eq!(fuse_route(parent).unwrap().session, route.session);
        bind_mount(
            parent,
            child,
            anchor.clone(),
            Area::Writable,
            "fuse",
            "bind",
        )
        .unwrap();
        assert!(fuse_route(child).is_some());
        assert!(
            !fuse_table_lines()
                .unwrap()
                .iter()
                .any(|line| line.split('\t').next() == Some(child))
        );
        remove_mount(child).unwrap();
        let slave = NAMESPACE_VIEW.lock().unwrap().take().unwrap();
        *NAMESPACE_VIEW.lock().unwrap() = Some(NamespaceView {
            page: upstream.generation().unwrap(),
            owner: upstream,
            generation: 0,
            records: Default::default(),
        });
        refresh_namespace().unwrap();
        actual_fuse_publication(parent, &anchor, "", None).unwrap();
        *NAMESPACE_VIEW.lock().unwrap() = Some(slave);
        refresh_namespace().unwrap();
        refresh_fuse_mounts().unwrap();
        *PROPAGATION_RULES.lock().unwrap() = old_rules;
        PRIVATE_MOUNTS.store(old_private, Ordering::Release);
    }
    #[test]
    fn fuse_bind_view_preserves_session_and_relative_tree_without_raw_path_resolution() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::fuse_route_tests::fuse_bind_view_preserves_session_and_relative_tree_without_raw_path_resolution",
        ) {
            return;
        }
        let (_guard, root) = test_view();
        let target = "/mnt/aim-fuse-test";
        let options =
            crate::sys::fuse_mount::parse(b"fd=17,rootmode=40000,user_id=0,group_id=0,allow_other")
                .unwrap();
        let anchor = root.join("fuse-anchor");
        std::fs::create_dir_all(&anchor).unwrap();
        let session = root.join("fuse-session.sock");
        add_fuse_mount(
            target,
            session.clone(),
            anchor.clone(),
            "fuse",
            &options,
            false,
        )
        .unwrap();
        bind_mount(
            "/mnt/aim-fuse-test/user/0",
            "/storage/aim-fuse-test",
            anchor,
            Area::Writable,
            "fuse",
            "bind",
        )
        .unwrap();
        let route = fuse_route("/storage/aim-fuse-test/Documents/a.txt").unwrap();
        assert_eq!(route.session, session);
        assert_eq!(route.relative, "user/0/Documents/a.txt");
        assert!(route.allow_other);
        let text = own_mounts_text();
        assert!(text.contains("fuse-session.sock"));
        assert!(remove_mount("/storage/aim-fuse-test").unwrap());
        assert!(remove_mount(target).unwrap());
        assert!(fuse_route("/storage/aim-fuse-test/Documents/a.txt").is_none());
    }
}

#[cfg(test)]
mod external_namespace_entry_tests {
    use super::*;
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};
    const CHILD: &str = "vfs::external_namespace_entry_tests::external_entry_child";
    #[test]
    #[ignore = "actual child executed by explicit_external_entry_requires_live_authentic_owner"]
    fn external_entry_child() {
        let mut input = std::io::stdin().lock();
        let mut line = String::new();
        input.read_line(&mut line).unwrap();
        let map = PathBuf::from(line.trim_end());
        let owner = enter_init_namespace(Some(&map), None).unwrap();
        let current =
            aim_storage::process_namespace::ProcessIdentity::running(unsafe { libc::getpid() })
                .unwrap();
        assert_eq!(
            aim_storage::process_namespace::mount_namespace_of(
                &map.parent().unwrap().join("identity/by-pid"),
                current
            )
            .unwrap(),
            owner.id()
        );
        crate::sys::cred::init(
            crate::sys::cred::Identity::default(),
            Some(map.parent().unwrap().join("identity/by-pid")),
        );
        assert_eq!(
            crate::sys::posix_locks::start(Some(
                &map.parent().unwrap().join("posix-control-owner")
            )),
            Err(crate::errno::EPERM)
        );
        assert!(crate::sys::posix_locks::current().is_err());
        let table = map.parent().unwrap().join("identity/by-pid");
        let locator = map.parent().unwrap().join("posix-control-owner");
        let mut denied = crate::sys::cred::Identity::default();
        denied.uid = [2000; 4];
        denied.cap_eff = 0;
        crate::sys::cred::init(denied, Some(table.clone()));
        assert_eq!(
            crate::sys::posix_locks::start_external(Some(&locator)),
            Err(crate::errno::EPERM)
        );
        crate::sys::cred::init(crate::sys::cred::Identity::default(), Some(table.clone()));
        let receipt = table.join(format!("{}.mount-namespace", current.host_pid));
        let original = std::fs::read(&receipt).unwrap();
        std::fs::write(
            &receipt,
            format!(
                "AIMPROCNS1\t{}\t{}\t{}\t{}\n",
                current.host_pid,
                current.start_seconds + 1,
                current.start_microseconds,
                owner.id()
            ),
        )
        .unwrap();
        assert_eq!(
            crate::sys::posix_locks::start_external(Some(&locator)),
            Err(crate::errno::ESRCH)
        );
        std::fs::remove_file(&receipt).unwrap();
        assert_eq!(
            crate::sys::posix_locks::start_external(Some(&locator)),
            Err(crate::errno::ENOENT)
        );
        std::fs::write(&receipt, &original).unwrap();
        let identity = table.join(current.host_pid.to_string());
        std::fs::write(&identity, b"cap_effective\t0x200000\n").unwrap();
        assert_eq!(
            crate::sys::posix_locks::start_external(Some(&locator)),
            Err(71)
        );
        // setns(CLONE_NEWNS) takes CAP_SYS_ADMIN and CAP_SYS_CHROOT.
        let mut privileged = crate::sys::cred::Identity::default();
        privileged.uid = [2000; 4];
        privileged.cap_eff = (1 << 21) | (1 << 18);
        crate::sys::cred::init(privileged, Some(table.clone()));
        aim_storage::process_namespace::register_mount_namespace(&table, current, "foreign-owner")
            .unwrap();
        assert_eq!(
            crate::sys::posix_locks::start_external(Some(&locator)),
            Err(crate::errno::EPERM)
        );
        aim_storage::process_namespace::register_mount_namespace(&table, current, owner.id())
            .unwrap();
        crate::sys::posix_locks::start_external(Some(&locator)).unwrap();
        let client = crate::sys::posix_locks::current().unwrap();
        assert_eq!(client.owner.guest_pid, current.host_pid);
        use std::os::fd::AsFd;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(map.parent().unwrap().join("actual-lock"))
            .unwrap();
        let lock = crate::sys::posix_locks::LinuxFlock {
            kind: 1,
            whence: 0,
            pad: 0,
            start: 0,
            len: 1,
            pid: 0,
            pad2: 0,
        };
        client.lock(file.as_fd(), 6, lock, || false).unwrap();

        println!("EXTERNAL_NAMESPACE_BOUND");
        std::io::stdout().flush().unwrap();
        line.clear();
        input.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), "close-lock");
        client
            .close_inode(aim_storage::inode_lease::Identity::from_fd(file.as_fd()).unwrap())
            .unwrap();
        drop(file);
        let final_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(map.parent().unwrap().join("actual-lock"))
            .unwrap();
        client.lock(final_file.as_fd(), 6, lock, || false).unwrap();
        println!("EXTERNAL_FINAL_LOCK_HELD");
        std::io::stdout().flush().unwrap();
        line.clear();
        input.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), "final-exit");
    }
    #[test]
    #[ignore = "actual init target executed by explicit_external_entry_requires_live_authentic_owner"]
    fn admission_target_child() {
        let mut input = std::io::stdin().lock();
        let mut line = String::new();
        input.read_line(&mut line).unwrap();
        let table = PathBuf::from(line.trim_end());
        let process =
            aim_storage::process_namespace::ProcessIdentity::running(unsafe { libc::getpid() })
                .unwrap();
        let init = aim_storage::process_namespace::InitRegistration::register(
            &table,
            process,
            "actual-owner",
        )
        .unwrap();
        aim_storage::process_namespace::register_mount_namespace(&table, process, "actual-owner")
            .unwrap();
        let holder = aim_paths::input(
            aim_paths::host_bin("aim-lock-holder"),
            "host/aim-lock-holder",
        )
        .unwrap();
        let controller =
            aim_storage::posix_broker::Controller::start(aim_storage::posix_broker::Config {
                endpoint: format!("dev.aim.external-admission.{}", process.host_pid),
                holder,
                startup_timeout: std::time::Duration::from_secs(5),
            })
            .unwrap();
        controller.bind_namespace(&table, &init).unwrap();
        controller
            .register_guest(aim_storage::posix_control::Owner {
                process,
                guest_pid: 1,
            })
            .unwrap();
        controller
            .owner_config()
            .unwrap()
            .write(
                &table
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("posix-control-owner"),
            )
            .unwrap();
        println!("ADMISSION_TARGET_READY");
        std::io::stdout().flush().unwrap();
        line.clear();
        input.read_line(&mut line).unwrap();
    }
    #[test]
    fn explicit_external_entry_requires_live_authentic_owner() {
        if crate::sys::fdtab::isolated_kernel_test(
            "vfs::external_namespace_entry_tests::explicit_external_entry_requires_live_authentic_owner",
        ) {
            return;
        }
        // The admission target needs the lock holder; without it the test skips here.
        if aim_paths::input(
            aim_paths::host_bin("aim-lock-holder"),
            "host/aim-lock-holder",
        )
        .is_none()
        {
            return;
        }
        let root =
            std::env::temp_dir().join(format!("aim-external-namespace-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _directory = Directory(root.clone());
        let table = root.join("identity/by-pid");
        std::fs::create_dir_all(&table).unwrap();
        std::fs::write(root.join("actual-lock"), b"native external lock").unwrap();
        let map = root.join("path-map");
        let base = format!("root\t/\t{}\n", root.display());
        std::fs::write(&map, &base).unwrap();
        let process =
            aim_storage::process_namespace::ProcessIdentity::running(unsafe { libc::getpid() })
                .unwrap();
        let owner = aim_storage::mount_namespace::Namespace::open(&root, "actual-owner").unwrap();
        owner.initialize(&base).unwrap();
        aim_storage::process_namespace::InitRegistration::register(&table, process, owner.id())
            .unwrap();
        aim_storage::process_namespace::register_mount_namespace(&table, process, owner.id())
            .unwrap();
        assert!(enter_init_namespace(None, None).is_err());
        assert!(enter_init_namespace(Some(&map), Some(&root)).is_err());
        let init = std::fs::read(table.join("namespace-init")).unwrap();
        std::fs::write(table.join("namespace-init"), b"damaged").unwrap();
        assert!(enter_init_namespace(Some(&map), None).is_err());
        std::fs::write(table.join("namespace-init"), &init).unwrap();
        let receipt = table.join(format!("{}.mount-namespace", process.host_pid));
        let original = std::fs::read(&receipt).unwrap();
        std::fs::write(
            &receipt,
            format!(
                "AIMPROCNS1\t{}\t{}\t{}\tactual-owner\n",
                process.host_pid,
                process.start_seconds + 1,
                process.start_microseconds
            ),
        )
        .unwrap();
        assert!(enter_init_namespace(Some(&map), None).is_err());
        std::fs::write(&receipt, &original).unwrap();
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                }
                let _ = self.0.wait();
            }
        }
        let mut target = Child(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "vfs::external_namespace_entry_tests::admission_target_child",
                    "--ignored",
                    "--nocapture",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut target_input = target.0.stdin.take().unwrap();
        writeln!(target_input, "{}", table.display()).unwrap();
        let mut target_output = std::io::BufReader::new(target.0.stdout.take().unwrap());
        let mut ready = String::new();
        loop {
            ready.clear();
            assert!(target_output.read_line(&mut ready).unwrap() > 0);
            if ready.trim_end() == "ADMISSION_TARGET_READY" {
                break;
            }
        }
        let mut child = Child(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CHILD, "--ignored", "--nocapture"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut input = child.0.stdin.take().unwrap();
        writeln!(input, "{}", map.display()).unwrap();
        let mut output = std::io::BufReader::new(child.0.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(output.read_line(&mut line).unwrap() > 0);
            if line.trim_end() == "EXTERNAL_NAMESPACE_BOUND" {
                break;
            }
        }
        use std::os::fd::AsFd;
        enter_init_namespace(Some(&map), None).unwrap();
        crate::sys::cred::init(crate::sys::cred::Identity::default(), Some(table.clone()));
        crate::sys::posix_locks::start_external(Some(&root.join("posix-control-owner"))).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("actual-lock"))
            .unwrap();
        let client = crate::sys::posix_locks::current().unwrap();
        let query = crate::sys::posix_locks::LinuxFlock {
            kind: 1,
            whence: 0,
            pad: 0,
            start: 0,
            len: 1,
            pid: 0,
            pad2: 0,
        };
        let held = client.lock(file.as_fd(), 5, query, || false).unwrap();
        assert_eq!(held.kind, 1);
        assert_eq!(held.pid, child.0.id() as i32);
        writeln!(input, "close-lock").unwrap();
        loop {
            line.clear();
            assert!(output.read_line(&mut line).unwrap() > 0);
            if line.trim_end() == "EXTERNAL_FINAL_LOCK_HELD" {
                break;
            }
        }
        assert_eq!(
            client.lock(file.as_fd(), 5, query, || false).unwrap().kind,
            1
        );
        writeln!(input, "final-exit").unwrap();
        drop(input);
        assert!(child.0.wait().unwrap().success());
        assert_eq!(
            client.lock(file.as_fd(), 5, query, || false).unwrap().kind,
            2
        );
        // Admission retains the actual namespace independently of the target receipt.
        writeln!(target_input, "exit").unwrap();
        drop(target_input);
        assert!(target.0.wait().unwrap().success());
        assert!(enter_init_namespace(Some(&map), None).is_err());
        assert!(
            owner
                .read()
                .unwrap()
                .mounts
                .iter()
                .any(|mount| mount.guest == "/")
        );
    }
}

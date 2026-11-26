//! Loop and device-mapper nodes for apexd.
//!
//! `/dev/loop-control`, `/dev/loopN`, `/dev/block/loopN`, `/dev/device-mapper`
//! and `/dev/block/dm-N` are the nodes android-16.0.0_r1 apexd and libdm
//! open. The ioctl set is the one that path issues. Any other request on
//! these fds is `ENOTTY`, the errno Linux returns for an unknown device
//! command. A dm-verity table is checked per block on read
//! ([`super::dmverity`]); a mismatch is `EIO`.
//!
//! Eight loop devices start unbound, as `CONFIG_BLK_DEV_LOOP_MIN_COUNT`
//! does, so `LOOP_CTL_ADD` of those ids is `EEXIST`. apexd counts a
//! success only when the call returns greater than zero
//! (`PreAllocateLoopDevices`), so id 0 must already exist: a new id 0
//! would return 0 and abort bootstrap. `EEXIST` with no
//! `/sys/block/loopN/loop` directory is the idle device it keeps.
//!
//! An open records the device's major and minor. ioctl, read and fstat
//! follow that pair. `/dev/loop-control` is 10:237, `/dev/device-mapper`
//! is 10:236, `/dev/loopN` is 7:N and `/dev/block/dm-N` is 253:N. A pin
//! duplicates the host fd; the duplicate carries the same device
//! numbers, and device-mapper commands are not accepted on loop-control.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::errno::{self, EBADF, EBUSY, EEXIST, EIO, EINVAL, ENODEV, ENOTTY, ENXIO, EROFS, Errno};
use crate::vfs::{self, Area};

use super::dir::{self, Entry};
use super::ext4ro::{Image, ReadAt};
use super::procfs::Node;
use super::uevent::Device;

const LOOP_MAJOR: u32 = 7;
const DM_MAJOR: u32 = 253;
const MISC_MAJOR: u32 = 10;
const LOOP_CONTROL_MINOR: u32 = 237;
const DM_CONTROL_MINOR: u32 = 236;
const MIN_COUNT: u32 = 8;

const LOOP_SET_FD: u64 = 0x4c00;
const LOOP_CLR_FD: u64 = 0x4c01;
const LOOP_SET_STATUS64: u64 = 0x4c04;
const LOOP_GET_STATUS64: u64 = 0x4c05;
const LOOP_SET_BLOCK_SIZE: u64 = 0x4c09;
const LOOP_CONFIGURE: u64 = 0x4c0a;
const LOOP_CTL_ADD: u64 = 0x4c80;
const LOOP_CTL_REMOVE: u64 = 0x4c81;
const LOOP_CTL_GET_FREE: u64 = 0x4c82;
const BLKGETSIZE: u8 = 96;
const BLKFLSBUF: u8 = 97;
const BLKGETSIZE64: u8 = 114;

const LO_FLAGS_READ_ONLY: u32 = 1;
const LO_FLAGS_AUTOCLEAR: u32 = 4;
const LO_FLAGS_PARTSCAN: u32 = 8;
const LO_FLAGS_DIRECT_IO: u32 = 16;
const LO_FLAGS_OK: u32 = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN | LO_FLAGS_DIRECT_IO;

const DM_VERSION: u8 = 0;
const DM_DEV_CREATE: u8 = 3;
const DM_DEV_REMOVE: u8 = 4;
const DM_DEV_SUSPEND: u8 = 6;
const DM_DEV_STATUS: u8 = 7;
const DM_TABLE_LOAD: u8 = 9;
const DM_READONLY: u32 = 1;
const DM_SUSPEND: u32 = 2;
const DM_UEVENT: u32 = 1 << 13;
const O_DIRECTORY: u64 = 0o40000;
const O_CLOEXEC: u64 = 0o2000000;

struct Backing {
    fd: OwnedFd,
    offset: u64,
    sizelimit: u64,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    file_size: u64,
}

struct Loop {
    backing: Option<Backing>,
    block_size: u32,
    read_ahead_kb: u32,
    nr_requests: u32,
    scheduler: String,
    opens: u32,
}

struct Dm {
    name: String,
    uuid: String,
    readonly: bool,
    suspended: bool,
    inactive: Option<Target>,
    live: Option<Target>,
    read_ahead_kb: u32,
    nr_requests: u32,
    scheduler: String,
    opens: u32,
}

#[derive(Clone)]
enum Target {
    Error,
    Verity(super::dmverity::Table),
}

#[derive(Clone, Copy)]
enum Kind {
    Control,
    Loop(u32),
    Mapper,
    Dm(u32),
}

#[derive(Clone, Copy)]
struct Open {
    kind: Kind,
}

/// The device numbers resolved when this fd was opened, and its offset.
pub struct OpenDev {
    pub major: u32,
    pub minor: u32,
    pub pos: Mutex<u64>,
}

struct State {
    loops: BTreeMap<u32, Loop>,
    dms: BTreeMap<u32, Dm>,
    names: BTreeMap<String, u32>,
    opens: BTreeMap<i32, Open>,
    seeded: bool,
}

static STATE: Mutex<State> = Mutex::new(State {
    loops: BTreeMap::new(),
    dms: BTreeMap::new(),
    names: BTreeMap::new(),
    opens: BTreeMap::new(),
    seeded: false,
});

fn lock() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn ensure(state: &mut State) {
    if !state.seeded {
        for minor in 0..MIN_COUNT {
            state.loops.entry(minor).or_insert_with(new_loop);
        }
        state.seeded = true;
    }
    // Another process (apexd) created these. This process's table starts
    // empty, so status and sysfs would otherwise answer `ENXIO` / `ENOENT`.
    absorb(state);
}

fn catalog_path() -> Option<PathBuf> {
    vfs::runtime_dir().map(|dir| dir.join("block-devices"))
}

fn publish(state: &State) {
    let Some(path) = catalog_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut text = String::new();
    for minor in state.loops.keys() {
        text.push_str(&format!("loop\t{minor}\n"));
    }
    for (minor, dev) in &state.dms {
        let name = dev.name.replace(['\t', '\n'], "_");
        let uuid = dev.uuid.replace(['\t', '\n'], "_");
        text.push_str(&format!(
            "dm\t{minor}\t{name}\t{uuid}\t{}\t{}\n",
            u8::from(dev.suspended),
            u8::from(dev.readonly)
        ));
    }
    let _ = fs::write(path, text);
}

fn absorb(state: &mut State) {
    let Some(path) = catalog_path() else {
        return;
    };
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let mut fields = line.split('\t');
        match fields.next() {
            Some("loop") => {
                let Some(minor) = fields.next().and_then(|text| text.parse().ok()) else {
                    continue;
                };
                state.loops.entry(minor).or_insert_with(new_loop);
            }
            Some("dm") => {
                let Some(minor) = fields.next().and_then(|text| text.parse().ok()) else {
                    continue;
                };
                let Some(name) = fields.next() else {
                    continue;
                };
                if state.names.contains_key(name) || state.dms.contains_key(&minor) {
                    continue;
                }
                let uuid = fields.next().unwrap_or("").to_string();
                let mut dev = new_dm(name.to_string(), uuid);
                dev.suspended = fields.next() == Some("1");
                dev.readonly = fields.next() == Some("1");
                state.names.insert(name.to_string(), minor);
                state.dms.insert(minor, dev);
            }
            _ => {}
        }
    }
}

/// A guest node ueventd can `chown`. The open path is still the device
/// table; the file is only so the directory entry exists. The image root
/// is not written.
fn place_node(guest: &str) {
    let (host, area) = vfs::lookup(guest);
    if area == Area::Image {
        return;
    }
    if let Some(parent) = host.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::OpenOptions::new().write(true).create(true).open(host);
}

fn new_loop() -> Loop {
    Loop {
        backing: None,
        block_size: 512,
        read_ahead_kb: 128,
        nr_requests: 128,
        scheduler: "none".into(),
        opens: 0,
    }
}

fn new_dm(name: String, uuid: String) -> Dm {
    Dm {
        name,
        uuid,
        readonly: false,
        suspended: true,
        inactive: None,
        live: None,
        read_ahead_kb: 128,
        nr_requests: 128,
        scheduler: "none".into(),
        opens: 0,
    }
}

#[derive(Clone, Copy)]
enum Which {
    Loop(u32),
    Dm(u32),
}

/// `open` of a loop or device-mapper node. None: some other path.
pub fn open(guest: &str, flags: u64) -> Option<i64> {
    let kind = classify(guest)?;
    if flags & O_DIRECTORY != 0 {
        return Some(-(errno::ENOTDIR as i64));
    }
    let mut state = lock();
    ensure(&mut state);
    let resolved = match resolve(&state, kind) {
        Ok(kind) => kind,
        Err(error) => return Some(-(error as i64)),
    };
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Some(-(errno::last() as i64));
    }
    super::fdtab::set_flags(fd, flags & 0o4000 != 0, flags & O_CLOEXEC != 0);
    let (major, minor) = numbers(resolved);
    hold(&mut state, resolved);
    state.opens.insert(fd, Open { kind: resolved });
    drop(state);
    super::fdtab::insert(
        fd,
        super::fdtab::Kind::Dev(Arc::new(OpenDev {
            major,
            minor,
            pos: Mutex::new(0),
        })),
    );
    Some(fd as i64)
}

fn numbers(kind: Kind) -> (u32, u32) {
    match kind {
        Kind::Control => (MISC_MAJOR, LOOP_CONTROL_MINOR),
        Kind::Mapper => (MISC_MAJOR, DM_CONTROL_MINOR),
        Kind::Loop(minor) => (LOOP_MAJOR, minor),
        Kind::Dm(minor) => (DM_MAJOR, minor),
    }
}

fn kind_of(major: u32, minor: u32) -> Option<Kind> {
    match (major, minor) {
        (MISC_MAJOR, LOOP_CONTROL_MINOR) => Some(Kind::Control),
        (MISC_MAJOR, DM_CONTROL_MINOR) => Some(Kind::Mapper),
        (LOOP_MAJOR, minor) => Some(Kind::Loop(minor)),
        (DM_MAJOR, minor) => Some(Kind::Dm(minor)),
        _ => None,
    }
}

fn recorded(fd: i32) -> Option<Arc<OpenDev>> {
    match super::fdtab::get(fd) {
        Some(super::fdtab::Kind::Dev(dev)) => Some(dev),
        _ => None,
    }
}

/// A fork child keeps the device numbers and offset of an inherited open.
pub fn restore_open(fd: i32, major: u32, minor: u32, pos: u64) -> Arc<OpenDev> {
    if let Some(kind) = kind_of(major, minor) {
        let mut state = lock();
        state.opens.entry(fd).or_insert(Open { kind });
    }
    Arc::new(OpenDev {
        major,
        minor,
        pos: Mutex::new(pos),
    })
}

fn hold(state: &mut State, kind: Kind) {
    match kind {
        Kind::Loop(minor) => {
            if let Some(dev) = state.loops.get_mut(&minor) {
                dev.opens += 1;
            }
        }
        Kind::Dm(minor) => {
            if let Some(dev) = state.dms.get_mut(&minor) {
                dev.opens += 1;
            }
        }
        Kind::Control | Kind::Mapper => {}
    }
}

pub fn on_close(fd: i32) {
    let mut state = lock();
    let Some(open) = state.opens.remove(&fd) else {
        return;
    };
    match open.kind {
        Kind::Loop(minor) => {
            let Some(dev) = state.loops.get_mut(&minor) else {
                return;
            };
            dev.opens = dev.opens.saturating_sub(1);
            if dev.opens == 0
                && dev
                    .backing
                    .as_ref()
                    .is_some_and(|b| b.flags & LO_FLAGS_AUTOCLEAR != 0)
            {
                dev.backing = None;
            }
        }
        Kind::Dm(minor) => {
            if let Some(dev) = state.dms.get_mut(&minor) {
                dev.opens = dev.opens.saturating_sub(1);
            }
        }
        Kind::Control | Kind::Mapper => {}
    }
}

pub fn on_dup(old: i32, new: i32) {
    let mut state = lock();
    let Some(open) = state.opens.get(&old).cloned() else {
        return;
    };
    hold(&mut state, open.kind);
    state.opens.insert(new, open);
}

/// stat of a loop or dm node that exists. None: not one of these paths.
pub fn stat(guest: &str) -> Option<libc::stat> {
    if let Some(st) = block_dir_stat(guest) {
        return Some(st);
    }
    let kind = classify(guest)?;
    let mut state = lock();
    ensure(&mut state);
    let kind = resolve(&state, kind).ok()?;
    Some(stat_of(&state, kind))
}

pub fn fstat(fd: i32, st: &mut libc::stat) -> bool {
    let Some(dev) = recorded(fd) else {
        return false;
    };
    let Some(kind) = kind_of(dev.major, dev.minor) else {
        return false;
    };
    *st = stat_of(&lock(), kind);
    true
}

pub fn ioctl(fd: i32, req: u64, arg: u64) -> Option<i64> {
    let dev = recorded(fd)?;
    let kind = kind_of(dev.major, dev.minor)?;
    Some(match command(kind, req & 0xffff_ffff, arg) {
        Ok(value) => value,
        Err(error) => -(error as i64),
    })
}

/// Read, write, or positioned read/write. None: not one of these fds.
pub fn pio(fd: i32, buf: u64, len: usize, pos: Option<i64>, write: bool) -> Option<i64> {
    if recorded(fd).is_none() {
        return None;
    }
    if write {
        return Some(-(EROFS as i64));
    }
    Some(match read_fd(fd, buf, len, pos) {
        Ok(n) => n,
        Err(error) => -(error as i64),
    })
}

pub fn rwv(fd: i32, iov: &[libc::iovec], write: bool) -> Option<i64> {
    if recorded(fd).is_none() {
        return None;
    }
    if write {
        return Some(-(EROFS as i64));
    }
    let mut total = 0i64;
    for v in iov {
        if v.iov_len == 0 {
            continue;
        }
        match read_fd(fd, v.iov_base as u64, v.iov_len, None) {
            Ok(n) => {
                total += n;
                if (n as usize) < v.iov_len {
                    break;
                }
            }
            Err(error) => return Some(if total > 0 { total } else { -(error as i64) }),
        }
    }
    Some(total)
}

pub fn lseek(fd: i32, off: i64, whence: i32) -> Option<i64> {
    let dev = recorded(fd)?;
    let kind = kind_of(dev.major, dev.minor)?;
    let len = device_len(&lock(), kind).unwrap_or(0);
    let mut pos = dev.pos.lock().unwrap_or_else(|error| error.into_inner());
    let next = match whence {
        0 => off,
        1 => *pos as i64 + off,
        2 => len as i64 + off,
        3 => {
            if off < 0 || off as u64 > len {
                return Some(-(ENXIO as i64));
            }
            off
        }
        4 => {
            if off < 0 || off as u64 > len {
                return Some(-(ENXIO as i64));
            }
            len as i64
        }
        _ => return Some(-(EINVAL as i64)),
    };
    if next < 0 {
        return Some(-(EINVAL as i64));
    }
    *pos = next as u64;
    Some(next)
}

/// One installed ext4 tree. The directory is the superblock: every
/// namespace that mounts it names this host path. Dropping the loop or
/// dm device table does not drop the tree, and a namespace copy does not
/// open the device again.
struct Superblock {
    host: PathBuf,
    source: String,
}

static SUPERBLOCKS: Mutex<Vec<Superblock>> = Mutex::new(Vec::new());

pub(super) fn remember_superblock(host: &Path, source: &str) {
    let mut held = SUPERBLOCKS.lock().unwrap_or_else(|e| e.into_inner());
    if held.iter().any(|block| block.host == host) {
        return;
    }
    held.push(Superblock {
        host: host.to_path_buf(),
        source: source.to_string(),
    });
}

/// `mount` of an ext4 loop or dm-verity device.
///
/// The tree is a directory filled from the block reader at this call.
/// It is mounted read-only as an image, and a guest lookup of a file
/// under it resolves to that directory. The host backing file is not
/// opened again, so changing it after the mount cannot change a guest
/// read. A dm-verity source is checked while the directory is filled;
/// a bad block fails the mount. The directory outlives the device table
/// and is shared by every namespace that keeps the mount.
pub fn mount_ext4(source: &str, guest: &str, readonly: bool) -> Result<(), Errno> {
    if !readonly {
        return Err(EROFS);
    }
    let host = materialize(source)?;
    remember_superblock(&host, source);
    if let Err(error) = vfs::add_mount(guest, host.clone(), Area::Image, source, "ext4") {
        let _ = fs::remove_dir_all(&host);
        let _ = fs::remove_file(vfs::ext4_stamp_path(&host));
        SUPERBLOCKS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|block| block.host != host);
        return Err(error);
    }
    Ok(())
}

/// Sources whose ext4 trees are still installed. Device-table resets do
/// not remove these.
pub(super) fn superblock_sources() -> Vec<String> {
    SUPERBLOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|block| block.source.clone())
        .collect()
}

/// Forget loop and dm devices. Installed ext4 trees stay.
pub(super) fn detach_all_backings() {
    let mut state = lock();
    for dev in state.loops.values_mut() {
        dev.backing = None;
    }
    state.dms.clear();
    state.names.clear();
}

/// `reader_for` after the device table is gone. A mounted tree does not
/// use this.
pub(super) fn source_reader_errno(source: &str) -> i32 {
    match reader_for(source) {
        Ok(_) => 0,
        Err(error) => error,
    }
}

fn materialize(source: &str) -> Result<PathBuf, Errno> {
    let reader = reader_for(source)?;
    let image = Image::open(reader)?;
    let host = fresh_dir()?;
    if let Err(error) = image.install(&host) {
        let _ = fs::remove_dir_all(&host);
        let _ = fs::remove_file(vfs::ext4_stamp_path(&host));
        return Err(error);
    }
    if let Err(error) = vfs::note_ext4_host(&host) {
        let _ = fs::remove_dir_all(&host);
        let _ = fs::remove_file(vfs::ext4_stamp_path(&host));
        return Err(error);
    }
    Ok(host)
}

/// A new directory under `apex-mounts`. The name carries this process's
/// pid, and an existing directory is left alone: another process's counter
/// also starts at 1, and installing into that directory deleted the tree a
/// mount still named.
fn fresh_dir() -> Result<PathBuf, Errno> {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let base = vfs::runtime_dir().map(|p| p.join("apex-mounts")).unwrap_or_else(|| {
        std::env::temp_dir().join(format!("aim-apex-mounts-{}", std::process::id()))
    });
    fs::create_dir_all(&base)
        .map_err(|e| errno::from_darwin(e.raw_os_error().unwrap_or(libc::EIO)))?;
    let pid = std::process::id();
    for _ in 0..100_000 {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("{pid}-{n}"));
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)));
            }
        }
    }
    Err(crate::errno::ENOMEM)
}

fn reader_for(source: &str) -> Result<Box<dyn ReadAt + Send>, Errno> {
    let mut state = lock();
    ensure(&mut state);
    let Some(kind) = classify(source) else {
        return Err(ENODEV);
    };
    let kind = resolve(&state, kind)?;
    match kind {
        Kind::Loop(minor) => Ok(Box::new(loop_io(&state, minor)?)),
        Kind::Dm(minor) => {
            let dev = state.dms.get(&minor).ok_or(ENXIO)?;
            let Some(Target::Verity(table)) = dev.live.clone() else {
                return Err(EIO);
            };
            if table.data_device != table.hash_device {
                return Err(EINVAL);
            }
            let minor = loop_minor(&table.data_device).ok_or(EINVAL)?;
            let io = loop_io(&state, minor)?;
            Ok(Box::new(super::dmverity::Verified::new(io, table)))
        }
        Kind::Control | Kind::Mapper => Err(ENOTTY),
    }
}

fn loop_io(state: &State, minor: u32) -> Result<FdAt, Errno> {
    let backing = state
        .loops
        .get(&minor)
        .and_then(|dev| dev.backing.as_ref())
        .ok_or(ENXIO)?;
    let fd = backing
        .fd
        .try_clone()
        .map_err(|e| errno::from_darwin(e.raw_os_error().unwrap_or(libc::EIO)))?;
    let len = mapped_len(backing);
    Ok(FdAt {
        fd,
        base: backing.offset,
        limit: len,
        file_size: backing.file_size,
    })
}

struct FdAt {
    fd: OwnedFd,
    base: u64,
    limit: u64,
    file_size: u64,
}

impl ReadAt for FdAt {
    fn len(&self) -> u64 {
        self.limit
    }
    fn read_exact_at(&self, at: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let end = at.checked_add(buf.len() as u64).ok_or(EIO)?;
        if end > self.limit {
            return Err(EIO);
        }
        let file_at = self.base + at;
        if file_at >= self.file_size {
            buf.fill(0);
            return Ok(());
        }
        let have = (self.file_size - file_at) as usize;
        if have >= buf.len() {
            return pread_full(self.fd.as_raw_fd(), file_at, buf);
        }
        pread_full(self.fd.as_raw_fd(), file_at, &mut buf[..have])?;
        buf[have..].fill(0);
        Ok(())
    }
}

fn command(kind: Kind, req: u64, arg: u64) -> Result<i64, Errno> {
    if let Some(nr) = blk_nr(req) {
        return blk(kind, nr, arg);
    }
    if let Some(nr) = dm_cmd(req) {
        return if matches!(kind, Kind::Mapper) {
            dm(nr, arg)
        } else {
            Err(ENOTTY)
        };
    }
    match (kind, req) {
        (Kind::Control, LOOP_CTL_ADD) => ctl_add(arg as u32),
        (Kind::Control, LOOP_CTL_REMOVE) => ctl_remove(arg as u32),
        (Kind::Control, LOOP_CTL_GET_FREE) => ctl_free(),
        (Kind::Loop(minor), LOOP_SET_FD) => {
            set_fd(minor, arg as i32)?;
            Ok(0)
        }
        (Kind::Loop(minor), LOOP_CLR_FD) => {
            clr_fd(minor)?;
            Ok(0)
        }
        (Kind::Loop(minor), LOOP_SET_STATUS64) => {
            let info = super::user_memory::read_exact(arg, 232)?;
            set_status(minor, &info)?;
            Ok(0)
        }
        (Kind::Loop(minor), LOOP_GET_STATUS64) => {
            let info = get_status(minor)?;
            super::user_memory::write_exact(arg, &info)?;
            Ok(0)
        }
        (Kind::Loop(minor), LOOP_SET_BLOCK_SIZE) => {
            set_block(minor, arg as u32)?;
            Ok(0)
        }
        (Kind::Loop(minor), LOOP_CONFIGURE) => {
            let raw = super::user_memory::read_exact(arg, 240)?;
            let fd = i32::from_le_bytes(raw[0..4].try_into().unwrap());
            let block = u32::from_le_bytes(raw[4..8].try_into().unwrap());
            configure_checked(minor, fd, block, &raw[8..240])?;
            Ok(0)
        }
        (Kind::Loop(_), LOOP_CTL_ADD | LOOP_CTL_REMOVE | LOOP_CTL_GET_FREE) => Err(ENOTTY),
        (Kind::Control | Kind::Loop(_) | Kind::Mapper | Kind::Dm(_), _) => Err(ENOTTY),
    }
}

fn ctl_add(id: u32) -> Result<i64, Errno> {
    if id > 1_048_575 {
        return Err(EINVAL);
    }
    let mut state = lock();
    ensure(&mut state);
    if state.loops.contains_key(&id) {
        return Err(EEXIST);
    }
    state.loops.insert(id, new_loop());
    publish(&state);
    drop(state);
    place_node(&format!("/dev/block/loop{id}"));
    place_node(&format!("/dev/loop{id}"));
    let event = loop_device(id);
    super::uevent::emit("add", &event, &[]);
    Ok(i64::from(id))
}

fn ctl_remove(id: u32) -> Result<i64, Errno> {
    let mut state = lock();
    let dev = state.loops.get(&id).ok_or(EINVAL)?;
    if dev.backing.is_some() || dev.opens > 0 {
        return Err(EBUSY);
    }
    state.loops.remove(&id);
    publish(&state);
    Ok(0)
}

pub(super) fn ctl_free() -> Result<i64, Errno> {
    let mut state = lock();
    ensure(&mut state);
    if let Some(minor) = state
        .loops
        .iter()
        .find(|(_, dev)| dev.backing.is_none())
        .map(|(m, _)| *m)
    {
        return Ok(i64::from(minor));
    }
    let minor = state.loops.keys().next_back().copied().unwrap_or(0) + 1;
    state.loops.insert(minor, new_loop());
    publish(&state);
    drop(state);
    place_node(&format!("/dev/block/loop{minor}"));
    place_node(&format!("/dev/loop{minor}"));
    let event = loop_device(minor);
    super::uevent::emit("add", &event, &[]);
    Ok(i64::from(minor))
}

fn configure_checked(minor: u32, fd: i32, block: u32, info: &[u8]) -> Result<(), Errno> {
    // The apexd probe passes fd -1. Linux returns EBADF before EBUSY.
    // A `CLONE_FILES` thread shares this process's descriptor table, so
    // `F_GETFD` fails only when the fd is not open in the process. The
    // first `LOOP_CONFIGURE` of loop0 in the Mac trace passed an fd this
    // thread had not opened; that result is the same `EBADF`.
    if fd < 0 {
        return Err(EBADF);
    }
    configure(minor, fd, block, info)
}

pub(super) fn configure(minor: u32, fd: i32, block: u32, info: &[u8]) -> Result<(), Errno> {
    if info.len() < 232 {
        return Err(EINVAL);
    }
    let backing = attach(fd, info)?;
    let block = check_block(block)?;
    let mut state = lock();
    ensure(&mut state);
    let dev = state.loops.get_mut(&minor).ok_or(ENXIO)?;
    if dev.backing.is_some() {
        return Err(EBUSY);
    }
    dev.backing = Some(backing);
    dev.block_size = block;
    Ok(())
}

fn set_fd(minor: u32, fd: i32) -> Result<(), Errno> {
    let backing = attach(fd, &[0; 232])?;
    let mut state = lock();
    ensure(&mut state);
    let dev = state.loops.get_mut(&minor).ok_or(ENXIO)?;
    if dev.backing.is_some() {
        return Err(EBUSY);
    }
    dev.backing = Some(backing);
    Ok(())
}

fn set_status(minor: u32, info: &[u8]) -> Result<(), Errno> {
    let offset = u64::from_le_bytes(info[24..32].try_into().unwrap());
    let sizelimit = u64::from_le_bytes(info[32..40].try_into().unwrap());
    let flags = u32::from_le_bytes(info[52..56].try_into().unwrap());
    if flags & !LO_FLAGS_OK != 0 {
        return Err(EINVAL);
    }
    let mut state = lock();
    ensure(&mut state);
    let dev = state.loops.get_mut(&minor).ok_or(ENXIO)?;
    let backing = dev.backing.as_mut().ok_or(ENXIO)?;
    backing.offset = offset;
    backing.sizelimit = sizelimit;
    backing.flags = flags | LO_FLAGS_READ_ONLY;
    backing.file_name = name_at(info, 56);
    backing.crypt_name = name_at(info, 120);
    Ok(())
}

fn get_status(minor: u32) -> Result<[u8; 232], Errno> {
    let mut state = lock();
    ensure(&mut state);
    let backing = state
        .loops
        .get(&minor)
        .and_then(|dev| dev.backing.as_ref())
        .ok_or(ENXIO)?;
    let mut info = [0u8; 232];
    info[24..32].copy_from_slice(&backing.offset.to_le_bytes());
    info[32..40].copy_from_slice(&backing.sizelimit.to_le_bytes());
    info[40..44].copy_from_slice(&minor.to_le_bytes());
    info[52..56].copy_from_slice(&backing.flags.to_le_bytes());
    info[56..120].copy_from_slice(&backing.file_name);
    info[120..184].copy_from_slice(&backing.crypt_name);
    Ok(info)
}

fn clr_fd(minor: u32) -> Result<(), Errno> {
    let mut state = lock();
    let dev = state.loops.get_mut(&minor).ok_or(ENXIO)?;
    if dev.backing.is_none() {
        return Err(ENXIO);
    }
    dev.backing = None;
    Ok(())
}

fn set_block(minor: u32, block: u32) -> Result<(), Errno> {
    let block = check_block(block)?;
    let mut state = lock();
    let dev = state.loops.get_mut(&minor).ok_or(ENXIO)?;
    if dev.backing.is_none() {
        return Err(ENXIO);
    }
    dev.block_size = block;
    Ok(())
}

fn attach(fd: i32, info: &[u8]) -> Result<Backing, Errno> {
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(EBADF);
    }
    let owned = reopen(fd)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(owned.as_raw_fd(), &mut st) } < 0 {
        return Err(errno::last());
    }
    let flags = if info.len() >= 56 {
        u32::from_le_bytes(info[52..56].try_into().unwrap())
    } else {
        0
    };
    if flags & !LO_FLAGS_OK != 0 {
        return Err(EINVAL);
    }
    Ok(Backing {
        fd: owned,
        offset: if info.len() >= 32 {
            u64::from_le_bytes(info[24..32].try_into().unwrap())
        } else {
            0
        },
        sizelimit: if info.len() >= 40 {
            u64::from_le_bytes(info[32..40].try_into().unwrap())
        } else {
            0
        },
        flags: flags | LO_FLAGS_READ_ONLY,
        file_name: if info.len() >= 120 { name_at(info, 56) } else { [0; 64] },
        crypt_name: if info.len() >= 184 { name_at(info, 120) } else { [0; 64] },
        file_size: st.st_size.max(0) as u64,
    })
}

fn name_at(info: &[u8], at: usize) -> [u8; 64] {
    let mut name = [0u8; 64];
    name.copy_from_slice(&info[at..at + 64]);
    name
}

fn check_block(block: u32) -> Result<u32, Errno> {
    let block = if block == 0 { 512 } else { block };
    if matches!(block, 512 | 1024 | 2048 | 4096) {
        Ok(block)
    } else {
        Err(EINVAL)
    }
}

fn reopen(fd: i32) -> Result<OwnedFd, Errno> {
    if let Some(path) = fd_path(fd) {
        if let Ok(c) = CString::new(path) {
            let n = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if n >= 0 {
                return Ok(unsafe { OwnedFd::from_raw_fd(n) });
            }
        }
    }
    let n = unsafe { libc::dup(fd) };
    if n < 0 {
        return Err(errno::last());
    }
    unsafe { libc::fcntl(n, libc::F_SETFD, libc::FD_CLOEXEC) };
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

fn fd_path(fd: i32) -> Option<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        fs::read_link(format!("/proc/self/fd/{fd}"))
            .ok()
            .map(|p| p.into_os_string().into_encoded_bytes())
    }
    #[cfg(target_os = "macos")]
    {
        let mut buf = [0u8; 4096];
        if unsafe { crate::sys::fgetpath(fd, buf.as_mut_ptr()) } == 0 {
            Some(
                unsafe { std::ffi::CStr::from_ptr(buf.as_ptr().cast()) }
                    .to_bytes()
                    .to_vec(),
            )
        } else {
            None
        }
    }
}

fn blk(kind: Kind, nr: u8, arg: u64) -> Result<i64, Errno> {
    let len = device_len(&lock(), kind).ok_or(ENOTTY)?;
    match nr {
        BLKFLSBUF => Ok(0),
        BLKGETSIZE => {
            let sectors = (len / 512) as u64;
            super::user_memory::write_exact(arg, &sectors.to_le_bytes())?;
            Ok(0)
        }
        BLKGETSIZE64 => {
            super::user_memory::write_exact(arg, &len.to_le_bytes())?;
            Ok(0)
        }
        _ => Err(ENOTTY),
    }
}

fn device_len(state: &State, kind: Kind) -> Option<u64> {
    match kind {
        Kind::Loop(minor) => state.loops.get(&minor)?.backing.as_ref().map(mapped_len),
        Kind::Dm(minor) => Some(dm_len(state.dms.get(&minor)?)),
        Kind::Control | Kind::Mapper => None,
    }
}

fn mapped_len(backing: &Backing) -> u64 {
    let available = backing.file_size.saturating_sub(backing.offset);
    if backing.sizelimit == 0 {
        available
    } else {
        backing.sizelimit.min(available)
    }
}

fn dm_len(dev: &Dm) -> u64 {
    match &dev.live {
        Some(Target::Verity(table)) => table.data_len(),
        Some(Target::Error) => 512,
        None => 0,
    }
}

fn dm(nr: u8, arg: u64) -> Result<i64, Errno> {
    let head = super::user_memory::read_exact(arg, 16)?;
    let data_size = u32::from_le_bytes(head[12..16].try_into().unwrap());
    if data_size < 312 || data_size > (1 << 20) {
        return Err(EINVAL);
    }
    let mut buf = super::user_memory::read_exact(arg, data_size as usize)?;
    let status = match nr {
        DM_VERSION => dm_version(&mut buf),
        DM_DEV_CREATE => dm_create(&mut buf),
        DM_DEV_REMOVE => dm_remove(&mut buf),
        DM_DEV_SUSPEND => dm_suspend(&mut buf),
        DM_DEV_STATUS => dm_status(&mut buf),
        DM_TABLE_LOAD => dm_load(&mut buf),
        _ => return Err(ENOTTY),
    };
    super::user_memory::write_exact(arg, &buf)?;
    status?;
    Ok(0)
}

fn dm_version(buf: &mut [u8]) -> Result<(), Errno> {
    let major = u32_at(buf, 0);
    put_version(buf);
    if major == 4 { Ok(()) } else { Err(EINVAL) }
}

fn dm_create(buf: &mut [u8]) -> Result<(), Errno> {
    let name = ioctl_name(buf)?;
    if name.is_empty() || name.len() >= 128 {
        return Err(EINVAL);
    }
    let uuid = ioctl_uuid(buf);
    let mut state = lock();
    ensure(&mut state);
    if state.names.contains_key(&name) {
        return Err(EEXIST);
    }
    let minor = (0..).find(|m| !state.dms.contains_key(m)).unwrap();
    state.dms.insert(minor, new_dm(name.clone(), uuid));
    state.names.insert(name, minor);
    publish(&state);
    drop(state);
    place_node(&format!("/dev/block/dm-{minor}"));
    put_version(buf);
    put_u32(buf, 20, 0);
    put_u32(buf, 24, 0);
    put_u32(buf, 28, DM_SUSPEND);
    put_u64(buf, 40, encode_dev(DM_MAJOR, minor));
    Ok(())
}

fn dm_remove(buf: &mut [u8]) -> Result<(), Errno> {
    let mut state = lock();
    ensure(&mut state);
    let minor = find_dm(&state, buf)?;
    let dev = state.dms.get(&minor).ok_or(ENXIO)?;
    if dev.opens > 0 {
        return Err(EBUSY);
    }
    let name = dev.name.clone();
    state.dms.remove(&minor);
    state.names.remove(&name);
    publish(&state);
    put_version(buf);
    put_u32(buf, 28, u32_at(buf, 28) | DM_UEVENT);
    let event = dm_device(minor, &name);
    drop(state);
    super::uevent::emit("remove", &event, &[]);
    Ok(())
}

fn dm_suspend(buf: &mut [u8]) -> Result<(), Errno> {
    let suspend = u32_at(buf, 28) & DM_SUSPEND != 0;
    let mut state = lock();
    ensure(&mut state);
    let minor = find_dm(&state, buf)?;
    let dev = state.dms.get_mut(&minor).ok_or(ENXIO)?;
    if suspend {
        dev.suspended = true;
    } else if let Some(table) = dev.inactive.take() {
        dev.live = Some(table);
        dev.suspended = false;
    } else {
        dev.suspended = false;
    }
    let readonly = dev.readonly;
    let name = dev.name.clone();
    put_version(buf);
    let mut flags = if dev.suspended { DM_SUSPEND } else { 0 };
    if readonly {
        flags |= DM_READONLY;
    }
    put_u32(buf, 28, flags);
    put_u64(buf, 40, encode_dev(DM_MAJOR, minor));
    publish(&state);
    if !suspend {
        let event = dm_device(minor, &name);
        drop(state);
        super::uevent::emit("change", &event, &[]);
    }
    Ok(())
}

fn dm_status(buf: &mut [u8]) -> Result<(), Errno> {
    let mut state = lock();
    ensure(&mut state);
    let minor = find_dm(&state, buf)?;
    let dev = state.dms.get(&minor).ok_or(ENXIO)?;
    put_version(buf);
    put_u32(buf, 20, u32::from(dev.live.is_some()));
    put_u32(buf, 24, dev.opens);
    let mut flags = if dev.suspended { DM_SUSPEND } else { 0 };
    if dev.readonly {
        flags |= DM_READONLY;
    }
    put_u32(buf, 28, flags);
    put_u64(buf, 40, encode_dev(DM_MAJOR, minor));
    write_name(buf, 48, 128, &dev.name);
    write_name(buf, 176, 129, &dev.uuid);
    Ok(())
}

fn dm_load(buf: &mut [u8]) -> Result<(), Errno> {
    let count = u32_at(buf, 20);
    if count != 1 {
        return Err(EINVAL);
    }
    let start = u32_at(buf, 16) as usize;
    if start + 40 > buf.len() {
        return Err(EINVAL);
    }
    let next = u32_at(buf, start + 20) as usize;
    if next < 40 || start + next > buf.len() {
        return Err(EINVAL);
    }
    let spec = &buf[start..start + next];
    let mut ty = [0u8; 16];
    ty.copy_from_slice(&spec[24..40]);
    let ty = c_string(&ty);
    let param = c_string(&spec[40..]);
    let target = match ty.as_str() {
        "error" => Target::Error,
        "verity" => {
            let table = super::dmverity::Table::parse(&param)?;
            if loop_minor(&table.data_device).is_none() || table.data_device != table.hash_device {
                return Err(EINVAL);
            }
            Target::Verity(table)
        }
        _ => return Err(EINVAL),
    };
    let readonly = u32_at(buf, 28) & DM_READONLY != 0;
    let mut state = lock();
    ensure(&mut state);
    let minor = find_dm(&state, buf)?;
    let dev = state.dms.get_mut(&minor).ok_or(ENXIO)?;
    dev.inactive = Some(target);
    dev.readonly = readonly || dev.readonly;
    put_version(buf);
    let event = dm_device(minor, &dev.name);
    drop(state);
    super::uevent::emit("change", &event, &[]);
    Ok(())
}

fn find_dm(state: &State, buf: &[u8]) -> Result<u32, Errno> {
    let name = ioctl_name(buf)?;
    if !name.is_empty() {
        return state.names.get(&name).copied().ok_or(ENXIO);
    }
    let dev = u64_at(buf, 40);
    let major = ((dev >> 8) & 0xfff) as u32;
    let minor = ((dev & 0xff) | ((dev >> 12) & 0xffffff00)) as u32;
    if major != DM_MAJOR || !state.dms.contains_key(&minor) {
        return Err(ENXIO);
    }
    Ok(minor)
}

fn ioctl_name(buf: &[u8]) -> Result<String, Errno> {
    if buf.len() < 176 {
        return Err(EINVAL);
    }
    Ok(c_string(&buf[48..176]))
}

fn ioctl_uuid(buf: &[u8]) -> String {
    if buf.len() < 305 {
        return String::new();
    }
    c_string(&buf[176..305])
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn write_name(buf: &mut [u8], at: usize, len: usize, text: &str) {
    buf[at..at + len].fill(0);
    let n = text.len().min(len - 1);
    buf[at..at + n].copy_from_slice(&text.as_bytes()[..n]);
}

fn put_version(buf: &mut [u8]) {
    put_u32(buf, 0, 4);
    put_u32(buf, 4, 0);
    put_u32(buf, 8, 0);
}

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}
fn u64_at(buf: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(buf[at..at + 8].try_into().unwrap())
}

fn encode_dev(major: u32, minor: u32) -> u64 {
    let minor = minor as u64;
    let major = major as u64;
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

fn blk_nr(req: u64) -> Option<u8> {
    ((req >> 8) & 0xff == 0x12).then_some((req & 0xff) as u8)
}
/// `_IOWR(0xfd, nr, struct dm_ioctl)` with `sizeof(struct dm_ioctl) == 312`.
/// The observed Mac requests are `0xc138fd03` and `0xc138fd07`.
fn dm_cmd(req: u64) -> Option<u8> {
    let dir = req >> 30;
    let size = (req >> 16) & 0x3fff;
    let typ = (req >> 8) & 0xff;
    (dir == 3 && size == 0x138 && typ == 0xfd).then_some((req & 0xff) as u8)
}

fn loop_minor(path: &str) -> Option<u32> {
    path.rsplit('/')
        .next()?
        .strip_prefix("loop")?
        .parse()
        .ok()
}

enum Look {
    Control,
    Loop(u32),
    Mapper,
    Dm(u32),
    Uuid(String),
}

fn classify(guest: &str) -> Option<Look> {
    match guest {
        "/dev/loop-control" => Some(Look::Control),
        "/dev/device-mapper" | "/dev/mapper/control" => Some(Look::Mapper),
        other => {
            if let Some(n) = other
                .strip_prefix("/dev/block/loop")
                .or_else(|| other.strip_prefix("/dev/loop"))
            {
                return n.parse().ok().map(Look::Loop);
            }
            if let Some(n) = other.strip_prefix("/dev/block/dm-") {
                return n.parse().ok().map(Look::Dm);
            }
            other
                .strip_prefix("/dev/block/mapper/by-uuid/")
                .filter(|u| !u.is_empty() && !u.contains('/'))
                .map(|u| Look::Uuid(u.to_string()))
        }
    }
}

fn resolve(state: &State, look: Look) -> Result<Kind, Errno> {
    Ok(match look {
        Look::Control => Kind::Control,
        Look::Mapper => Kind::Mapper,
        Look::Loop(minor) if state.loops.contains_key(&minor) => Kind::Loop(minor),
        Look::Dm(minor) if state.dms.contains_key(&minor) => Kind::Dm(minor),
        Look::Uuid(uuid) => {
            let minor = state
                .dms
                .iter()
                .find(|(_, dev)| dev.uuid == uuid)
                .map(|(m, _)| *m)
                .ok_or(ENXIO)?;
            Kind::Dm(minor)
        }
        Look::Loop(_) | Look::Dm(_) => return Err(ENXIO),
    })
}

/// `/dev/block` and the mapper uuid directory. They are not host
/// directories. A walk still has to see them as directories so
/// `/dev/block/loopN` and `/dev/block/dm-N` resolve.
fn block_dir_stat(guest: &str) -> Option<libc::stat> {
    let ino = match guest {
        "/dev/block" => 0x10,
        "/dev/block/mapper" => 0x11,
        "/dev/block/mapper/by-uuid" => 0x12,
        _ => return None,
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    st.st_mode = libc::S_IFDIR | 0o755;
    st.st_nlink = 2;
    st.st_ino = ino;
    st.st_blksize = 4096;
    Some(st)
}

fn stat_of(state: &State, kind: Kind) -> libc::stat {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    st.st_nlink = 1;
    st.st_blksize = 4096;
    match kind {
        Kind::Control => {
            st.st_mode = libc::S_IFCHR | 0o660;
            st.st_rdev = ((MISC_MAJOR << 24) | LOOP_CONTROL_MINOR) as _;
            st.st_ino = 1;
        }
        Kind::Mapper => {
            st.st_mode = libc::S_IFCHR | 0o660;
            st.st_rdev = ((MISC_MAJOR << 24) | DM_CONTROL_MINOR) as _;
            st.st_ino = 2;
        }
        Kind::Loop(minor) => {
            st.st_mode = libc::S_IFBLK | 0o660;
            st.st_rdev = ((LOOP_MAJOR << 24) | minor) as _;
            st.st_ino = 0x1000 + u64::from(minor);
            st.st_size = device_len(state, kind).unwrap_or(0) as _;
        }
        Kind::Dm(minor) => {
            st.st_mode = libc::S_IFBLK | 0o660;
            st.st_rdev = ((DM_MAJOR << 24) | minor) as _;
            st.st_ino = 0x2000 + u64::from(minor);
            st.st_size = device_len(state, kind).unwrap_or(0) as _;
        }
    }
    st
}

fn read_fd(fd: i32, buf: u64, len: usize, pos: Option<i64>) -> Result<i64, Errno> {
    if len == 0 {
        return Ok(0);
    }
    let dev = recorded(fd).ok_or(EBADF)?;
    let kind = kind_of(dev.major, dev.minor).ok_or(EBADF)?;
    let at = match pos {
        Some(p) if p < 0 => return Err(EINVAL),
        Some(p) => p as u64,
        None => *dev.pos.lock().unwrap_or_else(|error| error.into_inner()),
    };
    let state = lock();
    let len_dev = device_len(&state, kind).ok_or(ENXIO)?;
    if at >= len_dev {
        return Ok(0);
    }
    let take = ((len_dev - at) as usize).min(len);
    let io = match kind {
        Kind::Loop(minor) => loop_io(&state, minor).map(Io::Loop)?,
        Kind::Dm(minor) => {
            let dev = state.dms.get(&minor).ok_or(ENXIO)?;
            match dev.live.clone() {
                Some(Target::Verity(table)) => {
                    let loop_minor = loop_minor(&table.data_device).ok_or(EINVAL)?;
                    Io::Verity(super::dmverity::Verified::new(loop_io(&state, loop_minor)?, table))
                }
                _ => return Err(EIO),
            }
        }
        Kind::Control | Kind::Mapper => return Err(EINVAL),
    };
    drop(state);
    let mut tmp = vec![0u8; take];
    match &io {
        Io::Loop(fd) => fd.read_exact_at(at, &mut tmp)?,
        Io::Verity(v) => v.read_exact_at(at, &mut tmp)?,
    }
    super::user_memory::write_exact(buf, &tmp)?;
    if pos.is_none() {
        *dev.pos.lock().unwrap_or_else(|error| error.into_inner()) = at + take as u64;
    }
    Ok(take as i64)
}

enum Io {
    Loop(FdAt),
    Verity(super::dmverity::Verified<FdAt>),
}

fn pread_full(fd: i32, mut at: u64, buf: &mut [u8]) -> Result<(), Errno> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = unsafe {
            libc::pread(
                fd,
                buf[filled..].as_mut_ptr().cast(),
                buf.len() - filled,
                at as i64,
            )
        };
        if n < 0 {
            let error = errno::last();
            if error == errno::EINTR {
                continue;
            }
            return Err(error);
        }
        if n == 0 {
            return Err(EIO);
        }
        filled += n as usize;
        at += n as u64;
    }
    Ok(())
}

pub fn sys_node(rest: &str) -> Option<Node> {
    let mut state = lock();
    ensure(&mut state);
    if rest == "block" || rest == "devices/virtual/block" || rest == "class/block" {
        let mut names: Vec<String> = state.loops.keys().map(|m| format!("loop{m}")).collect();
        names.extend(state.dms.keys().map(|m| format!("dm-{m}")));
        return Some(dir_list(names, dir::DT_DIR));
    }
    if rest == "class/misc" || rest == "devices/virtual/misc" {
        return Some(dir_list(vec!["loop-control".into()], dir::DT_DIR));
    }
    if rest == "dev/block" {
        let mut names: Vec<String> = state.loops.keys().map(|m| format!("{LOOP_MAJOR}:{m}")).collect();
        names.extend(state.dms.keys().map(|m| format!("{DM_MAJOR}:{m}")));
        return Some(dir_list(names, dir::DT_LNK));
    }
    if rest == "class/misc/loop-control" || rest == "devices/virtual/misc/loop-control" {
        return Some(dir_list(vec!["dev".into(), "uevent".into()], dir::DT_REG));
    }
    if rest == "class/misc/loop-control/dev" || rest == "devices/virtual/misc/loop-control/dev" {
        return Some(Node::File(format!("{MISC_MAJOR}:{LOOP_CONTROL_MINOR}\n").into_bytes()));
    }
    if rest == "class/misc/loop-control/uevent" || rest == "devices/virtual/misc/loop-control/uevent"
    {
        return Some(Node::File(control_device().attribute()));
    }
    if let Some(rest) = rest.strip_prefix("dev/block/") {
        return dev_link(&state, rest).or_else(|| volume_link(rest));
    }
    if let Some(node) = volume_node(rest) {
        return Some(node);
    }
    if rest == "dev/char/10:237" {
        return Some(Node::Link("/sys/devices/virtual/misc/loop-control".into()));
    }
    let (name, tail) = block_tail(rest)?;
    let which = device_which(&state, name)?;
    block_node(&state, &which, tail)
}

fn block_tail(rest: &str) -> Option<(&str, &str)> {
    let rest = rest
        .strip_prefix("devices/virtual/block/")
        .or_else(|| rest.strip_prefix("class/block/"))
        .or_else(|| rest.strip_prefix("block/"))?;
    Some(rest.split_once('/').unwrap_or((rest, "")))
}

fn device_which(state: &State, name: &str) -> Option<Which> {
    if let Some(n) = name.strip_prefix("loop") {
        let minor = n.parse().ok()?;
        state.loops.contains_key(&minor).then_some(Which::Loop(minor))
    } else if let Some(n) = name.strip_prefix("dm-") {
        let minor = n.parse().ok()?;
        state.dms.contains_key(&minor).then_some(Which::Dm(minor))
    } else {
        None
    }
}

fn block_node(state: &State, which: &Which, tail: &str) -> Option<Node> {
    let bound = match which {
        Which::Loop(minor) => state.loops.get(minor).is_some_and(|d| d.backing.is_some()),
        Which::Dm(_) => true,
    };
    Some(match tail {
        "" => {
            let mut entries = vec![
                Entry::new(1, dir::DT_DIR, "queue".to_string()),
                Entry::new(1, dir::DT_REG, "uevent".to_string()),
                Entry::new(1, dir::DT_REG, "dev".to_string()),
            ];
            if bound && matches!(which, Which::Loop(_)) {
                entries.push(Entry::new(1, dir::DT_DIR, "loop".to_string()));
            }
            Node::Dir(entries)
        }
        "queue" => dir_list(
            vec!["scheduler".into(), "nr_requests".into(), "read_ahead_kb".into()],
            dir::DT_REG,
        ),
        "queue/scheduler" => Node::File(format!("{}\n", queue(state, which).0).into_bytes()),
        "queue/nr_requests" => Node::File(format!("{}\n", queue(state, which).1).into_bytes()),
        "queue/read_ahead_kb" => Node::File(format!("{}\n", queue(state, which).2).into_bytes()),
        "dev" => Node::File(dev_text(which).into_bytes()),
        "uevent" => Node::File(block_uevent(which).attribute()),
        "loop" if bound => dir_list(Vec::new(), dir::DT_DIR),
        _ => return None,
    })
}

fn queue(state: &State, which: &Which) -> (String, u32, u32) {
    match which {
        Which::Loop(minor) => state
            .loops
            .get(minor)
            .map(|d| (d.scheduler.clone(), d.nr_requests, d.read_ahead_kb))
            .unwrap_or(("none".into(), 128, 128)),
        Which::Dm(minor) => state
            .dms
            .get(minor)
            .map(|d| (d.scheduler.clone(), d.nr_requests, d.read_ahead_kb))
            .unwrap_or(("none".into(), 128, 128)),
    }
}

fn dev_text(which: &Which) -> String {
    match which {
        Which::Loop(minor) => format!("{LOOP_MAJOR}:{minor}\n"),
        Which::Dm(minor) => format!("{DM_MAJOR}:{minor}\n"),
    }
}

/// `stat` of a file on the image volume. apexd's queue-depth walk
/// `readlink`s `/sys/dev/block/<major>:<minor>` of that `st_dev`. On the
/// Mac archive that pair was `1:24`.
fn volume_id() -> Option<(u32, u32)> {
    let root = vfs::root();
    let path = CString::new(root.as_os_str().as_bytes()).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let d = st.st_dev as u32 as u64;
    let major = (d >> 24) as u32;
    let minor = (d & 0xff_ffff) as u32;
    Some((major, minor))
}

fn volume_link(rest: &str) -> Option<Node> {
    let (major, minor) = rest.split_once(':')?;
    let major: u32 = major.parse().ok()?;
    let minor: u32 = minor.parse().ok()?;
    let (have_major, have_minor) = volume_id()?;
    (major == have_major && minor == have_minor)
        .then(|| Node::Link("/sys/devices/virtual/block/vd0".into()))
}

fn volume_node(rest: &str) -> Option<Node> {
    let tail = rest
        .strip_prefix("devices/virtual/block/vd0")
        .or_else(|| rest.strip_prefix("class/block/vd0"))
        .or_else(|| rest.strip_prefix("block/vd0"))?;
    let tail = tail.strip_prefix('/').unwrap_or(tail);
    let (major, minor) = volume_id()?;
    Some(match tail {
        "" => dir_list(
            vec!["dev".into(), "uevent".into(), "mq".into(), "queue".into()],
            dir::DT_DIR,
        ),
        "dev" => Node::File(format!("{major}:{minor}\n").into_bytes()),
        "uevent" => Node::File(
            format!("MAJOR={major}\nMINOR={minor}\nDEVNAME=block/vd0\n").into_bytes(),
        ),
        "mq" => dir_list(vec!["0".into()], dir::DT_DIR),
        "mq/0" => dir_list(vec!["nr_tags".into()], dir::DT_REG),
        "mq/0/nr_tags" | "queue/nr_requests" => Node::File(b"128\n".to_vec()),
        _ => return None,
    })
}

fn dev_link(state: &State, rest: &str) -> Option<Node> {
    let (major, minor) = rest.split_once(':')?;
    let major: u32 = major.parse().ok()?;
    let minor: u32 = minor.parse().ok()?;
    let path = if major == LOOP_MAJOR && state.loops.contains_key(&minor) {
        format!("/sys/devices/virtual/block/loop{minor}")
    } else if major == DM_MAJOR && state.dms.contains_key(&minor) {
        format!("/sys/devices/virtual/block/dm-{minor}")
    } else {
        return None;
    };
    Some(Node::Link(path))
}

fn dir_list(names: Vec<String>, ty: u8) -> Node {
    Node::Dir(names.into_iter().map(|n| Entry::new(1, ty, n)).collect())
}

/// A writable queue file. The fd is a knob, so a write changes the value
/// instead of being refused as a device-tree attribute.
pub fn open_sysfs(guest: &str, flags: u64) -> Option<i64> {
    let (which, attr) = queue_file(guest)?;
    let text = {
        let mut state = lock();
        ensure(&mut state);
        if device_which(&state, &which).is_none() {
            return Some(-(ENODEV as i64));
        }
        let key = device_which(&state, &which).unwrap();
        match attr {
            "scheduler" => format!("{}\n", queue(&state, &key).0),
            "nr_requests" => format!("{}\n", queue(&state, &key).1),
            "read_ahead_kb" => format!("{}\n", queue(&state, &key).2),
            _ => return None,
        }
    };
    let cloexec = flags & O_CLOEXEC != 0;
    Some(super::knob::open(
        text.as_bytes(),
        cloexec,
        super::knob::Knob::LoopQueue(guest.to_string()),
    ))
}

pub fn queue_attr(guest: &str) -> bool {
    queue_file(guest).is_some()
}

pub fn write_queue(path: &str, bytes: &[u8]) -> Result<(), Errno> {
    let (name, attr) = queue_file(path).ok_or(ENODEV)?;
    let text = std::str::from_utf8(bytes).map_err(|_| EINVAL)?.trim();
    let mut state = lock();
    let which = device_which(&state, &name).ok_or(ENODEV)?;
    match attr {
        "scheduler" => {
            if text != "none" && text != "noop" {
                return Err(EINVAL);
            }
            match which {
                Which::Loop(minor) => state.loops.get_mut(&minor).ok_or(ENODEV)?.scheduler = text.into(),
                Which::Dm(minor) => state.dms.get_mut(&minor).ok_or(ENODEV)?.scheduler = text.into(),
            }
        }
        "nr_requests" | "read_ahead_kb" => {
            let n: u32 = text.parse().map_err(|_| EINVAL)?;
            if n == 0 {
                return Err(EINVAL);
            }
            match (attr, which) {
                ("nr_requests", Which::Loop(minor)) => {
                    state.loops.get_mut(&minor).ok_or(ENODEV)?.nr_requests = n
                }
                ("read_ahead_kb", Which::Loop(minor)) => {
                    state.loops.get_mut(&minor).ok_or(ENODEV)?.read_ahead_kb = n
                }
                ("nr_requests", Which::Dm(minor)) => {
                    state.dms.get_mut(&minor).ok_or(ENODEV)?.nr_requests = n
                }
                ("read_ahead_kb", Which::Dm(minor)) => {
                    state.dms.get_mut(&minor).ok_or(ENODEV)?.read_ahead_kb = n
                }
                _ => return Err(EINVAL),
            }
        }
        _ => return Err(EINVAL),
    }
    Ok(())
}

fn queue_file(guest: &str) -> Option<(String, &'static str)> {
    let rest = guest.strip_prefix("/sys/")?;
    let rest = rest
        .strip_prefix("devices/virtual/block/")
        .or_else(|| rest.strip_prefix("class/block/"))
        .or_else(|| rest.strip_prefix("block/"))?;
    let (dev, tail) = rest.split_once("/queue/")?;
    let attr = match tail {
        "scheduler" => "scheduler",
        "nr_requests" => "nr_requests",
        "read_ahead_kb" => "read_ahead_kb",
        _ => return None,
    };
    Some((dev.to_string(), attr))
}

pub fn uevent_device(devpath: &str) -> Option<Device> {
    let path = devpath.strip_prefix("/sys").unwrap_or(devpath);
    if path == "/devices/virtual/misc/loop-control" || path == "/class/misc/loop-control" {
        return Some(control_device());
    }
    let rest = path.trim_start_matches('/');
    let (name, tail) = block_tail(rest).or_else(|| {
        rest.strip_prefix("devices/virtual/block/")
            .or_else(|| rest.strip_prefix("block/"))
            .map(|r| r.split_once('/').unwrap_or((r, "")))
    })?;
    if !tail.is_empty() && tail != "uevent" {
        return None;
    }
    let state = lock();
    let which = device_which(&state, name)?;
    Some(block_uevent(&which))
}

pub fn char_dev_names() -> Vec<String> {
    vec![format!("{MISC_MAJOR}:{LOOP_CONTROL_MINOR}")]
}

fn control_device() -> Device {
    Device {
        devpath: "/devices/virtual/misc/loop-control".into(),
        subsystem: "misc".into(),
        env: vec![
            format!("MAJOR={MISC_MAJOR}"),
            format!("MINOR={LOOP_CONTROL_MINOR}"),
            "DEVNAME=loop-control".into(),
        ],
    }
}

fn loop_device(minor: u32) -> Device {
    block_uevent(&Which::Loop(minor))
}

fn dm_device(minor: u32, name: &str) -> Device {
    let mut dev = block_uevent(&Which::Dm(minor));
    dev.env.push(format!("DM_NAME={name}"));
    dev
}

fn block_uevent(which: &Which) -> Device {
    let (minor, name, major) = match which {
        Which::Loop(minor) => (*minor, format!("loop{minor}"), LOOP_MAJOR),
        Which::Dm(minor) => (*minor, format!("dm-{minor}"), DM_MAJOR),
    };
    Device {
        devpath: format!("/devices/virtual/block/{name}"),
        subsystem: "block".into(),
        env: vec![
            format!("MAJOR={major}"),
            format!("MINOR={minor}"),
            format!("DEVNAME=block/{name}"),
        ],
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStrExt;

    use super::*;

    fn gate() -> std::sync::MutexGuard<'static, ()> {
        static GATE: Mutex<()> = Mutex::new(());
        GATE.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn configure_at_an_offset_reads_the_runtime_manifest() {
        let _gate = gate();
        let (image, manifest) = super::super::ext4ro::manifest_fixture();
        let dir = std::env::temp_dir().join(format!("aim-loop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.img");
        let mut file = vec![0u8; 4096];
        file.extend_from_slice(&image);
        fs::write(&path, &file).unwrap();
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        let err = configure_checked(7, -1, 4096, &[0; 232]).unwrap_err();
        assert_eq!(err, EBADF);
        let mut info = [0u8; 232];
        info[24..32].copy_from_slice(&4096u64.to_le_bytes());
        info[32..40].copy_from_slice(&(image.len() as u64).to_le_bytes());
        info[52..56].copy_from_slice(&LO_FLAGS_AUTOCLEAR.to_le_bytes());
        info[120..125].copy_from_slice(b"apex:");
        configure(7, fd, 4096, &info).unwrap();
        unsafe { libc::close(fd) };
        let host = materialize("/dev/block/loop7").unwrap();
        let got = fs::read(host.join("apex_manifest.pb")).unwrap();
        assert_eq!(got, manifest);
        clr_fd(7).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&host);
    }

    /// A directory that already holds a mounted tree is not the next
    /// payload's host. Two processes both start their counter at 1; reusing
    /// `apex-mounts/1` deleted `linker64` while a mount still named it.
    #[test]
    fn a_later_host_does_not_reuse_a_mounted_ext4_directory() {
        let _gate = gate();
        let (_view, root) = crate::vfs::test_view();
        let base = root.join("apex-mounts");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let pid = std::process::id();
        let mut planted = Vec::new();
        for n in 1..=128 {
            let dir = base.join(format!("{pid}-{n}"));
            fs::create_dir_all(dir.join("bin")).unwrap();
            fs::write(dir.join("bin/linker64"), b"already-mounted").unwrap();
            planted.push(dir);
            let legacy = base.join(n.to_string());
            fs::create_dir_all(legacy.join("bin")).unwrap();
            fs::write(legacy.join("bin/linker64"), b"legacy-mounted").unwrap();
            planted.push(legacy);
        }
        let host = fresh_dir().unwrap();
        assert!(
            host.file_name().and_then(|name| name.to_str()).is_some_and(|name| {
                name.starts_with(&format!("{pid}-"))
            }),
            "host {}",
            host.display()
        );
        assert!(
            fs::read_dir(&host).unwrap().next().is_none(),
            "reused {}",
            host.display()
        );
        for dir in &planted {
            let bytes = fs::read(dir.join("bin/linker64")).unwrap_or_default();
            assert!(
                bytes == b"already-mounted" || bytes == b"legacy-mounted",
                "wiped {} ({})",
                dir.display(),
                String::from_utf8_lossy(&bytes)
            );
        }
        let _ = fs::remove_dir_all(&host);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn free_add_and_an_unknown_ioctl_is_enotty() {
        let _gate = gate();
        let fd = open("/dev/loop-control", O_CLOEXEC).unwrap();
        assert!(fd >= 0);
        let free = ioctl(fd as i32, LOOP_CTL_GET_FREE, 0).unwrap();
        assert!(free >= 0);
        let added = ctl_add(40).unwrap();
        assert_eq!(added, 40);
        assert_eq!(ctl_add(40).unwrap_err(), EEXIST);
        // Id 0 is one of the eight preallocated devices. Linux returns
        // EEXIST, and apexd treats a zero return as failure.
        assert_eq!(ctl_add(0).unwrap_err(), EEXIST);
        assert_eq!(ioctl(fd as i32, 0x4cff, 0).unwrap(), -(ENOTTY as i64));
        ctl_remove(40).unwrap();
        super::super::fdtab::on_close(fd as i32);
        unsafe { libc::close(fd as i32) };
    }

    /// apexd's order, through `fs::openat` and `fs::ioctl` (syscall 29).
    #[test]
    fn apexd_ioctls_go_through_the_syscall_dispatcher() {
        let _gate = gate();
        let dm = guest_open("/dev/device-mapper");
        assert!(dm >= 0, "{dm}");
        assert_eq!(guest_rdev(dm as i32), linux_rdev(10, 236));
        assert_eq!(path_rdev("/dev/device-mapper"), linux_rdev(10, 236));
        let mut version = dm_header("");
        let rc = guest_ioctl(dm as i32, 0xc138_fd00, version.as_mut_ptr() as u64);
        assert_eq!(rc, 0, "{rc}");
        assert_eq!(u32::from_le_bytes(version[0..4].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(version[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(version[8..12].try_into().unwrap()), 0);
        // A sign-extended request is the same command.
        let mut again = dm_header("");
        assert_eq!(
            guest_ioctl(dm as i32, 0xffff_ffff_c138_fd00, again.as_mut_ptr() as u64),
            0
        );
        // The size field is part of the command. 0x139 is not struct dm_ioctl.
        assert_eq!(guest_ioctl(dm as i32, 0xc139_fd00, version.as_mut_ptr() as u64), -(ENOTTY as i64));

        let ctl = guest_open("/dev/loop-control");
        assert!(ctl >= 0, "{ctl}");
        assert_eq!(guest_rdev(ctl as i32), linux_rdev(10, 237));
        assert_eq!(path_rdev("/dev/loop-control"), linux_rdev(10, 237));
        // Device-mapper commands stay on 10:236.
        assert_eq!(
            guest_ioctl(ctl as i32, 0xc138_fd00, version.as_mut_ptr() as u64),
            -(ENOTTY as i64)
        );
        let free = guest_ioctl(ctl as i32, 0x4c82, 0);
        assert!(free >= 0, "{free}");
        assert_eq!(guest_ioctl(ctl as i32, 0x4c80, 0), -(EEXIST as i64));
        // Loop-control commands stay on 10:237.
        assert_eq!(guest_ioctl(dm as i32, 0x4c82, 0), -(ENOTTY as i64));

        let node = format!("/dev/loop{free}");
        let loop_fd = guest_open(&node);
        assert!(loop_fd >= 0, "{loop_fd}");
        assert_eq!(guest_rdev(loop_fd as i32), linux_rdev(7, free as u32));
        assert_eq!(path_rdev(&node), linux_rdev(7, free as u32));
        let dir = std::env::temp_dir().join(format!("aim-dispatch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload");
        fs::write(&path, vec![0x11u8; 4096]).unwrap();
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        let backing = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(backing >= 0);
        let mut cfg = [0u8; 240];
        cfg[0..4].copy_from_slice(&(backing as u32).to_le_bytes());
        cfg[4..8].copy_from_slice(&4096u32.to_le_bytes());
        cfg[8 + 32..8 + 40].copy_from_slice(&4096u64.to_le_bytes());
        assert_eq!(guest_ioctl(loop_fd as i32, 0x4c0a, cfg.as_ptr() as u64), 0);
        unsafe { libc::close(backing) };

        let name = "aim-dispatch";
        let mut create = dm_header(name);
        assert_eq!(guest_ioctl(dm as i32, 0xc138_fd03, create.as_mut_ptr() as u64), 0);
        assert_eq!(u32::from_le_bytes(create[0..4].try_into().unwrap()), 4);
        let mut load = vec![0u8; 312 + 48];
        load[..312].copy_from_slice(&dm_header(name));
        let load_len = load.len() as u32;
        put_u32(&mut load, 12, load_len);
        put_u32(&mut load, 16, 312);
        put_u32(&mut load, 20, 1);
        put_u32(&mut load, 312 + 20, 48);
        load[312 + 24..312 + 29].copy_from_slice(b"error");
        assert_eq!(guest_ioctl(dm as i32, 0xc138_fd09, load.as_mut_ptr() as u64), 0);
        let mut resume = dm_header(name);
        assert_eq!(guest_ioctl(dm as i32, 0xc138_fd06, resume.as_mut_ptr() as u64), 0);
        let mut status = dm_header(name);
        assert_eq!(guest_ioctl(dm as i32, 0xc138_fd07, status.as_mut_ptr() as u64), 0);
        assert_eq!(u32::from_le_bytes(status[20..24].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(status[28..32].try_into().unwrap()) & 2, 0);

        let mut rm = dm_header(name);
        assert_eq!(guest_ioctl(dm as i32, 0xc138_fd04, rm.as_mut_ptr() as u64), 0);
        clr_fd(free as u32).unwrap();
        let _ = fs::remove_dir_all(&dir);
        for fd in [loop_fd, ctl, dm] {
            assert_eq!(super::super::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
    }

    #[test]
    fn a_mounted_tree_ignores_a_later_change_to_the_host_file() {
        let _gate = gate();
        let (_view, _) = crate::vfs::test_view();
        let (image, manifest) = super::super::ext4ro::manifest_fixture();
        let dir = std::env::temp_dir().join(format!("aim-tamper-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.img");
        fs::write(&path, &image).unwrap();
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        let minor = ctl_free().unwrap() as u32;
        configure(minor, fd, 4096, &[0; 232]).unwrap();
        unsafe { libc::close(fd) };
        let guest = "/aim-tamper-mount";
        mount_ext4(&format!("/dev/block/loop{minor}"), guest, true).unwrap();
        let got = guest_read(&format!("{guest}/apex_manifest.pb"));
        assert_eq!(got, manifest);
        fs::write(&path, vec![0u8; image.len()]).unwrap();
        let again = guest_read(&format!("{guest}/apex_manifest.pb"));
        assert_eq!(again, manifest);
        crate::vfs::remove_mount(guest).unwrap();
        clr_fd(minor).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    fn guest_open(path: &str) -> i64 {
        let c = CString::new(path).unwrap();
        super::super::fs::openat([
            crate::vfs::LINUX_AT_FDCWD as u64,
            c.as_ptr() as u64,
            2 | O_CLOEXEC,
            0,
            0,
            0,
        ])
    }

    fn guest_ioctl(fd: i32, req: u64, arg: u64) -> i64 {
        super::super::fs::ioctl([fd as u64, req, arg, 0, 0, 0])
    }

    fn guest_rdev(fd: i32) -> u64 {
        let mut buf = vec![0u8; 128];
        let rc = super::super::fs::fstat([fd as u64, buf.as_mut_ptr() as u64, 0, 0, 0, 0]);
        assert_eq!(rc, 0, "{rc}");
        u64::from_le_bytes(buf[32..40].try_into().unwrap())
    }

    fn path_rdev(path: &str) -> u64 {
        let c = CString::new(path).unwrap();
        let mut buf = vec![0u8; 128];
        let rc = super::super::fs::newfstatat([
            crate::vfs::LINUX_AT_FDCWD as u64,
            c.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            0,
            0,
            0,
        ]);
        assert_eq!(rc, 0, "{rc}");
        u64::from_le_bytes(buf[32..40].try_into().unwrap())
    }

    fn linux_rdev(major: u32, minor: u32) -> u64 {
        let (major, minor) = (u64::from(major), u64::from(minor));
        (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12)
    }

    fn dm_header(name: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 312];
        put_u32(&mut buf, 0, 4);
        put_u32(&mut buf, 12, 312);
        write_name(&mut buf, 48, 128, name);
        buf
    }

    fn guest_read(path: &str) -> Vec<u8> {
        let c = CString::new(path).unwrap();
        let fd = super::super::fs::openat([
            crate::vfs::LINUX_AT_FDCWD as u64,
            c.as_ptr() as u64,
            0,
            0,
            0,
            0,
        ]);
        assert!(fd >= 0, "{fd}");
        let mut buf = vec![0u8; 4096];
        let n = super::super::fs::read([
            fd as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
        ]);
        assert!(n >= 0, "{n}");
        assert_eq!(super::super::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        buf.truncate(n as usize);
        buf
    }

    #[test]
    fn verity_read_of_a_dm_device_fails_when_a_byte_changes() {
        let _gate = gate();
        let block = vec![0x5au8; 4096];
        let (image, table) = super::super::dmverity::seal(std::slice::from_ref(&block), b"salt");
        let dir = std::env::temp_dir().join(format!("aim-verity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("image");
        fs::write(&path, &image).unwrap();
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        configure(6, fd, 4096, &[0; 232]).unwrap();
        unsafe { libc::close(fd) };
        let mut buf = vec![0u8; 312];
        write_name(&mut buf, 48, 128, "apex-verity");
        put_u32(&mut buf, 12, 312);
        dm_create(&mut buf).unwrap();
        let dm_minor = (u64_at(&buf, 40) & 0xff) as u32;
        let dm_path = format!("/dev/block/dm-{dm_minor}");
        let params = format!(
            "1 /dev/loop6 /dev/loop6 4096 4096 {} {} sha256 {} {}",
            table.num_data_blocks,
            table.hash_start_block,
            hex(&table.root_digest),
            hex(&table.salt),
        );
        let mut load = vec![0u8; 312 + 40 + params.len() + 8];
        write_name(&mut load, 48, 128, "apex-verity");
        let load_len = load.len() as u32;
        put_u32(&mut load, 12, load_len);
        put_u32(&mut load, 16, 312);
        put_u32(&mut load, 20, 1);
        put_u32(&mut load, 28, DM_READONLY);
        let spec = 312;
        put_u64(&mut load, spec, 0);
        put_u64(&mut load, spec + 8, table.data_len() / 512);
        put_u32(&mut load, spec + 20, (40 + params.len() + 1).next_multiple_of(8) as u32);
        load[spec + 24..spec + 30].copy_from_slice(b"verity");
        load[spec + 40..spec + 40 + params.len()].copy_from_slice(params.as_bytes());
        dm_load(&mut load).unwrap();
        let mut resume = vec![0u8; 312];
        write_name(&mut resume, 48, 128, "apex-verity");
        put_u32(&mut resume, 12, 312);
        dm_suspend(&mut resume).unwrap();
        let mut got = [0u8; 4];
        read_dev(&dm_path, 0, &mut got).unwrap();
        assert_eq!(got, [0x5a; 4]);
        let mut raw = fs::read(&path).unwrap();
        raw[0] ^= 0xff;
        fs::write(&path, &raw).unwrap();
        assert_eq!(read_dev(&dm_path, 0, &mut got).unwrap_err(), EIO);
        clr_fd(6).unwrap();
        let mut rm = vec![0u8; 312];
        write_name(&mut rm, 48, 128, "apex-verity");
        put_u32(&mut rm, 12, 312);
        dm_remove(&mut rm).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    fn read_dev(path: &str, at: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let mut state = lock();
        ensure(&mut state);
        let kind = resolve(&state, classify(path).unwrap())?;
        match kind {
            Kind::Dm(minor) => {
                let dev = state.dms.get(&minor).unwrap();
                let Target::Verity(table) = dev.live.clone().unwrap() else {
                    return Err(EIO);
                };
                let minor = loop_minor(&table.data_device).unwrap();
                let io = loop_io(&state, minor)?;
                drop(state);
                super::super::dmverity::Verified::new(io, table).read_exact_at(at, buf)
            }
            _ => Err(ENODEV),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_closed_backing_fd_is_ebadf_on_the_shared_table() {
        let _gate = gate();
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        unsafe { libc::close(fd) };
        assert_eq!(
            configure_checked(0, fd, 4096, &[0; 232]).unwrap_err(),
            EBADF
        );
    }

    #[test]
    fn an_added_loop_stays_visible_to_status_and_sysfs() {
        let _gate = gate();
        let (_view, _) = crate::vfs::test_view();
        assert_eq!(ctl_add(8).unwrap(), 8);
        {
            let mut state = lock();
            state.loops.remove(&8);
            state.dms.clear();
            state.names.clear();
        }
        match sys_node("dev/block/7:8") {
            Some(Node::Link(path)) => {
                assert_eq!(path, "/sys/devices/virtual/block/loop8");
            }
            _ => panic!("loop8 sysfs link"),
        }
        match sys_node("block/loop8/dev") {
            Some(Node::File(bytes)) => assert_eq!(bytes, b"7:8\n"),
            _ => panic!("loop8 dev"),
        }
        let mut created = vec![0u8; 312];
        write_name(&mut created, 48, 128, "shared-dm");
        put_u32(&mut created, 0, 4);
        put_u32(&mut created, 12, 312);
        dm_create(&mut created).unwrap();
        {
            let mut state = lock();
            state.dms.clear();
            state.names.clear();
        }
        let mut status = vec![0u8; 312];
        write_name(&mut status, 48, 128, "shared-dm");
        put_u32(&mut status, 0, 4);
        put_u32(&mut status, 12, 312);
        dm_status(&mut status).unwrap();
        dm_remove(&mut status).unwrap();
        ctl_remove(8).unwrap();
        let (major, minor) = volume_id().expect("image volume");
        match sys_node(&format!("dev/block/{major}:{minor}")) {
            Some(Node::Link(path)) => {
                assert_eq!(path, "/sys/devices/virtual/block/vd0");
            }
            _ => panic!("volume sysfs link"),
        }
        match sys_node("class/block/vd0/mq/0/nr_tags") {
            Some(Node::File(bytes)) => assert_eq!(bytes, b"128\n"),
            _ => panic!("volume queue depth"),
        }
    }

    #[test]
    fn mount_ext4_then_fork_does_not_return_host_enoent() {
        let _gate = gate();
        let (_view, _) = crate::vfs::test_view();
        let (image, manifest) = super::super::ext4ro::manifest_fixture();
        let dir = std::env::temp_dir().join(format!("aim-fork-mount-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.img");
        fs::write(&path, &image).unwrap();
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        let minor = ctl_free().unwrap() as u32;
        configure(minor, fd, 4096, &[0; 232]).unwrap();
        unsafe { libc::close(fd) };
        let guest = "/aim-fork-mount";
        mount_ext4(&format!("/dev/block/loop{minor}"), guest, true).unwrap();
        assert_eq!(guest_read(&format!("{guest}/apex_manifest.pb")), manifest);
        // A child without `CLONE_NEWNS` reloads the mount line. Dropping
        // the mount and loading that line brings the file back.
        let text = crate::vfs::own_mounts_text();
        let line = text
            .lines()
            .find(|line| line.contains(guest))
            .expect("mount line")
            .to_string();
        assert!(line.contains("ext4"), "{line}");
        crate::vfs::remove_mount(guest).unwrap();
        crate::vfs::load_own_mounts(&line).unwrap();
        assert_eq!(guest_read(&format!("{guest}/apex_manifest.pb")), manifest);
        super::super::pty_owner::with_owner_down(|| {
            super::super::pty_owner::inherit_child(1).unwrap();
        });
        // `clone` reports a host `posix_spawn` `ENOENT` as `EIO`. A live
        // guest fork needs the Darwin register frame, which this host has not.
        super::super::fork::spawn::repair_host_cwd(Some(std::path::Path::new("/")));
        assert_eq!(
            super::super::fork::spawn::map_spawn_errno(c"/no/such/linux-run", libc::ENOENT)
                .unwrap_err(),
            -(crate::errno::EIO as i64)
        );
        crate::vfs::remove_mount(guest).unwrap();
        clr_fd(minor).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}

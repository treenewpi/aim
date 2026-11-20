//! Original `getprop` and `setprop` against a file-backed property service.
//!
//! The servicemanager root still carries a generated
//! `servicemanager.ready=true` area. This root does not. The only value
//! written before a client connects is `ro.property_service.version=2`,
//! which is the protocol version init publishes. `servicemanager.ready`
//! appears only after an original `setprop` sends it on the socket.
//!
//! `system/bin/property-wait` is generated. It links the image libc and
//! calls `__system_property_wait_any`. Original `getprop` has no wait
//! flag. This is not a reDroid boot.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use aim_android_init::props::area::{AreaMemory, PA_SIZE};
use aim_android_init::props::areas::{PROPERTIES_SERIAL, PROPERTY_INFO};
use aim_android_init::props::protocol::{
    self, Decoded, PROP_ERROR_PERMISSION_DENIED, PROP_SUCCESS,
};
use aim_android_init::props::info::{DEFAULT_CONTEXT, DEFAULT_TYPE};
use aim_android_init::props::{
    build_trie, FutexWaker, PropertyAreas, PropertyService, Ucred, WakeTarget,
};

use super::manager::{copy_tree, require_arm64, resolve_lib};
use super::{
    guest_file, guest_root, read_elf, require_layer, set_mode, sha256_file, write_entry, ElfInfo,
    LINKER_SHA256,
};

/// Original `toolbox`. `getprop` and `setprop` are symlinks to it, and
/// `argv[0]` selects the applet.
pub const GETPROP_SHA256: &str =
    "f2233523a39537e741a0c728fb56abbb1c0c5bc8422ce623a84f12a0f52192e4";
pub const LIBBASE_SHA256: &str =
    "025a1c793543c73887e386d888aa3de247af4492ec53ca750a8c985b6ab8c865";
/// Generated `property-wait`. Not an image file.
pub const PROPERTY_WAIT_SHA256: &str =
    "3b87daaaa4a695ae72321641fc36320d0ad0e26d42068d4506a68072801a319d";

const PROPERTY_WAIT: &[u8] = include_bytes!("../probe/property-wait");
pub(crate) const READY: &str = "servicemanager.ready";
const VERSION: &str = "ro.property_service.version";
pub(crate) const SHELL: &str = "uid\t2000\ngid\t2000\nseclabel\tu:r:shell:s0\n";
/// The identity the android and libbinder commands already give the
/// original servicemanager. The integrated matrix uses the same text so
/// the property server records that peer, not a shell set.
pub(crate) const SERVICEMANAGER_IDENTITY: &str =
    "uid\t1000\ngid\t1000\ngroups\t1000 3009\nseclabel\tu:r:servicemanager:s0\n";

pub fn property_root() -> PathBuf {
    super::stage_dir()
        .parent()
        .expect("redroid stage")
        .join("redroid-16-property")
        .join("root")
}

/// The identity file `linux-run` publishes when it is its own pid-namespace
/// init. `new_table` names the directory `aim-pidns-<pid>` and the watcher
/// writes `posix-control-owner` there before the guest is loaded.
///
/// A directory this harness creates and passes as `--by-pid` is not that
/// table. Admission then opens a missing `posix-control-owner` and returns
/// errno 2 (`stage=standalone-owner`) before `getprop` runs. `linux-run` is
/// the lock holder when `aim-lock-holder` is not beside it; that sibling is
/// not what creates the owner file.
fn standalone_identity(pid: i32) -> PathBuf {
    std::env::temp_dir()
        .join(format!("aim-pidns-{pid}"))
        .join(pid.to_string())
}

/// Copy the audited bionic root and add the original property clients.
/// Does not write `servicemanager.ready`.
pub fn prepare_property() -> Result<PathBuf, String> {
    let layer = require_layer()?;
    let bionic = guest_root();
    let linker = guest_file(&bionic, super::LINKER_GUEST).map_err(|_| {
        format!(
            "bionic root {} has no linker64; run bionic-smoke --prepare first",
            bionic.display()
        )
    })?;
    if sha256_file(&linker)? != LINKER_SHA256 {
        return Err("bionic root linker64 is not the pinned file".into());
    }
    let root = property_root();
    if root.exists() {
        fs::remove_dir_all(&root).map_err(|e| format!("remove {}: {e}", root.display()))?;
    }
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    copy_tree(&bionic, &root)?;
    set_mode(&root, 0o755)?;
    extract_clients(&layer, &root)?;
    install_wait(&root)?;
    audit(&root)?;
    write_provenance(&root, &layer)?;
    println!(
        "bionic-smoke: original property root {} (staged, not executed)",
        root.display()
    );
    println!(
        "bionic-smoke: this root has no servicemanager.ready value; acceptance is a real Apple Silicon Mac"
    );
    Ok(root)
}

pub(crate) fn install_property_clients(layer: &Path, root: &Path) -> Result<(), String> {
    extract_clients(layer, root)
}

fn extract_clients(layer: &Path, root: &Path) -> Result<(), String> {
    let wanted = [
        "system/bin/toolbox",
        "system/bin/getprop",
        "system/bin/setprop",
        "system/lib64/libbase.so",
    ];
    let mut found = [false; 4];
    let file = File::open(layer).map_err(|e| format!("open {}: {e}", layer.display()))?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let entries = archive
        .entries()
        .map_err(|e| format!("read layer tar: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        let raw = entry
            .path()
            .map_err(|e| format!("tar path: {e}"))?
            .into_owned();
        let name = raw.to_string_lossy().trim_start_matches("./").to_string();
        let Some(index) = wanted.iter().position(|item| *item == name) else {
            continue;
        };
        found[index] = true;
        write_entry(&mut entry, &root.join(&name))?;
    }
    let missing: Vec<_> = wanted
        .iter()
        .zip(found.iter())
        .filter(|(_, ok)| !**ok)
        .map(|(name, _)| *name)
        .collect();
    if !missing.is_empty() {
        return Err(format!("layer is missing {missing:?}"));
    }
    for bin in ["system/bin/getprop", "system/bin/setprop", "system/bin/property-wait"] {
        let path = root.join(bin);
        if path.is_file() {
            let mode = fs::metadata(&path).map_err(|e| e.to_string())?.permissions().mode();
            if mode & 0o111 == 0 {
                set_mode(&path, mode | 0o755)?;
            }
        }
    }
    Ok(())
}

fn install_wait(root: &Path) -> Result<(), String> {
    let path = root.join("system/bin/property-wait");
    fs::write(&path, PROPERTY_WAIT).map_err(|e| format!("write {}: {e}", path.display()))?;
    set_mode(&path, 0o755)?;
    Ok(())
}

fn audit(root: &Path) -> Result<(), String> {
    check_hash(root, "system/bin/toolbox", GETPROP_SHA256)?;
    check_hash(root, "system/bin/getprop", GETPROP_SHA256)?;
    check_hash(root, "system/bin/setprop", GETPROP_SHA256)?;
    require_link(root, "system/bin/getprop", "toolbox")?;
    require_link(root, "system/bin/setprop", "toolbox")?;
    check_hash(root, "system/lib64/libbase.so", LIBBASE_SHA256)?;
    check_hash(root, "system/bin/property-wait", PROPERTY_WAIT_SHA256)?;
    for (rel, what) in [
        ("system/bin/toolbox", "toolbox"),
        ("system/bin/property-wait", "property-wait"),
        ("system/lib64/libbase.so", "libbase"),
    ] {
        let bytes = fs::read(root.join(rel)).map_err(|e| e.to_string())?;
        let info = read_elf(&bytes)?;
        require_arm64(&info, what)?;
        audit_needed(root, &info)?;
    }
    let wait = read_elf(PROPERTY_WAIT)?;
    if wait.interp.as_deref() != Some("/system/bin/linker64") {
        return Err(format!("property-wait interp {:?}", wait.interp));
    }
    if wait.needed != ["libc.so"] {
        return Err(format!("property-wait NEEDED {:?}", wait.needed));
    }
    let text = String::from_utf8_lossy(PROPERTY_WAIT);
    if text.contains(READY) || text.contains("servicemanager.ready=true") {
        return Err("property-wait contains a planted property name".into());
    }
    if root.join("dev/__properties__").exists() {
        return Err("property root must not contain a prebuilt property area".into());
    }
    Ok(())
}

fn audit_needed(root: &Path, info: &ElfInfo) -> Result<(), String> {
    for lib in &info.needed {
        let path = resolve_lib(root, lib)?;
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let nested = read_elf(&bytes)?;
        require_arm64(&nested, lib)?;
    }
    Ok(())
}

fn require_link(root: &Path, rel: &str, target: &str) -> Result<(), String> {
    let got = fs::read_link(root.join(rel)).map_err(|e| format!("readlink {rel}: {e}"))?;
    if got != Path::new(target) {
        return Err(format!("{rel} points at {}, not {target}", got.display()));
    }
    Ok(())
}

fn check_hash(root: &Path, rel: &str, expect: &str) -> Result<(), String> {
    let path = root.join(rel);
    let hash = sha256_file(&path)?;
    if hash != expect {
        return Err(format!("{} sha256 {hash} != {expect}", path.display()));
    }
    Ok(())
}

fn write_provenance(root: &Path, layer: &Path) -> Result<(), String> {
    let text = format!(
        "kind original-property-clients\n\
         layer {}\n\
         not_play_store true\n\
         not_redroid_boot true\n\
         original system/bin/toolbox\n\
         getprop_and_setprop_symlink_toolbox true\n\
         toolbox_sha256 {GETPROP_SHA256}\n\
         original system/lib64/libbase.so\n\
         libbase_sha256 {LIBBASE_SHA256}\n\
         generated system/bin/property-wait\n\
         property_wait_sha256 {PROPERTY_WAIT_SHA256}\n\
         property_wait_links_image_libc true\n\
         property_wait_is_not_an_original_image_file true\n\
         servicemanager_ready_not_seeded true\n\
         property_info_is_default_context_only true\n\
         ro_property_service_version_is_init_protocol_version true\n\
         acceptance_platform apple-silicon-macos-xnu\n\
         linux_stage_is_not_acceptance true\n\
         executed false\n",
        layer.display()
    );
    let path = root
        .parent()
        .ok_or("property root has no parent")?
        .join("provenance.txt");
    fs::write(path, text).map_err(|e| e.to_string())
}

struct MmapMem {
    base: *mut u8,
    len: usize,
}

// SAFETY: the mapping is owned by this value and is not aliased mutably.
unsafe impl Send for MmapMem {}

impl MmapMem {
    fn create(path: &Path) -> Result<Self, String> {
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("{} is not a C path", path.display()))?;
        // SAFETY: the fd is closed before return; the mapping outlives it.
        unsafe {
            let fd = libc::open(
                c_path.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o444,
            );
            if fd < 0 {
                return Err(format!("create {}: {}", path.display(), io_error()));
            }
            let mapped = (|| {
                if libc::ftruncate(fd, PA_SIZE as libc::off_t) != 0 {
                    return Err(format!("truncate {}: {}", path.display(), io_error()));
                }
                let base = libc::mmap(
                    std::ptr::null_mut(),
                    PA_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                );
                if base == libc::MAP_FAILED {
                    return Err(format!("mmap {}: {}", path.display(), io_error()));
                }
                Ok(Self {
                    base: base.cast(),
                    len: PA_SIZE,
                })
            })();
            libc::close(fd);
            mapped
        }
    }
}

impl Drop for MmapMem {
    fn drop(&mut self) {
        // SAFETY: mapped in create with this length.
        unsafe { libc::munmap(self.base.cast(), self.len) };
    }
}

// SAFETY: the mapping stays writable for the value's lifetime.
unsafe impl AreaMemory for MmapMem {
    fn base(&self) -> *mut u8 {
        self.base
    }
    fn len(&self) -> usize {
        self.len
    }
}

struct SharedWake {
    bases: HashMap<String, usize>,
}

impl FutexWaker for SharedWake {
    fn wake_all(&self, target: WakeTarget<'_>) {
        let Some(base) = self.bases.get(target.area) else {
            return;
        };
        let addr = base + target.offset;
        wake_shared(addr);
    }
}

fn wake_shared(addr: usize) {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr as *mut libc::c_void,
            libc::FUTEX_WAKE,
            i32::MAX,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0u32,
        );
    }
    #[cfg(target_os = "macos")]
    unsafe {
        const UL_COMPARE_AND_WAIT_SHARED: u32 = 3;
        const ULF_WAKE_ALL: u32 = 0x100;
        const ULF_NO_ERRNO: u32 = 0x0100_0000;
        __ulock_wake(
            UL_COMPARE_AND_WAIT_SHARED | ULF_WAKE_ALL | ULF_NO_ERRNO,
            addr as *mut libc::c_void,
            0,
        );
    }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn pthread_fchdir_np(fd: libc::c_int) -> libc::c_int;
    fn __ulock_wake(operation: u32, addr: *mut libc::c_void, value: u64) -> libc::c_int;
}

pub struct PropertyServer {
    stop: Arc<AtomicBool>,
    service: Arc<Mutex<PropertyService<MmapMem>>>,
    log: Arc<Mutex<String>>,
    thread: Option<JoinHandle<()>>,
    socket: PathBuf,
    area: PathBuf,
    owner: PathBuf,
}

/// `dev/__properties__` under a guest root.
pub(crate) fn property_area(root: &Path) -> PathBuf {
    root.join("dev/__properties__")
}

/// Beside the guest root, not inside it. The guest cannot see this file.
/// It marks an area this process created, so a later run can remove that
/// leftover without deleting a seeded area that has no mark.
pub(crate) fn property_area_owner(root: &Path) -> PathBuf {
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("root");
    root.parent()
        .unwrap_or(root)
        .join(format!("property-area-owner-{name}"))
}

const AREA_OWNER_MARK: &str = "property-service\n";

fn owner_is_ours(path: &Path) -> bool {
    fs::read_to_string(path).ok().as_deref() == Some(AREA_OWNER_MARK)
}

/// Remove an area this server created and then left behind. A directory
/// with no owner file stays, so a seeded `servicemanager.ready` fixture
/// still fails the caller's assertion.
pub(crate) fn reclaim_owned_property_area(root: &Path) -> Result<(), String> {
    let area = property_area(root);
    let owner = property_area_owner(root);
    let owned = owner_is_ours(&owner);
    if area.exists() && owned {
        fs::remove_dir_all(&area).map_err(|e| format!("remove {}: {e}", area.display()))?;
        let _ = fs::remove_file(&owner);
    } else if !area.exists() && owned {
        let _ = fs::remove_file(&owner);
    }
    Ok(())
}

pub(crate) fn release_property_area(area: &Path, owner: &Path) {
    if area.exists() {
        let _ = fs::remove_dir_all(area);
    }
    if owner.exists() {
        let _ = fs::remove_file(owner);
    }
}

impl PropertyServer {
    /// Maps `/dev/__properties__` under `root` and listens on
    /// `/dev/socket/property_service`. `servicemanager.ready` is absent.
    /// A peer's context is the file its own `linux-run` published.
    pub fn start(root: &Path) -> Result<Self, String> {
        let prop_dir = property_area(root);
        let owner = property_area_owner(root);
        if prop_dir.exists() {
            fs::remove_dir_all(&prop_dir)
                .map_err(|e| format!("remove {}: {e}", prop_dir.display()))?;
        }
        fs::create_dir_all(&prop_dir).map_err(|e| e.to_string())?;
        set_mode(&prop_dir, 0o755)?;
        if let Err(error) = fs::write(&owner, AREA_OWNER_MARK) {
            let _ = fs::remove_dir_all(&prop_dir);
            return Err(format!("write {}: {error}", owner.display()));
        }
        let info = build_trie(&[], DEFAULT_CONTEXT, DEFAULT_TYPE)?;
        fs::write(prop_dir.join(PROPERTY_INFO), &info).map_err(|e| e.to_string())?;
        set_mode(&prop_dir.join(PROPERTY_INFO), 0o444)?;
        let contexts = aim_android_init::props::PropertyInfoArea::new(&info)?.contexts();
        let mut names: Vec<String> = contexts.into_iter().map(str::to_string).collect();
        names.push(PROPERTIES_SERIAL.to_string());
        let mut created = HashMap::new();
        for name in &names {
            created.insert(name.clone(), MmapMem::create(&prop_dir.join(name))?);
        }
        let mut bases = HashMap::new();
        let areas = PropertyAreas::with_memory(info, |name| {
            let mem = created.remove(name).expect("area file");
            bases.insert(name.to_string(), mem.base() as usize);
            mem
        })?;
        let mut service = PropertyService::with_areas(areas);
        service.set_waker(Box::new(SharedWake { bases }));
        let outcome = service.init_set(VERSION, "2");
        if outcome.reply != Some(PROP_SUCCESS) || service.get(VERSION).as_deref() != Some("2") {
            return Err(format!(
                "init could not publish {VERSION}: reply {:?} error {:?} value {:?}",
                outcome.reply,
                outcome.error,
                service.get(VERSION)
            ));
        }
        if service.get(READY).is_some() {
            return Err(format!("{READY} was written before any client"));
        }
        let sock_dir = root.join("dev/socket");
        fs::create_dir_all(&sock_dir).map_err(|e| e.to_string())?;
        set_mode(&root.join("dev"), 0o755)?;
        set_mode(&sock_dir, 0o755)?;
        let listener = listen_socket(&sock_dir, "property_service")?;
        let service = Arc::new(Mutex::new(service));
        let stop = Arc::new(AtomicBool::new(false));
        let log = Arc::new(Mutex::new(String::new()));
        let stop_flag = Arc::clone(&stop);
        let service_thr = Arc::clone(&service);
        let log_thr = Arc::clone(&log);
        let thread = thread::spawn(move || accept_loop(listener, service_thr, stop_flag, log_thr));
        println!("property-service init name={VERSION} value=2 reply=0");
        println!("property-service: {READY} absent");
        println!("property-service listening");
        Ok(Self {
            stop,
            service,
            log,
            thread: Some(thread),
            socket: sock_dir.join("property_service"),
            area: prop_dir,
            owner,
        })
    }

    pub fn get(&self, name: &str) -> Option<String> {
        self.service.lock().expect("property service").get(name)
    }

    pub fn log(&self) -> String {
        self.log.lock().expect("property log").clone()
    }
}

impl Drop for PropertyServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.socket);
        release_property_area(&self.area, &self.owner);
    }
}

fn accept_loop(
    listener: UnixListener,
    service: Arc<Mutex<PropertyService<MmapMem>>>,
    stop: Arc<AtomicBool>,
    log: Arc<Mutex<String>>,
) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => handle_client(&mut stream, &service, &log),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                note(&log, &format!("property-service accept: {error}"));
                break;
            }
        }
    }
}

fn handle_client(
    stream: &mut UnixStream,
    service: &Mutex<PropertyService<MmapMem>>,
    log: &Mutex<String>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let request = loop {
        match protocol::decode_request(&buf) {
            Decoded::Incomplete => {
                if buf.len() > 16 + 2 * 0xffff {
                    reply(stream, protocol::PROP_ERROR_READ_DATA);
                    return;
                }
                match stream.read(&mut tmp) {
                    Ok(0) => {
                        if let Some(code) = protocol::truncated_reply(&buf) {
                            reply(stream, code);
                        }
                        return;
                    }
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(error) => {
                        note(log, &format!("property-service read: {error}"));
                        if let Some(code) = protocol::truncated_reply(&buf) {
                            reply(stream, code);
                        }
                        return;
                    }
                }
            }
            Decoded::Reject(code) => {
                reply(stream, code);
                return;
            }
            Decoded::Complete(request, _) => break request,
        }
    };
    let pid = match peer_pid(stream.as_raw_fd()) {
        Ok(pid) => pid,
        Err(error) => {
            note(log, &format!("property-service peer: {error}"));
            reply(stream, PROP_ERROR_PERMISSION_DENIED);
            return;
        }
    };
    let Some((uid, gid, context)) = read_identity(pid) else {
        note(
            log,
            &format!("property-service: peer pid={pid} has no published identity"),
        );
        reply(stream, PROP_ERROR_PERMISSION_DENIED);
        return;
    };
    let cred = Ucred { pid, uid, gid };
    let served = {
        let mut service = service.lock().expect("property service");
        protocol::serve(&mut service, &request, Some(&context), &cred)
    };
    let (name, value) = match &request {
        protocol::Request::SetProp2 { name, value } | protocol::Request::SetProp { name, value } => {
            (
                String::from_utf8_lossy(name).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            )
        }
    };
    let code = served.reply.unwrap_or(0xffff_ffff);
    note(
        log,
        &format!(
            "property-service set pid={pid} uid={uid} context={context} name={name} value={value} reply={code}"
        ),
    );
    if let Some(code) = served.reply {
        reply(stream, code);
    }
}

fn reply(stream: &UnixStream, code: u32) {
    let _ = (&*stream).write_all(&code.to_ne_bytes());
}

fn note(log: &Mutex<String>, line: &str) {
    println!("{line}");
    log.lock().expect("property log").push_str(line);
    log.lock().expect("property log").push('\n');
}

fn read_identity(pid: i32) -> Option<(u32, u32, String)> {
    let path = standalone_identity(pid);
    for _ in 0..25 {
        if let Ok(text) = fs::read_to_string(&path) {
            let mut uid = None;
            let mut gid = None;
            let mut label = None;
            for line in text.lines() {
                let Some((key, value)) = line.split_once('\t') else {
                    continue;
                };
                match key {
                    "uid" => uid = value.parse().ok(),
                    "gid" => gid = value.parse().ok(),
                    "seclabel" => {
                        if !value.is_empty() {
                            label = Some(value.to_string());
                        }
                    }
                    _ => {}
                }
            }
            if let (Some(uid), Some(gid), Some(label)) = (uid, gid, label) {
                return Some((uid, gid, label));
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    None
}

fn peer_pid(fd: std::os::fd::RawFd) -> Result<i32, String> {
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io_error());
        }
        return Ok(cred.pid);
    }
    #[cfg(target_os = "macos")]
    {
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                &mut pid as *mut libc::pid_t as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io_error());
        }
        return Ok(pid);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        Err("no peer pid on this host".into())
    }
}

fn listen_socket(dir: &Path, name: &str) -> Result<UnixListener, String> {
    let path = dir.join(name);
    let _ = fs::remove_file(&path);
    #[cfg(not(target_os = "macos"))]
    let listener = {
        let listener = UnixListener::bind(&path).map_err(|e| format!("bind {}: {e}", path.display()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("nonblock {}: {e}", path.display()))?;
        listener
    };
    #[cfg(target_os = "macos")]
    let listener = listen_short(dir, name)?;
    set_mode(&path, 0o666)?;
    Ok(listener)
}

#[cfg(target_os = "macos")]
fn listen_short(dir: &Path, name: &str) -> Result<UnixListener, String> {
    if name.contains('/') || name.len() >= 100 {
        return Err(format!("socket name {name} is not a short file name"));
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(format!("socket: {}", io_error()));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    let dir_c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| format!("{} is not a C path", dir.display()))?;
    let dfd = unsafe { libc::open(dir_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if dfd < 0 {
        return Err(format!("open {}: {}", dir.display(), io_error()));
    }
    let bound = unsafe {
        let chdir = pthread_fchdir_np(dfd);
        let result = if chdir != 0 {
            Err(format!("fchdir {}: {}", dir.display(), io_error()))
        } else {
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            for (i, byte) in name.bytes().enumerate() {
                addr.sun_path[i] = byte as libc::c_char;
            }
            let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
            addr.sun_len = len as u8;
            if libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), len) != 0 {
                Err(format!("bind {name}: {}", io_error()))
            } else if libc::listen(fd, 8) != 0 {
                Err(format!("listen {name}: {}", io_error()))
            } else {
                Ok(())
            }
        };
        pthread_fchdir_np(-1);
        libc::close(dfd);
        result
    };
    bound?;
    let listener = UnixListener::from(owned);
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("nonblock {name}: {e}"))?;
    Ok(listener)
}

fn io_error() -> String {
    std::io::Error::last_os_error().to_string()
}

/// Runs original getprop and setprop, and the generated waiter, against
/// the property service. Linux can compile this. A pass is the Mac run.
pub fn run_property(linux_run: &Path) -> Result<(), String> {
    print_host();
    if !linux_run.is_file() {
        return Err(format!(
            "linux-run is not a file at {} (cargo build --locked -p aim-linux-abi --release --bin linux-run)",
            linux_run.display()
        ));
    }
    let root = property_root();
    if !root.join("system/bin/getprop").is_file() {
        return Err(
            "property root is not staged; run bionic-smoke --prepare-property (after --prepare)"
                .into(),
        );
    }
    let server = PropertyServer::start(&root)?;
    if server.get(READY).is_some() {
        return blocker("ready was present at start", &server.log());
    }
    let mut before = guest(linux_run, &root, &["/system/bin/getprop", READY])?;
    let (code, out, err) = take("getprop-before", &mut before, Duration::from_secs(25));
    println!(
        "property-service: getprop before pid={} exit={code:?} stdout={out:?}",
        before.child.id()
    );
    if code != Some(0) {
        return blocker(
            "getprop before setprop did not run",
            &format!("exit={code:?}\nstdout={out:?}\n{err}"),
        );
    }
    if out.contains("true") {
        return blocker(
            "getprop before setprop printed true",
            &format!("stdout={out:?}\n{err}"),
        );
    }
    if !opened(&err, "/dev/__properties__/property_info") {
        return blocker("getprop did not open property_info", &err);
    }
    let mut waiter = guest(
        linux_run,
        &root,
        &["/system/bin/property-wait", READY, "true"],
    )?;
    let waiter_pid = waiter.child.id();
    if !wait_parked(&mut waiter, Duration::from_secs(25))? {
        let err = stderr_of(&waiter);
        let out = stdout_of(&waiter);
        emit_guest("property-wait-not-parked", waiter_pid, None, &out, &err);
        return blocker(
            "property-wait was not parked in futex before setprop",
            &format!("stdout={out:?}\n{err}"),
        );
    }
    emit_guest(
        "property-wait-parked",
        waiter_pid,
        None,
        &stdout_of(&waiter),
        &stderr_of(&waiter),
    );
    println!("property-service: waiter pid={waiter_pid} parked");
    let mut set = guest(linux_run, &root, &["/system/bin/setprop", READY, "true"])?;
    let set_pid = set.child.id();
    let (set_code, set_out, set_err) = take("setprop-ready", &mut set, Duration::from_secs(25));
    println!("property-service: setprop pid={set_pid} exit={set_code:?} stdout={set_out:?}");
    if set_code != Some(0) {
        return blocker("setprop servicemanager.ready true failed", &format!("{set_out}\n{set_err}\n{}", server.log()));
    }
    if !connect_ok(&set_err) {
        return blocker("setprop did not complete connect", &set_err);
    }
    let line = format!(
        "property-service set pid={set_pid} uid=2000 context=u:r:shell:s0 name={READY} value=true reply=0"
    );
    if !server.log().contains(&line) {
        return blocker("server did not record the shell set", &format!("want {line}\n{}", server.log()));
    }
    if server.get(READY).as_deref() != Some("true") {
        return blocker(
            "area does not contain the value setprop sent",
            &format!("value={:?}\n{}", server.get(READY), server.log()),
        );
    }
    let (wait_code, wait_out, wait_err) = take("property-wait", &mut waiter, Duration::from_secs(20));
    println!("property-service: waiter exit={wait_code:?} stdout={wait_out:?}");
    if wait_code != Some(0) || wait_out != "property wait: servicemanager.ready=true\n" {
        return blocker(
            "property-wait did not print the value it read",
            &format!("stdout={wait_out:?}\n{wait_err}"),
        );
    }
    if futex_parked(&wait_err) {
        return blocker("property-wait exited while a futex was still entered", &wait_err);
    }
    let mut after = guest(linux_run, &root, &["/system/bin/getprop", READY])?;
    let after_pid = after.child.id();
    let (after_code, after_out, after_err) = take("getprop-after", &mut after, Duration::from_secs(25));
    println!("property-service: getprop after pid={after_pid} exit={after_code:?} stdout={after_out:?}");
    if after_code != Some(0) || after_out != "true\n" {
        return blocker("getprop after setprop did not print true", &format!("stdout={after_out:?}\n{after_err}"));
    }
    if after_pid == set_pid || after_pid == waiter_pid {
        return blocker("getprop pid collided with setprop or the waiter", "");
    }
    let mut ro = guest(linux_run, &root, &["/system/bin/setprop", VERSION, "9"])?;
    let ro_pid = ro.child.id();
    let (ro_code, ro_out, ro_err) = take("setprop-ro", &mut ro, Duration::from_secs(25));
    println!("property-service: ro setprop pid={ro_pid} exit={ro_code:?} stdout={ro_out:?}");
    if ro_code == Some(0) || server.get(VERSION).as_deref() != Some("2") {
        return blocker(
            "ro.property_service.version accepted a second write",
            &format!("stdout={ro_out:?}\n{ro_err}\n{}", server.log()),
        );
    }
    let mut version = guest(linux_run, &root, &["/system/bin/getprop", VERSION])?;
    let (ver_code, ver_out, ver_err) = take("getprop-version", &mut version, Duration::from_secs(25));
    println!("property-service: getprop version exit={ver_code:?} stdout={ver_out:?}");
    if ver_code != Some(0) || ver_out != "2\n" {
        return blocker(
            "getprop ro.property_service.version did not stay 2",
            &format!("stdout={ver_out:?}\n{ver_err}"),
        );
    }
    let mut unset = guest(linux_run, &root, &["/system/bin/getprop", "debug.aim.unset"])?;
    let (unset_code, unset_out, unset_err) = take("getprop-unset", &mut unset, Duration::from_secs(25));
    println!("property-service: getprop unset exit={unset_code:?} stdout={unset_out:?}");
    if unset_code != Some(0) || unset_out.contains("true") || unset_out.contains("set-me") {
        return blocker(
            "unset property printed a planted value",
            &format!("stdout={unset_out:?}\n{unset_err}"),
        );
    }
    drop(server);
    if root.join("dev/socket/property_service").exists() {
        return blocker("property socket was left behind", "");
    }
    println!(
        "property-service ok waiter={waiter_pid} setprop={set_pid} getprop={after_pid}"
    );
    println!("property-service: this is not ART and not a reDroid boot");
    Ok(())
}

fn blocker(why: &str, detail: &str) -> Result<(), String> {
    Err(format!("property-service: first blocker: {why}\n{detail}"))
}

/// Build a `linux-run` command. No `--by-pid`: linux-run creates
/// `aim-pidns-<pid>`, starts its watcher, and that watcher writes
/// `posix-control-owner`. The identity text is published into that table
/// by linux-run, not by this process.
pub(crate) fn launch_command(
    linux_run: &Path,
    root: &Path,
    identity: &str,
    binder: Option<&str>,
    args: &[&str],
) -> Command {
    let mut command = Command::new(linux_run);
    command
        .arg("--no-cache")
        .arg("--trace")
        .arg("--root")
        .arg(root);
    if let Some(name) = binder {
        command.arg("--binder").arg(name);
    }
    command.arg("--identity-text").arg(identity).args(args);
    command
}

fn guest(linux_run: &Path, root: &Path, args: &[&str]) -> Result<Guest, String> {
    launch(linux_run, root, SHELL, None, args)
}

pub(crate) fn launch(
    linux_run: &Path,
    root: &Path,
    identity: &str,
    binder: Option<&str>,
    args: &[&str],
) -> Result<Guest, String> {
    let mut child = launch_command(linux_run, root, identity, binder, args);
    child.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = child
        .spawn()
        .map_err(|e| format!("start linux-run {}: {e}", args.join(" ")))?;
    let stdout = Arc::new(Mutex::new(String::new()));
    let stderr = Arc::new(Mutex::new(String::new()));
    let mut readers = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        let buf = Arc::clone(&stdout);
        readers.push(thread::spawn(move || {
            let mut tmp = [0u8; 1024];
            loop {
                match pipe.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf
                        .lock()
                        .expect("stdout")
                        .push_str(&String::from_utf8_lossy(&tmp[..n])),
                }
            }
        }));
    }
    if let Some(mut pipe) = child.stderr.take() {
        let buf = Arc::clone(&stderr);
        readers.push(thread::spawn(move || {
            let mut tmp = [0u8; 1024];
            loop {
                match pipe.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf
                        .lock()
                        .expect("stderr")
                        .push_str(&String::from_utf8_lossy(&tmp[..n])),
                }
            }
        }));
    }
    Ok(Guest {
        child,
        stdout,
        stderr,
        readers,
    })
}

pub(crate) struct Guest {
    pub(crate) child: Child,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    readers: Vec<JoinHandle<()>>,
}

impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

pub(crate) fn stdout_of(guest: &Guest) -> String {
    guest.stdout.lock().expect("stdout").clone()
}

pub(crate) fn stderr_of(guest: &Guest) -> String {
    guest.stderr.lock().expect("stderr").clone()
}

pub(crate) fn finish(guest: &mut Guest, limit: Duration) -> (Option<i32>, String, String) {
    let start = Instant::now();
    let code = loop {
        match guest.child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) if start.elapsed() >= limit => {
                let _ = guest.child.kill();
                let _ = guest.child.wait();
                break None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => break None,
        }
    };
    thread::sleep(Duration::from_millis(50));
    (code, stdout_of(guest), stderr_of(guest))
}

fn wait_parked(guest: &mut Guest, limit: Duration) -> Result<bool, String> {
    let start = Instant::now();
    loop {
        match guest.child.try_wait() {
            Ok(Some(status)) => {
                println!(
                    "property-service: waiter exited early status={status:?} stdout={:?}",
                    stdout_of(guest)
                );
                return Ok(false);
            }
            Ok(None) => {}
            Err(error) => return Err(format!("wait property-wait: {error}")),
        }
        if futex_parked(&stderr_of(guest)) {
            thread::sleep(Duration::from_millis(100));
            if guest.child.try_wait().ok().flatten().is_none() && futex_parked(&stderr_of(guest)) {
                return Ok(true);
            }
        }
        if start.elapsed() >= limit {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn take(
    role: &str,
    guest: &mut Guest,
    limit: Duration,
) -> (Option<i32>, String, String) {
    let pid = guest.child.id();
    let (code, out, err) = finish(guest, limit);
    emit_guest(role, pid, code, &out, &err);
    (code, out, err)
}

/// The success path prints the guest's own stdout, stderr, and the
/// `linux-run` trace. A count line is not a substitute for that text.
pub(crate) fn format_guest(
    role: &str,
    pid: u32,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> String {
    let mut text = String::new();
    text.push_str(&format!(
        "----- {role} pid={pid} exit={exit_code:?} stdout -----\n"
    ));
    text.push_str(stdout);
    if !stdout.is_empty() && !stdout.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("----- {role} pid={pid} stderr -----\n"));
    text.push_str(stderr);
    if !stderr.is_empty() && !stderr.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("----- end {role} pid={pid} -----\n"));
    let counts = trace_counts(stderr);
    text.push_str(&format!(
        "property-trace {role} pid={pid} exit={exit_code:?} property_info_open={} connect_ok={} futex_enter={} futex_leave={} binder_open={}\n",
        counts.property_info_open,
        counts.connect_ok,
        counts.futex_enter,
        counts.futex_leave,
        counts.binder_open
    ));
    text
}

pub(crate) fn emit_guest(
    role: &str,
    pid: u32,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) {
    print!(
        "{}",
        format_guest(role, pid, exit_code, stdout, stderr)
    );
}

pub(crate) struct TraceCounts {
    pub property_info_open: u32,
    pub connect_ok: u32,
    pub futex_enter: u32,
    pub futex_leave: u32,
    pub binder_open: u32,
}

pub(crate) fn trace_counts(stderr: &str) -> TraceCounts {
    let mut counts = TraceCounts {
        property_info_open: 0,
        connect_ok: 0,
        futex_enter: 0,
        futex_leave: 0,
        binder_open: 0,
    };
    for line in stderr.lines() {
        if line.starts_with("[linux] openat(")
            && line.contains("\"/dev/__properties__/property_info\"")
            && line.contains(" leave]")
            && leave_ok(line)
        {
            counts.property_info_open += 1;
        }
        if line.starts_with("[linux] connect(") && line.contains(" leave]") && leave_ok(line) {
            counts.connect_ok += 1;
        }
        if line.starts_with("[linux] futex(") && line.contains(" enter]") {
            counts.futex_enter += 1;
        }
        if line.starts_with("[linux] futex(") && line.contains(" leave]") {
            counts.futex_leave += 1;
        }
        if super::binder_device_opened(line) {
            counts.binder_open += 1;
        }
    }
    counts
}

pub(crate) fn opened(stderr: &str, path: &str) -> bool {
    let quoted = format!("\"{path}\"");
    stderr.lines().any(|line| {
        line.starts_with("[linux] openat(")
            && line.contains(&quoted)
            && line.contains(" leave]")
            && leave_ok(line)
    })
}

fn connect_ok(stderr: &str) -> bool {
    stderr.lines().any(|line| {
        line.starts_with("[linux] connect(") && line.contains(" leave]") && leave_ok(line)
    })
}

fn leave_ok(line: &str) -> bool {
    let Some((_, result)) = line.rsplit_once(" = ") else {
        return false;
    };
    let token = result.split_whitespace().next().unwrap_or("");
    !token.starts_with('-') && !token.is_empty() && token.chars().all(|c| c.is_ascii_digit())
}

pub(crate) fn futex_parked(stderr: &str) -> bool {
    let mut enters = 0;
    let mut leaves = 0;
    for line in stderr.lines() {
        if !line.starts_with("[linux] futex(") {
            continue;
        }
        if line.contains(" enter]") {
            enters += 1;
        }
        if line.contains(" leave]") {
            leaves += 1;
        }
    }
    enters > leaves
}

pub(crate) fn print_host() {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut uts) };
    let text = |bytes: &[libc::c_char]| {
        let bytes = unsafe { &*(bytes as *const [libc::c_char] as *const [u8]) };
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    };
    let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    println!(
        "host sysname={} nodename={} release={} version={} machine={} pagesize={pagesize}",
        text(&uts.sysname),
        text(&uts.nodename),
        text(&uts.release),
        text(&uts.version),
        text(&uts.machine)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use aim_android_init::props::protocol::{encode_setprop2, PROP_ERROR_READ_ONLY_PROPERTY};
    use sha2::Digest;
    use std::io::Read;

    #[test]
    fn probe_is_marked_and_has_no_planted_name() {
        assert_eq!(PROPERTY_WAIT_SHA256.len(), 64);
        assert_eq!(GETPROP_SHA256.len(), 64);
        assert_eq!(LIBBASE_SHA256.len(), 64);
        let mut hasher = sha2::Sha256::new();
        hasher.update(PROPERTY_WAIT);
        assert_eq!(format!("{:x}", hasher.finalize()), PROPERTY_WAIT_SHA256);
        let info = read_elf(PROPERTY_WAIT).unwrap();
        assert_eq!(info.machine, 183);
        assert!(info.aligns.iter().all(|align| *align >= 16384));
        assert!(!String::from_utf8_lossy(PROPERTY_WAIT).contains(READY));
        assert!(futex_parked(
            "[linux] futex(0x1, 0x80, 0x1, 0x0) [pid=1 tid=1 call=1 enter]\n"
        ));
        assert!(!futex_parked(
            "[linux] futex(0x1, 0x80, 0x1, 0x0) [pid=1 tid=1 call=1 enter]\n[linux] futex(0x1, 0x80, 0x1, 0x0) = 0 [pid=1 tid=1 call=1 leave]\n"
        ));
        assert!(opened(
            "[linux] openat(-100, \"/dev/__properties__/property_info\", 0x0, 0x0) = 3 [pid=1 tid=1 call=2 leave]\n",
            "/dev/__properties__/property_info"
        ));
        assert!(!opened(
            "[linux] openat(-100, \"/dev/__properties__/property_info\", 0x0, 0x0) = -2 (ENOENT) [pid=1 tid=1 call=2 leave]\n",
            "/dev/__properties__/property_info"
        ));
        assert!(connect_ok(
            "[linux] connect(0x3, 0x1, 0x6e) = 0 [pid=4 tid=4 call=3 leave]\n"
        ));
        let args: Vec<String> = launch_command(
            Path::new("linux-run"),
            Path::new("root"),
            SHELL,
            None,
            &["/system/bin/getprop", READY],
        )
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
        assert!(args.iter().any(|arg| arg == "--identity-text"));
        assert!(!args.iter().any(|arg| arg == "--by-pid"));
        assert!(!args.iter().any(|arg| arg == "--binder"));
        let sm: Vec<String> = launch_command(
            Path::new("linux-run"),
            Path::new("root"),
            SERVICEMANAGER_IDENTITY,
            Some("dev.aim.integrated.1"),
            &["/system/bin/servicemanager"],
        )
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
        assert!(sm.windows(2).any(|pair| pair == ["--binder", "dev.aim.integrated.1"]));
        assert!(sm.iter().any(|arg| arg.contains("u:r:servicemanager:s0")));
        assert!(!sm.iter().any(|arg| arg == "--by-pid"));
        let counts = trace_counts(
            "[linux] openat(-100, \"/dev/__properties__/property_info\", 0x0, 0x0) = 3 [pid=1 tid=1 call=2 leave]\n\
             [linux] futex(0x1, 0x80, 0x1, 0x0) [pid=1 tid=1 call=3 enter]\n\
             [linux] connect(0x4, 0x1, 0x6e) = 0 [pid=4 tid=4 call=4 leave]\n\
             [linux] openat(-100, \"/dev/binder\", 0x80002, 0x0) = 5 [pid=1 tid=1 call=5 leave]\n",
        );
        assert_eq!(counts.property_info_open, 1);
        assert_eq!(counts.futex_enter, 1);
        assert_eq!(counts.futex_leave, 0);
        assert_eq!(counts.connect_ok, 1);
        assert_eq!(counts.binder_open, 1);
    }

    #[test]
    fn socket_set_is_the_only_way_ready_appears() {
        let dir = std::env::temp_dir().join(format!("aim-prop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("dev")).unwrap();
        let pid = std::process::id() as i32;
        let identity = standalone_identity(pid);
        let table = identity.parent().unwrap().to_path_buf();
        assert!(
            !table.exists(),
            "this process already has a standalone pid table"
        );
        struct Remove(PathBuf);
        impl Drop for Remove {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _remove_table = Remove(table.clone());
        let server = PropertyServer::start(&dir).unwrap();
        assert!(server.get(READY).is_none());
        assert_eq!(server.get(VERSION).as_deref(), Some("2"));

        let denied = exchange(&dir, &encode_setprop2(READY.as_bytes(), b"true"));
        assert_eq!(denied, PROP_ERROR_PERMISSION_DENIED);
        assert!(server.get(READY).is_none());
        assert!(server.log().contains("has no published identity"));

        fs::create_dir_all(&table).unwrap();
        fs::write(&identity, SHELL).unwrap();
        let ok = exchange(&dir, &encode_setprop2(READY.as_bytes(), b"true"));
        assert_eq!(ok, PROP_SUCCESS);
        assert_eq!(server.get(READY).as_deref(), Some("true"));
        assert!(server.log().contains(&format!(
            "pid={pid} uid=2000 context=u:r:shell:s0 name={READY} value=true reply=0"
        )));

        let ro = exchange(&dir, &encode_setprop2(VERSION.as_bytes(), b"9"));
        assert_eq!(ro, PROP_ERROR_READ_ONLY_PROPERTY);
        assert_eq!(server.get(VERSION).as_deref(), Some("2"));
        drop(server);
        assert!(!dir.join("dev/socket/property_service").exists());
        assert!(
            !property_area(&dir).exists(),
            "the server removes the area it created"
        );
        assert!(!property_area_owner(&dir).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reclaim_removes_only_an_area_this_server_created() {
        let parent = std::env::temp_dir().join(format!("aim-area-{}", std::process::id()));
        let _ = fs::remove_dir_all(&parent);
        let root = parent.join("root");
        let area = property_area(&root);
        fs::create_dir_all(&area).unwrap();
        fs::write(area.join("property_info"), b"seed").unwrap();
        reclaim_owned_property_area(&root).unwrap();
        assert!(area.join("property_info").is_file(), "a seed has no owner file");
        fs::write(property_area_owner(&root), AREA_OWNER_MARK).unwrap();
        reclaim_owned_property_area(&root).unwrap();
        assert!(!area.exists());
        assert!(!property_area_owner(&root).exists());
        fs::create_dir_all(&area).unwrap();
        fs::write(property_area_owner(&root), b"not-the-server\n").unwrap();
        reclaim_owned_property_area(&root).unwrap();
        assert!(area.exists(), "a foreign marker is not this server");
        release_property_area(&area, &property_area_owner(&root));
        assert!(!area.exists());
        assert!(!property_area_owner(&root).exists());
        let _ = fs::remove_dir_all(&parent);
    }

    fn exchange(root: &Path, request: &[u8]) -> u32 {
        let mut stream = UnixStream::connect(root.join("dev/socket/property_service")).unwrap();
        stream.write_all(request).unwrap();
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).unwrap();
        u32::from_ne_bytes(reply)
    }
}

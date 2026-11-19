//! A bounded run of the original `/system/bin/init`.
//!
//! The 2026-09-27 note in `docs/guest-init-contract.md` section 10 says an
//! older `linux-run` stopped `linkerconfig`, `servicemanager`, and `logd`
//! inside `linker64` on `mremap`, `SOCK_SEQPACKET`, and
//! `rt_tgsigqueueinfo`. That note is not a trace of this binary on the
//! current Mac. Those three calls are dispatched in the current
//! `linux-run` source. Original `servicemanager` and `service` have since
//! reached `main` on the Mac. This probe is what measures init.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use super::manager::copy_tree;
use super::property::{format_guest, launch_command};
use super::{guest_root, read_elf, require_layer, set_mode, write_entry, LINKER_GUEST, LINKER_SHA256};
use super::sha256_file;

const INIT_GUEST: &str = "/system/bin/init";
const BOOTSTRAP_LINKER: &str = "system/bin/bootstrap/linker64";
/// uid 0 is init's own credential. It is published by linux-run, not written
/// into the property area.
const INIT_IDENTITY: &str = "uid\t0\ngid\t0\nseclabel\tu:r:init:s0\n";

pub fn init_root() -> PathBuf {
    super::stage_dir()
        .parent()
        .expect("redroid stage")
        .join("redroid-16-init")
        .join("root")
}

/// Files `PropertyInit` reads before it serializes property info. The
/// platform file is the one Android 16 opens first. The others are copied
/// only when the pinned layer contains them. None of these bytes are
/// written here.
const CONTEXT_FILES: &[&str] = &[
    "system/etc/selinux/plat_property_contexts",
    "system_ext/etc/selinux/system_ext_property_contexts",
    "vendor/etc/selinux/vendor_property_contexts",
    "product/etc/selinux/product_property_contexts",
    "odm/etc/selinux/odm_property_contexts",
    "plat_property_contexts",
    "system_ext_property_contexts",
    "vendor_property_contexts",
    "product_property_contexts",
    "odm_property_contexts",
];

/// `access` of the platform file decides the branch. The root fallback is
/// the recovery layout. At least one of them has to come from the layer.
const REQUIRED_CONTEXTS: &[&str] = &[
    "system/etc/selinux/plat_property_contexts",
    "plat_property_contexts",
];

/// Directories `MountExtraFilesystems` mounts tmpfs on. `/apex` is already
/// in the bionic root. The other two are not, and a missing directory makes
/// `mount` return ENOENT, which that function's `CHECKCALL` aborts on.
const MOUNTPOINTS: &[&str] = &["bootstrap-apex", "linkerconfig"];

struct LayerRootFiles {
    contexts: Vec<String>,
    dev_from_layer: bool,
    dev_copied: Vec<String>,
    dev_skipped: Vec<String>,
    /// `(name, source)`. `source` is `present`, `empty-mountpoint`, or
    /// `empty-mountpoint layer-entry`. Children of a layer entry are not copied.
    mountpoints: Vec<(String, &'static str)>,
    kmsg_marker: bool,
}

/// Copy the bionic root and add original init plus the libraries its
/// transitive `DT_NEEDED` closure asks for. The measured Mac stop was
/// `libext2_uuid.so`, needed by `libext4_utils.so`, which is not a direct
/// dependency of init. Also copies the layer's SELinux property-context
/// files and a `/dev` directory. Does not author a property area, a
/// context file, or an init.rc that would make init look successful.
pub fn prepare_init() -> Result<PathBuf, String> {
    let layer = require_layer()?;
    let bionic = guest_root();
    let linker = super::guest_file(&bionic, LINKER_GUEST).map_err(|_| {
        format!(
            "bionic root {} has no linker64; run bionic-smoke --prepare first",
            bionic.display()
        )
    })?;
    if sha256_file(&linker)? != LINKER_SHA256 {
        return Err("bionic root linker64 is not the pinned file".into());
    }
    let root = init_root();
    if root.exists() {
        fs::remove_dir_all(&root).map_err(|e| format!("remove {}: {e}", root.display()))?;
    }
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    copy_tree(&bionic, &root)?;
    set_mode(&root, 0o755)?;
    let copied = extract_closure(&layer, &root)?;
    let init_path = root.join(INIT_GUEST.trim_start_matches('/'));
    let info = read_elf(&fs::read(&init_path).map_err(|e| e.to_string())?)?;
    if info.interp.as_deref() != Some("/system/bin/bootstrap/linker64") {
        return Err(format!("init interpreter {:?}", info.interp));
    }
    if info.machine != 183 {
        return Err(format!("init machine {}", info.machine));
    }
    if !root.join(BOOTSTRAP_LINKER).is_file() {
        return Err("bootstrap linker64 was not in the layer".into());
    }
    for lib in &info.needed {
        super::manager::resolve_lib(&root, lib)?;
    }
    let root_files = extract_root_files(&layer, &root)?;
    if root.join("dev/__properties__").exists() {
        return Err("init probe root must not contain a property area".into());
    }
    if !root.join("dev").is_dir() {
        return Err("init probe root has no /dev directory".into());
    }
    write_provenance(&root, &layer, &copied, &root_files)?;
    for name in ["init-guest.stdout", "init-guest.stderr", "init-probe.txt"] {
        if let Some(parent) = root.parent() {
            let _ = fs::remove_file(parent.join(name));
        }
    }
    let mounts: Vec<String> = root_files
        .mountpoints
        .iter()
        .map(|(name, source)| format!("{name}={source}"))
        .collect();
    println!(
        "bionic-smoke: original init root {} copied {} closure libraries, {} property context files, dev from layer {}, mountpoints {}, kernel log marker {} (staged, not executed)",
        root.display(),
        copied.len(),
        root_files.contexts.len(),
        root_files.dev_from_layer,
        mounts.join(","),
        root_files.kmsg_marker
    );
    println!("bionic-smoke: init-probe is an observation, not a boot");
    Ok(root)
}

/// Transitive `DT_NEEDED` of `/system/bin/init`. Each round reads the
/// ELFs already in the root and copies only the basenames still missing,
/// so a library the bionic root already has is not unpacked again.
fn extract_closure(layer: &Path, root: &Path) -> Result<Vec<String>, String> {
    let exact = [
        "system/bin/init".to_string(),
        BOOTSTRAP_LINKER.to_string(),
    ];
    let found = scan_wanted(layer, root, &exact, &[])?;
    if !root.join("system/bin/init").is_file() {
        return Err(format!("layer has no system/bin/init (copied {found} other files)"));
    }
    let mut copied = Vec::new();
    for _ in 0..32 {
        let missing = missing_needed(root)?;
        if missing.is_empty() {
            copied.sort();
            copied.dedup();
            return Ok(copied);
        }
        let found = scan_wanted(layer, root, &[], &missing)?;
        if found == 0 {
            return Err(format!(
                "layer is missing init closure libraries {missing:?}"
            ));
        }
        copied.extend(newly_copied(root, &missing)?);
    }
    Err(format!(
        "init library closure did not settle; still missing {:?}",
        missing_needed(root)?
    ))
}

fn missing_needed(root: &Path) -> Result<Vec<String>, String> {
    let mut queue = vec!["system/bin/init".to_string()];
    let mut seen = BTreeSet::new();
    let mut missing = BTreeSet::new();
    while let Some(rel) = queue.pop() {
        if !seen.insert(rel.clone()) {
            continue;
        }
        let path = root.join(&rel);
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let info = match read_elf(&bytes) {
            Ok(info) => info,
            Err(_) => continue,
        };
        for lib in info.needed {
            match find_lib(root, &lib) {
                Ok(found) => {
                    if let Ok(next) = found.strip_prefix(root) {
                        queue.push(next.to_string_lossy().replace('\\', "/"));
                    }
                }
                Err(_) => {
                    missing.insert(lib);
                }
            }
        }
    }
    Ok(missing.into_iter().collect())
}

fn newly_copied(root: &Path, basenames: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for name in basenames {
        if let Ok(path) = find_lib(root, name) {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(out)
}

/// The bootstrap linker looks in `system/lib64/bootstrap` before
/// `system/lib64`. A closure library that exists only in one of those
/// directories is present.
fn find_lib(root: &Path, lib: &str) -> Result<PathBuf, String> {
    for dir in [
        "/system/lib64/bootstrap",
        "/system/lib64",
        "/apex/com.android.runtime/lib64/bionic",
    ] {
        if let Ok(path) = super::guest_file(root, &format!("{dir}/{lib}")) {
            return Ok(path);
        }
    }
    Err(format!("NEEDED {lib} is not in the init root"))
}

fn scan_wanted(
    layer: &Path,
    root: &Path,
    exact: &[String],
    basenames: &[String],
) -> Result<usize, String> {
    let file = File::open(layer).map_err(|e| format!("open {}: {e}", layer.display()))?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let entries = archive
        .entries()
        .map_err(|e| format!("read layer tar: {e}"))?;
    let mut found = 0;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        let raw = entry
            .path()
            .map_err(|e| format!("tar path: {e}"))?
            .into_owned();
        let name = raw.to_string_lossy().trim_start_matches("./").to_string();
        let base = name.rsplit('/').next().unwrap_or("");
        let exact_hit = exact.iter().any(|item| item == &name);
        let lib_hit = basenames.iter().any(|item| item == base)
            && (name.starts_with("system/lib64/")
                || name.starts_with("apex/com.android.runtime/lib64/"));
        if !exact_hit && !lib_hit {
            continue;
        }
        if !entry.header().entry_type().is_file() && !entry.header().entry_type().is_symlink() {
            continue;
        }
        let dest = root.join(&name);
        if dest.exists() {
            continue;
        }
        write_entry(&mut entry, &dest)?;
        found += 1;
    }
    Ok(found)
}

/// `372d08ff` aborted in `PropertyInit` because `/dev` and the property
/// contexts were absent. `14a42a5` copied both; init wrote `property_info`
/// itself and then aborted in `MountExtraFilesystems`. That function
/// mounts tmpfs on `/apex` (the bionic root already has it), and, when
/// `/system/bin/recovery` is absent, on `/bootstrap-apex` and then on
/// `/linkerconfig`. A missing directory is ENOENT, and `CHECKCALL` turns
/// that into SIGABRT. Those two directories are created here, from a
/// layer directory entry when the layer has one and as an empty mount
/// point otherwise. Their children are not copied: init covers them with
/// tmpfs. `dev/__properties__` is still not copied and not created.
///
/// The layer's `/dev/kmsg` is a device node, which is not copied. The
/// syscall layer's ring adopts an empty regular file at that path, the
/// same marker guest-init creates. Init's `LOG` goes there after it
/// points stdio at `/dev/null`.
fn extract_root_files(layer: &Path, root: &Path) -> Result<LayerRootFiles, String> {
    let file = File::open(layer).map_err(|e| format!("open {}: {e}", layer.display()))?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let entries = archive
        .entries()
        .map_err(|e| format!("read layer tar: {e}"))?;
    let mut contexts = Vec::new();
    let mut dev_from_layer = false;
    let mut dev_copied = Vec::new();
    let mut dev_skipped = Vec::new();
    let mut layer_mount_dirs = BTreeSet::new();
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        let raw = entry
            .path()
            .map_err(|e| format!("tar path: {e}"))?
            .into_owned();
        let name = tar_rel(&raw);
        if property_area_rel(&name) {
            continue;
        }
        if context_rel(&name) {
            let dest = root.join(&name);
            if !dest.exists() {
                write_entry(&mut entry, &dest)?;
            }
            contexts.push(name);
            continue;
        }
        if mountpoint_rel(&name) && entry.header().entry_type().is_dir() {
            layer_mount_dirs.insert(name);
            continue;
        }
        if !dev_rel(&name) {
            continue;
        }
        dev_from_layer = true;
        let kind = entry.header().entry_type();
        let dest = root.join(&name);
        if kind.is_dir() {
            fs::create_dir_all(&dest).map_err(|e| format!("mkdir {}: {e}", dest.display()))?;
            let mode = entry.header().mode().unwrap_or(0o755) & 0o777;
            set_mode(&dest, mode)?;
            continue;
        }
        if kind.is_file() || kind.is_symlink() {
            if !dest.exists() {
                write_entry(&mut entry, &dest)?;
            }
            dev_copied.push(name);
            continue;
        }
        dev_skipped.push(name);
    }
    contexts.sort();
    contexts.dedup();
    dev_copied.sort();
    dev_skipped.sort();
    if !REQUIRED_CONTEXTS
        .iter()
        .any(|rel| root.join(rel).exists())
    {
        return Err(
            "layer has neither system/etc/selinux/plat_property_contexts nor plat_property_contexts; refusing to invent property contexts"
                .into(),
        );
    }
    let dev = root.join("dev");
    if !dev.is_dir() {
        fs::create_dir_all(&dev).map_err(|e| format!("mkdir {}: {e}", dev.display()))?;
        set_mode(&dev, 0o755)?;
    }
    let mut mountpoints = Vec::new();
    for name in MOUNTPOINTS {
        let dest = root.join(name);
        // An existing directory stays, including `/linkerconfig` from the
        // bionic root. That directory holds `ld.config.txt`, which the
        // linker opens. `present` records it; the files are not removed.
        let source = if dest.is_dir() {
            "present"
        } else if dest.exists() {
            return Err(format!("{name} exists and is not a directory"));
        } else if layer_mount_dirs.contains(*name) {
            "empty-mountpoint layer-entry"
        } else {
            "empty-mountpoint"
        };
        if !dest.exists() {
            fs::create_dir_all(&dest).map_err(|e| format!("mkdir {}: {e}", dest.display()))?;
            set_mode(&dest, 0o755)?;
        }
        mountpoints.push(((*name).to_string(), source));
    }
    let kmsg = root.join("dev/kmsg");
    let kmsg_marker = if kmsg.is_file() {
        false
    } else if kmsg.exists() {
        return Err("dev/kmsg exists and is not a regular file".into());
    } else {
        fs::write(&kmsg, b"").map_err(|e| format!("create {}: {e}", kmsg.display()))?;
        set_mode(&kmsg, 0o644)?;
        true
    };
    Ok(LayerRootFiles {
        contexts,
        dev_from_layer,
        dev_copied,
        dev_skipped,
        mountpoints,
        kmsg_marker,
    })
}

fn tar_rel(raw: &Path) -> String {
    let text = raw.to_string_lossy();
    text.trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

fn property_area_rel(name: &str) -> bool {
    name == "dev/__properties__" || name.starts_with("dev/__properties__/")
}

fn dev_rel(name: &str) -> bool {
    name == "dev" || name.starts_with("dev/")
}

fn context_rel(name: &str) -> bool {
    CONTEXT_FILES.contains(&name)
}

fn mountpoint_rel(name: &str) -> bool {
    MOUNTPOINTS.contains(&name)
}

fn write_provenance(
    root: &Path,
    layer: &Path,
    copied: &[String],
    root_files: &LayerRootFiles,
) -> Result<(), String> {
    let mut libraries = String::new();
    for rel in copied {
        let hash = sha256_file(&root.join(rel))?;
        libraries.push_str(&format!("copied {rel} sha256 {hash}\n"));
    }
    let mut contexts = String::new();
    for rel in &root_files.contexts {
        let hash = sha256_file(&root.join(rel))?;
        contexts.push_str(&format!("property_context {rel} sha256 {hash}\n"));
    }
    let dev = if root_files.dev_from_layer {
        "from-layer"
    } else {
        "empty-mountpoint"
    };
    let mut dev_files = String::new();
    for rel in &root_files.dev_copied {
        let hash = sha256_file(&root.join(rel))?;
        dev_files.push_str(&format!("dev_file {rel} sha256 {hash}\n"));
    }
    let mut skipped = String::new();
    for rel in &root_files.dev_skipped {
        skipped.push_str(&format!("dev_node_not_copied {rel}\n"));
    }
    let mut mounts = String::new();
    for (name, source) in &root_files.mountpoints {
        mounts.push_str(&format!("mountpoint {name} {source}\n"));
    }
    let kmsg = if root_files.kmsg_marker {
        "kernel_log_marker dev/kmsg empty-regular-file\n"
    } else {
        "kernel_log_marker dev/kmsg already-regular-file\n"
    };
    let text = format!(
        "kind original-init-probe\n\
         layer {}\n\
         not_play_store true\n\
         not_redroid_boot true\n\
         original system/bin/init\n\
         interpreter /system/bin/bootstrap/linker64\n\
         closure transitive-dt-needed\n\
         {libraries}\
         {contexts}\
         dev_directory {dev}\n\
         {dev_files}\
         {skipped}\
         {mounts}\
         {kmsg}\
         dev_property_area_not_copied true\n\
         servicemanager_ready_not_seeded true\n\
         property_area_not_seeded true\n\
         measured_6d5f448_stop libext2_uuid.so needed by libext4_utils.so\n\
         measured_90882eb_prctl_set_vma EBADF on bss 0x80004c5000/0x13000 and 0x80002f9000/0x1000\n\
         measured_372d08f_stop PropertyInit SIGABRT after mkdir /dev/__properties__ ENOENT and plat_property_contexts ENOENT\n\
         measured_14a42a5_stop MountExtraFilesystems CHECKCALL of tmpfs on /bootstrap-apex ENOENT after /apex mounted and access /system/bin/recovery ENOENT\n\
         measured_a6e5306_stop second stage logged; property contexts read; no property_info; no mount after umount2 of /debug_ramdisk; writev(fd 2)=149 payload not in that trace\n\
         file_vma_ends_on_4kib_guest_page true\n\
         syscall_trace_is_not_guest_fd_2 true\n\
         prctl_set_vma_uses_4kib_guest_granule true\n\
         historical_2026_09_27_linker_stops_are_not_this_measurement true\n\
         mremap_seqpacket_rt_tgsigqueueinfo_were_not_the_measured_stop true\n\
         acceptance_platform apple-silicon-macos-xnu\n\
         linux_stage_is_not_acceptance true\n\
         executed false\n",
        layer.display()
    );
    let path = root
        .parent()
        .ok_or("init root has no parent")?
        .join("provenance.txt");
    fs::write(path, text).map_err(|e| e.to_string())
}

/// Run init for at most eight seconds. Guest stdout and stderr are files,
/// not pipes: a 64 KiB pipe stalled the previous Mac capture after the
/// guest had already exited. The full trace is `init-probe.txt` next to
/// the root. Exit success means the observation was recorded. It does
/// not mean init booted.
pub fn run_init(linux_run: &Path) -> Result<(), String> {
    super::property::print_host();
    println!("init-probe original-init not-a-boot");
    if !linux_run.is_file() {
        return Err(format!("linux-run is not a file at {}", linux_run.display()));
    }
    let root = init_root();
    if !root.join("system/bin/init").is_file() {
        return Err("init root is not staged; run bionic-smoke --prepare-init".into());
    }
    let parent = root
        .parent()
        .ok_or("init root has no parent")?
        .to_path_buf();
    let stdout_path = parent.join("init-guest.stdout");
    let stderr_path = parent.join("init-guest.stderr");
    let report_path = parent.join("init-probe.txt");
    let stdout_file = File::create(&stdout_path)
        .map_err(|e| format!("create {}: {e}", stdout_path.display()))?;
    let stderr_file = File::create(&stderr_path)
        .map_err(|e| format!("create {}: {e}", stderr_path.display()))?;
    let mut command = launch_command(linux_run, &root, INIT_IDENTITY, None, &[INIT_GUEST]);
    command
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    let mut child = command
        .spawn()
        .map_err(|e| format!("start linux-run {}: {e}", INIT_GUEST))?;
    let pid = child.id();
    let code = wait_child(&mut child, Duration::from_secs(8));
    let timed_out = code.is_none();
    let out = read_lossy(&stdout_path)?;
    let err = read_lossy(&stderr_path)?;
    let observation = first_observation(&out, &err, code, timed_out);
    let mut report = format_guest("init", pid, code, &out, &err);
    report.push_str(&format!("init-probe: first observation: {observation}\n"));
    report.push_str(&format!(
        "init-probe: pid={pid} exit={code:?} timed_out={timed_out}\n"
    ));
    report.push_str("init-probe: not a boot\n");
    fs::write(&report_path, &report).map_err(|e| format!("write {}: {e}", report_path.display()))?;
    let last_trace = err
        .lines()
        .rev()
        .find(|line| line.starts_with("[linux] ") || line.starts_with("[linux-abi] "))
        .unwrap_or("(no trace line)");
    println!(
        "init-probe: syscall trace is the diagnostics descriptor, not guest fd 2"
    );
    println!("init-probe: last trace: {last_trace}");
    println!("init-probe: trace file {}", report_path.display());
    println!("init-probe: guest stdout {}", stdout_path.display());
    println!("init-probe: guest stderr {}", stderr_path.display());
    println!(
        "init-probe: trace bytes stdout={} stderr={}",
        out.len(),
        err.len()
    );
    println!("init-probe: first observation: {observation}");
    println!("init-probe: pid={pid} exit={code:?} timed_out={timed_out}");
    println!("init-probe: not a boot");
    if err.contains("POSIX lock process admission") || err.contains("stage=standalone-owner") {
        return Err(format!(
            "init-probe: first blocker: admission failed before init was loaded\n{observation}"
        ));
    }
    if !err.contains("[linux] ") && !err.contains("[linux-abi] ") {
        return Err(format!(
            "init-probe: first blocker: linux-run produced no trace\n{observation}"
        ));
    }
    Ok(())
}

fn wait_child(child: &mut std::process::Child, limit: Duration) -> Option<i32> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) if start.elapsed() >= limit => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
}

fn read_lossy(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Classify a trace. The first negative syscall leave is reported on its
/// own: init survives the early `newfstatat("/dev/__properties__")` ENOENT.
/// A stage is named only from a log line or from `PropertyInit` creating
/// `property_info`. Guest stdio is `/dev/null` before those logs, so a
/// missing `init first stage started!` is not evidence about `main`.
/// The last `[kmsg]` line before SIGABRT is recorded as that line, not as
/// the fatal. A `[linux-trace] stdio` line is the captured fd 0/1/2 write.
/// There is no `init ok` here.
pub(crate) fn first_observation(
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
    timed_out: bool,
) -> String {
    if stderr.contains("POSIX lock process admission") || stderr.contains("stage=standalone-owner")
    {
        return "admission failed before the guest was loaded".into();
    }
    let mut text = stage_from(stdout, stderr);
    match first_failed_leave(stderr) {
        Some(line) => {
            text.push_str("; first failed syscall (survived; not the stop) ");
            text.push_str(&line);
        }
        None => text.push_str("; first failed syscall none"),
    }
    if let Some(line) = abort_leave(stderr) {
        text.push_str("; abort ");
        text.push_str(&line);
    }
    if let Some(line) = kmsg_before_abort(stderr) {
        text.push_str("; last kmsg before abort ");
        text.push_str(&line);
    }
    if let Some(line) = stdio_before_abort(stderr) {
        text.push_str("; stdio before abort ");
        text.push_str(&line);
    }
    if timed_out {
        let last = stderr
            .lines()
            .rev()
            .find(|line| line.starts_with("[linux] ") || line.starts_with("[linux-abi] "))
            .unwrap_or("(no trace line)");
        text.push_str("; still running at the bound; last trace ");
        text.push_str(last);
    } else {
        text.push_str(&format!("; exit={exit_code:?}"));
    }
    if let Some(line) = linker_stop(stdout).or_else(|| linker_stop(stderr)) {
        text.push_str("; linker: ");
        text.push_str(&line);
    }
    text
}

fn stage_from(stdout: &str, stderr: &str) -> String {
    let second = stdout.contains("init second stage started!")
        || stderr.contains("init second stage started!");
    let first = stdout.contains("init first stage started!")
        || stderr.contains("init first stage started!");
    if second {
        return "stage second: log \"init second stage started!\"".into();
    }
    if created_property_info(stderr) {
        return "stage second: PropertyInit created /dev/__properties__/property_info".into();
    }
    if first {
        return "stage first: log \"init first stage started!\"".into();
    }
    "stage unconfirmed".into()
}

/// `open`/`openat` of `property_info` with `O_CREAT` and a nonnegative
/// result. `SecondStageMain` is what calls `PropertyInit`.
fn created_property_info(stderr: &str) -> bool {
    stderr.lines().any(|line| {
        let Some(rest) = line.strip_prefix("[linux] ") else {
            return false;
        };
        if !rest.contains(" leave]") {
            return false;
        }
        let Some((call, result)) = rest.rsplit_once(" = ") else {
            return false;
        };
        let token = result.split_whitespace().next().unwrap_or("");
        if token.is_empty() || token.starts_with('-') {
            return false;
        }
        if !call.starts_with("openat(") && !call.starts_with("open(") {
            return false;
        }
        let Some(path_at) = call.find("\"/dev/__properties__/property_info\"") else {
            return false;
        };
        let after = &call[path_at + "\"/dev/__properties__/property_info\"".len()..];
        let after = after.trim_start_matches([',', ' ']);
        let flags = after
            .split([',', ')'])
            .next()
            .unwrap_or("")
            .trim();
        parse_u64(flags).is_ok_and(|flags| flags & 0x40 != 0)
    })
}

fn parse_u64(text: &str) -> Result<u64, ()> {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        text.parse().map_err(|_| ())
    }
}

fn abort_leave(stderr: &str) -> Option<String> {
    stderr
        .lines()
        .rev()
        .find(|line| {
            line.starts_with("[linux] rt_tgsigqueueinfo(")
                && line.contains(" leave]")
                && line.contains(" = 0")
        })
        .map(str::to_string)
}

fn kmsg_before_abort(stderr: &str) -> Option<String> {
    line_before_abort(stderr, "[kmsg] ")
}

fn stdio_before_abort(stderr: &str) -> Option<String> {
    line_before_abort(stderr, "[linux-trace] stdio ")
}

fn line_before_abort(stderr: &str, prefix: &str) -> Option<String> {
    let lines: Vec<&str> = stderr.lines().collect();
    let abort_at = lines.iter().rposition(|line| {
        line.starts_with("[linux] rt_tgsigqueueinfo(") && line.contains(" leave]")
    })?;
    lines[..abort_at]
        .iter()
        .rev()
        .find(|line| line.starts_with(prefix))
        .map(|line| (*line).to_string())
}

fn linker_stop(text: &str) -> Option<String> {
    text.lines()
        .find(|line| line.contains("CANNOT LINK EXECUTABLE"))
        .map(|line| line.trim().to_string())
}

fn first_failed_leave(stderr: &str) -> Option<String> {
    stderr.lines().find_map(|line| {
        let syscall = line.starts_with("[linux] ") && line.contains(" leave]");
        if !syscall {
            return None;
        }
        let (_, result) = line.rsplit_once(" = ")?;
        let token = result.split_whitespace().next().unwrap_or("");
        if token.starts_with('-') {
            Some(line.to_string())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{
        context_rel, dev_rel, first_observation, mountpoint_rel, property_area_rel, tar_rel,
    };

    #[test]
    fn property_contexts_are_the_layer_paths_and_the_property_area_is_excluded() {
        assert!(context_rel("system/etc/selinux/plat_property_contexts"));
        assert!(context_rel("plat_property_contexts"));
        assert!(!context_rel("system/etc/selinux/plat_file_contexts"));
        assert!(!context_rel("dev/__properties__/property_info"));
        assert!(dev_rel("dev"));
        assert!(dev_rel("dev/null"));
        assert!(property_area_rel("dev/__properties__"));
        assert!(property_area_rel("dev/__properties__/property_info"));
        assert!(!property_area_rel("dev"));
        assert!(!property_area_rel("dev/null"));
        assert_eq!(
            tar_rel(std::path::Path::new("./dev/__properties__/")),
            "dev/__properties__"
        );
        assert!(mountpoint_rel("bootstrap-apex"));
        assert!(mountpoint_rel("linkerconfig"));
        assert!(!mountpoint_rel("apex"));
        assert!(!mountpoint_rel("dev/__properties__"));
    }

    #[test]
    fn observation_names_the_trace_line_and_not_a_historical_syscall() {
        let trace = "\
[linux] openat(-100, \"/system/bin/init\", 0x0, 0x0) = 3 [pid=9 tid=9 call=1 leave]
[linux] mremap(0x1, 0x1000, 0x2000, 0x1, 0x0) = -38 (ENOSYS) [pid=9 tid=9 call=2 leave]
";
        let text = first_observation("", trace, Some(127), false);
        assert!(text.contains("stage unconfirmed"));
        assert!(!text.contains("did not reach main"));
        assert!(text.contains("mremap"));
        assert!(text.contains("-38"));
        assert!(text.contains("survived; not the stop"));
        assert!(!text.contains("rt_tgsigqueueinfo"));
        assert!(!text.contains("init ok"));
        let started = first_observation("init first stage started!\n", trace, None, true);
        assert!(started.contains("stage first: log \"init first stage started!\""));
        assert!(started.contains("still running at the bound"));
        assert!(!started.contains("did not reach main"));
        let second = "\
[linux] newfstatat(-100, \"/dev/__properties__\", 0x1, 0x0) = -2 (ENOENT) [pid=9 tid=9 call=66 leave]
[linux] openat(-100, \"/dev/__properties__/property_info\", 0x88241, 0x1b6) = 3 [pid=9 tid=9 call=2366 leave]
[kmsg] level=0 mount(\"tmpfs\", \"/bootstrap-apex\", \"tmpfs\", MS_NOEXEC | MS_NOSUID | MS_NODEV, \"mode=0755,uid=0,gid=0\") failed: No such file or directory
[linux-trace] stdio writev fd=2 iov=1 lens=13 requested=13 returned=13 captured=13 payload=\"FATAL example\" [pid=9 tid=9 call=5932]
[linux] rt_tgsigqueueinfo(0x16e82, 0x16e82, 0x6, 0x8005e84000) = 0 [pid=9 tid=9 call=5933 leave]
[linux] exit_group(0x6) [pid=9 tid=9 call=5934 enter]
";
        let reached = first_observation("", second, Some(6), false);
        assert!(reached.contains(
            "stage second: PropertyInit created /dev/__properties__/property_info"
        ));
        assert!(reached.contains("call=66"));
        assert!(reached.contains("survived; not the stop"));
        assert!(reached.contains("abort "));
        assert!(reached.contains("rt_tgsigqueueinfo"));
        assert!(reached.contains("last kmsg before abort"));
        assert!(reached.contains("stdio before abort"));
        assert!(reached.contains("FATAL example"));
        assert!(reached.contains("bootstrap-apex"));
        assert!(!reached.contains("did not reach main"));
        assert!(!reached.contains("init ok"));
        let logged = first_observation("", "init second stage started!\n", Some(0), false);
        assert!(logged.contains("stage second: log \"init second stage started!\""));
        let stopped = first_observation(
            "",
            "linker: CANNOT LINK EXECUTABLE \"/system/bin/init\": library \"libext2_uuid.so\" not found: needed by /system/lib64/libext4_utils.so\n",
            Some(1),
            false,
        );
        assert!(stopped.contains("stage unconfirmed"));
        assert!(stopped.contains("libext2_uuid.so"));
        assert!(stopped.contains("first failed syscall none"));
    }
}

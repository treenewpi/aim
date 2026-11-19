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

/// Copy the bionic root and add original init plus the libraries its
/// transitive `DT_NEEDED` closure asks for. The measured Mac stop was
/// `libext2_uuid.so`, needed by `libext4_utils.so`, which is not a direct
/// dependency of init. Does not write a property area or an init.rc that
/// would make init look successful.
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
    if root.join("dev/__properties__").exists() {
        return Err("init probe root must not contain a property area".into());
    }
    write_provenance(&root, &layer, &copied)?;
    for name in ["init-guest.stdout", "init-guest.stderr", "init-probe.txt"] {
        if let Some(parent) = root.parent() {
            let _ = fs::remove_file(parent.join(name));
        }
    }
    println!(
        "bionic-smoke: original init root {} copied {} closure libraries (staged, not executed)",
        root.display(),
        copied.len()
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

fn write_provenance(root: &Path, layer: &Path, copied: &[String]) -> Result<(), String> {
    let mut libraries = String::new();
    for rel in copied {
        let hash = sha256_file(&root.join(rel))?;
        libraries.push_str(&format!("copied {rel} sha256 {hash}\n"));
    }
    let text = format!(
        "kind original-init-probe\n\
         layer {}\n\
         not_play_store true\n\
         not_redroid_boot true\n\
         original system/bin/init\n\
         interpreter /system/bin/bootstrap/linker64\n\
         closure transitive-dt-needed\n\
         {libraries}\
         servicemanager_ready_not_seeded true\n\
         measured_6d5f448_stop libext2_uuid.so needed by libext4_utils.so\n\
         measured_90882eb_prctl_set_vma EBADF on bss 0x80004c5000/0x13000 and 0x80002f9000/0x1000\n\
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

/// Classify a trace without treating a historical syscall list as the cause.
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
    let main = stdout.contains("init first stage started!")
        || stderr.contains("init first stage started!");
    let failed = first_failed_leave(stderr);
    let linker = linker_stop(stdout).or_else(|| linker_stop(stderr));
    let mut text = match (main, failed, timed_out) {
        (true, Some(line), timeout) => format!(
            "reached main log \"init first stage started!\"; timed_out={timeout}; first failed syscall {line}"
        ),
        (true, None, true) => {
            "reached main log \"init first stage started!\" and was still running at the bound"
                .into()
        }
        (true, None, false) => {
            format!("reached main log \"init first stage started!\"; exit={exit_code:?}")
        }
        (false, Some(line), timeout) => {
            format!("did not reach main; timed_out={timeout}; first failed syscall {line}")
        }
        (false, None, true) => {
            let last = stderr
                .lines()
                .rev()
                .find(|line| line.starts_with("[linux] ") || line.starts_with("[linux-abi] "))
                .unwrap_or("(no trace line)");
            format!("did not reach main; still running at the bound; last trace {last}")
        }
        (false, None, false) => {
            format!("did not reach main; exit={exit_code:?}; no failed syscall leave")
        }
    };
    if let Some(line) = linker {
        text.push_str("; linker: ");
        text.push_str(&line);
    }
    text
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
    use super::first_observation;

    #[test]
    fn observation_names_the_trace_line_and_not_a_historical_syscall() {
        let trace = "\
[linux] openat(-100, \"/system/bin/init\", 0x0, 0x0) = 3 [pid=9 tid=9 call=1 leave]
[linux] mremap(0x1, 0x1000, 0x2000, 0x1, 0x0) = -38 (ENOSYS) [pid=9 tid=9 call=2 leave]
";
        let text = first_observation("", trace, Some(127), false);
        assert!(text.contains("did not reach main"));
        assert!(text.contains("mremap"));
        assert!(text.contains("-38"));
        assert!(!text.contains("rt_tgsigqueueinfo"));
        let started = first_observation("init first stage started!\n", trace, None, true);
        assert!(started.contains("reached main log"));
        assert!(started.contains("timed_out=true"));
        let stopped = first_observation(
            "",
            "linker: CANNOT LINK EXECUTABLE \"/system/bin/init\": library \"libext2_uuid.so\" not found: needed by /system/lib64/libext4_utils.so\n",
            Some(1),
            false,
        );
        assert!(stopped.contains("did not reach main"));
        assert!(stopped.contains("libext2_uuid.so"));
        assert!(stopped.contains("no failed syscall leave"));
    }
}

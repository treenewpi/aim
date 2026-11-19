//! A bounded run of the original `/system/bin/init`.
//!
//! The 2026-09-27 note in `docs/guest-init-contract.md` section 10 says an
//! older `linux-run` stopped `linkerconfig`, `servicemanager`, and `logd`
//! inside `linker64` on `mremap`, `SOCK_SEQPACKET`, and
//! `rt_tgsigqueueinfo`. That note is not a trace of this binary on the
//! current Mac. Those three calls are dispatched in the current
//! `linux-run` source. Original `servicemanager` and `service` have since
//! reached `main` on the Mac. This probe is what measures init.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::manager::copy_tree;
use super::property::{emit_guest, finish, launch};
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
/// `DT_NEEDED` closure asks for. Does not write a property area or an
/// init.rc that would make init look successful.
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
    extract_closure(&layer, &root)?;
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
    write_provenance(&root, &layer)?;
    println!(
        "bionic-smoke: original init root {} (staged, not executed)",
        root.display()
    );
    println!("bionic-smoke: init-probe is an observation, not a boot");
    Ok(root)
}

/// Direct `DT_NEEDED` of init only. Libraries those binaries themselves
/// need stay for the guest linker, so the trace names the first miss.
fn extract_closure(layer: &Path, root: &Path) -> Result<(), String> {
    let exact = [
        "system/bin/init".to_string(),
        BOOTSTRAP_LINKER.to_string(),
    ];
    let found = scan_wanted(layer, root, &exact, &[])?;
    if !root.join("system/bin/init").is_file() {
        return Err(format!("layer has no system/bin/init (copied {found} other files)"));
    }
    let info = read_elf(&fs::read(root.join("system/bin/init")).map_err(|e| e.to_string())?)?;
    let missing: Vec<String> = info
        .needed
        .iter()
        .filter(|name| super::manager::resolve_lib(root, name).is_err())
        .cloned()
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let found = scan_wanted(layer, root, &[], &missing)?;
    let still: Vec<_> = missing
        .iter()
        .filter(|name| super::manager::resolve_lib(root, name).is_err())
        .cloned()
        .collect::<Vec<_>>();
    if !still.is_empty() {
        return Err(format!(
            "layer is missing init's direct libraries {still:?} (found {found} files this pass)"
        ));
    }
    Ok(())
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
        let lib_hit = basenames.iter().any(|item| item == base) && name.starts_with("system/lib64/");
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

fn write_provenance(root: &Path, layer: &Path) -> Result<(), String> {
    let text = format!(
        "kind original-init-probe\n\
         layer {}\n\
         not_play_store true\n\
         not_redroid_boot true\n\
         original system/bin/init\n\
         interpreter /system/bin/bootstrap/linker64\n\
         servicemanager_ready_not_seeded true\n\
         historical_2026_09_27_linker_stops_are_not_this_measurement true\n\
         mremap_seqpacket_rt_tgsigqueueinfo_are_dispatched_in_source_not_measured_here true\n\
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

/// Run init for at most eight seconds and print the trace. Exit success
/// means the observation was recorded. It does not mean init booted.
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
    let mut child = launch(linux_run, &root, INIT_IDENTITY, None, &[INIT_GUEST])?;
    let pid = child.child.id();
    let (code, out, err) = finish(&mut child, Duration::from_secs(8));
    let timed_out = code.is_none();
    emit_guest("init", pid, code, &out, &err);
    let observation = first_observation(&out, &err, code, timed_out);
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
    let main = stdout.contains("init first stage started!");
    let failed = first_failed_leave(stderr);
    match (main, failed, timed_out) {
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
    }
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
    }
}

//! Stage the original `servicemanager` and `service` client from the pinned
//! reDroid layer into their own root.
//!
//! The binaries, libraries, VINTF manifests and SELinux texts are the
//! layer's bytes. `linkerconfig/ld.config.txt` is generated, because
//! reDroid leaves `/linkerconfig` empty until init runs. `dev/__properties__`
//! is also generated: the original `service` waits in
//! `android::base::WaitForProperty("servicemanager.ready", "true")` before
//! it opens `/dev/binder`, and this root has no init to publish that
//! value. The area is the bionic format, and the value is `true` so that
//! wait returns. It is not a binder result and not a claim that
//! servicemanager has registered. This does not execute either program.
//! Staging on Linux is not acceptance: only a later run of the original
//! binaries under `linux-run` on Apple Silicon macOS counts.

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::{
    guest_file, guest_root, read_elf, require_layer, set_mode, sha256_file, write_entry,
    LINKER_GUEST, LINKER_SHA256,
};

pub const SERVICEMANAGER_SHA256: &str =
    "a48b209c2bcd81acf20bd9ce481c3e017c21270da596bf09658680ec0b0fe14e";
pub const SERVICE_SHA256: &str = "16d982757fd2c5bfa68ac63ca2b9f9d456bceea6b7c1228f9237a761d12f7d06";
pub const BOOTSTRAP_LINKER_SHA256: &str =
    "85284627f597726c152445292fd89d63895cd12d80ed97b3d97256da2db8a8ec";
pub const LIBBINDER_SHA256: &str =
    "988b365aa7f0907942bf0685956ab86089c6304302f9013fcb2016efe18aa401";
/// Original `libbinder_ndk.so` from the pinned layer. The probe links it.
pub const LIBBINDER_NDK_SHA256: &str =
    "3eed4eb5a9adba460f510abd749559fb499f8d95aed84cdbe50c55cb722d79c6";
/// Generated guest that calls that library. Not an image file.
pub const PROBE_SHA256: &str = "3f9489b1edb76c7d8d64ed4d5e92f6425c09c54b006259c6206d662276d873e9";
pub const PLAT_SEPOLICY_SHA256: &str =
    "c3390caf754eb7924b638c9f1a156336e80391fae12afbccb56ba01faa790883";
pub const LIBDL_ANDROID_SHA256: &str =
    "739c5716653bcff6700501d98f576957fc299e4f2483c3ad2bd1c0f641e96422";

const EXACT: &[&str] = &[
    "system/bin/servicemanager",
    "system/bin/service",
    "system/bin/bootstrap/linker64",
    "system/lib64/libbase.so",
    "system/lib64/libvintf.so",
    "system/lib64/libcutils.so",
    "system/lib64/liblog.so",
    "system/lib64/libselinux.so",
    "system/lib64/libperfetto_c.so",
    "system/lib64/libbinder.so",
    "system/lib64/libbinder_ndk.so",
    "system/lib64/libutils.so",
    "system/lib64/libc++.so",
    "system/lib64/libtinyxml2.so",
    "system/lib64/libz.so",
    "system/lib64/libpcre2.so",
    "system/lib64/libpackagelistparser.so",
    "system/lib64/libapexsupport.so",
    "system/lib64/libvndksupport.so",
    "system/lib64/libdl_android.so",
    "system/etc/init/servicemanager.rc",
    "system/etc/selinux/plat_sepolicy.cil",
    "system/etc/selinux/plat_service_contexts",
    "system/etc/selinux/plat_file_contexts",
];

/// Generated linker config. Not a file from the image.
pub fn linker_config() -> &'static str {
    "\
# generated for the original servicemanager root; not an original image file
dir.default = /system/bin
dir.default = /apex/com.android.runtime/bin
[default]
namespace.default.isolated = false
namespace.default.search.paths = /system/lib64:/apex/com.android.runtime/lib64/bionic
"
}

pub fn manager_root() -> PathBuf {
    super::stage_dir()
        .parent()
        .expect("redroid stage")
        .join("redroid-16-servicemanager")
        .join("root")
}

/// Copy the audited bionic root and add the original servicemanager closure.
pub fn prepare_manager() -> Result<PathBuf, String> {
    let layer = require_layer()?;
    let bionic = guest_root();
    let linker = guest_file(&bionic, LINKER_GUEST).map_err(|_| {
        format!(
            "bionic root {} has no linker64; run bionic-smoke --prepare first",
            bionic.display()
        )
    })?;
    if sha256_file(&linker)? != LINKER_SHA256 {
        return Err("bionic root linker64 is not the pinned file".into());
    }
    let root = manager_root();
    if root.exists() {
        fs::remove_dir_all(&root).map_err(|e| format!("remove {}: {e}", root.display()))?;
    }
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    copy_tree(&bionic, &root)?;
    extract_originals(&layer, &root)?;
    copy_apex_libdl(&root)?;
    write_probe(&root)?;
    let config = root.join("linkerconfig/ld.config.txt");
    fs::write(&config, linker_config()).map_err(|e| e.to_string())?;
    write_ready_property(&root)?;
    audit(&root)?;
    write_provenance(&root, &layer)?;
    println!(
        "bionic-smoke: original servicemanager root {} (staged, not executed)",
        root.display()
    );
    println!(
        "bionic-smoke: acceptance is a real Apple Silicon Mac running this root under linux-run; this staging is not that run"
    );
    Ok(root)
}

pub(crate) fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    fs::create_dir_all(to).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(from).map_err(|e| format!("read {}: {e}", from.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let dest = to.join(entry.file_name());
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_symlink() {
            let target = fs::read_link(entry.path()).map_err(|e| e.to_string())?;
            let _ = fs::remove_file(&dest);
            std::os::unix::fs::symlink(&target, &dest)
                .map_err(|e| format!("symlink {} -> {}: {e}", dest.display(), target.display()))?;
        } else if kind.is_dir() {
            copy_tree(&entry.path(), &dest)?;
        } else if kind.is_file() {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::copy(entry.path(), &dest).map_err(|e| format!("copy {}: {e}", dest.display()))?;
            let mode = entry
                .metadata()
                .map_err(|e| e.to_string())?
                .permissions()
                .mode()
                & 0o777;
            set_mode(&dest, mode)?;
        }
    }
    Ok(())
}

fn extract_originals(layer: &Path, root: &Path) -> Result<(), String> {
    let mut found = vec![false; EXACT.len()];
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
        let take = EXACT.iter().position(|item| *item == name).is_some()
            || name.starts_with("system/etc/vintf/");
        if !take {
            continue;
        }
        if let Some(index) = EXACT.iter().position(|item| *item == name) {
            found[index] = true;
        }
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        write_entry(&mut entry, &root.join(&name))?;
    }
    let missing: Vec<_> = EXACT
        .iter()
        .zip(found.iter())
        .filter(|(_, ok)| !**ok)
        .map(|(name, _)| *name)
        .collect();
    if !missing.is_empty() {
        return Err(format!("layer is missing {missing:?}"));
    }
    for bin in [
        "system/bin/servicemanager",
        "system/bin/service",
        "system/bin/bootstrap/linker64",
    ] {
        let path = root.join(bin);
        let mode = fs::metadata(&path)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            set_mode(&path, mode | 0o755)?;
        }
    }
    Ok(())
}

fn audit(root: &Path) -> Result<(), String> {
    check_hash(root, "system/bin/servicemanager", SERVICEMANAGER_SHA256)?;
    check_hash(root, "system/bin/service", SERVICE_SHA256)?;
    check_hash(
        root,
        "system/bin/bootstrap/linker64",
        BOOTSTRAP_LINKER_SHA256,
    )?;
    check_hash(root, "system/lib64/libbinder.so", LIBBINDER_SHA256)?;
    check_hash(root, "system/lib64/libbinder_ndk.so", LIBBINDER_NDK_SHA256)?;
    check_hash(root, "system/bin/libbinder-ping", PROBE_SHA256)?;
    let probe =
        read_elf(&fs::read(root.join("system/bin/libbinder-ping")).map_err(|e| e.to_string())?)?;
    if probe.interp.as_deref() != Some("/system/bin/linker64") {
        return Err(format!("libbinder-ping interpreter {:?}", probe.interp));
    }
    require_arm64(&probe, "libbinder-ping")?;
    if !probe.needed.iter().any(|n| n == "libbinder_ndk.so")
        || !probe.needed.iter().any(|n| n == "libc.so")
    {
        return Err(format!("libbinder-ping NEEDED {:?}", probe.needed));
    }
    let ndk = read_elf(
        &fs::read(root.join("system/lib64/libbinder_ndk.so")).map_err(|e| e.to_string())?,
    )?;
    require_arm64(&ndk, "libbinder_ndk.so")?;
    for lib in probe.needed.iter().chain(ndk.needed.iter()) {
        resolve_lib(root, lib)?;
    }
    check_hash(
        root,
        "system/etc/selinux/plat_sepolicy.cil",
        PLAT_SEPOLICY_SHA256,
    )?;
    let libdl = guest_file(root, "/system/lib64/libdl_android.so")?;
    let digest = sha256_file(&libdl)?;
    if digest != LIBDL_ANDROID_SHA256 {
        return Err(format!(
            "libdl_android.so sha256 {digest} != {LIBDL_ANDROID_SHA256}"
        ));
    }
    let bionic_linker = guest_file(root, LINKER_GUEST)?;
    if sha256_file(&bionic_linker)? != LINKER_SHA256 {
        return Err("servicemanager root lost the pinned apex linker64".into());
    }
    let sm =
        read_elf(&fs::read(root.join("system/bin/servicemanager")).map_err(|e| e.to_string())?)?;
    if sm.interp.as_deref() != Some("/system/bin/bootstrap/linker64") {
        return Err(format!("servicemanager interpreter {:?}", sm.interp));
    }
    let service = read_elf(&fs::read(root.join("system/bin/service")).map_err(|e| e.to_string())?)?;
    if service.interp.as_deref() != Some("/system/bin/linker64") {
        return Err(format!("service interpreter {:?}", service.interp));
    }
    require_arm64(&sm, "servicemanager")?;
    require_arm64(&service, "service")?;
    let mut queue = sm.needed.clone();
    queue.extend(service.needed.iter().cloned());
    let mut seen = std::collections::BTreeSet::new();
    while let Some(lib) = queue.pop() {
        if !seen.insert(lib.clone()) {
            continue;
        }
        let path = resolve_lib(root, &lib)?;
        if lib == "libc.so" && !path.ends_with("apex/com.android.runtime/lib64/bionic/libc.so") {
            return Err(format!("libc.so resolved to {}", path.display()));
        }
        let info = read_elf(&fs::read(&path).map_err(|e| e.to_string())?)?;
        require_arm64(&info, &lib)?;
        queue.extend(info.needed);
    }
    let config =
        fs::read_to_string(root.join("linkerconfig/ld.config.txt")).map_err(|e| e.to_string())?;
    if config != linker_config() {
        return Err("linker config is not the generated servicemanager text".into());
    }
    Ok(())
}

/// `system/lib64/libdl_android.so` is the layer's symlink into the runtime
/// apex. The bionic stage does not unpack that file.
fn copy_apex_libdl(root: &Path) -> Result<(), String> {
    let apex = super::stage_dir().join("original/com.android.runtime.apex");
    let source = android_image_extract::source::FileSource::open(&apex)
        .map_err(|e| format!("open runtime apex: {e}"))?;
    android_image_extract::apex::with_payload(&source, |manifest, tree, format| {
        if manifest.name != "com.android.runtime" || format != "ext4" {
            return Err(android_image_extract::invalid(
                "runtime apex is not the pinned payload".to_string(),
            ));
        }
        let rel = "lib64/bionic/libdl_android.so";
        let id = android_image_extract::tree::lookup(tree, rel)
            .map_err(|e| android_image_extract::invalid(e.to_string()))?
            .ok_or_else(|| android_image_extract::invalid("apex missing libdl_android.so"))?;
        let bytes = android_image_extract::tree::read_file(tree, id, 32 << 20)
            .map_err(|e| android_image_extract::invalid(e.to_string()))?;
        let to = root.join("apex/com.android.runtime").join(rel);
        fs::create_dir_all(to.parent().unwrap())
            .map_err(|e| android_image_extract::invalid(e.to_string()))?;
        fs::write(&to, bytes).map_err(|e| android_image_extract::invalid(e.to_string()))?;
        let node = tree
            .node(id)
            .map_err(|e| android_image_extract::invalid(e.to_string()))?;
        set_mode(&to, node.mode & 0o777).map_err(android_image_extract::invalid)?;
        Ok(())
    })
    .map_err(|e| format!("runtime apex libdl_android: {e}"))
}

pub(crate) fn resolve_lib(root: &Path, lib: &str) -> Result<PathBuf, String> {
    for dir in ["/system/lib64", "/apex/com.android.runtime/lib64/bionic"] {
        if let Ok(path) = guest_file(root, &format!("{dir}/{lib}")) {
            return Ok(path);
        }
    }
    Err(format!(
        "NEEDED {lib} is not in /system/lib64 or the runtime apex"
    ))
}

pub(crate) fn require_arm64(info: &super::ElfInfo, what: &str) -> Result<(), String> {
    if info.machine != 183 {
        return Err(format!("{what} machine {}", info.machine));
    }
    if info
        .aligns
        .iter()
        .any(|align| *align != 0 && *align < 16384)
    {
        return Err(format!("{what} align {:?}", info.aligns));
    }
    Ok(())
}

fn write_probe(root: &Path) -> Result<(), String> {
    let path = root.join("system/bin/libbinder-ping");
    fs::write(&path, include_bytes!("../probe/libbinder-ping"))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    set_mode(&path, 0o755)?;
    Ok(())
}

fn check_hash(root: &Path, rel: &str, expect: &str) -> Result<(), String> {
    let hash = sha256_file(&root.join(rel))?;
    if hash != expect {
        return Err(format!("{rel} sha256 {hash} != {expect}"));
    }
    Ok(())
}

/// Bionic's `/dev/__properties__` with one value, so the original client's
/// `WaitForProperty` can observe it. The files are generated.
pub const READY_PROPERTY: &str = "servicemanager.ready";
const READY_CONTEXT: &str = "u:object_r:default_prop:s0";

fn write_ready_property(root: &Path) -> Result<(), String> {
    use aim_android_init::props::{build_trie, NoWake, PropertyAreas, PropertyInfoEntry};

    let info = build_trie(
        &[PropertyInfoEntry::new(
            READY_PROPERTY,
            READY_CONTEXT,
            "bool",
            true,
        )],
        READY_CONTEXT,
        "string",
    )?;
    let areas = PropertyAreas::new(info.clone())?;
    areas
        .add(READY_PROPERTY, b"true", &NoWake)
        .map_err(|error| format!("{READY_PROPERTY}: {error:?}"))?;
    if areas.get(READY_PROPERTY).as_deref() != Some("true") {
        return Err("generated servicemanager.ready did not read back as true".into());
    }
    let dir = root.join("dev/__properties__");
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    set_mode(&dir, 0o755)?;
    let write = |name: &str, bytes: &[u8]| -> Result<(), String> {
        let path = dir.join(name);
        fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        set_mode(&path, 0o444)?;
        Ok(())
    };
    write("property_info", &info)?;
    let area = areas
        .area(READY_CONTEXT)
        .ok_or("ready context has no property area")?;
    write(READY_CONTEXT, &area.bytes())?;
    write("properties_serial", &areas.serial_area().bytes())?;
    Ok(())
}

fn write_provenance(root: &Path, layer: &Path) -> Result<(), String> {
    let mut text = format!(
        "kind original-servicemanager-root\n\
         layer {}\n\
         layer_bytes {}\n\
         not_play_store true\n\
         not_redroid_boot true\n\
         not_synthetic_pie true\n\
         servicemanager_sha256 {SERVICEMANAGER_SHA256}\n\
         service_sha256 {SERVICE_SHA256}\n\
         libbinder_sha256 {LIBBINDER_SHA256}\n\
         bootstrap_linker_sha256 {BOOTSTRAP_LINKER_SHA256}\n\
         libdl_android_sha256 {LIBDL_ANDROID_SHA256}\n\
         generated linkerconfig/ld.config.txt\n\
         generated dev/__properties__ servicemanager.ready=true\n\
         generated_property_is_not_a_binder_result true\n\
         generated_property_is_not_a_property_service true\n\
         original system/lib64/libbinder_ndk.so\n\
         generated system/bin/libbinder-ping\n\
         probe_links_original_libbinder_ndk true\n\
         probe_is_not_an_original_image_file true\n\
         probe_is_not_the_synthetic_binder_pie true\n\
         selinux_texts original plat_sepolicy.cil and service contexts\n\
         selinux_decisions the existing permissive runtime, not a policy loaded from this root\n\
         acceptance_platform apple-silicon-macos-xnu\n\
         linux_stage_is_not_acceptance true\n",
        layer.display(),
        super::LAYER_SIZE
    );
    text.push_str("executed false\n");
    let path = root
        .parent()
        .ok_or("manager root has no parent")?
        .join("provenance.txt");
    fs::write(path, text).map_err(|e| e.to_string())
}

/// A completed `openat` of `/dev/binder` whose result is a file descriptor.
/// A path mentioned anywhere else, or an open that returned an errno, is
/// not an open.
pub fn binder_device_opened(stderr: &str) -> bool {
    for line in stderr.lines() {
        let Some(rest) = line.strip_prefix("[linux] openat(") else {
            continue;
        };
        if !rest.ends_with(" leave]") || !rest.contains("\"/dev/binder\"") {
            continue;
        }
        let Some((_, result)) = rest.rsplit_once(" = ") else {
            continue;
        };
        let token = result.split_whitespace().next().unwrap_or("");
        if token.starts_with('-') {
            continue;
        }
        if token.parse::<u32>().is_ok() {
            let args = rest.split(" = ").next().unwrap_or("");
            if args.contains("\"/dev/binder\"") && !args.contains("\"/dev/binder/") {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_and_generated_config_are_marked() {
        for hash in [
            SERVICEMANAGER_SHA256,
            SERVICE_SHA256,
            BOOTSTRAP_LINKER_SHA256,
            LIBBINDER_SHA256,
            PLAT_SEPOLICY_SHA256,
            LIBDL_ANDROID_SHA256,
            LIBBINDER_NDK_SHA256,
            PROBE_SHA256,
        ] {
            assert_eq!(hash.len(), 64);
        }
        assert!(linker_config().contains("not an original image file"));
        assert!(linker_config().contains("/system/lib64"));
        let dir = std::env::temp_dir().join(format!("aim-ready-prop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        write_ready_property(&dir).unwrap();
        let prop = dir.join("dev/__properties__");
        let bytes = fs::read(prop.join(READY_CONTEXT)).unwrap();
        let reader = aim_android_init::props::PropAreaReader::new(&bytes).unwrap();
        let info = reader.find(READY_PROPERTY).unwrap();
        assert_eq!(reader.read(info).unwrap().value, "true");
        assert!(prop.join("property_info").is_file());
        assert!(prop.join("properties_serial").is_file());
        let probe_bytes = include_bytes!("../probe/libbinder-ping");
        let probe = read_elf(probe_bytes).unwrap();
        assert_eq!(probe.machine, 183);
        assert_eq!(probe.interp.as_deref(), Some("/system/bin/linker64"));
        assert!(probe.needed.iter().any(|n| n == "libbinder_ndk.so"));
        assert!(probe.needed.iter().any(|n| n == "libc.so"));
        assert!(probe.aligns.iter().all(|align| *align >= 16384));
        let text = String::from_utf8_lossy(probe_bytes);
        assert!(text.contains("binder reply: value="));
        assert!(text.contains("serving %s pid="));
        assert!(text.contains("binder missing:"));
        let file = dir.join("libbinder-ping");
        fs::write(&file, probe_bytes).unwrap();
        assert_eq!(sha256_file(&file).unwrap(), PROBE_SHA256);
        let _ = fs::remove_dir_all(&dir);
        assert!(!binder_device_opened(
            "openat(\"/dev/binder\"\n[linux] ioctl(0x3, 0x1, 0x2)\n"
        ));
        assert!(!binder_device_opened(
            "[linux] openat(-100, \"/dev/binder\", 0x80002, 0x0) = -13 (EACCES) [pid=1 tid=1 call=0 leave]"
        ));
        assert!(binder_device_opened(
            "[linux] openat(-100, \"/dev/binder\", 0x80002, 0x0) = 3 [pid=1 tid=1 call=0 leave]"
        ));
        assert!(!binder_device_opened(
            "[linux] openat(-100, \"/dev/binderfs/hwbinder\", 0x80002, 0x0) = 3 [pid=1 tid=1 call=0 leave]"
        ));
    }

    #[test]
    fn original_closure_matches_the_pinned_layer() {
        if !super::super::layer_path().is_file() || !guest_root().join("apex").is_dir() {
            aim_paths::skip(
                "pinned reDroid layer or the prepared bionic root is absent; not executed",
            );
            return;
        }
        let before = sha256_file(&guest_file(&guest_root(), LINKER_GUEST).unwrap()).unwrap();
        let root = prepare_manager().unwrap();
        let after = sha256_file(&guest_file(&guest_root(), LINKER_GUEST).unwrap()).unwrap();
        assert_eq!(before, after);
        assert_eq!(before, LINKER_SHA256);
        assert!(root.join("system/bin/servicemanager").is_file());
        assert!(root.join("system/etc/vintf/manifest.xml").is_file());
        let note = fs::read_to_string(root.parent().unwrap().join("provenance.txt")).unwrap();
        assert!(note.contains("not_synthetic_pie true"));
        assert!(note.contains("executed false"));
        assert!(note.contains("linux_stage_is_not_acceptance true"));
        assert!(note.contains("generated dev/__properties__ servicemanager.ready=true"));
        assert!(note.contains("probe_is_not_an_original_image_file true"));
        assert!(note.contains("generated_property_is_not_a_property_service true"));
        assert_eq!(
            sha256_file(&root.join("system/lib64/libbinder_ndk.so")).unwrap(),
            LIBBINDER_NDK_SHA256
        );
        assert_eq!(
            sha256_file(&root.join("system/bin/libbinder-ping")).unwrap(),
            PROBE_SHA256
        );
        let ready = fs::read(root.join("dev/__properties__").join(READY_CONTEXT)).unwrap();
        let reader = aim_android_init::props::PropAreaReader::new(&ready).unwrap();
        let found = reader.find(READY_PROPERTY).unwrap();
        assert_eq!(reader.read(found).unwrap().value, "true");
        assert_eq!(
            sha256_file(&root.join("system/bin/service")).unwrap(),
            SERVICE_SHA256
        );
        assert_eq!(
            sha256_file(&root.join("system/bin/servicemanager")).unwrap(),
            SERVICEMANAGER_SHA256
        );
    }
}

//! The owner an image inode was built with, when the extract kept the
//! mode and dropped `dev.aim.android-inode`.
//!
//! libcutils `get_fs_config` reads the partition `fs_config_files` /
//! `fs_config_dirs` binaries (most specific rule first), then the compiled
//! `android_files` / `android_dirs` table. The first match is that path's
//! uid and gid. The mode is not applied: the extract already stored it in
//! the host inode, and a different mode would publish permission bits the
//! inode does not have. File capabilities in the record are not consulted;
//! a service's caps come from its init.rc.

use std::ffi::CString;
use std::sync::Mutex;

use super::attrs::Attr;

struct Rule {
    uid: u32,
    gid: u32,
    prefix: String,
}

struct Loaded {
    files: Vec<Rule>,
    dirs: Vec<Rule>,
}

static LOADED: Mutex<Option<Loaded>> = Mutex::new(None);

const FILE_CONFIGS: &[&str] = &[
    "system/etc/fs_config_files",
    "vendor/etc/fs_config_files",
    "oem/etc/fs_config_files",
    "odm/etc/fs_config_files",
    "product/etc/fs_config_files",
    "system_ext/etc/fs_config_files",
];

const DIR_CONFIGS: &[&str] = &[
    "system/etc/fs_config_dirs",
    "vendor/etc/fs_config_dirs",
    "oem/etc/fs_config_dirs",
    "odm/etc/fs_config_dirs",
    "product/etc/fs_config_dirs",
    "system_ext/etc/fs_config_dirs",
];

/// `(uid, gid, prefix)` in libcutils' first-match order. Modes live in the
/// AOSP table and are not copied onto the inode.
const FILES: &[(u32, u32, &str)] = &[
    (1000, 1000, "data/app/*"),
    (1000, 1000, "data/app-ephemeral/*"),
    (1000, 1000, "data/app-private/*"),
    (10000, 10000, "data/data/*"),
    (1023, 1023, "data/media/*"),
    (0, 0, "default.prop"),
    (0, 0, "system/etc/prop.default"),
    (0, 0, "odm/build.prop"),
    (0, 0, "odm/default.prop"),
    (0, 0, "odm/etc/build.prop"),
    (0, 0, "odm/etc/fs_config_dirs"),
    (0, 0, "odm/etc/fs_config_files"),
    (0, 0, "oem/etc/fs_config_dirs"),
    (0, 0, "oem/etc/fs_config_files"),
    (0, 0, "product/build.prop"),
    (0, 0, "product/etc/fs_config_dirs"),
    (0, 0, "product/etc/fs_config_files"),
    (0, 0, "system_ext/build.prop"),
    (0, 0, "system_ext/etc/fs_config_dirs"),
    (0, 0, "system_ext/etc/fs_config_files"),
    (0, 2000, "system/bin/crash_dump32"),
    (0, 2000, "system/bin/crash_dump64"),
    (0, 2000, "system/bin/debuggerd"),
    (1036, 1036, "system/bin/logd"),
    (0, 0, "system/bin/secilc"),
    (0, 0, "system/bin/uncrypt"),
    (0, 0, "system/build.prop"),
    (0, 0, "system/etc/fs_config_dirs"),
    (0, 0, "system/etc/fs_config_files"),
    (0, 2000, "system/etc/init.goldfish.rc"),
    (0, 2000, "system/etc/init.goldfish.sh"),
    (0, 2000, "system/etc/init.ril"),
    (0, 0, "system/etc/ppp/*"),
    (0, 0, "system/etc/rc.*"),
    (0, 0, "vendor/bin/install-recovery.sh"),
    (0, 0, "vendor/build.prop"),
    (0, 0, "vendor/default.prop"),
    (0, 0, "vendor/etc/recovery.img"),
    (0, 0, "vendor/etc/fs_config_dirs"),
    (0, 0, "vendor/etc/fs_config_files"),
    (0, 0, "system/xbin/procmem"),
    (0, 2000, "system/xbin/su"),
    (1000, 2000, "system/bin/inputflinger"),
    (0, 2000, "system/bin/run-as"),
    (0, 2000, "system/bin/simpleperf_app_runner"),
    (0, 0, "first_stage_ramdisk/system/bin/e2fsck"),
    (0, 0, "first_stage_ramdisk/system/bin/linker64"),
    (0, 0, "first_stage_ramdisk/system/bin/resize2fs"),
    (0, 0, "first_stage_ramdisk/system/bin/snapuserd"),
    (0, 0, "first_stage_ramdisk/system/bin/snapuserd_ramdisk"),
    (0, 0, "first_stage_ramdisk/system/bin/tune2fs"),
    (0, 0, "first_stage_ramdisk/system/bin/fsck.f2fs"),
    (0, 0, "bin/*"),
    (0, 0, "first_stage.sh"),
    (0, 2000, "fstab.*"),
    (0, 2000, "init*"),
    (0, 0, "*.rc"),
    (0, 2000, "odm/bin/*"),
    (0, 0, "odm/framework/*"),
    (0, 0, "odm/app/*"),
    (0, 0, "odm/priv-app/*"),
    (0, 2000, "product/bin/*"),
    (0, 0, "product/framework/*"),
    (0, 0, "product/app/*"),
    (0, 0, "product/priv-app/*"),
    (0, 2000, "system/bin/*"),
    (0, 2000, "system/xbin/*"),
    (0, 0, "system/framework/*"),
    (0, 0, "system/app/*"),
    (0, 0, "system/priv-app/*"),
    (0, 2000, "system_ext/bin/*"),
    (0, 0, "system_ext/framework/*"),
    (0, 0, "system_ext/app/*"),
    (0, 0, "system_ext/priv-app/*"),
    (0, 2000, "vendor/bin/*"),
    (0, 2000, "vendor/xbin/*"),
    (0, 0, "vendor/framework/*"),
    (0, 0, "vendor/app/*"),
    (0, 0, "vendor/priv-app/*"),
];

const DIRS: &[(u32, u32, &str)] = &[
    (1000, 2001, "cache"),
    (0, 0, "config"),
    (1000, 1000, "data/app"),
    (1000, 1000, "data/app-private"),
    (1000, 1000, "data/app-ephemeral"),
    (0, 0, "data/dalvik-cache"),
    (1000, 1000, "data/data"),
    (2000, 2000, "data/local/tmp"),
    (2000, 2000, "data/local"),
    (1014, 1014, "data/misc/dhcp"),
    (1037, 1037, "data/misc/shared_relro"),
    (1000, 9998, "data/misc"),
    (1023, 1023, "data/media/Music"),
    (1023, 1023, "data/media"),
    (0, 0, "data/preloads"),
    (1000, 1000, "data"),
    (0, 1000, "mnt"),
    (0, 2000, "product/bin"),
    (0, 0, "sdcard"),
    (0, 1028, "storage"),
    (0, 2000, "system/bin"),
    (0, 0, "system/etc/ppp"),
    (0, 2000, "system/vendor"),
    (0, 2000, "system/xbin"),
    (0, 2000, "system_ext/bin"),
    (0, 2000, "vendor/bin"),
    (0, 2000, "vendor"),
];

/// Drop a cached read of the image's `fs_config_*` files. The next stat
/// reads them again. Tests write a fixture after the first stat.
#[cfg(test)]
pub(super) fn reload() {
    *LOADED.lock().unwrap() = None;
}

/// uid and gid of `guest` from the image's fs_config, when it has no
/// android-inode. `directory` selects the directory table. The host mode
/// is left as it is.
pub(super) fn published(guest: &str, directory: bool) -> Option<Attr> {
    let path = guest.trim_start_matches('/');
    if path.is_empty() {
        return None;
    }
    let mut cache = LOADED.lock().unwrap();
    if cache.is_none() {
        *cache = Some(load());
    }
    let loaded = cache.as_ref().unwrap();
    let found = if directory {
        find(&loaded.dirs, true, path).or_else(|| find_static(DIRS, true, path))
    } else {
        find(&loaded.files, false, path).or_else(|| find_static(FILES, false, path))
    };
    found.map(|(uid, gid)| Attr {
        uid: Some(uid),
        gid: Some(gid),
        mode: None,
    })
}

fn find(rules: &[Rule], directory: bool, path: &str) -> Option<(u32, u32)> {
    rules
        .iter()
        .find(|rule| rule_matches(directory, &rule.prefix, path))
        .map(|rule| (rule.uid, rule.gid))
}

fn find_static(rules: &[(u32, u32, &str)], directory: bool, path: &str) -> Option<(u32, u32)> {
    rules
        .iter()
        .find(|rule| rule_matches(directory, rule.2, path))
        .map(|rule| (rule.0, rule.1))
}

fn load() -> Loaded {
    Loaded {
        files: read_configs(FILE_CONFIGS),
        dirs: read_configs(DIR_CONFIGS),
    }
}

fn read_configs(names: &[&str]) -> Vec<Rule> {
    let mut rules = Vec::new();
    let root = crate::vfs::root();
    for name in names {
        let Some(bytes) = read_nofollow(&root.join(name)) else {
            continue;
        };
        rules.extend(parse(&bytes));
    }
    rules
}

/// `O_NOFOLLOW`: a config path that leaves the image is not a record.
fn read_nofollow(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: NUL-terminated path.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: open fd, local buffer.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            let err = std::io::Error::last_os_error().raw_os_error();
            if err == Some(libc::EINTR) {
                continue;
            }
            unsafe { libc::close(fd) };
            return None;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    unsafe { libc::close(fd) };
    Some(out)
}

/// `fs_path_config_from_file`: uint16 len, mode, uid, gid, uint64
/// capabilities, then a NUL-terminated prefix. `len` is the whole record,
/// including the padding the generator adds to keep the next record
/// 8-byte aligned. A short or unterminated record ends the file.
fn parse(bytes: &[u8]) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut at = 0;
    while at + 16 <= bytes.len() {
        let len = u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
        if len < 16 || at + len > bytes.len() {
            break;
        }
        let uid = u16::from_le_bytes(bytes[at + 4..at + 6].try_into().unwrap()) as u32;
        let gid = u16::from_le_bytes(bytes[at + 6..at + 8].try_into().unwrap()) as u32;
        let prefix = &bytes[at + 16..at + len];
        let Some(end) = prefix.iter().position(|byte| *byte == 0) else {
            break;
        };
        let Ok(prefix) = std::str::from_utf8(&prefix[..end]) else {
            break;
        };
        rules.push(Rule {
            uid,
            gid,
            prefix: prefix.to_string(),
        });
        at += len;
    }
    rules
}

/// libcutils `fs_config_cmp`: `fnmatch` with `FNM_NOESCAPE` and no
/// `FNM_PATHNAME`, so `*` crosses `/`. A directory pattern gains a
/// trailing `/*` and the path gains a trailing `/`.
fn rule_matches(directory: bool, prefix: &str, path: &str) -> bool {
    if !directory {
        return glob_match(prefix, path) || alias_match(prefix, path);
    }
    let mut pattern = prefix.to_string();
    if !pattern.ends_with("/*") {
        if pattern.ends_with('/') {
            pattern.push('*');
        } else {
            pattern.push_str("/*");
        }
    }
    let mut input = path.to_string();
    if !input.ends_with('/') {
        input.push('/');
    }
    glob_match(&pattern, &input) || alias_match(&pattern, &input)
}

/// `system/product/<rest>` is also `product/<rest>`, and the same for
/// `system_ext`, `vendor`, and `vendor/odm`.
fn alias_match(pattern: &str, input: &str) -> bool {
    const LOGICAL: &[&str] = &[
        "system/product/",
        "system/system_ext/",
        "system/vendor/",
        "vendor/odm/",
    ];
    if !LOGICAL.iter().any(|prefix| input.starts_with(prefix)) {
        return false;
    }
    let Some((_, rest)) = input.split_once('/') else {
        return false;
    };
    const PARTS: &[&str] = &["odm/", "oem/", "product/", "system_ext/", "vendor/"];
    PARTS.iter().any(|prefix| rest.starts_with(prefix)) && glob_match(pattern, rest)
}

/// `*` matches any span, including an empty one and including `/`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let Some((first, mut rest_pat)) = pattern.split_once('*') else {
        return pattern == text;
    };
    if !text.starts_with(first) {
        return false;
    }
    let mut rest = &text[first.len()..];
    loop {
        if let Some((piece, next)) = rest_pat.split_once('*') {
            if piece.is_empty() {
                rest_pat = next;
                continue;
            }
            let Some(at) = rest.find(piece) else {
                return false;
            };
            rest = &rest[at + piece.len()..];
            rest_pat = next;
        } else {
            return rest.ends_with(rest_pat);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_follow_fs_config_cmp() {
        assert!(rule_matches(false, "system/bin/logd", "system/bin/logd"));
        assert!(!rule_matches(false, "system/bin/logd", "system/bin/log"));
        assert!(rule_matches(false, "system/bin/*", "system/bin/logd"));
        assert!(rule_matches(false, "system/bin/*", "system/bin/hw/foo"));
        assert!(rule_matches(false, "*.rc", "system/etc/init/logd.rc"));
        assert!(!rule_matches(false, "bin/*", "system/bin/logd"));
        assert!(rule_matches(true, "system/bin", "system/bin"));
        assert!(rule_matches(true, "system/bin", "system/bin/hw"));
        assert!(rule_matches(
            false,
            "vendor/bin/*",
            "system/vendor/bin/vold"
        ));
        assert!(rule_matches(true, "vendor/bin", "system/vendor/bin"));
        assert!(!rule_matches(false, "vendor/bin/*", "system/bin/logd"));
    }

    #[test]
    fn a_padded_record_does_not_swallow_the_next() {
        let mut bytes = Vec::new();
        push(&mut bytes, "system/bin/logd", 0o550, 1036, 1036, true);
        push(&mut bytes, "system/bin/*", 0o755, 0, 2000, false);
        let rules = parse(&bytes);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].prefix, "system/bin/logd");
        assert_eq!(rules[1].prefix, "system/bin/*");
        assert_eq!(find(&rules, false, "system/bin/logd"), Some((1036, 1036)));
        assert_eq!(find(&rules, false, "system/bin/sh"), Some((0, 2000)));
    }

    fn push(out: &mut Vec<u8>, prefix: &str, mode: u16, uid: u16, gid: u16, pad: bool) {
        let text = prefix.as_bytes();
        let mut len = 16 + text.len() + 1;
        if pad {
            len = (len + 7) & !7;
        }
        out.extend_from_slice(&(len as u16).to_le_bytes());
        out.extend_from_slice(&mode.to_le_bytes());
        out.extend_from_slice(&uid.to_le_bytes());
        out.extend_from_slice(&gid.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(text);
        out.push(0);
        out.resize(out.len() + (len - (16 + text.len() + 1)), 0);
    }
}

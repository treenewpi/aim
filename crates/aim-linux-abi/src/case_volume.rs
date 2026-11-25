//! Host volumes the guest creates files on. Linux compares path bytes.
//! APFS folds case unless the volume was created case-sensitive, so two
//! names become one file. prepare-init uses this probe on the image root;
//! linux-run uses it on every backing directory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) struct VolumeCheck {
    pub role: String,
    pub path: PathBuf,
}

struct Folded {
    role: String,
    path: PathBuf,
    probed: PathBuf,
}

/// Fail when any directory is on a case-folding volume. A path that does
/// not exist yet is probed at the directory that will hold it.
pub(crate) fn require(entries: &[VolumeCheck]) -> Result<(), String> {
    let mut folded = Vec::new();
    let mut seen = BTreeMap::<PathBuf, bool>::new();
    let mut reported = BTreeSet::new();
    for entry in entries {
        let probed = existing_dir(&entry.path)?;
        let sensitive = if let Some(known) = seen.get(&probed) {
            *known
        } else {
            let sensitive = directory_is_case_sensitive(&probed)?;
            seen.insert(probed.clone(), sensitive);
            sensitive
        };
        if sensitive {
            continue;
        }
        let key = format!("{}\0{}", entry.role, entry.path.display());
        if !reported.insert(key) {
            continue;
        }
        folded.push(Folded {
            role: entry.role.clone(),
            path: entry.path.clone(),
            probed,
        });
    }
    if folded.is_empty() {
        Ok(())
    } else {
        Err(fold_message(&folded))
    }
}

fn existing_dir(path: &Path) -> Result<PathBuf, String> {
    let mut cur = path.to_path_buf();
    loop {
        match fs::metadata(&cur) {
            Ok(meta) if meta.is_dir() => {
                return cur
                    .canonicalize()
                    .map_err(|e| format!("canonicalize {}: {e}", cur.display()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("probe {}: {error}", cur.display())),
        }
        match cur.parent() {
            Some(parent) if parent != cur => cur = parent.to_path_buf(),
            _ => {
                return Err(format!(
                    "no directory to probe for {}",
                    path.display()
                ))
            }
        }
    }
}

fn directory_is_case_sensitive(dir: &Path) -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    if pathconf_case_sensitive(dir)? == Some(false) {
        return Ok(false);
    }
    probe_case_sensitive(dir)
}

#[cfg(target_os = "macos")]
fn pathconf_case_sensitive(dir: &Path) -> Result<Option<bool>, String> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| format!("{} has an interior nul", dir.display()))?;
    let rc = unsafe { libc::pathconf(c_path.as_ptr(), libc::_PC_CASE_SENSITIVE) };
    if rc < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINVAL) {
            return Ok(None);
        }
        return Err(format!("pathconf {}: {error}", dir.display()));
    }
    Ok(Some(rc == 1))
}

fn probe_case_sensitive(dir: &Path) -> Result<bool, String> {
    let upper = dir.join(".aim-case-A");
    let lower = dir.join(".aim-case-a");
    let _ = fs::remove_file(&upper);
    let _ = fs::remove_file(&lower);
    fs::write(&upper, b"A").map_err(|e| format!("probe {}: {e}", upper.display()))?;
    let folded = lower.exists();
    let _ = fs::remove_file(&upper);
    let _ = fs::remove_file(&lower);
    Ok(!folded)
}

fn fold_message(folded: &[Folded]) -> String {
    let mut names = String::new();
    for (i, item) in folded.iter().enumerate() {
        if i > 0 {
            names.push_str("; ");
        }
        names.push_str(&item.role);
        names.push(' ');
        names.push_str(&item.path.display().to_string());
        if item.probed != item.path {
            names.push_str(" (probed ");
            names.push_str(&item.probed.display().to_string());
            names.push(')');
        }
    }
    format!(
        "case-insensitive volume: {names}. The guest creates files in /data, /cache, tmpfs backing directories (<runtime>/tmpfs), writable layers, socket directories, and TMPDIR. A case-folding volume keeps one file where Linux keeps two. Put each of these directories on a case-sensitive APFS image. Creating one does not need sudo: hdiutil create -fs 'Case-sensitive APFS'. Mount it on the directory before starting linux-run."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_case_sensitive_directory_passes_and_the_probe_file_is_removed() {
        let dir = std::env::temp_dir().join(format!(
            "aim-case-volume-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let sensitive = probe_case_sensitive(&dir).unwrap();
        assert!(!dir.join(".aim-case-A").exists());
        assert!(!dir.join(".aim-case-a").exists());
        let missing = dir.join("tmpfs").join("later");
        let result = require(&[
            VolumeCheck {
                role: "TMPDIR".into(),
                path: dir.clone(),
            },
            VolumeCheck {
                role: "tmpfs backing".into(),
                path: missing,
            },
        ]);
        if sensitive {
            result.unwrap();
        } else {
            let text = result.unwrap_err();
            assert!(text.contains("case-insensitive"));
            assert!(text.contains(&dir.display().to_string()));
            assert!(text.contains("tmpfs backing"));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_fold_message_names_each_directory_and_the_image() {
        let text = fold_message(&[
            Folded {
                role: "writable /data".into(),
                path: PathBuf::from("/data-host"),
                probed: PathBuf::from("/data-host"),
            },
            Folded {
                role: "tmpfs backing".into(),
                path: PathBuf::from("/run/tmpfs"),
                probed: PathBuf::from("/run"),
            },
            Folded {
                role: "TMPDIR".into(),
                path: PathBuf::from("/var/tmp"),
                probed: PathBuf::from("/var/tmp"),
            },
        ]);
        assert!(text.contains("case-insensitive volume"));
        assert!(text.contains("writable /data /data-host"));
        assert!(text.contains("tmpfs backing /run/tmpfs (probed /run)"));
        assert!(text.contains("TMPDIR /var/tmp"));
        assert!(text.contains("/cache"));
        assert!(text.contains("<runtime>/tmpfs"));
        assert!(text.contains("socket directories"));
        assert!(text.contains("hdiutil create -fs 'Case-sensitive APFS'"));
    }
}

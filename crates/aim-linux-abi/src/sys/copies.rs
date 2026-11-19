//! Private file mappings: anonymous memory standing in for them (ELF
//! segments the loader copied and rewrote, executable private mappings of
//! files that are not translated), and the file-backed ones (`mem::mmap`).
//! Linux would show all of them file-backed. Recording what file each came
//! from, and from where, lets `/proc/self/maps` name them and lets
//! MADV_DONTNEED restore the file's contents instead of zeros. A fork
//! child needs the offset of a file-backed one too: its copy of the
//! mapping reports offset 0 into a copy of the file's pages.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Clone)]
pub struct Copy {
    pub end: u64,
    pub guest: String,
    pub host: PathBuf,
    /// File offset of the copy's first byte.
    pub offset: u64,
    pub dev: u64,
    pub ino: u64,
}

static COPIES: Mutex<BTreeMap<u64, Copy>> = Mutex::new(BTreeMap::new());

/// Drop what is recorded for `[lo, hi)`, keeping the parts outside it.
pub fn forget(lo: u64, hi: u64) {
    let mut m = COPIES.lock().unwrap();
    let hit: Vec<u64> = m
        .range(..hi)
        .filter(|(s, c)| **s < hi && c.end > lo)
        .map(|(s, _)| *s)
        .collect();
    for s in hit {
        let c = m.remove(&s).unwrap();
        if s < lo {
            m.insert(
                s,
                Copy {
                    end: lo,
                    ..c.clone()
                },
            );
        }
        if c.end > hi {
            let offset = c.offset + (hi - s);
            m.insert(hi, Copy { offset, ..c });
        }
    }
}

/// `[start, start+len)` now holds a copy of `host` from `offset`.
pub fn note(start: u64, len: u64, host: &Path, guest: &str, offset: u64) {
    let (dev, ino) = std::fs::metadata(host).map_or((0, 0), |m| {
        use std::os::unix::fs::MetadataExt;
        (m.dev() as u32 as u64, m.ino())
    });
    note_file(start, len, host, guest, offset, (dev, ino));
}

/// As [`note`], for the file with device and inode `id`.
pub fn note_file(start: u64, len: u64, host: &Path, guest: &str, offset: u64, id: (u64, u64)) {
    let (dev, ino) = id;
    forget(start, start + len);
    COPIES.lock().unwrap().insert(
        start,
        Copy {
            end: start + len,
            guest: guest.to_string(),
            host: host.to_path_buf(),
            offset,
            dev,
            ino,
        },
    );
}

/// The copy containing `addr`, with the file offset of `addr`.
pub fn find(addr: u64) -> Option<(Copy, u64)> {
    let m = COPIES.lock().unwrap();
    let (s, c) = m.range(..=addr).next_back()?;
    (addr < c.end).then(|| (c.clone(), c.offset + (addr - s)))
}

/// `[lo, hi)` cut at copy boundaries. `Some` is the file-backed piece and
/// the file offset of its start. `None` is a gap: anonymous, including the
/// ELF `.bss` that starts on the next 4 KiB page after the file bytes.
pub fn covered(lo: u64, hi: u64) -> Vec<(u64, u64, Option<(Copy, u64)>)> {
    if lo >= hi {
        return Vec::new();
    }
    let m = COPIES.lock().unwrap();
    let mut out = Vec::new();
    let mut cur = lo;
    let from = m
        .range(..lo)
        .next_back()
        .filter(|(_, c)| c.end > lo)
        .map_or(lo, |(&s, _)| s);
    for (&key, c) in m.range(from..hi) {
        let start = key.max(lo);
        let end = c.end.min(hi);
        if start >= end {
            continue;
        }
        if start > cur {
            out.push((cur, start, None));
        }
        out.push((start, end, Some((c.clone(), c.offset + (start - key)))));
        cur = end;
    }
    if cur < hi {
        out.push((cur, hi, None));
    }
    out
}

/// mremap moved `[old, old+len)` to `new`.
pub fn moved(old: u64, new: u64, len: u64) {
    let parts: Vec<(u64, Copy)> = {
        let m = COPIES.lock().unwrap();
        m.range(..old + len)
            .filter(|(s, c)| **s < old + len && c.end > old)
            .map(|(s, c)| (*s, c.clone()))
            .collect()
    };
    forget(old, old + len);
    forget(new, new + len);
    let mut m = COPIES.lock().unwrap();
    for (s, c) in parts {
        let lo = s.max(old);
        let hi = c.end.min(old + len);
        m.insert(
            new + (lo - old),
            Copy {
                end: new + (hi - old),
                offset: c.offset + (lo - s),
                ..c
            },
        );
    }
}

/// Fork: the record goes with the memory it describes.
pub(super) fn fork_save(w: &mut super::fork_state::Writer) {
    let m = COPIES.lock().unwrap();
    w.seq(m.iter(), |w, (s, c)| {
        w.u64(*s);
        w.u64(c.end);
        w.str(&c.guest);
        w.path(&c.host);
        w.u64(c.offset);
        w.u64(c.dev);
        w.u64(c.ino);
    });
}

pub(super) fn fork_restore(r: &mut super::fork_state::Reader) {
    let v = r.seq(|r| {
        (
            r.u64(),
            Copy {
                end: r.u64(),
                guest: r.str(),
                host: r.path(),
                offset: r.u64(),
                dev: r.u64(),
                ino: r.u64(),
            },
        )
    });
    COPIES.lock().unwrap().extend(v);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn bss_on_the_next_guest_page_is_not_a_file_copy() {
        // Measured init PR_SET_VMA ranges. The file VMA ends where bionic's
        // 4 KiB PAGE_END(filesz) ends. Naming starts there.
        let path = Path::new("/system/bin/init");
        note_file(
            0x8000_4c40_00,
            0x1000,
            path,
            "/system/bin/init",
            0x4c_4000,
            (1, 2),
        );
        note_file(
            0x8000_2f80_00,
            0x1000,
            path,
            "/system/bin/init",
            0x2f_8000,
            (1, 2),
        );
        assert!(
            covered(0x8000_4c50_00, 0x8000_4d80_00)
                .iter()
                .all(|(_, _, copy)| copy.is_none())
        );
        assert!(
            covered(0x8000_2f90_00, 0x8000_2fa0_00)
                .iter()
                .all(|(_, _, copy)| copy.is_none())
        );
        let across = covered(0x8000_4c40_00, 0x8000_4c60_00);
        assert!(across[0].2.is_some());
        assert!(across[1].2.is_none());
        assert_eq!(across[0].1, 0x8000_4c50_00);
        forget(0x8000_2f80_00, 0x8000_4d80_00);
    }
}

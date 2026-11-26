//! Read-only ext4 for an APEX payload image.
//!
//! The pinned Android 16 layer's 35 payload images are ext4, 4096-byte
//! blocks. Every one has the same feature words: compat `0x28`
//! (`EXT_ATTR|DIR_INDEX`, so a directory may be an htree), incompat `0x42`
//! (`FILETYPE|EXTENTS`), ro_compat `0x407b`
//! (`SPARSE_SUPER|LARGE_FILE|HUGE_FILE|GDT_CSUM|DIR_NLINK|EXTRA_ISIZE|SHARED_BLOCKS`).
//! `FLEX_BG`, `METADATA_CSUM` and `INLINE_DATA` are unset. Extent trees are
//! depth 0 or 1. A mount copies each inode's bytes out through [`ReadAt`]
//! (the loop device, or a dm-verity wrapper over it). Shared blocks are
//! read as stored. An incompat bit outside `FILETYPE|EXTENTS` fails the
//! mount with `EINVAL`, as Linux does for a feature the filesystem does
//! not implement. `BIGALLOC` fails with `EOPNOTSUPP`.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::errno::{self, EIO, EINVAL, EOPNOTSUPP, Errno};

const SUPER_MAGIC: u16 = 0xef53;
const EXTENT_MAGIC: u16 = 0xf30a;
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_EXTENTS: u32 = 0x40;
const INCOMPAT_OK: u32 = INCOMPAT_FILETYPE | INCOMPAT_EXTENTS;
const RO_BIGALLOC: u32 = 0x200;
const EXTENTS_FL: u32 = 0x80000;
const INDEX_FL: u32 = 0x1000;
const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;

pub trait ReadAt {
    fn read_exact_at(&self, at: u64, buf: &mut [u8]) -> Result<(), Errno>;
    fn len(&self) -> u64;
}

impl ReadAt for &[u8] {
    fn read_exact_at(&self, at: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let start = usize::try_from(at).map_err(|_| EIO)?;
        let end = start.checked_add(buf.len()).ok_or(EIO)?;
        if end as u64 > self.len() {
            return Err(EIO);
        }
        buf.copy_from_slice(&self[start..end]);
        Ok(())
    }
    fn len(&self) -> u64 {
        (*self).len() as u64
    }
}

impl ReadAt for Vec<u8> {
    fn read_exact_at(&self, at: u64, buf: &mut [u8]) -> Result<(), Errno> {
        self.as_slice().read_exact_at(at, buf)
    }
    fn len(&self) -> u64 {
        self.as_slice().len() as u64
    }
}

impl ReadAt for Box<dyn ReadAt + Send> {
    fn read_exact_at(&self, at: u64, buf: &mut [u8]) -> Result<(), Errno> {
        (**self).read_exact_at(at, buf)
    }
    fn len(&self) -> u64 {
        (**self).len()
    }
}

pub struct Image<R> {
    io: R,
    block_size: u64,
    inode_size: u64,
    inodes_per_group: u64,
    /// Byte offset of each group's inode table.
    inode_table: Vec<u64>,
}

struct Inode {
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    flags: u32,
    /// `i_block`, 60 bytes.
    raw: [u8; 60],
}

impl<R: ReadAt> Image<R> {
    pub fn open(io: R) -> Result<Self, Errno> {
        let mut sb = [0u8; 256];
        io.read_exact_at(1024, &mut sb)?;
        let magic = ru16(&sb, 0x38);
        let log_block = ru32(&sb, 0x18);
        let incompat = ru32(&sb, 0x60);
        let ro = ru32(&sb, 0x64);
        if magic != SUPER_MAGIC || log_block > 2 {
            return Err(EINVAL);
        }
        let block_size = 1024u64 << log_block;
        if block_size != 4096 || incompat & !INCOMPAT_OK != 0 || incompat & INCOMPAT_EXTENTS == 0 {
            return Err(EINVAL);
        }
        if ro & RO_BIGALLOC != 0 {
            return Err(EOPNOTSUPP);
        }
        let inodes = ru32(&sb, 0) as u64;
        let blocks = ru32(&sb, 4) as u64;
        let blocks_per_group = ru32(&sb, 0x20) as u64;
        let inodes_per_group = ru32(&sb, 0x28) as u64;
        let inode_size = ru16(&sb, 0x58) as u64;
        if inodes == 0
            || blocks == 0
            || blocks_per_group == 0
            || inodes_per_group == 0
            || !(128..=512).contains(&inode_size)
            || inode_size % 4 != 0
        {
            return Err(EINVAL);
        }
        let groups = inodes.div_ceil(inodes_per_group);
        let desc_bytes = groups.checked_mul(32).ok_or(EINVAL)?;
        let mut desc = vec![0u8; desc_bytes as usize];
        // 4 KiB blocks: the group descriptors start at block 1.
        io.read_exact_at(block_size, &mut desc)?;
        let mut inode_table = Vec::with_capacity(groups as usize);
        for group in 0..groups {
            let table = ru32(&desc, (group as usize) * 32 + 8) as u64;
            if table == 0 || table >= blocks {
                return Err(EINVAL);
            }
            inode_table.push(table * block_size);
        }
        Ok(Self {
            io,
            block_size,
            inode_size,
            inodes_per_group,
            inode_table,
        })
    }

    /// Copy the tree at inode 2 onto `root`. Every byte comes from `self`.
    pub fn install(&self, root: &Path) -> Result<(), Errno> {
        let _ = fs::remove_dir_all(root);
        fs::create_dir_all(root).map_err(io_err)?;
        let mut seen = BTreeMap::new();
        self.install_dir(2, root, &mut seen)
    }

    fn install_dir(
        &self,
        ino: u64,
        path: &Path,
        seen: &mut BTreeMap<u64, PathBuf>,
    ) -> Result<(), Errno> {
        if seen.insert(ino, path.to_path_buf()).is_some() {
            return Ok(());
        }
        let inode = self.inode(ino)?;
        if inode.mode & S_IFMT != S_IFDIR {
            return Err(EIO);
        }
        let mode = mode_bits(inode.mode, 0o755);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(path)
            .map_err(io_err)?;
        // `mkdir` applies the umask. The inode mode is the one the guest
        // walks, so put it back, the same way a regular file is restored.
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_err)?;
        store_owner(path, &inode);
        for (child_ino, name) in self.dir_entries(&inode)? {
            if name == "." || name == ".." || name.contains('/') || name.contains('\0') {
                continue;
            }
            let child_path = path.join(&name);
            let child = self.inode(child_ino)?;
            if let Some(prev) = seen.get(&child_ino) {
                if child.mode & S_IFMT == S_IFREG {
                    fs::hard_link(prev, &child_path).map_err(io_err)?;
                }
                continue;
            }
            match child.mode & S_IFMT {
                S_IFDIR => self.install_dir(child_ino, &child_path, seen)?,
                S_IFREG => {
                    self.write_reg(&child, &child_path)?;
                    seen.insert(child_ino, child_path);
                }
                S_IFLNK => {
                    let target = self.link_target(&child)?;
                    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(&target), &child_path)
                        .map_err(io_err)?;
                    seen.insert(child_ino, child_path);
                }
                _ => return Err(EIO),
            }
        }
        Ok(())
    }

    fn write_reg(&self, inode: &Inode, path: &Path) -> Result<(), Errno> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode_bits(inode.mode, 0o644))
            .open(path)
            .map_err(io_err)?;
        let mut done = 0u64;
        let mut buf = vec![0u8; self.block_size as usize];
        while done < inode.size {
            let logical = done / self.block_size;
            let take = ((inode.size - done) as usize).min(buf.len());
            match self.map(inode, logical)? {
                None => buf[..take].fill(0),
                Some(phys) => {
                    self.io.read_exact_at(phys * self.block_size, &mut buf)?;
                }
            }
            use std::io::Write;
            file.write_all(&buf[..take]).map_err(io_err)?;
            done += take as u64;
        }
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(mode_bits(inode.mode, 0o644)),
        )
        .map_err(io_err)?;
        store_owner(path, inode);
        Ok(())
    }

    fn link_target(&self, inode: &Inode) -> Result<Vec<u8>, Errno> {
        if inode.size <= 60 && ru16(&inode.raw, 0) != EXTENT_MAGIC {
            return Ok(inode.raw[..inode.size as usize].to_vec());
        }
        let mut out = vec![0u8; inode.size as usize];
        let mut done = 0usize;
        while done < out.len() {
            let logical = (done as u64) / self.block_size;
            let mut buf = vec![0u8; self.block_size as usize];
            if let Some(phys) = self.map(inode, logical)? {
                self.io.read_exact_at(phys * self.block_size, &mut buf)?;
            }
            let take = (out.len() - done).min(buf.len());
            out[done..done + take].copy_from_slice(&buf[..take]);
            done += take;
        }
        Ok(out)
    }

    fn inode(&self, ino: u64) -> Result<Inode, Errno> {
        if ino == 0 {
            return Err(EIO);
        }
        let group = (ino - 1) / self.inodes_per_group;
        let index = (ino - 1) % self.inodes_per_group;
        let table = *self.inode_table.get(group as usize).ok_or(EIO)?;
        let at = table + index * self.inode_size;
        let mut raw = vec![0u8; self.inode_size as usize];
        self.io.read_exact_at(at, &mut raw)?;
        let mode = ru16(&raw, 0);
        let mut uid = ru16(&raw, 2) as u32;
        let mut gid = ru16(&raw, 0x18) as u32;
        // Linux `osd2`: `i_uid_high` at 0x78 and `i_gid_high` at 0x7a.
        if raw.len() >= 0x7c {
            uid |= (ru16(&raw, 0x78) as u32) << 16;
            gid |= (ru16(&raw, 0x7a) as u32) << 16;
        }
        let mut size = ru32(&raw, 4) as u64;
        if mode & S_IFMT != S_IFDIR && raw.len() >= 0x70 {
            size |= (ru32(&raw, 0x6c) as u64) << 32;
        }
        let mut block = [0u8; 60];
        block.copy_from_slice(&raw[0x28..0x64]);
        Ok(Inode {
            mode,
            uid,
            gid,
            size,
            flags: ru32(&raw, 0x20),
            raw: block,
        })
    }

    fn dir_entries(&self, inode: &Inode) -> Result<Vec<(u64, String)>, Errno> {
        let mut out = Vec::new();
        if inode.flags & INDEX_FL == 0 {
            let blocks = inode.size.div_ceil(self.block_size).max(1);
            for logical in 0..blocks {
                self.read_dir_block(inode, logical, &mut out, false)?;
            }
            return Ok(out);
        }
        self.read_dir_block(inode, 0, &mut out, true)?;
        for logical in self.htree_leaves(inode)? {
            self.read_dir_block(inode, logical, &mut out, false)?;
        }
        Ok(out)
    }

    /// `dots_only` keeps `.` and `..` from an htree root and skips the index.
    fn read_dir_block(
        &self,
        inode: &Inode,
        logical: u64,
        out: &mut Vec<(u64, String)>,
        dots_only: bool,
    ) -> Result<(), Errno> {
        let Some(phys) = self.map(inode, logical)? else {
            return Ok(());
        };
        let mut block = vec![0u8; self.block_size as usize];
        self.io.read_exact_at(phys * self.block_size, &mut block)?;
        let mut at = 0usize;
        while at + 8 <= block.len() {
            let ino = ru32(&block, at) as u64;
            let rec = ru16(&block, at + 4) as usize;
            let name_len = block[at + 6] as usize;
            if rec < 8 || at + rec > block.len() || rec % 4 != 0 {
                return Err(EIO);
            }
            if ino != 0 && at + 8 + name_len <= block.len() {
                let name = std::str::from_utf8(&block[at + 8..at + 8 + name_len]).map_err(|_| EIO)?;
                if !dots_only || name == "." || name == ".." {
                    out.push((ino, name.to_string()));
                }
            }
            if dots_only && at >= 24 {
                break;
            }
            at += rec;
        }
        Ok(())
    }

    fn htree_leaves(&self, inode: &Inode) -> Result<Vec<u64>, Errno> {
        let Some(phys) = self.map(inode, 0)? else {
            return Err(EIO);
        };
        let mut root = vec![0u8; self.block_size as usize];
        self.io.read_exact_at(phys * self.block_size, &mut root)?;
        if root.len() < 40 {
            return Err(EIO);
        }
        let levels = root[24 + 6];
        let children = dx_blocks(&root, 32)?;
        if levels == 0 {
            return Ok(children);
        }
        if levels != 1 {
            return Err(EOPNOTSUPP);
        }
        let mut leaves = Vec::new();
        for logical in children {
            let Some(phys) = self.map(inode, logical)? else {
                return Err(EIO);
            };
            let mut node = vec![0u8; self.block_size as usize];
            self.io.read_exact_at(phys * self.block_size, &mut node)?;
            leaves.extend(dx_blocks(&node, 8)?);
        }
        Ok(leaves)
    }

    /// Physical block for logical `block`, or a hole.
    fn map(&self, inode: &Inode, block: u64) -> Result<Option<u64>, Errno> {
        if inode.raw[..4] == [0, 0, 0, 0] && inode.flags & EXTENTS_FL == 0 {
            return Ok(None);
        }
        self.map_node(&inode.raw, block, 0)
    }

    fn map_node(&self, header: &[u8], block: u64, depth_left: u32) -> Result<Option<u64>, Errno> {
        if depth_left > 5 || header.len() < 12 || ru16(header, 0) != EXTENT_MAGIC {
            return Err(EIO);
        }
        let entries = ru16(header, 2) as usize;
        let depth = ru16(header, 6);
        if entries.saturating_mul(12) + 12 > header.len() {
            // The header in an inode is only 60 bytes. A leaf block is larger;
            // an index node stored in the inode holds at most four entries.
            if 12 + entries * 12 > header.len() && header.len() == 60 && entries > 4 {
                return Err(EIO);
            }
        }
        if depth == 0 {
            for i in 0..entries {
                let at = 12 + i * 12;
                if at + 12 > header.len() {
                    return Err(EIO);
                }
                let start_block = ru32(header, at) as u64;
                let len_raw = ru16(header, at + 4);
                let len = (len_raw & 0x7fff) as u64;
                let uninit = len_raw & 0x8000 != 0;
                let phys = ((ru16(header, at + 6) as u64) << 32) | ru32(header, at + 8) as u64;
                if block >= start_block && block < start_block + len {
                    return Ok(if uninit { None } else { Some(phys + block - start_block) });
                }
            }
            return Ok(None);
        }
        let mut leaf = None;
        for i in 0..entries {
            let at = 12 + i * 12;
            if at + 12 > header.len() {
                return Err(EIO);
            }
            let ei_block = ru32(header, at) as u64;
            let phys = ((ru16(header, at + 8) as u64) << 32) | ru32(header, at + 4) as u64;
            if ei_block <= block {
                leaf = Some(phys);
            }
        }
        let leaf = leaf.ok_or(EIO)?;
        let mut child = vec![0u8; self.block_size as usize];
        self.io.read_exact_at(leaf * self.block_size, &mut child)?;
        self.map_node(&child, block, depth_left + 1)
    }
}

/// `dx_countlimit` overlays the first entry. Each entry's block is a child.
fn dx_blocks(block: &[u8], entries_at: usize) -> Result<Vec<u64>, Errno> {
    if entries_at + 8 > block.len() {
        return Err(EIO);
    }
    let count = ru16(block, entries_at + 2) as usize;
    if count == 0 || entries_at + count * 8 > block.len() {
        return Err(EIO);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        out.push(ru32(block, entries_at + i * 8 + 4) as u64);
    }
    Ok(out)
}

fn mode_bits(mode: u16, default: u32) -> u32 {
    let bits = (mode as u32) & 0o7777;
    if bits == 0 { default } else { bits }
}

/// The inode's owner and mode, in the same `dev.aim.android-inode` record
/// the image extractor writes. The guest check uses that, not the host
/// file's mode: a host create can leave the other and group execute bits
/// clear, and this does not add them. `user.aim.android-inode` is the same
/// record where the host rejects a name outside the `user` namespace.
fn store_owner(path: &Path, inode: &Inode) {
    let mut bytes = [0u8; 20];
    bytes[..8].copy_from_slice(b"DARI\x01\0\0\0");
    bytes[8..12].copy_from_slice(&inode.uid.to_le_bytes());
    bytes[12..16].copy_from_slice(&inode.gid.to_le_bytes());
    bytes[16..20].copy_from_slice(&(inode.mode as u32).to_le_bytes());
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    for name in [c"dev.aim.android-inode", c"user.aim.android-inode"] {
        // SAFETY: path and name are NUL-terminated; the value is 20 bytes.
        let wrote = unsafe {
            aim_storage::host::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                aim_storage::host::XATTR_NOFOLLOW,
            )
        };
        if wrote == 0 {
            return;
        }
    }
}

fn io_err(error: std::io::Error) -> Errno {
    errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO))
}

#[cfg(test)]
pub(crate) fn manifest_fixture() -> (Vec<u8>, &'static [u8]) {
    (tests::image(tests::MANIFEST, false), tests::MANIFEST)
}

/// An apex-shaped tree: `bin/boringssl_self_test64` is mode 0755, uid 0,
/// gid 2000, as in the conscrypt payload. `bin/private` is 0750 and
/// `bin/data` is 0644, both uid 0 gid 2000. The root is uid 1000 gid 1000
/// mode 0755, and `bin` is uid 0 gid 2000 mode 0755.
#[cfg(test)]
pub(crate) fn permission_payload() -> Vec<u8> {
    tests::permission_image()
}

fn ru16(buf: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(buf[at..at + 2].try_into().unwrap())
}
fn ru32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runtime payload's `apex_manifest.pb` (143 bytes).
    pub(super) const MANIFEST: &[u8] = &[
        0x0a, 0x13, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x72,
        0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x10, 0x01, 0x42, 0x07, 0x6c, 0x69, 0x62, 0x63, 0x2e,
        0x73, 0x6f, 0x42, 0x25, 0x6c, 0x69, 0x62, 0x63, 0x6c, 0x61, 0x6e, 0x67, 0x5f, 0x72, 0x74,
        0x2e, 0x68, 0x77, 0x61, 0x73, 0x61, 0x6e, 0x2d, 0x61, 0x61, 0x72, 0x63, 0x68, 0x36, 0x34,
        0x2d, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x73, 0x6f, 0x42, 0x0d, 0x6c, 0x69,
        0x62, 0x64, 0x65, 0x78, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x73, 0x6f, 0x42, 0x08, 0x6c, 0x69,
        0x62, 0x64, 0x6c, 0x2e, 0x73, 0x6f, 0x42, 0x10, 0x6c, 0x69, 0x62, 0x64, 0x6c, 0x5f, 0x61,
        0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x73, 0x6f, 0x42, 0x09, 0x6c, 0x69, 0x62, 0x6c,
        0x6f, 0x67, 0x2e, 0x73, 0x6f, 0x42, 0x07, 0x6c, 0x69, 0x62, 0x6d, 0x2e, 0x73, 0x6f, 0x42,
        0x07, 0x6c, 0x69, 0x62, 0x7a, 0x2e, 0x73, 0x6f,
    ];

    fn put16(buf: &mut [u8], at: usize, v: u16) {
        buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(buf: &mut [u8], at: usize, v: u32) {
        buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// A 16-block image whose root holds `apex_manifest.pb`.
    /// `index` stores the file through an extent index node.
    pub(super) fn image(file: &[u8], index: bool) -> Vec<u8> {
        let bs = 4096usize;
        let mut img = vec![0u8; bs * 16];
        let sb = &mut img[1024..];
        put32(sb, 0, 16); // inodes
        put32(sb, 4, 16); // blocks
        put32(sb, 0x18, 2); // log block size
        put32(sb, 0x20, 16);
        put32(sb, 0x28, 16);
        put16(sb, 0x38, SUPER_MAGIC);
        put32(sb, 0x4c, 1); // dynamic rev
        put32(sb, 0x54, 11);
        put16(sb, 0x58, 256);
        put32(sb, 0x60, INCOMPAT_FILETYPE | INCOMPAT_EXTENTS);
        // inode table at block 4
        put32(&mut img, bs + 8, 4);
        let write_inode = |img: &mut [u8], ino: usize, mode: u16, size: u64, blocks: &[u8]| {
            let at = 4 * bs + (ino - 1) * 256;
            put16(img, at, mode);
            put32(img, at + 4, size as u32);
            put16(img, at + 0x1a, 1);
            put32(img, at + 0x20, EXTENTS_FL);
            img[at + 0x28..at + 0x28 + blocks.len()].copy_from_slice(blocks);
            if size > u32::MAX as u64 {
                put32(img, at + 0x6c, (size >> 32) as u32);
            }
        };
        let mut root_ext = [0u8; 24];
        put16(&mut root_ext, 0, EXTENT_MAGIC);
        put16(&mut root_ext, 2, 1);
        put16(&mut root_ext, 4, 4);
        put32(&mut root_ext, 12, 0);
        put16(&mut root_ext, 16, 1);
        put32(&mut root_ext, 20, 5); // directory block
        write_inode(&mut img, 2, S_IFDIR | 0o755, 4096, &root_ext);
        let mut file_ext = [0u8; 24];
        if index {
            put16(&mut file_ext, 0, EXTENT_MAGIC);
            put16(&mut file_ext, 2, 1);
            put16(&mut file_ext, 4, 4);
            put16(&mut file_ext, 6, 1); // depth
            put32(&mut file_ext, 12, 0); // ei_block
            put32(&mut file_ext, 16, 7); // leaf block
            // leaf header at block 7
            put16(&mut img, 7 * bs, EXTENT_MAGIC);
            put16(&mut img, 7 * bs + 2, 1);
            put16(&mut img, 7 * bs + 4, 340);
            put32(&mut img, 7 * bs + 12, 0);
            put16(&mut img, 7 * bs + 16, 1);
            put32(&mut img, 7 * bs + 20, 6);
        } else {
            put16(&mut file_ext, 0, EXTENT_MAGIC);
            put16(&mut file_ext, 2, 1);
            put16(&mut file_ext, 4, 4);
            put32(&mut file_ext, 12, 0);
            put16(&mut file_ext, 16, 1);
            put32(&mut file_ext, 20, 6);
        }
        write_inode(&mut img, 12, S_IFREG | 0o644, file.len() as u64, &file_ext);
        img[6 * bs..6 * bs + file.len()].copy_from_slice(file);
        let mut tool_ext = [0u8; 24];
        put16(&mut tool_ext, 0, EXTENT_MAGIC);
        put16(&mut tool_ext, 2, 1);
        put16(&mut tool_ext, 4, 4);
        put32(&mut tool_ext, 12, 0);
        put16(&mut tool_ext, 16, 1);
        put32(&mut tool_ext, 20, 8);
        write_inode(&mut img, 13, S_IFREG | 0o755, 4, &tool_ext);
        img[8 * bs..8 * bs + 4].copy_from_slice(b"exec");
        // directory block: . .. apex_manifest.pb
        let dir = &mut img[5 * bs..6 * bs];
        put32(dir, 0, 2);
        put16(dir, 4, 12);
        dir[6] = 1;
        dir[7] = 2;
        dir[8] = b'.';
        put32(dir, 12, 2);
        put16(dir, 16, 12);
        dir[18] = 2;
        dir[19] = 2;
        dir[20] = b'.';
        dir[21] = b'.';
        let name = b"apex_manifest.pb";
        put32(dir, 24, 12);
        put16(dir, 28, 24);
        dir[30] = name.len() as u8;
        dir[31] = 1;
        dir[32..32 + name.len()].copy_from_slice(name);
        let tool = b"tool";
        put32(dir, 48, 13);
        put16(dir, 52, (bs - 48) as u16);
        dir[54] = tool.len() as u8;
        dir[55] = 1;
        dir[56..56 + tool.len()].copy_from_slice(tool);
        img
    }

    /// The inode mode is the host mode, including under a umask that would
    /// clear execute on create. A mode without execute is not given it.
    #[test]
    fn install_keeps_regular_file_modes() {
        use std::os::unix::fs::PermissionsExt;
        let img = image(MANIFEST, false);
        let parsed = Image::open(img).unwrap();
        let dir = std::env::temp_dir().join(format!("aim-ext4-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let previous = unsafe { libc::umask(0o077) };
        parsed.install(&dir).unwrap();
        unsafe { libc::umask(previous) };
        let mode = |name: &str| fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("tool"), 0o755);
        assert_eq!(mode("apex_manifest.pb"), 0o644);
        assert_eq!(fs::read(dir.join("tool")).unwrap(), b"exec");
        assert_eq!(recorded(&dir.join("tool")), (0, 0, S_IFREG as u32 | 0o755));
        assert_eq!(
            recorded(&dir.join("apex_manifest.pb")),
            (0, 0, S_IFREG as u32 | 0o644)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    fn recorded(path: &Path) -> (u32, u32, u32) {
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut buf = [0u8; 20];
        for name in [c"dev.aim.android-inode", c"user.aim.android-inode"] {
            // SAFETY: path and name are NUL-terminated; the buffer is 20 bytes.
            let n = unsafe {
                aim_storage::host::getxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    aim_storage::host::XATTR_NOFOLLOW,
                )
            };
            if n == 20 && &buf[..8] == b"DARI\x01\0\0\0" {
                let word = |at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
                return (word(8), word(12), word(16));
            }
        }
        panic!("inode owner was not stored");
    }

    /// `bin/boringssl_self_test64` matches the conscrypt payload's owner.
    pub(super) fn permission_image() -> Vec<u8> {
        let bs = 4096usize;
        let mut img = vec![0u8; bs * 32];
        let sb = &mut img[1024..];
        put32(sb, 0, 32);
        put32(sb, 4, 32);
        put32(sb, 0x18, 2);
        put32(sb, 0x20, 32);
        put32(sb, 0x28, 32);
        put16(sb, 0x38, SUPER_MAGIC);
        put32(sb, 0x4c, 1);
        put32(sb, 0x54, 11);
        put16(sb, 0x58, 256);
        put32(sb, 0x60, INCOMPAT_FILETYPE | INCOMPAT_EXTENTS);
        put32(&mut img, bs + 8, 4);
        let write_inode = |img: &mut [u8],
                           ino: usize,
                           mode: u16,
                           uid: u32,
                           gid: u32,
                           size: u64,
                           blocks: &[u8]| {
            let at = 4 * bs + (ino - 1) * 256;
            put16(img, at, mode);
            put16(img, at + 2, uid as u16);
            put32(img, at + 4, size as u32);
            put16(img, at + 0x18, gid as u16);
            put16(img, at + 0x1a, 2);
            put32(img, at + 0x20, EXTENTS_FL);
            put16(img, at + 0x78, (uid >> 16) as u16);
            put16(img, at + 0x7a, (gid >> 16) as u16);
            img[at + 0x28..at + 0x28 + blocks.len()].copy_from_slice(blocks);
        };
        let extent = |logical_block: u32| {
            let mut ext = [0u8; 24];
            put16(&mut ext, 0, EXTENT_MAGIC);
            put16(&mut ext, 2, 1);
            put16(&mut ext, 4, 4);
            put32(&mut ext, 12, 0);
            put16(&mut ext, 16, 1);
            put32(&mut ext, 20, logical_block);
            ext
        };
        let root_ext = extent(6);
        let bin_ext = extent(7);
        let exec_ext = extent(8);
        let private_ext = extent(9);
        let data_ext = extent(10);
        write_inode(&mut img, 2, S_IFDIR | 0o755, 1000, 1000, 4096, &root_ext);
        write_inode(&mut img, 11, S_IFDIR | 0o755, 0, 2000, 4096, &bin_ext);
        let exec_body = b"not an elf";
        let private_body = b"private";
        let data_body = b"data";
        write_inode(
            &mut img,
            12,
            S_IFREG | 0o755,
            0,
            2000,
            exec_body.len() as u64,
            &exec_ext,
        );
        write_inode(
            &mut img,
            13,
            S_IFREG | 0o750,
            0,
            2000,
            private_body.len() as u64,
            &private_ext,
        );
        write_inode(
            &mut img,
            14,
            S_IFREG | 0o644,
            0,
            2000,
            data_body.len() as u64,
            &data_ext,
        );
        img[8 * bs..8 * bs + exec_body.len()].copy_from_slice(exec_body);
        img[9 * bs..9 * bs + private_body.len()].copy_from_slice(private_body);
        img[10 * bs..10 * bs + data_body.len()].copy_from_slice(data_body);
        write_dir(
            &mut img[6 * bs..7 * bs],
            &[(2, ".", 2), (2, "..", 2), (11, "bin", 2)],
        );
        write_dir(
            &mut img[7 * bs..8 * bs],
            &[
                (11, ".", 2),
                (2, "..", 2),
                (12, "boringssl_self_test64", 1),
                (13, "private", 1),
                (14, "data", 1),
            ],
        );
        img
    }

    fn write_dir(dir: &mut [u8], entries: &[(u32, &str, u8)]) {
        let mut at = 0usize;
        for (i, (ino, name, kind)) in entries.iter().enumerate() {
            let name = name.as_bytes();
            let need = (8 + name.len() + 3) & !3;
            let rec = if i + 1 == entries.len() {
                dir.len() - at
            } else {
                need
            };
            put32(dir, at, *ino);
            put16(dir, at + 4, rec as u16);
            dir[at + 6] = name.len() as u8;
            dir[at + 7] = *kind;
            dir[at + 8..at + 8 + name.len()].copy_from_slice(name);
            at += if i + 1 == entries.len() { need } else { rec };
        }
    }

    #[test]
    fn reads_the_runtime_manifest_from_a_leaf_and_an_index() {
        for index in [false, true] {
            let img = image(MANIFEST, index);
            let parsed = Image::open(img).unwrap();
            let dir = std::env::temp_dir().join(format!(
                "aim-ext4-{}-{}",
                std::process::id(),
                u8::from(index)
            ));
            parsed.install(&dir).unwrap();
            let got = fs::read(dir.join("apex_manifest.pb")).unwrap();
            assert_eq!(got, MANIFEST);
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn rejects_a_superblock_that_is_not_extent_ext4() {
        let mut img = image(MANIFEST, false);
        img[1024 + 0x38] = 0;
        match Image::open(img) {
            Err(err) => assert_eq!(err, EINVAL),
            Ok(_) => panic!("a superblock without the ext4 magic opened"),
        }
    }

    #[test]
    fn rejects_an_incompat_bit_outside_the_supported_set() {
        // Linux returns EINVAL from ext4_fill_super when an incompat bit
        // is outside the features this filesystem implements. FLEX_BG is
        // that kind of bit here, and it is unset on every pinned payload.
        let mut img = image(MANIFEST, false);
        let at = 1024 + 0x60;
        let incompat = u32::from_le_bytes(img[at..at + 4].try_into().unwrap());
        assert_eq!(incompat, INCOMPAT_OK);
        img[at..at + 4].copy_from_slice(&(incompat | 0x200).to_le_bytes());
        match Image::open(img) {
            Err(err) => assert_eq!(err, EINVAL),
            Ok(_) => panic!("flex_bg opened"),
        }
    }
}

//! dm-verity over one image, checked when a block is read.
//!
//! Android's APEX hashtree is version 1: the salt is hashed before the
//! block. Version 0 hashes it after. A data block is hashed and compared
//! with the digest stored in the tree, and that hash block is checked up
//! to the root digest. A mismatch is `EIO` and a diagnostics line. Nothing
//! is treated as already verified.

use std::collections::BTreeMap;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::errno::{EIO, EINVAL, Errno};

use super::ext4ro::ReadAt;

#[derive(Clone)]
pub struct Table {
    pub version: u32,
    pub data_device: String,
    pub hash_device: String,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub num_data_blocks: u64,
    pub hash_start_block: u64,
    pub root_digest: Vec<u8>,
    pub salt: Vec<u8>,
    /// Hash blocks at each level, leaves first. The last level is the root.
    levels: Vec<u64>,
}

impl Table {
    /// The verity parameter string libdm sends, without the target header.
    pub fn parse(params: &str) -> Result<Self, Errno> {
        let fields: Vec<&str> = params.split_whitespace().collect();
        if fields.len() < 10 {
            return Err(EINVAL);
        }
        let version: u32 = fields[0].parse().map_err(|_| EINVAL)?;
        if version > 1 || fields[7] != "sha256" {
            return Err(EINVAL);
        }
        let data_block_size: u32 = fields[3].parse().map_err(|_| EINVAL)?;
        let hash_block_size: u32 = fields[4].parse().map_err(|_| EINVAL)?;
        let num_data_blocks: u64 = fields[5].parse().map_err(|_| EINVAL)?;
        let hash_start_block: u64 = fields[6].parse().map_err(|_| EINVAL)?;
        if num_data_blocks == 0
            || !block_ok(data_block_size)
            || !block_ok(hash_block_size)
            || hash_block_size % 32 != 0
        {
            return Err(EINVAL);
        }
        let root_digest = unhex(fields[8])?;
        let salt = if fields[9] == "-" {
            Vec::new()
        } else {
            unhex(fields[9])?
        };
        if root_digest.len() != 32 {
            return Err(EINVAL);
        }
        let hashes_per_block = (hash_block_size as u64) / 32;
        let mut levels = Vec::new();
        let mut n = num_data_blocks;
        loop {
            n = n.div_ceil(hashes_per_block);
            levels.push(n);
            if n <= 1 {
                break;
            }
        }
        Ok(Self {
            version,
            data_device: fields[1].to_string(),
            hash_device: fields[2].to_string(),
            data_block_size,
            hash_block_size,
            num_data_blocks,
            hash_start_block,
            root_digest,
            salt,
            levels,
        })
    }

    pub fn data_len(&self) -> u64 {
        self.num_data_blocks * u64::from(self.data_block_size)
    }
}

pub struct Verified<R> {
    image: R,
    table: Table,
    /// Hash blocks whose digest matched their parent (or the root).
    cache: Mutex<BTreeMap<(u32, u64), Vec<u8>>>,
}

impl<R: ReadAt> Verified<R> {
    pub fn new(image: R, table: Table) -> Self {
        Self {
            image,
            table,
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        if self.table.version >= 1 {
            hasher.update(&self.table.salt);
            hasher.update(data);
        } else {
            hasher.update(data);
            hasher.update(&self.table.salt);
        }
        hasher.finalize().into()
    }

    fn hash_block(&self, level: u32, index: u64) -> Result<Vec<u8>, Errno> {
        let key = (level, index);
        if let Some(hit) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .cloned()
        {
            return Ok(hit);
        }
        let hashes_per_block = u64::from(self.table.hash_block_size) / 32;
        let mut skip = 0u64;
        for prior in &self.table.levels[..level as usize] {
            skip += prior;
        }
        let at = (self.table.hash_start_block + skip + index)
            * u64::from(self.table.hash_block_size);
        let mut block = vec![0u8; self.table.hash_block_size as usize];
        self.image.read_exact_at(at, &mut block)?;
        let got = self.hash(&block);
        let expect = if level as usize + 1 == self.table.levels.len() {
            self.table.root_digest.clone()
        } else {
            let parent = self.hash_block(level + 1, index / hashes_per_block)?;
            let slot = (index % hashes_per_block) as usize * 32;
            parent.get(slot..slot + 32).ok_or(EIO)?.to_vec()
        };
        if got.as_slice() != expect.as_slice() {
            crate::diag!(
                "dm-verity: hash block level {level} index {index} disagrees with {}",
                if level as usize + 1 == self.table.levels.len() {
                    "the root digest"
                } else {
                    "its parent"
                }
            );
            return Err(EIO);
        }
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, block.clone());
        Ok(block)
    }
}

impl<R: ReadAt> ReadAt for Verified<R> {
    fn len(&self) -> u64 {
        self.table.data_len()
    }

    fn read_exact_at(&self, at: u64, buf: &mut [u8]) -> Result<(), Errno> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = at.checked_add(buf.len() as u64).ok_or(EIO)?;
        if end > self.table.data_len() {
            return Err(EIO);
        }
        let bs = u64::from(self.table.data_block_size);
        let hashes_per_block = u64::from(self.table.hash_block_size) / 32;
        let mut filled = 0usize;
        while filled < buf.len() {
            let pos = at + filled as u64;
            let index = pos / bs;
            let skip = (pos % bs) as usize;
            let level0 = self.hash_block(0, index / hashes_per_block)?;
            let slot = (index % hashes_per_block) as usize * 32;
            let expect = level0.get(slot..slot + 32).ok_or(EIO)?;
            let mut block = vec![0u8; bs as usize];
            self.image.read_exact_at(index * bs, &mut block)?;
            let got = self.hash(&block);
            if got.as_slice() != expect {
                crate::diag!("dm-verity: data block {index} digest mismatch");
                return Err(EIO);
            }
            let take = (buf.len() - filled).min(block.len() - skip);
            buf[filled..filled + take].copy_from_slice(&block[skip..skip + take]);
            filled += take;
        }
        Ok(())
    }
}

fn block_ok(size: u32) -> bool {
    (512..=65536).contains(&size) && size.is_power_of_two()
}

fn unhex(text: &str) -> Result<Vec<u8>, Errno> {
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(EINVAL);
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| EINVAL))
        .collect()
}

/// Build a version-1 sha256 hashtree over `blocks` of `block` bytes.
/// The returned image is the data followed by the hash levels.
#[cfg(test)]
pub fn seal(blocks: &[Vec<u8>], salt: &[u8]) -> (Vec<u8>, Table) {
    let block = blocks[0].len();
    assert!(blocks.iter().all(|b| b.len() == block));
    let hashes_per_block = block / 32;
    let mut levels: Vec<Vec<Vec<u8>>> = Vec::new();
    let digests: Vec<[u8; 32]> = blocks.iter().map(|b| hash_v1(salt, b)).collect();
    let mut current = digests;
    loop {
        let mut packed = Vec::new();
        for chunk in current.chunks(hashes_per_block) {
            let mut buf = vec![0u8; block];
            for (i, digest) in chunk.iter().enumerate() {
                buf[i * 32..(i + 1) * 32].copy_from_slice(digest);
            }
            packed.push(buf);
        }
        let next: Vec<[u8; 32]> = packed.iter().map(|b| hash_v1(salt, b)).collect();
        let rootish = packed.len() == 1;
        levels.push(packed);
        if rootish {
            break;
        }
        current = next;
    }
    let root = hash_v1(salt, &levels.last().unwrap()[0]);
    let mut image = Vec::new();
    for block in blocks {
        image.extend_from_slice(block);
    }
    let hash_start = (image.len() / block) as u64;
    for level in &levels {
        for block in level {
            image.extend_from_slice(block);
        }
    }
    let table = Table::parse(&format!(
        "1 /dev/loop0 /dev/loop0 {block} {block} {} {hash_start} sha256 {} {}",
        blocks.len(),
        hex(&root),
        if salt.is_empty() { "-".into() } else { hex(salt) }
    ))
    .expect("sealed table");
    (image, table)
}

#[cfg(test)]
fn hash_v1(salt: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_block_matches_and_a_flipped_byte_is_eio() {
        let salt = b"apex";
        let mut block = vec![0x11u8; 4096];
        let (image, table) = seal(&[block.clone()], salt);
        let verified = Verified::new(image.clone(), table);
        let mut got = [0u8; 16];
        verified.read_exact_at(0, &mut got).unwrap();
        assert_eq!(got, [0x11; 16]);
        block[0] = 0x12;
        let (image, table) = seal(&[vec![0x11u8; 4096]], salt);
        let mut image = image;
        image[0] = 0x12;
        let verified = Verified::new(image, table);
        let err = verified.read_exact_at(0, &mut got).unwrap_err();
        assert_eq!(err, EIO);
        let _ = block;
    }

    #[test]
    fn a_two_level_tree_checks_the_block_it_reads() {
        let mut blocks = Vec::new();
        for i in 0..129 {
            let mut block = vec![0u8; 4096];
            block[0] = i as u8;
            blocks.push(block);
        }
        let (image, table) = seal(&blocks, &[]);
        assert_eq!(table.levels.len(), 2);
        let verified = Verified::new(image.clone(), table);
        let mut got = [0u8; 1];
        verified.read_exact_at(128 * 4096, &mut got).unwrap();
        assert_eq!(got, [128]);
        let mut image = image;
        image[128 * 4096] ^= 0xff;
        let (_, table) = seal(&blocks, &[]);
        let verified = Verified::new(image, table);
        assert_eq!(verified.read_exact_at(128 * 4096, &mut got).unwrap_err(), EIO);
        // An untouched block still checks.
        let (image, table) = seal(&blocks, &[]);
        let mut image = image;
        image[128 * 4096] ^= 0xff;
        let verified = Verified::new(image, table);
        verified.read_exact_at(0, &mut got).unwrap();
        assert_eq!(got, [0]);
    }
}

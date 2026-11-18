//! Guest `mprotect` is tracked in 4 KiB slices. The host page stays 16 KiB,
//! and its protection is the union of the slices that share it.
//!
//! Bionic's `WriteProtected` calls `mprotect` on `__libc_globals` (vaddr
//! `0x18e000`, length `0x1000`, `PROT_READ`). That slice sits inside a host
//! page that also holds writable globals. The call succeeds and those
//! globals stay writable. When every slice of a page asks for the same
//! protection, the host page changes. Execute is part of that union: text
//! and a read-only slice share the page, and the page stays executable.

/// Host and guest granules. The guest value is Bionic's hardcoded length,
/// not `AT_PAGESZ`.
pub const PAGE: u64 = 16384;
pub const GUEST_PAGE: u64 = 4096;

pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;

pub const ENOMEM: i32 = 12;
pub const EINVAL: i32 = 22;

/// One host page whose protection changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostProtect {
    pub addr: u64,
    pub old: u32,
    pub prot: u32,
}

pub fn prot_bits(prot: u32) -> u32 {
    prot & (PROT_READ | PROT_WRITE | PROT_EXEC)
}

/// How a private file `mmap` is backed.
///
/// A 16 KiB-aligned offset is the file itself, copy-on-write. Bionic maps
/// `libcrypto.so`'s dynamic section at file offset `0x17a000` (8 KiB into a
/// 16 KiB page) with length `0x12c0` and `PROT_READ`. That offset is copied
/// into a fresh host page: the returned pointer's first byte is file offset
/// `0x17a000`, and the recorded offset stays `0x17a000`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateFileMap {
    Direct { offset: u64, length: u64 },
    Copy { offset: u64, length: u64 },
}

/// `length` and `offset` are the guest arguments. `Ok` lengths are rounded
/// up to [`PAGE`]. A zero length, or an offset that is not a multiple of
/// 4 KiB, is [`EINVAL`].
pub fn private_file_map(offset: u64, length: u64) -> Result<PrivateFileMap, i32> {
    if length == 0 || offset & (GUEST_PAGE - 1) != 0 {
        return Err(EINVAL);
    }
    let length = host_span(length)?;
    if offset & (PAGE - 1) == 0 {
        Ok(PrivateFileMap::Direct { offset, length })
    } else {
        Ok(PrivateFileMap::Copy { offset, length })
    }
}

/// Bytes of a copied mapping that come from the file, and bytes that stay
/// zero because they are past EOF. `length` is the guest length.
pub fn copied_file_bytes(offset: u64, length: u64, file_len: u64) -> Result<(u64, u64), i32> {
    let length = host_span(length)?;
    let copied = file_len.saturating_sub(offset).min(length);
    Ok((copied, length - copied))
}

/// One host page and the 4 KiB slices of it that a guest range covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageCover {
    pub host: u64,
    /// Bit `i` is set when slice `i` of [`PageCover::host`] is in the range.
    pub cover: u8,
}

/// A guest range split into whole host pages and the partial pages at its edges.
///
/// Bionic reserves one anonymous region, `munmap`s the padding off both ends
/// (those ends are often only 4 KiB-aligned), then `MAP_FIXED`s each segment
/// at the address that remains. A partial page's uncovered slices are the
/// neighbor that must stay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeSplit {
    pub head: Option<PageCover>,
    pub full_lo: u64,
    pub full_hi: u64,
    pub tail: Option<PageCover>,
}

impl RangeSplit {
    pub fn is_partial(self) -> bool {
        self.head.is_some() || self.tail.is_some()
    }
}

/// Split `[start, start+length)` after rounding `length` up to 4 KiB.
/// A zero length or a start that is not a multiple of 4 KiB is [`EINVAL`].
pub fn split_guest_range(start: u64, length: u64) -> Result<RangeSplit, i32> {
    if length == 0 || start & (GUEST_PAGE - 1) != 0 {
        return Err(EINVAL);
    }
    let span = guest_page_len(length)?;
    let end = start.checked_add(span).ok_or(ENOMEM)?;
    let host_lo = start & !(PAGE - 1);
    let host_hi = end.checked_add(PAGE - 1).ok_or(ENOMEM)? & !(PAGE - 1);
    let mut full_lo = host_lo;
    let mut full_hi = host_hi;
    let mut head = None;
    let mut tail = None;
    if start > host_lo || end < host_lo + PAGE {
        let hi = end.min(host_lo + PAGE);
        head = Some(PageCover {
            host: host_lo,
            cover: cover_mask(start, hi, host_lo),
        });
        full_lo = host_lo + PAGE;
    }
    if host_hi > host_lo + PAGE && end < host_hi {
        let tail_host = host_hi - PAGE;
        tail = Some(PageCover {
            host: tail_host,
            cover: cover_mask(tail_host, end, tail_host),
        });
        full_hi = tail_host;
    }
    if full_lo >= full_hi {
        full_lo = 0;
        full_hi = 0;
    }
    Ok(RangeSplit {
        head,
        full_lo,
        full_hi,
        tail,
    })
}

/// File offset of guest address `at` in a mapping that starts at `map_addr`
/// with file offset `map_off`.
pub fn file_offset_at(map_addr: u64, map_off: u64, at: u64) -> u64 {
    map_off + (at - map_addr)
}

/// Offset a whole host page inside a partial `MAP_FIXED` is created with.
///
/// A file page keeps the file position of its first byte. An anonymous page
/// is zeros: the guest offset and the distance from the unaligned start are
/// not a file offset. `.bss` is `mmap(addr, 0x8000, PROT_READ|PROT_WRITE,
/// MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` with `addr` only 4 KiB-aligned,
/// so the page in the middle would otherwise be asked for at offset `0x1000`.
pub fn partial_page_offset(anonymous: bool, map_addr: u64, map_off: u64, page: u64) -> u64 {
    if anonymous {
        0
    } else {
        file_offset_at(map_addr, map_off, page)
    }
}

fn cover_mask(lo: u64, hi: u64, host: u64) -> u8 {
    let mut mask = 0u8;
    for slot in 0..4 {
        let slice = host + slot * GUEST_PAGE;
        if slice < hi && slice + GUEST_PAGE > lo {
            mask |= 1 << slot;
        }
    }
    mask
}

fn host_span(length: u64) -> Result<u64, i32> {
    if length == 0 {
        return Err(EINVAL);
    }
    let sum = length.checked_add(PAGE - 1).ok_or(ENOMEM)?;
    Ok(sum & !(PAGE - 1))
}

/// Round `len` up to [`GUEST_PAGE`]. Zero stays zero. Overflow is [`ENOMEM`].
pub fn guest_page_len(len: u64) -> Result<u64, i32> {
    if len == 0 {
        return Ok(0);
    }
    let rounded = len.checked_add(GUEST_PAGE - 1).ok_or(ENOMEM)?;
    Ok(rounded & !(GUEST_PAGE - 1))
}

/// True when `[addr, addr+len)` is empty or covers only whole host pages.
///
/// A 4 KiB length at a 16 KiB-aligned address is false. Rounding that length
/// up to the host page would change the next three slices.
pub fn whole_host_pages(addr: u64, len: u64) -> Result<bool, i32> {
    if addr & (GUEST_PAGE - 1) != 0 {
        return Err(EINVAL);
    }
    let len = guest_page_len(len)?;
    if len == 0 {
        return Ok(addr & (PAGE - 1) == 0);
    }
    let end = addr.checked_add(len).ok_or(ENOMEM)?;
    Ok(addr & (PAGE - 1) == 0 && end & (PAGE - 1) == 0)
}

/// Alignment and length checks for a guest `mprotect` that is not aligned
/// to [`PAGE`]. `Ok(0)` is a successful no-op. `Ok(len)` is the rounded
/// length the caller maps and protects. Execute is allowed; the host page
/// uses the union.
pub fn begin_subpage(addr: u64, len: u64, prot: u32) -> Result<u64, i32> {
    if addr & (GUEST_PAGE - 1) != 0 {
        return Err(EINVAL);
    }
    let len = guest_page_len(len)?;
    if len == 0 {
        return Ok(0);
    }
    if addr.checked_add(len).is_none() {
        return Err(ENOMEM);
    }
    let _ = prot;
    Ok(len)
}

/// Plan the host operations and the guest slices a sub-page `mprotect` stores.
///
/// `current` is every 4 KiB slice of each touched host page, in order. A
/// length that is not a multiple of four slices is [`EINVAL`]: the caller
/// walked the wrong range. The host protection is the union, including
/// execute when any slice has it.
pub fn plan_subpage(
    host_lo: u64,
    req_lo: u64,
    req_hi: u64,
    prot: u32,
    current: &[u32],
) -> Result<(Vec<HostProtect>, Vec<(u64, u32)>), i32> {
    let per_host = (PAGE / GUEST_PAGE) as usize;
    if current.len() % per_host != 0 {
        return Err(EINVAL);
    }
    let mut host_ops = Vec::new();
    let mut slices = Vec::with_capacity(current.len());
    for (host_index, chunk) in current.chunks(per_host).enumerate() {
        let page = host_lo + host_index as u64 * PAGE;
        let mut next = Vec::with_capacity(chunk.len());
        let mut old_host = 0u32;
        for (slot, &was) in chunk.iter().enumerate() {
            let guest = page + slot as u64 * GUEST_PAGE;
            let now = if guest >= req_lo && guest < req_hi {
                prot
            } else {
                was
            };
            next.push(now);
            old_host |= was;
            slices.push((guest, now));
        }
        let new_host = next.iter().fold(0, |bits, slice| bits | slice);
        if new_host != old_host {
            host_ops.push(HostProtect {
                addr: page,
                old: old_host,
                prot: new_host,
            });
        }
    }
    Ok((host_ops, slices))
}

/// Protection the host page has after `ops`. A page with no operation keeps
/// the union of its current slices.
pub fn host_prot_at(ops: &[HostProtect], current: &[u32], host_lo: u64, page: u64) -> u32 {
    if let Some(op) = ops
        .iter()
        .find(|op| page >= op.addr && page < op.addr + PAGE)
    {
        return op.prot;
    }
    let per_host = (PAGE / GUEST_PAGE) as usize;
    let slot = ((page - host_lo) / GUEST_PAGE) as usize;
    let base = slot & !(per_host - 1);
    current[base..base + per_host]
        .iter()
        .fold(0, |bits, slice| bits | slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW: u32 = PROT_READ | PROT_WRITE;
    const RO: u32 = PROT_READ;
    const RX: u32 = PROT_READ | PROT_EXEC;

    fn recorded(
        host: u64,
        current: &[u32],
        ops: &[HostProtect],
        slices: &[(u64, u32)],
    ) -> Vec<(u64, u32)> {
        slices
            .iter()
            .copied()
            .filter(|(page, prot)| *prot != host_prot_at(ops, current, host, *page))
            .collect()
    }

    #[test]
    fn guest4k_android_writeprotected_records_the_slice_and_leaves_the_host_page() {
        // linker64 `__libc_globals` at vaddr 0x18e000, length 0x1000, PROT_READ.
        // The other three 4 KiB slices of that 16 KiB page stay writable.
        let current = [RW, RW, RW, RW];
        let (host, slices) = plan_subpage(0x18c000, 0x18e000, 0x18f000, RO, &current).unwrap();
        assert!(host.is_empty(), "host page stays read-write: {host:?}");
        assert_eq!(
            recorded(0x18c000, &current, &host, &slices),
            [(0x18e000, RO)]
        );
    }

    #[test]
    fn guest4k_an_unchanged_protection_records_nothing() {
        let current = [RW, RW, RW, RW];
        let (host, slices) = plan_subpage(0x18c000, 0x18e000, 0x18f000, RW, &current).unwrap();
        assert!(host.is_empty());
        assert!(recorded(0x18c000, &current, &host, &slices).is_empty());
    }

    #[test]
    fn guest4k_length_rounds_up_to_4k_and_rejects_overflow() {
        assert_eq!(guest_page_len(1).unwrap(), 0x1000);
        assert_eq!(guest_page_len(0x1000).unwrap(), 0x1000);
        assert_eq!(guest_page_len(0x1001).unwrap(), 0x2000);
        assert_eq!(guest_page_len(u64::MAX - 0xfff).unwrap(), u64::MAX - 0xfff);
        assert_eq!(guest_page_len(u64::MAX - 0xffe), Err(ENOMEM));
        assert_eq!(guest_page_len(u64::MAX), Err(ENOMEM));
    }

    #[test]
    fn guest4k_subpage_crosses_a_host_page_and_keeps_an_overlapping_slice() {
        let current = [RW, RW, RW, RW, RW, RW, RW, RW];
        let (host, slices) = plan_subpage(0x18c000, 0x18e000, 0x191000, RO, &current).unwrap();
        assert!(host.is_empty());
        assert_eq!(
            recorded(0x18c000, &current, &host, &slices),
            [(0x18e000, RO), (0x18f000, RO), (0x190000, RO)]
        );
        let current = [RO, RW, RW, RW];
        let (host, slices) = plan_subpage(0x18c000, 0x18d000, 0x18e000, RO, &current).unwrap();
        assert!(host.is_empty());
        assert_eq!(
            recorded(0x18c000, &current, &host, &slices),
            [(0x18c000, RO), (0x18d000, RO)]
        );
    }

    #[test]
    fn guest4k_uniform_reads_tighten_one_host_page_and_drop_the_records() {
        let current = [RW, RW, RO, RW];
        let (host, slices) = plan_subpage(0x18c000, 0x18c000, 0x190000, RO, &current).unwrap();
        assert_eq!(
            host,
            vec![HostProtect {
                addr: 0x18c000,
                old: RW,
                prot: RO
            }]
        );
        assert!(
            recorded(0x18c000, &current, &host, &slices).is_empty(),
            "the host page is now uniformly read-only"
        );
    }

    #[test]
    fn guest4k_a_writable_slice_widens_the_host_page_and_keeps_the_stricter_ones() {
        let current = [RO, RO, RO, RO];
        let (host, slices) = plan_subpage(0x18c000, 0x18e000, 0x18f000, RW, &current).unwrap();
        assert_eq!(
            host,
            vec![HostProtect {
                addr: 0x18c000,
                old: RO,
                prot: RW,
            }]
        );
        assert_eq!(
            recorded(0x18c000, &current, &host, &slices),
            [(0x18c000, RO), (0x18d000, RO), (0x18f000, RO)]
        );
    }

    #[test]
    fn guest4k_prot_none_is_recorded_and_does_not_open_or_close_the_host_page() {
        let current = [RW, RW, RW, RW];
        let (host, slices) = plan_subpage(0x18c000, 0x18e000, 0x18f000, 0, &current).unwrap();
        assert!(host.is_empty());
        assert_eq!(
            recorded(0x18c000, &current, &host, &slices),
            [(0x18e000, 0)]
        );
    }

    #[test]
    fn guest4k_partial_execute_unaligned_address_and_short_current_are_invalid() {
        assert_eq!(
            plan_subpage(0x18c000, 0x18e000, 0x18f000, RO, &[RW, RW, RW]),
            Err(EINVAL)
        );
        assert_eq!(begin_subpage(0x18e001, 0x1000, RO), Err(EINVAL));
        assert_eq!(begin_subpage(0x18e000, 0, RO), Ok(0));
        assert_eq!(begin_subpage(0x18e000, u64::MAX, RO), Err(ENOMEM));
        assert_eq!(begin_subpage(0x18e000, 1, RX), Ok(0x1000));
        assert_eq!(begin_subpage(0x18e000, 1, RO), Ok(0x1000));
        // A 16 KiB-aligned address is not this path. The caller keeps the
        // old rounding for it. Zero length is still a no-op here.
        assert_eq!(begin_subpage(0x18c000, 0, RO), Ok(0));
    }

    #[test]
    fn guest4k_libcrypto_dynamic_section_is_copied_at_its_file_offset() {
        // toybox: mmap(0, 0x12c0, PROT_READ, MAP_PRIVATE, fd, 0x17a000).
        assert_eq!(
            private_file_map(0x17a000, 0x12c0),
            Ok(PrivateFileMap::Copy {
                offset: 0x17a000,
                length: 0x4000
            })
        );
        assert_eq!(
            private_file_map(0x178000, 0x12c0),
            Ok(PrivateFileMap::Direct {
                offset: 0x178000,
                length: 0x4000
            })
        );
    }

    #[test]
    fn guest4k_file_offset_alignment_eof_and_overflow() {
        assert_eq!(private_file_map(0x17a001, 0x12c0), Err(EINVAL));
        assert_eq!(private_file_map(0x17a000, 0), Err(EINVAL));
        assert_eq!(private_file_map(0, u64::MAX), Err(ENOMEM));
        assert_eq!(
            copied_file_bytes(0x17a000, 0x12c0, 0x17a100),
            Ok((0x100, 0x3f00))
        );
        assert_eq!(
            copied_file_bytes(0x17a000, 0x12c0, 0x17a000),
            Ok((0, 0x4000))
        );
        assert_eq!(
            copied_file_bytes(0x17a000, 0x12c0, 0x17a000 + 0x5000),
            Ok((0x4000, 0))
        );
    }

    fn covers(split: RangeSplit, addr: u64) -> bool {
        let host = addr & !(PAGE - 1);
        let bit = 1u8 << ((addr - host) / GUEST_PAGE);
        if let Some(head) = split.head
            && head.host == host
        {
            return head.cover & bit != 0;
        }
        if let Some(tail) = split.tail
            && tail.host == host
        {
            return tail.cover & bit != 0;
        }
        split.full_lo <= addr && addr < split.full_hi
    }

    #[test]
    fn guest4k_reservation_trim_keeps_the_neighbor_slice() {
        // munmap(0x8005d3d000, 0x1e000): tail of a reservation, 4 KiB into a page.
        let tail = split_guest_range(0x8005d3d000, 0x1e000).unwrap();
        assert!(covers(tail, 0x8005d3d000));
        assert!(
            !covers(tail, 0x8005d3c000),
            "the live slice before the trim stays"
        );
        assert_eq!(tail.head.unwrap().cover, 0b1110);
        assert_eq!(tail.full_lo, 0x8005d40000);
        assert_eq!(tail.full_hi, 0x8005d58000);
        assert_eq!(tail.tail.unwrap().cover, 0b0111);

        // munmap(0x8005d5c000, 0x49000) ends at 0x8005da5000, the next segment.
        let prefix = split_guest_range(0x8005d5c000, 0x49000).unwrap();
        assert!(covers(prefix, 0x8005da4000));
        assert!(!covers(prefix, 0x8005da5000));
        assert!(!covers(prefix, 0x8005da6000));
        assert_eq!(prefix.full_hi, 0x8005da4000);
        assert!(prefix.head.is_none());

        // MAP_FIXED mmap(0x8005da5000, 0xdd0) is only the next 4 KiB slice.
        let fixed = split_guest_range(0x8005da5000, 0xdd0).unwrap();
        assert!(fixed.is_partial());
        assert_eq!(fixed.full_lo, 0);
        assert!(covers(fixed, 0x8005da5000));
        assert!(!covers(fixed, 0x8005da4000));
        assert!(!covers(fixed, 0x8005da6000));
        assert_eq!(file_offset_at(0x8005da5000, 0, 0x8005da5000), 0);
    }

    #[test]
    fn guest4k_second_library_fixed_map_and_aligned_range() {
        // Formal smoke: mmap(0x8005d4b000, 0x4e44) is a different library.
        let mapped = split_guest_range(0x8005d4b000, 0x4e44).unwrap();
        assert!(covers(mapped, 0x8005d4b000));
        assert!(!covers(mapped, 0x8005d48000));
        assert_eq!(mapped.full_lo, 0x8005d4c000);
        assert_eq!(file_offset_at(0x8005d4b000, 0, 0x8005d4c000), 0x1000);
        let aligned = split_guest_range(0x8005ce0000, 0x4000).unwrap();
        assert!(!aligned.is_partial());
        assert_eq!(aligned.full_lo, 0x8005ce0000);
        assert_eq!(aligned.full_hi, 0x8005ce4000);
        assert_eq!(split_guest_range(0x1001, 0x1000), Err(EINVAL));
        assert_eq!(split_guest_range(0x8005da5000, 0), Err(EINVAL));
        let other = split_guest_range(0x8005db2000, 0x29000).unwrap();
        assert!(other.is_partial());
        assert!(covers(other, 0x8005db2000));
        assert!(!covers(other, 0x8005db1000));
    }

    #[test]
    fn guest4k_anonymous_bss_zeros_its_slices_and_keeps_the_file_neighbor() {
        // toybox: the data slice at 0x800619e000 stays; .bss is the next
        // 0x8000 bytes, anonymous, and stops where the tail trim began.
        let bss = split_guest_range(0x800619f000, 0x8000).unwrap();
        assert!(covers(bss, 0x800619f000));
        assert!(!covers(bss, 0x800619e000));
        assert_eq!(bss.head.unwrap().cover, 0b1000);
        assert_eq!(bss.full_lo, 0x80061a0000);
        assert_eq!(bss.full_hi, 0x80061a4000);
        assert!(covers(bss, 0x80061a6000));
        assert!(!covers(bss, 0x80061a7000));
        assert_eq!(bss.tail.unwrap().cover, 0b0111);
        assert_eq!(partial_page_offset(true, 0x800619f000, 0, bss.full_lo), 0);
        assert_eq!(
            partial_page_offset(false, 0x800619f000, 0, bss.full_lo),
            0x1000
        );
        let trimmed = split_guest_range(0x80061a7000, 0x59000).unwrap();
        assert!(covers(trimmed, 0x80061a7000));
        assert!(!covers(trimmed, 0x80061a6000));

        // Formal smoke, libc++.so: same length, different address.
        let other = split_guest_range(0x8005de7000, 0x8000).unwrap();
        assert!(covers(other, 0x8005de7000));
        assert!(!covers(other, 0x8005de6000));
        assert_eq!(other.full_lo, 0x8005de8000);
        assert!(!covers(other, 0x8005def000));
        assert_eq!(
            partial_page_offset(true, 0x8005de7000, 0x1000, other.full_lo),
            0
        );
    }

    #[test]
    fn guest4k_relro_beside_text_and_bti_mprotect_share_the_host_page() {
        // libz.so: text occupies the first three slices of 0x8005fb0000
        // (RX) and the data slice 0x8005fb3000 is RW. GNU RELRO asks for
        // PROT_READ on that one slice. The host stays RWX because the text
        // is still executable; the data slice is recorded read-only.
        let current = [RX, RX, RX, RW];
        let (host, slices) =
            plan_subpage(0x8005fb0000, 0x8005fb3000, 0x8005fb4000, RO, &current).unwrap();
        assert_eq!(
            host,
            vec![HostProtect {
                addr: 0x8005fb0000,
                old: RW | RX,
                prot: RX,
            }]
        );
        assert_eq!(
            recorded(0x8005fb0000, &current, &host, &slices),
            [(0x8005fb3000, RO)]
        );
        // libc++.so: mprotect(0x8005ee2000, 0x80000, PROT_READ|PROT_EXEC|PROT_BTI).
        // BTI is not a host bit. The range is already executable, so the
        // host page does not change.
        assert_eq!(prot_bits(0x15), RX);
        assert_eq!(begin_subpage(0x8005ee2000, 0x80000, RX), Ok(0x80000));
        let current = [RX, RX, RX, RX];
        let (host, _) =
            plan_subpage(0x8005ee0000, 0x8005ee2000, 0x8005ee4000, RX, &current).unwrap();
        assert!(host.is_empty());
    }

    #[test]
    fn guest4k_aligned_short_mprotect_leaves_the_next_slice_writable() {
        // toybox wrote 0x80061f5008 (the next slice, +8) after
        // mprotect(0x80061f4000, 0x1000, PROT_READ). The start is 16 KiB
        // aligned and the length is one guest page, so this is not a whole
        // host page. The same shape at 0x8006190000 and 0x8006148000 faulted;
        // 0x8005f17000 and 0x80061a3000 are not 16 KiB aligned and returned.
        assert_eq!(whole_host_pages(0x80061f4000, 0x1000), Ok(false));
        assert_eq!(whole_host_pages(0x8006190000, 0x1000), Ok(false));
        assert_eq!(whole_host_pages(0x8006148000, 0x1000), Ok(false));
        assert_eq!(whole_host_pages(0x8005f17000, 0x1000), Ok(false));
        assert_eq!(whole_host_pages(0x80061f4000, 0x4000), Ok(true));
        assert_eq!(whole_host_pages(0x80061f4001, 0x1000), Err(EINVAL));
        let current = [RW, RW, RW, RW];
        let (host, slices) =
            plan_subpage(0x80061f4000, 0x80061f4000, 0x80061f5000, RO, &current).unwrap();
        assert!(
            host.is_empty(),
            "the other three slices stay writable: {host:?}"
        );
        assert_eq!(slices[1], (0x80061f5000, RW));
        assert_eq!(
            recorded(0x80061f4000, &current, &host, &slices),
            [(0x80061f4000, RO)]
        );
    }
}

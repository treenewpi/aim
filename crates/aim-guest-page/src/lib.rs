//! Guest `mprotect` is tracked in 4 KiB slices. The host page stays 16 KiB.
//! Its protection is write-wins: the read bits of every present slice, write
//! if any slice asks for write, and execute only when some slice asks for
//! execute and none asks for write. Write and execute are never both set.
//!
//! Bionic's `WriteProtected` calls `mprotect` on `__libc_globals` (vaddr
//! `0x18e000`, length `0x1000`, `PROT_READ`). That slice sits inside a host
//! page that also holds writable globals. The call succeeds and those
//! globals stay writable. When every slice of a page asks for the same
//! protection, the host page changes. A read-only slice beside text leaves
//! the page executable. A writable slice drops execute until that write is
//! gone, including a neighbor module's data or an anonymous mapping.

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

/// A non-`MAP_FIXED` file map whose offset is a multiple of 4 KiB.
///
/// The host maps `host_offset` (`offset` cleared to 16 KiB) for
/// `host_length`. The guest pointer is `displacement` bytes into that
/// mapping, still 4 KiB-aligned, and the guest range is `guest_length`.
/// The bytes before the pointer and after the guest range are host slack.
/// They stay mapped until every guest slice of that host page is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShiftedFileMap {
    pub host_offset: u64,
    pub displacement: u64,
    pub host_length: u64,
    pub guest_length: u64,
}

/// `length` and `offset` are the guest arguments. An offset that is not a
/// multiple of 4 KiB, or a zero length, is [`EINVAL`].
pub fn shifted_file_map(offset: u64, length: u64) -> Result<ShiftedFileMap, i32> {
    if length == 0 || offset & (GUEST_PAGE - 1) != 0 {
        return Err(EINVAL);
    }
    let guest_length = guest_page_len(length)?;
    if guest_length == 0 {
        return Err(EINVAL);
    }
    let host_offset = offset & !(PAGE - 1);
    let displacement = offset - host_offset;
    let span = displacement.checked_add(guest_length).ok_or(ENOMEM)?;
    let host_length = host_span(span)?;
    Ok(ShiftedFileMap {
        host_offset,
        displacement,
        host_length,
        guest_length,
    })
}

/// One host page of a shifted file map, relative to EOF.
///
/// A 4 KiB slice is past EOF when it starts at or after `file_len`. Linux
/// `mmap` still succeeds; a touch of that slice raises SIGBUS. A slice that
/// starts before EOF is file data, and the bytes after EOF in that slice
/// are zeros.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EofHost {
    /// Every guest-visible slice starts before EOF.
    File,
    /// Every guest-visible slice starts at or after EOF.
    Bus,
    /// File slices and past-EOF slices share this host page. `bus_at` is
    /// the file offset of the first past-EOF slice.
    Mixed { bus_at: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EofHostPage {
    /// File offset of the host page (`offset` cleared to 16 KiB, plus a
    /// multiple of 16 KiB).
    pub file_offset: u64,
    pub kind: EofHost,
}

/// Classify each host page of `plan` that the guest range touches.
pub fn eof_host_pages(plan: &ShiftedFileMap, file_len: u64) -> Vec<EofHostPage> {
    let guest_lo = plan.host_offset + plan.displacement;
    let guest_hi = guest_lo + plan.guest_length;
    let mut pages = Vec::new();
    let mut host = plan.host_offset;
    let host_end = plan.host_offset + plan.host_length;
    while host < host_end {
        let mut file_slices = 0u8;
        let mut bus_slices = 0u8;
        let mut bus_at = 0u64;
        for slot in 0..4 {
            let at = host + slot * GUEST_PAGE;
            if at >= guest_lo && at + GUEST_PAGE <= guest_hi {
                if at >= file_len {
                    if bus_slices == 0 {
                        bus_at = at;
                    }
                    bus_slices |= 1 << slot;
                } else {
                    file_slices |= 1 << slot;
                }
            }
        }
        let kind = if file_slices == 0 && bus_slices == 0 {
            host += PAGE;
            continue;
        } else if bus_slices == 0 {
            EofHost::File
        } else if file_slices == 0 {
            EofHost::Bus
        } else {
            EofHost::Mixed { bus_at }
        };
        pages.push(EofHostPage {
            file_offset: host,
            kind,
        });
        host += PAGE;
    }
    pages
}

/// True when a 4 KiB page of `[offset, offset+guest_length)` starts at or
/// after `file_len`. Linux raises SIGBUS for a touch of that page.
pub fn guest_page_wholly_past_eof(offset: u64, guest_length: u64, file_len: u64) -> bool {
    if guest_length == 0 {
        return false;
    }
    let mut page = offset & !(GUEST_PAGE - 1);
    let end = match offset.checked_add(guest_length) {
        Some(end) => end,
        None => return true,
    };
    while page < end {
        if page >= file_len {
            return true;
        }
        page += GUEST_PAGE;
    }
    false
}

/// `MAP_FIXED` can be a host file mapping only when the address and the
/// file offset have the same residue modulo 16 KiB. Otherwise the slack
/// before the guest pointer would land on a different address than the
/// file page.
pub fn fixed_residue_matches(addr: u64, offset: u64) -> bool {
    addr & (PAGE - 1) == offset & (PAGE - 1)
}

/// A file `mmap` whose address and offset disagree modulo 16 KiB.
///
/// `MAP_SHARED` cannot be a copy and still be shared. `MAP_PRIVATE` is a
/// copy at every protection: a private write never reaches the file.
/// `PROT_EXEC` without `PROT_WRITE` is filled read-write and then
/// `mprotect`'d, so the copy is never writable and executable at once.
/// Requesting both is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidueMismatch {
    SharedRefused,
    PrivateCopy { fill_rw_then_protect: bool },
}

pub fn residue_mismatch(shared: bool, prot: u32) -> ResidueMismatch {
    if shared {
        ResidueMismatch::SharedRefused
    } else {
        ResidueMismatch::PrivateCopy {
            fill_rw_then_protect: prot & PROT_EXEC != 0 && prot & PROT_WRITE == 0,
        }
    }
}

pub fn private_copy_is_wx(prot: u32) -> bool {
    prot & (PROT_WRITE | PROT_EXEC) == PROT_WRITE | PROT_EXEC
}

/// Host protection of the present slices on one page.
///
/// Read is the union. Write is set when any slice asks for it. Execute is
/// set only when some slice asks for it and none asks for write. A zero
/// word (absent or `PROT_NONE`) contributes nothing: a reservation gap is
/// not a writable neighbor. The result never has write and execute together.
pub fn host_protection(slices: impl IntoIterator<Item = u32>) -> u32 {
    let mut read = 0u32;
    let mut write = false;
    let mut execute = false;
    for prot in slices {
        let prot = prot_bits(prot);
        if prot == 0 {
            continue;
        }
        read |= prot & PROT_READ;
        write |= prot & PROT_WRITE != 0;
        execute |= prot & PROT_EXEC != 0;
    }
    let mut host = read;
    if write {
        host |= PROT_WRITE;
    } else if execute {
        host |= PROT_EXEC;
    }
    host
}

/// Guest protections after `MAP_FIXED` covers `cover` of one host page.
///
/// `prior` is the protection each slice had before this call. Slots outside
/// `cover` keep it, including a `PROT_NONE` reservation (0). The caller
/// passes that prior from before any temporary writable protection used to
/// fill the new slices. A fill does not make the gap writable.
pub fn overlay_fixed(prior: [u32; 4], prior_present: u8, cover: u8, prot: u32) -> ([u32; 4], u8) {
    let prot = prot_bits(prot);
    let mut out = prior.map(prot_bits);
    let mut present = prior_present;
    for slot in 0..4 {
        if cover & (1 << slot) != 0 {
            out[slot] = prot;
            present |= 1 << slot;
        }
    }
    (out, present)
}

/// Hint for a non-`MAP_FIXED` mapping.
///
/// Zero stays zero. An address that is already a host page stays. An
/// address inside a host page moves to the next one, so the mapping does
/// not start in another mapping's leftover 4 KiB slices. Sharing a host
/// page is only for a guest `MAP_FIXED`.
pub fn host_exclusive_hint(addr: u64) -> u64 {
    if addr == 0 || addr & (PAGE - 1) == 0 {
        addr
    } else {
        (addr | (PAGE - 1)).wrapping_add(1)
    }
}

/// How a slice is named in the fault trace: the module, the syscall that
/// established it, and the guest protections since then.
pub fn slice_origin_label(name: &str, call: Option<u64>, history: &[u32]) -> String {
    let call = match call {
        Some(call) => call.to_string(),
        None => "none".to_string(),
    };
    let history = if history.is_empty() {
        "none".to_string()
    } else {
        history
            .iter()
            .map(|prot| format!("{prot:#x}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!("{name} call {call} prot {history}")
}

/// Bytes of the host page to invalidate after a write-to-execute transition.
///
/// The span is the whole 16 KiB page. A guest 4 KiB request is not enough:
/// the other slices of the page were writable too.
pub fn icache_span_on_execute_restore(old: u32, new: u32) -> Option<u64> {
    let (old, new) = (prot_bits(old), prot_bits(new));
    if new & PROT_EXEC != 0 && old & PROT_EXEC == 0 {
        Some(PAGE)
    } else {
        None
    }
}

/// One present 4 KiB slice, named by the module that mapped it.
pub struct SliceView<'a> {
    pub addr: u64,
    pub prot: u32,
    pub module: &'a str,
}

/// An instruction fetch that wants execute while some slice on the same
/// host page still wants write. The host page is not executable.
pub struct ExecWindow<'a> {
    pub fetch: u64,
    pub fetch_slice: u64,
    pub fetch_module: &'a str,
    pub write_slice: u64,
    pub write_module: &'a str,
    pub host: u64,
    pub host_prot: u32,
}

/// `None` when the fetch may run: the slice does not want execute, or the
/// host page is executable because no slice wants write.
pub fn exec_window<'a>(addr: u64, slices: &'a [SliceView<'a>]) -> Option<ExecWindow<'a>> {
    let host = addr & !(PAGE - 1);
    let fetch_slice = addr & !(GUEST_PAGE - 1);
    let fetch = slices.iter().find(|slice| slice.addr == fetch_slice)?;
    if prot_bits(fetch.prot) & PROT_EXEC == 0 {
        return None;
    }
    let host_prot = host_protection(slices.iter().map(|slice| slice.prot));
    if host_prot & PROT_EXEC != 0 {
        return None;
    }
    let write = slices
        .iter()
        .find(|slice| slice.addr != fetch_slice && prot_bits(slice.prot) & PROT_WRITE != 0)
        .or_else(|| {
            slices
                .iter()
                .find(|slice| prot_bits(slice.prot) & PROT_WRITE != 0)
        })?;
    Some(ExecWindow {
        fetch: addr,
        fetch_slice,
        fetch_module: fetch.module,
        write_slice: write.addr,
        write_module: write.module,
        host,
        host_prot,
    })
}

/// Linux `SIGSEGV` / `SEGV_ACCERR`. The address is the fetch.
pub struct ExecFault<'a> {
    pub signo: i32,
    pub code: i32,
    pub si_addr: u64,
    pub window: ExecWindow<'a>,
}

pub const SIGSEGV: i32 = 11;
pub const SEGV_ACCERR: i32 = 2;

pub fn exec_fault<'a>(addr: u64, slices: &'a [SliceView<'a>]) -> Option<ExecFault<'a>> {
    let window = exec_window(addr, slices)?;
    Some(ExecFault {
        signo: SIGSEGV,
        code: SEGV_ACCERR,
        si_addr: window.fetch,
        window,
    })
}

/// The traced line for [`exec_fault`]. `thread` names the guest tid and the
/// host thread, so a different thread is distinguishable.
pub fn format_exec_window(thread: &str, window: &ExecWindow<'_>, count: u64) -> String {
    format!(
        "[linux-abi] SIGSEGV SEGV_ACCERR si_addr {:#x}: {thread} fetch slice {:#x} module {} wants X; slice {:#x} module {} holds W; host page {:#x} prot {:#x} (exec window {count})",
        window.fetch,
        window.fetch_slice,
        window.fetch_module,
        window.write_slice,
        window.write_module,
        window.host,
        window.host_prot,
    )
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
/// walked the wrong range. The host protection is [`host_protection`] of
/// all four slices, including a neighbor module and an anonymous mapping.
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
        for (slot, &was) in chunk.iter().enumerate() {
            let guest = page + slot as u64 * GUEST_PAGE;
            let now = if guest >= req_lo && guest < req_hi {
                prot
            } else {
                was
            };
            next.push(now);
            slices.push((guest, now));
        }
        let old_host = host_protection(chunk.iter().copied());
        let new_host = host_protection(next.iter().copied());
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
/// [`host_protection`] of its current slices.
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
    host_protection(current[base..base + per_host].iter().copied())
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
    fn apexd_shared_zip_map_shifts_onto_the_host_page() {
        // mmap(NULL, 0x24a9, PROT_READ, MAP_SHARED, fd, 0x5a000).
        let plan = shifted_file_map(0x5a000, 0x24a9).unwrap();
        assert_eq!(plan.host_offset, 0x58000);
        assert_eq!(plan.displacement, 0x2000);
        assert_eq!(plan.guest_length, 0x3000);
        assert_eq!(plan.host_length, 0x8000);
        assert_eq!(plan.host_offset + plan.displacement, 0x5a000);
        assert!(!guest_page_wholly_past_eof(
            0x5a000,
            plan.guest_length,
            0x5a000 + 0x24a9
        ));
        assert!(guest_page_wholly_past_eof(0x5a000, plan.guest_length, 0x5c000));
        let inside = eof_host_pages(&plan, 0x5a000 + 0x24a9);
        assert!(inside.iter().all(|page| page.kind == EofHost::File));
        let past = eof_host_pages(&plan, 0x5c000);
        assert_eq!(
            past,
            vec![
                EofHostPage {
                    file_offset: 0x58000,
                    kind: EofHost::File
                },
                EofHostPage {
                    file_offset: 0x5c000,
                    kind: EofHost::Bus
                },
            ]
        );
        let at_eof = shifted_file_map(0x5000, 0x1000).unwrap();
        assert_eq!(
            eof_host_pages(&at_eof, 0x5000),
            vec![EofHostPage {
                file_offset: 0x4000,
                kind: EofHost::Bus
            }]
        );
        let mixed = shifted_file_map(0x5000, 0x2000).unwrap();
        assert_eq!(
            eof_host_pages(&mixed, 0x5100),
            vec![EofHostPage {
                file_offset: 0x4000,
                kind: EofHost::Mixed { bus_at: 0x6000 }
            }]
        );
        assert_eq!(shifted_file_map(0x5a100, 0x24a9), Err(EINVAL));
        assert!(!fixed_residue_matches(0x1000, 0x5a000));
        assert!(fixed_residue_matches(0x2000, 0x5a000));
    }

    #[test]
    fn write_wins_drops_execute_while_any_slice_is_writable() {
        let mixed = host_protection([RX, RW, RX, RW]);
        assert_eq!(mixed & (PROT_WRITE | PROT_EXEC), PROT_WRITE);
        assert_eq!(mixed & PROT_READ, PROT_READ);
        assert_eq!(host_protection([RX, RO, 0, 0]), RX);
        assert_eq!(
            icache_span_on_execute_restore(RW, RX),
            Some(PAGE),
            "the whole host page, not the 4 KiB request"
        );
        assert_eq!(icache_span_on_execute_restore(RX, RX), None);
        assert_eq!(icache_span_on_execute_restore(RX, RW), None);
    }

    #[test]
    fn libcpp_fixed_private_segments_are_copies() {
        // property-r1 getprop-after, /system/lib64/libc++.so.
        // PT_LOAD (p_vaddr, p_offset), each (p_vaddr - p_offset) ≡ 0 (mod 16 KiB):
        // (0, 0), (0x7b8c0, 0x778c0), (0xfed80, 0xf6d80), (0x109c88, 0xfdc88).
        // p_align is 0x4000. One load bias ≡ 0 (mod 16 KiB) would make every
        // segment a file mapping. The measured bias 0x8006206000 ≡ 0x2000, so
        // these MAP_FIXED calls do not.
        for (vaddr, offset) in [
            (0u64, 0u64),
            (0x7b8c0, 0x778c0),
            (0xfed80, 0xf6d80),
            (0x109c88, 0xfdc88),
        ] {
            assert_eq!(vaddr.wrapping_sub(offset) & (PAGE - 1), 0);
        }
        assert_eq!(0x8006206000u64 & (PAGE - 1), 0x2000);
        // mmap(0x8006281000, 0x7fd80, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED, fd, 0x77000)
        let rx = (0x8006281000u64, 0x7fd80u64, 0x77000u64, PROT_READ | PROT_EXEC);
        // mmap(0x8006304000, 0x7c88, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED, fd, 0xf6000)
        let rw = (0x8006304000u64, 0x7c88u64, 0xf6000u64, PROT_READ | PROT_WRITE);
        for (addr, len, off, prot) in [rx, rw] {
            assert!(matches!(
                private_file_map(off, len),
                Ok(PrivateFileMap::Copy { .. })
            ));
            assert!(!fixed_residue_matches(addr, off));
            assert!(!private_copy_is_wx(prot));
        }
        assert_eq!(
            residue_mismatch(false, PROT_READ | PROT_EXEC),
            ResidueMismatch::PrivateCopy {
                fill_rw_then_protect: true
            }
        );
        assert_eq!(
            residue_mismatch(false, PROT_READ | PROT_WRITE),
            ResidueMismatch::PrivateCopy {
                fill_rw_then_protect: false
            }
        );
        assert_eq!(
            residue_mismatch(true, PROT_READ),
            ResidueMismatch::SharedRefused
        );
        assert!(private_copy_is_wx(PROT_READ | PROT_WRITE | PROT_EXEC));
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
        // PROT_READ on that one slice. While the data slice is writable the
        // host page is RW, not executable. After the slice is read-only the
        // host page is RX again, and that slice stays recorded.
        let current = [RX, RX, RX, RW];
        let (host, slices) =
            plan_subpage(0x8005fb0000, 0x8005fb3000, 0x8005fb4000, RO, &current).unwrap();
        assert_eq!(
            host,
            vec![HostProtect {
                addr: 0x8005fb0000,
                old: RW,
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

    #[test]
    fn liblog_bias_12288_relro_restores_execute_and_the_data_stays_reachable() {
        // system/lib64/liblog.so, p_align 0x4000.
        // LOAD RX vaddr 0x8000 filesz 0x96e0; GNU RELRO covers the RW load at
        // vaddr 0x14000 memsz 0x1000; the permanent RW load is vaddr 0x18000.
        // Bias 12288 (0x3000), the residue of the Mac run's 0x8005c47000.
        // RX occupies [0xb000, 0x15000). RELRO occupies [0x17000, 0x18000).
        // Those share host page 0x14000. Data at 0x1b000 is the next page.
        let window = [RX, 0, 0, RW];
        assert_eq!(host_protection(window), RW);
        let during = [
            SliceView {
                addr: 0x14000,
                prot: RX,
                module: "liblog.so",
            },
            SliceView {
                addr: 0x17000,
                prot: RW,
                module: "liblog.so",
            },
        ];
        let fault = exec_fault(0x14010, &during).expect("fetch during the window");
        assert_eq!(
            (fault.signo, fault.code, fault.si_addr),
            (SIGSEGV, SEGV_ACCERR, 0x14010)
        );
        let msg = format_exec_window("guest tid 3 pthread 0x10", &fault.window, 1);
        assert!(msg.contains("liblog.so"), "{msg}");
        assert!(msg.contains("0x14000"), "{msg}");
        assert!(msg.contains("0x17000"), "{msg}");
        assert!(msg.contains("guest tid 3"), "{msg}");
        assert!(msg.contains("wants X") && msg.contains("holds W"), "{msg}");
        let (ops, _) = plan_subpage(0x14000, 0x17000, 0x18000, RO, &window).unwrap();
        assert_eq!(
            ops,
            vec![HostProtect {
                addr: 0x14000,
                old: RW,
                prot: RX,
            }]
        );
        assert_eq!(
            icache_span_on_execute_restore(ops[0].old, ops[0].prot),
            Some(PAGE)
        );
        let after = [
            SliceView {
                addr: 0x14000,
                prot: RX,
                module: "liblog.so",
            },
            SliceView {
                addr: 0x17000,
                prot: RO,
                module: "liblog.so",
            },
        ];
        assert!(exec_fault(0x14010, &after).is_none());
        assert_eq!(host_protection([RX, 0, 0, RO]), RX);
        // The permanent data segment is a different host page and stays writable.
        assert_eq!(host_protection([0, 0, 0, RW]), RW);
    }

    #[test]
    fn libm_bias_4096_relro_window_ends_executable() {
        // apex libm.so, p_align 0x4000. LOAD RX vaddr 0x14000 memsz 0x230c0
        // rounds to guest end 0x38000. GNU RELRO is vaddr 0x38000 memsz 0x1000.
        // Bias 4096 puts RX at slice 0x38000 and RELRO at slice 0x39000 of host
        // page 0x38000. The permanent RW load at vaddr 0x3c000 lands at 0x3d000.
        let window = [RX, RW, 0, 0];
        assert_eq!(host_protection(window), RW);
        let during = [
            SliceView {
                addr: 0x38000,
                prot: RX,
                module: "libm.so",
            },
            SliceView {
                addr: 0x39000,
                prot: RW,
                module: "libm.so",
            },
        ];
        let fault = exec_fault(0x38020, &during).expect("fetch during the window");
        assert_eq!(
            (fault.signo, fault.code, fault.si_addr),
            (SIGSEGV, SEGV_ACCERR, 0x38020)
        );
        let msg = format_exec_window("guest tid 4 pthread 0x20", &fault.window, 1);
        assert!(msg.contains("0x38000") && msg.contains("0x39000"), "{msg}");
        assert!(msg.contains("libm.so") && msg.contains("guest tid 4"), "{msg}");
        let (ops, _) = plan_subpage(0x38000, 0x39000, 0x3a000, RO, &window).unwrap();
        assert_eq!(
            ops,
            vec![HostProtect {
                addr: 0x38000,
                old: RW,
                prot: RX,
            }]
        );
        assert_eq!(
            icache_span_on_execute_restore(ops[0].old, ops[0].prot),
            Some(PAGE)
        );
        assert!(
            exec_fault(
                0x38020,
                &[
                    SliceView {
                        addr: 0x38000,
                        prot: RX,
                        module: "libm.so",
                    },
                    SliceView {
                        addr: 0x39000,
                        prot: RO,
                        module: "libm.so",
                    },
                ],
            )
            .is_none()
        );
        assert_eq!(host_protection([0, RW, 0, 0]), RW);
    }

    #[test]
    fn two_modules_share_a_host_page_until_the_last_write_drops() {
        // liba.so text, libb.so data, and an anonymous mapping on one page.
        let during = [RX, RX, RW, RW];
        assert_eq!(host_protection(during), RW);
        let views = [
            SliceView {
                addr: 0x8000,
                prot: RX,
                module: "liba.so",
            },
            SliceView {
                addr: 0x9000,
                prot: RX,
                module: "liba.so",
            },
            SliceView {
                addr: 0xa000,
                prot: RW,
                module: "libb.so",
            },
            SliceView {
                addr: 0xb000,
                prot: RW,
                module: "anonymous",
            },
        ];
        let fault = exec_fault(0x8004, &views).unwrap();
        assert_eq!(fault.window.fetch_module, "liba.so");
        assert_eq!(fault.window.fetch_slice, 0x8000);
        assert_eq!(fault.window.write_module, "libb.so");
        assert_eq!(fault.window.write_slice, 0xa000);
        assert_eq!(fault.si_addr, 0x8004);
        let msg = format_exec_window("guest tid 9 pthread 0xabc", &fault.window, 2);
        assert!(msg.contains("liba.so") && msg.contains("libb.so"), "{msg}");
        assert!(msg.contains("guest tid 9"), "{msg}");
        // Protecting libb's data does not restore execute: anonymous still writes.
        let (ops, _) = plan_subpage(0x8000, 0xa000, 0xb000, RO, &during).unwrap();
        assert!(ops.is_empty(), "a remaining writer keeps execute off: {ops:?}");
        let still = [RX, RX, RO, RW];
        assert_eq!(host_protection(still), RW);
        let held = [
            SliceView {
                addr: 0x8000,
                prot: RX,
                module: "liba.so",
            },
            SliceView {
                addr: 0xb000,
                prot: RW,
                module: "anonymous",
            },
        ];
        let fault = exec_fault(0x8010, &held).unwrap();
        assert_eq!(fault.window.write_module, "anonymous");
        assert_eq!(fault.window.write_slice, 0xb000);
        // munmap of the last writable slice restores execute.
        let (ops, _) = plan_subpage(0x8000, 0xb000, 0xc000, 0, &still).unwrap();
        assert_eq!(
            ops,
            vec![HostProtect {
                addr: 0x8000,
                old: RW,
                prot: RX,
            }]
        );
        assert_eq!(
            icache_span_on_execute_restore(ops[0].old, ops[0].prot),
            Some(PAGE)
        );
        assert!(
            exec_fault(
                0x8010,
                &[SliceView {
                    addr: 0x8000,
                    prot: RX,
                    module: "liba.so",
                }],
            )
            .is_none()
        );
    }

    #[test]
    fn libc_text_tail_keeps_execute_beside_a_prot_none_reservation() {
        // apex libc.so LOAD RX: vaddr 0x58000, p_filesz == p_memsz == 0x8cc30,
        // p_align 0x4000. Bias 0x8009ef8000 is the traced mapping
        // mmap(0x8009f50000, 0x8cc30, R|X, PRIVATE|FIXED, fd, 0x58000).
        // Guest end rounds to 0x8009fdd000. The next LOAD starts at vaddr
        // 0xe8000 (0x8009fe0000). MapBssSection does not run: the file page
        // end and the memory page end are the same. The three slices
        // [0x8009fdd000, 0x8009fe0000) are the PROT_NONE reservation
        // ReserveWithAlignmentPadding left between the segments. There is
        // no second mmap. A fill of the text slice must not record that gap
        // as writable.
        let host = 0x8009fdc000u64;
        let prior = [0, 0, 0, 0];
        let (prot, present) = overlay_fixed(prior, 0b1111, 0b0001, RX);
        assert_eq!(present, 0b1111);
        assert_eq!(prot, [RX, 0, 0, 0]);
        assert_eq!(host_protection(prot), RX);
        let fixed = [
            SliceView {
                addr: host,
                prot: RX,
                module: "libc.so+0xe4000 call 200 prot 0x5",
            },
            SliceView {
                addr: host + 0x1000,
                prot: 0,
                module: "anonymous call 40 prot 0x0",
            },
            SliceView {
                addr: host + 0x2000,
                prot: 0,
                module: "anonymous call 40 prot 0x0",
            },
            SliceView {
                addr: host + 0x3000,
                prot: 0,
                module: "anonymous call 40 prot 0x0",
            },
        ];
        assert!(
            exec_fault(0x8009fdc9f0, &fixed).is_none(),
            "PROT_NONE is not a writer"
        );
        // The bug recorded the fill's writable host protection on the gap.
        let leaked = [RX, RW, RW, RW];
        assert_eq!(host_protection(leaked), RW);
        let leaked_views = [
            SliceView {
                addr: host,
                prot: RX,
                module: "libc.so+0xe4000 call 200 prot 0x5",
            },
            SliceView {
                addr: host + 0x1000,
                prot: RW,
                module: "anonymous call 40 prot 0x3",
            },
        ];
        let fault = exec_fault(0x8009fdc9f0, &leaked_views).unwrap();
        assert_eq!(fault.si_addr, 0x8009fdc9f0);
        assert_eq!(fault.window.write_slice, host + 0x1000);
        assert_eq!(fault.window.fetch_slice, host);
        let msg = format_exec_window("guest tid 53315 pthread 0x1", &fault.window, 1);
        assert!(msg.contains("anonymous call 40 prot 0x3"), "{msg}");
        assert!(msg.contains("libc.so+0xe4000 call 200 prot 0x5"), "{msg}");
        assert!(msg.contains("guest tid 53315"), "{msg}");
        // A later MAP_FIXED anonymous writer in the gap is a real neighbor.
        let (with_writer, _) = overlay_fixed(prot, present, 0b0010, RW);
        assert_eq!(with_writer, [RX, RW, 0, 0]);
        assert_eq!(host_protection(with_writer), RW);
        assert_eq!(
            host_exclusive_hint(0x8009fdd000),
            0x8009fe0000,
            "a non-fixed hint inside this page starts at the next host page"
        );
        assert_eq!(host_exclusive_hint(host), host);
        assert_eq!(host_exclusive_hint(0), 0);
        assert_eq!(
            slice_origin_label("anonymous", Some(40), &[0]),
            "anonymous call 40 prot 0x0"
        );
        assert_eq!(
            slice_origin_label("anonymous", None, &[0, RW]),
            "anonymous call none prot 0x0,0x3"
        );
    }
}

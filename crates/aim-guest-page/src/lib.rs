//! How a 4 KiB guest `mprotect` lands on a 16 KiB host page.
//!
//! Bionic's `WriteProtected` locks `__libc_globals` with a hardcoded
//! `mprotect(addr, 0x1000, PROT_READ)` (`linker64` vaddr `0x18e000`, 8 KiB
//! into a 16 KiB page) even though every `PT_LOAD` is 16 KiB-aligned.
//! Darwin cannot change protection below 16 KiB. The host page's protection
//! is the union of its 4 KiB slices. A stricter slice beside a more
//! permissive one is recorded by the caller and not enforced. This is not
//! a 4 KiB sandbox. `PROT_EXEC` on a partial host page is rejected instead
//! of widening the page to RWX.

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

/// Round `len` up to [`GUEST_PAGE`]. Zero stays zero. Overflow is [`ENOMEM`].
pub fn guest_page_len(len: u64) -> Result<u64, i32> {
    if len == 0 {
        return Ok(0);
    }
    let rounded = len.checked_add(GUEST_PAGE - 1).ok_or(ENOMEM)?;
    Ok(rounded & !(GUEST_PAGE - 1))
}

/// Alignment, length and execute checks for a guest `mprotect` that is not
/// aligned to [`PAGE`]. `Ok(0)` is a successful no-op. `Ok(len)` is the
/// rounded length the caller maps and protects.
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
    // A partial host page cannot gain execute without making its other
    // slices executable too.
    if prot & PROT_EXEC != 0 {
        return Err(EINVAL);
    }
    Ok(len)
}

/// Plan the host operations and the guest slices a sub-page `mprotect` stores.
///
/// `current` is every 4 KiB slice of each touched host page, in order. A
/// length that is not a multiple of four slices is [`EINVAL`]: the caller
/// walked the wrong range. A resulting host page that is executable in some
/// slices and not in others is [`EINVAL`].
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
        if next.iter().any(|slice| slice & PROT_EXEC != 0)
            && next.iter().any(|slice| slice & PROT_EXEC == 0)
        {
            return Err(EINVAL);
        }
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
            plan_subpage(0x18c000, 0x18e000, 0x18f000, RX, &[RW, RW, RW, RW]),
            Err(EINVAL)
        );
        assert_eq!(
            plan_subpage(0x18c000, 0x18e000, 0x18f000, RO, &[RW, RW, RW]),
            Err(EINVAL)
        );
        assert_eq!(begin_subpage(0x18e001, 0x1000, RO), Err(EINVAL));
        assert_eq!(begin_subpage(0x18e000, 0, RO), Ok(0));
        assert_eq!(begin_subpage(0x18e000, u64::MAX, RO), Err(ENOMEM));
        assert_eq!(begin_subpage(0x18e000, 1, RX), Err(EINVAL));
        assert_eq!(begin_subpage(0x18e000, 1, RO), Ok(0x1000));
        // A 16 KiB-aligned address is not this path. The caller keeps the
        // old rounding for it. Zero length is still a no-op here.
        assert_eq!(begin_subpage(0x18c000, 0, RO), Ok(0));
    }
}

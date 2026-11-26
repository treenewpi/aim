//! Memory syscalls: mmap, munmap, mremap, mprotect, madvise, brk.
//!
//! - Executable private file mappings of translated files (and of
//!   originals with nothing to rewrite) are mapped shared and read-only,
//!   then made executable, so every process shares the same pages (Darwin
//!   refuses PROT_EXEC in the mmap itself; ADR 0012, "Platform probes").
//!   Executable private mappings of other files are materialized as
//!   anonymous memory filled with `pread` and rewritten (see `patch`).
//! - Other private mappings of regular files map the file copy-on-write,
//!   as Linux does: pages are shared with the file until written, and a
//!   write stays private. Whether a later change to the file shows is
//!   unspecified (mmap(2)): Linux shows it in pages not written yet,
//!   Darwin's copy-on-write keeps the file as it was at mmap (as the
//!   anonymous copies did). An access to a page wholly past the end of
//!   the file faults (SIGBUS), and MADV_DONTNEED reads the file again. A
//!   mapping of a file that needs rewriting is rewritten when it becomes
//!   executable ([`mprotect`]), which copies only the pages written.
//! - Shared file mappings go straight to Darwin `mmap`. An offset that is
//!   a multiple of 4 KiB but not of 16 KiB is the enclosing host pages,
//!   and the pointer is displaced into that mapping. `mmap_rnd_bits` does
//!   not move the file offset. A `MAP_FIXED` request whose address and
//!   offset disagree modulo 16 KiB is `EINVAL`: a copy would not be shared.
//!   A guest page that starts at or after EOF is installed, and a touch
//!   raises SIGBUS. A past-EOF page that shares a host page with a guest
//!   page that still contains file bytes stays that shared mapping.
//! - A BoringSSL FIPS module rewritten at load time gets its integrity hash
//!   recomputed in memory, as the translator does for cached files.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::context::GuestContext;
use crate::errno::{self, EEXIST, EINVAL, ENOMEM};
use crate::patch;
use crate::xlate::fips;
use crate::xrt::{self, ExecSource};

use std::os::unix::ffi::OsStrExt;

use super::{arena, copies, vm_account, vmmap, window};

pub(super) use aim_guest_page::PAGE;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const PROT_BTI: u64 = 0x10;
const PROT_MTE: u64 = 0x20;

const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_SHARED_VALIDATE: u64 = 0x03;
const MAP_TYPE: u64 = 0x0f;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_GROWSDOWN: u64 = 0x0100;
const MAP_NORESERVE: u64 = 0x4000;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;

fn page_up(v: u64) -> u64 {
    (v + PAGE - 1) & !(PAGE - 1)
}

fn host_prot(p: u64) -> i32 {
    (p & (PROT_READ | PROT_WRITE | PROT_EXEC)) as i32
}

fn host_mmap(addr: u64, len: u64, prot: i32, flags: i32, fd: i32, off: i64) -> Result<u64, i64> {
    // SAFETY: forwarding a validated guest request to Darwin.
    let p = unsafe { libc::mmap(addr as *mut _, len as usize, prot, flags, fd, off) };
    if p == libc::MAP_FAILED {
        Err(-(errno::last() as i64))
    } else {
        if flags & libc::MAP_FIXED != 0 {
            super::memfd::unmapped(p as u64, len);
        }
        Ok(p as u64)
    }
}

fn host_mprotect(addr: u64, len: u64, prot: i32) -> i64 {
    // SAFETY: guest-requested protection change on guest memory.
    errno::check(unsafe { libc::mprotect(addr as *mut _, len as usize, prot) } as i64)
}

fn trace_stats(what: &str, addr: u64, len: u64, stats: &patch::PatchStats) {
    if crate::sys::tracing() && stats.total() > 0 {
        crate::diag!(
            "[linux-abi] {what} {:#x}..{:#x}: {} svc, {} mrs/{} msr tpidr_el0, {} scs, {} ctr_el0, {} brk fallbacks",
            addr,
            addr + len,
            stats.svc,
            stats.mrs_tp,
            stats.msr_tp,
            stats.scs,
            stats.ctr,
            stats.brk_fallback
        );
    }
}

/// Fill `[b, b+len)` from `fd` at `off`.
fn populate(b: u64, len: u64, fd: i32, off: u64) -> Result<(), i64> {
    use std::os::fd::BorrowedFd;
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let description =
        super::regular_file::adopt_kernel(borrowed, 0).map_err(|error| -(error as i64))?;
    let source = super::verified_source::VerifiedSource::from_descriptor(borrowed, description)
        .map_err(|error| -(error as i64))?;
    let available = source
        .len()
        .map_err(|error| -(error as i64))?
        .saturating_sub(off)
        .min(len);
    let mut bytes = vec![0; available as usize];
    source
        .read_exact_at(&mut bytes, off)
        .map_err(|error| -(error as i64))?;
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), b as *mut u8, bytes.len());
    }
    Ok(())
}

/// Rewrite a freshly populated private file mapping (not executable yet)
/// using the file's sites, or a scan when there is no metadata.
fn rewrite_file_copy(b: u64, len: u64, fd: i32, off: u64, source: &ExecSource) -> Result<(), i64> {
    let stats = match source {
        ExecSource::LoadTime(Some(a)) => {
            let abs: Vec<_> = a
                .sites
                .iter()
                .filter(|&&(o, _, _)| o >= off && o + 4 <= off + len)
                .map(|&(o, kind, rt)| (b + (o - off), kind, rt))
                .collect();
            let stats = patch::rewrite_sites(&abs, b, b + len, true);
            if let Some(m) = &a.fips {
                rehash_fips(m, b, len, fd, off)?;
            }
            stats
        }
        // Already translated (or nothing to rewrite): a scan would only hit
        // words the translator identified as data.
        ExecSource::Shared => return Ok(()),
        ExecSource::LoadTime(None) => patch::rewrite_region(b, len),
    };
    // Every file that takes this path is named, sites or not: no cache
    // had it (the image cache test counts these).
    if crate::sys::tracing() {
        let path = xrt::fd_path(fd).unwrap_or_default();
        crate::diag!(
            "[linux-abi] load-time rewrite of {} at offset {off:#x}: {} sites",
            path.display(),
            stats.total()
        );
    }
    trace_stats("rewrote", b, len, &stats);
    Ok(())
}

/// After the copy at `b` (file offset `off`) holding the module text was
/// rewritten, store the module's new hash. The read-only data is never
/// rewritten, so it comes from the file. The hash is in `.rodata` (or, in
/// static builds, after the text), which linker64 has mapped by now: it maps
/// segments in program header order.
fn rehash_fips(m: &fips::Module, b: u64, len: u64, fd: i32, off: u64) -> Result<(), i64> {
    let text_len = m.text.1 - m.text.0;
    if m.text_offset < off || m.text_offset + text_len > off + len {
        return Ok(());
    }
    let text_addr = b + (m.text_offset - off);
    let rodata = match m.rodata {
        Some((lo, hi)) => {
            let mut v = vec![0u8; (hi - lo) as usize];
            use std::os::fd::BorrowedFd;
            let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
            let description =
                super::regular_file::adopt_kernel(borrowed, 0).map_err(|error| -(error as i64))?;
            let source =
                super::verified_source::VerifiedSource::from_descriptor(borrowed, description)
                    .map_err(|error| -(error as i64))?;
            source
                .read_exact_at(&mut v, m.rodata_offset)
                .map_err(|error| -(error as i64))?;
            Some(v)
        }
        None => None,
    };
    // SAFETY: the module text lies inside the populated copy.
    let text = unsafe { std::slice::from_raw_parts(text_addr as *const u8, text_len as usize) };
    let new = fips::digest(text, rodata.as_deref());
    let hash_addr = (text_addr - m.text.0).wrapping_add(m.hash_vaddr);
    if !store_hash(hash_addr, &m.original, &new) {
        crate::diag!("[linux-abi] FIPS module hash at {hash_addr:#x} is not mapped from this file");
    }
    Ok(())
}

/// Replace `original` with `new` at `addr` in an anonymous copy of the
/// file. False when no such copy is mapped there.
fn store_hash(addr: u64, original: &fips::Hash, new: &fips::Hash) -> bool {
    let Some((lo, hi, prot, _)) = patch::vm::region(addr) else {
        return false;
    };
    if lo > addr || hi < addr + 32 || prot & libc::PROT_READ == 0 || file_backed(addr) {
        return false;
    }
    // SAFETY: readable, inside one region.
    if unsafe { std::slice::from_raw_parts(addr as *const u8, 32) } != original {
        return false;
    }
    let page = addr & !(PAGE - 1);
    let span = page_up(addr + 32) - page;
    let opened = prot & libc::PROT_WRITE == 0;
    if opened && host_mprotect(page, span, prot | libc::PROT_WRITE) < 0 {
        return false;
    }
    // SAFETY: writable now; the 32 bytes checked above.
    unsafe { std::ptr::copy_nonoverlapping(new.as_ptr(), addr as *mut u8, 32) };
    if opened {
        host_mprotect(page, span, prot);
    }
    true
}

/// mmap, counted against RLIMIT_AS and RLIMIT_DATA (`mmap_region`).
pub fn mmap(a: [u64; 6]) -> i64 {
    let result = mmap_accounted(a);
    if result >= 0 {
        let partial = a[3] & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0
            && aim_guest_page::split_guest_range(a[0], a[1])
                .ok()
                .is_some_and(|split| split.is_partial());
        let len = if partial {
            aim_guest_page::guest_page_len(a[1]).unwrap_or(0)
        } else {
            page_up(a[1])
        };
        // After `mmap_guest` drops origins inside the new range. The
        // reservation's slices outside that range keep the call that
        // created them.
        record_established(result as u64, len, a[2], a[3], a[4] as i32, a[5]);
    }
    result
}

fn mmap_accounted(a: [u64; 6]) -> i64 {
    if a[3] & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0
        && let Ok(split) = aim_guest_page::split_guest_range(a[0], a[1])
        && split.is_partial()
    {
        let len = match aim_guest_page::guest_page_len(a[1]) {
            Ok(len) => len,
            Err(error) => return -(error as i64),
        };
        let kind = vm_account::Kind {
            shared: matches!(a[3] & MAP_TYPE, MAP_SHARED | MAP_SHARED_VALIDATE),
            writable: a[2] & PROT_WRITE != 0,
            stack: a[3] & MAP_GROWSDOWN != 0,
        };
        let (limits, heap) = (super::cred::memory_limits(), brk_heap());
        if !vm_account::with(|s| s.may_map(limits, heap, a[0], len, kind)) {
            return -(ENOMEM as i64);
        }
        return mmap_guest(a, |lo| {
            vm_account::with(|s| s.map(lo, lo + len, kind));
            forget_guest_slices(lo, lo + len);
        });
    }
    let len = page_up(a[1]);
    let kind = vm_account::Kind {
        shared: matches!(a[3] & MAP_TYPE, MAP_SHARED | MAP_SHARED_VALIDATE),
        writable: a[2] & PROT_WRITE != 0,
        stack: a[3] & MAP_GROWSDOWN != 0,
    };
    if len != 0 {
        let (limits, heap) = (super::cred::memory_limits(), brk_heap());
        let replaced = if a[3] & MAP_FIXED != 0 {
            a[0]
        } else {
            u64::MAX
        };
        if !vm_account::with(|s| s.may_map(limits, heap, replaced, len, kind)) {
            return -(ENOMEM as i64);
        }
    }
    mmap_guest(a, |lo| {
        vm_account::with(|s| s.map(lo, lo + len, kind));
        super::vma_names::forget(lo, lo + len);
        forget_guest_slices(lo, lo + len);
    })
}
/// The mapping itself; `mapped` records a new one at its address, under the
/// VM epoch with it.
fn mmap_guest(mut a: [u64; 6], mapped: impl FnOnce(u64)) -> i64 {
    if a[3] & MAP_ANONYMOUS != 0 {
        let _epoch = super::verity_pager::mutation();
        let _mapping = super::memfd::mapping_change();
        let result = mmap_owned(a);
        if result >= 0
            && let Err(error) = super::verity_pager::reconcile_memberships()
        {
            return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
        }
        if result >= 0 {
            mapped(result as u64);
        }
        return result;
    }
    use std::os::fd::AsRawFd;
    let guest_fd = a[4] as i32;
    let held = match super::fdtab::pin_guest(guest_fd) {
        Ok(held) => held,
        Err(error) => return -(error as i64),
    };
    if matches!(held.kind(), Some(super::fdtab::Kind::Path(_))) {
        return -(crate::errno::EBADF as i64);
    }
    if matches!(held.kind(), Some(super::fdtab::Kind::ProcMem(_))) {
        return -(crate::errno::ENODEV as i64);
    }
    let object = match held.kind() {
        Some(super::fdtab::Kind::Bpf) if a[1] == 0 || a[5] & (PAGE - 1) != 0 => {
            return -(EINVAL as i64);
        }
        Some(super::fdtab::Kind::Bpf) => match super::bpf::mmap_pieces(
            held.descriptor().as_raw_fd(),
            a[5],
            page_up(a[1]),
            a[2] & PROT_WRITE != 0,
            matches!(a[3] & MAP_TYPE, MAP_SHARED | MAP_SHARED_VALIDATE),
        ) {
            Ok(pieces) => Some(pieces),
            Err(error) => return error,
        },
        _ => None,
    };
    let identity = match held.kind() {
        Some(super::fdtab::Kind::Regular(description)) => Some(description.identity),
        _ => None,
    };
    let client = identity.and_then(|_| crate::verity_client());
    // Begin before the VM epoch: an enable transaction may need its exclusive
    // epoch while admission waits. Proof lookup below happens after this ACK.
    let admission = match (&client, identity) {
        (Some(client), Some(identity)) => match client.admission(identity.to_bytes()) {
            Ok(admission) => Some(admission),
            Err(error) => {
                crate::diag!(
                    "[mmap-owner] stage=verity-admission guest_fd={guest_fd} native_fd={} error={error}",
                    held.descriptor().as_raw_fd()
                );
                return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
            }
        },
        _ => None,
    };
    let _epoch = super::verity_pager::mutation();
    if a[3] & MAP_FIXED != 0 {
        super::verity_pager::wait_pending(a[0], page_up(a[1]));
    }
    let _mapping = super::memfd::mapping_change();
    a[4] = held.descriptor().as_raw_fd() as u64;
    let result = match object {
        Some(pieces) => mmap_object(a, &pieces),
        None => mmap_pinned(a, &held),
    };
    if let Some(admission) = admission {
        let finish = if result >= 0 {
            super::verity_pager::publish_membership(identity.unwrap(), admission)
        } else {
            admission.abort()
        };
        if let Err(error) = finish {
            if result >= 0 {
                let _ = super::verity_pager::forget(result as u64, page_up(a[1]));
                window::unmap(result as u64, page_up(a[1]));
            }
            return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
        }
    }
    if result >= 0
        && let Err(error) = super::verity_pager::reconcile_memberships()
    {
        return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
    }
    if result >= 0 {
        mapped(result as u64);
    }
    result
}
/// mmap of a bpf object (`a[4]`, its host fd): its `pieces`, one after the
/// other, over a reservation of the whole range. As `bpf_map_mmap` clears
/// VM_MAYWRITE, a mapping made without write never gains it.
fn mmap_object(a: [u64; 6], pieces: &[(u64, u64)]) -> i64 {
    let len = page_up(a[1]);
    let base = match pieces {
        [(offset, _)] => mmap_owned([a[0], a[1], a[2], a[3], a[4], *offset]),
        _ => mmap_owned([
            a[0],
            len,
            0,
            (a[3] & !MAP_TYPE) | MAP_PRIVATE | MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]),
    };
    if base < 0 {
        return base;
    }
    if pieces.len() > 1 {
        let mut at = base as u64;
        for &(offset, n) in pieces {
            let placed = mmap_owned([
                at,
                n,
                a[2],
                (a[3] & !MAP_FIXED_NOREPLACE) | MAP_FIXED,
                a[4],
                offset,
            ]);
            if placed < 0 {
                window::unmap(base as u64, len);
                return placed;
            }
            at += n;
        }
    }
    if a[2] & PROT_WRITE == 0 {
        let most = (libc::PROT_READ | libc::PROT_EXEC) as i32;
        // SAFETY: the maximum protection of the mapping made above.
        if unsafe { mach_vm_protect(task(), base as u64, len, 1, most) } != 0 {
            window::unmap(base as u64, len);
            return -(ENOMEM as i64);
        }
    }
    base
}
fn mmap_pinned(a: [u64; 6], held: &super::fdtab::Pinned) -> i64 {
    use std::os::fd::AsRawFd;
    // A 4 KiB-aligned MAP_FIXED range is filled by copying the covered
    // slices. Verity registrations are 16 KiB, so this range is not one.
    let partial = a[3] & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0
        && matches!(
            aim_guest_page::split_guest_range(a[0], a[1]),
            Ok(split) if split.is_partial()
        );
    if let Some(super::fdtab::Kind::Regular(description)) = held.kind() {
        if !matches!(description.flags & 3, 0 | 2) {
            return -(errno::EACCES as i64);
        }
        if partial {
            return mmap_owned(a);
        }
        let proof = match description.store.lookup(description.identity) {
            Ok(proof) => proof,
            Err(_) => return -(errno::EIO as i64),
        };
        if let Some(proof) = proof {
            use std::os::fd::FromRawFd;
            let source = match aim_storage::private_fd::PrivateFd::allocate(|| {
                let fd =
                    unsafe { libc::fcntl(held.descriptor().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
            }) {
                Ok(data) => std::sync::Arc::new(super::verity_pager::Source {
                    data,
                    proof: Some(std::sync::Arc::new(proof)),
                    description: Some(description.clone()),
                    cache: match super::verity_pager::MappingCache::runtime() {
                        Ok(cache) => cache,
                        Err(error) => {
                            return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO))
                                as i64);
                        }
                    },
                    extent: None,
                    derivative: None,
                }),
                Err(error) => {
                    return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
                }
            };
            let shared = matches!(a[3] & MAP_TYPE, MAP_SHARED | MAP_SHARED_VALIDATE);
            if shared && a[2] & PROT_WRITE != 0 {
                return -(errno::EACCES as i64);
            }
            let result = mmap_owned([
                a[0],
                a[1],
                0,
                (a[3] & !MAP_TYPE) | MAP_PRIVATE | MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]);
            if result < 0 {
                return result;
            }
            let base = result as u64;
            let length = page_up(a[1]);
            match super::verity_pager::register(base, length, a[5], host_prot(a[2]), shared, source)
            {
                Ok(mapping) => {
                    super::verity_pager::retain(mapping);
                    return result;
                }
                Err(error) => {
                    window::unmap(base, length);
                    return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
                }
            }
        }
    }
    let result = mmap_owned(a);
    if result >= 0
        && let Some(super::fdtab::Kind::Regular(description)) = held.kind()
    {
        use std::os::fd::FromRawFd;
        let data = match aim_storage::private_fd::PrivateFd::allocate(|| {
            let fd =
                unsafe { libc::fcntl(held.descriptor().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
        }) {
            Ok(data) => data,
            Err(error) => {
                return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
            }
        };
        let cache = match super::verity_pager::MappingCache::runtime() {
            Ok(cache) => cache,
            Err(error) => {
                crate::diag!(
                    "[mmap-owner] stage=mapping-cache native_fd={} error={error}",
                    held.descriptor().as_raw_fd()
                );
                return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
            }
        };
        let source = std::sync::Arc::new(super::verity_pager::Source {
            data,
            proof: None,
            description: Some(description.clone()),
            cache,
            extent: None,
            derivative: None,
        });
        if let Err(error) = super::verity_pager::track_existing(
            result as u64,
            page_up(a[1]),
            a[5],
            host_prot(a[2]),
            matches!(a[3] & MAP_TYPE, MAP_SHARED | MAP_SHARED_VALIDATE),
            source,
        ) {
            window::unmap(result as u64, page_up(a[1]));
            return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
        }
    }
    result
}

/// Kernel callers retain their authenticated private descriptor separately.
/// This entry never treats a hidden kernel carrier as a guest descriptor.
fn mmap_owned(a: [u64; 6]) -> i64 {
    if a[3] & MAP_FIXED != 0 && super::verity_pager::overlaps(a[0], page_up(a[1])) {
        return super::verity_pager::replace_range(a[0], page_up(a[1]), || mmap_kernel(a));
    }
    mmap_kernel(a)
}
fn file_len(fd: i32) -> Result<u64, i64> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(-(errno::last() as i64));
    }
    Ok(st.st_size.max(0) as u64)
}

/// `MAP_SHARED` of a 4 KiB-aligned file offset. The host mapping starts at
/// `offset & ~0x3fff` and the returned pointer is `base + (offset & 0x3fff)`.
/// Slack at either end of a host page is released only when that page's
/// guest slices are all gone (`PAGE_PIECES`).
fn mmap_shifted_shared(addr: u64, len: u64, prot: u64, _flags: u64, fd: i32, off: u64) -> i64 {
    let plan = match aim_guest_page::shifted_file_map(off, len) {
        Ok(plan) => plan,
        Err(error) => return -(error as i64),
    };
    let file_len = match file_len(fd) {
        Ok(len) => len,
        Err(error) => return error,
    };
    let eof_pages = aim_guest_page::eof_host_pages(&plan, file_len);
    let any_file = eof_pages
        .iter()
        .any(|page| !matches!(page.kind, aim_guest_page::EofHost::Bus));
    let any_bus = eof_pages
        .iter()
        .any(|page| matches!(page.kind, aim_guest_page::EofHost::Bus));
    for page in &eof_pages {
        if let aim_guest_page::EofHost::Mixed { bus_at } = page.kind {
            crate::diag!(
                "[linux-abi] mmap: 4 KiB page at file offset {bus_at:#x} is past EOF {file_len:#x} and shares a 16 KiB page with file bytes; that slice stays the shared mapping's zero-fill"
            );
        }
    }
    let hint = arena::hint(addr.wrapping_sub(plan.displacement), plan.host_length);
    let placing = arena::placing();
    let file_map = host_mmap(
        hint,
        plan.host_length,
        host_prot(prot),
        libc::MAP_SHARED,
        fd,
        plan.host_offset as i64,
    );
    let base = match file_map {
        Ok(base) => base,
        Err(error) if !any_file => match host_mmap(
            hint,
            plan.host_length,
            libc::PROT_NONE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        ) {
            Ok(base) => base,
            Err(_) => return error,
        },
        Err(error) => return error,
    };
    if !arena::contains(base, plan.host_length) {
        unsafe { libc::munmap(base as *mut _, plan.host_length as usize) };
        return -(ENOMEM as i64);
    }
    drop(placing);
    if file_map.is_ok() {
        for page in &eof_pages {
            if !matches!(page.kind, aim_guest_page::EofHost::Bus) {
                continue;
            }
            let host = base + (page.file_offset - plan.host_offset);
            let result = host_mprotect(host, PAGE, libc::PROT_NONE);
            if result < 0 {
                unsafe { libc::munmap(base as *mut _, plan.host_length as usize) };
                return result;
            }
        }
    }
    let guest = base + plan.displacement;
    if any_bus {
        crate::diag!(
            "[linux-abi] mmap: file offset {off:#x} length {:#x} includes a page at or past EOF {file_len:#x}; a touch raises SIGBUS",
            plan.guest_length
        );
        note_eof_bus(base, &plan, file_len);
    }
    note_shifted_slack(base, guest, &plan, prot);
    if file_map.is_ok() {
        note_file_copy(guest, plan.guest_length, fd, off, false);
    }
    guest as i64
}

fn note_eof_bus(base: u64, plan: &aim_guest_page::ShiftedFileMap, file_len: u64) {
    let guest_lo = plan.host_offset + plan.displacement;
    let guest_hi = guest_lo + plan.guest_length;
    for page in aim_guest_page::eof_host_pages(plan, file_len) {
        if !matches!(page.kind, aim_guest_page::EofHost::Bus) {
            continue;
        }
        let host = base + (page.file_offset - plan.host_offset);
        for slot in 0..4 {
            let at = page.file_offset + slot * aim_guest_page::GUEST_PAGE;
            if at >= guest_lo && at + aim_guest_page::GUEST_PAGE <= guest_hi {
                let addr = host + slot * aim_guest_page::GUEST_PAGE;
                EOF_BUS
                    .lock()
                    .unwrap()
                    .push((addr, addr + aim_guest_page::GUEST_PAGE));
            }
        }
    }
}

pub(super) fn past_eof_bus(addr: u64) -> bool {
    EOF_BUS
        .lock()
        .unwrap()
        .iter()
        .any(|&(lo, hi)| addr >= lo && addr < hi)
}

fn forget_eof_bus(lo: u64, hi: u64) {
    if lo >= hi {
        return;
    }
    let mut ranges = EOF_BUS.lock().unwrap();
    let old = std::mem::take(&mut *ranges);
    for (start, end) in old {
        if end <= lo || start >= hi {
            ranges.push((start, end));
            continue;
        }
        if start < lo {
            ranges.push((start, lo));
        }
        if hi < end {
            ranges.push((hi, end));
        }
    }
}

fn note_shifted_slack(
    host: u64,
    guest: u64,
    plan: &aim_guest_page::ShiftedFileMap,
    prot: u64,
) {
    let guest_end = guest + plan.guest_length;
    let host_end = host + plan.host_length;
    let prot = aim_guest_page::prot_bits(prot as u32);
    let mut page = host;
    while page < host_end {
        let mut present = 0u8;
        for slot in 0..4 {
            let at = page + slot * GUEST_PAGE;
            if at >= guest && at + GUEST_PAGE <= guest_end {
                present |= 1 << slot;
            }
        }
        if present != 0 && present != 0b1111 {
            PAGE_PIECES.lock().unwrap().insert(
                page,
                PagePieces {
                    present,
                    prot: [prot; 4],
                },
            );
        }
        page += PAGE;
    }
}

fn mmap_kernel(a: [u64; 6]) -> i64 {
    let (addr, len, prot, flags, fd, off) = (
        a[0],
        a[1],
        a[2] & !(PROT_BTI | PROT_MTE),
        a[3],
        a[4] as i32,
        a[5],
    );
    if flags & MAP_ANONYMOUS == 0 && super::proxy_file::is_proxy(fd) {
        return -(crate::errno::ENODEV as i64);
    }
    // Private file maps consult `private_file_map`: a 16 KiB-aligned offset
    // stays a host file mapping, and a 4 KiB offset is copied so the
    // returned pointer starts at that file offset.
    let mut shift_shared = false;
    let copy_file = if flags & MAP_ANONYMOUS == 0 && flags & MAP_TYPE == MAP_PRIVATE {
        match aim_guest_page::private_file_map(off, len) {
            Ok(aim_guest_page::PrivateFileMap::Copy { .. }) => {
                let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
                if aim_guest_page::private_copy_is_wx(prot as u32) {
                    crate::diag!(
                        "[linux-abi] mmap: MAP_PRIVATE copy at {addr:#x} offset {off:#x} prot {prot:#x} would be writable and executable; refusing"
                    );
                    return -(EINVAL as i64);
                }
                if fixed && !aim_guest_page::fixed_residue_matches(addr, off) {
                    crate::diag!(
                        "[linux-abi] mmap: MAP_PRIVATE at {addr:#x} offset {off:#x} prot {prot:#x} copied; address and offset differ mod 16 KiB"
                    );
                }
                true
            }
            Ok(_) => false,
            Err(error) => return -(error as i64),
        }
    } else if flags & MAP_ANONYMOUS != 0 {
        // MAP_ANONYMOUS ignores the offset and the descriptor. A `.bss`
        // fixed map passes fd -1 and offset 0; a whole page inside an
        // unaligned range is also anonymous zeros, not a file at the
        // displacement from the guest address.
        if len == 0 {
            return -(EINVAL as i64);
        }
        false
    } else {
        // MAP_SHARED / MAP_SHARED_VALIDATE. A 4 KiB multiple that is not a
        // 16 KiB multiple is a real shared mapping of the enclosing host
        // pages. MAP_FIXED cannot place the slack without clobbering a
        // neighbour, so it stays EINVAL rather than a private copy.
        if len == 0 || off & (aim_guest_page::GUEST_PAGE - 1) != 0 {
            return -(EINVAL as i64);
        }
        let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
        if off & (PAGE - 1) != 0 || (fixed && addr & (PAGE - 1) != 0) {
            if fixed {
                crate::diag!(
                    "[linux-abi] mmap: MAP_FIXED shared file at {addr:#x} offset {off:#x} is not a 16 KiB host mapping; not copying"
                );
                return -(EINVAL as i64);
            }
            shift_shared = true;
        }
        false
    };
    if !shift_shared
        && flags & MAP_ANONYMOUS == 0
        && let Some(file) = super::fuse_client::get(fd)
    {
        let shared = matches!(flags & MAP_TYPE, MAP_SHARED | MAP_SHARED_VALIDATE);
        let cache = match super::fuse_cache::prepare(file, fd, shared, prot & PROT_WRITE != 0) {
            Ok(cache) => cache,
            Err(error) => return -(error as i64),
        };
        let result = mmap_owned([addr, len, prot, flags, cache.fd() as u64, off]);
        if result >= 0 {
            if let Err(error) =
                super::fuse_cache::note(cache, result as u64, page_up(len), off, shared)
            {
                window::unmap(result as u64, page_up(len));
                return -(error as i64);
            }
        }
        return result;
    }
    if flags & MAP_ANONYMOUS == 0
        && fd >= 0
        && let Some(r) = super::binder::mmap(addr, len, prot, flags, fd)
    {
        if r >= 0 {
            super::memfd::unmapped(r as u64, page_up(len));
        }
        return r;
    }
    if flags & MAP_ANONYMOUS == 0 && fd >= 0 {
        super::procfs::on_mmap(fd);
    }
    if flags & MAP_ANONYMOUS == 0
        && fd >= 0
        && let Some(e) = super::ashmem::before_mmap(fd, len, prot)
            .or_else(|| super::dma_heap::before_mmap(fd, len, off))
    {
        return e;
    }
    if shift_shared {
        if flags & MAP_ANONYMOUS == 0
            && let Some(file) = super::fuse_client::get(fd)
        {
            let cache = match super::fuse_cache::prepare(file, fd, true, prot & PROT_WRITE != 0) {
                Ok(cache) => cache,
                Err(error) => return -(error as i64),
            };
            let result = mmap_shifted_shared(addr, len, prot, flags, cache.fd() as i32, off);
            if result >= 0 {
                let guest_len = aim_guest_page::guest_page_len(len).unwrap_or(0);
                if let Err(error) =
                    super::fuse_cache::note(cache, result as u64, guest_len, off, true)
                {
                    if let Ok(plan) = aim_guest_page::shifted_file_map(off, len) {
                        let host = (result as u64).wrapping_sub(plan.displacement);
                        let mut pieces = PAGE_PIECES.lock().unwrap();
                        let mut page = host;
                        while page < host + plan.host_length {
                            pieces.remove(&page);
                            page += PAGE;
                        }
                        drop(pieces);
                        unsafe { libc::munmap(host as *mut _, plan.host_length as usize) };
                    }
                    return -(error as i64);
                }
            }
            return result;
        }
        return mmap_shifted_shared(addr, len, prot, flags, fd, off);
    }
    let mut fixed = flags & MAP_FIXED != 0;
    let noreplace = flags & MAP_FIXED_NOREPLACE != 0;
    if (fixed || noreplace)
        && let Ok(split) = aim_guest_page::split_guest_range(addr, len)
        && split.is_partial()
    {
        return mmap_partial_fixed(addr, len, prot, flags, fd, off, split);
    }
    if (fixed || noreplace) && addr & (PAGE - 1) != 0 {
        return -(EINVAL as i64);
    }
    let len = page_up(len);
    let mut addr = addr;
    // A hint in the heap reference window takes the reserved pages there
    // exactly; a hint that cannot be honoured there is dropped, as Linux
    // places the mapping elsewhere.
    if !fixed && (window::BASE..window::BASE + window::SIZE).contains(&addr) {
        if addr & (PAGE - 1) == 0 && window::is_free(addr, len) {
            fixed = true;
        } else if noreplace {
            return -(EEXIST as i64);
        } else {
            addr = 0;
        }
    }
    // Anywhere means anywhere in the guest range; MAP_FIXED_NOREPLACE
    // wants exactly its address.
    let placed = !fixed && !noreplace;
    if placed {
        addr = arena::hint(addr, len);
    }
    let placing = placed.then(arena::placing);
    let kind = flags & MAP_TYPE;
    let anon = flags & MAP_ANONYMOUS != 0;
    if fixed && let Err(error) = super::fuse_cache::flush_range(addr, len) {
        return -(error as i64);
    }
    let mut hflags = if fixed { libc::MAP_FIXED } else { 0 };
    if flags & MAP_NORESERVE != 0 {
        hflags |= libc::MAP_NORESERVE;
    }
    let exec = prot & PROT_EXEC != 0;
    let writable = prot & PROT_WRITE != 0;
    // Fresh RWX memory: `jit` makes it so below.
    let fresh_jit = anon && exec && writable;
    // (base, what remains to do before returning)
    enum Finish {
        Nothing,
        Protect,
    }
    let mut noted = false;
    let shared = kind == MAP_SHARED || kind == MAP_SHARED_VALIDATE;
    let (base, finish) = if shared
        && !anon
        && !noreplace
        && let Some(r) = super::sharedfile::map(fd, addr, len, prot as i32, fixed, off)
    {
        match r {
            Ok(b) => {
                super::memfd::unmapped(b, len);
                (b, Finish::Nothing)
            }
            Err(e) => return e,
        }
    } else if shared {
        let memfd = if anon {
            None
        } else {
            match super::memfd::map_shared(fd, addr, len, host_prot(prot), fixed, off) {
                super::memfd::Shared::Done(r) => return r,
                super::memfd::Shared::File(k) => k,
            }
        };
        let f = hflags | libc::MAP_SHARED | if anon { libc::MAP_ANON } else { 0 };
        match host_mmap(
            addr,
            len,
            host_prot(prot),
            f,
            if anon { -1 } else { fd },
            off as i64,
        ) {
            Ok(b) => {
                if let Some((k, _guard)) = memfd {
                    super::memfd::note_view(k, b, len, off);
                    super::memfd::seal_view(fd, b, len, host_prot(prot));
                }
                (b, Finish::Nothing)
            }
            Err(e) => return e,
        }
    } else if kind == MAP_PRIVATE {
        let source = if !anon && exec && !writable {
            Some(xrt::exec_source(fd, off))
        } else {
            None
        };
        if let Some(ExecSource::Shared) = source
            && !copy_file
        {
            // Translated (or nothing to rewrite): the file itself, shared.
            let b = match host_mmap(
                addr,
                len,
                libc::PROT_READ,
                hflags | libc::MAP_SHARED,
                fd,
                off as i64,
            ) {
                Ok(b) => b,
                Err(e) => return e,
            };
            crate::diag::register_fd_module(b, len, fd, off);
            (b, Finish::Protect)
        } else if !anon && !exec && maps_file(fd) && !copy_file {
            // The file itself, copy-on-write. A 4 KiB file offset falls
            // through and is copied so the pointer starts at that offset.
            noted = true;
            match host_mmap(
                addr,
                len,
                host_prot(prot),
                hflags | libc::MAP_PRIVATE,
                fd,
                off as i64,
            ) {
                Ok(b) => (b, Finish::Nothing),
                Err(e) => return e,
            }
        } else {
            let fill = !anon;
            let initial = if fresh_jit {
                libc::PROT_NONE
            } else if fill || exec {
                libc::PROT_READ | libc::PROT_WRITE
            } else {
                host_prot(prot)
            };
            let b = match host_mmap(
                addr,
                len,
                initial,
                hflags | libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            ) {
                Ok(b) => b,
                Err(e) => return e,
            };
            if fill {
                noted = true;
                if let Err(e) = populate(b, len, fd, off) {
                    // SAFETY: unmapping what we just mapped.
                    unsafe { libc::munmap(b as *mut _, len as usize) };
                    return e;
                }
                if exec {
                    crate::diag::register_fd_module(b, len, fd, off);
                    let source = source.unwrap_or_else(|| xrt::exec_source(fd, off));
                    if let Err(error) = rewrite_file_copy(b, len, fd, off, &source) {
                        window::unmap(b, len);
                        return error;
                    }
                }
            } else if exec && !fresh_jit {
                // Fresh anonymous code: nothing written yet, but scan anyway so
                // the path is the same as mprotect's.
                trace_stats("rewrote", b, len, &patch::rewrite_region(b, len));
            }
            (
                b,
                if fill || exec {
                    Finish::Protect
                } else {
                    Finish::Nothing
                },
            )
        }
    } else {
        return -(EINVAL as i64);
    };
    if noreplace && base != addr {
        // SAFETY: unmapping the mapping we just created at the wrong place.
        unsafe { libc::munmap(base as *mut _, len as usize) };
        return -(EEXIST as i64);
    }
    if placed && !arena::contains(base, len) {
        // SAFETY: unmapping the mapping Darwin placed outside the range.
        unsafe { libc::munmap(base as *mut _, len as usize) };
        return -(ENOMEM as i64);
    }
    drop(placing);
    match finish {
        Finish::Nothing => {}
        Finish::Protect => {
            if copy_file && exec && !writable {
                crate::diag!(
                    "[linux-abi] mmap: private copy {base:#x}..{:#x} filled RW, mprotect {prot:#x}; W and X are not set together",
                    base + len
                );
            }
            let r = if writable && exec {
                super::jit::protect_rwx(base, len)
            } else {
                host_mprotect(base, len, host_prot(prot))
            };
            if r < 0 {
                if fresh_jit {
                    // SAFETY: unmapping the mapping we just created.
                    unsafe { libc::munmap(base as *mut _, len as usize) };
                }
                return r;
            }
        }
    }
    copies::forget(base, base + len);
    super::fuse_cache::forget(base, len);
    if noted {
        note_file_copy(base, len, fd, off, copy_file);
    }
    base as i64
}

/// execve in place: the old image's memory goes, the whole guest range,
/// with what is recorded about it; the heap window is reserved again.
pub fn exec_reset() {
    let _epoch = super::verity_pager::mutation();
    let _mapping = super::memfd::mapping_change();
    super::vma_names::exec_reset();
    if let Err(error) = super::verity_pager::clear() {
        crate::diag!("verity mapping retirement before exec failed: {error}");
    }
    if let Err(error) = super::fuse_cache::shutdown_writeback() {
        crate::diag!("FUSE writeback before exec failed: {error}");
    }
    if let Err(error) = super::fuse_cache::flush_range(arena::LO, arena::HI - arena::LO) {
        crate::diag!("FUSE mapped writeback on exec failed: {error}");
    }
    super::fuse_cache::forget(arena::LO, arena::HI - arena::LO);
    // SAFETY: nothing of the old image is used from here on.
    unsafe { mach_vm_deallocate(task(), arena::LO, arena::HI - arena::LO) };
    // Executable memfds force a fresh process at exec; only file views remain.
    super::memfd::unmapped(arena::LO, arena::HI - arena::LO);
    forget_guest_slices(arena::LO, arena::HI);
    window::init();
    copies::forget(arena::LO, arena::HI);
    DEFERRED_UNMAPS.with(|d| d.borrow_mut().clear());
}

/// Record that `[base, base+len)` maps (or holds a copy of) `fd` from
/// `off`.
fn note_file_copy(base: u64, len: u64, fd: i32, off: u64, anonymous: bool) {
    let mut buf = [0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes; fstat into a local
    // buffer.
    let st = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if crate::sys::fgetpath(fd, buf.as_mut_ptr()) < 0 || libc::fstat(fd, &mut st) < 0 {
            return;
        }
        st
    };
    let n = buf.iter().position(|&c| c == 0).unwrap_or(0);
    let host = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..n]));
    let guest = super::procfs::fd_guest_path(fd).unwrap_or_default();
    let id = (st.st_dev as u32 as u64, st.st_ino);
    if anonymous {
        crate::diag!(
            "[linux-abi] mmap: private copy {base:#x}..{:#x} of {} offset {off:#x} is not a file mapping",
            base + len,
            if guest.is_empty() {
                host.display().to_string()
            } else {
                guest.clone()
            }
        );
    }
    copies::note_file(base, len, &host, &guest, off, id, anonymous);
}

thread_local! {
    /// munmaps of this thread's own stack, run when the thread exits.
    static DEFERRED_UNMAPS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
}

/// The syscall stub keeps x16, x17 and x30 in the 32 bytes below the guest
/// sp until the syscall returns. bionic's `_exit_with_stack_teardown` unmaps
/// the calling thread's own stack and then calls `exit`, so an munmap that
/// covers that frame is deferred to thread exit (ADR 0012, "Platform probes").
pub fn munmap(ctx: &GuestContext, a: [u64; 6]) -> i64 {
    if a[1] == 0 {
        return 0;
    }
    let split = match aim_guest_page::split_guest_range(a[0], a[1]) {
        Ok(split) => split,
        Err(error) => return -(error as i64),
    };
    let _epoch = super::verity_pager::mutation();
    let _mapping = super::memfd::mapping_change();
    if !split.is_partial() {
        return munmap_aligned(ctx, split.full_lo, split.full_hi - split.full_lo);
    }
    if let Some(head) = split.head {
        let result = punch_page(head.host, head.cover);
        if result < 0 {
            return result;
        }
    }
    if split.full_hi > split.full_lo {
        let result = munmap_aligned(ctx, split.full_lo, split.full_hi - split.full_lo);
        if result < 0 {
            return result;
        }
    }
    if let Some(tail) = split.tail {
        let result = punch_page(tail.host, tail.cover);
        if result < 0 {
            return result;
        }
    }
    0
}

fn munmap_aligned(ctx: &GuestContext, addr: u64, len: u64) -> i64 {
    super::verity_pager::wait_pending(addr, len);
    let frame_lo = ctx.sp.saturating_sub(32);
    if len > 0 && frame_lo < addr.saturating_add(len) && ctx.sp > addr {
        DEFERRED_UNMAPS.with(|d| d.borrow_mut().push((addr, len)));
        vm_account::with(|s| s.unmap(addr, addr + len));
        super::vma_names::forget(addr, addr + len);
        forget_guest_slices(addr, addr + len);
        return 0;
    }
    release_aligned(addr, len)
}

fn release_aligned(addr: u64, len: u64) -> i64 {
    if let Err(error) = super::verity_pager::forget(addr, len) {
        return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
    }
    copies::forget(addr, addr + len);
    if let Err(error) = super::fuse_cache::flush_range(addr, len) {
        return -(error as i64);
    }
    let result = window::unmap(addr, len);
    if result == 0 {
        vm_account::with(|s| s.unmap(addr, addr + len));
        super::vma_names::forget(addr, addr + len);
        super::fuse_cache::forget(addr, len);
        forget_guest_slices(addr, addr + len);
        if let Err(error) = super::verity_pager::reconcile_memberships() {
            return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
        }
    }
    result
}

/// Run the munmaps deferred by [`munmap`]; called on the host stack when the
/// thread exits.
pub fn run_deferred_unmaps() -> usize {
    let _epoch = super::verity_pager::mutation();
    let _mapping = super::memfd::mapping_change();
    DEFERRED_UNMAPS.with(|d| {
        let v = std::mem::take(&mut *d.borrow_mut());
        for &(addr, len) in &v {
            if let Err(error) = super::verity_pager::forget(addr, len) {
                crate::diag!("verity deferred mapping retirement failed: {error}");
                continue;
            }
            if let Err(error) = super::fuse_cache::flush_range(addr, len) {
                crate::diag!("FUSE deferred unmap writeback failed: {error}");
            }
            super::fuse_cache::forget(addr, len);
            // SAFETY: the guest asked for this unmap; its thread is exiting.
            if unsafe { libc::munmap(addr as *mut _, len as usize) } == 0 {
                super::memfd::unmapped(addr, len);
            }
        }
        if let Err(error) = super::verity_pager::reconcile_memberships() {
            crate::diag!("verity deferred membership retirement failed: {error}");
        }
        v.len()
    })
}

/// Whether private mappings of `fd` can map the file itself: a regular
/// file, but not a memfd whose pages moved to anonymous memory for an
/// executable view (`memfd`). Copying a 16 MiB memfd cost 1.6 ms (#501).
fn maps_file(fd: i32) -> bool {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat into a local buffer.
    let regular =
        unsafe { libc::fstat(fd, &mut st) } == 0 && st.st_mode & libc::S_IFMT == libc::S_IFREG;
    regular && !super::memfd::converted(&st)
}

/// Whether the region at `addr` maps a file whose pages are never
/// rewritten: shared (writing would change the file), or a translated
/// file or one with nothing to rewrite.
fn unrewritten_file(addr: u64) -> bool {
    vmmap::region_at(addr).is_some_and(|r| {
        r.file
            .as_ref()
            .is_some_and(|(host, _, _)| r.shared || xrt::is_shared_source(host))
    })
}

/// Whether the region at `addr` is backed by a file.
fn file_backed(addr: u64) -> bool {
    let mut buf = [0u8; 16];
    // SAFETY: proc_regionfilename writes at most buf.len() bytes.
    unsafe {
        crate::hostlibc::proc_regionfilename(
            libc::getpid(),
            addr,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        ) > 0
    }
}

/// Guest protection granule. See `aim_guest_page`: Bionic's `WriteProtected`
/// hardcodes 4 KiB inside a 16 KiB page.
const GUEST_PAGE: u64 = aim_guest_page::GUEST_PAGE;

/// Guest slices whose protection differs from their 16 KiB host page.
/// Absence means the slice has the host page's protection.
static GUEST_SLICES: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());

/// Guest addresses whose 4 KiB page starts at or after EOF. A touch is
/// SIGBUS. The host page is `PROT_NONE`, which Darwin reports as a
/// protection fault, so the translator consults this set.
static EOF_BUS: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());

fn forget_guest_slices(lo: u64, hi: u64) {
    forget_guest_slice_state(lo, hi, true);
}

/// Drop per-slice protection rows in `[lo, hi)`. `drop_origin` is for
/// unmap and for the range a new mmap replaces. A protection change keeps
/// the establishing syscall and appends the new protection instead.
fn forget_guest_slice_state(lo: u64, hi: u64, drop_origin: bool) {
    if lo >= hi {
        return;
    }
    forget_eof_bus(lo, hi);
    let mut slices = GUEST_SLICES.lock().unwrap();
    let keys: Vec<u64> = slices
        .range(lo.saturating_sub(GUEST_PAGE - 1)..hi)
        .map(|(&page, _)| page)
        .filter(|&page| page < hi && page + GUEST_PAGE > lo)
        .collect();
    for page in keys {
        slices.remove(&page);
    }
    drop(slices);
    if drop_origin {
        forget_slice_modules(lo, hi);
    }
    let mut pages = PAGE_PIECES.lock().unwrap();
    let hosts: Vec<u64> = pages
        .range(lo.saturating_sub(PAGE - 1)..hi)
        .map(|(&host, _)| host)
        .filter(|&host| host >= lo && host + PAGE <= hi)
        .collect();
    for host in hosts {
        pages.remove(&host);
    }
}

/// Slices of one host page after a 4 KiB `munmap` or `MAP_FIXED`.
/// Absence of a page means every slice is present with the host protection.
#[derive(Clone, Copy)]
struct PagePieces {
    present: u8,
    prot: [u32; 4],
}

static PAGE_PIECES: Mutex<BTreeMap<u64, PagePieces>> = Mutex::new(BTreeMap::new());

/// Who established each guest slice, and the guest protections since. The
/// fault diagnostic names the syscall and this history, so a `PROT_NONE`
/// reservation is distinguishable from a later writable mapping.
struct SliceOrigin {
    call: Option<u64>,
    name: String,
    history: Vec<u32>,
}

static SLICE_ORIGIN: Mutex<BTreeMap<u64, SliceOrigin>> = Mutex::new(BTreeMap::new());

const PROT_HISTORY: usize = 8;

static HOST_PROT_TRANSITIONS: AtomicU64 = AtomicU64::new(0);
static EXEC_WINDOW_FAULTS: AtomicU64 = AtomicU64::new(0);

fn page_prot(host: u64) -> Option<u32> {
    match vmmap::info_at(host) {
        Some(info) if host >= info.start && host < info.end => {
            Some(aim_guest_page::prot_bits(info.prot))
        }
        // The next entry means this address is a hole. `None` is the
        // Linux test host, where `proc_pidinfo` is not implemented.
        Some(_) => None,
        None => maps_prot(host),
    }
}

/// Protection of `addr` from `/proc/self/maps`. Darwin answers `page_prot`
/// from `proc_pidinfo`, so this file is not opened there.
fn maps_prot(addr: u64) -> Option<u32> {
    let text = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            u64::from_str_radix(start, 16),
            u64::from_str_radix(end, 16),
        ) else {
            continue;
        };
        if addr < start || addr >= end {
            continue;
        }
        let bytes = perms.as_bytes();
        let mut prot = 0u32;
        if bytes.first() == Some(&b'r') {
            prot |= libc::PROT_READ as u32;
        }
        if bytes.get(1) == Some(&b'w') {
            prot |= libc::PROT_WRITE as u32;
        }
        if bytes.get(2) == Some(&b'x') {
            prot |= libc::PROT_EXEC as u32;
        }
        return Some(prot);
    }
    None
}

fn slice_module_name(anon: bool, fd: i32) -> String {
    if anon {
        return "anonymous".to_string();
    }
    if let Some(path) = crate::xrt::original_guest_path(fd) {
        return path;
    }
    xrt::fd_path(fd)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| format!("fd {fd}"))
}

fn remember_slice(addr: u64, name: &str, prot: u32) {
    SLICE_ORIGIN.lock().unwrap().insert(
        addr,
        SliceOrigin {
            call: super::active_trace_call(),
            name: name.to_string(),
            history: vec![aim_guest_page::prot_bits(prot)],
        },
    );
}

fn note_slice_prot(addr: u64, prot: u32) {
    let prot = aim_guest_page::prot_bits(prot);
    let mut origins = SLICE_ORIGIN.lock().unwrap();
    let Some(origin) = origins.get_mut(&addr) else {
        return;
    };
    if origin.history.last().copied() == Some(prot) {
        return;
    }
    if origin.history.len() == PROT_HISTORY {
        origin.history.remove(0);
    }
    origin.history.push(prot);
}

fn slice_label(addr: u64, prot: u32) -> String {
    let origin = SLICE_ORIGIN.lock().unwrap().get(&addr).map(|origin| {
        (
            origin.name.clone(),
            origin.call,
            origin.history.clone(),
        )
    });
    let (name, call, history) = match origin {
        Some((name, call, history)) => (name, call, history),
        None => {
            let described = crate::diag::describe(addr);
            let name = if described == "?" {
                "anonymous".to_string()
            } else {
                described
            };
            (name, None, vec![aim_guest_page::prot_bits(prot)])
        }
    };
    aim_guest_page::slice_origin_label(&name, call, &history)
}

fn record_established(base: u64, len: u64, prot: u64, flags: u64, fd: i32, map_off: u64) {
    if len == 0 {
        return;
    }
    let prot = aim_guest_page::prot_bits((prot & !(PROT_BTI | PROT_MTE)) as u32);
    let anon = flags & MAP_ANONYMOUS != 0;
    let path = slice_module_name(anon, fd);
    let mut at = base & !(GUEST_PAGE - 1);
    let end = base.saturating_add(len);
    while at < end {
        let name = if anon {
            path.clone()
        } else {
            format!(
                "{path}+{:#x}",
                aim_guest_page::file_offset_at(base, map_off, at)
            )
        };
        remember_slice(at, &name, prot);
        at += GUEST_PAGE;
    }
}

fn note_prot_range(lo: u64, hi: u64, prot: u32) {
    if lo >= hi {
        return;
    }
    let mut at = lo & !(GUEST_PAGE - 1);
    while at < hi {
        if at + GUEST_PAGE > lo {
            note_slice_prot(at, prot);
        }
        at += GUEST_PAGE;
    }
}

fn forget_slice_modules(lo: u64, hi: u64) {
    if lo >= hi {
        return;
    }
    let mut modules = SLICE_ORIGIN.lock().unwrap();
    let keys: Vec<u64> = modules
        .range(lo..hi)
        .map(|(&addr, _)| addr)
        .filter(|&addr| addr < hi && addr + GUEST_PAGE > lo)
        .collect();
    for addr in keys {
        modules.remove(&addr);
    }
}

fn present_prots(pieces: &PagePieces) -> Vec<u32> {
    (0..4)
        .filter(|slot| pieces.present & (1 << slot) != 0)
        .map(|slot| pieces.prot[slot])
        .collect()
}

fn trace_host_transition(host: u64, pieces: &PagePieces, old: u32, new: u32) {
    let n = HOST_PROT_TRANSITIONS.fetch_add(1, Ordering::Relaxed) + 1;
    let slices: Vec<String> = (0..4usize)
        .map(|slot| {
            let at = host + slot as u64 * GUEST_PAGE;
            if pieces.present & (1 << slot) == 0 {
                format!("{at:#x}:absent")
            } else {
                format!(
                    "{at:#x}:{:#x} {}",
                    pieces.prot[slot],
                    slice_label(at, pieces.prot[slot])
                )
            }
        })
        .collect();
    crate::diag!(
        "[linux-abi] host page {host:#x} slices {} prot {old:#x} -> {new:#x} (transition {n})",
        slices.join(" ")
    );
}

/// Install `new` on the host page. A transition that gains execute
/// invalidates the whole 16 KiB page. `wrote` is set when this call filled
/// bytes while the page was writable, which also needs that invalidate.
fn apply_host_prot(host: u64, pieces: &PagePieces, old: u32, new: u32, wrote: bool) -> i64 {
    if old != new {
        trace_host_transition(host, pieces, old, new);
        let mut result = host_mprotect(host, PAGE, host_prot(new as u64));
        if result == -(errno::EACCES as i64) {
            result = super::jit::protect_around(host, PAGE, host_prot(new as u64));
        }
        if result != 0 {
            return result;
        }
    }
    let gain = aim_guest_page::icache_span_on_execute_restore(old, new);
    if gain.is_some() || (wrote && new & aim_guest_page::PROT_EXEC != 0) {
        let span = gain.unwrap_or(PAGE);
        // SAFETY: `host` is a mapped page in this process. The span is the
        // whole host page, not the guest slice that was written.
        unsafe { sys_icache_invalidate(host as *mut libc::c_void, span as usize) };
        if old & aim_guest_page::PROT_WRITE != 0 && gain.is_some() {
            crate::diag!(
                "[linux-abi] host page {host:#x} write dropped, execute restored, icache invalidated {span:#x}"
            );
        } else {
            crate::diag!(
                "[linux-abi] host page {host:#x} icache invalidated {span:#x}"
            );
        }
    }
    0
}

fn punch_page(host: u64, cover: u8) -> i64 {
    if cover == 0 {
        return 0;
    }
    for slot in 0..4 {
        if cover & (1 << slot) != 0 {
            let at = host + slot * GUEST_PAGE;
            forget_eof_bus(at, at + GUEST_PAGE);
            SLICE_ORIGIN.lock().unwrap().remove(&at);
        }
    }
    if cover == 0b1111 {
        return release_aligned(host, PAGE);
    }
    let Some(prot) = page_prot(host) else {
        return 0;
    };
    let plan = {
        let mut pages = PAGE_PIECES.lock().unwrap();
        let entry = pages.entry(host).or_insert(PagePieces {
            present: 0b1111,
            prot: [prot; 4],
        });
        let saved = *entry;
        let old = aim_guest_page::host_protection(present_prots(entry));
        entry.present &= !cover;
        for slot in 0..4 {
            if cover & (1 << slot) != 0 {
                entry.prot[slot] = 0;
            }
        }
        let new = aim_guest_page::host_protection(present_prots(entry));
        let gone = entry.present == 0;
        let pieces = *entry;
        if gone {
            pages.remove(&host);
        }
        (gone, old, new, pieces, saved)
    };
    let (gone, old, new, pieces, saved) = plan;
    if gone {
        return release_aligned(host, PAGE);
    }
    if old == new {
        return 0;
    }
    let result = apply_host_prot(host, &pieces, old, new, false);
    if result != 0 {
        PAGE_PIECES.lock().unwrap().insert(host, saved);
        return result;
    }
    result
}

fn map_covered_slices(
    host: u64,
    cover: u8,
    prot: u32,
    anon: bool,
    fd: i32,
    map_addr: u64,
    map_off: u64,
) -> i64 {
    if cover == 0 {
        return 0;
    }
    let prot = aim_guest_page::prot_bits(prot);
    // A request that itself asks for write and execute stays refused for a
    // file copy. A neighbor slice wanting the other bit is write-wins, below.
    if aim_guest_page::private_copy_is_wx(prot) && !anon {
        crate::diag!(
            "[linux-abi] mmap: private copy host page {host:#x} prot {prot:#x} would be writable and executable; refusing"
        );
        return -(EINVAL as i64);
    }
    let existed = page_prot(host);
    // Snapshot before the fill makes this host page writable. The gap beside
    // libc's text is the linker's PROT_NONE reservation: it has no mmap of
    // its own. Reading the host protection after the fill stored that
    // temporary write on the gap, and write-wins then dropped execute.
    let existing = { PAGE_PIECES.lock().unwrap().get(&host).copied() };
    let seeded = if let Some(entry) = existing {
        entry
    } else if let Some(bits) = existed {
        let mut prior = [bits; 4];
        for slot in 0..4usize {
            let at = host + slot as u64 * GUEST_PAGE;
            if let Ok(found) = slice_prot(at) {
                prior[slot] = found;
            }
        }
        PagePieces {
            present: 0b1111,
            prot: prior,
        }
    } else {
        PagePieces {
            present: 0,
            prot: [0; 4],
        }
    };
    if existed.is_none() {
        match host_mmap(
            host,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        ) {
            Ok(mapped) if mapped == host => {}
            Ok(mapped) => {
                unsafe { libc::munmap(mapped as *mut _, PAGE as usize) };
                return -(ENOMEM as i64);
            }
            Err(error) => return error,
        }
    } else if existed.unwrap() & libc::PROT_WRITE as u32 == 0 {
        let result = host_mprotect(host, PAGE, libc::PROT_READ | libc::PROT_WRITE);
        if result < 0 {
            return result;
        }
    }
    let module = slice_module_name(anon, fd);
    for slot in 0..4 {
        if cover & (1 << slot) == 0 {
            continue;
        }
        let at = host + slot * GUEST_PAGE;
        // The host page was just created writable, or mprotect'd writable.
        unsafe { std::ptr::write_bytes(at as *mut u8, 0, GUEST_PAGE as usize) };
        if !anon {
            let file_off = aim_guest_page::file_offset_at(map_addr, map_off, at);
            if let Err(error) = populate(at, GUEST_PAGE, fd, file_off) {
                return error;
            }
            if prot & libc::PROT_EXEC as u32 != 0 {
                let source = xrt::exec_source(fd, file_off);
                if let Err(error) = rewrite_file_copy(at, GUEST_PAGE, fd, file_off, &source) {
                    return error;
                }
            }
        } else if prot & libc::PROT_EXEC as u32 != 0 {
            patch::rewrite_region(at, GUEST_PAGE);
        }
        remember_slice(at, &module, prot);
        if anon {
            crate::diag::register_module(at, at + GUEST_PAGE, "anonymous".to_string());
        } else {
            let file_off = aim_guest_page::file_offset_at(map_addr, map_off, at);
            crate::diag::register_fd_module(at, GUEST_PAGE, fd, file_off);
        }
    }
    let (row, present) = aim_guest_page::overlay_fixed(seeded.prot, seeded.present, cover, prot);
    let pieces = PagePieces {
        present,
        prot: row,
    };
    let old_host = aim_guest_page::host_protection(present_prots(&seeded));
    let new_host = aim_guest_page::host_protection(present_prots(&pieces));
    {
        let mut pages = PAGE_PIECES.lock().unwrap();
        if present == 0 || (present == 0b1111 && row.iter().all(|item| *item == row[0])) {
            pages.remove(&host);
        } else {
            pages.insert(host, pieces);
        }
    }
    if aim_guest_page::private_copy_is_wx(prot) {
        // Anonymous request that itself asks for write and execute. This is
        // the MAP_JIT path, not a neighbor slice.
        return super::jit::protect_rwx(host, PAGE);
    }
    if !anon && new_host & libc::PROT_EXEC as u32 != 0 && new_host & libc::PROT_WRITE as u32 == 0 {
        crate::diag!(
            "[linux-abi] mmap: private copy host page {host:#x} filled RW, mprotect {new_host:#x}; W and X are not set together"
        );
    }
    apply_host_prot(host, &pieces, old_host, new_host, true)
}

/// `MAP_FIXED` of a range whose address or end is only 4 KiB-aligned.
/// Whole host pages use the ordinary path. An edge page keeps the slices
/// the request does not cover, and the call returns the requested address.
/// The host page's protection is write-wins over every present slice, and a
/// slice that was unmapped stays readable until the whole page is gone.
fn mmap_partial_fixed(
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: i32,
    off: u64,
    split: aim_guest_page::RangeSplit,
) -> i64 {
    if matches!(flags & MAP_TYPE, MAP_SHARED | MAP_SHARED_VALIDATE) {
        return -(EINVAL as i64);
    }
    let anon = flags & MAP_ANONYMOUS != 0;
    if let Some(head) = split.head {
        let result = map_covered_slices(head.host, head.cover, prot as u32, anon, fd, addr, off);
        if result < 0 {
            return result;
        }
    }
    if split.full_hi > split.full_lo {
        let file_off = aim_guest_page::partial_page_offset(anon, addr, off, split.full_lo);
        let result = mmap_kernel([
            split.full_lo,
            split.full_hi - split.full_lo,
            prot,
            flags,
            fd as u64,
            file_off,
        ]);
        if result < 0 {
            return result;
        }
    }
    if let Some(tail) = split.tail {
        let result = map_covered_slices(tail.host, tail.cover, prot as u32, anon, fd, addr, off);
        if result < 0 {
            return result;
        }
    }
    if !anon && let Ok(span) = aim_guest_page::guest_page_len(len) {
        let anonymous = matches!(
            aim_guest_page::private_file_map(off, len),
            Ok(aim_guest_page::PrivateFileMap::Copy { .. })
        );
        note_file_copy(addr, span, fd, off, anonymous);
    }
    addr as i64
}

fn slice_prot(page: u64) -> Result<u32, i64> {
    if let Some(prot) = GUEST_SLICES.lock().unwrap().get(&page).copied() {
        return Ok(prot);
    }
    let host = page & !(PAGE - 1);
    let slot = ((page - host) / GUEST_PAGE) as u32;
    if let Some(pieces) = PAGE_PIECES.lock().unwrap().get(&host).copied() {
        if pieces.present & (1 << slot) == 0 {
            return Ok(0);
        }
        return Ok(pieces.prot[slot as usize]);
    }
    match vmmap::info_at(page) {
        Some(info) if page >= info.start && page < info.end => {
            Ok(aim_guest_page::prot_bits(info.prot))
        }
        Some(_) => Err(-(ENOMEM as i64)),
        None => match maps_prot(page) {
            Some(prot) => Ok(prot),
            None => Err(-(ENOMEM as i64)),
        },
    }
}

/// An instruction fetch whose slice wants execute while another slice on
/// the same host page wants write. The host page is not executable. The
/// line names both modules, both slices, and the thread.
pub(super) fn note_exec_window(addr: u64) {
    let host = addr & !(PAGE - 1);
    let slot = ((addr - host) / GUEST_PAGE) as usize;
    if slot >= 4 {
        return;
    }
    let pieces = {
        let pages = PAGE_PIECES.lock().unwrap();
        match pages.get(&host).copied() {
            Some(pieces) => pieces,
            None => return,
        }
    };
    if pieces.present & (1 << slot) == 0 {
        return;
    }
    let mut owned = Vec::new();
    for s in 0..4usize {
        if pieces.present & (1 << s) == 0 {
            continue;
        }
        let at = host + s as u64 * GUEST_PAGE;
        let module = slice_label(at, pieces.prot[s]);
        owned.push((at, pieces.prot[s], module));
    }
    let views: Vec<aim_guest_page::SliceView<'_>> = owned
        .iter()
        .map(|(at, prot, module)| aim_guest_page::SliceView {
            addr: *at,
            prot: *prot,
            module,
        })
        .collect();
    let Some(window) = aim_guest_page::exec_window(addr, &views) else {
        return;
    };
    let n = EXEC_WINDOW_FAULTS.fetch_add(1, Ordering::Relaxed) + 1;
    // SAFETY: the fault is on this thread.
    let pthread = unsafe { libc::pthread_self() } as u64;
    let thread = match super::current_guest_tid() {
        Some(tid) => format!("guest tid {tid} pthread {pthread:#x}"),
        None => format!("guest tid none pthread {pthread:#x}"),
    };
    crate::diag!(
        "{}",
        aim_guest_page::format_exec_window(&thread, &window, n)
    );
}

/// `mprotect` of a 4 KiB-aligned range that is not 16 KiB-aligned.
///
/// The host page stays 16 KiB. Its protection is write-wins over every
/// slice (`aim_guest_page`), so a read-only slice keeps its writable
/// neighbors, and execute waits until no slice on the page wants write.
fn mprotect_subpage(a: [u64; 6]) -> i64 {
    let _epoch = super::verity_pager::exclusive_mutation();
    let prot = aim_guest_page::prot_bits((a[2] & !(PROT_BTI | PROT_MTE)) as u32);
    let len = match aim_guest_page::begin_subpage(a[0], a[1], prot) {
        Ok(0) => return 0,
        Ok(len) => len,
        Err(error) => return -(error as i64),
    };
    let addr = a[0];
    let end = addr + len;
    if window::touches_reserved(addr, end) {
        return -(ENOMEM as i64);
    }
    if prot & libc::PROT_WRITE as u32 != 0
        && vmmap::regions(addr, end)
            .any(|region| region.shared && region.usage.max_prot & libc::PROT_WRITE as u32 == 0)
    {
        return -(errno::EACCES as i64);
    }
    if !super::verity_pager::covered(addr, len).is_empty() {
        return -(EINVAL as i64);
    }
    let host_lo = addr & !(PAGE - 1);
    let Some(host_hi) = end.checked_add(PAGE - 1) else {
        return -(ENOMEM as i64);
    };
    let host_hi = host_hi & !(PAGE - 1);
    let mut current = Vec::new();
    let mut page = host_lo;
    while page < host_hi {
        current.push(match slice_prot(page) {
            Ok(prot) => prot,
            Err(error) => return error,
        });
        page += GUEST_PAGE;
    }
    if aim_guest_page::private_copy_is_wx(prot) {
        crate::diag!(
            "[linux-abi] mprotect: refusing W+X on {addr:#x}..{end:#x}"
        );
        return -(EINVAL as i64);
    }
    let (host_ops, slices) = match aim_guest_page::plan_subpage(host_lo, addr, end, prot, &current)
    {
        Ok(plan) => plan,
        Err(error) => return -(error as i64),
    };
    for op in &host_ops {
        let n = HOST_PROT_TRANSITIONS.fetch_add(1, Ordering::Relaxed) + 1;
        let shown: Vec<String> = slices
            .iter()
            .filter(|(at, _)| *at >= op.addr && *at < op.addr + PAGE)
            .map(|(at, bits)| format!("{at:#x}:{bits:#x}"))
            .collect();
        crate::diag!(
            "[linux-abi] host page {:#x} slices {} prot {:#x} -> {:#x} (transition {n})",
            op.addr,
            shown.join(" "),
            op.old,
            op.prot
        );
    }
    for (done, op) in host_ops.iter().enumerate() {
        let mut result = host_mprotect(op.addr, PAGE, op.prot as i32);
        if result == -(errno::EACCES as i64) {
            // A page that was made RWX is MAP_JIT and rejects mprotect.
            result = super::jit::protect_around(op.addr, PAGE, op.prot as i32);
        }
        if result != 0 {
            for undo in &host_ops[..done] {
                host_mprotect(undo.addr, PAGE, undo.old as i32);
            }
            return result;
        }
        if let Some(span) = aim_guest_page::icache_span_on_execute_restore(op.old, op.prot) {
            // SAFETY: the host page is mapped. Invalidate all 16 KiB, not the
            // 4 KiB the guest named.
            unsafe { sys_icache_invalidate(op.addr as *mut libc::c_void, span as usize) };
            crate::diag!(
                "[linux-abi] host page {:#x} write dropped, execute restored, icache invalidated {span:#x}",
                op.addr
            );
        }
    }
    {
        let mut recorded = GUEST_SLICES.lock().unwrap();
        let mut pages = PAGE_PIECES.lock().unwrap();
        let mut planned: BTreeMap<u64, [u32; 4]> = BTreeMap::new();
        for &(page, prot) in &slices {
            let host = page & !(PAGE - 1);
            let slot = ((page - host) / GUEST_PAGE) as usize;
            let row = planned.entry(host).or_insert_with(|| {
                if let Some(entry) = pages.get(&host) {
                    entry.prot
                } else {
                    let base = ((host - host_lo) / GUEST_PAGE) as usize;
                    let mut prior = [0u32; 4];
                    for s in 0..4 {
                        prior[s] = current[base + s];
                    }
                    prior
                }
            });
            row[slot] = prot;
        }
        for (host, row) in planned {
            let present = pages.get(&host).map(|entry| entry.present).unwrap_or(0b1111);
            let mut prot_row = pages.get(&host).map(|entry| entry.prot).unwrap_or(row);
            for slot in 0..4 {
                if present & (1 << slot) != 0 {
                    prot_row[slot] = row[slot];
                }
            }
            if present == 0b1111 && prot_row.iter().all(|item| *item == prot_row[0]) {
                pages.remove(&host);
            } else {
                pages.insert(
                    host,
                    PagePieces {
                        present,
                        prot: prot_row,
                    },
                );
            }
        }
        for (page, prot) in slices {
            note_slice_prot(page, prot);
            if prot == aim_guest_page::host_prot_at(&host_ops, &current, host_lo, page) {
                recorded.remove(&page);
            } else {
                recorded.insert(page, prot);
            }
        }
    }
    for op in &host_ops {
        let was = op.old & libc::PROT_WRITE as u32 != 0;
        let now = op.prot & libc::PROT_WRITE as u32 != 0;
        if was != now {
            vm_account::with(|space| space.protect(op.addr, op.addr + PAGE, now));
        }
    }
    0
}

/// mprotect with PROT_EXEC: code becoming executable is rewritten first.
///
/// - Pieces that are already executable are not touched: they were rewritten
///   when they became executable, and other threads may be running them.
/// - Shared file mappings and mappings of translated files need nothing.
/// - Other pieces are not executable, so nothing runs them: they are made
///   readable if needed, scanned and rewritten (a private file mapping
///   gets its own copy of each page written), then protected.
pub fn mprotect(a: [u64; 6]) -> i64 {
    // A 16 KiB-aligned start whose length is only a few 4 KiB slices must
    // not be rounded up to the host page: the next slices stay as they are.
    match aim_guest_page::whole_host_pages(a[0], a[1]) {
        Ok(false) => return mprotect_subpage(a),
        Ok(true) => {}
        Err(error) => return -(error as i64),
    }
    let _epoch = super::verity_pager::exclusive_mutation();
    let (addr, len) = (a[0], page_up(a[1]));
    if super::verity_pager::failed_range(addr, len) {
        return -(errno::EIO as i64);
    }
    // `mprotect_fixup`: a private mapping turning into data must fit
    // RLIMIT_DATA.
    let writable = a[2] & PROT_WRITE != 0;
    if writable && addr & (PAGE - 1) == 0 {
        let (limits, heap) = (super::cred::memory_limits(), brk_heap());
        if !vm_account::with(|s| s.may_protect(limits, heap, addr, addr + len)) {
            return -(ENOMEM as i64);
        }
    }
    let result = mprotect_owned(a);
    if result == 0 {
        vm_account::with(|s| s.protect(addr, addr + len, writable));
        // The length covered whole host pages, so every guest slice in it
        // now has this protection. The establishing syscall stays.
        note_prot_range(addr, addr + len, a[2] as u32);
        forget_guest_slice_state(addr, addr + len, false);
    }
    result
}
fn mprotect_owned(a: [u64; 6]) -> i64 {
    let (addr, len, prot) = (a[0], page_up(a[1]), a[2] & !(PROT_BTI | PROT_MTE));
    super::verity_pager::wait_pending(addr, len);
    if addr & (PAGE - 1) != 0 {
        return -(EINVAL as i64);
    }
    if window::touches_reserved(addr, addr + len) {
        return -(ENOMEM as i64);
    }
    // Check VM_MAYWRITE before executable/JIT replacement can raise the
    // host maximum protection of a read-only shared mapping.
    if prot & PROT_WRITE != 0
        && vmmap::regions(addr, addr + len)
            .any(|r| r.shared && r.usage.max_prot & libc::PROT_WRITE as u32 == 0)
    {
        return -(errno::EACCES as i64);
    }
    let ranges = super::verity_pager::covered(addr, len);
    if !ranges.is_empty() {
        if let Err(error) = super::verity_pager::validate_protection(addr, len, host_prot(prot)) {
            return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
        }
        let mut previous = Vec::new();
        for region in vmmap::regions(addr, addr + len) {
            previous.push((
                region.start.max(addr),
                region.end.min(addr + len),
                region.prot,
            ));
        }
        let mut cursor = addr;
        for &(lo, hi) in &ranges {
            if cursor < lo {
                let result = mprotect_owned([cursor, lo - cursor, prot, 0, 0, 0]);
                if result < 0 {
                    return result;
                }
            }
            cursor = hi;
        }
        if cursor < addr + len {
            let result = mprotect_owned([cursor, addr + len - cursor, prot, 0, 0, 0]);
            if result < 0 {
                return result;
            }
        }
        if let Err(error) = super::verity_pager::protect_range(addr, len, host_prot(prot)) {
            for (lo, hi, old) in previous {
                if !super::verity_pager::overlaps(lo, hi - lo) {
                    host_mprotect(lo, hi - lo, old as i32);
                }
            }
            return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
        }
        return 0;
    }
    let rwx = prot & (PROT_WRITE | PROT_EXEC) == PROT_WRITE | PROT_EXEC;
    if rwx && copies::covers_anonymous(addr, addr + len) {
        crate::diag!(
            "[linux-abi] mprotect: refusing W+X on private copy {addr:#x}..{:#x}",
            addr + len
        );
        return -(EINVAL as i64);
    }
    if prot & PROT_EXEC != 0 {
        if let Err(error) = super::memfd::before_exec_protect(addr, addr + len) {
            return error;
        }
        let end = addr + len;
        let mut cur = addr;
        while cur < end {
            let Some((lo, hi, cur_prot, _)) = patch::vm::region(cur) else {
                break;
            };
            if lo >= end {
                break;
            }
            let (lo, hi) = (lo.max(cur), hi.min(end));
            // A memfd's views are ART's dual-mapped JIT cache: never scanned.
            if cur_prot & libc::PROT_EXEC == 0
                && !(rwx && vmmap::info_at(lo).is_some_and(|i| i.empty))
                && !unrewritten_file(lo)
                && super::memfd::anon_name(lo).is_none()
            {
                if cur_prot & libc::PROT_READ == 0 {
                    host_mprotect(lo, hi - lo, cur_prot | libc::PROT_READ);
                }
                trace_stats("rewrote", lo, hi - lo, &patch::rewrite_region(lo, hi - lo));
            }
            cur = hi;
        }
    }
    if rwx {
        return super::jit::protect_rwx(addr, len);
    }
    let r = host_mprotect(addr, len, host_prot(prot));
    if r == 0 {
        super::verity_pager::note_protection(addr, len, host_prot(prot));
    }
    if r == -(errno::EACCES as i64) {
        // JIT pages keep their protection.
        return super::jit::protect_around(addr, len, host_prot(prot));
    }
    r
}

const MADV_DONTNEED: u64 = 4;
const MADV_WILLNEED: u64 = 3;
const MADV_FREE: u64 = 8;
const MADV_REMOVE: u64 = 9;

use patch::vm::{
    VM_FLAGS_FIXED, VM_FLAGS_OVERWRITE, VM_INHERIT_COPY, mach_vm_deallocate, mach_vm_protect,
    mach_vm_remap, task,
};

unsafe extern "C" {
    fn sys_icache_invalidate(start: *mut libc::c_void, len: usize);
    fn mach_vm_allocate(task: crate::mach_port_t, address: *mut u64, size: u64, flags: i32) -> i32;
    fn mach_vm_inherit(task: crate::mach_port_t, address: u64, size: u64, inheritance: u32) -> i32;
    fn mach_vm_read_overwrite(
        task: crate::mach_port_t,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
}

const VM_INHERIT_SHARE: u32 = 0;

/// Map the pages of `[src, src+len)` at `dst` too (replacing what is
/// there), sharing them; protections and inheritance follow the source.
pub(super) fn remap_shared(dst: u64, src: u64, len: u64) -> Result<(), i64> {
    let (mut addr, mut cur, mut max) = (dst, 0, 0);
    // SAFETY: remapping guest memory within our own task.
    let kr = unsafe {
        mach_vm_remap(
            task(),
            &mut addr,
            len,
            0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            task(),
            src,
            0,
            &mut cur,
            &mut max,
            VM_INHERIT_COPY,
        )
    };
    if kr != 0 {
        return Err(-(ENOMEM as i64));
    }
    // mach_vm_remap sets the inheritance given; keep the source's sharing.
    for r in vmmap::regions(src, src + len) {
        if r.shared {
            inherit_shared(dst + (r.start - src), r.end - r.start);
        }
    }
    Ok(())
}

/// The caller holds the exclusive VM epoch and validated the mapping generation.
/// No unfilled executable memory is visible to another guest pthread.
pub(super) fn publish_verified_jit_page(dst: u64, bytes: &[u8]) -> std::io::Result<()> {
    unsafe {
        aim_storage::host::pthread_jit_write_protect_np(1);
    }
    let _placement = arena::placing_exclusive();
    let outcome = super::thread::with_guest_threads_quiescent(|| {
        if unsafe { libc::munmap(dst as *mut _, bytes.len()) } != 0 {
            return Err(errno::last());
        }
        let protection = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        let mapped = unsafe {
            libc::mmap(
                dst as *mut _,
                bytes.len(),
                protection,
                libc::MAP_PRIVATE | libc::MAP_ANON | aim_storage::host::MAP_JIT,
                -1,
                0,
            )
        };
        let failure = if mapped == libc::MAP_FAILED {
            Some(errno::last())
        } else if mapped as u64 != dst {
            unsafe {
                libc::munmap(mapped, bytes.len());
            }
            Some(errno::ENOMEM)
        } else {
            None
        };
        if let Some(failure) = failure {
            let restored = unsafe {
                libc::mmap(
                    dst as *mut _,
                    bytes.len(),
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if restored == libc::MAP_FAILED {
                return Err(errno::last());
            }
            return Err(failure);
        }
        unsafe {
            aim_storage::host::pthread_jit_write_protect_np(0);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped.cast::<u8>(), bytes.len());
            aim_storage::host::pthread_jit_write_protect_np(1);
            sys_icache_invalidate(mapped, bytes.len());
        }
        Ok(())
    })
    .map_err(std::io::Error::from_raw_os_error)?;
    outcome.map_err(std::io::Error::from_raw_os_error)
}

/// Change an owned resident page without losing its private COW bytes. JIT
/// entries cannot be overwritten with Mach remap on this host kernel.
pub(super) fn reprotect_verified_page(
    address: u64,
    length: u64,
    protection: i32,
) -> std::io::Result<()> {
    let current = vmmap::info_at(address)
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOMEM))?
        .prot as i32
        & 7;
    let rwx = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    if current != rwx && protection != rwx {
        return if unsafe { libc::mprotect(address as *mut _, length as usize, protection) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        };
    }
    if current == protection {
        return Ok(());
    }
    let mut bytes = vec![0; length as usize];
    unsafe {
        aim_storage::host::pthread_jit_write_protect_np(1);
    }
    let _placement = arena::placing_exclusive();
    let result = super::thread::with_guest_threads_quiescent(|| {
        unsafe {
            std::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), bytes.len());
        }
        unsafe {
            libc::munmap(address as *mut _, bytes.len());
        }
        let flags = libc::MAP_PRIVATE
            | libc::MAP_ANON
            | if protection == rwx {
                aim_storage::host::MAP_JIT
            } else {
                libc::MAP_FIXED
            };
        let initial = if protection == rwx {
            rwx
        } else {
            libc::PROT_READ | libc::PROT_WRITE
        };
        let mapped = unsafe { libc::mmap(address as *mut _, bytes.len(), initial, flags, -1, 0) };
        let failure = if mapped == libc::MAP_FAILED {
            Some(errno::last())
        } else if mapped as u64 != address {
            unsafe {
                libc::munmap(mapped, bytes.len());
            }
            Some(errno::ENOMEM)
        } else {
            unsafe {
                if protection == rwx {
                    aim_storage::host::pthread_jit_write_protect_np(0);
                }
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped.cast::<u8>(), bytes.len());
                if protection == rwx {
                    aim_storage::host::pthread_jit_write_protect_np(1);
                }
                sys_icache_invalidate(mapped, bytes.len());
            }
            if protection != rwx && unsafe { libc::mprotect(mapped, bytes.len(), protection) } != 0
            {
                Some(errno::last())
            } else {
                None
            }
        };
        if let Some(failure) = failure {
            unsafe {
                libc::munmap(address as *mut _, bytes.len());
            }
            let flags = libc::MAP_PRIVATE
                | libc::MAP_ANON
                | if current == rwx {
                    aim_storage::host::MAP_JIT
                } else {
                    libc::MAP_FIXED
                };
            let restored = unsafe {
                libc::mmap(
                    address as *mut _,
                    bytes.len(),
                    if current == rwx {
                        rwx
                    } else {
                        libc::PROT_READ | libc::PROT_WRITE
                    },
                    flags,
                    -1,
                    0,
                )
            };
            if restored as u64 != address {
                if restored != libc::MAP_FAILED {
                    unsafe {
                        libc::munmap(restored, bytes.len());
                    }
                }
                return Err(errno::ENOMEM);
            }
            unsafe {
                if current == rwx {
                    aim_storage::host::pthread_jit_write_protect_np(0);
                }
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), restored.cast::<u8>(), bytes.len());
                if current == rwx {
                    aim_storage::host::pthread_jit_write_protect_np(1);
                }
                sys_icache_invalidate(restored, bytes.len());
            }
            if current != rwx && unsafe { libc::mprotect(restored, bytes.len(), current) } != 0 {
                return Err(errno::last());
            }
            return Err(failure);
        }
        Ok(())
    })
    .map_err(std::io::Error::from_raw_os_error)?;
    result.map_err(std::io::Error::from_raw_os_error)
}

/// Publish a fully verified staging object without a guest-visible writable
/// interval. RWX staging first publishes fully initialized non-executable
/// bytes; execute permission is added only after the owned fixed remap.
pub(super) fn remap_verified_page(
    dst: u64,
    src: u64,
    len: u64,
    protection: i32,
    private: bool,
) -> std::io::Result<()> {
    let rwx = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    let jit = if private && protection & rwx == rwx {
        let staging = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | aim_storage::host::MAP_JIT,
                -1,
                0,
            )
        };
        if staging == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        unsafe {
            aim_storage::host::pthread_jit_write_protect_np(0);
            std::ptr::copy_nonoverlapping(src as *const u8, staging.cast::<u8>(), len as usize);
            aim_storage::host::pthread_jit_write_protect_np(1);
            sys_icache_invalidate(staging, len as usize);
        }
        Some(staging as u64)
    } else {
        if unsafe { libc::mprotect(src as *mut _, len as usize, protection) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        None
    };
    let source = jit.unwrap_or(src);
    let (mut addr, mut current, mut maximum) = (dst, 0, 0);
    let result = unsafe {
        mach_vm_remap(
            task(),
            &mut addr,
            len,
            0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            task(),
            source,
            i32::from(private && jit.is_none()),
            &mut current,
            &mut maximum,
            if private {
                VM_INHERIT_COPY
            } else {
                VM_INHERIT_SHARE
            },
        )
    };
    if let Some(staging) = jit {
        unsafe {
            libc::munmap(staging as *mut _, len as usize);
        }
    }
    if result != 0 {
        return Err(std::io::Error::other(format!(
            "Mach verified remap: kr {result:#x}"
        )));
    }
    super::memfd::unmapped(dst, len);
    if jit.is_some() {
        if unsafe { libc::mprotect(dst as *mut _, len as usize, protection) } != 0 {
            let failure = std::io::Error::last_os_error();
            if unsafe { libc::mprotect(dst as *mut _, len as usize, libc::PROT_NONE) } != 0 {
                return Err(std::io::Error::other(format!(
                    "JIT publish {failure}; protection rollback {}",
                    std::io::Error::last_os_error()
                )));
            }
            return Err(failure);
        }
        current = protection;
    }

    if addr != dst || current & protection != protection {
        return Err(std::io::Error::other(format!(
            "Mach verified remap protections {current:#x}/{maximum:#x}, requested {protection:#x}"
        )));
    }
    Ok(())
}

/// Make fork children share `[addr, addr+len)` instead of copying it.
pub(super) fn inherit_shared(addr: u64, len: u64) {
    // SAFETY: changing the inheritance of our own mapping.
    unsafe { mach_vm_inherit(task(), addr, len, VM_INHERIT_SHARE) };
}

/// Fresh anonymous memory anywhere in the guest range.
pub(super) fn allocate(len: u64) -> Result<u64, i64> {
    arena::map_anon(len, libc::PROT_READ | libc::PROT_WRITE)
}

fn host_page_aligned(addr: u64, len: u64) -> bool {
    addr & (PAGE - 1) == 0 && len & (PAGE - 1) == 0
}

/// Run `write` on `[lo, lo+len)` without remapping that span. A 16 KiB
/// `MAP_FIXED` would also clear the rest of the host page, which is how
/// call 2371 turned Scudo's 4 KiB `MADV_DONTNEED` into a zero chunk header
/// at `0x81af1ed6c0`.
fn write_guest_bytes(lo: u64, len: u64, region_prot: i32, write: impl FnOnce() -> i64) -> i64 {
    let mut cur = lo;
    let end = lo + len;
    let mut widened = Vec::new();
    while cur < end {
        let host = cur & !(PAGE - 1);
        let prot = page_prot(host).unwrap_or(region_prot as u32);
        if prot & libc::PROT_WRITE as u32 == 0 {
            let result = host_mprotect(host, PAGE, (prot | libc::PROT_WRITE as u32) as i32);
            if result < 0 {
                for (host, prot) in widened.iter().rev() {
                    host_mprotect(*host, PAGE, *prot as i32);
                }
                return result;
            }
            widened.push((host, prot));
        }
        cur = host + PAGE;
    }
    let written = write();
    for (host, prot) in widened.iter().rev() {
        let result = host_mprotect(*host, PAGE, *prot as i32);
        if result < 0 {
            return result;
        }
    }
    written
}

/// Linux MADV_DONTNEED on private memory must read back zeros (anonymous)
/// or the file's contents (file-backed); Darwin's does not guarantee it.
/// A whole 16 KiB host page is replaced. A 4 KiB guest page is written in
/// place so the other slices of that host page stay. Shared mappings keep
/// their contents, as on Linux.
fn discard_private(addr: u64, len: u64) -> i64 {
    for r in vmmap::regions(addr, addr + len) {
        let prot = r.prot as i32 & (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
        if r.shared || prot & libc::PROT_EXEC != 0 || prot == 0 {
            continue;
        }
        let (lo, n) = (r.start, r.end - r.start);
        if !host_page_aligned(lo, n) {
            let result = if r.file.is_none() {
                // SAFETY: `lo` is inside a mapped private region. Absent
                // 4 KiB slices stay readable until the whole host page goes.
                write_guest_bytes(lo, n, prot, || unsafe {
                    std::ptr::write_bytes(lo as *mut u8, 0, n as usize);
                    0
                })
            } else {
                let Some((path, _, _)) = &r.file else {
                    continue;
                };
                let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
                    continue;
                };
                // SAFETY: reopening the region's own backing file.
                let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if fd < 0 {
                    continue;
                }
                let offset = copies::find(lo).map_or(r.offset, |(_, off)| off);
                let filled = write_guest_bytes(lo, n, prot, || {
                    populate(lo, n, fd, offset).map_or_else(|error| error, |_| 0)
                });
                // SAFETY: our temporary fd.
                unsafe { libc::close(fd) };
                filled
            };
            if result < 0 {
                return result;
            }
            continue;
        }
        let fresh = match &r.file {
            Some((path, _, _)) => {
                let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
                    continue;
                };
                // SAFETY: reopening the region's own backing file.
                let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if fd < 0 {
                    continue;
                }
                // A fork child's copy reports offset 0 (`copies`).
                let offset = copies::find(lo).map_or(r.offset, |(_, off)| off);
                let m = host_mmap(
                    lo,
                    n,
                    prot,
                    libc::MAP_FIXED | libc::MAP_PRIVATE,
                    fd,
                    offset as i64,
                );
                // SAFETY: our temporary fd.
                unsafe { libc::close(fd) };
                m
            }
            None => host_mmap(
                lo,
                n,
                prot,
                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            ),
        };
        if let Err(e) = fresh {
            return e;
        }
        if r.file.is_none() {
            if let Err(error) = refill_copy(lo, n, prot) {
                return error;
            }
        }
    }
    0
}

/// Reload the file contents of copied pages in fresh `[lo, lo+n)`.
fn refill_copy(lo: u64, n: u64, prot: i32) -> Result<(), i64> {
    let mut cur = lo;
    while cur < lo + n {
        let Some((copy, offset)) = copies::find(cur) else {
            cur += PAGE;
            continue;
        };
        let end = copy.end.min(lo + n);
        let path = std::ffi::CString::new(copy.host.as_os_str().as_bytes())
            .map_err(|_| -(errno::EINVAL as i64))?;
        let source = super::verified_source::VerifiedSource::open(&path, false)
            .map_err(|error| -(error as i64))?;
        let mut bytes = vec![0; (end - cur) as usize];
        source
            .read_exact_at(&mut bytes, offset)
            .map_err(|error| -(error as i64))?;
        if prot & libc::PROT_WRITE == 0
            && host_mprotect(cur, end - cur, prot | libc::PROT_WRITE) < 0
        {
            return Err(-(errno::last() as i64));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), cur as *mut u8, bytes.len());
        }
        if prot & libc::PROT_WRITE == 0 && host_mprotect(cur, end - cur, prot) < 0 {
            return Err(-(errno::last() as i64));
        }
        cur = end;
    }
    Ok(())
}

pub fn madvise(a: [u64; 6]) -> i64 {
    let advice = a[2];
    // Bionic and Scudo discard 4 KiB pages (`GUEST_PAGE`). Rounding a
    // 4 KiB `MADV_DONTNEED` up to the 16 KiB host page zeros live chunks
    // on the following slices. `MADV_WILLNEED` stays on the host page.
    let granule = if matches!(advice, MADV_DONTNEED | MADV_REMOVE) {
        GUEST_PAGE
    } else {
        PAGE
    };
    let Some(len) = a[1].checked_add(granule - 1).map(|n| n & !(granule - 1)) else {
        return -(EINVAL as i64);
    };
    if a[0].checked_add(len).is_none() {
        return -(EINVAL as i64);
    }
    let _epoch = super::verity_pager::mutation();
    let _mapping = super::memfd::mapping_change();
    if super::verity_pager::failed_range(a[0], len) {
        return -(errno::EIO as i64);
    }
    let (addr, advice) = (a[0], advice);
    super::verity_pager::wait_pending(addr, len);
    if addr & (granule - 1) != 0 {
        return -(EINVAL as i64);
    }
    match advice {
        MADV_WILLNEED => {
            // Linux madvise(2): request read-ahead and report unmapped ranges.
            // SAFETY: advisory access to the validated guest range.
            errno::check(
                unsafe { libc::madvise(addr as *mut _, len as usize, libc::MADV_WILLNEED) } as i64,
            )
        }
        MADV_DONTNEED | MADV_REMOVE => {
            let ranges = super::verity_pager::covered(addr, len);
            if ranges.is_empty() {
                return discard_private(addr, len);
            }
            let mut cursor = addr;
            for &(lo, hi) in &ranges {
                if cursor < lo {
                    let result = discard_private(cursor, lo - cursor);
                    if result < 0 {
                        return result;
                    }
                }
                cursor = hi;
            }
            if cursor < addr + len {
                let result = discard_private(cursor, addr + len - cursor);
                if result < 0 {
                    return result;
                }
            }
            super::verity_pager::discard_range(addr, len)
                .map(|_| 0)
                .unwrap_or_else(|error| {
                    -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64)
                })
        }
        MADV_FREE => {
            // SAFETY: advisory only.
            unsafe { libc::madvise(addr as *mut _, len as usize, libc::MADV_FREE) };
            0
        }
        _ => 0,
    }
}

const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MREMAP_DONTUNMAP: u64 = 4;

/// Protection of one mapped guest page. An absent slice, or a host page
/// that is not mapped, is `EFAULT`. `GUEST_SLICES` wins over the host page
/// when the slice is present, which is the protection a later move keeps.
fn guest_slice_prot(page: u64) -> Result<u32, i64> {
    let host = page & !(PAGE - 1);
    let slot = ((page - host) / GUEST_PAGE) as usize;
    if let Some(pieces) = PAGE_PIECES.lock().unwrap().get(&host).copied() {
        if pieces.present & (1 << slot) == 0 {
            return Err(-(libc::EFAULT as i64));
        }
        if let Some(prot) = GUEST_SLICES.lock().unwrap().get(&page).copied() {
            return Ok(prot);
        }
        return Ok(pieces.prot[slot]);
    }
    match page_prot(host) {
        Some(prot) => {
            if let Some(found) = GUEST_SLICES.lock().unwrap().get(&page).copied() {
                return Ok(found);
            }
            Ok(prot)
        }
        None => Err(-(libc::EFAULT as i64)),
    }
}

/// Bytes of one guest page. A host page that is not readable is made
/// readable for the copy and put back before the page is punched, so a
/// `PROT_NONE` neighbor is not left readable and the page is never
/// writable and executable together.
fn copy_slice(addr: u64) -> Result<[u8; 4096], i64> {
    let host = addr & !(PAGE - 1);
    let old = page_prot(host).ok_or(-(libc::EFAULT as i64))?;
    let opened = old & libc::PROT_READ as u32 == 0;
    if opened {
        let result = host_mprotect(host, PAGE, libc::PROT_READ);
        if result < 0 {
            return Err(result);
        }
    }
    let mut buf = [0u8; 4096];
    // SAFETY: `addr` is a mapped guest page. The host page was readable
    // already, or this call just made the whole host page readable.
    unsafe {
        std::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), 4096);
    }
    if opened {
        let result = host_mprotect(host, PAGE, old as i32);
        if result < 0 {
            return Err(result);
        }
    }
    Ok(buf)
}

/// Install `bytes` as the guest page at `addr` with `prot`. Neighbors of
/// the host page stay. The host protection is write-wins, so the page is
/// never writable and executable together. A slice that itself asks for
/// both is refused.
fn place_slice(addr: u64, prot: u32, bytes: &[u8; 4096]) -> i64 {
    let prot = aim_guest_page::prot_bits(prot);
    if aim_guest_page::private_copy_is_wx(prot) {
        return -(EINVAL as i64);
    }
    let host = addr & !(PAGE - 1);
    let slot = ((addr - host) / GUEST_PAGE) as usize;
    let cover = 1u8 << slot;
    let existed = page_prot(host);
    let existing = { PAGE_PIECES.lock().unwrap().get(&host).copied() };
    let seeded = if let Some(mut entry) = existing {
        for s in 0..4usize {
            if entry.present & (1 << s) == 0 {
                continue;
            }
            let at = host + s as u64 * GUEST_PAGE;
            if let Ok(found) = guest_slice_prot(at) {
                entry.prot[s] = found;
            }
        }
        entry
    } else if let Some(bits) = existed {
        let mut prior = [bits; 4];
        for s in 0..4usize {
            let at = host + s as u64 * GUEST_PAGE;
            if let Ok(found) = guest_slice_prot(at) {
                prior[s] = found;
            }
        }
        PagePieces {
            present: 0b1111,
            prot: prior,
        }
    } else {
        PagePieces {
            present: 0,
            prot: [0; 4],
        }
    };
    // The bytes are written through a writable host page. That widening is
    // undone below: `opened` is the protection the page has while the bytes
    // are copied. Passing the protection from before the copy would leave a
    // read-only CFI shadow writable, because the write-wins result equals
    // that earlier protection.
    let writable = (libc::PROT_READ | libc::PROT_WRITE) as u32;
    let opened = if existed.is_none() {
        match host_mmap(
            host,
            PAGE,
            writable as i32,
            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        ) {
            Ok(mapped) if mapped == host => true,
            Ok(mapped) => {
                unsafe { libc::munmap(mapped as *mut _, PAGE as usize) };
                return -(ENOMEM as i64);
            }
            Err(error) => return error,
        }
    } else if existed.unwrap() & libc::PROT_WRITE as u32 == 0 {
        let result = host_mprotect(host, PAGE, writable as i32);
        if result < 0 {
            return result;
        }
        true
    } else {
        false
    };
    // SAFETY: the host page was just created writable, or mprotect'd
    // writable, or it was already writable. The write covers one guest page.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, 4096);
    }
    remember_slice(addr, "anonymous", prot);
    let (row, present) = aim_guest_page::overlay_fixed(seeded.prot, seeded.present, cover, prot);
    let pieces = PagePieces {
        present,
        prot: row,
    };
    let old_host = aim_guest_page::host_protection(present_prots(&seeded));
    let new_host = aim_guest_page::host_protection(present_prots(&pieces));
    {
        let mut pages = PAGE_PIECES.lock().unwrap();
        if present == 0 || (present == 0b1111 && row.iter().all(|item| *item == row[0])) {
            pages.remove(&host);
        } else {
            pages.insert(host, pieces);
        }
        let mut recorded = GUEST_SLICES.lock().unwrap();
        if prot == new_host {
            recorded.remove(&addr);
        } else {
            recorded.insert(addr, prot);
        }
    }
    let from = if opened { writable } else { old_host };
    apply_host_prot(host, &pieces, from, new_host, true)
}

/// `mremap` of a range that is not a whole number of 16 KiB host pages.
///
/// Bionic's CFI shadow update moves one 4 KiB page with
/// `MREMAP_MAYMOVE|MREMAP_FIXED`. Rounding that length up to the host page
/// would take the next three slices with it, and a destination that is only
/// 4 KiB-aligned is `EINVAL` on the host-page path. The slice moves, or the
/// call returns the errno of a move Linux would refuse. A successful return
/// is the new address. Shrinking in place punches the tail. A grow, or a
/// move whose size changes, would have to be rounded onto a neighbor, so
/// that call is `ENOMEM`.
fn mremap_subpage(a: [u64; 6]) -> i64 {
    let _epoch = super::verity_pager::mutation();
    let _mapping = super::memfd::mapping_change();
    let old = a[0];
    let old_len = match aim_guest_page::guest_page_len(a[1]) {
        Ok(len) => len,
        Err(error) => return -(error as i64),
    };
    let new_len = match aim_guest_page::guest_page_len(a[2]) {
        Ok(len) => len,
        Err(error) => return -(error as i64),
    };
    let flags = a[3];
    let new_addr = a[4];
    if old & (GUEST_PAGE - 1) != 0
        || old_len == 0
        || new_len == 0
        || flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
        || flags & (MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 && flags & MREMAP_MAYMOVE == 0
        || flags & MREMAP_DONTUNMAP != 0 && old_len != new_len
    {
        return -(EINVAL as i64);
    }
    let end = match old.checked_add(old_len) {
        Some(end) => end,
        None => return -(ENOMEM as i64),
    };
    if !super::verity_pager::covered(old, old_len).is_empty() {
        return -(EINVAL as i64);
    }
    let mut page = old;
    while page < end {
        if guest_slice_prot(page).is_err() {
            return -(libc::EFAULT as i64);
        }
        if vmmap::region_at(page).is_some_and(|region| {
            page >= region.start && page < region.end && (region.file.is_some() || region.shared)
        }) {
            return -(EINVAL as i64);
        }
        page += GUEST_PAGE;
    }
    let fixed = flags & MREMAP_FIXED != 0;
    let keep = flags & MREMAP_DONTUNMAP != 0;
    if fixed {
        if new_addr & (GUEST_PAGE - 1) != 0 {
            return -(EINVAL as i64);
        }
        let new_end = match new_addr.checked_add(new_len) {
            Some(end) => end,
            None => return -(ENOMEM as i64),
        };
        if new_addr < end && old < new_end {
            return -(EINVAL as i64);
        }
        if new_len != old_len {
            return -(ENOMEM as i64);
        }
        if window::touches_reserved(new_addr, new_end) {
            return -(ENOMEM as i64);
        }
        let mut moved = Vec::with_capacity((old_len / GUEST_PAGE) as usize);
        let mut page = old;
        while page < end {
            let prot = match guest_slice_prot(page) {
                Ok(prot) => prot,
                Err(error) => return error,
            };
            let bytes = match copy_slice(page) {
                Ok(bytes) => bytes,
                Err(error) => return error,
            };
            moved.push((prot, bytes));
            page += GUEST_PAGE;
        }
        for (index, (prot, bytes)) in moved.iter().enumerate() {
            let at = new_addr + index as u64 * GUEST_PAGE;
            let result = place_slice(at, *prot, bytes);
            if result < 0 {
                return result;
            }
        }
        if keep {
            // The source mapping stays. Drop a file-copy record of the
            // range this move replaced. A shared or file source was refused
            // above, so the source record stays where it is.
            copies::forget(new_addr, new_addr + new_len);
        } else {
            let punched = punch_guest_range(old, end);
            if punched < 0 {
                return punched;
            }
            forget_guest_slices(old, end);
            copies::moved(old, new_addr, old_len);
        }
        let kind = vm_account::with(|space| space.kind_at(old));
        if let Some(kind) = kind {
            vm_account::with(|space| {
                if !keep {
                    space.unmap(old, end);
                }
                space.map(new_addr, new_addr + new_len, kind);
            });
        }
        super::vma_names::remap(old, old_len, new_addr, new_len, keep);
        if let Err(error) = super::verity_pager::reconcile_memberships() {
            return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
        }
        return new_addr as i64;
    }
    if new_len > old_len {
        return -(ENOMEM as i64);
    }
    if new_len < old_len {
        let tail = old + new_len;
        let punched = punch_guest_range(tail, end);
        if punched < 0 {
            return punched;
        }
        forget_guest_slices(tail, end);
        copies::forget(tail, end);
        let kind = vm_account::with(|space| space.kind_at(old));
        if kind.is_some() {
            vm_account::with(|space| space.unmap(tail, end));
        }
        super::vma_names::remap(old, old_len, old, new_len, false);
    }
    old as i64
}

/// Unmap each guest page of `[lo, hi)`. A host page whose slices are all
/// covered is released. A page that still has a neighbor stays, with that
/// neighbor's protection.
fn punch_guest_range(lo: u64, hi: u64) -> i64 {
    let mut host = lo & !(PAGE - 1);
    while host < hi {
        let mut cover = 0u8;
        for slot in 0..4 {
            let at = host + slot * GUEST_PAGE;
            if at >= lo && at + GUEST_PAGE <= hi {
                cover |= 1 << slot;
            }
        }
        if cover != 0 {
            let result = punch_page(host, cover);
            if result < 0 {
                return result;
            }
        }
        host += PAGE;
    }
    0
}

/// Map `[addr, addr+len)` as the continuation of the mapping whose last
/// page is `like`, as mremap(2) grows it: the file's following pages with
/// the same sharing and protection for a file mapping, fresh anonymous
/// memory otherwise. `addr` must be free unless `replace`.
fn extend_at(addr: u64, len: u64, like: u64, replace: bool) -> Result<(), i64> {
    let replace = replace || window::is_free(addr, len);
    let mut at = addr;
    let flags = VM_FLAGS_FIXED | if replace { VM_FLAGS_OVERWRITE } else { 0 };
    // SAFETY: allocating in our own task; FIXED without OVERWRITE fails
    // rather than replacing anything.
    if unsafe { mach_vm_allocate(task(), &mut at, len, flags) } != 0 {
        return Err(-(ENOMEM as i64));
    }
    super::memfd::unmapped(addr, len);
    let Some(r) = vmmap::region_at(like).filter(|r| r.start <= like) else {
        return Ok(());
    };
    let prot = r.prot as u64 & (PROT_READ | PROT_WRITE | PROT_EXEC);
    // A private file mapping (or a copy standing in for one) is recorded
    // with its file and offset, which a fork child's copy does not report.
    // Executable file views not recorded are translated code the guest
    // mapped private, from a cache file ([`mmap`]).
    let copy = copies::find(like);
    let file = match (&copy, &r.file) {
        (Some((c, off)), _) => Some((c.host.clone(), off + PAGE, false)),
        (None, Some((host, _, _))) if prot & PROT_EXEC == 0 => {
            Some((host.clone(), r.offset + (like - r.start) + PAGE, r.shared))
        }
        _ => None,
    };
    let Some((host, off, shared)) = file else {
        // SAFETY: our fresh allocation.
        unsafe { mach_vm_protect(task(), addr, len, 0, prot as i32) };
        return Ok(());
    };
    let mapped = map_file_at(addr, len, prot, &host, off, shared);
    if let Err(e) = mapped {
        window::unmap(addr, len);
        return Err(e);
    }
    if let Some((c, _)) = copy {
        copies::note_file(addr, len, &c.host, &c.guest, off, (c.dev, c.ino), c.anonymous);
    }
    Ok(())
}

/// Map `host` from `off` at `addr` (replacing what is there) as the guest's
/// mmap would.
fn map_file_at(
    addr: u64,
    len: u64,
    prot: u64,
    host: &std::path::Path,
    off: u64,
    shared: bool,
) -> Result<(), i64> {
    let c = std::ffi::CString::new(host.as_os_str().as_bytes()).map_err(|_| -(ENOMEM as i64))?;
    let mode = if shared && prot & PROT_WRITE != 0 {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };
    // SAFETY: reopening the mapping's own backing file.
    let fd = unsafe { libc::open(c.as_ptr(), mode | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(-(errno::last() as i64));
    }
    let kind = if shared { MAP_SHARED } else { MAP_PRIVATE };
    let r = mmap_owned([addr, len, prot, kind | MAP_FIXED, fd as u64, off]);
    // SAFETY: our temporary fd.
    unsafe { libc::close(fd) };
    if r < 0 { Err(r) } else { Ok(()) }
}

/// Move `[old, old+old_len)` to `new` (resized to `new_len`), replacing
/// what is at the destination.
fn move_to(old: u64, old_len: u64, new: u64, new_len: u64, keep_old: bool) -> Result<(), i64> {
    let moved = old_len.min(new_len);
    remap_shared(new, old, moved)?;
    super::memfd::note_alias(old, new, moved);
    copies::moved(old, new, moved);
    if new_len > old_len {
        extend_at(new + old_len, new_len - old_len, new + old_len - PAGE, true)?;
    }
    if keep_old {
        // MREMAP_DONTUNMAP: the old range stays mapped, empty.
        let result = discard_private(old, old_len);
        if result < 0 {
            return Err(result);
        }
    } else {
        // The old pages now live at `new`.
        window::unmap(old, old_len);
    }
    Ok(())
}

pub fn mremap(a: [u64; 6]) -> i64 {
    match aim_guest_page::whole_host_pages(a[0], a[1]) {
        Ok(false) => return mremap_subpage(a),
        Ok(true) => {}
        Err(error) => return -(error as i64),
    }
    let _epoch = super::verity_pager::mutation();
    let _mapping = super::memfd::mapping_change();
    let (old, old_len, new_len, flags) = (a[0], page_up(a[1]), page_up(a[2]), a[3]);
    let kind = vm_account::with(|s| s.kind_at(old));
    // `vma_to_resize`: growth is counted against the limits.
    if let Some(kind) = kind
        && new_len > old_len
    {
        let (limits, heap) = (super::cred::memory_limits(), brk_heap());
        if !vm_account::with(|s| s.may_expand(limits, heap, kind.data(), new_len - old_len)) {
            return -(ENOMEM as i64);
        }
    }
    let result = mremap_guest(a);
    if result >= 0 {
        if flags & MREMAP_DONTUNMAP == 0 {
            forget_guest_slices(old, old + old_len);
        }
        forget_guest_slices(result as u64, result as u64 + new_len);
        super::vma_names::remap(
            old,
            old_len,
            result as u64,
            new_len,
            flags & MREMAP_DONTUNMAP != 0,
        );
    }
    if result >= 0
        && let Some(kind) = kind
    {
        let new = result as u64;
        vm_account::with(|s| {
            if flags & MREMAP_DONTUNMAP == 0 {
                s.unmap(old, old + old_len);
            }
            s.map(new, new + new_len, kind);
        });
    }
    if result >= 0
        && let Err(error) = super::verity_pager::reconcile_memberships()
    {
        return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
    }
    result
}
fn mremap_guest(a: [u64; 6]) -> i64 {
    if super::verity_pager::failed_range(a[0], page_up(a[1])) {
        return -(errno::EIO as i64);
    }
    let (old, old_len, new_len, flags, new_addr) = (a[0], page_up(a[1]), page_up(a[2]), a[3], a[4]);
    super::verity_pager::wait_pending(old, old_len);
    if flags & MREMAP_FIXED != 0 {
        super::verity_pager::wait_pending(new_addr, new_len);
    }
    if !super::verity_pager::covered(old, old_len).is_empty() {
        if old % PAGE != 0
            || new_len == 0
            || flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
            || flags & (MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 && flags & MREMAP_MAYMOVE == 0
            || flags & MREMAP_DONTUNMAP != 0 && old_len != new_len
        {
            return -(EINVAL as i64);
        }
        let fixed = flags & MREMAP_FIXED != 0;
        let keep = flags & MREMAP_DONTUNMAP != 0;
        let destination = if fixed {
            if new_addr % PAGE != 0 || new_addr < old + old_len && old < new_addr + new_len {
                return -(EINVAL as i64);
            }
            new_addr
        } else if !keep && new_len <= old_len {
            old
        } else {
            if flags & MREMAP_MAYMOVE == 0 {
                return -(ENOMEM as i64);
            }
            match arena::map_anon(new_len, libc::PROT_NONE) {
                Ok(address) => address,
                Err(error) => return error,
            }
        };
        let result = super::verity_pager::remap(old, old_len, destination, new_len, keep, || {
            if destination == old {
                if new_len < old_len && window::unmap(old + new_len, old_len - new_len) < 0 {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
                }
            } else {
                if fixed {
                    let reservation = unsafe {
                        libc::mmap(
                            destination as *mut _,
                            new_len as usize,
                            libc::PROT_NONE,
                            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                            -1,
                            0,
                        )
                    };
                    if reservation == libc::MAP_FAILED {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                remap_shared(destination, old, old_len.min(new_len))
                    .map_err(|error| std::io::Error::from_raw_os_error((-error) as i32))?;
                if keep {
                    let blank = unsafe {
                        libc::mmap(
                            old as *mut _,
                            old_len as usize,
                            libc::PROT_NONE,
                            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                            -1,
                            0,
                        )
                    };
                    if blank == libc::MAP_FAILED {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if window::unmap(old, old_len) < 0 {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
                }
            }
            Ok(())
        });
        return match result {
            Ok(true) => destination as i64,
            Ok(false) => -(libc::EFAULT as i64),
            Err(error) => -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64),
        };
    }
    let owner = match super::fuse_cache::remap_owner(old, old_len) {
        Ok(owner) => owner,
        Err(error) => return -(error as i64),
    };
    if owner.is_some() {
        if old_len > new_len
            && let Err(error) = super::fuse_cache::flush_range(old + new_len, old_len - new_len)
        {
            return -(error as i64);
        }
        if flags & MREMAP_FIXED != 0
            && let Err(error) = super::fuse_cache::flush_range(new_addr, new_len)
        {
            return -(error as i64);
        }
    }
    let tracked = super::verity_pager::mapping_view(old, old_len);
    let result = mremap_inner(a);
    if result >= 0
        && let Some(view) = tracked
    {
        if let Err(error) = super::verity_pager::moved_existing(
            view,
            result as u64,
            new_len,
            flags & MREMAP_DONTUNMAP != 0,
        ) {
            return -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64);
        }
    }
    if result >= 0
        && let Some(owner) = owner
    {
        super::fuse_cache::remapped(
            owner,
            old,
            old_len,
            result as u64,
            new_len,
            flags & MREMAP_DONTUNMAP != 0,
        );
    }
    result
}
fn mremap_inner(a: [u64; 6]) -> i64 {
    let (old, old_len, new_len, flags, new_addr) = (a[0], page_up(a[1]), page_up(a[2]), a[3], a[4]);
    if old & (PAGE - 1) != 0
        || flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
        || (flags & (MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 && flags & MREMAP_MAYMOVE == 0)
        || new_len == 0
    {
        return -(EINVAL as i64);
    }
    if flags & MREMAP_DONTUNMAP != 0 && old_len != new_len {
        return -(EINVAL as i64);
    }
    let Some(region) = vmmap::region_at(old).filter(|r| r.start <= old) else {
        return -(libc::EFAULT as i64);
    };
    // `vma_to_resize`: a bpf object's mapping (VM_DONTEXPAND) never grows.
    if new_len > old_len && super::bpf::maps_object(&region) {
        return -(libc::EFAULT as i64);
    }
    let keep_old = flags & MREMAP_DONTUNMAP != 0;
    if flags & MREMAP_FIXED != 0 {
        if new_addr & (PAGE - 1) != 0 || (new_addr < old + old_len && old < new_addr + new_len) {
            return -(EINVAL as i64);
        }
        return match move_to(old, old_len, new_addr, new_len, keep_old) {
            Ok(()) => new_addr as i64,
            Err(e) => e,
        };
    }
    if old_len == 0 {
        // Linux: a second mapping of the same (shared) pages.
        let at = match allocate(new_len) {
            Ok(a) => a,
            Err(e) => return e,
        };
        return match remap_shared(at, old, new_len) {
            Ok(()) => {
                super::memfd::note_alias(old, at, new_len);
                at as i64
            }
            Err(e) => e,
        };
    }
    if !keep_old && new_len <= old_len {
        if new_len < old_len {
            copies::forget(old + new_len, old + old_len);
            window::unmap(old + new_len, old_len - new_len);
        }
        return old as i64;
    }
    if !keep_old
        && extend_at(
            old + old_len,
            new_len - old_len,
            old + old_len - PAGE,
            false,
        )
        .is_ok()
    {
        return old as i64;
    }
    if flags & MREMAP_MAYMOVE == 0 {
        return -(ENOMEM as i64);
    }
    let at = match allocate(new_len) {
        Ok(a) => a,
        Err(e) => return e,
    };
    match move_to(old, old_len, at, new_len, keep_old) {
        Ok(()) => at as i64,
        Err(e) => {
            // SAFETY: releasing our reservation.
            unsafe { mach_vm_deallocate(task(), at, new_len) };
            e
        }
    }
}

pub fn mincore(a: [u64; 6]) -> i64 {
    let (addr, len, vec) = (a[0], page_up(a[1]), a[2]);
    if addr & (PAGE - 1) != 0 {
        return -(EINVAL as i64);
    }
    if vmmap::regions(addr, addr + len)
        .map(|r| r.end - r.start)
        .sum::<u64>()
        != len
    {
        return -(ENOMEM as i64);
    }
    // SAFETY: guest vector of len/PAGE bytes. Darwin's mincore wants
    // `*mut c_char`; Linux's wants `*mut u8`.
    #[cfg(target_os = "macos")]
    let resident = vec as *mut libc::c_char;
    #[cfg(not(target_os = "macos"))]
    let resident = vec as *mut u8;
    let r = unsafe { libc::mincore(addr as *mut _, len as usize, resident) };
    if r < 0 {
        return -(errno::last() as i64);
    }
    for i in 0..(len / PAGE) as usize {
        // SAFETY: inside the guest vector; Linux reports only residency.
        let byte = user_read!(vec + i as u64, u8);
        user_write!(vec + i as u64, u8, byte & 1);
    }
    0
}

pub fn msync(a: [u64; 6]) -> i64 {
    const MS_ASYNC: u64 = 1;
    const MS_INVALIDATE: u64 = 2;
    const MS_SYNC: u64 = 4;
    let (addr, len, flags) = (a[0], a[1], a[2]);
    if addr & (GUEST_PAGE - 1) != 0
        || flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || flags & (MS_ASYNC | MS_SYNC) == (MS_ASYNC | MS_SYNC)
    {
        return -(EINVAL as i64);
    }
    let Some(end) = addr.checked_add(len).map(|n| (n + GUEST_PAGE - 1) & !(GUEST_PAGE - 1)) else {
        return -(EINVAL as i64);
    };
    if end == addr {
        return 0;
    }
    let host_lo = addr & !(PAGE - 1);
    let host_hi = (end + PAGE - 1) & !(PAGE - 1);
    if window::touches_reserved(host_lo, host_hi) {
        return -(ENOMEM as i64);
    }
    let mut h = 0;
    if flags & MS_ASYNC != 0 {
        h |= libc::MS_ASYNC;
    }
    if flags & MS_SYNC != 0 {
        h |= libc::MS_SYNC;
    }
    if flags & MS_INVALIDATE != 0 {
        h |= libc::MS_INVALIDATE;
    }
    // The guest address is 4 KiB-aligned. Darwin syncs the host pages
    // that cover it.
    let result = errno::check(unsafe {
        libc::msync(host_lo as *mut _, (host_hi - host_lo) as usize, h)
    } as i64);
    if result < 0 {
        return result;
    }
    let flushed = if flags & MS_SYNC != 0 {
        super::fuse_cache::flush_range(host_lo, host_hi - host_lo)
    } else {
        super::fuse_cache::schedule_range(host_lo, host_hi - host_lo)
    };
    match flushed {
        Ok(()) => 0,
        Err(error) => -(error as i64),
    }
}

pub fn mlock(nr: u64, a: [u64; 6]) -> i64 {
    let privileged = super::cred::capable(super::cred::CAP_IPC_LOCK);
    let limit = match super::cred::own_rlimit(8, None, false) {
        Ok(l) => l[0],
        Err(e) => return e,
    };
    if nr != 229 && limit == 0 && !privileged {
        return -(errno::EPERM as i64);
    }
    // Linux accepts unaligned addresses and charges every touched page.
    let addr = a[0] & !(PAGE - 1);
    let Some(end) = a[0]
        .checked_add(a[1])
        .and_then(|n| n.checked_add(PAGE - 1))
        .map(|n| n & !(PAGE - 1))
    else {
        return -(EINVAL as i64);
    };
    if addr == end {
        return 0;
    }
    static LOCK: Mutex<()> = Mutex::new(());
    let _lock = LOCK.lock().unwrap();
    let mut cursor = addr;
    let mut already_locked = 0;
    let mut unwired = Vec::new();
    for r in vmmap::regions(addr, end) {
        if r.start != cursor {
            return -(ENOMEM as i64);
        }
        if r.usage.wired {
            already_locked += r.end - r.start;
        } else {
            unwired.push((r.start, r.end - r.start));
        }
        cursor = r.end;
    }
    if cursor != end {
        return -(ENOMEM as i64);
    }
    if nr != 229 && !privileged && limit != u64::MAX {
        let locked: u64 = vmmap::regions(0, u64::MAX)
            .filter(|r| r.usage.wired)
            .map(|r| r.end - r.start)
            .sum();
        if locked + (end - addr - already_locked) > limit / PAGE * PAGE {
            return -(ENOMEM as i64);
        }
    }
    // SAFETY: mapped page-aligned range. Darwin performs real wiring; a host
    // resource failure is returned, never replaced by a successful pin.
    if nr == 229 {
        return errno::check(
            unsafe { libc::munlock(addr as *const _, (end - addr) as usize) } as i64,
        );
    }
    // Darwin's user wiring nests; Linux mlock does not. Wire only new pages.
    for (i, &(start, len)) in unwired.iter().enumerate() {
        if unsafe { libc::mlock(start as *const _, len as usize) } < 0 {
            let error = errno::last();
            for &(start, len) in &unwired[..i] {
                unsafe {
                    libc::munlock(start as *const _, len as usize);
                }
            }
            return -(error as i64);
        }
    }
    0
}

const MEMBARRIER_CMD_QUERY: u64 = 0;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED: u64 = 1 << 3;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: u64 = 1 << 4;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 1 << 5;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 1 << 6;

unsafe extern "C" {
    fn thread_get_register_pointer_values(
        thread: u32,
        sp: *mut u64,
        length: *mut usize,
        values: *mut u64,
    ) -> i32;
}

/// Serialize the process's other running threads, as Linux interrupts
/// only the cores that run them: reading a thread's registers makes the
/// kernel interrupt it, which is a full barrier and a context
/// synchronization on its core (as .NET does on macOS arm64). A thread
/// that is not running takes the scheduler's thread lock, which reading
/// its state also takes, and an exception return before it runs again;
/// the fence puts the caller's accesses before that read, as Linux's
/// smp_mb before it looks at the run queues.
fn barrier_all_threads() {
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    super::thread::each_running_other(|t| {
        let (mut sp, mut n, mut regs) = (0u64, 128usize, [0u64; 128]);
        // SAFETY: a live thread of this task; results into locals.
        unsafe { thread_get_register_pointer_values(t, &mut sp, &mut n, regs.as_mut_ptr()) };
    });
}

pub fn membarrier(a: [u64; 6]) -> i64 {
    let (cmd, flags) = (a[0], a[1]);
    if flags != 0 {
        return -(EINVAL as i64);
    }
    match cmd {
        MEMBARRIER_CMD_QUERY => {
            (MEMBARRIER_CMD_PRIVATE_EXPEDITED
                | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
                | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
                | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE) as i64
        }
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
        | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => 0,
        MEMBARRIER_CMD_PRIVATE_EXPEDITED | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
            barrier_all_threads();
            0
        }
        _ => -(EINVAL as i64),
    }
}

/// process_vm_readv/writev: on this process here, on another through its
/// agent (`ptrace`). `pid` may name any thread of the process.
pub fn process_vm_rw(write: bool, a: [u64; 6]) -> i64 {
    let (pid, local, lcnt, remote, rcnt, flags) = (a[0] as i32, a[1], a[2], a[3], a[4], a[5]);
    if flags != 0 || lcnt > 1024 || rcnt > 1024 {
        return -(EINVAL as i64);
    }
    // SAFETY: guest iovec arrays of the given counts.
    let iov = |p: u64, n: u64| -> Result<Vec<(u64, u64)>, i32> {
        let mut vectors = Vec::new();
        for index in 0..n {
            let vector = user_read!(p + index * 16, [u64; 2]);
            if vector[1] != 0 {
                vectors.push((vector[0], vector[1]));
            }
        }
        Ok(vectors)
    };
    let (l, r) = (user_try!(iov(local, lcnt)), user_try!(iov(remote, rcnt)));
    let owner = super::thread::owner(pid);
    // SAFETY: trivial.
    if pid <= 0 || owner != unsafe { libc::getpid() } {
        return super::ptrace::remote_vm(write, owner, &l, &r);
    }
    let (mut li, mut lo, mut done) = (0usize, 0u64, 0u64);
    for (rbase, rlen) in r {
        let mut ro = 0u64;
        while ro < rlen && li < l.len() {
            let n = (rlen - ro).min(l[li].1 - lo);
            let (src, dst) = if write {
                (l[li].0 + lo, rbase + ro)
            } else {
                (rbase + ro, l[li].0 + lo)
            };
            let mut got = 0u64;
            // SAFETY: a fault-safe copy within our own task.
            if unsafe { mach_vm_read_overwrite(task(), src, n, dst, &mut got) } != 0 {
                return if done > 0 {
                    done as i64
                } else {
                    -(libc::EFAULT as i64)
                };
            }
            done += n;
            ro += n;
            lo += n;
            if lo == l[li].1 {
                li += 1;
                lo = 0;
            }
        }
    }
    done as i64
}

struct Brk {
    base: u64,
    cur: u64,
    mapped: u64,
    limit: u64,
}

static BRK: Mutex<Brk> = Mutex::new(Brk {
    base: 0,
    cur: 0,
    mapped: 0,
    limit: 0,
});
const BRK_RESERVE: u64 = 64 << 20;

/// Reserve the program break area near the end of the main executable.
pub fn init_brk(hint: u64) {
    let base = host_mmap(
        page_up(hint),
        BRK_RESERVE,
        libc::PROT_NONE,
        libc::MAP_PRIVATE | libc::MAP_ANON,
        -1,
        0,
    )
    .unwrap_or(0);
    let mut b = BRK.lock().unwrap();
    *b = Brk {
        base,
        cur: base,
        mapped: base,
        limit: base + BRK_RESERVE,
    };
}

/// brk: a break it cannot move to leaves it where it was, as Linux
/// answers (`check_data_rlimit`, then `do_brk_flags`' `may_expand_vm`).
pub fn brk(a: [u64; 6]) -> i64 {
    let want = a[0];
    let limits = super::cred::memory_limits();
    let _epoch = super::verity_pager::mutation();
    let mut b = BRK.lock().unwrap();
    if want == 0 || want < b.base || want > b.limit {
        return b.cur as i64;
    }
    if !vm_account::with(|s| s.brk_fits(limits, want - b.base)) {
        return b.cur as i64;
    }
    let (old_heap, new_heap) = (page_up(b.cur) - b.base, page_up(want) - b.base);
    if new_heap > old_heap
        && !vm_account::with(|s| s.may_expand(limits, old_heap, true, new_heap - old_heap))
    {
        return b.cur as i64;
    }
    let need = page_up(want);
    if need > b.mapped {
        if host_mprotect(
            b.mapped,
            need - b.mapped,
            libc::PROT_READ | libc::PROT_WRITE,
        ) != 0
        {
            return b.cur as i64;
        }
        b.mapped = need;
    }
    b.cur = want;
    vm_account::with(|s| s.set_heap(need - b.base));
    b.cur as i64
}

/// The program break's heap as Linux maps it (`start_brk` to the page
/// above the break).
fn brk_heap() -> u64 {
    let b = BRK.lock().unwrap();
    page_up(b.cur).saturating_sub(b.base)
}

/// Exec: the program's and the interpreter's segments are the guest's
/// first mappings (`load_elf_binary`), and the program's set the data
/// segment brk counts (`start_data` is the last segment's address,
/// `end_data` the furthest end of file data).
pub fn account_image(loads: &[crate::elf::Phdr], bias: u64, program: bool) {
    const PF_W: u32 = 2;
    let (mut start_data, mut end_data) = (0, 0);
    // The headers as the loader read them from the file: the image's own
    // pages may not be readable yet (an authenticated image's are verified
    // on the guest's first touch).
    vm_account::with(|s| {
        for h in loads {
            let p_flags = h.p_flags;
            let (vaddr, filesz, memsz) = (h.p_vaddr, h.p_filesz, h.p_memsz);
            let lo = (bias + vaddr) & !(PAGE - 1);
            let hi = page_up(bias + vaddr + memsz);
            let kind = vm_account::Kind {
                shared: false,
                writable: p_flags & PF_W != 0,
                stack: false,
            };
            s.map(lo, hi, kind);
            start_data = start_data.max(vaddr);
            end_data = end_data.max(vaddr + filesz);
        }
        if program {
            s.set_data_segment(end_data.saturating_sub(start_data));
        }
    });
}

/// Fork: the program break (its pages come with the guest's memory).
pub(super) fn fork_save(w: &mut super::fork_state::Writer) {
    {
        let b = BRK.lock().unwrap();
        for v in [b.base, b.cur, b.mapped, b.limit] {
            w.u64(v);
        }
    }
    vm_account::fork_save(w);
    super::vma_names::fork_save(w);
}

pub(super) fn fork_restore(r: &mut super::fork_state::Reader) {
    let v = [(); 4].map(|_| r.u64());
    *BRK.lock().unwrap() = Brk {
        base: v[0],
        cur: v[1],
        mapped: v[2],
        limit: v[3],
    };
    vm_account::fork_restore(r);
    let heap = brk_heap();
    vm_account::with(|s| s.set_heap(heap));
    super::vma_names::fork_restore(r);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_locking_charges_pages_once_and_honors_linux_limits() {
        if super::super::fdtab::isolated_kernel_test(
            "sys::mem::tests::memory_locking_charges_pages_once_and_honors_linux_limits",
        ) {
            return;
        }
        let mut identity = super::super::cred::Identity::default();
        identity.cap_eff = 0;
        identity.rlimits[8] = Some((PAGE, u64::MAX));
        super::super::cred::init(identity.clone(), None);
        // SAFETY: fresh writable pages, released below.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                (3 * PAGE) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        let at = ptr as u64;
        let lock = |addr, len| mlock(228, [addr, len, 0, 0, 0, 0]);
        let unlock = |addr, len| mlock(229, [addr, len, 0, 0, 0, 0]);
        assert_eq!(lock(at + 1, PAGE), -(ENOMEM as i64));
        assert_eq!(lock(at + 1, 1), 0);
        assert!(vmmap::region_at(at).unwrap().usage.wired);
        assert_eq!(lock(at + 2, 1), 0, "overlap is charged only once");
        assert_eq!(lock(at + PAGE, 1), -(ENOMEM as i64));
        assert_eq!(unlock(at + 1, 1), 0);
        assert!(!vmmap::region_at(at).unwrap().usage.wired);
        assert_eq!(lock(at + PAGE, 1), 0);
        assert_eq!(unlock(at + PAGE, 1), 0);
        super::super::cred::own_rlimit(8, Some([3 * PAGE, u64::MAX]), false).unwrap();
        assert_eq!(lock(at, 1), 0);
        assert_eq!(
            lock(at, 2 * PAGE),
            0,
            "partial overlap wires only new pages"
        );
        assert_eq!(unlock(at, 2 * PAGE), 0);
        assert!(!vmmap::region_at(at).unwrap().usage.wired);
        assert_eq!(lock(u64::MAX - 1, 4), -(EINVAL as i64));
        // SAFETY: make a hole in our own mapping.
        assert_eq!(
            unsafe { libc::munmap((at + PAGE) as *mut _, PAGE as usize) },
            0
        );
        assert_eq!(lock(at, 3 * PAGE), -(ENOMEM as i64));
        assert_eq!(unlock(at, 3 * PAGE), -(ENOMEM as i64));
        assert!(!vmmap::region_at(at).unwrap().usage.wired);
        super::super::cred::own_rlimit(8, Some([0, u64::MAX]), false).unwrap();
        assert_eq!(lock(at, 1), -(errno::EPERM as i64));
        identity.cap_eff = 1 << super::super::cred::CAP_IPC_LOCK;
        identity.rlimits[8] = Some((0, u64::MAX));
        super::super::cred::init(identity, None);
        assert_eq!(lock(at, 1), 0, "CAP_IPC_LOCK bypasses the guest limit");
        assert_eq!(unlock(at, 1), 0);
        // SAFETY: release the two surviving pages.
        unsafe {
            libc::munmap(ptr, PAGE as usize);
            libc::munmap((at + 2 * PAGE) as *mut _, PAGE as usize);
        }
        // Pinner's HOME budget must be real wired memory, above Linux's common
        // unprivileged limit. The host must still accept the actual wiring.
        use std::os::fd::AsRawFd;
        let bytes = 60 * 1024 * 1024;
        let path = std::env::temp_dir().join(format!("aim-pinner-lock-{}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        file.set_len(bytes as u64).unwrap();
        // Pinner maps regular files read-only and shared before locking ranges.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        assert_eq!(
            madvise([ptr as u64, bytes as u64, MADV_WILLNEED, 0, 0, 0]),
            0
        );
        assert_eq!(lock(ptr as u64, bytes as u64), 0);
        assert!(vmmap::region_at(ptr as u64).unwrap().usage.wired);
        assert_eq!(unlock(ptr as u64, bytes as u64), 0);
        unsafe {
            libc::munmap(ptr, bytes);
        }
    }

    #[test]
    fn willneed_requests_readahead_and_reports_invalid_ranges() {
        // madvise(2): alignment, rounding, overflow and unmapped-range errors.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        let at = ptr as u64;
        assert_eq!(madvise([at, 1, MADV_WILLNEED, 0, 0, 0]), 0);
        assert_eq!(
            madvise([at + 1, 1, MADV_WILLNEED, 0, 0, 0]),
            -(EINVAL as i64)
        );
        assert_eq!(
            madvise([at, u64::MAX, MADV_WILLNEED, 0, 0, 0]),
            -(EINVAL as i64)
        );
        assert_eq!(
            madvise([u64::MAX & !(PAGE - 1), PAGE, MADV_WILLNEED, 0, 0, 0]),
            -(EINVAL as i64)
        );
        unsafe {
            libc::munmap(ptr, PAGE as usize);
        }
        assert_eq!(madvise([0, PAGE, MADV_WILLNEED, 0, 0, 0]), -(ENOMEM as i64));
    }

    #[test]
    fn dontneed_discards_one_guest_page_and_leaves_the_rest() {
        let bytes = 3 * PAGE as usize;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        let raw = ptr as u64;
        let start = (raw + PAGE - 1) & !(PAGE - 1);
        assert!(start + PAGE <= raw + bytes as u64);
        let slice = |at, n| unsafe { std::slice::from_raw_parts(at as *const u8, n) };
        let fill = |at, n| unsafe { std::ptr::write_bytes(at as *mut u8, 0x5a, n) };
        fill(start, PAGE as usize);
        assert_eq!(
            madvise([start, GUEST_PAGE, MADV_DONTNEED, 0, 0, 0]),
            0,
            "a 4 KiB discard at a 16 KiB boundary"
        );
        assert!(slice(start, GUEST_PAGE as usize).iter().all(|b| *b == 0));
        assert!(
            slice(start + GUEST_PAGE, (PAGE - GUEST_PAGE) as usize)
                .iter()
                .all(|b| *b == 0x5a),
            "the other slices of the host page stay"
        );
        fill(start, PAGE as usize);
        assert_eq!(
            madvise([start + GUEST_PAGE, GUEST_PAGE, MADV_DONTNEED, 0, 0, 0]),
            0,
            "a 4 KiB-aligned address is a valid guest page"
        );
        assert!(slice(start, GUEST_PAGE as usize).iter().all(|b| *b == 0x5a));
        assert!(
            slice(start + GUEST_PAGE, GUEST_PAGE as usize)
                .iter()
                .all(|b| *b == 0)
        );
        assert!(
            slice(start + 2 * GUEST_PAGE, (PAGE - 2 * GUEST_PAGE) as usize)
                .iter()
                .all(|b| *b == 0x5a)
        );
        unsafe { libc::munmap(ptr, bytes) };
    }

    /// Bionic's CFI shadow update. One 4 KiB page, flags
    /// `MREMAP_MAYMOVE|MREMAP_FIXED`, destination 4 KiB-aligned and not
    /// 16 KiB-aligned. The slice moves. The other slices of both host pages
    /// stay. The host page is writable because a neighbor is, and it is not
    /// executable.
    #[test]
    fn fixed_mremap_moves_one_guest_page() {
        let map = || -> (u64, u64) {
            // Two host pages, so one of them starts on a 16 KiB boundary
            // when the kernel's own page is 4 KiB.
            let len = 2 * PAGE as usize;
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            assert_ne!(ptr, libc::MAP_FAILED);
            let raw = ptr as u64;
            let start = (raw + PAGE - 1) & !(PAGE - 1);
            assert!(start + PAGE <= raw + len as u64);
            (raw, start)
        };
        let (src_raw, src) = map();
        let (dst_raw, dst_base) = map();
        let dst = dst_base + 0x1000;
        assert_eq!(src & (PAGE - 1), 0);
        assert_eq!(dst & (GUEST_PAGE - 1), 0);
        assert_ne!(dst & (PAGE - 1), 0);
        unsafe {
            std::ptr::write_bytes(src as *mut u8, 0x5a, 0x1000);
            std::ptr::write_bytes((src + 0x1000) as *mut u8, 0x11, 0x1000);
            std::ptr::write_bytes(dst_base as *mut u8, 0x22, 0x1000);
            std::ptr::write_bytes(dst as *mut u8, 0x33, 0x1000);
            std::ptr::write_bytes((dst + 0x1000) as *mut u8, 0x44, 0x1000);
        }
        let rx = (libc::PROT_READ | libc::PROT_EXEC) as u64;
        assert_eq!(mprotect([src, 0x1000, rx, 0, 0, 0]), 0);
        let flags = super::MREMAP_MAYMOVE | super::MREMAP_FIXED;
        let moved = mremap([src, 0x1000, 0x1000, flags, dst, 0]);
        assert_eq!(moved, dst as i64);
        unsafe {
            assert_eq!(*(dst as *const u8), 0x5a);
            assert_eq!(*((dst + 16) as *const u8), 0x5a);
            assert_eq!(*((src + 0x1000) as *const u8), 0x11);
            assert_eq!(*(dst_base as *const u8), 0x22);
            assert_eq!(*((dst + 0x1000) as *const u8), 0x44);
        }
        let prot = super::page_prot(dst).expect("dest host page");
        assert_eq!(
            prot & (libc::PROT_WRITE | libc::PROT_EXEC) as u32,
            libc::PROT_WRITE as u32,
            "host prot {prot:#x}"
        );
        assert_eq!(
            mremap([src, 0x1000, 0x1000, flags, dst + 0x2000, 0]),
            -(libc::EFAULT as i64)
        );
        assert_eq!(
            mremap([
                dst_base,
                0x2000,
                0x2000,
                flags,
                dst_base + 0x1000,
                0
            ]),
            -(libc::EINVAL as i64)
        );
        assert_eq!(
            mremap([
                src + 0x1000,
                0x1000,
                0x1000,
                super::MREMAP_FIXED,
                dst + 0x2000,
                0
            ]),
            -(libc::EINVAL as i64)
        );
        unsafe {
            libc::munmap(src_raw as *mut _, 2 * PAGE as usize);
            libc::munmap(dst_raw as *mut _, 2 * PAGE as usize);
        }

        // The shadow page is read-only, and the slice being published is
        // read-only. Writing the bytes must not leave that host page
        // writable.
        let (ro_src_raw, ro_src) = map();
        let (ro_dst_raw, ro_base) = map();
        let ro = ro_base + 0x1000;
        unsafe {
            std::ptr::write_bytes(ro_src as *mut u8, 0xab, 0x1000);
            std::ptr::write_bytes((ro_src + 0x1000) as *mut u8, 0xcd, 0x1000);
            std::ptr::write_bytes(ro_base as *mut u8, 0x21, 0x1000);
            std::ptr::write_bytes((ro + 0x1000) as *mut u8, 0x43, 0x1000);
        }
        let read = libc::PROT_READ as u64;
        assert_eq!(mprotect([ro_src, PAGE, read, 0, 0, 0]), 0);
        assert_eq!(mprotect([ro_base, PAGE, read, 0, 0, 0]), 0);
        assert_eq!(
            mremap([ro_src, 0x1000, 0x1000, flags, ro, 0]),
            ro as i64
        );
        unsafe {
            assert_eq!(*(ro as *const u8), 0xab);
            assert_eq!(*(ro_base as *const u8), 0x21);
            assert_eq!(*((ro + 0x1000) as *const u8), 0x43);
            assert_eq!(*((ro_src + 0x1000) as *const u8), 0xcd);
        }
        let prot = super::page_prot(ro).expect("read-only dest host page");
        assert_eq!(
            prot & (libc::PROT_WRITE | libc::PROT_EXEC) as u32,
            0,
            "read-only shadow stayed writable: host prot {prot:#x}"
        );
        unsafe {
            libc::munmap(ro_src_raw as *mut _, 2 * PAGE as usize);
            libc::munmap(ro_dst_raw as *mut _, 2 * PAGE as usize);
        }
    }
}

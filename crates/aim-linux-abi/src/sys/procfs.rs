//! `/proc` and `/sys`, synthesized from Darwin state (after FreeBSD's
//! linprocfs/linsysfs, BSD-2-Clause).
//!
//! - Files are generated when opened and handed to the guest as an unlinked
//!   temporary file, so reads, seeks and fstat behave like a regular file.
//!   `/proc/mounts` and `mountinfo` are that file plus `mounts_poll`: always
//!   readable, and `POLLERR|POLLPRI` for one observation after this
//!   process's mount table changes. A later read shows the table then.
//! - Directories are directory streams with fixed entries (see `dir`).
//! - Values init wrote under `<runtime>/kernfs/...`
//!   (`docs/guest-init-contract.md` section 7) take precedence over the
//!   synthesized ones and may be rewritten by the guest, but for sysfs's
//!   device trees, which hold only the modeled devices (`device_tree`).
//! - `/proc/<pid>` for another process is read from Darwin's process info,
//!   the process's record (`procrec`: threads, names, tracers, command
//!   line) and its agent (`ptrace`: memory maps and fds).

use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use super::dir::{self, DirStream, Entry};
use super::fdtab::{self, Kind};
use super::vmmap;
use crate::errno::{self, EACCES, ENOENT, Errno};
use crate::vfs::{self, Area};

/// What a synthesized path is.
pub enum Node {
    File(Vec<u8>),
    NetTable(String),
    Mem(i32),
    MountTable {
        host_pid: i32,
        info: bool,
        /// `None` is the thread-group leader (`/proc/self/mounts`).
        thread: Option<i32>,
    },
    Dir(Vec<Entry>),
    Link(String),
    /// Another process's node the caller may not read
    /// (PTRACE_MODE_READ_FSCREDS): with the mode `stat` shows, else
    /// refused at lookup (`proc_fd_permission` on the `fd` directory).
    Denied(Option<u32>),
}

/// The main thread's stack and argument areas, recorded by the loader.
#[derive(Clone, Copy, Default)]
pub struct StackInfo {
    pub lo: u64,
    pub hi: u64,
    pub start_stack: u64,
    pub args: (u64, u64),
    pub env: (u64, u64),
}

/// The current program's; replaced when the process execs in place.
static STACK: RwLock<Option<StackInfo>> = RwLock::new(None);

/// Note the program's stack and make the process's record of it
/// (`procrec`).
pub fn note_stack(s: StackInfo) {
    *STACK.write().unwrap_or_else(|e| e.into_inner()) = Some(s);
    super::procrec::init(&s);
}

fn stack() -> Option<StackInfo> {
    *STACK.read().unwrap_or_else(|e| e.into_inner())
}

/// Fork: the main thread's stack areas (the child's memory has them at
/// the same addresses).
/// Fork, before the child is spawned: the pool stays with this process,
/// so its hidden fds go before the child inherits the fd table.
pub(super) fn fork_prepare() {
    POOL.drain();
}

pub(super) fn fork_save(w: &mut super::fork_state::Writer) {
    w.opt(stack(), |w, s| {
        for v in [
            s.lo,
            s.hi,
            s.start_stack,
            s.args.0,
            s.args.1,
            s.env.0,
            s.env.1,
        ] {
            w.u64(v);
        }
    });
}

pub(super) fn fork_restore(r: &mut super::fork_state::Reader) {
    if let Some(v) = r.opt(|r| [(); 7].map(|_| r.u64())) {
        note_stack(StackInfo {
            lo: v[0],
            hi: v[1],
            start_stack: v[2],
            args: (v[3], v[4]),
            env: (v[5], v[6]),
        });
    }
}

fn pid() -> i32 {
    super::process::getpid() as i32
}

/// Guest path of an open host fd.
pub fn fd_guest_path(fd: i32) -> Result<String, Errno> {
    if let Some(text) = mount_ns_text(fd) {
        return Ok(text);
    }
    if let Some(Kind::TracePipe(open)) = fdtab::get(fd) {
        return Ok(open.path.clone());
    }
    if let Some(guest) = fdtab::socket_path_guest(fd) {
        return Ok(guest);
    }
    if let Some(reference) = fdtab::character_reference(fd) {
        reference
            .stat(fd)
            .map_err(|error| errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)))?;
        return Ok(reference.guest);
    }
    if let Some(Kind::ProcMem(open)) = fdtab::get(fd) {
        return Ok(format!("/proc/{}/mem", open.guest_pid));
    }
    if let Some(p) = crate::xrt::original_guest_path(fd) {
        return Ok(p);
    }
    let mut buf = [0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes.
    if unsafe { crate::sys::fgetpath(fd, buf.as_mut_ptr()) } < 0 {
        return Err(errno::last());
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
    let host = PathBuf::from(String::from_utf8_lossy(&buf[..len]).into_owned());
    Ok(vfs::guest_path_of_host(&host).unwrap_or_else(|| host.display().to_string()))
}

/// Target of `/proc/self/fd/N`.
pub(super) fn fd_link(fd: i32) -> Option<String> {
    if !fdtab::visible(fd) {
        return None;
    }
    if let Some(text) = mount_ns_text(fd) {
        return Some(text);
    }
    if let Some(Kind::TracePipe(open)) = fdtab::get(fd) {
        return Some(open.path.clone());
    }
    if let Some(guest) = fdtab::socket_path_guest(fd) {
        return Some(guest);
    }
    if fdtab::character_reference(fd).is_some() {
        return fd_guest_path(fd).ok();
    }
    if let Some((inode, _)) = super::net::proc_socket_identity(fd) {
        return Some(format!("socket:[{inode}]"));
    }
    if let Some(n) = fdtab::anon_name(fd) {
        return Some(n);
    }
    // A synthesized /proc or /sys directory: its host fd is the root.
    if let Some(p) = super::dir::synthesized_path(fd) {
        return Some(p);
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat into a local buffer.
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return None;
    }
    if let Some(n) = super::memfd::fd_link(fd, &st) {
        return Some(n);
    }
    if let Some(n) = super::ashmem::link_name(&st) {
        return Some(n);
    }
    if let Some(n) = super::dma_heap::link_name(fd, &st) {
        return Some(n);
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFSOCK => return Some(format!("socket:[{}]", st.st_ino)),
        libc::S_IFIFO => return Some(format!("pipe:[{}]", st.st_ino)),
        _ => {}
    }
    let path = fd_guest_path(fd).ok()?;
    super::tmpfile::fd_link(&path, &st).or(Some(path))
}

// ---- process information ---------------------------------------------------

fn task_info(pid: i32) -> Option<crate::hostlibc::proc_taskallinfo> {
    let mut t: crate::hostlibc::proc_taskallinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<crate::hostlibc::proc_taskallinfo>() as i32;
    // SAFETY: proc_pidinfo writes at most `size` bytes.
    let n = unsafe {
        crate::hostlibc::proc_pidinfo(
            pid,
            crate::hostlibc::PROC_PIDTASKALLINFO,
            0,
            (&mut t as *mut crate::hostlibc::proc_taskallinfo).cast(),
            size,
        )
    };
    (n == size).then_some(t)
}

/// argv of a host process running `linux-run`, without its own options.
fn host_argv(pid: i32) -> Vec<Vec<u8>> {
    let mut mib = [crate::hostlibc::CTL_KERN, crate::hostlibc::KERN_PROCARGS2, pid];
    let mut buf = vec![0u8; 256 << 10];
    let mut len = buf.len();
    // SAFETY: sysctl into our buffer.
    if unsafe {
        crate::hostlibc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } < 0
        || len < 4
    {
        return Vec::new();
    }
    let argc = i32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    let mut rest = &buf[4..len];
    // exec path, then NUL padding, then argv.
    let skip = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    rest = &rest[skip..];
    let start = rest.iter().position(|&c| c != 0).unwrap_or(rest.len());
    rest = &rest[start..];
    let argv: Vec<Vec<u8>> = rest
        .split(|&c| c == 0)
        .take(argc)
        .map(<[u8]>::to_vec)
        .collect();
    guest_argv(argv)
}

/// A `linux-run` command line's guest program and arguments, after its
/// own options (`src/bin/linux-run.rs`); any other argv as it is.
fn guest_argv(argv: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    if !argv.first().is_some_and(|a| a.ends_with(b"linux-run")) {
        return argv;
    }
    let mut i = 1;
    while i < argv.len() && argv[i].starts_with(b"--") {
        let takes_value = !matches!(
            &argv[i][..],
            b"--trace" | b"--inherit-env" | b"--stdio-null" | b"--no-cache"
        );
        i += if takes_value { 2 } else { 1 };
    }
    argv[i.min(argv.len())..].to_vec()
}

fn read_guest(lo: u64, hi: u64) -> Vec<u8> {
    let mut v = vec![0u8; hi.saturating_sub(lo) as usize];
    let mut got = 0u64;
    // SAFETY: a fault-safe copy from our own task.
    unsafe {
        mach_vm_read_overwrite(
            mach_task_self_,
            lo,
            v.len() as u64,
            v.as_mut_ptr() as u64,
            &mut got,
        )
    };
    v.truncate(got as usize);
    v
}

unsafe extern "C" {
    static mach_task_self_: crate::mach_port_t;
    fn mach_vm_read_overwrite(t: crate::mach_port_t, a: u64, s: u64, d: u64, o: *mut u64) -> i32;
}

/// A command line as Linux's `get_mm_cmdline` reads it from the memory
/// `read` reads: the argument area `args`; or, when its last byte is no
/// longer NUL (setproctitle(3) wrote past argv, into the environment area
/// `env` if that follows), the title from the start up to its first NUL,
/// within the two areas and a page.
pub(super) fn linux_cmdline(
    args: (u64, u64),
    env: (u64, u64),
    read: impl Fn(u64, u64) -> Vec<u8>,
) -> Vec<u8> {
    let (lo, hi) = args;
    if hi <= lo || read(hi - 1, hi).first().is_none_or(|&c| c == 0) {
        return read(lo, hi);
    }
    let end = if env.0 == hi && env.1 >= env.0 {
        env.1
    } else {
        hi
    };
    let mut title = read(lo, end.min(lo + super::mem::PAGE));
    if let Some(n) = title.iter().position(|&c| c == 0) {
        title.truncate(n + 1);
    }
    title
}

fn cmdline(p: i32) -> Vec<u8> {
    if p == pid()
        && let Some(s) = stack()
    {
        return linux_cmdline(s.args, s.env, read_guest);
    }
    if let Some(c) = super::procrec::cmdline(p) {
        return c;
    }
    let mut out = Vec::new();
    for a in host_argv(p) {
        out.extend_from_slice(&a);
        out.push(0);
    }
    out
}

/// This process's `comm`.
pub(super) fn own_comm() -> String {
    comm(pid())
}

/// The `comm` of process `p`: its main thread's.
fn comm(p: i32) -> String {
    if let Some(n) = thread_comm(p, p) {
        return n;
    }
    let argv0 = if p == pid() {
        super::process::exe_guest_path()
    } else {
        host_argv(p)
            .first()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .unwrap_or_default()
    };
    let base = argv0.rsplit('/').next().unwrap_or("").to_string();
    base.chars().take(15).collect()
}

/// When the host booted on the wall clock (CLOCK_REALTIME minus
/// CLOCK_BOOTTIME), as (seconds, microseconds).
fn boot_time() -> (i64, i64) {
    use super::clock::Base;
    let ns = Base::Realtime.now() - Base::Boottime.now();
    (
        (ns / 1_000_000_000) as i64,
        (ns % 1_000_000_000 / 1000) as i64,
    )
}

fn now() -> f64 {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: local timeval.
    unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
    tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6
}

fn ncpu() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

const TICKS: u64 = 100;

/// `PROC_PIDTHREADID64INFO` (sys/proc_info.h): a thread by its host id.
const PROC_PIDTHREADID64INFO: i32 = 15;

/// User and system CPU time of thread `tid` of process `p`, in
/// nanoseconds, and its state, from its host thread.
fn thread_times(p: i32, tid: i32) -> Option<(u64, u64, char)> {
    let host = if p == pid() {
        super::thread::host_thread_id(tid)?
    } else {
        super::procrec::threads(p)?
            .into_iter()
            .find(|t| t.tid == tid)?
            .host
    };
    let mut ti: crate::hostlibc::proc_threadinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<crate::hostlibc::proc_threadinfo>() as i32;
    // SAFETY: proc_pidinfo writes at most `size` bytes.
    let n = unsafe {
        crate::hostlibc::proc_pidinfo(
            p,
            PROC_PIDTHREADID64INFO,
            host,
            (&mut ti as *mut crate::hostlibc::proc_threadinfo).cast(),
            size,
        )
    };
    if n != size {
        return Some((0, 0, 'S'));
    }
    // TH_STATE_* (mach/thread_info.h).
    let state = match ti.pth_run_state {
        1 => 'R',
        2 => 'T',
        4 => 'D',
        _ => 'S',
    };
    Some((ti.pth_user_time, ti.pth_system_time, state))
}

/// `/proc/<p>/stat`, or with `thread` its thread's
/// `/proc/<p>/task/<tid>/stat`: the thread's id, `comm`, state and CPU
/// times.
fn stat_line(p: i32, thread: Option<i32>) -> Option<String> {
    let t = task_info(p)?;
    let b = &t.pbsd;
    let ti = &t.ptinfo;
    let state = match b.pbi_status {
        2 => 'R',
        4 => 'T',
        5 => 'Z',
        _ => 'S',
    };
    let (boot, _) = boot_time();
    let start = (b.pbi_start_tvsec as i64 - boot).max(0) as u64 * TICKS
        + b.pbi_start_tvusec as u64 * TICKS / 1_000_000;
    let ns_to_ticks = |ns: u64| ns / (1_000_000_000 / TICKS);
    let s = if p == pid() {
        stack().unwrap_or_default()
    } else {
        StackInfo::default()
    };
    let rss_pages = ti.pti_resident_size / super::mem::PAGE;
    let (id, name, user, system, state) = match thread {
        Some(tid) => {
            let (user, system, state) = thread_times(p, tid).unwrap_or((0, 0, state));
            let name = thread_comm(p, tid).unwrap_or_else(|| comm(p));
            (tid, name, user, system, state)
        }
        None => (p, comm(p), ti.pti_total_user, ti.pti_total_system, state),
    };
    let id = super::pidns::guest_pid(id).ok()?;
    Some(format!(
        "{id} ({name}) {state} {} {} {} 0 -1 4194560 {} 0 {} 0 {} {} 0 0 20 {} {} 0 {start} {} {rss_pages} 18446744073709551615 0 0 {} 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 {} {} {} {} 0\n",
        super::process::linux_ppid(b.pbi_ppid as i32),
        super::pidns::id_in_ns(b.pbi_pgid as i32),
        super::pidns::id_in_ns(unsafe { libc::getsid(p) }),
        ti.pti_faults,
        ti.pti_pageins,
        ns_to_ticks(user),
        ns_to_ticks(system),
        b.pbi_nice,
        if p == pid() {
            tids(p).len() as i32
        } else {
            ti.pti_threadnum
        },
        vm(p, ti.pti_virtual_size)[0],
        s.start_stack,
        s.args.0,
        s.args.1,
        s.env.0,
        s.env.1,
    ))
}

/// The credential lines of `/proc/<p>/status`, from the process's
/// identity (another's from the process table).
fn cred_lines(p: i32) -> String {
    super::cred::proc_status(p)
}

/// Process `p`'s `total_vm`, `data_vm` and `hiwater_vm` in bytes, as the
/// layer counts its mappings; `host` for all three without a record.
fn vm(p: i32, host: u64) -> [u64; 3] {
    super::procrec::vm_of(p).unwrap_or([host; 3])
}

/// `/proc/<p>/status`, or with `thread` its thread's: the thread's `comm`
/// and id.
fn status(p: i32, thread: Option<i32>) -> Option<String> {
    let t = task_info(p)?;
    let state = match t.pbsd.pbi_status {
        2 => "R (running)",
        4 => "T (stopped)",
        5 => "Z (zombie)",
        _ => "S (sleeping)",
    };
    let kb = |b: u64| b / 1024;
    let n = ncpu();
    let guest_tgid = super::pidns::guest_pid(super::procrec::tgid(p)).ok()?;
    // task_mem: the guest's own mappings (Darwin's virtual size counts the
    // whole address space it reserved), Darwin's without a record.
    let [total, data, peak] = vm(p, t.ptinfo.pti_virtual_size);
    Some(format!(
        "Name:\t{}\nUmask:\t0022\nState:\t{state}\nTgid:\t{guest_tgid}\nNgid:\t0\nPid:\t{}\nPPid:\t{}\nTracerPid:\t{}\n\
         {}FDSize:\t256\n\
         VmPeak:\t{} kB\nVmSize:\t{} kB\nVmLck:\t0 kB\nVmPin:\t0 kB\nVmHWM:\t{} kB\nVmRSS:\t{} kB\n\
         RssAnon:\t{} kB\nRssFile:\t0 kB\nRssShmem:\t0 kB\nVmData:\t{} kB\nVmStk:\t8192 kB\nVmExe:\t0 kB\n\
         VmLib:\t0 kB\nVmPTE:\t0 kB\nVmSwap:\t0 kB\nThreads:\t{}\nSigQ:\t0/0\nSigPnd:\t0000000000000000\n\
         ShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\n\
         SigCgt:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\n\
         Cpus_allowed:\t{:x}\nCpus_allowed_list:\t0-{}\nvoluntary_ctxt_switches:\t{}\nnonvoluntary_ctxt_switches:\t0\n",
        thread
            .and_then(|tid| thread_comm(p, tid))
            .unwrap_or_else(|| comm(p)),
        super::pidns::guest_pid(thread.unwrap_or(p)).ok()?,
        super::process::linux_ppid(t.pbsd.pbi_ppid as i32),
        super::pidns::guest_pid(tracer(p, thread.unwrap_or(p))).ok()?,
        cred_lines(p),
        kb(peak),
        kb(total),
        kb(t.ptinfo.pti_resident_size),
        kb(t.ptinfo.pti_resident_size),
        kb(t.ptinfo.pti_resident_size),
        kb(data),
        if p == pid() {
            tids(p).len() as i32
        } else {
            t.ptinfo.pti_threadnum
        },
        (1u64 << n) - 1,
        n - 1,
        t.ptinfo.pti_csw,
    ))
}

/// The tracer of thread `tid` of process `p`, or 0.
fn tracer(p: i32, tid: i32) -> i32 {
    if p == pid() {
        return super::ptrace::tracer_of(tid);
    }
    super::procrec::threads(p)
        .and_then(|v| v.into_iter().find(|t| t.tid == tid))
        .map_or(0, |t| t.tracer)
}

/// In pages of the guest's page size (`AT_PAGESZ`), as `rss` in `stat`.
fn statm(p: i32) -> Option<String> {
    let t = task_info(p)?;
    let pg = |b: u64| b / super::mem::PAGE;
    Some(format!(
        "{} {} 0 0 0 {} 0\n",
        pg(t.ptinfo.pti_virtual_size),
        pg(t.ptinfo.pti_resident_size),
        pg(t.ptinfo.pti_resident_size)
    ))
}

/// A mapping as `maps` and `smaps` show it.
pub(super) struct Vma {
    pub region: vmmap::Region,
    /// Its `maps` line, with the newline.
    pub line: String,
    /// Its name in the line, if any.
    pub name: String,
    /// Mapped from a file of the guest.
    pub file: bool,
    /// A memfd's memory.
    pub shmem: bool,
}

/// Linux-format `/proc/self/maps` from the VM map.
pub(super) fn maps() -> String {
    vmas().into_iter().map(|v| v.line).collect()
}

/// This process's mappings, from the VM map.
pub(super) fn vmas() -> Vec<Vma> {
    vmas_in(0, u64::MAX)
}

/// This process's mappings in `[lo, hi)`, cut to it.
pub(super) fn vmas_in(lo: u64, hi: u64) -> Vec<Vma> {
    let paths = vfs::HostPathView::capture();
    let stack = stack().unwrap_or_default();
    let mut out = Vec::new();
    let mut regions = vmmap::regions(lo, hi).peekable();
    while let Some(mut r) = regions.next() {
        // The string pages are the top of the stack, mapped from the
        // process record (`procrec`): one `[stack]` with the rest.
        if super::procrec::is_strings(r.start) {
            r.shared = false;
            r.file = None;
        }
        while let Some(n) = regions.next_if(|n| {
            n.start == r.end && n.prot == r.prot && super::procrec::is_strings(n.start)
        }) {
            r.end = n.end;
            r.usage.merge(&n.usage);
        }
        let prot = r.prot;
        let perms = format!(
            "{}{}{}{}",
            if prot & 1 != 0 { 'r' } else { '-' },
            if prot & 2 != 0 { 'w' } else { '-' },
            if prot & 4 != 0 { 'x' } else { '-' },
            if r.shared { 's' } else { 'p' }
        );
        let (mut offset, mut dev, mut ino, mut name) = (0u64, 0u64, 0u64, String::new());
        // A host file outside the guest's view (linux-run, dyld, host
        // libraries, the process record) reads as anonymous memory: its
        // path is the Mac's, not a file of the guest.
        let shmem_file = r.file.as_ref().and_then(|(path, d, i)| {
            super::memfd::link_name(path, *d, *i).or_else(|| super::ashmem::map_name(*d, *i))
        });
        let mut shmem = shmem_file.is_some();
        let guest_file = r.file.as_ref().and_then(|(path, d, i)| {
            shmem_file
                .or_else(|| crate::xrt::original_guest_path_of_host(path))
                .or_else(|| paths.as_ref().and_then(|view| view.guest_path(path)))
                .map(|n| (n, *d, *i))
        });
        if let Some((n, d, i)) = guest_file {
            // A fork child's copy of a private file mapping reports
            // offset 0 (`copies`).
            offset = super::copies::find(r.start).map_or(r.offset, |(_, off)| off);
            dev = d;
            ino = i;
            name = n;
        } else if super::copies::covered(r.start, r.end)
            .iter()
            .any(|(_, _, copy)| copy.is_some())
        {
            // The Darwin entry can run from the file bytes into the
            // anonymous `.bss`. Only the recorded file extent is a file.
            // The rest can take `PR_SET_VMA_ANON_NAME`.
            push_copy_split(&mut out, &r, &perms);
            continue;
        } else if r.start < stack.hi && stack.lo < r.end && prot != 0 {
            name = "[stack]".into();
        } else if let Some(n) = crate::vdso::name_of(r.start) {
            name = n.into();
        } else if let Some(n) = super::memfd::anon_name(r.start) {
            name = n;
            shmem = true;
        }
        let line = |r: &vmmap::Region, name: &str| {
            let mut line = format!(
                "{:08x}-{:08x} {perms} {offset:08x} {:02x}:{:02x} {ino}",
                r.start,
                r.end,
                (dev >> 24) & 0xff,
                dev & 0xff_ffff
            );
            if !name.is_empty() {
                push_name(&mut line, name);
            }
            line.push('\n');
            line
        };
        // `get_vma_name`: an anonymous mapping that is no stack or vDSO
        // shows its name, and Linux's VMAs end where the name changes.
        let pieces = if name.is_empty() && !shmem {
            super::vma_names::pieces(r.start, r.end)
        } else {
            Vec::new()
        };
        if pieces.iter().all(|(_, _, n)| n.is_none()) {
            out.push(Vma {
                line: line(&r, &name),
                region: r,
                name,
                file: ino != 0,
                shmem,
            });
            continue;
        }
        let pages = (r.end - r.start) / super::mem::PAGE;
        for (start, end, n) in pieces {
            let piece = vmmap::Region {
                start,
                end,
                prot: r.prot,
                shared: r.shared,
                offset: r.offset,
                file: r.file.clone(),
                usage: r.usage.share((end - start) / super::mem::PAGE, pages),
            };
            let name = match n {
                Some(n) if r.shared => format!("[anon_shmem:{n}]"),
                Some(n) => format!("[anon:{n}]"),
                None => String::new(),
            };
            out.push(Vma {
                line: line(&piece, &name),
                region: piece,
                name,
                file: false,
                shmem: false,
            });
        }
    }
    out
}

/// One Darwin entry that holds both a copied file and anonymous bytes.
fn push_copy_split(out: &mut Vec<Vma>, r: &vmmap::Region, perms: &str) {
    let pages = (r.end - r.start) / super::mem::PAGE;
    let share = |start: u64, end: u64| r.usage.share((end - start) / super::mem::PAGE, pages);
    let line_of = |start: u64, end: u64, offset: u64, dev: u64, ino: u64, name: &str| {
        let mut line = format!(
            "{start:08x}-{end:08x} {perms} {offset:08x} {:02x}:{:02x} {ino}",
            (dev >> 24) & 0xff,
            dev & 0xff_ffff
        );
        if !name.is_empty() {
            push_name(&mut line, name);
        }
        line.push('\n');
        line
    };
    for (start, end, copy) in super::copies::covered(r.start, r.end) {
        if let Some((c, offset)) = copy {
            let piece = vmmap::Region {
                start,
                end,
                prot: r.prot,
                shared: r.shared,
                offset,
                file: None,
                usage: share(start, end),
            };
            out.push(Vma {
                line: line_of(start, end, offset, c.dev, c.ino, &c.guest),
                region: piece,
                name: c.guest,
                file: c.ino != 0,
                shmem: false,
            });
            continue;
        }
        let named = super::vma_names::pieces(start, end);
        let anon = |start: u64, end: u64| vmmap::Region {
            start,
            end,
            prot: r.prot,
            shared: r.shared,
            offset: 0,
            file: None,
            usage: share(start, end),
        };
        if named.iter().all(|(_, _, n)| n.is_none()) {
            out.push(Vma {
                line: line_of(start, end, 0, 0, 0, ""),
                region: anon(start, end),
                name: String::new(),
                file: false,
                shmem: false,
            });
            continue;
        }
        for (start, end, n) in named {
            let name = match n {
                Some(n) if r.shared => format!("[anon_shmem:{n}]"),
                Some(n) => format!("[anon:{n}]"),
                None => String::new(),
            };
            out.push(Vma {
                line: line_of(start, end, 0, 0, 0, &name),
                region: anon(start, end),
                name,
                file: false,
                shmem: false,
            });
        }
    }
}

/// A mapping's name after its `maps` line, from column 73 on.
pub(super) fn push_name(line: &mut String, name: &str) {
    line.push_str(&" ".repeat(73usize.saturating_sub(line.len()).max(1)));
    line.push_str(name);
}

fn sysctl_u64(name: &str) -> u64 {
    let c = CString::new(name).unwrap();
    let mut v = 0u64;
    let mut len = 8usize;
    // SAFETY: sysctlbyname into a u64.
    unsafe {
        crate::hostlibc::sysctlbyname(
            c.as_ptr(),
            (&mut v as *mut u64).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    v
}

fn sysctl_string(name: &str) -> String {
    let c = CString::new(name).unwrap();
    let mut buf = [0u8; 256];
    let mut len = buf.len();
    // SAFETY: sysctlbyname into our buffer.
    unsafe {
        crate::hostlibc::sysctlbyname(
            c.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    String::from_utf8_lossy(&buf[..len.min(buf.len())])
        .trim_end_matches('\0')
        .to_string()
}

unsafe extern "C" {
    fn mach_host_self() -> u32;
    fn host_statistics64(host: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
    fn host_processor_info(
        host: u32,
        flavor: i32,
        count: *mut u32,
        info: *mut *mut i32,
        n: *mut u32,
    ) -> i32;
    fn mach_vm_deallocate(t: crate::mach_port_t, a: u64, s: u64) -> i32;
}

fn meminfo() -> String {
    let total = sysctl_u64("hw.memsize");
    let page = 16384u64;
    // vm_statistics64: free, active, inactive, wire, ... (natural_t counts).
    let mut v = [0i32; 64];
    let mut count = 38u32;
    // SAFETY: HOST_VM_INFO64 (4) into a large enough buffer.
    unsafe { host_statistics64(mach_host_self(), 4, v.as_mut_ptr(), &mut count) };
    let pages = |i: usize| v[i] as u32 as u64 * page / 1024;
    let (free, active, inactive, wired) = (pages(0), pages(1), pages(2), pages(3));
    // external_page_count (file-backed) is word 34 of vm_statistics64.
    let cached = pages(34);
    let avail = aim_host_memory::available() / 1024;
    let kb = total / 1024;
    format!(
        "MemTotal:       {kb:>8} kB\nMemFree:        {free:>8} kB\nMemAvailable:   {avail:>8} kB\n\
         Buffers:               0 kB\nCached:         {cached:>8} kB\nSwapCached:            0 kB\n\
         Active:         {active:>8} kB\nInactive:       {inactive:>8} kB\nUnevictable:    {wired:>8} kB\n\
         Mlocked:               0 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n\
         Dirty:                 0 kB\nWriteback:             0 kB\nAnonPages:      {active:>8} kB\n\
         Mapped:         {cached:>8} kB\nShmem:                 0 kB\nSlab:                  0 kB\n\
         SReclaimable:          0 kB\nSUnreclaim:            0 kB\nKernelStack:           0 kB\n\
         PageTables:            0 kB\nCommitLimit:    {kb:>8} kB\nCommitted_AS:   {:>8} kB\n\
         VmallocTotal:   {:>8} kB\nVmallocUsed:           0 kB\nVmallocChunk:          0 kB\n",
        kb - free,
        1u64 << 37,
    )
}

const HWCAP_NAMES: [&str; 32] = [
    "fp", "asimd", "evtstrm", "aes", "pmull", "sha1", "sha2", "crc32", "atomics", "fphp",
    "asimdhp", "cpuid", "asimdrdm", "jscvt", "fcma", "lrcpc", "dcpop", "sha3", "sm3", "sm4",
    "asimddp", "sha512", "sve", "asimdfhm", "dit", "uscat", "ilrcpc", "flagm", "ssbs", "sb",
    "paca", "pacg",
];
const HWCAP2_NAMES: [&str; 38] = [
    "dcpodp",
    "sve2",
    "sveaes",
    "svepmull",
    "svebitperm",
    "svesha3",
    "svesm4",
    "flagm2",
    "frint",
    "svei8mm",
    "svef32mm",
    "svef64mm",
    "svebf16",
    "i8mm",
    "bf16",
    "dgh",
    "rng",
    "bti",
    "mte",
    "ecv",
    "afp",
    "rpres",
    "mte3",
    "sme",
    "smei16i64",
    "smef64f64",
    "smei8i32",
    "smef16f32",
    "smeb16f32",
    "smef32f32",
    "smefa64",
    "wfxt",
    "ebf16",
    "sveebf16",
    "cssc",
    "rprfm",
    "sve2p1",
    "sme2",
];

fn cpuinfo() -> String {
    let (h, h2) = crate::hwcap::host_hwcaps();
    let mut feats: Vec<&str> = (0..32)
        .filter(|b| h & (1 << b) != 0)
        .map(|b| HWCAP_NAMES[b])
        .collect();
    feats.extend(
        (0..HWCAP2_NAMES.len())
            .filter(|b| h2 & (1 << b) != 0)
            .map(|b| HWCAP2_NAMES[b]),
    );
    let feats = feats.join(" ");
    let mut out = String::new();
    for i in 0..ncpu() {
        out.push_str(&format!(
            "processor\t: {i}\nBogoMIPS\t: 48.00\nFeatures\t: {feats}\nCPU implementer\t: 0x61\n\
             CPU architecture: 8\nCPU variant\t: 0x0\nCPU part\t: 0x000\nCPU revision\t: 0\n\n"
        ));
    }
    out
}

fn proc_stat() -> String {
    let mut n = 0u32;
    let mut info: *mut i32 = std::ptr::null_mut();
    let mut cnt = 0u32;
    // SAFETY: PROCESSOR_CPU_LOAD_INFO (2): per-CPU [user, system, idle, nice]
    // tick counts in a vm_allocated array we release below.
    let ok = unsafe { host_processor_info(mach_host_self(), 2, &mut n, &mut info, &mut cnt) } == 0;
    let mut cpus = Vec::new();
    if ok {
        for i in 0..n as usize {
            // SAFETY: n entries of 4 ints.
            let t = unsafe { std::slice::from_raw_parts(info.add(i * 4), 4) };
            cpus.push([
                t[0] as u32 as u64,
                t[3] as u32 as u64,
                t[1] as u32 as u64,
                t[2] as u32 as u64,
            ]);
        }
        // SAFETY: releasing the kernel's array.
        unsafe { mach_vm_deallocate(mach_task_self_, info as u64, cnt as u64 * 4) };
    }
    let mut total = [0u64; 4];
    for c in &cpus {
        for k in 0..4 {
            total[k] += c[k];
        }
    }
    let line = |name: &str, c: &[u64; 4]| {
        format!("{name} {} {} {} {} 0 0 0 0 0 0\n", c[0], c[1], c[2], c[3])
    };
    let mut out = line("cpu ", &total);
    for (i, c) in cpus.iter().enumerate() {
        out.push_str(&line(&format!("cpu{i}"), c));
    }
    out.push_str(&format!(
        "intr 0\nctxt 0\nbtime {}\nprocesses 0\nprocs_running 1\nprocs_blocked 0\nsoftirq 0\n",
        boot_time().0
    ));
    out
}

fn uptime() -> String {
    let (s, us) = boot_time();
    let up = now() - (s as f64 + us as f64 / 1e6);
    format!("{up:.2} {:.2}\n", up * ncpu() as f64 * 0.9)
}

/// `/proc/config.gz`: the configuration of the kernel the layer plays, as
/// libvintf's `RuntimeInfo` reads it (system_server's `Debug.isVmapStack`
/// aborts when it cannot). Options the layer does not provide are absent.
const KERNEL_CONFIG: &str = "\
# Linux/arm64 6.6.0 Kernel Configuration (aim-linux-abi)
CONFIG_ARM64=y
CONFIG_64BIT=y
CONFIG_MMU=y
CONFIG_SMP=y
CONFIG_ARM64_4K_PAGES=y
CONFIG_ANDROID_BINDER_IPC=y
CONFIG_ASHMEM=y
CONFIG_MEMFD_CREATE=y
CONFIG_BPF_SYSCALL=y
CONFIG_CGROUPS=y
CONFIG_INOTIFY_USER=y
CONFIG_EPOLL=y
CONFIG_EVENTFD=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_FUTEX=y
CONFIG_POSIX_TIMERS=y
CONFIG_INPUT_EVDEV=y
CONFIG_UNIX=y
CONFIG_INET=y
CONFIG_IPV6=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_SECURITY_SELINUX=y
CONFIG_VMAP_STACK=y
";

/// `data` as a gzip file of stored (uncompressed) deflate blocks.
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    let mut chunks = data.chunks(0xffff).peekable();
    if chunks.peek().is_none() {
        out.extend([1, 0, 0, 0xff, 0xff]);
    }
    while let Some(c) = chunks.next() {
        let len = c.len() as u16;
        out.push(chunks.peek().is_none() as u8);
        out.extend(len.to_le_bytes());
        out.extend((!len).to_le_bytes());
        out.extend(c);
    }
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
    }
    out.extend((!crc).to_le_bytes());
    out.extend((data.len() as u32).to_le_bytes());
    out
}

fn loadavg() -> String {
    let mut l = [0f64; 3];
    // SAFETY: three doubles.
    unsafe { libc::getloadavg(l.as_mut_ptr(), 3) };
    format!("{:.2} {:.2} {:.2} 1/1 {}\n", l[0], l[1], l[2], pid())
}

fn uuid(bytes: [u8; 16]) -> String {
    let h: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}\n",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

fn random_uuid() -> String {
    let mut b = [0u8; 16];
    // SAFETY: local buffer.
    unsafe { libc::getentropy(b.as_mut_ptr().cast(), 16) };
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid(b)
}

fn cpu_range() -> String {
    format!("0-{}\n", ncpu() - 1)
}

/// The processes `/proc` lists: the guest's pid namespace (`pidns`), not
/// the Mac's; every host process without one.
pub(super) fn pids() -> Vec<i32> {
    let mut v = match super::pidns::members() {
        Some(mut v) => {
            v.retain(|&p| task_info(p).is_some());
            v
        }
        // SAFETY: sizing call then a buffer of that size.
        None => unsafe {
            let n = crate::hostlibc::proc_listallpids(std::ptr::null_mut(), 0);
            let mut v = vec![0i32; n.max(0) as usize + 64];
            let n = crate::hostlibc::proc_listallpids(v.as_mut_ptr().cast(), (v.len() * 4) as i32);
            v.truncate(n.max(0) as usize);
            v
        },
    };
    v = v
        .into_iter()
        .filter_map(|host| super::pidns::guest_pid(host).ok())
        .collect();
    v.retain(|&p| p > 0);
    v.sort_unstable();
    v.dedup();
    v
}

/// The tids of process `p`: its guest threads, another process's from its
/// record.
pub(super) fn tids(p: i32) -> Vec<i32> {
    let t = if p == pid() {
        let mut t = super::thread::tids();
        t.extend(super::procrec::foreign_tids());
        t
    } else {
        super::procrec::threads(p).map_or(Vec::new(), |v| v.into_iter().map(|t| t.tid).collect())
    };
    if t.is_empty() { vec![p] } else { t }
}

pub(super) fn entries(names: &[(&str, u8)]) -> Vec<Entry> {
    names
        .iter()
        .map(|(n, t)| Entry::new(1, *t, n.as_bytes()))
        .collect()
}

const PID_ENTRIES: &[(&str, u8)] = &[
    ("attr", dir::DT_DIR),
    ("cgroup", dir::DT_REG),
    ("cmdline", dir::DT_REG),
    ("mem", dir::DT_REG),
    ("comm", dir::DT_REG),
    ("cwd", dir::DT_LNK),
    ("environ", dir::DT_REG),
    ("exe", dir::DT_LNK),
    ("fd", dir::DT_DIR),
    ("net", dir::DT_DIR),
    ("maps", dir::DT_REG),
    ("mountinfo", dir::DT_REG),
    ("mounts", dir::DT_REG),
    ("oom_score_adj", dir::DT_REG),
    ("root", dir::DT_LNK),
    ("smaps", dir::DT_REG),
    ("smaps_rollup", dir::DT_REG),
    ("stat", dir::DT_REG),
    ("statm", dir::DT_REG),
    ("status", dir::DT_REG),
    ("task", dir::DT_DIR),
];

/// The persistent areas of the guest-init contract (docs/guest-init-contract.md,
/// section 2), which Android mounts from block devices; the other `rw` areas
/// are per boot, as tmpfs.
const BLOCK_MOUNTS: &[&str] = &["/data", "/metadata", "/cache"];

/// The mount table: the read-only image at `/` and the path map's areas.
/// Each is `(source, target, fstype, options)`.
fn mount_table(points: Vec<vfs::MountPoint>) -> Vec<(String, String, String, String)> {
    let blocks = block_hosts(&points);
    points
        .into_iter()
        .filter_map(|mp| mount_entry(mp, &blocks))
        .collect()
}

/// The hosts of the block areas, with their guest paths.
fn block_hosts(points: &[vfs::MountPoint]) -> Vec<(std::path::PathBuf, String)> {
    points
        .iter()
        .filter(|mp| {
            mp.area == vfs::Area::Writable
                && mp.source.is_none()
                && BLOCK_MOUNTS.contains(&mp.guest.as_str())
        })
        .map(|mp| (mp.host.clone(), mp.guest.clone()))
        .collect()
}

fn mount_entry(
    mp: vfs::MountPoint,
    blocks: &[(std::path::PathBuf, String)],
) -> Option<(String, String, String, String)> {
    let guest = mp.guest;
    // A cgroup v1 hierarchy: a `cgroup` filesystem with its controller
    // (`cgroup1_show_options`).
    if let Some(c) = mp
        .fstype
        .as_deref()
        .and_then(aim_storage::cgroup_v1::Controller::from_map_kind)
    {
        let options = format!("rw,nosuid,nodev,noexec,relatime,{}", c.mount_options());
        return Some(("none".into(), guest, "cgroup".into(), options));
    }
    // A kernel filesystem of the path map (cgroup2, bpf) or a mount the
    // process made.
    if let (Some(source), Some(fstype)) = (mp.source, mp.fstype) {
        let options = if mp.area == vfs::Area::Image {
            "ro,relatime"
        } else {
            "rw,nosuid,nodev,noexec,relatime"
        };
        return Some((source, guest, fstype, options.to_string()));
    }
    // A bind of a block area's directory (the `/data_mirror` binds of
    // `/data`) is that filesystem, as `show_vfsmnt` shows a bind mount's
    // superblock: its device, type and options.
    let block = blocks
        .iter()
        .find(|(host, _)| mp.area == vfs::Area::Writable && mp.host.starts_with(host))
        .map(|(_, block)| block.as_str());
    let (source, fstype, options) = match (mp.area, guest.as_str(), block) {
        (vfs::Area::Image, _, _) => ("/dev/root".into(), "erofs", "ro,relatime"),
        (vfs::Area::Kernfs, "/proc", _) => {
            ("proc".into(), "proc", "rw,nosuid,nodev,noexec,relatime")
        }
        (vfs::Area::Kernfs, "/sys", _) => {
            ("sysfs".into(), "sysfs", "rw,nosuid,nodev,noexec,relatime")
        }
        (vfs::Area::Writable, _, Some(block)) => (
            format!("/dev/block/by-name{block}"),
            "ext4",
            "rw,nosuid,nodev,noatime",
        ),
        (vfs::Area::Writable, _, None) => ("tmpfs".into(), "tmpfs", "rw,nosuid,relatime"),
        _ => return None,
    };
    Some((source, guest, fstype.to_string(), options.to_string()))
}

/// `/proc/<pid>/mounts`, as fstab(5) lines.
fn mounts(points: Vec<vfs::MountPoint>) -> String {
    mount_table(points)
        .into_iter()
        .map(|(source, target, fstype, options)| {
            format!("{source} {target} {fstype} {options} 0 0\n")
        })
        .collect()
}

/// The actual mount objects of the target process, including cloned IDs.
fn mountinfo(points: Vec<vfs::MountPoint>) -> String {
    use std::os::unix::fs::MetadataExt;
    let blocks = block_hosts(&points);
    points.into_iter().filter_map(|point|{
        let id=point.id;let parent=point.parent;let root=point.root.clone();
        let mut propagation=String::new();if point.shared!=0{propagation.push_str(&format!(" shared:{}",point.shared));}if point.master!=0{propagation.push_str(&format!(" master:{}",point.master));}
        let device=std::fs::metadata(&point.host).map(|stat|stat.dev()).unwrap_or(0);
        mount_entry(point, &blocks).map(|(source,target,fstype,options)|{
            let rw=options.split(',').next().unwrap_or("rw");
            format!("{id} {parent} {}:{} {root} {target} {options}{propagation} - {fstype} {source} {rw}\n",(device>>24)&0xff,device&0xffffff)
        })
    }).collect()
}

fn poll_generation(poll: &MountPoll) -> u64 {
    poll.ns
        .as_ref()
        .map(|ns| vfs::mount_namespace_event(ns))
        .unwrap_or_else(vfs::mount_event)
}

fn mount_poll_points(
    host_pid: i32,
    ns: Option<&Arc<vfs::MountNs>>,
) -> Result<Vec<vfs::MountPoint>, Errno> {
    if host_pid == pid()
        && let Some(ns) = ns
    {
        vfs::refresh_fuse_mounts()?;
        return vfs::mount_points_of(ns);
    }
    process_mount_points(host_pid)
}

fn process_mount_points(host_pid: i32) -> Result<Vec<vfs::MountPoint>, Errno> {
    if host_pid == pid() {
        vfs::refresh_fuse_mounts()?;
        return vfs::mount_points();
    }
    let table = super::cred::by_pid_dir().ok_or(errno::ESRCH)?;
    let process = aim_storage::process_namespace::ProcessIdentity::running(host_pid)
        .map_err(|error| errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)))?;
    let id = aim_storage::process_namespace::mount_namespace_of(table, process)
        .map_err(|error| errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)))?;
    vfs::namespace_mount_points(&id)
}

/// The `comm` of thread `tid` of process `p`, once it has been named.
fn thread_comm(p: i32, tid: i32) -> Option<String> {
    let n = if p == pid() {
        super::thread::name_of(tid)?
    } else {
        super::procrec::threads(p)?
            .into_iter()
            .find(|t| t.tid == tid)?
            .name
    };
    let len = n.iter().position(|&b| b == 0).unwrap_or(16);
    (len > 0).then(|| String::from_utf8_lossy(&n[..len]).into_owned())
}

const NET_FILES: [&str; 5] = ["dev", "tcp", "tcp6", "udp", "udp6"];

/// Nodes under `/proc/<p>/` (`rest` is the path after it); `thread` is the
/// tid for `/proc/<p>/task/<tid>/` (and `/proc/<tid>/`).
fn pid_node(p: i32, rest: &str, thread: Option<i32>, listed: bool) -> Option<Node> {
    let me = p == pid();
    if !me && (!super::pidns::contains(p) || task_info(p).is_none()) {
        return None;
    }
    Some(match rest {
        "" => {
            let mut e: Vec<_> = PID_ENTRIES
                .iter()
                .filter(|(n, _)| thread.is_none() || *n != "task")
                .map(|(n, t)| Entry::new(1, *t, n.as_bytes()))
                .collect();
            if me {
                e.push(Entry::new(1, dir::DT_DIR, b"ns"));
            }
            Node::Dir(e)
        }
        "ns" if me => Node::Dir(entries(&[("mnt", dir::DT_LNK)])),
        "ns/mnt" if me => Node::Link(vfs::proc_namespace_link(thread)),
        "net" => Node::Dir(
            NET_FILES
                .iter()
                .map(|name| Entry::new(1, dir::DT_REG, name.as_bytes()))
                .collect(),
        ),
        name if name.starts_with("net/") => {
            let kind = name.strip_prefix("net/")?;
            if !NET_FILES.contains(&kind) {
                return None;
            }
            Node::NetTable(kind.to_owned())
        }
        "mem" => Node::Mem(p),
        "cmdline" => Node::File(cmdline(p)),
        "cgroup" => Node::File(super::cgroup::proc_cgroup(p, thread.unwrap_or(p)).into_bytes()),
        "comm" => {
            let named = thread.and_then(|t| thread_comm(p, t));
            Node::File(format!("{}\n", named.unwrap_or_else(|| comm(p))).into_bytes())
        }
        "environ" if me => Node::File(stack().map_or(Vec::new(), |s| read_guest(s.env.0, s.env.1))),
        "stat" => Node::File(stat_line(p, thread)?.into_bytes()),
        "status" => Node::File(status(p, thread)?.into_bytes()),
        "statm" => Node::File(statm(p)?.into_bytes()),
        "maps" if me => Node::File(maps().into_bytes()),
        "maps" | "smaps" | "smaps_rollup" if !me && !super::cred::may_ptrace(p, true) => {
            Node::Denied(Some(libc::S_IFREG as u32 | 0o444))
        }
        "maps" => Node::File(super::ptrace::remote_maps(p)?.into_bytes()),
        "smaps" | "smaps_rollup" if me => {
            Node::File(super::smaps::smaps(rest == "smaps_rollup").into_bytes())
        }
        "smaps" | "smaps_rollup" => {
            Node::File(super::ptrace::remote_smaps(p, rest == "smaps_rollup")?.into_bytes())
        }
        "mounts" => Node::MountTable {
            host_pid: p,
            info: false,
            thread,
        },
        "mountinfo" => Node::MountTable {
            host_pid: p,
            info: true,
            thread,
        },
        "oom_score_adj" => {
            Node::File(format!("{}\n", super::cred::oom_score_adj_of(p).unwrap_or(0)).into_bytes())
        }
        "attr" => Node::Dir(entries(&[("current", dir::DT_REG)])),
        "attr/current" => Node::File(attr_current(p)),
        "exe" if me => Node::Link(super::process::exe_guest_path()),
        "cwd" if me => Node::Link(vfs::cwd()),
        "root" => Node::Link("/".into()),
        "fd" if me && !listed => Node::Dir(Vec::new()),
        "fd" if me => Node::Dir(
            super::fd_visibility::visible()
                .into_iter()
                .map(|fd| Entry::new(fd as u64 + 1, dir::DT_LNK, fd.to_string()))
                .collect(),
        ),
        "fd" if !super::cred::may_ptrace(p, true) => {
            Node::Denied(Some(libc::S_IFDIR as u32 | 0o500))
        }
        "fd" => Node::Dir(
            super::ptrace::remote_fds(p)?
                .into_iter()
                .map(|fd| Entry::new(fd as u64 + 1, dir::DT_LNK, fd.to_string()))
                .collect(),
        ),
        "task" if thread.is_none() => Node::Dir(
            tids(p)
                .into_iter()
                .filter_map(|t| super::pidns::guest_pid(t).ok())
                .map(|t| Entry::new(t as u64, dir::DT_DIR, t.to_string()))
                .collect(),
        ),
        _ => {
            if let Some(n) = rest.strip_prefix("fd/") {
                let fd: i32 = n.parse().ok()?;
                if !me && !super::cred::may_ptrace(p, true) {
                    return Some(Node::Denied(None));
                }
                return if me {
                    fd_link(fd)
                } else {
                    super::ptrace::remote_fd_link(p, fd)
                }
                .map(Node::Link);
            }
            let t = rest.strip_prefix("task/").filter(|_| thread.is_none())?;
            let (tid, sub) = t.split_once('/').unwrap_or((t, ""));
            let tid: i32 = tid.parse().ok()?;
            let tid = super::pidns::syscall_pid(tid).ok()?;
            if !tids(p).contains(&tid) {
                return None;
            }
            return pid_node(p, sub, Some(tid), listed);
        }
    })
}

/// The synthesized node at a normalized guest path under /proc or /sys.
pub fn node(guest: &str) -> Option<Node> {
    node_listed(guest, true)
}

/// [`node`], with the entries of `/proc` and `/proc/<pid>/fd` only when
/// `listed`: `stat` needs a directory's kind, and every path walk through
/// `/proc/self/fd/N` stats both, while listing them walks the pid
/// namespace's processes and every descriptor slot.
fn node_listed(guest: &str, listed: bool) -> Option<Node> {
    if let Some(node) = super::fuse_sysfs::node(guest) {
        return node.ok();
    }
    if let Some(rest) = guest.strip_prefix("/proc") {
        let rest = rest.trim_start_matches('/');
        let (first, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let me = pid();
        return Some(match first {
            "" => {
                let mut e = entries(&[
                    ("self", dir::DT_LNK),
                    ("thread-self", dir::DT_LNK),
                    ("config.gz", dir::DT_REG),
                    ("cpuinfo", dir::DT_REG),
                    ("filesystems", dir::DT_REG),
                    ("loadavg", dir::DT_REG),
                    ("meminfo", dir::DT_REG),
                    ("mounts", dir::DT_LNK),
                    ("net", dir::DT_LNK),
                    ("stat", dir::DT_REG),
                    ("sys", dir::DT_DIR),
                    ("uptime", dir::DT_REG),
                    ("version", dir::DT_REG),
                ]);
                if listed {
                    e.extend(
                        pids()
                            .into_iter()
                            .map(|p| Entry::new(p as u64, dir::DT_DIR, p.to_string())),
                    );
                }
                Node::Dir(e)
            }
            "self" if tail.is_empty() => Node::Link(me.to_string()),
            "mounts" if tail.is_empty() => Node::Link("self/mounts".into()),
            "net" if tail.is_empty() => Node::Link("self/net".into()),
            "net" => return pid_node(me, &format!("net/{tail}"), None, listed),
            "thread-self" if tail.is_empty() => {
                Node::Link(format!("{me}/task/{}", super::process::gettid()))
            }
            "self" => return pid_node(me, tail, None, listed),
            "thread-self" => {
                return pid_node(me, tail, Some(super::process::gettid() as i32), listed);
            }
            "config.gz" => Node::File(gzip_stored(KERNEL_CONFIG.as_bytes())),
            "cpuinfo" => Node::File(cpuinfo().into_bytes()),
            "meminfo" => Node::File(meminfo().into_bytes()),
            "stat" => Node::File(proc_stat().into_bytes()),
            "uptime" => Node::File(uptime().into_bytes()),
            "loadavg" => Node::File(loadavg().into_bytes()),
            // linux_banner: `Linux version <release> (<builder>) <version>`.
            "version" => Node::File(
                format!(
                    "Linux version {} (aim-linux-abi) {}\n",
                    super::pstate::kernel_release(),
                    super::pstate::KERNEL_VERSION
                )
                .into_bytes(),
            ),
            "filesystems" => {
                Node::File(b"nodev\tsysfs\nnodev\tproc\nnodev\ttmpfs\nnodev\tbpf\n\text4\n".to_vec())
            }
            "sys" => return sys_node(tail),
            n => {
                // `/proc/<tid>` of a thread other than a main thread: the
                // thread's view of its process, as on Linux, with the
                // process's tasks.
                let guest: i32 = n.parse().ok()?;
                let n = super::pidns::syscall_pid(guest).ok()?;
                let p = super::thread::owner(n);
                if p == n {
                    return pid_node(p, tail, None, listed);
                }
                if !tids(p).contains(&n) {
                    return None;
                }
                if tail == "task" || tail.starts_with("task/") {
                    return pid_node(p, tail, None, listed);
                }
                return pid_node(p, tail, Some(n), listed);
            }
        });
    }
    let rest = guest.strip_prefix("/sys")?.trim_start_matches('/');
    if let Some(t) = rest.strip_prefix("fs/selinux")
        && (t.is_empty() || t.starts_with('/'))
    {
        return super::selinuxfs::node(t);
    }
    if guest == "/sys/kernel/debug/tracing" {
        return Some(Node::Link("/sys/kernel/tracing".to_string()));
    }
    if let Some(tail) = super::tracefs::tail(guest) {
        return super::tracefs::node(tail);
    }
    Some(match rest {
        "" => Node::Dir(entries(&[
            ("block", dir::DT_DIR),
            ("class", dir::DT_DIR),
            ("dev", dir::DT_DIR),
            ("devices", dir::DT_DIR),
            ("fs", dir::DT_DIR),
            ("kernel", dir::DT_DIR),
        ])),
        "fs" => Node::Dir(entries(&[("bpf", dir::DT_DIR), ("selinux", dir::DT_DIR)])),
        // `sysfs_create_mount_point(fs_kobj, "bpf")`: the directory bpffs
        // is mounted on. Empty until that mount.
        "fs/bpf" => Node::Dir(entries(&[])),
        "kernel" => Node::Dir(entries(&[
            ("debug", dir::DT_DIR),
            ("tracing", dir::DT_DIR),
            ("uevent_seqnum", dir::DT_REG),
        ])),
        // `uevent_seqnum_show`.
        "kernel/uevent_seqnum" => Node::File(format!("{}\n", super::uevent::seqnum()).into_bytes()),
        "kernel/debug" => Node::Dir(entries(&[("tracing", dir::DT_DIR)])),
        "devices" => Node::Dir(entries(&[
            ("system", dir::DT_DIR),
            ("virtual", dir::DT_DIR),
        ])),
        "devices/system" => Node::Dir(entries(&[("cpu", dir::DT_DIR)])),
        "devices/system/cpu" => {
            let mut e = entries(&[
                ("kernel_max", dir::DT_REG),
                ("online", dir::DT_REG),
                ("possible", dir::DT_REG),
                ("present", dir::DT_REG),
            ]);
            e.extend((0..ncpu()).map(|i| Entry::new(1, dir::DT_DIR, format!("cpu{i}"))));
            Node::Dir(e)
        }
        "devices/system/cpu/possible"
        | "devices/system/cpu/present"
        | "devices/system/cpu/online" => Node::File(cpu_range().into_bytes()),
        "devices/system/cpu/kernel_max" => Node::File(format!("{}\n", ncpu() - 1).into_bytes()),
        _ => {
            let Some(c) = rest.strip_prefix("devices/system/cpu/cpu") else {
                return super::evdev::sys_node(rest);
            };
            let (n, tail) = c.split_once('/').unwrap_or((c, ""));
            if n.parse::<usize>().ok()? >= ncpu() {
                return None;
            }
            match tail {
                "" => Node::Dir(entries(&[("online", dir::DT_REG)])),
                "online" => Node::File(b"1\n".to_vec()),
                _ => return None,
            }
        }
    })
}

/// `/proc/sys/net/core`: the two JIT knobs NetBpfLoad writes. `None`
/// leaves the rest of `/proc/sys/net` to the IPv6 configuration.
fn net_core_node(rest: &str) -> Option<Node> {
    Some(match rest {
        "core" => Node::Dir(entries(&[
            ("bpf_jit_enable", dir::DT_REG),
            ("bpf_jit_kallsyms", dir::DT_REG),
        ])),
        "core/bpf_jit_enable" => {
            Node::File(super::sysctl::text("/proc/sys/net/core/bpf_jit_enable").ok()?)
        }
        "core/bpf_jit_kallsyms" => {
            Node::File(super::sysctl::text("/proc/sys/net/core/bpf_jit_kallsyms").ok()?)
        }
        _ => return None,
    })
}

fn sys_node(tail: &str) -> Option<Node> {
    if tail == "net" || tail.starts_with("net/") {
        let rest = tail.strip_prefix("net").unwrap().trim_start_matches('/');
        if let Some(node) = net_core_node(rest) {
            return Some(node);
        }
        return super::ipv6conf::node(rest);
    }
    Some(match tail {
        "" => Node::Dir(entries(&[
            ("fs", dir::DT_DIR),
            ("kernel", dir::DT_DIR),
            ("net", dir::DT_DIR),
            ("vm", dir::DT_DIR),
        ])),
        "fs" => Node::Dir(entries(&[("inotify", dir::DT_DIR)])),
        "fs/inotify" => Node::Dir(entries(&[("max_queued_events", dir::DT_REG)])),
        "fs/inotify/max_queued_events" => {
            Node::File(format!("{}\n", super::inotify::MAX_QUEUED_EVENTS).into_bytes())
        }
        "vm" => Node::Dir(entries(&[
            ("memfd_noexec", dir::DT_REG),
            ("mmap_rnd_bits", dir::DT_REG),
            ("mmap_rnd_compat_bits", dir::DT_REG),
        ])),
        "vm/memfd_noexec" => {
            Node::File(format!("{}\n", super::memfd::noexec_scope().ok()?).into_bytes())
        }
        "vm/mmap_rnd_bits" => {
            Node::File(super::sysctl::text("/proc/sys/vm/mmap_rnd_bits").ok()?)
        }
        "vm/mmap_rnd_compat_bits" => {
            Node::File(super::sysctl::text("/proc/sys/vm/mmap_rnd_compat_bits").ok()?)
        }
        "kernel" => Node::Dir(entries(&[
            ("hostname", dir::DT_REG),
            ("kptr_restrict", dir::DT_REG),
            ("osrelease", dir::DT_REG),
            ("ostype", dir::DT_REG),
            ("pid_max", dir::DT_REG),
            ("random", dir::DT_DIR),
            ("unprivileged_bpf_disabled", dir::DT_REG),
        ])),
        "kernel/kptr_restrict" => {
            Node::File(super::sysctl::text("/proc/sys/kernel/kptr_restrict").ok()?)
        }
        "kernel/unprivileged_bpf_disabled" => {
            Node::File(super::sysctl::text("/proc/sys/kernel/unprivileged_bpf_disabled").ok()?)
        }
        "kernel/random" => Node::Dir(entries(&[("boot_id", dir::DT_REG), ("uuid", dir::DT_REG)])),
        "kernel/random/boot_id" => {
            let s = match vfs::runtime_dir().map(aim_storage::boot_id::BootId::read) {
                Some(Ok(boot_id)) => boot_id.uuid,
                Some(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    let runtime = vfs::runtime_dir().unwrap();
                    match aim_storage::process_namespace::InitRegistration::read(
                        &runtime.join("identity/by-pid"),
                    ) {
                        Ok(_) => return None,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => return None,
                    }
                    sysctl_string("kern.bootsessionuuid").to_lowercase()
                }
                Some(Err(_)) => return None,
                _ => sysctl_string("kern.bootsessionuuid").to_lowercase(),
            };
            Node::File(format!("{s}\n").into_bytes())
        }
        "kernel/random/uuid" => Node::File(random_uuid().into_bytes()),
        "kernel/pid_max" => Node::File(format!("{}\n", super::pidns::tids::PID_MAX).into_bytes()),
        "kernel/ostype" => Node::File(b"Linux\n".to_vec()),
        "kernel/osrelease" => {
            Node::File(format!("{}\n", super::pstate::kernel_release()).into_bytes())
        }
        "kernel/hostname" => {
            Node::File(format!("{}\n", sysctl_string("kern.hostname")).into_bytes())
        }
        _ => return None,
    })
}

/// Under /proc or /sys, and not in a writable area mapped there (the cgroup
/// v2 hierarchy).
fn is_kernfs(guest: &str) -> bool {
    (guest == "/proc"
        || guest.starts_with("/proc/")
        || guest == "/sys"
        || guest.starts_with("/sys/"))
        && vfs::lookup(guest).1 != Area::Writable
}

/// The host path init recorded a value at, if it exists.
fn recorded(guest: &str) -> Option<(PathBuf, libc::stat)> {
    let (host, area) = vfs::lookup(guest);
    if area != Area::Kernfs || device_tree(guest) {
        return None;
    }
    // A value written for a process or thread lasts as long as it does.
    if let Some(n) = proc_entry(&canonical(guest))
        && node(&format!("/proc/{n}")).is_none()
    {
        return None;
    }
    let c = CString::new(host.as_os_str().as_encoded_bytes()).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: host path, local buffer.
    (unsafe { libc::stat(c.as_ptr(), &mut st) } == 0).then_some((host, st))
}

/// The pid or tid of the `/proc/<n>` directory a canonical path is in.
fn proc_entry(canon: &str) -> Option<i32> {
    canon
        .strip_prefix("/proc/")?
        .split('/')
        .next()?
        .parse()
        .ok()
}

/// Files of content fds the guest closed while nothing else referred to
/// them, kept as hidden fds for the next content fd: creating and removing
/// a file takes over 100 µs of kernel time on a Mac, rewriting one a few
/// (#446). A fork child does not get them ([`fork_save`]).
static POOL: Pool = Pool(Mutex::new(Vec::new()));
const POOL_MAX: usize = 8;

struct Pool(Mutex<Vec<i32>>);

/// An open mounts or mountinfo file. `seen` is Linux `proc_mounts.event`:
/// dup shares it, and the poll that observes a generation change consumes
/// it. The host fd stays the content file (`fstat` is a regular file).
pub(super) struct MountPoll {
    host_pid: i32,
    info: bool,
    seen: AtomicU64,
    filled: AtomicU64,
    /// Namespace the path named at open. Later `unshare` does not retarget it.
    ns: Option<Arc<vfs::MountNs>>,
}

static MOUNT_POLLS: Mutex<BTreeMap<i32, Arc<MountPoll>>> = Mutex::new(BTreeMap::new());

const MOUNT_IN: i16 = 0x1;
const MOUNT_PRI: i16 = 0x2;
const MOUNT_ERR: i16 = 0x8;
const MOUNT_RDNORM: i16 = 0x40;

fn open_mount_table(host_pid: i32, info: bool, thread: Option<i32>, cloexec: bool) -> i64 {
    // Sample the generation around the read. A mount during the read
    // retries so the file does not open already holding an edge. A storm
    // that never settles still opens: the next change remains visible.
    // `/proc/self/mounts` is the leader's namespace, captured here.
    let ns = (host_pid == pid()).then(|| vfs::proc_mount_namespace(thread));
    let mut prepared = (String::new(), 0u64);
    for _ in 0..8 {
        let event = ns
            .as_ref()
            .map(|ns| vfs::mount_namespace_event(ns))
            .unwrap_or(0);
        let text = match mount_poll_points(host_pid, ns.as_ref()) {
            Ok(points) => {
                if info {
                    mountinfo(points)
                } else {
                    mounts(points)
                }
            }
            Err(error) => return -(error as i64),
        };
        let now = ns
            .as_ref()
            .map(|ns| vfs::mount_namespace_event(ns))
            .unwrap_or(0);
        let stable = now == event;
        prepared = (text, event);
        if stable {
            break;
        }
    }
    let (text, event) = prepared;
    let fd = content_fd_unpublished(text.as_bytes(), cloexec);
    if fd < 0 {
        return fd;
    }
    let fd_i = fd as i32;
    MOUNT_POLLS.lock().unwrap().insert(
        fd_i,
        Arc::new(MountPoll {
            host_pid,
            info,
            seen: AtomicU64::new(event),
            filled: AtomicU64::new(event),
            ns,
        }),
    );
    if let Err(error) = fdtab::publish_guest(fd_i) {
        fdtab::on_close(fd_i);
        // SAFETY: the fd we just opened.
        unsafe {
            libc::close(fd_i);
        }
        return -(error as i64);
    }
    fd
}

/// `mounts_poll` without consuming the edge.
pub(super) fn mount_poll_bits(fd: i32) -> Option<i16> {
    let polls = MOUNT_POLLS.lock().unwrap();
    let poll = polls.get(&fd)?;
    let mut bits = MOUNT_IN | MOUNT_RDNORM;
    // Another process's table is not this process's `ns->event`. The file
    // is still pollable; it does not invent a priority edge.
    if poll.host_pid == pid() && poll.seen.load(Ordering::Acquire) != poll_generation(poll) {
        bits |= MOUNT_ERR | MOUNT_PRI;
    }
    Some(bits)
}

/// The poll that observes `ns->event` advances `p->event`. False when
/// another waiter already did, or this fd is not a mount file.
pub(super) fn take_mount_edge(fd: i32) -> bool {
    let polls = MOUNT_POLLS.lock().unwrap();
    let Some(poll) = polls.get(&fd) else {
        return false;
    };
    if poll.host_pid != pid() {
        return false;
    }
    let current = poll_generation(poll);
    let seen = poll.seen.load(Ordering::Acquire);
    if seen == current {
        return false;
    }
    poll.seen.store(current, Ordering::Release);
    true
}

pub(super) fn is_mount_poll(fd: i32) -> bool {
    MOUNT_POLLS.lock().unwrap().contains_key(&fd)
}

pub(super) fn mount_wake_fd() -> i32 {
    vfs::mount_wake_fd()
}

pub(super) fn mount_wake_errno() -> i32 {
    vfs::mount_wake_errno()
}

pub(super) fn drain_mount_wake() {
    vfs::drain_mount_wake();
}

/// A dup shares the open file, including `p->event`.
pub(super) fn dup_mount_poll(old: i32, new: i32) {
    let mut polls = MOUNT_POLLS.lock().unwrap();
    if let Some(poll) = polls.get(&old).cloned() {
        polls.insert(new, poll);
    }
}

pub(super) fn close_mount_poll(fd: i32) {
    MOUNT_POLLS.lock().unwrap().remove(&fd);
}

/// An open `/proc/<pid>/ns/mnt` fd. The Arc is the namespace it named at
/// open, which stays after `unshare` switches the process away.
static MOUNT_NS_FDS: Mutex<BTreeMap<i32, Arc<vfs::MountNs>>> = Mutex::new(BTreeMap::new());

fn mount_ns_ino(target: &str) -> Option<u64> {
    let rest = target.strip_prefix("mnt:[")?.strip_suffix(']')?;
    if rest.is_empty() || !rest.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

fn mount_ns_text(fd: i32) -> Option<String> {
    let ns = MOUNT_NS_FDS.lock().unwrap().get(&fd).cloned()?;
    Some(format!("mnt:[{}]", vfs::mount_namespace_ino(&ns)))
}

pub(super) fn mount_namespace_of(fd: i32) -> Option<Arc<vfs::MountNs>> {
    MOUNT_NS_FDS.lock().unwrap().get(&fd).cloned()
}

/// Inherited namespace fds. The host descriptor arrives by `dup2`; this is
/// the namespace it named in the parent.
pub(super) fn mount_namespace_fds() -> Vec<(i32, u64)> {
    MOUNT_NS_FDS
        .lock()
        .unwrap()
        .iter()
        .map(|(fd, ns)| (*fd, vfs::mount_namespace_ino(ns)))
        .collect()
}

pub(super) fn bind_mount_namespace(fd: i32, ns: Arc<vfs::MountNs>) {
    MOUNT_NS_FDS.lock().unwrap().insert(fd, ns);
}

#[cfg(test)]
pub(super) fn testing_clear_namespace_fds() {
    MOUNT_NS_FDS.lock().unwrap().clear();
}

fn open_mount_namespace(ino: u64, cloexec: bool) -> i64 {
    let Some(ns) = vfs::mount_namespace(ino) else {
        return -(ENOENT as i64);
    };
    let fd = content_fd(&[], cloexec);
    if fd < 0 {
        return fd;
    }
    MOUNT_NS_FDS.lock().unwrap().insert(fd as i32, ns);
    fd
}

pub(super) fn close_mount_namespace(fd: i32) {
    MOUNT_NS_FDS.lock().unwrap().remove(&fd);
}

pub(super) fn dup_mount_namespace(old: i32, new: i32) {
    let mut fds = MOUNT_NS_FDS.lock().unwrap();
    if let Some(ns) = fds.get(&old).cloned() {
        fds.insert(new, ns);
    }
}

/// Identity of the open file's `mounts_poll` cursor, for a fork that shares
/// one description across dup.
pub(super) fn mount_poll_ptr(fd: i32) -> Option<*const ()> {
    MOUNT_POLLS
        .lock()
        .unwrap()
        .get(&fd)
        .map(|poll| Arc::as_ptr(poll) as *const ())
}

pub(super) fn mount_poll_record(fd: i32) -> Option<(bool, u64, u64)> {
    let polls = MOUNT_POLLS.lock().unwrap();
    let poll = polls.get(&fd)?;
    Some((
        poll.info,
        poll.seen.load(Ordering::Acquire),
        poll.filled.load(Ordering::Acquire),
    ))
}

pub(super) fn save_mount_poll(fd: i32, w: &mut super::fork_state::Writer) {
    let (info, seen, filled) = mount_poll_record(fd).expect("mount poll");
    w.bool(info);
    w.u64(seen);
    w.u64(filled);
}

pub(super) fn load_mount_poll(r: &mut super::fork_state::Reader) -> Arc<MountPoll> {
    Arc::new(MountPoll {
        host_pid: pid(),
        info: r.bool(),
        seen: AtomicU64::new(r.u64()),
        filled: AtomicU64::new(r.u64()),
        ns: Some(vfs::proc_mount_namespace(None)),
    })
}

pub(super) fn install_mount_poll(fd: i32, poll: Arc<MountPoll>) {
    MOUNT_POLLS.lock().unwrap().insert(fd, poll);
}

/// Exec shares one cursor per open file, keyed by the id in the exec text.
pub(super) struct MountPollCache(BTreeMap<u64, Arc<MountPoll>>);

impl MountPollCache {
    pub(super) fn new() -> Self {
        Self(BTreeMap::new())
    }
}

pub(super) fn restore_mount_exec(
    cache: &mut MountPollCache,
    fd: i32,
    id: u64,
    info: bool,
    seen: u64,
    filled: u64,
) {
    let poll = cache
        .0
        .entry(id)
        .or_insert_with(|| {
            Arc::new(MountPoll {
                host_pid: pid(),
                info,
                seen: AtomicU64::new(seen),
                filled: AtomicU64::new(filled),
                ns: Some(vfs::proc_mount_namespace(None)),
            })
        })
        .clone();
    install_mount_poll(fd, poll);
}

#[cfg(test)]
pub(crate) fn detach_mount_polls() {
    MOUNT_POLLS.lock().unwrap().clear();
}

/// Rewrite the content file when the mount generation moved, keeping the
/// offset. `seq_read` shows the namespace as it is at the read.
pub(super) fn refresh_mount_file(fd: i32) {
    let poll = {
        let polls = MOUNT_POLLS.lock().unwrap();
        polls.get(&fd).cloned()
    };
    let Some(poll) = poll else {
        return;
    };
    if poll.host_pid != pid() {
        return;
    }
    for _ in 0..4 {
        let event = poll_generation(&poll);
        if poll.filled.load(Ordering::Acquire) == event {
            return;
        }
        let text = match mount_poll_points(poll.host_pid, poll.ns.as_ref()) {
            Ok(points) => {
                if poll.info {
                    mountinfo(points)
                } else {
                    mounts(points)
                }
            }
            Err(_) => return,
        };
        if poll_generation(&poll) != event {
            continue;
        }
        // SAFETY: the content file's offset, restored after the rewrite.
        let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
        fill(fd, text.as_bytes());
        if pos > 0 {
            let end = text.len() as i64;
            unsafe {
                libc::lseek(fd, pos.min(end), libc::SEEK_SET);
            }
        }
        poll.filled.store(event, Ordering::Release);
        return;
    }
}

/// A file holding `data`, positioned at 0. Closing it gives the file back
/// to the pool ([`recycle`]).
pub(super) fn content_fd(data: &[u8], cloexec: bool) -> i64 {
    let fd = content_fd_unpublished(data, cloexec);
    if fd >= 0 {
        if let Err(error) = fdtab::publish_guest(fd as i32) {
            fdtab::on_close(fd as i32);
            unsafe {
                libc::close(fd as i32);
            }
            return -(error as i64);
        }
    }
    fd
}

pub(super) fn content_fd_unpublished(data: &[u8], cloexec: bool) -> i64 {
    let fd = match POOL.reuse(data, cloexec) {
        Some(fd) => fd,
        None => match fresh(data) {
            Ok(fd) => {
                fdtab::set_flags(fd, false, cloexec);
                fd
            }
            Err(e) => return e,
        },
    };
    fdtab::insert(fd, Kind::Content);
    fd as i64
}

/// A new unlinked file holding `data`.
fn fresh(data: &[u8]) -> Result<i32, i64> {
    let fd = crate::vfs::unnamed_file("linux-abi-proc").map_err(|error| -(error as i64))?;
    fill(fd, data);
    Ok(fd)
}

/// Make the file of `fd` hold exactly `data`, positioned at 0.
fn fill(fd: i32, data: &[u8]) {
    let mut off = 0;
    // SAFETY: writing our own file from a local buffer.
    unsafe {
        while off < data.len() {
            let n = libc::pwrite(
                fd,
                data[off..].as_ptr().cast(),
                data.len() - off,
                off as i64,
            );
            if n <= 0 {
                break;
            }
            off += n as usize;
        }
        libc::ftruncate(fd, off as i64);
        libc::lseek(fd, 0, libc::SEEK_SET);
    }
}

impl Pool {
    /// A pooled file holding `data`, on the lowest free fd.
    fn reuse(&self, data: &[u8], cloexec: bool) -> Option<i32> {
        let h = self.0.lock().unwrap().pop()?;
        fill(h, data);
        let cmd = if cloexec {
            libc::F_DUPFD_CLOEXEC
        } else {
            libc::F_DUPFD
        };
        // SAFETY: plain fcntls on our hidden fd; its status flags (O_NONBLOCK,
        // O_APPEND) are the last user's, so they are cleared.
        let fd = unsafe {
            libc::fcntl(h, libc::F_SETFL, 0);
            libc::fcntl(h, cmd, 0)
        };
        fdtab::unhide(h);
        // SAFETY: our hidden fd; `fd`, if any, keeps the file open.
        unsafe { libc::close(h) };
        (fd >= 0).then_some(fd)
    }

    /// The guest is closing content fd `fd`: its file goes back to the pool
    /// unless another fd, a process, a message or a mapping still refers to it.
    fn recycle(&self, fd: i32) {
        let mut pool = self.0.lock().unwrap();
        if pool.len() >= POOL_MAX
            || shared(fd)
            || file_id(fd).is_none_or(|id| MAPPED.lock().unwrap().contains(&id))
        {
            return;
        }
        // SAFETY: duplicating the guest's fd before it closes it.
        let h = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, fdtab::hidden_base()) };
        if h >= 0 {
            fdtab::keep_hidden(h);
            pool.push(h);
        }
    }

    /// Close the pooled files.
    fn drain(&self) {
        for h in self.0.lock().unwrap().drain(..) {
            fdtab::unhide(h);
            // SAFETY: our hidden fd.
            unsafe { libc::close(h) };
        }
    }
}

/// Content files that were mapped, by (dev, ino): a mapping holds the file
/// without an fd (libselinux maps `/sys/fs/selinux/status`), so they never
/// go back to the pool.
static MAPPED: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());

fn file_id(fd: i32) -> Option<(u64, u64)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat into a local buffer.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev as u64, st.st_ino))
}

/// `fd` is being mapped.
pub fn on_mmap(fd: i32) {
    if matches!(fdtab::get(fd), Some(Kind::Content | Kind::Knob(_)))
        && let Some(id) = file_id(fd)
    {
        MAPPED.lock().unwrap().push(id);
    }
}

/// The guest is closing content fd `fd` ([`Pool::recycle`]).
pub fn recycle(fd: i32) {
    POOL.recycle(fd);
}

/// Whether the open file of `fd` has other references than `fd`
/// (`PROC_FP_SHARED`); true when that cannot be told.
fn shared(fd: i32) -> bool {
    const PROC_PIDFDVNODEINFO: i32 = 1;
    const PROC_FP_SHARED: u32 = 1;
    // struct vnode_fdinfo (176 bytes); fi_status is its second word.
    let mut info = [0u32; 44];
    // SAFETY: a buffer of the flavour's size.
    let n = unsafe {
        crate::hostlibc::proc_pidfdinfo(
            libc::getpid(),
            fd,
            PROC_PIDFDVNODEINFO,
            info.as_mut_ptr().cast(),
            std::mem::size_of_val(&info) as i32,
        )
    };
    n <= 4 || info[1] & PROC_FP_SHARED != 0
}

/// A directory fd for a synthesized directory.
fn dir_fd(guest: &str, list: Vec<Entry>, cloexec: bool) -> i64 {
    let mut list = list;
    if !guest.starts_with("/sys/fs/fuse")
        && let Some((host, _)) = recorded(guest)
        && let Ok(rd) = std::fs::read_dir(&host)
    {
        for e in rd.flatten() {
            let name = e.file_name().as_encoded_bytes().to_vec();
            // Only the namespace's processes are directories of /proc.
            let process = guest == "/proc" && name.iter().all(u8::is_ascii_digit);
            if !process && !list.iter().any(|x| x.name == name) {
                let t = if e.file_type().is_ok_and(|t| t.is_dir()) {
                    dir::DT_DIR
                } else {
                    dir::DT_REG
                };
                list.push(Entry::new(1, t, name));
            }
        }
    }
    // A real directory backs the fd so fstat and fchdir behave.
    let c = CString::new(vfs::root().as_os_str().as_encoded_bytes()).unwrap_or_default();
    // SAFETY: opening the root directory read-only.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 {
        return -(errno::last() as i64);
    }
    fdtab::set_flags(fd, false, cloexec);
    let mut all = vec![
        Entry::new(1, dir::DT_DIR, "."),
        Entry::new(1, dir::DT_DIR, ".."),
    ];
    all.extend(list);
    fdtab::insert(
        fd,
        Kind::Dir(Arc::new(Mutex::new(DirStream::synthesized(
            guest.to_string(),
            all,
        )))),
    );
    if let Err(error) = fdtab::publish_guest(fd) {
        fdtab::on_close(fd);
        unsafe {
            libc::close(fd);
        }
        return -(error as i64);
    }
    fd as i64
}

/// Canonical form: `self` and `thread-self` become the pid path.
/// `/proc/self/...` below the link itself: `/proc/self` alone stays a link.
fn canonical(guest: &str) -> String {
    let me = pid();
    if let Some(t) = guest.strip_prefix("/proc/self/") {
        return format!("/proc/{me}/{t}");
    }
    if let Some(t) = guest.strip_prefix("/proc/thread-self/") {
        return format!("/proc/{me}/task/{}/{t}", super::process::gettid());
    }
    super::evdev::canonical(guest).unwrap_or_else(|| guest.to_string())
}

/// The current process's procfs descriptor magic link. Callers must retain the
/// referenced descriptor before changing its inode, rather than reopen its name.
pub(super) fn current_fd_link(guest: &str) -> Option<Result<i32, Errno>> {
    let canon = canonical(guest);
    let tail = canon
        .strip_prefix(&format!("/proc/{}/fd/", pid()))
        .or_else(|| {
            canon.strip_prefix(&format!(
                "/proc/{}/task/{}/fd/",
                pid(),
                super::process::gettid()
            ))
        })?;
    let fd: i32 = tail.parse().ok()?;
    if !fdtab::visible(fd) {
        return Some(Err(ENOENT));
    }
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Some(Err(ENOENT));
    }
    Some(Ok(fd))
}

/// The thread of this process whose `comm` a canonical path names.
fn comm_tid(canon: &str) -> Option<i32> {
    let rest = canon.strip_prefix("/proc/")?.strip_suffix("/comm")?;
    let (p, tid) = match rest.split_once("/task/") {
        Some((p, t)) => (p.parse().ok()?, t.parse().ok()?),
        None => {
            let t: i32 = rest.parse().ok()?;
            (super::thread::owner(t), t)
        }
    };
    (p == pid() && super::thread::find(tid).is_some()).then_some(tid)
}

/// The process of `/proc/<pid>/oom_score_adj` or
/// `/proc/<pid>/task/<tid>/oom_score_adj`, when it exists.
fn oom_score_adj_pid(canon: &str) -> Option<i32> {
    let rest = canon
        .strip_prefix("/proc/")?
        .strip_suffix("/oom_score_adj")?;
    let p: i32 = rest.split('/').next()?.parse().ok()?;
    node(canon).is_some().then_some(p)
}

const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const O_CLOEXEC: u64 = 0o2000000;

/// openat of a guest path under /proc or /sys. None: not ours.
fn publish_plain_open(fd: i32) -> i64 {
    if fd < 0 {
        return -(errno::last() as i64);
    }
    if let Err(error) = fdtab::publish_guest(fd) {
        unsafe {
            libc::close(fd);
        }
        return -(error as i64);
    }
    fd as i64
}

pub(super) fn write_comm(tid: i32, b: &[u8]) -> Result<(), errno::Errno> {
    // Linux takes up to 15 bytes as they are, newline included.
    let mut name = [0u8; 16];
    let len = b
        .iter()
        .take(15)
        .position(|&c| c == 0)
        .unwrap_or(b.len().min(15));
    name[..len].copy_from_slice(&b[..len]);
    if !super::thread::set_name_of(tid, name) {
        // proc_pid_comm refuses a task outside the writer's thread group.
        return Err(errno::EINVAL);
    }
    Ok(())
}

pub fn open(guest: &str, flags: u64, host_flags: i32) -> Option<i64> {
    if let Some(result) = super::fuse_sysfs::open(guest, flags) {
        return Some(result);
    }
    if let Some(result) = super::loopdev::open_sysfs(guest, flags) {
        return Some(result);
    }
    if !is_kernfs(guest) {
        return None;
    }
    if let Some(node) = super::fuse_sysfs::node(guest) {
        return Some(match node {
            Ok(Node::Dir(entries)) => dir_fd(guest, entries, flags & O_CLOEXEC != 0),
            Ok(Node::File(_) | Node::NetTable(_) | Node::MountTable { .. } | Node::Mem(_)) => {
                -(errno::EACCES as i64)
            }
            Ok(Node::Link(_)) => -(errno::EINVAL as i64),
            Ok(Node::Denied(_)) => -(errno::EACCES as i64),
            Err(error) => -(error as i64),
        });
    }
    if let Some(result) = super::tracefs::open(guest, flags) {
        return Some(result);
    }
    let cloexec = flags & O_CLOEXEC != 0;
    let write = flags & O_ACCMODE != 0;
    if canonical(guest) == super::memfd::NOEXEC_SYSCTL {
        return Some(super::memfd::open_noexec(write, cloexec));
    }
    if let Some(result) = super::sysctl::open(&canonical(guest), flags & O_ACCMODE, cloexec) {
        return Some(result);
    }
    if canonical(guest) == "/proc/kmsg" {
        return Some(super::kmsg::open_proc(flags, host_flags));
    }
    if let Some(rest) = canonical(guest).strip_prefix("/proc/sys/net/ipv6/conf/")
        && let Some(r) = super::ipv6conf::open(rest, flags & O_ACCMODE != 1, write, cloexec)
    {
        return Some(r);
    }
    // A process's oom_score_adj is its own value, not a recorded file.
    if write && let Some(p) = oom_score_adj_pid(&canonical(guest)) {
        if !super::cred::may_write_owned_by(p) {
            return Some(-(EACCES as i64));
        }
        let value = super::cred::oom_score_adj_of(p).unwrap_or(0);
        return Some(super::knob::open(
            format!("{value}\n").as_bytes(),
            cloexec,
            super::knob::Knob::OomScoreAdj(p),
        ));
    }
    if let Some((host, st)) = recorded(guest)
        && st.st_mode & libc::S_IFMT != libc::S_IFDIR
    {
        let c = CString::new(host.as_os_str().as_encoded_bytes()).ok()?;
        // SAFETY: opening the recorded value file.
        return Some(publish_plain_open(unsafe {
            libc::open(c.as_ptr(), host_flags, 0o644)
        }));
    }
    let canon = canonical(guest);

    if canon.ends_with("/tracing/trace_marker") && node(&canon).is_some() {
        // Trace events are not collected: writes are discarded.
        // SAFETY: opening the host's null device.
        return Some(publish_plain_open(unsafe {
            libc::open(c"/dev/null".as_ptr(), host_flags)
        }));
    }
    if let Some(tid) = comm_tid(&canon) {
        let name = thread_comm(pid(), tid).unwrap_or_else(|| comm(pid()));
        return Some(super::knob::open(
            format!("{name}\n").as_bytes(),
            cloexec,
            super::knob::Knob::Comm(tid),
        ));
    }
    if write && let Some(dev) = super::uevent::attribute(&canon) {
        return Some(super::knob::open(
            &dev.attribute(),
            cloexec,
            super::knob::Knob::Uevent(dev),
        ));
    }
    // /proc/<pid>/fd/N reopens the file behind fd N.
    if let Some(n) = canon
        .strip_prefix(&format!("/proc/{}/fd/", pid()))
        .and_then(|n| n.parse::<i32>().ok())
    {
        if !fdtab::visible(n) {
            return Some(-(ENOENT as i64));
        }
        if let Some(guest) = fdtab::socket_path_guest(n) {
            let path = std::ffi::CString::new(guest).ok()?;
            return Some(super::fs::openat_as(
                [
                    vfs::LINUX_AT_FDCWD as u64,
                    path.as_ptr() as u64,
                    flags,
                    0,
                    0,
                    0,
                ],
                &super::cred::current(),
            ));
        }
        if let Some(reference) = fdtab::character_reference(n) {
            if let Err(error) = reference.stat(n) {
                return Some(
                    -(errno::from_darwin(error.raw_os_error().unwrap_or(libc::EIO)) as i64),
                );
            }
            let path = std::ffi::CString::new(reference.guest).ok()?;
            return Some(super::fs::openat_as(
                [
                    vfs::LINUX_AT_FDCWD as u64,
                    path.as_ptr() as u64,
                    flags,
                    0,
                    0,
                    0,
                ],
                &super::cred::current(),
            ));
        }
        if let Some(r) = super::memfd::reopen(n, host_flags) {
            return Some(r);
        }
        // A bpf object is an anon inode, which no open reopens.
        if super::bpf::is_object(n) {
            return Some(-(errno::ENXIO as i64));
        }
        // The link leads to the file itself, which may_open checks for
        // this open's access as any open of it (proc_fd_link, then
        // inode_permission).
        let want = match host_flags & libc::O_ACCMODE {
            libc::O_RDONLY => 4,
            libc::O_WRONLY => 2,
            _ => 6,
        };
        match super::fs::stat_fd_kernel(n) {
            Ok(st)
                if !super::attrs::permits(&st, want, &super::cred::current(), super::attrs::FS) =>
            {
                return Some(-(EACCES as i64));
            }
            Ok(_) => {}
            Err(error) => return Some(error),
        }
        let mut path = [0u8; libc::PATH_MAX as usize];
        // SAFETY: F_GETPATH into a local buffer; then open or dup.
        return Some(unsafe {
            if crate::sys::fgetpath(n, path.as_mut_ptr()) == 0 {
                errno::check(
                    libc::open(path.as_ptr().cast(), host_flags & !libc::O_CREAT, 0) as i64,
                )
            } else {
                let r = libc::fcntl(
                    n,
                    if cloexec {
                        libc::F_DUPFD_CLOEXEC
                    } else {
                        libc::F_DUPFD
                    },
                    0,
                );
                if r >= 0 {
                    fdtab::on_dup(n, r);
                }
                errno::check(r as i64)
            }
        });
    }
    Some(match node(&canon) {
        Some(Node::Mem(pid)) => super::proc_mem::open(pid, flags),
        Some(Node::MountTable {
            host_pid,
            info,
            thread,
        }) => {
            if write {
                return Some(-(EACCES as i64));
            }
            open_mount_table(host_pid, info, thread, cloexec)
        }
        Some(Node::NetTable(kind)) => {
            if write {
                return Some(-(EACCES as i64));
            }
            let table = if kind == "dev" {
                super::netif::proc_dev()
            } else {
                super::net::proc_table(&kind)
            };
            match table {
                Ok(bytes) => content_fd(&bytes, cloexec),
                Err(error) => -(error as i64),
            }
        }
        Some(Node::File(data)) => {
            if write && (device_tree(&canon) || READ_ONLY.contains(&canon.as_str())) {
                // An attribute with no store method (`kernfs_fop_open`).
                return Some(-(EACCES as i64));
            }
            if write {
                // Kernel knobs the layer does not emulate: record the value
                // under kernfs like init's writes, or refuse.
                return Some(record_write(guest, host_flags));
            }
            content_fd(&data, cloexec)
        }
        Some(Node::Dir(list)) => dir_fd(&canon, list, cloexec),
        Some(Node::Denied(_)) => -(EACCES as i64),
        Some(Node::Link(t)) => {
            if let Some(ino) = mount_ns_ino(&t) {
                if write {
                    return Some(-(EACCES as i64));
                }
                return Some(open_mount_namespace(ino, cloexec));
            }
            let target = if t.starts_with('/') {
                t
            } else {
                format!("/proc/{t}")
            };
            let linked = node(&canonical(&target));
            if let Some(Node::MountTable {
                host_pid,
                info,
                thread,
            }) = linked
            {
                if write {
                    return Some(-(EACCES as i64));
                }
                open_mount_table(host_pid, info, thread, cloexec)
            } else if let Some(Node::Dir(list)) = linked {
                dir_fd(&canonical(&target), list, cloexec)
            } else if let Some(Node::File(data)) = linked.filter(|_| !write) {
                // /proc/mounts -> self/mounts.
                content_fd(&data, cloexec)
            } else {
                let r = match vfs::resolve(vfs::LINUX_AT_FDCWD, target.as_bytes(), true) {
                    Ok(r) => r,
                    Err(e) => return Some(-(e as i64)),
                };
                if r.guest == super::process::exe_guest_path() {
                    let c = CString::new(super::process::exe_host_path()).ok()?;
                    // SAFETY: opening the program file.
                    return Some(errno::check(
                        unsafe { libc::open(c.as_ptr(), host_flags) } as i64
                    ));
                }
                // SAFETY: opening the link target.
                errno::check(unsafe { libc::open(r.host.as_ptr(), host_flags, 0) } as i64)
            }
        }
        // sysfs creates no files: a missing device attribute stays missing.
        None if device_tree(&canon) || super::tracefs::tail(&canon).is_some() => {
            let parent = canon.rsplit_once('/').map_or("", |(p, _)| p);
            if flags & O_CREAT != 0 && matches!(node(parent), Some(Node::Dir(_))) {
                -(EACCES as i64)
            } else {
                -(ENOENT as i64)
            }
        }
        None if flags & O_CREAT != 0 || write => record_write(guest, host_flags),
        None => -(ENOENT as i64),
    })
}

/// sysfs attributes outside the device trees that have no store method
/// (mode 0444).
const READ_ONLY: &[&str] = &["/sys/kernel/uevent_seqnum"];

/// Whether `guest` is in sysfs's device trees, which hold only the devices
/// the layer models and their attributes. Values init wrote there are not
/// served: on Linux such a write fails for a device that does not exist
/// (`/sys/class/android_usb` on a device without a USB gadget), and the
/// modeled attributes answer for themselves.
fn device_tree(guest: &str) -> bool {
    ["block", "bus", "class", "dev", "devices"].iter().any(|t| {
        guest
            .strip_prefix("/sys/")
            .and_then(|r| r.strip_prefix(t))
            .is_some_and(|r| r.is_empty() || r.starts_with('/'))
    })
}

/// A guest write to a /proc or /sys value: kept under kernfs when there is
/// a path map, else refused.
fn record_write(guest: &str, host_flags: i32) -> i64 {
    let (host, area) = vfs::lookup(guest);
    if area != Area::Kernfs {
        return -(EACCES as i64);
    }
    if let Some(p) = host.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let Ok(c) = CString::new(host.as_os_str().as_encoded_bytes()) else {
        return -(ENOENT as i64);
    };
    // SAFETY: creating or opening the value file.
    errno::check(unsafe { libc::open(c.as_ptr(), host_flags | libc::O_CREAT, 0o644) } as i64)
}

/// stat of a guest path under /proc or /sys (links followed when
/// `follow`). None: not ours.
pub fn stat(guest: &str, follow: bool) -> Option<Result<libc::stat, Errno>> {
    if !is_kernfs(guest) {
        return None;
    }
    let canon = canonical(guest);
    // A process's files belong to its effective ids, the rest to root.
    let owner = match proc_entry(&canon).map(super::thread::owner) {
        Some(p) if p == pid() => super::attrs::ids(super::attrs::EFFECTIVE),
        Some(p) => {
            let c = super::cred::peer(p);
            (c.uid, c.gid)
        }
        None => (0, 0),
    };
    if let Some(node) = super::fuse_sysfs::node(&canon) {
        return Some(node.map(|node| {
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            stat.st_ino = canon.bytes().fold(1469598103934665603u64, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(1099511628211)
            });
            stat.st_blksize = 4096;
            match node {
                Node::Dir(_) => {
                    stat.st_mode = libc::S_IFDIR | 0o555;
                    stat.st_nlink = 2;
                }
                _ => {
                    stat.st_mode = libc::S_IFREG | 0o200;
                    stat.st_nlink = 1;
                }
            }
            stat
        }));
    }
    let conf6 = canon
        .strip_prefix("/proc/sys/net/ipv6/conf/")
        .and_then(super::ipv6conf::file_mode);
    if conf6.is_none()
        && let Some((_, mut st)) = recorded(guest)
    {
        if super::tracefs::tail(guest).is_some() {
            let (host, _) = vfs::lookup(guest);
            super::attrs::apply(
                super::attrs::Host::Path(&CString::new(host.as_os_str().as_encoded_bytes()).ok()?),
                || guest.to_string(),
                &mut st,
            );
        } else {
            (st.st_uid, st.st_gid) = owner;
        }
        return Some(Ok(st));
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let me = pid();
    st.st_uid = owner.0;
    st.st_gid = owner.1;
    st.st_blksize = 1024;
    st.st_ino = canon.bytes().fold(1469598103934665603u64, |h, b| {
        (h ^ b as u64).wrapping_mul(1099511628211)
    });
    let now = now() as i64;
    st.st_atime = now;
    st.st_mtime = now;
    st.st_ctime = now;
    match node_listed(&canon, false) {
        Some(Node::Mem(_)) => {
            st.st_mode = libc::S_IFREG | 0o600;
            st.st_nlink = 1;
        }
        Some(Node::File(_))
            if canon == super::memfd::NOEXEC_SYSCTL
                || super::sysctl::known(&canon)
                || super::loopdev::queue_attr(&canon) =>
        {
            st.st_mode = libc::S_IFREG | 0o644;
            st.st_nlink = 1;
        }
        Some(Node::File(_)) if conf6.is_some() => {
            st.st_mode = libc::S_IFREG as libc::mode_t | conf6.unwrap() as libc::mode_t;
            st.st_nlink = 1;
        }
        Some(Node::File(_) | Node::NetTable(_) | Node::MountTable { .. }) => {
            st.st_mode = libc::S_IFREG | 0o444;
            st.st_nlink = 1;
        }
        Some(Node::Dir(_)) => {
            st.st_mode = libc::S_IFDIR | 0o555;
            st.st_nlink = 2;
        }
        Some(Node::Denied(Some(mode))) => {
            st.st_mode = mode as libc::mode_t;
            st.st_nlink = if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                2
            } else {
                1
            };
        }
        Some(Node::Denied(None)) => return Some(Err(EACCES)),
        Some(Node::Link(t)) if follow => {
            if let Some(ino) = mount_ns_ino(&t) {
                st.st_mode = libc::S_IFREG | 0o444;
                st.st_ino = ino;
                st.st_nlink = 1;
                return Some(Ok(st));
            }
            let fd_n = canon
                .strip_prefix(&format!("/proc/{me}/fd/"))
                .and_then(|n| n.parse::<i32>().ok());
            if let Some(n) = fd_n {
                return Some(super::fs::stat_fd_kernel(n).map_err(|error| (-error) as Errno));
            }
            let target = if t.starts_with('/') {
                t
            } else {
                format!("/proc/{t}")
            };
            if let Some(r) = stat(&target, true) {
                return Some(r);
            }
            let path = if target == super::process::exe_guest_path() {
                CString::new(super::process::exe_host_path()).ok()?
            } else {
                match vfs::resolve(vfs::LINUX_AT_FDCWD, target.as_bytes(), true) {
                    Ok(r) => r.host,
                    Err(e) => return Some(Err(e)),
                }
            };
            // SAFETY: host path, local buffer.
            if unsafe { libc::stat(path.as_ptr(), &mut st) } < 0 {
                return Some(Err(errno::last()));
            }
        }
        Some(Node::Link(t)) => {
            st.st_mode = libc::S_IFLNK | 0o777;
            st.st_nlink = 1;
            st.st_size = t.len() as i64;
        }
        None => return Some(Err(ENOENT)),
    }
    Some(Ok(st))
}

/// Target of a `/proc` link, or None when `path` is not one we synthesize.
pub fn readlink(path: &[u8]) -> Option<Result<Vec<u8>, Errno>> {
    let guest = std::str::from_utf8(path).ok()?;
    if !guest.starts_with("/proc/") {
        return None;
    }
    let canon = canonical(guest);
    Some(match node(&canon) {
        Some(Node::Link(t)) => Ok(t.into_bytes()),
        Some(Node::Denied(_)) => Err(EACCES),
        Some(_) => Err(crate::errno::EINVAL),
        None => Err(ENOENT),
    })
}

/// `attr/current`: the identity's context, NUL-terminated.
fn attr_current(p: i32) -> Vec<u8> {
    let mut v = super::cred::seclabel_of(p).into_bytes();
    v.push(0);
    v
}

/// Whether `path` names `/proc/self/exe`.
pub fn is_self_exe(path: &[u8]) -> bool {
    path == b"/proc/self/exe" || path == format!("/proc/{}/exe", pid()).as_bytes()
}

#[cfg(test)]
mod tests {
    /// /proc/sys/fs/inotify/max_queued_events is the limit the queue keeps.
    #[test]
    fn inotify_max_queued_events_is_the_queue_limit() {
        assert!(matches!(
            super::sys_node("fs/inotify/max_queued_events"),
            Some(super::Node::File(bytes)) if bytes == b"16384\n"
        ));
    }

    #[test]
    fn boot_id_uses_the_authenticated_generation_record() {
        if super::super::fdtab::isolated_kernel_test(
            "sys::procfs::tests::boot_id_uses_the_authenticated_generation_record",
        ) {
            return;
        }
        let (_view, _root) = crate::vfs::test_view();
        let runtime = crate::vfs::runtime_dir().unwrap();
        let table = runtime.join("identity/by-pid");
        std::fs::create_dir_all(&table).unwrap();
        let owner = aim_storage::process_namespace::ProcessIdentity::running_strict(
            std::process::id() as i32,
        )
        .unwrap();
        let registration = aim_storage::process_namespace::InitRegistration::register(
            &table,
            owner,
            "boot-id-test",
        )
        .unwrap();
        let boot_id = aim_storage::boot_id::BootId::generate(owner).unwrap();
        boot_id.publish(runtime).unwrap();
        let expected = format!("{}\n", boot_id.uuid).into_bytes();
        assert!(
            matches!(super::sys_node("kernel/random/boot_id"), Some(super::Node::File(bytes)) if bytes == expected)
        );
        assert!(
            matches!(super::sys_node("kernel/random/boot_id"), Some(super::Node::File(bytes)) if bytes == expected)
        );
        std::fs::remove_file(runtime.join("boot-id")).unwrap();
        assert!(super::sys_node("kernel/random/boot_id").is_none());
        registration.remove(&table).unwrap();
        assert!(matches!(
            super::sys_node("kernel/random/boot_id"),
            Some(super::Node::File(_))
        ));
    }
    #[test]
    fn real_registered_process_mountinfo_uses_current_namespace_and_stable_clone_ids() {
        if super::super::fdtab::isolated_kernel_test(
            "sys::procfs::tests::real_registered_process_mountinfo_uses_current_namespace_and_stable_clone_ids",
        ) {
            return;
        }
        let (_view, root) = crate::vfs::test_view();
        let runtime = crate::vfs::runtime_dir().unwrap();
        let table = runtime.join("identity/by-pid");
        std::fs::create_dir_all(&table).unwrap();
        let bootstrap_id = crate::vfs::mount_namespace_id().unwrap();
        let bootstrap =
            aim_storage::mount_namespace::Namespace::open(runtime, &bootstrap_id).unwrap();
        let default = bootstrap.clone_to("actual-default-render").unwrap();
        let process =
            aim_storage::process_namespace::ProcessIdentity::running(unsafe { libc::getpid() })
                .unwrap();
        aim_storage::process_namespace::InitRegistration::register(&table, process, &bootstrap_id)
            .unwrap();
        aim_storage::process_namespace::register_init_signals(&table, process, 0).unwrap();
        aim_storage::process_namespace::InitRegistration::read(&table)
            .unwrap()
            .activate_pid_mapping(&table)
            .unwrap();
        super::super::cred::init(Default::default(), Some(table.clone()));
        aim_storage::process_namespace::register_mount_namespace(&table, process, default.id())
            .expect("actual current namespace receipt");
        crate::vfs::load_own_mounts(&format!("namespace-owner\t{}\n", default.id()))
            .expect("actual current namespace view");
        let child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                }
                let _ = self.0.wait();
            }
        }
        let child = Child(child);
        let child_identity =
            aim_storage::process_namespace::ProcessIdentity::running(child.0.id() as i32).unwrap();
        std::fs::write(
            table.join(child.0.id().to_string()),
            b"service\tactual-child\nuid\t0\ngid\t0\n",
        )
        .unwrap();
        aim_storage::process_namespace::register_mount_namespace(
            &table,
            child_identity,
            &bootstrap_id,
        )
        .unwrap();
        let read_root = |pid: i32| {
            let path = std::ffi::CString::new(format!("/proc/{pid}/mountinfo")).unwrap();
            let fd = super::super::fs::openat([
                crate::vfs::LINUX_AT_FDCWD as u64,
                path.as_ptr() as u64,
                0,
                0,
                0,
                0,
            ]);
            assert!(fd >= 0, "actual mountinfo open {fd}");
            let mut bytes = vec![0u8; 65536];
            let n = super::super::fs::read([
                fd as u64,
                bytes.as_mut_ptr() as u64,
                bytes.len() as u64,
                0,
                0,
                0,
            ]);
            assert!(n > 0);
            assert_eq!(super::super::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
            let text = std::str::from_utf8(&bytes[..n as usize]).unwrap();
            let fields = text
                .lines()
                .find_map(|line| {
                    let fields: Vec<_> = line.split(' ').collect();
                    (fields[4] == "/").then_some(fields)
                })
                .unwrap();
            (
                fields[0].parse::<u64>().unwrap(),
                fields[1].parse::<u64>().unwrap(),
            )
        };
        let init = read_root(1);
        let early = read_root(child.0.id() as i32);
        assert_ne!(init.0, early.0);
        assert_eq!(init.0, init.1);
        assert_eq!(early.0, early.1);
        assert_eq!(init, read_root(1));
        assert!(root.is_dir());
        drop(child);
    }
    use std::io::Write;
    use std::process::{Command, Stdio};

    /// A bind of `/data`'s directories (`/data_mirror`) shows `/data`'s
    /// filesystem, not a tmpfs (#455); `/data_mirror` itself is a tmpfs.
    #[test]
    fn binds_of_a_block_area_show_its_filesystem() {
        let (_view, _) = crate::vfs::test_view();
        let table = super::mount_table(crate::vfs::mount_points().unwrap());
        let entry = |target: &str| {
            table
                .iter()
                .find(|(_, t, _, _)| t == target)
                .map(|(source, _, fstype, _)| (source.as_str(), fstype.as_str()))
        };
        assert_eq!(entry("/data"), Some(("/dev/block/by-name/data", "ext4")));
        assert_eq!(
            entry("/data_mirror/data_ce/null/0"),
            Some(("/dev/block/by-name/data", "ext4"))
        );
        assert_eq!(entry("/data_mirror"), Some(("tmpfs", "tmpfs")));
    }

    #[test]
    fn mounts_symlink_opens_the_same_live_namespace_as_self_mounts() {
        let (_view, root) = crate::vfs::test_view();
        let read = |path: &str| {
            let fd = super::open(path, 0, libc::O_RDONLY).unwrap();
            assert!(fd >= 0, "{path}: errno {}", -fd);
            let mut bytes = vec![0u8; 65536];
            let length =
                unsafe { libc::pread(fd as i32, bytes.as_mut_ptr().cast(), bytes.len(), 0) };
            assert!(length >= 0);
            bytes.truncate(length as usize);
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
            bytes
        };
        let before = read("/proc/mounts");
        assert_eq!(before, read("/proc/self/mounts"));
        let host = root.join("proc-mount-link-test");
        std::fs::create_dir_all(&host).unwrap();
        crate::vfs::add_mount(
            "/mnt/proc-link-test",
            host.clone(),
            crate::vfs::Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        let after = read("/proc/mounts");
        assert_eq!(after, read("/proc/self/mounts"));
        assert_ne!(before, after);
        assert!(
            String::from_utf8(after)
                .unwrap()
                .contains(" /mnt/proc-link-test tmpfs ")
        );
        assert_eq!(
            super::readlink(b"/proc/mounts").unwrap().unwrap(),
            b"self/mounts"
        );
        assert_eq!(
            super::open("/proc/mounts", 1, libc::O_WRONLY),
            Some(-(crate::errno::EACCES as i64))
        );
        crate::vfs::remove_mount("/mnt/proc-link-test").unwrap();
        assert_eq!(read("/proc/mounts"), before);
        std::fs::remove_dir(host).unwrap();
    }

    #[test]
    fn stat_of_proc_and_an_fd_directory_lists_neither() {
        let (_view, _) = crate::vfs::test_view();
        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
        super::super::fd_visibility::publish(fd, false).unwrap();
        let me = super::pid();
        let names = |node: Option<super::Node>| match node {
            Some(super::Node::Dir(entries)) => entries
                .iter()
                .map(|e| String::from_utf8_lossy(&e.name).into_owned())
                .collect::<Vec<_>>(),
            _ => panic!("not a directory"),
        };
        let fds = format!("/proc/{me}/fd");
        assert!(names(super::node(&fds)).contains(&fd.to_string()));
        assert!(names(super::node("/proc")).contains(&me.to_string()));
        assert!(names(super::node_listed(&fds, false)).is_empty());
        assert!(!names(super::node_listed("/proc", false)).contains(&me.to_string()));
        for path in ["/proc", fds.as_str()] {
            let st = super::stat(path, true).unwrap().unwrap();
            assert_eq!(st.st_mode, libc::S_IFDIR | 0o555, "{path}");
        }
        super::super::fd_visibility::withdraw(fd).unwrap();
    }

    fn read_all(fd: i32) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        // SAFETY: a local buffer.
        let n = unsafe { libc::pread(fd, b.as_mut_ptr().cast(), b.len(), 0) };
        b.truncate(n.max(0) as usize);
        b
    }

    #[test]
    fn a_closed_content_file_is_reused_only_when_nothing_else_holds_it() {
        // Its own process: a child another test spawns or forks meanwhile
        // inherits the file and rightly keeps it out of the pool.
        if super::super::fdtab::isolated_kernel_test(
            "sys::procfs::tests::a_closed_content_file_is_reused_only_when_nothing_else_holds_it",
        ) {
            return;
        }
        let pool = super::Pool(std::sync::Mutex::new(Vec::new()));
        let ino = |fd: i32| {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: a local buffer.
            unsafe { libc::fstat(fd, &mut st) };
            st.st_ino
        };
        // SAFETY: plain fd calls on our own fds.
        let close = |fd: i32| unsafe { libc::close(fd) };
        let a = super::fresh(b"a longer first content\n").unwrap();
        let first = ino(a);
        // SAFETY: plain dup of our fd.
        let dup = unsafe { libc::dup(a) };
        // Still held by `dup`: not pooled.
        pool.recycle(a);
        close(a);
        assert!(pool.reuse(b"b\n", true).is_none());
        assert_eq!(read_all(dup), b"a longer first content\n");
        // The last fd: pooled and reused, holding exactly its new contents,
        // at offset 0, visible and not close-on-exec as asked.
        pool.recycle(dup);
        close(dup);
        let c = pool.reuse(b"c\n", false).unwrap();
        assert_eq!(ino(c), first);
        assert_eq!(read_all(c), b"c\n");
        // SAFETY: plain fcntl/lseek on our fd.
        unsafe {
            assert_eq!(libc::lseek(c, 0, libc::SEEK_CUR), 0);
            assert_eq!(libc::fcntl(c, libc::F_GETFD) & libc::FD_CLOEXEC, 0);
        }
        assert!(!crate::sys::fdtab::is_hidden(c));
        // A mapped one is not reused: the mapping still shows its contents.
        crate::sys::fdtab::insert(c, crate::sys::fdtab::Kind::Content);
        super::on_mmap(c);
        crate::sys::fdtab::on_close(c);
        pool.recycle(c);
        close(c);
        assert!(pool.reuse(b"d\n", true).is_none());
    }

    #[test]
    fn guest_argv_skips_linux_run_options() {
        let argv = |s: &str| {
            s.split(' ')
                .map(|a| a.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        let run = "/t/linux-run --root /r --path-map /m --inherit-env --binder b --stdio-null \
                   --no-cache --trace /system/bin/servicemanager -v";
        assert_eq!(
            super::guest_argv(argv(run)),
            argv("/system/bin/servicemanager -v")
        );
        assert!(super::guest_argv(argv("/t/linux-run --root /r --fork-child 7")).is_empty());
        assert_eq!(
            super::guest_argv(argv("/bin/sh -c x")),
            argv("/bin/sh -c x")
        );
    }

    /// The host's gzip reads `/proc/config.gz` back verbatim.
    #[test]
    fn config_gz_is_gzip() {
        let big: String = super::KERNEL_CONFIG.repeat(200);
        for data in ["", super::KERNEL_CONFIG, big.as_str()] {
            let mut child = Command::new("gzip")
                .arg("-dc")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let gz = super::gzip_stored(data.as_bytes());
            child.stdin.take().unwrap().write_all(&gz).unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success());
            assert_eq!(out.stdout, data.as_bytes());
        }
    }

    /// Linux `mounts_poll`: the fd is a regular file that poll can watch.
    /// `EPOLLERR|EPOLLPRI` is one edge per mount-table change, shared by
    /// dup, and a later read shows the new table. Another proc file stays
    /// EPERM. Init's MountHandler registers exactly those two bits.
    #[test]
    fn proc_mounts_polls_once_per_mount_change() {
        let (_view, root) = crate::vfs::test_view();
        let ep = crate::sys::epoll::epoll_create1([0; 6]);
        assert!(ep >= 0, "epoll {ep}");
        let stat = super::open("/proc/self/stat", 0, libc::O_RDONLY).unwrap();
        assert!(stat >= 0, "stat {stat}");
        let interest = [0xau64, 0x4d];
        let add = |ep: i64, fd: i64| {
            crate::sys::epoll::epoll_ctl([
                ep as u64,
                1,
                fd as u64,
                interest.as_ptr() as u64,
                0,
                0,
            ])
        };
        assert_eq!(add(ep, stat), -(crate::errno::EPERM as i64));
        assert_eq!(crate::sys::fs::close([stat as u64, 0, 0, 0, 0, 0]), 0);

        let mounts = super::open("/proc/mounts", 0, libc::O_RDONLY).unwrap();
        let info = super::open("/proc/self/mountinfo", 0, libc::O_RDONLY).unwrap();
        assert!(mounts >= 0 && info >= 0 && mounts != info);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(mounts as i32, &mut st) }, 0);
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFREG);
        assert!(matches!(
            crate::sys::fdtab::get(mounts as i32),
            Some(crate::sys::fdtab::Kind::Content)
        ));
        assert_eq!(add(ep, info), 0);
        assert_eq!(add(ep, mounts), 0);
        let wait = |ms: i64| {
            let mut out = [0u64; 2];
            let n = crate::sys::epoll::epoll_pwait([
                ep as u64,
                out.as_mut_ptr() as u64,
                1,
                ms as u64,
                0,
                0,
            ]);
            (n, out)
        };
        assert_eq!(wait(0).0, 0);
        let polled = |fd: i64, events: i16| {
            let mut entry = libc::pollfd {
                fd: fd as i32,
                events,
                revents: 0,
            };
            let mut timeout = [0i64; 2];
            let n = crate::sys::poll::ppoll([
                &mut entry as *mut libc::pollfd as u64,
                1,
                timeout.as_mut_ptr() as u64,
                0,
                0,
                0,
            ]);
            (n, entry.revents)
        };
        assert_eq!(polled(mounts, 0x2), (0, 0));
        let words = (mounts as usize + 1).div_ceil(64);
        let mut read = vec![0u64; words];
        let mut write = vec![0u64; words];
        let mut exc = vec![0u64; words];
        exc[(mounts as usize) / 64] |= 1u64 << ((mounts as usize) % 64);
        let mut timeout = [0i64; 2];
        assert_eq!(
            crate::sys::poll::pselect6([
                mounts as u64 + 1,
                read.as_ptr() as u64,
                write.as_ptr() as u64,
                exc.as_mut_ptr() as u64,
                timeout.as_mut_ptr() as u64,
                0,
            ]),
            0
        );
        assert_eq!(polled(mounts, 0x1 | 0x40), (1, 0x1 | 0x40));
        assert_eq!(wait(0).0, 0);

        let copied = crate::sys::fs::dup([mounts as u64, 0, 0, 0, 0, 0]);
        let dupfd = crate::sys::fs::fcntl([mounts as u64, 0, 0, 0, 0, 0]);
        assert!(copied >= 0 && dupfd >= 0 && copied != dupfd && copied != mounts);
        let ep2 = crate::sys::epoll::epoll_create1([0; 6]);
        assert_eq!(add(ep2, dupfd), 0);
        assert_eq!(crate::sys::fs::close([ep2 as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(crate::sys::fs::close([dupfd as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(crate::sys::fs::close([info as u64, 0, 0, 0, 0, 0]), 0);

        let mount_at = |name: &str| {
            let host = root.join(name);
            std::fs::create_dir_all(&host).unwrap();
            let guest = format!("/mnt/{name}");
            crate::vfs::add_mount(
                &guest,
                host,
                crate::vfs::Area::Writable,
                "tmpfs",
                "tmpfs",
            )
            .unwrap();
            guest
        };
        let names = ["mount-poll-a", "mount-poll-b", "mount-poll-c", "mount-poll-d"];
        struct Cleanup(Vec<String>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for guest in &self.0 {
                    let _ = crate::vfs::remove_mount(guest);
                }
            }
        }
        let mut cleanup = Cleanup(Vec::new());
        let root_thread = root.clone();
        let added = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let host = root_thread.join("mount-poll-a");
            std::fs::create_dir_all(&host).unwrap();
            crate::vfs::add_mount(
                "/mnt/mount-poll-a",
                host,
                crate::vfs::Area::Writable,
                "tmpfs",
                "tmpfs",
            )
            .unwrap();
        });
        let (n, out) = wait(2_000);
        added.join().unwrap();
        cleanup.0.push("/mnt/mount-poll-a".into());
        assert_eq!(n, 1, "epoll did not observe the mount");
        assert_eq!(out[0] & 0xa, 0xa);
        assert_eq!(out[0] & 0x1, 0);
        assert_eq!(out[1], 0x4d);
        assert_eq!(wait(0).0, 0);
        assert_eq!(polled(copied, 0x2), (0, 0));

        let mut bytes = vec![0u8; 65536];
        let length = crate::sys::fs::pread64([
            mounts as u64,
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        ]);
        assert!(length > 0);
        bytes.truncate(length as usize);
        assert!(String::from_utf8(bytes).unwrap().contains(" /mnt/mount-poll-a "));

        cleanup.0.push(mount_at("mount-poll-b"));
        assert_eq!(polled(copied, 0x2), (1, 0x2 | 0x8));
        assert_eq!(wait(0).0, 0);
        assert_eq!(crate::sys::fs::close([copied as u64, 0, 0, 0, 0, 0]), 0);
        cleanup.0.push(mount_at("mount-poll-c"));
        let (n, out) = wait(0);
        assert_eq!((n, out[0] & 0xa, out[1]), (1, 0xa, 0x4d));
        assert_eq!(crate::sys::fs::close([mounts as u64, 0, 0, 0, 0, 0]), 0);
        cleanup.0.push(mount_at("mount-poll-d"));
        assert_eq!(wait(0).0, 0);
        let again = super::open("/proc/mounts", 0, libc::O_RDONLY).unwrap();
        assert_eq!(add(ep, again), 0);
        assert_eq!(wait(0).0, 0);
        let mut bytes = vec![0u8; 65536];
        let length = crate::sys::fs::pread64([
            again as u64,
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        ]);
        assert!(length > 0);
        bytes.truncate(length as usize);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(" /mnt/mount-poll-d "));
        assert_eq!(crate::sys::fs::close([again as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(crate::sys::fs::close([ep as u64, 0, 0, 0, 0, 0]), 0);
        drop(cleanup);
        for name in names {
            let _ = std::fs::remove_dir(root.join(name));
        }
    }

    fn mount_at(root: &std::path::Path, name: &str) -> String {
        let host = root.join(name);
        std::fs::create_dir_all(&host).unwrap();
        let guest = format!("/mnt/{name}");
        crate::vfs::add_mount(
            &guest,
            host,
            crate::vfs::Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        guest
    }

    fn pri(fd: i64) -> (i64, i16) {
        let mut entry = libc::pollfd {
            fd: fd as i32,
            events: 0x2,
            revents: 0,
        };
        let timeout = [0i64; 2];
        let n = crate::sys::poll::ppoll([
            &mut entry as *mut libc::pollfd as u64,
            1,
            timeout.as_ptr() as u64,
            0,
            0,
            0,
        ]);
        (n, entry.revents)
    }

    /// `ep_insert` polls the file. `mounts_poll` consumes a change between
    /// open and ADD, and `ep_send_events` polls again, so that edge is not
    /// delivered. `EPOLLIN` is the current state: once for `EPOLLET`, on
    /// every wait when level-triggered.
    #[test]
    fn proc_mounts_epoll_insert_observes_the_open_file() {
        let (_view, root) = crate::vfs::test_view();
        struct Cleanup(Vec<String>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for guest in &self.0 {
                    let _ = crate::vfs::remove_mount(guest);
                }
            }
        }
        let mut cleanup = Cleanup(Vec::new());
        let mounts = super::open("/proc/mounts", 0, libc::O_RDONLY).unwrap();
        let ep = crate::sys::epoll::epoll_create1([0; 6]);
        cleanup.0.push(mount_at(&root, "mount-insert-a"));
        let interest = [0xau64, 0x11];
        assert_eq!(
            crate::sys::epoll::epoll_ctl([
                ep as u64,
                1,
                mounts as u64,
                interest.as_ptr() as u64,
                0,
                0,
            ]),
            0
        );
        assert_eq!(pri(mounts), (0, 0));
        let wait = |ep: i64, ms: i64| {
            let mut out = [0u64; 2];
            let n = crate::sys::epoll::epoll_pwait([
                ep as u64,
                out.as_mut_ptr() as u64,
                1,
                ms as u64,
                0,
                0,
            ]);
            (n, out)
        };
        assert_eq!(wait(ep, 0).0, 0);
        cleanup.0.push(mount_at(&root, "mount-insert-b"));
        let (n, out) = wait(ep, 0);
        assert_eq!((n, out[0] & 0xa, out[1]), (1, 0xa, 0x11));
        assert_eq!(wait(ep, 0).0, 0);

        let copied = crate::sys::fs::dup([mounts as u64, 0, 0, 0, 0, 0]);
        let edge = crate::sys::epoll::epoll_create1([0; 6]);
        let et = [1u64 | (1 << 31), 0x22];
        assert_eq!(
            crate::sys::epoll::epoll_ctl([
                edge as u64,
                1,
                copied as u64,
                et.as_ptr() as u64,
                0,
                0,
            ]),
            0
        );
        let (n, out) = wait(edge, 0);
        assert_eq!(n, 1);
        assert_eq!(out[0] & (0x1 | 0x40), 0x1 | 0x40);
        assert_eq!(out[0] & 0x2, 0);
        assert_eq!(out[1], 0x22);
        assert_eq!(wait(edge, 0).0, 0);
        cleanup.0.push(mount_at(&root, "mount-insert-c"));
        let (n, out) = wait(edge, 0);
        assert_eq!(n, 1);
        assert_eq!(out[0] & (0x1 | 0x40 | 0x8), 0x1 | 0x40 | 0x8);
        assert_eq!(wait(edge, 0).0, 0);

        let level_fd = super::open("/proc/self/mounts", 0, libc::O_RDONLY).unwrap();
        let level = crate::sys::epoll::epoll_create1([0; 6]);
        let inn = [1u64, 0x33];
        assert_eq!(
            crate::sys::epoll::epoll_ctl([
                level as u64,
                1,
                level_fd as u64,
                inn.as_ptr() as u64,
                0,
                0,
            ]),
            0
        );
        for _ in 0..2 {
            let (n, out) = wait(level, 0);
            assert_eq!(n, 1);
            assert_eq!(out[0] & (0x1 | 0x40), 0x1 | 0x40);
            assert_eq!(out[1], 0x33);
        }
        for fd in [mounts, copied, level_fd, ep, edge, level] {
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
        drop(cleanup);
        for name in ["mount-insert-a", "mount-insert-b", "mount-insert-c"] {
            let _ = std::fs::remove_dir(root.join(name));
        }
    }

    /// Fork copies the open file's cursor and this process's generation.
    /// dup shares that copy. exec of a non-`CLOEXEC` mount fd does too.
    /// Closing one fd leaves the other.
    #[test]
    fn proc_mounts_fork_keeps_the_poll_cursor() {
        let (_view, root) = crate::vfs::test_view();
        struct Cleanup(Vec<String>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for guest in &self.0 {
                    let _ = crate::vfs::remove_mount(guest);
                }
            }
        }
        let mut cleanup = Cleanup(Vec::new());
        let mounts = super::open("/proc/mounts", 0, libc::O_RDONLY).unwrap();
        let copied = crate::sys::fs::dup([mounts as u64, 0, 0, 0, 0, 0]);
        cleanup.0.push(mount_at(&root, "mount-fork-a"));
        assert_eq!(pri(mounts), (1, 0x2 | 0x8));
        assert_eq!(pri(copied), (0, 0));

        let save = || {
            let mut writer = crate::sys::fork_state::Writer::default();
            crate::sys::fdtab::fork_save(&mut writer);
            writer.into_bytes()
        };
        let restore = |blob: &[u8]| {
            super::detach_mount_polls();
            crate::vfs::restore_mount_event(0);
            let mut reader = crate::sys::fork_state::Reader::new(blob);
            crate::sys::fdtab::fork_restore(&mut reader);
            assert!(reader.ok(), "{}", reader.diagnostic());
        };
        let caught_up = save();
        super::detach_mount_polls();
        let ep = crate::sys::epoll::epoll_create1([0; 6]);
        let interest = [0xau64, 1];
        assert_eq!(
            crate::sys::epoll::epoll_ctl([
                ep as u64,
                1,
                mounts as u64,
                interest.as_ptr() as u64,
                0,
                0,
            ]),
            -(crate::errno::EPERM as i64)
        );
        restore(&caught_up);
        assert_eq!(pri(mounts), (0, 0));
        assert_eq!(pri(copied), (0, 0));
        assert_eq!(
            crate::sys::epoll::epoll_ctl([
                ep as u64,
                1,
                mounts as u64,
                interest.as_ptr() as u64,
                0,
                0,
            ]),
            0
        );
        assert_eq!(crate::sys::fs::close([ep as u64, 0, 0, 0, 0, 0]), 0);

        cleanup.0.push(mount_at(&root, "mount-fork-b"));
        let pending = save();
        restore(&pending);
        assert_eq!(pri(mounts), (1, 0x2 | 0x8));
        assert_eq!(pri(copied), (0, 0));
        assert_eq!(crate::sys::fs::close([mounts as u64, 0, 0, 0, 0, 0]), 0);
        assert!(super::is_mount_poll(copied as i32));
        cleanup.0.push(mount_at(&root, "mount-fork-c"));
        assert_eq!(pri(copied), (1, 0x2 | 0x8));

        let again = crate::sys::fs::dup([copied as u64, 0, 0, 0, 0, 0]);
        cleanup.0.push(mount_at(&root, "mount-fork-d"));
        let text = crate::sys::fdtab::regular_exec_text().unwrap();
        let mounts_only = text
            .lines()
            .filter(|line| line.starts_with("mounts\t") || line.starts_with("mountevent\t"))
            .collect::<Vec<_>>()
            .join("\n");
        super::detach_mount_polls();
        crate::vfs::restore_mount_event(0);
        crate::sys::fdtab::restore_regular_exec(&mounts_only).unwrap();
        assert_eq!(pri(copied), (1, 0x2 | 0x8));
        assert_eq!(pri(again), (0, 0));
        assert_eq!(crate::sys::fs::close([copied as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(crate::sys::fs::close([again as u64, 0, 0, 0, 0, 0]), 0);
        drop(cleanup);
        for name in ["mount-fork-a", "mount-fork-b", "mount-fork-c", "mount-fork-d"] {
            let _ = std::fs::remove_dir(root.join(name));
        }
    }

    /// A missing wake pipe fails a blocking wait. It does not invent an
    /// edge, and a generation that already moved is still one edge.
    #[test]
    fn proc_mounts_wake_failure_reports_the_pipe_errno() {
        let (_view, root) = crate::vfs::test_view();
        struct Arm;
        impl Drop for Arm {
            fn drop(&mut self) {
                crate::vfs::testing_fail_mount_wake(false);
            }
        }
        let _arm = Arm;
        struct Cleanup(Vec<String>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for guest in &self.0 {
                    let _ = crate::vfs::remove_mount(guest);
                }
            }
        }
        let mut cleanup = Cleanup(Vec::new());
        let mounts = super::open("/proc/mounts", 0, libc::O_RDONLY).unwrap();
        let ep = crate::sys::epoll::epoll_create1([0; 6]);
        let interest = [0xau64, 0x44];
        assert_eq!(
            crate::sys::epoll::epoll_ctl([
                ep as u64,
                1,
                mounts as u64,
                interest.as_ptr() as u64,
                0,
                0,
            ]),
            0
        );
        crate::vfs::testing_fail_mount_wake(true);
        cleanup.0.push(mount_at(&root, "mount-wake-a"));
        let mut out = [0u64; 2];
        let n = crate::sys::epoll::epoll_pwait([
            ep as u64,
            out.as_mut_ptr() as u64,
            1,
            0,
            0,
            0,
        ]);
        assert_eq!((n, out[0] & 0xa, out[1]), (1, 0xa, 0x44));
        assert_eq!(
            crate::sys::epoll::epoll_pwait([ep as u64, out.as_mut_ptr() as u64, 1, 0, 0, 0]),
            0
        );
        assert_eq!(
            crate::sys::epoll::epoll_pwait([ep as u64, out.as_mut_ptr() as u64, 1, 200, 0, 0]),
            -(crate::errno::EMFILE as i64)
        );
        assert_eq!(pri(mounts), (0, 0));
        let mut entry = libc::pollfd {
            fd: mounts as i32,
            events: 0x2,
            revents: 0,
        };
        let timeout = [0i64, 200_000_000];
        assert_eq!(
            crate::sys::poll::ppoll([
                &mut entry as *mut libc::pollfd as u64,
                1,
                timeout.as_ptr() as u64,
                0,
                0,
                0,
            ]),
            -(crate::errno::EMFILE as i64)
        );
        crate::vfs::testing_fail_mount_wake(false);
        cleanup.0.push(mount_at(&root, "mount-wake-b"));
        let n = crate::sys::epoll::epoll_pwait([
            ep as u64,
            out.as_mut_ptr() as u64,
            1,
            0,
            0,
            0,
        ]);
        assert_eq!((n, out[0] & 0xa, out[1]), (1, 0xa, 0x44));
        assert_eq!(crate::sys::fs::close([mounts as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(crate::sys::fs::close([ep as u64, 0, 0, 0, 0, 0]), 0);
        drop(cleanup);
        for name in ["mount-wake-a", "mount-wake-b"] {
            let _ = std::fs::remove_dir(root.join(name));
        }
    }

    fn ns_text(path: &str) -> String {
        let bytes = super::readlink(path.as_bytes()).unwrap().unwrap();
        String::from_utf8(bytes).unwrap()
    }

    fn mounts_text() -> String {
        let fd = super::open("/proc/mounts", 0, libc::O_RDONLY).unwrap();
        let mut bytes = vec![0u8; 65536];
        let n = crate::sys::fs::pread64([
            fd as u64,
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        ]);
        assert!(n > 0);
        assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        bytes.truncate(n as usize);
        String::from_utf8(bytes).unwrap()
    }

    /// Init's `SetupMountNamespaces`: the bootstrap fd stays the namespace
    /// from before `unshare`, and `setns` switches back to it. `setns` of a
    /// bad fd is `EBADF`, of the wrong kind or `nstype` is `EINVAL`, and
    /// without `CAP_SYS_ADMIN` or `CAP_SYS_CHROOT` is `EPERM`.
    #[test]
    fn mount_namespace_setns_switches_the_named_table() {
        let (_view, root) = crate::vfs::test_view();
        struct Cred(crate::sys::cred::Identity);
        impl Drop for Cred {
            fn drop(&mut self) {
                crate::sys::cred::init(self.0.clone(), None);
            }
        }
        let _cred = Cred(crate::sys::cred::current());
        let boot = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        assert!(boot >= 0);
        let boot_link = ns_text("/proc/self/ns/mnt");
        assert!(boot_link.starts_with("mnt:[") && boot_link.ends_with(']'));
        assert_eq!(ns_text(&format!("/proc/self/fd/{boot}")), boot_link);
        let pid = super::pid();
        let by_pid = super::open(&format!("/proc/{pid}/ns/mnt"), 0, libc::O_RDONLY).unwrap();
        assert!(by_pid >= 0);
        assert_eq!(ns_text(&format!("/proc/{pid}/ns/mnt")), boot_link);
        assert_eq!(crate::sys::fs::close([by_pid as u64, 0, 0, 0, 0, 0]), 0);

        assert_eq!(
            crate::sys::mount::unshare([0x20000, 0, 0, 0, 0, 0]),
            0
        );
        let default_ns = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        let default_link = ns_text("/proc/self/ns/mnt");
        assert_ne!(default_link, boot_link);
        assert_eq!(ns_text(&format!("/proc/self/fd/{default_ns}")), default_link);

        // The mounts below name the namespace. `/` is shared until told
        // otherwise, so this tree is made private before them.
        crate::vfs::set_mount_propagation("/", (1 << 18) | 0x4000).unwrap();
        let host = root.join("ns-default");
        std::fs::create_dir_all(&host).unwrap();
        crate::vfs::add_mount(
            "/mnt/ns-default",
            host.clone(),
            crate::vfs::Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        assert!(mounts_text().contains(" /mnt/ns-default "));

        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        assert_eq!(ns_text("/proc/self/ns/mnt"), boot_link);
        assert!(!mounts_text().contains(" /mnt/ns-default "));
        let host = root.join("ns-boot");
        std::fs::create_dir_all(&host).unwrap();
        crate::vfs::add_mount(
            "/mnt/ns-boot",
            host,
            crate::vfs::Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        let text = mounts_text();
        assert!(text.contains(" /mnt/ns-boot "));
        assert!(!text.contains(" /mnt/ns-default "));

        let copied = crate::sys::fs::dup([boot as u64, 0, 0, 0, 0, 0]);
        assert_eq!(crate::sys::fs::close([boot as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(ns_text(&format!("/proc/self/fd/{copied}")), boot_link);
        assert_eq!(
            crate::sys::mount::setns([default_ns as u64, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(ns_text("/proc/self/ns/mnt"), default_link);
        let text = mounts_text();
        assert!(text.contains(" /mnt/ns-default "));
        assert!(!text.contains(" /mnt/ns-boot "));
        assert_eq!(
            crate::sys::mount::setns([copied as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        assert_eq!(ns_text("/proc/self/ns/mnt"), boot_link);
        assert!(mounts_text().contains(" /mnt/ns-boot "));

        assert_eq!(
            crate::sys::mount::setns([(-1i32) as u64, 0x20000, 0, 0, 0, 0]),
            -(crate::errno::EBADF as i64)
        );
        let gone = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        assert_eq!(crate::sys::fs::close([gone as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(
            crate::sys::mount::setns([gone as u64, 0x20000, 0, 0, 0, 0]),
            -(crate::errno::EBADF as i64)
        );
        let mounts = super::open("/proc/mounts", 0, libc::O_RDONLY).unwrap();
        assert_eq!(
            crate::sys::mount::setns([mounts as u64, 0x20000, 0, 0, 0, 0]),
            -(crate::errno::EINVAL as i64)
        );
        assert_eq!(
            crate::sys::mount::setns([copied as u64, 0x2000_0000, 0, 0, 0, 0]),
            -(crate::errno::EINVAL as i64)
        );

        let mut weak = crate::sys::cred::current();
        weak.cap_eff &= !(1 << 21);
        crate::sys::cred::init(weak, None);
        assert_eq!(
            crate::sys::mount::setns([default_ns as u64, 0x20000, 0, 0, 0, 0]),
            -(crate::errno::EPERM as i64)
        );
        let mut admin = _cred.0.clone();
        admin.cap_eff &= !(1 << 18);
        crate::sys::cred::init(admin, None);
        assert_eq!(
            crate::sys::mount::setns([default_ns as u64, 0, 0, 0, 0, 0]),
            -(crate::errno::EPERM as i64)
        );
        crate::sys::cred::init(_cred.0.clone(), None);
        assert_eq!(
            crate::sys::mount::setns([default_ns as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        let _ = crate::vfs::remove_mount("/mnt/ns-default");
        assert_eq!(
            crate::sys::mount::setns([copied as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        let _ = crate::vfs::remove_mount("/mnt/ns-boot");
        for fd in [default_ns, copied, mounts] {
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
        let _ = std::fs::remove_dir(root.join("ns-default"));
        let _ = std::fs::remove_dir(root.join("ns-boot"));
    }

    /// `mntns_install` rejects a shared `fs_struct` (`users != 1`), including
    /// `setns` back into the namespace the caller is already in.
    #[test]
    fn mount_namespace_setns_with_a_shared_fs_is_einval() {
        let (_view, _root) = crate::vfs::test_view();
        let share = crate::vfs::testing_share_fs();
        let boot = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            -(crate::errno::EINVAL as i64)
        );
        drop(share);
        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        assert_eq!(crate::sys::fs::close([boot as u64, 0, 0, 0, 0, 0]), 0);
    }

    /// vendor_init's fork is a new process. The inherited default-namespace
    /// fd is unbound until the image reinstalls it, which is the `EINVAL`
    /// from `mount_namespace_of`. Fork without `CLONE_FS` leaves `users == 1`
    /// even when the parent still has a shared `fs_struct`, and the child's
    /// `/proc/self/ns/mnt` stays the parent's current (bootstrap) inode.
    #[test]
    fn fork_child_rebinds_inherited_namespace_and_keeps_a_private_fs() {
        let (_view, root) = crate::vfs::test_view();
        let boot = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        let boot_link = ns_text("/proc/self/ns/mnt");
        assert_eq!(crate::sys::mount::unshare([0x20000, 0, 0, 0, 0, 0]), 0);
        let default_ns = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        let default_link = ns_text("/proc/self/ns/mnt");
        assert_ne!(default_link, boot_link);
        // The mounts below name the namespace. `/` is shared until told
        // otherwise, so this tree is made private before them.
        crate::vfs::set_mount_propagation("/", (1 << 18) | 0x4000).unwrap();
        let host = root.join("ns-default");
        std::fs::create_dir_all(&host).unwrap();
        crate::vfs::add_mount(
            "/mnt/ns-default",
            host.clone(),
            crate::vfs::Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        assert_eq!(ns_text("/proc/self/ns/mnt"), boot_link);
        let host = root.join("ns-boot");
        std::fs::create_dir_all(&host).unwrap();
        crate::vfs::add_mount(
            "/mnt/ns-boot",
            host.clone(),
            crate::vfs::Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        let image = crate::vfs::capture_fork_namespaces(false);
        let inherited = super::mount_namespace_fds();
        let share = crate::vfs::testing_share_fs();
        assert!(crate::vfs::fs_is_shared());
        assert_eq!(
            crate::sys::mount::setns([default_ns as u64, 0x20000, 0, 0, 0, 0]),
            -(crate::errno::EINVAL as i64)
        );
        crate::vfs::testing_forget_other_namespaces();
        super::testing_clear_namespace_fds();
        assert_eq!(
            crate::sys::mount::setns([default_ns as u64, 0x20000, 0, 0, 0, 0]),
            -(crate::errno::EINVAL as i64)
        );
        assert!(crate::vfs::install_fork_namespaces(&image));
        for (fd, ino) in inherited {
            let ns = crate::vfs::mount_namespace(ino).expect("restored namespace");
            super::bind_mount_namespace(fd, ns);
        }
        assert!(!crate::vfs::fs_is_shared());
        assert_eq!(ns_text("/proc/self/ns/mnt"), boot_link);
        assert_eq!(ns_text(&format!("/proc/self/fd/{default_ns}")), default_link);
        assert_eq!(
            crate::sys::mount::setns([default_ns as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        assert_eq!(ns_text("/proc/self/ns/mnt"), default_link);
        let text = mounts_text();
        assert!(text.contains(" /mnt/ns-default "));
        assert!(!text.contains(" /mnt/ns-boot "));
        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        assert_eq!(ns_text("/proc/self/ns/mnt"), boot_link);
        assert!(mounts_text().contains(" /mnt/ns-boot "));
        drop(share);
        let _ = crate::vfs::remove_mount("/mnt/ns-boot");
        assert_eq!(
            crate::sys::mount::setns([default_ns as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        let _ = crate::vfs::remove_mount("/mnt/ns-default");
        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        for fd in [boot, default_ns] {
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
        let _ = std::fs::remove_dir(root.join("ns-default"));
        let _ = std::fs::remove_dir(root.join("ns-boot"));
    }

    /// A plain `/proc` content file is an open file description. Fork keeps
    /// the fd; it is not only the mount-poll and namespace fds that are.
    #[test]
    fn fork_save_keeps_a_plain_proc_content_fd() {
        let _view = crate::vfs::test_view();
        let before = fd_entry_count();
        let fd = super::open("/proc/meminfo", 0, libc::O_RDONLY).unwrap();
        assert!(fd >= 0);
        assert!(matches!(
            super::fdtab::get(fd as i32),
            Some(super::fdtab::Kind::Content)
        ));
        assert_eq!(fd_entry_count(), before + 1);
        assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
    }

    fn fd_entry_count() -> u64 {
        let mut writer = super::super::fork::state::Writer::default();
        super::fdtab::fork_save(&mut writer);
        let bytes = writer.into_bytes();
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }

    /// vendor_init `setns` into the reconstructed default namespace, then
    /// `readlink("/proc/self/exe")`. The exe path is the executed file and
    /// does not move with the namespace. A fuse line whose origin is another
    /// namespace must not make that walk return `EIO`: the parked journal
    /// keeps its mount records. `mntns_install` sets the cwd to the
    /// namespace root.
    #[test]
    fn fork_setns_readlink_exe_uses_the_journal_records() {
        let (_view, _root) = crate::vfs::test_view();
        let previous_exe = (
            crate::sys::process::exe_guest_path(),
            crate::sys::process::exe_host_path(),
        );
        let previous_cwd = crate::vfs::cwd();
        crate::sys::process::set_exe("/system/bin/init".into(), "/system/bin/init".into());
        let boot = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        assert_eq!(crate::sys::mount::unshare([0x20000, 0, 0, 0, 0, 0]), 0);
        let default_ns = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        let journal = crate::vfs::mount_namespace_id().unwrap();
        let owner = aim_storage::mount_namespace::Namespace::open(
            crate::vfs::runtime_dir().unwrap(),
            &journal,
        )
        .unwrap();
        let state = owner.read().unwrap();
        assert!(
            state.mounts.iter().any(|mount| mount.guest == "/"),
            "default namespace journal has no root mount"
        );
        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        let image = crate::vfs::capture_fork_namespaces(false);
        let inherited = super::mount_namespace_fds();
        crate::vfs::testing_forget_other_namespaces();
        super::testing_clear_namespace_fds();
        assert!(crate::vfs::install_fork_namespaces(&image));
        for (fd, ino) in inherited {
            let ns = crate::vfs::mount_namespace(ino).expect("restored namespace");
            super::bind_mount_namespace(fd, ns);
        }
        let table = crate::vfs::runtime_dir().unwrap().join("fuse-mounts");
        let saved_table = std::fs::read(&table).ok();
        let line = [
            "/fuse-foreign-probe",
            "/var/empty",
            "src",
            "plain",
            "rw",
            "tmpfs",
            "",
            "not-this-namespace",
            "1",
            "1",
            "0",
            "0",
        ]
        .join("\t");
        std::fs::write(&table, format!("{line}\n")).unwrap();
        crate::vfs::set_cwd("/system".into());
        assert_eq!(
            crate::sys::mount::setns([default_ns as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        assert_eq!(crate::vfs::cwd(), "/");
        crate::vfs::refresh_fuse_mounts().expect("path walk after setns");
        let resolved = crate::vfs::resolve(
            crate::vfs::LINUX_AT_FDCWD,
            b"/proc/self/exe",
            false,
        )
        .expect("resolve /proc/self/exe");
        let bytes = super::readlink(resolved.guest.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(bytes, b"/system/bin/init");
        match saved_table {
            Some(bytes) => std::fs::write(&table, bytes).unwrap(),
            None => {
                let _ = std::fs::remove_file(&table);
            }
        }
        let _ = crate::vfs::remove_mount("/fuse-foreign-probe");
        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        crate::vfs::set_cwd(previous_cwd);
        crate::sys::process::set_exe(previous_exe.0, previous_exe.1);
        for fd in [boot, default_ns] {
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
    }

    /// `unshare(CLONE_NEWNS)` copies the caller's mount tree. It does not
    /// start an empty table. A file with no covering mount stays on the
    /// image root. A tmpfs mounted before the call, the way init covers
    /// `/linkerconfig` and `/apex` in `MountExtraFilesystems`, is in the
    /// copy and still hides the image file. Fork, `setns` into that
    /// namespace, and the exec replay (`load_own_mounts` of
    /// `own_mounts_text`) resolve the same hosts. `setns` sets cwd to `/`;
    /// these paths are absolute.
    #[test]
    fn fork_setns_exec_keeps_the_copied_mount_tree() {
        let (_view, dir) = crate::vfs::test_view();
        let image = dir.join("root");
        for rel in [
            "system/lib64/bootstrap",
            "system/bin",
            "linkerconfig",
            "apex/com.android.runtime/lib64/bionic",
        ] {
            std::fs::create_dir_all(image.join(rel)).unwrap();
        }
        std::fs::write(image.join("system/lib64/bootstrap/libc.so"), b"image-libc").unwrap();
        std::fs::write(image.join("system/bin/init"), b"image-init").unwrap();
        std::fs::write(image.join("linkerconfig/ld.config.txt"), b"image-config").unwrap();
        std::fs::write(
            image.join("apex/com.android.runtime/lib64/bionic/libc.so"),
            b"image-apex",
        )
        .unwrap();
        let paths = [
            "/linkerconfig/ld.config.txt",
            "/system/lib64/bootstrap/libc.so",
            "/system/bin/init",
            "/apex/com.android.runtime/lib64/bionic/libc.so",
        ];
        let startup: Vec<_> = paths
            .iter()
            .map(|guest| crate::vfs::lookup(guest))
            .collect();
        assert_eq!(startup[0].1, crate::vfs::Area::Image);
        assert_eq!(std::fs::read(&startup[0].0).unwrap(), b"image-config");
        assert_eq!(startup[1].1, crate::vfs::Area::Image);
        assert_eq!(std::fs::read(&startup[1].0).unwrap(), b"image-libc");
        assert_eq!(std::fs::read(&startup[3].0).unwrap(), b"image-apex");

        let linker_host = dir.join("tmpfs-linkerconfig");
        let apex_host = dir.join("tmpfs-apex");
        std::fs::create_dir_all(&linker_host).unwrap();
        std::fs::create_dir_all(&apex_host).unwrap();
        crate::vfs::add_mount(
            "/linkerconfig",
            linker_host.clone(),
            crate::vfs::Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        crate::vfs::add_mount(
            "/apex",
            apex_host.clone(),
            crate::vfs::Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        let covered: Vec<_> = paths
            .iter()
            .map(|guest| crate::vfs::lookup(guest))
            .collect();
        assert_eq!(covered[0].0, linker_host.join("ld.config.txt"));
        assert_eq!(covered[0].1, crate::vfs::Area::Writable);
        assert!(!covered[0].0.exists());
        assert_eq!(covered[1].0, startup[1].0);
        assert_eq!(std::fs::read(&covered[1].0).unwrap(), b"image-libc");
        assert_eq!(covered[2].0, startup[2].0);
        assert_eq!(covered[3].0, apex_host.join("com.android.runtime/lib64/bionic/libc.so"));
        assert!(!covered[3].0.exists());
        let listed = mounts_text();
        assert!(listed.contains(" /linkerconfig "));
        assert!(listed.contains(" /apex "));

        let boot = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        assert_eq!(crate::sys::mount::unshare([0x20000, 0, 0, 0, 0, 0]), 0);
        let copied: Vec<_> = paths
            .iter()
            .map(|guest| crate::vfs::lookup(guest))
            .collect();
        assert_eq!(copied, covered);
        let listed = mounts_text();
        assert!(
            listed.contains(" /linkerconfig ") && listed.contains(" /apex "),
            "unshare left a table without the pre-unshare mounts: {listed}"
        );
        let default_ns = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        let image = crate::vfs::capture_fork_namespaces(false);
        let inherited = super::mount_namespace_fds();
        crate::vfs::testing_forget_other_namespaces();
        super::testing_clear_namespace_fds();
        assert!(crate::vfs::install_fork_namespaces(&image));
        for (fd, ino) in inherited {
            let ns = crate::vfs::mount_namespace(ino).expect("restored namespace");
            super::bind_mount_namespace(fd, ns);
        }
        assert_eq!(
            crate::sys::mount::setns([default_ns as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        assert_eq!(crate::vfs::cwd(), "/");
        let after_setns: Vec<_> = paths
            .iter()
            .map(|guest| crate::vfs::lookup(guest))
            .collect();
        assert_eq!(after_setns, covered);
        let text = crate::vfs::own_mounts_text();
        assert!(text.contains("namespace-owner\t"));
        assert!(text.contains("/linkerconfig\t"));
        assert!(text.contains("/apex\t"));
        crate::vfs::load_own_mounts(&text).expect("exec mount replay");
        let after_exec: Vec<_> = paths
            .iter()
            .map(|guest| crate::vfs::lookup(guest))
            .collect();
        assert_eq!(after_exec, covered);
        assert_eq!(std::fs::read(&after_exec[1].0).unwrap(), b"image-libc");
        assert_eq!(std::fs::read(&after_exec[2].0).unwrap(), b"image-init");
        assert!(!after_exec[0].0.exists());
        assert!(!after_exec[3].0.exists());

        let _ = crate::vfs::remove_mount("/linkerconfig");
        let _ = crate::vfs::remove_mount("/apex");
        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        let _ = crate::vfs::remove_mount("/linkerconfig");
        let _ = crate::vfs::remove_mount("/apex");
        for fd in [boot, default_ns] {
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
        let _ = std::fs::remove_dir_all(dir.join("root/system"));
        let _ = std::fs::remove_dir_all(dir.join("root/linkerconfig"));
        let _ = std::fs::remove_dir_all(dir.join("root/apex"));
        let _ = std::fs::remove_dir_all(&linker_host);
        let _ = std::fs::remove_dir_all(&apex_host);
    }

    /// `unshare(CLONE_NEWCGROUP)` is not Linux's success. The flag is outside
    /// the mount-namespace mask, which is the unsupported-namespace answer
    /// (ADR 0012). Init continues after the `EINVAL`.
    #[test]
    fn unshare_clone_newcgroup_is_einval() {
        let _view = crate::vfs::test_view();
        assert_eq!(
            crate::sys::mount::unshare([0x200_0000, 0, 0, 0, 0, 0]),
            -(crate::errno::EINVAL as i64)
        );
    }

    /// Init's sequence with the property-service thread still alive:
    /// `unshare(CLONE_NEWNS)` unshares `fs`, the pre-unshare fd keeps its
    /// inode, and `setns` of that fd succeeds.
    #[test]
    fn mount_namespace_unshare_then_setns_with_another_thread() {
        let (_view, root) = crate::vfs::test_view();
        let share = crate::vfs::testing_share_fs();
        let boot = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        let boot_link = ns_text("/proc/self/ns/mnt");
        assert_eq!(ns_text(&format!("/proc/self/fd/{boot}")), boot_link);
        assert_eq!(share.namespace_link(), boot_link);

        assert_eq!(crate::sys::mount::unshare([0x20000, 0, 0, 0, 0, 0]), 0);
        let default_link = ns_text("/proc/self/ns/mnt");
        assert_ne!(default_link, boot_link);
        assert_eq!(ns_text(&format!("/proc/self/fd/{boot}")), boot_link);
        assert_eq!(share.namespace_link(), boot_link);
        let default_ns = super::open("/proc/self/ns/mnt", 0, libc::O_RDONLY).unwrap();
        assert_eq!(ns_text(&format!("/proc/self/fd/{default_ns}")), default_link);

        // The other thread stays in the bootstrap namespace. This tree is
        // made private so the mount is not a peer of that namespace.
        crate::vfs::set_mount_propagation("/", (1 << 18) | 0x4000).unwrap();
        let host = root.join("ns-other-thread");
        std::fs::create_dir_all(&host).unwrap();
        crate::vfs::add_mount(
            "/mnt/ns-other-thread",
            host.clone(),
            crate::vfs::Area::Writable,
            "tmpfs",
            "tmpfs",
        )
        .unwrap();
        assert!(mounts_text().contains(" /mnt/ns-other-thread "));
        assert!(!share.mounts_contain("/mnt/ns-other-thread"));

        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        assert_eq!(ns_text("/proc/self/ns/mnt"), boot_link);
        assert_eq!(ns_text(&format!("/proc/self/fd/{boot}")), boot_link);
        assert_eq!(share.namespace_link(), boot_link);
        assert!(!mounts_text().contains(" /mnt/ns-other-thread "));
        assert_eq!(
            crate::sys::mount::setns([(-1i32) as u64, 0x20000, 0, 0, 0, 0]),
            -(crate::errno::EBADF as i64)
        );

        assert_eq!(
            crate::sys::mount::setns([default_ns as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        let _ = crate::vfs::remove_mount("/mnt/ns-other-thread");
        assert_eq!(
            crate::sys::mount::setns([boot as u64, 0x20000, 0, 0, 0, 0]),
            0
        );
        drop(share);
        for fd in [boot, default_ns] {
            assert_eq!(crate::sys::fs::close([fd as u64, 0, 0, 0, 0, 0]), 0);
        }
        let _ = std::fs::remove_dir(host);
    }
}

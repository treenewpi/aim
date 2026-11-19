//! Three host processes, one binder driver.
//!
//! `aim-binder-proc` starts `daemon`, `serve` and `call` as separate
//! processes. The daemon is the same `Server` `aim-binderd` runs. `serve`
//! is the context manager. `call` sends one transaction, including the read
//! end of a pipe, and checks the reply. Each round prints the three pids.
//! `absent` looks up a name nobody checked in. `dead` transacts with no
//! context manager and must observe `BR_DEAD_REPLY`.
//!
//! `aim-binder-proc guest LINUX_RUN GUEST` is the guest-syscall check. Two
//! `linux-run` processes execute a synthetic AArch64 PIE (not an Android
//! library) that reaches the same daemon through `openat`, `mmap` and
//! `ioctl`. The trace gate is the completed leave line
//! `openat(-100, "/dev/binder", ...) = fd`, not the path string.
//! `android LINUX_RUN ROOT` runs the original reDroid `servicemanager`
//! and `service` from that root. The root's generated
//! `servicemanager.ready` property lets the original client finish its
//! wait and open the driver; the harness still requires the driver's
//! result and the client's own text. It prints their stdout and stops at
//! the first real failure. Acceptance is that run on Apple Silicon macOS/XNU,
//! with the host platform, page size, commit, pids, exit codes, and the
//! original transaction text. A Linux run is not that result. The
//! host-only subcommands stay as they are.
//!
//! An ioctl that is still blocked after 15s exits 101. This process raises
//! only its own soft `NOFILE` when the hard limit allows 4096.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use aim_binder_driver::uapi::*;
use aim_binder_driver::{Device, Errno};
use aim_binder_host::client::{BinderFile, Client, UserMemory};
use aim_binder_host::server::Server;

const ROUNDS: u32 = 3;
const WATCHDOG: Duration = Duration::from_secs(15);
const MAP: usize = 1 << 20;
const MARKER: u32 = 0x1122_3344;
const REPLY: u32 = 0x42;
const NOFILE: u64 = 4096;

struct Own;

impl UserMemory for Own {
    fn read(&mut self, address: u64, len: usize) -> Result<Vec<u8>, Errno> {
        Ok(unsafe { std::slice::from_raw_parts(address as *const u8, len) }.to_vec())
    }

    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Errno> {
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, data.len()) };
        Ok(())
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => orchestrate(),
        Some("daemon") => daemon(&need(&mut args)),
        Some("serve") => serve(&need(&mut args)),
        Some("call") => call(&need(&mut args)),
        Some("absent") => absent(&need(&mut args)),
        Some("dead") => dead(&need(&mut args)),
        Some("guest") => guest_orchestrate(args.next(), args.next()),
        Some("android") => android_orchestrate(args.next(), args.next()),
        _ => {
            eprintln!(
                "usage: aim-binder-proc [daemon|serve|call|absent|dead NAME]\n       \
                 aim-binder-proc guest LINUX_RUN GUEST\n       \
                 aim-binder-proc android LINUX_RUN ROOT"
            );
            ExitCode::from(2)
        }
    }
}

fn need(args: &mut impl Iterator<Item = String>) -> String {
    match args.next() {
        Some(name) => name,
        None => {
            eprintln!("aim-binder-proc: missing service name");
            std::process::exit(2);
        }
    }
}

fn raise_nofile(announce: bool) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } < 0 {
        eprintln!(
            "aim-binder-proc: getrlimit(NOFILE) failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(2);
    }
    if limit.rlim_cur >= NOFILE {
        if announce {
            eprintln!(
                "aim-binder-proc: NOFILE soft {} hard {}",
                limit.rlim_cur, limit.rlim_max
            );
        }
        return;
    }
    if limit.rlim_max >= NOFILE {
        let hard = limit.rlim_max;
        limit.rlim_cur = NOFILE;
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } == 0 {
            eprintln!(
                "aim-binder-proc: NOFILE soft raised for this process only to {NOFILE} (hard {hard})"
            );
            return;
        }
    }
    eprintln!(
        "aim-binder-proc: NOFILE soft {} hard {} is below {NOFILE}. For this process tree only: ulimit -Sn {NOFILE}",
        limit.rlim_cur, limit.rlim_max
    );
    std::process::exit(2);
}

fn daemon(name: &str) -> ExitCode {
    if let Err(error) = Server::start(name) {
        eprintln!("aim-binder-proc daemon: {error}");
        return ExitCode::from(1);
    }
    loop {
        std::thread::park();
    }
}

fn open_file(name: &str, euid: u32, context: &str) -> BinderFile {
    let client = Client::connect(name).unwrap_or_else(|| {
        eprintln!("aim-binder-proc: no daemon named {name}");
        std::process::exit(2);
    });
    let file = client
        .open(Device::Binder, false, true, euid, context)
        .unwrap_or_else(|error| {
            eprintln!("aim-binder-proc: open failed: {error}");
            std::process::exit(1);
        });
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            MAP,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        eprintln!("aim-binder-proc: mmap failed");
        std::process::exit(1);
    }
    if let Err(error) = file.mmap(base as u64, MAP as u64) {
        eprintln!("aim-binder-proc: binder mmap failed: {error}");
        std::process::exit(1);
    }
    file
}

fn serve(name: &str) -> ExitCode {
    raise_nofile(false);
    let file = open_file(name, 1000, "u:r:servicemanager:s0");
    let mut object = FlatBinderObject {
        kind: BINDER_TYPE_BINDER,
        flags: FLAT_BINDER_FLAG_ACCEPTS_FDS | FLAT_BINDER_FLAG_TXN_SECURITY_CTX,
        binder: 0x1234,
        cookie: 0x5678,
    }
    .encode();
    if let Err(error) = file.ioctl(
        1,
        BINDER_SET_CONTEXT_MGR_EXT,
        object.as_mut_ptr() as u64,
        &mut Own,
    ) {
        eprintln!("aim-binder-proc serve: context manager: {error}");
        return ExitCode::from(1);
    }
    let mut enter = Vec::new();
    cmd(&mut enter, BC_ENTER_LOOPER, &[]);
    if write_read(&file, &enter, false).is_err() {
        eprintln!("aim-binder-proc serve: enter looper failed");
        return ExitCode::from(1);
    }
    println!("ready");
    let _ = std::io::stdout().flush();
    let read = match write_read(&file, &[], true) {
        Ok(read) => read,
        Err(error) => {
            eprintln!("aim-binder-proc serve: read failed: {error}");
            return ExitCode::from(1);
        }
    };
    let Some((_, tr)) = returns(&read)
        .into_iter()
        .find(|(code, _)| *code == BR_TRANSACTION_SEC_CTX || *code == BR_TRANSACTION)
    else {
        eprintln!("aim-binder-proc serve: no transaction in {read:?}");
        return ExitCode::from(1);
    };
    let tr = tr.unwrap();
    if tr.code != 7 || tr.sender_euid != 10_001 {
        eprintln!(
            "aim-binder-proc serve: code {} euid {}",
            tr.code, tr.sender_euid
        );
        return ExitCode::from(1);
    }
    let (marker, fd_text) = unsafe {
        let marker = (tr.buffer as *const u32).read();
        let fd = ((tr.buffer + 16) as *const u32).read() as i32;
        let mut got = [0u8; 5];
        let n = libc::read(fd, got.as_mut_ptr().cast(), 5);
        (marker, (n == 5 && &got == b"hello").then_some("hello"))
    };
    if marker != MARKER || fd_text != Some("hello") {
        eprintln!("aim-binder-proc serve: marker {marker:#x} fd {fd_text:?}");
        return ExitCode::from(1);
    }
    let reply_data = REPLY.to_le_bytes();
    let reply = TransactionData {
        data_size: 4,
        buffer: reply_data.as_ptr() as u64,
        ..Default::default()
    };
    let mut write = Vec::new();
    cmd(&mut write, BC_FREE_BUFFER, &tr.buffer.to_le_bytes());
    cmd(&mut write, BC_REPLY, &reply.encode());
    if write_read(&file, &write, true).is_err() {
        eprintln!("aim-binder-proc serve: reply failed");
        return ExitCode::from(1);
    }
    println!("txn sender_pid={} fd=hello", tr.sender_pid);
    ExitCode::SUCCESS
}

fn call(name: &str) -> ExitCode {
    raise_nofile(false);
    let file = open_file(name, 10_001, "u:r:shell:s0");
    let mut pipe = [0i32; 2];
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
        eprintln!("aim-binder-proc call: pipe failed");
        return ExitCode::from(1);
    }
    if unsafe { libc::write(pipe[1], b"hello".as_ptr().cast(), 5) } != 5 {
        eprintln!("aim-binder-proc call: pipe write failed");
        return ExitCode::from(1);
    }
    unsafe { libc::close(pipe[1]) };
    let mut data = [0u8; 32];
    data[0..4].copy_from_slice(&MARKER.to_le_bytes());
    data[8..12].copy_from_slice(&BINDER_TYPE_FD.to_le_bytes());
    data[16..20].copy_from_slice(&(pipe[0] as u32).to_le_bytes());
    let offsets = 8u64.to_le_bytes();
    let tr = TransactionData {
        code: 7,
        data_size: data.len() as u64,
        offsets_size: 8,
        buffer: data.as_ptr() as u64,
        offsets: offsets.as_ptr() as u64,
        ..Default::default()
    };
    let mut write = Vec::new();
    cmd(&mut write, BC_TRANSACTION, &tr.encode());
    let mut read = match write_read(&file, &write, true) {
        Ok(read) => read,
        Err(error) => {
            eprintln!("aim-binder-proc call: transaction failed: {error}");
            return ExitCode::from(1);
        }
    };
    let reply = loop {
        if returns(&read)
            .iter()
            .any(|(code, _)| *code == BR_FAILED_REPLY || *code == BR_DEAD_REPLY)
        {
            eprintln!("aim-binder-proc call: driver returned a failed reply");
            return ExitCode::from(1);
        }
        if let Some((_, tr)) = returns(&read)
            .into_iter()
            .find(|(code, _)| *code == BR_REPLY)
        {
            break tr.unwrap();
        }
        read = match write_read(&file, &[], true) {
            Ok(read) => read,
            Err(error) => {
                eprintln!("aim-binder-proc call: read failed: {error}");
                return ExitCode::from(1);
            }
        };
    };
    let value = unsafe { (reply.buffer as *const u32).read() };
    if value != REPLY {
        eprintln!("aim-binder-proc call: reply {value:#x}");
        return ExitCode::from(1);
    }
    println!("reply {value:#x} pid={}", std::process::id());
    ExitCode::SUCCESS
}

fn absent(name: &str) -> ExitCode {
    if Client::connect(name).is_some() {
        eprintln!("aim-binder-proc absent: {name} is registered");
        return ExitCode::from(1);
    }
    println!("absent");
    ExitCode::SUCCESS
}

fn dead(name: &str) -> ExitCode {
    raise_nofile(false);
    let file = open_file(name, 10_001, "u:r:shell:s0");
    let marker = MARKER.to_le_bytes();
    let tr = TransactionData {
        code: 7,
        data_size: 4,
        buffer: marker.as_ptr() as u64,
        ..Default::default()
    };
    let mut write = Vec::new();
    cmd(&mut write, BC_TRANSACTION, &tr.encode());
    let read = match write_read(&file, &write, true) {
        Ok(read) => read,
        Err(error) => {
            eprintln!("aim-binder-proc dead: ioctl {error}");
            return ExitCode::from(1);
        }
    };
    if !returns(&read)
        .iter()
        .any(|(code, _)| *code == BR_DEAD_REPLY)
    {
        eprintln!("aim-binder-proc dead: expected BR_DEAD_REPLY in {read:?}");
        return ExitCode::from(1);
    }
    println!("dead-reply");
    ExitCode::SUCCESS
}

fn orchestrate() -> ExitCode {
    raise_nofile(true);
    let exe = std::env::current_exe().unwrap_or_else(|error| {
        eprintln!("aim-binder-proc: current_exe: {error}");
        std::process::exit(1);
    });
    for round in 1..=ROUNDS {
        let name = format!("dev.aim.binder-proc.{}.{round}", std::process::id());
        let mut kids = Kids::default();
        let daemon = spawn(&exe, &["daemon", &name]);
        kids.push(daemon);
        if !wait_until(Duration::from_secs(5), || Client::connect(&name).is_some()) {
            eprintln!("aim-binder-proc: daemon did not check in {name}");
            return ExitCode::from(1);
        }
        let daemon_pid = kids.pids[0];
        let mut serve = spawn(&exe, &["serve", &name]);
        let serve_pid = serve.id();
        let ready = read_line(&mut serve, Duration::from_secs(5));
        if ready.as_deref() != Some("ready") {
            eprintln!("aim-binder-proc: serve ready was {ready:?}");
            let _ = serve.kill();
            let _ = serve.wait();
            return ExitCode::from(1);
        }
        let mut call = spawn(&exe, &["call", &name]);
        let call_pid = call.id();
        let call_out = read_to_end(&mut call, WATCHDOG + Duration::from_secs(2));
        let serve_out = read_to_end(&mut serve, Duration::from_secs(2));
        let call_status = call.wait();
        let serve_status = serve.wait();
        if call_status
            .as_ref()
            .ok()
            .and_then(|s| s.code())
            .unwrap_or(101)
            != 0
            || serve_status
                .as_ref()
                .ok()
                .and_then(|s| s.code())
                .unwrap_or(101)
                != 0
        {
            eprintln!(
                "aim-binder-proc: round {round} serve {serve_status:?} call {call_status:?}\nserve {serve_out:?}\ncall {call_out:?}"
            );
            return ExitCode::from(1);
        }
        let call_line = call_out.trim();
        let sender = serve_out
            .lines()
            .find_map(|line| line.strip_prefix("txn sender_pid="));
        let Some(sender) = sender.and_then(|rest| rest.split(' ').next()) else {
            eprintln!("aim-binder-proc: round {round} missing sender line {serve_out:?}");
            return ExitCode::from(1);
        };
        let expected = format!("reply {REPLY:#x} pid={call_pid}");
        if call_line != expected || sender != call_pid.to_string() {
            eprintln!(
                "aim-binder-proc: round {round} call {call_line:?} sender {sender} expected {expected}"
            );
            return ExitCode::from(1);
        }
        if daemon_pid == serve_pid || daemon_pid == call_pid || serve_pid == call_pid {
            eprintln!(
                "aim-binder-proc: round {round} pids are not distinct daemon={daemon_pid} serve={serve_pid} call={call_pid}"
            );
            return ExitCode::from(1);
        }
        kids.pids.clear();
        if !kids.stop_first(daemon_pid) {
            eprintln!("aim-binder-proc: daemon {daemon_pid} did not exit");
            return ExitCode::from(1);
        }
        println!(
            "round {round} daemon={daemon_pid} serve={serve_pid} call={call_pid} sender_pid={sender} fd=hello reply={REPLY:#x}"
        );
    }
    let missing = format!("dev.aim.binder-proc.missing.{}", std::process::id());
    let mut absent = spawn(&exe, &["absent", &missing]);
    let absent_out = read_to_end(&mut absent, Duration::from_secs(2));
    if absent.wait().ok().and_then(|s| s.code()) != Some(0) || absent_out.trim() != "absent" {
        eprintln!("aim-binder-proc: absent check failed: {absent_out:?}");
        return ExitCode::from(1);
    }
    println!("absent refused");
    let name = format!("dev.aim.binder-proc.dead.{}", std::process::id());
    let mut kids = Kids::default();
    kids.push(spawn(&exe, &["daemon", &name]));
    if !wait_until(Duration::from_secs(5), || Client::connect(&name).is_some()) {
        eprintln!("aim-binder-proc: dead-check daemon did not check in");
        return ExitCode::from(1);
    }
    let mut dead = spawn(&exe, &["dead", &name]);
    let dead_out = read_to_end(&mut dead, WATCHDOG + Duration::from_secs(2));
    if dead.wait().ok().and_then(|s| s.code()) != Some(0) || dead_out.trim() != "dead-reply" {
        eprintln!("aim-binder-proc: dead check failed: {dead_out:?}");
        return ExitCode::from(1);
    }
    let daemon_pid = kids.pids[0];
    kids.pids.clear();
    if !kids.stop_first(daemon_pid) {
        eprintln!("aim-binder-proc: dead-check daemon {daemon_pid} did not exit");
        return ExitCode::from(1);
    }
    println!("no-context-manager BR_DEAD_REPLY");
    println!("aim-binder-proc ok");
    ExitCode::SUCCESS
}

const GUEST_ROUNDS: u32 = 2;

fn guest_orchestrate(linux_run: Option<String>, guest_elf: Option<String>) -> ExitCode {
    let (Some(linux_run), Some(guest_elf)) = (linux_run, guest_elf) else {
        eprintln!("usage: aim-binder-proc guest LINUX_RUN GUEST");
        return ExitCode::from(2);
    };
    let linux_run = PathBuf::from(linux_run);
    let guest_elf = PathBuf::from(guest_elf);
    if !linux_run.is_file() || !guest_elf.is_file() {
        eprintln!(
            "aim-binder-proc guest: missing {} or {}",
            linux_run.display(),
            guest_elf.display()
        );
        return ExitCode::from(2);
    }
    raise_nofile(true);
    println!("aim-binder-guest synthetic-pie not-android");
    let exe = std::env::current_exe().unwrap_or_else(|error| {
        eprintln!("aim-binder-proc: current_exe: {error}");
        std::process::exit(1);
    });
    let root = std::env::temp_dir().join(format!("aim-binder-guest-{}", std::process::id()));
    if let Err(error) = place_guest(&root, &guest_elf) {
        eprintln!("aim-binder-proc guest: {error}");
        let _ = std::fs::remove_dir_all(&root);
        return ExitCode::from(2);
    }
    let bytes = match std::fs::read(&guest_elf) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("aim-binder-proc guest: {error}");
            let _ = std::fs::remove_dir_all(&root);
            return ExitCode::from(2);
        }
    };
    let rewrites = aim_elf_smoke::count_rewrites(&bytes);
    let mut failed = false;
    for round in 1..=GUEST_ROUNDS {
        if !guest_round(&exe, &linux_run, &root, round, rewrites) {
            failed = true;
            break;
        }
    }
    if !failed && !guest_dead(&exe, &linux_run, &root, rewrites) {
        failed = true;
    }
    let _ = std::fs::remove_dir_all(&root);
    if failed {
        return ExitCode::from(1);
    }
    println!("aim-binder-guest ok");
    ExitCode::SUCCESS
}

fn place_guest(root: &Path, guest_elf: &Path) -> std::io::Result<()> {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin)?;
    let dest = bin.join("binder-guest");
    std::fs::copy(guest_elf, &dest)?;
    let mut mode = std::fs::metadata(&dest)?.permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(&dest, mode)
}

fn identity_text(uid: u32, label: &str) -> String {
    format!("uid\t{uid}\nseclabel\t{label}\n")
}

fn guest_round(
    exe: &Path,
    linux_run: &Path,
    root: &Path,
    round: u32,
    rewrites: aim_elf_smoke::Rewrites,
) -> bool {
    let name = format!("dev.aim.binder-guest.{}.{round}", std::process::id());
    let mut kids = Kids::default();
    kids.push(spawn(exe, &["daemon", &name]));
    if !wait_until(Duration::from_secs(5), || Client::connect(&name).is_some()) {
        eprintln!("aim-binder-proc guest: daemon did not check in {name}");
        return false;
    }
    let daemon_pid = kids.pids[0];
    let mut serve = spawn_guest(
        linux_run,
        root,
        &name,
        &identity_text(1000, "u:r:servicemanager:s0"),
        "serve",
    );
    let serve_pid = serve.child.id();
    let ready = read_line(&mut serve.child, Duration::from_secs(5));
    if ready.as_deref() != Some("ready") {
        eprintln!(
            "aim-binder-proc guest: serve ready was {ready:?}\n{}",
            serve.stderr_tail()
        );
        return false;
    }
    let mut call = spawn_guest(
        linux_run,
        root,
        &name,
        &identity_text(10001, "u:r:shell:s0"),
        "call",
    );
    let call_pid = call.child.id();
    let (call_code, call_out, call_err) =
        finish_guest(&mut call, WATCHDOG + Duration::from_secs(2));
    let (serve_code, serve_out, serve_err) = finish_guest(&mut serve, Duration::from_secs(2));
    if serve_code != Some(0) || call_code != Some(0) {
        eprintln!(
            "aim-binder-proc guest: round {round} serve {serve_code:?} call {call_code:?}\nserve {serve_out}\ncall {call_out}\n{}",
            tail(&serve_err)
        );
        return false;
    }
    let serve_line = format!("txn pid={call_pid} euid=10001 code=7 marker=11223344 fd=hello");
    let call_line = format!("reply=00000042 pid={call_pid}");
    // `ready` was consumed so the caller could start. The original stdout
    // is that line plus whatever the guest wrote afterwards.
    let serve_stdout = format!("ready\n{serve_out}");
    if !serve_out.lines().any(|line| line == serve_line) || call_out.trim() != call_line {
        eprintln!(
            "aim-binder-proc guest: round {round}\nserve {serve_out:?}\ncall {call_out:?}\nexpected {serve_line:?} and {call_line:?}"
        );
        return false;
    }
    if let Err(error) = aim_elf_smoke::accept_binder_trace(
        &serve_err,
        aim_elf_smoke::GuestRole::Serve,
        serve_pid,
        rewrites,
    ) {
        eprintln!("aim-binder-proc guest: round {round} serve trace: {error}");
        eprint!(
            "{}",
            guest_audit("serve", serve_pid, &serve_stdout, &serve_err)
        );
        return false;
    }
    if let Err(error) = aim_elf_smoke::accept_binder_trace(
        &call_err,
        aim_elf_smoke::GuestRole::Call,
        call_pid,
        rewrites,
    ) {
        eprintln!("aim-binder-proc guest: round {round} call trace: {error}");
        eprint!("{}", guest_audit("call", call_pid, &call_out, &call_err));
        return false;
    }
    print!(
        "{}",
        guest_audit("serve", serve_pid, &serve_stdout, &serve_err)
    );
    print!("{}", guest_audit("call", call_pid, &call_out, &call_err));
    if daemon_pid == serve_pid || daemon_pid == call_pid || serve_pid == call_pid {
        eprintln!(
            "aim-binder-proc guest: round {round} pids are not distinct daemon={daemon_pid} serve={serve_pid} call={call_pid}"
        );
        return false;
    }
    kids.pids.clear();
    if !kids.stop_first(daemon_pid) {
        eprintln!("aim-binder-proc guest: daemon {daemon_pid} did not exit");
        return false;
    }
    if !wait_until(Duration::from_secs(2), || Client::connect(&name).is_none()) {
        eprintln!("aim-binder-proc guest: {name} still registered after the daemon exited");
        return false;
    }
    println!(
        "guest round {round} daemon={daemon_pid} serve={serve_pid} call={call_pid} sender_pid={call_pid} euid=10001 marker=11223344 fd=hello reply=00000042 trace=openat(-100,\"/dev/binder\")=fd,mmap,ioctl=0"
    );
    true
}

fn guest_dead(
    exe: &Path,
    linux_run: &Path,
    root: &Path,
    rewrites: aim_elf_smoke::Rewrites,
) -> bool {
    let name = format!("dev.aim.binder-guest.dead.{}", std::process::id());
    let mut kids = Kids::default();
    kids.push(spawn(exe, &["daemon", &name]));
    if !wait_until(Duration::from_secs(5), || Client::connect(&name).is_some()) {
        eprintln!("aim-binder-proc guest: dead-check daemon did not check in");
        return false;
    }
    let mut dead = spawn_guest(
        linux_run,
        root,
        &name,
        &identity_text(10001, "u:r:shell:s0"),
        "dead",
    );
    let dead_pid = dead.child.id();
    let (code, out, err) = finish_guest(&mut dead, WATCHDOG + Duration::from_secs(2));
    let expected = format!("dead code={:08x}", BR_DEAD_REPLY);
    if code != Some(0) || out.trim() != expected {
        eprintln!(
            "aim-binder-proc guest: dead check failed code {code:?} out {out:?}\n{}",
            tail(&err)
        );
        return false;
    }
    if let Err(error) =
        aim_elf_smoke::accept_binder_trace(&err, aim_elf_smoke::GuestRole::Dead, dead_pid, rewrites)
    {
        eprintln!("aim-binder-proc guest: dead trace: {error}");
        eprint!("{}", guest_audit("dead", dead_pid, &out, &err));
        return false;
    }
    print!("{}", guest_audit("dead", dead_pid, &out, &err));
    let daemon_pid = kids.pids[0];
    kids.pids.clear();
    if !kids.stop_first(daemon_pid) {
        eprintln!("aim-binder-proc guest: dead-check daemon {daemon_pid} did not exit");
        return false;
    }
    if !wait_until(Duration::from_secs(2), || Client::connect(&name).is_none()) {
        eprintln!("aim-binder-proc guest: {name} still registered");
        return false;
    }
    println!("guest no-context-manager {expected}");
    true
}

/// The guest's original stdout and stderr, delimited so a later log can
/// be checked without reconstructing them from the summary line.
fn guest_audit(role: &str, pid: u32, stdout: &str, stderr: &str) -> String {
    let mut out = format!("----- guest {role} pid={pid} stdout -----\n");
    out.push_str(stdout);
    if !stdout.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("----- guest {role} pid={pid} stderr -----\n"));
    out.push_str(stderr);
    if !stderr.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("----- end guest {role} pid={pid} -----\n"));
    out
}

fn tail(text: &str) -> String {
    text.lines()
        .rev()
        .take(40)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

struct GuestProc {
    child: Child,
    stderr: mpsc::Receiver<String>,
}

impl GuestProc {
    fn stderr_tail(&mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stderr
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_default()
    }
}

impl Drop for GuestProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_guest(linux_run: &Path, root: &Path, name: &str, identity: &str, role: &str) -> GuestProc {
    let mut child = Command::new(linux_run);
    child
        .arg("--no-cache")
        .arg("--trace")
        .arg("--root")
        .arg(root)
        .arg("--binder")
        .arg(name)
        .arg("--identity-text")
        .arg(identity)
        .arg("/bin/binder-guest")
        .arg(role)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = child.spawn().unwrap_or_else(|error| {
        eprintln!("aim-binder-proc guest: spawn linux-run: {error}");
        std::process::exit(1);
    });
    let err = child.stderr.take().expect("stderr");
    let (send, stderr) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let mut err = err;
        let _ = err.read_to_string(&mut buf);
        let _ = send.send(buf);
    });
    GuestProc { child, stderr }
}

fn finish_guest(guest: &mut GuestProc, limit: Duration) -> (Option<i32>, String, String) {
    let stdout = read_to_end(&mut guest.child, limit);
    let code = guest.child.wait().ok().and_then(|status| status.code());
    let stderr = guest
        .stderr
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_default();
    // `Drop` would kill a process that has already been waited.
    (code, stdout, stderr)
}

struct Kids {
    children: Vec<Child>,
    pids: Vec<u32>,
}

impl Default for Kids {
    fn default() -> Self {
        Self {
            children: Vec::new(),
            pids: Vec::new(),
        }
    }
}

impl Kids {
    fn push(&mut self, child: Child) {
        self.pids.push(child.id());
        self.children.push(child);
    }

    fn stop_first(&mut self, pid: u32) -> bool {
        let Some(index) = self.children.iter().position(|child| child.id() == pid) else {
            return false;
        };
        let mut child = self.children.swap_remove(index);
        let _ = child.kill();
        let finished = wait_child(&mut child, Duration::from_secs(2));
        gone(pid) && finished
    }
}

impl Drop for Kids {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn gone(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as i32, 0) };
    result < 0
}

fn spawn(exe: &std::path::Path, args: &[&str]) -> Child {
    Command::new(exe)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| {
            eprintln!("aim-binder-proc: spawn {args:?}: {error}");
            std::process::exit(1);
        })
}

fn wait_until(limit: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn read_line(child: &mut Child, limit: Duration) -> Option<String> {
    let out = child.stdout.as_mut()?;
    let deadline = Instant::now() + limit;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while Instant::now() < deadline {
        let mut poll = libc::pollfd {
            fd: out.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let left = deadline.saturating_duration_since(Instant::now());
        let wait = left.as_millis().clamp(1, 200) as i32;
        if unsafe { libc::poll(&mut poll, 1, wait) } <= 0 {
            continue;
        }
        match out.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => return Some(String::from_utf8_lossy(&line).into_owned()),
            Ok(1) => line.push(byte[0]),
            Ok(0) => return None,
            _ => return None,
        }
    }
    None
}

fn read_to_end(child: &mut Child, limit: Duration) -> String {
    let Some(mut out) = child.stdout.take() else {
        return String::new();
    };
    let (send, recv) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = out.read_to_string(&mut buf);
        let _ = send.send(buf);
    });
    match recv.recv_timeout(limit) {
        Ok(buf) => buf,
        Err(_) => {
            let _ = child.kill();
            String::new()
        }
    }
}

fn wait_child(child: &mut Child, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn write_read(file: &BinderFile, write: &[u8], read: bool) -> Result<Vec<u8>, Errno> {
    let mut buf = vec![0u8; if read { 512 } else { 0 }];
    let bwr = WriteRead {
        write_size: write.len() as u64,
        write_buffer: write.as_ptr() as u64,
        read_size: buf.len() as u64,
        read_buffer: buf.as_mut_ptr() as u64,
        ..Default::default()
    };
    let mut arg = bwr.encode();
    let (send, recv) = mpsc::channel();
    std::thread::spawn(move || {
        if recv.recv_timeout(WATCHDOG).is_err() {
            eprintln!("aim-binder-proc: ioctl still blocked after 15s");
            std::process::exit(101);
        }
    });
    file.ioctl(1, BINDER_WRITE_READ, arg.as_mut_ptr() as u64, &mut Own)?;
    let _ = send.send(());
    let done = WriteRead::decode(&arg);
    if done.write_consumed != write.len() as u64 {
        return Err(22);
    }
    buf.truncate(done.read_consumed as usize);
    Ok(buf)
}

fn cmd(out: &mut Vec<u8>, code: u32, payload: &[u8]) {
    out.extend_from_slice(&code.to_le_bytes());
    out.extend_from_slice(payload);
}

/// Same leave-line predicate as `aim_bionic_smoke::binder_device_opened`.
/// A completed `openat` of `/dev/binder` whose result is a file descriptor.
fn binder_device_opened(stderr: &str) -> bool {
    for line in stderr.lines() {
        let Some(rest) = line.strip_prefix("[linux] openat(") else {
            continue;
        };
        if !rest.ends_with(" leave]") || !rest.contains("\"/dev/binder\"") {
            continue;
        }
        let Some((_, result)) = rest.rsplit_once(" = ") else {
            continue;
        };
        let token = result.split_whitespace().next().unwrap_or("");
        if token.starts_with('-') {
            continue;
        }
        if token.parse::<u32>().is_ok() {
            let args = rest.split(" = ").next().unwrap_or("");
            if args.contains("\"/dev/binder\"") && !args.contains("\"/dev/binder/") {
                return true;
            }
        }
    }
    false
}

fn print_host() {
    let mut uts = unsafe { std::mem::zeroed::<libc::utsname>() };
    let named = unsafe { libc::uname(&mut uts) } == 0;
    let field = |bytes: &[libc::c_char]| -> String {
        let bytes = unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const u8, bytes.len()) };
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    };
    let mut page: u64 = 0;
    let mut len = std::mem::size_of_val(&page);
    let page_ok = unsafe {
        libc::sysctlbyname(
            b"hw.pagesize\0".as_ptr() as *const libc::c_char,
            &mut page as *mut u64 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } == 0;
    if named && page_ok {
        println!(
            "host sysname={} release={} version={} machine={} pagesize={page}",
            field(&uts.sysname),
            field(&uts.release),
            field(&uts.version),
            field(&uts.machine)
        );
    } else {
        println!("host uname_ok={named} pagesize_ok={page_ok} pagesize={page}");
    }
}

fn android_orchestrate(linux_run: Option<String>, root: Option<String>) -> ExitCode {
    let (Some(linux_run), Some(root)) = (linux_run, root) else {
        eprintln!("usage: aim-binder-proc android LINUX_RUN ROOT");
        return ExitCode::from(2);
    };
    let linux_run = PathBuf::from(linux_run);
    let root = PathBuf::from(root);
    if !linux_run.is_file() || !root.join("system/bin/servicemanager").is_file() {
        eprintln!(
            "aim-binder-proc android: missing {} or {}/system/bin/servicemanager",
            linux_run.display(),
            root.display()
        );
        return ExitCode::from(2);
    }
    raise_nofile(true);
    println!("android-servicemanager original-binary not-synthetic");
    print_host();
    let exe = std::env::current_exe().unwrap_or_else(|error| {
        eprintln!("aim-binder-proc: current_exe: {error}");
        std::process::exit(1);
    });
    let name = format!("dev.aim.servicemanager.{}", std::process::id());
    let mut kids = Kids::default();
    kids.push(spawn(&exe, &["daemon", &name]));
    let daemon_pid = kids.pids[0];
    if !wait_until(Duration::from_secs(5), || Client::connect(&name).is_some()) {
        eprintln!("android-servicemanager: first blocker: daemon did not check in {name}");
        return ExitCode::from(1);
    }
    let shell = "uid\t2000\ngid\t2000\nseclabel\tu:r:shell:s0\n";
    let (absent_code, absent_out, absent_err) = run_android(
        &linux_run,
        &root,
        &name,
        shell,
        &["/system/bin/service", "check", "manager"],
        Duration::from_secs(20),
    );
    println!(
        "----- service check manager without a context manager exit={absent_code:?} -----\n{absent_out}----- stderr -----\n{absent_err}----- end -----"
    );
    if !absent_out.contains("Unable to get default service manager")
        || !binder_device_opened(&absent_err)
    {
        eprintln!(
            "android-servicemanager: first blocker: service check did not reach a live driver and report no context manager"
        );
        return ExitCode::from(1);
    }
    let sm_id = "uid\t1000\ngid\t1000\ngroups\t1000 3009\nseclabel\tu:r:servicemanager:s0\n";
    let mut sm = spawn_android(
        &linux_run,
        &root,
        &name,
        sm_id,
        &["/system/bin/servicemanager"],
    );
    let sm_pid = sm.child.id();
    let opened = wait_until(Duration::from_secs(20), || {
        sm.child.try_wait().ok().flatten().is_some() || binder_device_opened(&sm.stderr())
    });
    std::thread::sleep(Duration::from_millis(100));
    let opened = opened || binder_device_opened(&sm.stderr());
    let exited = sm.child.try_wait().ok().flatten().is_some();
    if exited || !opened {
        let _ = sm.child.kill();
        let status = sm.child.wait().ok();
        let why = if exited {
            "servicemanager exited"
        } else {
            "servicemanager produced no completed openat of /dev/binder within 20s"
        };
        eprintln!(
            "android-servicemanager: first blocker: {why} pid={sm_pid} status={status:?}\n{}\n{}",
            sm.stdout(),
            sm.stderr()
        );
        return ExitCode::from(1);
    }
    let (list_code, list_out, list_err) = run_android(
        &linux_run,
        &root,
        &name,
        shell,
        &["/system/bin/service", "list"],
        Duration::from_secs(20),
    );
    println!(
        "----- service list pid exit={list_code:?} stdout -----\n{list_out}----- stderr -----\n{list_err}----- end -----"
    );
    if list_code != Some(0) || !list_out.contains("manager: [android.os.IServiceManager]") {
        eprintln!(
            "android-servicemanager: first blocker: service list did not report the original manager"
        );
        return ExitCode::from(1);
    }
    let (found_code, found_out, found_err) = run_android(
        &linux_run,
        &root,
        &name,
        shell,
        &["/system/bin/service", "check", "manager"],
        Duration::from_secs(20),
    );
    println!(
        "----- service check manager exit={found_code:?} stdout -----\n{found_out}----- stderr -----\n{found_err}----- end -----"
    );
    if found_code != Some(0) || !found_out.contains("Service manager: found") {
        eprintln!("android-servicemanager: first blocker: service check manager was not found");
        return ExitCode::from(1);
    }
    let (missing_code, missing_out, missing_err) = run_android(
        &linux_run,
        &root,
        &name,
        shell,
        &["/system/bin/service", "check", "servicemanager"],
        Duration::from_secs(20),
    );
    println!(
        "----- service check servicemanager exit={missing_code:?} stdout -----\n{missing_out}----- stderr -----\n{missing_err}----- end -----"
    );
    if missing_code != Some(0) || !missing_out.contains("Service servicemanager: not found") {
        eprintln!(
            "android-servicemanager: first blocker: the absent name was not reported missing"
        );
        return ExitCode::from(1);
    }
    if !binder_device_opened(&list_err) {
        eprintln!("android-servicemanager: first blocker: service list did not open /dev/binder");
        return ExitCode::from(1);
    }
    let _ = sm.child.kill();
    let _ = sm.child.wait();
    kids.pids.clear();
    if !kids.stop_first(daemon_pid) {
        eprintln!("android-servicemanager: first blocker: daemon {daemon_pid} did not exit");
        return ExitCode::from(1);
    }
    if !wait_until(Duration::from_secs(2), || Client::connect(&name).is_none()) {
        eprintln!("android-servicemanager: first blocker: {name} still registered");
        return ExitCode::from(1);
    }
    println!(
        "android-servicemanager daemon={daemon_pid} servicemanager={sm_pid} trace=openat(-100,\"/dev/binder\")=fd"
    );
    println!("android-servicemanager ok");
    ExitCode::SUCCESS
}

struct AndroidProc {
    child: Child,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
}

impl AndroidProc {
    fn stdout(&self) -> String {
        self.stdout.lock().unwrap().clone()
    }

    fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }
}

impl Drop for AndroidProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_android(
    linux_run: &Path,
    root: &Path,
    name: &str,
    identity: &str,
    argv: &[&str],
) -> AndroidProc {
    let mut child = Command::new(linux_run);
    child
        .arg("--no-cache")
        .arg("--trace")
        .arg("--root")
        .arg(root)
        .arg("--binder")
        .arg(name)
        .arg("--identity-text")
        .arg(identity)
        .args(argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = child.spawn().unwrap_or_else(|error| {
        eprintln!("aim-binder-proc android: spawn linux-run: {error}");
        std::process::exit(1);
    });
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    AndroidProc {
        child,
        stdout: pipe_text(stdout),
        stderr: pipe_text(stderr),
    }
}

fn pipe_text(mut pipe: impl Read + Send + 'static) -> Arc<Mutex<String>> {
    let buf = Arc::new(Mutex::new(String::new()));
    let slot = Arc::clone(&buf);
    std::thread::spawn(move || {
        let mut tmp = [0u8; 8192];
        let mut text = String::new();
        loop {
            match pipe.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => text.push_str(&String::from_utf8_lossy(&tmp[..n])),
            }
            *slot.lock().unwrap() = text.clone();
        }
        *slot.lock().unwrap() = text;
    });
    buf
}

fn run_android(
    linux_run: &Path,
    root: &Path,
    name: &str,
    identity: &str,
    argv: &[&str],
    limit: Duration,
) -> (Option<i32>, String, String) {
    let mut guest = spawn_android(linux_run, root, name, identity, argv);
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Ok(Some(status)) = guest.child.try_wait() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = guest.child.kill();
            break guest.child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    std::thread::sleep(Duration::from_millis(50));
    (
        status.and_then(|status| status.code()),
        guest.stdout(),
        guest.stderr(),
    )
}

fn returns(read: &[u8]) -> Vec<(u32, Option<TransactionData>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= read.len() {
        let code = u32::from_le_bytes(read[at..at + 4].try_into().unwrap());
        at += 4;
        let tr = matches!(code, BR_TRANSACTION | BR_TRANSACTION_SEC_CTX | BR_REPLY)
            .then(|| TransactionData::decode(&read[at..]));
        out.push((code, tr));
        at += ioc_size(code);
    }
    out
}

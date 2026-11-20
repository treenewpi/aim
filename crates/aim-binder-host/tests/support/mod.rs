//! What the daemon's tests share: this process as the guest, and
//! BINDER_WRITE_READ built and parsed as IPCThreadState does.

use std::sync::Once;

use aim_binder_driver::uapi::*;
use aim_binder_driver::{Device, Errno};
use aim_binder_host::client::{BinderFile, Client, UserMemory};

/// Parallel transport tests need more than a fresh SSH soft limit of 256
/// descriptors. 4096 is what passed on the M4 when only this process tree
/// was raised. The hard limit is not changed, and nothing outside this
/// process is touched.
const TRANSPORT_NOFILE: u64 = 4096;

pub fn ensure_descriptor_limit() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } < 0 {
            eprintln!(
                "aim-binder-host: getrlimit(NOFILE) failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(2);
        }
        if limit.rlim_cur >= TRANSPORT_NOFILE {
            eprintln!(
                "aim-binder-host: NOFILE soft {} hard {} (no change)",
                limit.rlim_cur, limit.rlim_max
            );
            return;
        }
        if limit.rlim_max >= TRANSPORT_NOFILE {
            let hard = limit.rlim_max;
            limit.rlim_cur = TRANSPORT_NOFILE;
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } == 0 {
                eprintln!(
                    "aim-binder-host: NOFILE soft was below {TRANSPORT_NOFILE}; raised this process only to {TRANSPORT_NOFILE} (hard {hard}). A new shell stays at its own soft limit."
                );
                return;
            }
            eprintln!(
                "aim-binder-host: setrlimit(NOFILE, {TRANSPORT_NOFILE}) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        eprintln!(
            "aim-binder-host: NOFILE soft {} hard {} is below {TRANSPORT_NOFILE}. pipe() then fails and the 15s ioctl watchdog exits 101. This is not a binder assertion failure. For this process tree only, not a global setting and not sudo: ulimit -Sn {TRANSPORT_NOFILE}",
            limit.rlim_cur, limit.rlim_max
        );
        std::process::exit(2);
    });
}

/// This process's memory stands in for the guest's.
pub struct Own;

impl UserMemory for Own {
    fn read(&mut self, address: u64, len: usize) -> Result<Vec<u8>, Errno> {
        // SAFETY: the test passes pointers to its own live buffers.
        Ok(unsafe { std::slice::from_raw_parts(address as *const u8, len) }.to_vec())
    }

    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Errno> {
        // SAFETY: as above.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, data.len()) };
        Ok(())
    }
}

pub const MAP: usize = 1 << 20;

pub fn open(client: &Client, euid: u32, context: &str) -> BinderFile {
    ensure_descriptor_limit();
    let file = client
        .open(Device::Binder, false, true, euid, context)
        .unwrap();
    // SAFETY: reserving the range the receive buffer replaces.
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
    file.mmap(base as u64, MAP as u64).unwrap();
    file
}

/// One BINDER_WRITE_READ; returns the read bytes.
///
/// A read that never returns used to wedge the whole `transport` binary
/// under `cargo test`'s default threads. The limit fails that ioctl instead
/// of waiting for an external SIGTERM. It is not a pass: the process exits
/// nonzero while the blocked call is still outstanding.
pub fn write_read(file: &BinderFile, tid: i32, write: &[u8], read: bool) -> Result<Vec<u8>, Errno> {
    ensure_descriptor_limit();
    let mut buf = vec![0u8; if read { 512 } else { 0 }];
    let bwr = WriteRead {
        write_size: write.len() as u64,
        write_buffer: write.as_ptr() as u64,
        read_size: buf.len() as u64,
        read_buffer: buf.as_mut_ptr() as u64,
        ..Default::default()
    };
    let mut arg = bwr.encode();
    let (send, recv) = std::sync::mpsc::channel();
    let watch = std::thread::spawn(move || {
        if recv.recv_timeout(std::time::Duration::from_secs(15)).is_err() {
            eprintln!("binder transport ioctl still blocked after 15s");
            std::process::exit(101);
        }
    });
    let result = file.ioctl(tid, BINDER_WRITE_READ, arg.as_mut_ptr() as u64, &mut Own);
    let _ = send.send(());
    let _ = watch.join();
    result?;
    let done = WriteRead::decode(&arg);
    assert_eq!(done.write_consumed, write.len() as u64);
    buf.truncate(done.read_consumed as usize);
    Ok(buf)
}

pub fn cmd(out: &mut Vec<u8>, code: u32, payload: &[u8]) {
    out.extend_from_slice(&code.to_le_bytes());
    out.extend_from_slice(payload);
}

/// The BR codes of a read, with each transaction's data.
pub fn returns(read: &[u8]) -> Vec<(u32, Option<TransactionData>)> {
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

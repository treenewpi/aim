//! Host facilities the services call.
//!
//! On macOS these are the libc functions and `CLOCK_UPTIME_RAW`. On Linux
//! the uptime clock is `CLOCK_MONOTONIC` (it does not advance while
//! suspended, as `CLOCK_UPTIME_RAW` does not) and the random calls read
//! the kernel CSPRNG.

#[cfg(target_os = "macos")]
pub(crate) use libc::CLOCK_UPTIME_RAW;

#[cfg(not(target_os = "macos"))]
pub(crate) const CLOCK_UPTIME_RAW: libc::clockid_t = libc::CLOCK_MONOTONIC;

#[cfg(target_os = "macos")]
pub(crate) use libc::{arc4random, arc4random_buf, arc4random_uniform};

#[cfg(not(target_os = "macos"))]
pub(crate) unsafe fn arc4random_buf(buf: *mut libc::c_void, len: usize) {
    let mut off = 0;
    while off < len {
        let n = unsafe { libc::getrandom(buf.add(off), len - off, 0) };
        if n < 0 {
            if unsafe { *aim_storage::host::__error() } == libc::EINTR {
                continue;
            }
            unsafe { std::ptr::write_bytes(buf.add(off), 0, len - off) };
            return;
        }
        off += n as usize;
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) unsafe fn arc4random() -> u32 {
    let mut bytes = [0u8; 4];
    unsafe { arc4random_buf(bytes.as_mut_ptr().cast(), 4) };
    u32::from_ne_bytes(bytes)
}

#[cfg(not(target_os = "macos"))]
pub(crate) unsafe fn arc4random_uniform(upper: u32) -> u32 {
    if upper < 2 {
        return 0;
    }
    let limit = u32::MAX - u32::MAX % upper;
    loop {
        let value = unsafe { arc4random() };
        if value < limit {
            return value % upper;
        }
    }
}

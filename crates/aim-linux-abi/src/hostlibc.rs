//! Darwin libc items the guest ABI calls.
//!
//! On macOS every name here is the real libc item. On Linux the same names
//! exist so the crate typechecks: the calls fail (`ENOTSUP` or a Mach
//! `KERN_FAILURE`) and do not report that the operation happened.

#![allow(non_camel_case_types, dead_code)]

#[cfg(target_os = "macos")]
pub use libc::{
    __error, kqueue, kevent, kevent64, kevent64_s, proc_bsdinfo, proc_fdinfo, proc_listallpids,
    proc_pidfdinfo, proc_pidinfo, proc_regionfilename, proc_taskallinfo, proc_taskinfo,
    proc_threadinfo, pthread_get_qos_class_np, pthread_mach_thread_np, pthread_set_qos_class_self_np,
    sysctl, sysctlbyname, thread_basic_info, thread_extended_info, thread_info, time_value_t,
    CTL_KERN, EVFILT_PROC, EVFILT_READ, EVFILT_SIGNAL, EVFILT_TIMER, EVFILT_USER, EVFILT_VNODE,
    EVFILT_WRITE, EV_ADD, EV_CLEAR, EV_DELETE, EV_DISABLE, EV_ENABLE, EV_EOF, EV_ERROR, EV_ONESHOT,
    EV_RECEIPT, KERN_PROCARGS2, NOTE_ATTRIB, NOTE_CRITICAL, NOTE_DELETE, NOTE_EXIT, NOTE_EXTEND,
    NOTE_LEEWAY, NOTE_LOWAT, NOTE_MACH_CONTINUOUS_TIME, NOTE_NSECONDS, NOTE_RENAME, NOTE_REVOKE,
    NOTE_TRIGGER, NOTE_WRITE, PROC_PIDLISTFDS, PROC_PIDTASKALLINFO, PROC_PIDTASKINFO,
    PROC_PIDTBSDINFO, PROC_PIDTHREADINFO, PROX_FDTYPE_SOCKET, SZOMB, THREAD_BASIC_INFO,
    THREAD_BASIC_INFO_COUNT, THREAD_EXTENDED_INFO, THREAD_EXTENDED_INFO_COUNT, TH_STATE_RUNNING,
};

#[cfg(target_os = "macos")]
pub fn empty_sigset() -> libc::sigset_t {
    0
}

#[cfg(not(target_os = "macos"))]
mod linux {
    use std::os::raw::{c_char, c_int, c_uint, c_void};

    fn deny() -> c_int {
        unsafe { *super::super_error() = libc::ENOTSUP };
        -1
    }

    pub unsafe fn __error() -> *mut c_int {
        super::super_error()
    }

    pub unsafe fn kqueue() -> c_int {
        deny()
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct kevent {
        pub ident: usize,
        pub filter: i16,
        pub flags: u16,
        pub fflags: u32,
        pub data: isize,
        pub udata: *mut c_void,
    }

    pub unsafe fn kevent(
        _kq: c_int,
        _changelist: *const kevent,
        _nchanges: c_int,
        _eventlist: *mut kevent,
        _nevents: c_int,
        _timeout: *const libc::timespec,
    ) -> c_int {
        deny()
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct kevent64_s {
        pub ident: u64,
        pub filter: i16,
        pub flags: u16,
        pub fflags: u32,
        pub data: i64,
        pub udata: u64,
        pub ext: [u64; 2],
    }

    pub unsafe fn kevent64(
        _kq: c_int,
        _changelist: *const kevent64_s,
        _nchanges: c_int,
        _eventlist: *mut kevent64_s,
        _nevents: c_int,
        _flags: c_uint,
        _timeout: *const libc::timespec,
    ) -> c_int {
        deny()
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct proc_bsdinfo {
        pub pbi_flags: u32,
        pub pbi_status: u32,
        pub pbi_ppid: u32,
        pub pbi_pgid: u32,
        pub pbi_nice: i32,
        pub pbi_start_tvsec: u64,
        pub pbi_start_tvusec: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct proc_taskinfo {
        pub pti_virtual_size: u64,
        pub pti_resident_size: u64,
        pub pti_total_user: u64,
        pub pti_total_system: u64,
        pub pti_faults: i32,
        pub pti_pageins: i32,
        pub pti_csw: i32,
        pub pti_threadnum: i32,
        pub pti_priority: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct proc_taskallinfo {
        pub pbsd: proc_bsdinfo,
        pub ptinfo: proc_taskinfo,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct proc_threadinfo {
        pub pth_user_time: u64,
        pub pth_system_time: u64,
        pub pth_run_state: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct proc_fdinfo {
        pub proc_fd: i32,
        pub proc_fdtype: u32,
    }

    pub unsafe fn proc_pidinfo(
        _pid: c_int,
        _flavor: c_int,
        _arg: u64,
        _buffer: *mut c_void,
        _buffersize: c_int,
    ) -> c_int {
        deny();
        0
    }

    pub unsafe fn proc_pidfdinfo(
        _pid: c_int,
        _fd: c_int,
        _flavor: c_int,
        _buffer: *mut c_void,
        _buffersize: c_int,
    ) -> c_int {
        deny();
        0
    }

    pub unsafe fn proc_listallpids(_buffer: *mut c_void, _buffersize: c_int) -> c_int {
        deny()
    }

    pub unsafe fn proc_regionfilename(
        _pid: c_int,
        _address: u64,
        _buffer: *mut c_void,
        _buffersize: u32,
    ) -> c_int {
        deny()
    }

    pub unsafe fn sysctl(
        _name: *mut c_int,
        _namelen: c_uint,
        _oldp: *mut c_void,
        _oldlenp: *mut usize,
        _newp: *mut c_void,
        _newlen: usize,
    ) -> c_int {
        deny()
    }

    pub unsafe fn sysctlbyname(
        _name: *const c_char,
        _oldp: *mut c_void,
        _oldlenp: *mut usize,
        _newp: *mut c_void,
        _newlen: usize,
    ) -> c_int {
        deny()
    }

    pub unsafe fn pthread_get_qos_class_np(
        _thread: libc::pthread_t,
        _class: *mut crate::qos_class_t,
        _priority: *mut c_int,
    ) -> c_int {
        libc::ENOTSUP
    }

    pub unsafe fn pthread_set_qos_class_self_np(
        _class: crate::qos_class_t,
        _priority: c_int,
    ) -> c_int {
        libc::ENOTSUP
    }

    pub unsafe fn pthread_mach_thread_np(_thread: libc::pthread_t) -> u32 {
        0
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct time_value_t {
        pub seconds: i64,
        pub microseconds: i64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct thread_basic_info {
        pub user_time: time_value_t,
        pub system_time: time_value_t,
        pub run_state: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct thread_extended_info {
        pub pth_user_time: u64,
        pub pth_system_time: u64,
        pub pth_run_state: i32,
    }

    pub unsafe fn thread_info(
        _target: u32,
        _flavor: u32,
        _out: *mut c_void,
        _count: *mut u32,
    ) -> c_int {
        5
    }

    pub const EVFILT_READ: i16 = -1;
    pub const EVFILT_WRITE: i16 = -2;
    pub const EVFILT_VNODE: i16 = -4;
    pub const EVFILT_PROC: i16 = -5;
    pub const EVFILT_SIGNAL: i16 = -6;
    pub const EVFILT_TIMER: i16 = -7;
    pub const EVFILT_USER: i16 = -10;
    pub const EV_ADD: u16 = 0x1;
    pub const EV_DELETE: u16 = 0x2;
    pub const EV_ENABLE: u16 = 0x4;
    pub const EV_DISABLE: u16 = 0x8;
    pub const EV_ONESHOT: u16 = 0x10;
    pub const EV_CLEAR: u16 = 0x20;
    pub const EV_RECEIPT: u16 = 0x40;
    pub const EV_ERROR: u16 = 0x4000;
    pub const EV_EOF: u16 = 0x8000;
    pub const NOTE_TRIGGER: u32 = 0x01000000;
    pub const NOTE_LOWAT: u32 = 0x00000001;
    pub const NOTE_DELETE: u32 = 0x00000001;
    pub const NOTE_WRITE: u32 = 0x00000002;
    pub const NOTE_EXTEND: u32 = 0x00000004;
    pub const NOTE_ATTRIB: u32 = 0x00000008;
    pub const NOTE_RENAME: u32 = 0x00000020;
    pub const NOTE_REVOKE: u32 = 0x00000040;
    pub const NOTE_EXIT: u32 = 0x80000000;
    pub const NOTE_NSECONDS: u32 = 0x00000004;
    pub const NOTE_LEEWAY: u32 = 0x00000010;
    pub const NOTE_CRITICAL: u32 = 0x00000020;
    pub const NOTE_MACH_CONTINUOUS_TIME: u32 = 0x00000080;
    pub const PROC_PIDLISTFDS: c_int = 1;
    pub const PROC_PIDTASKALLINFO: c_int = 2;
    pub const PROC_PIDTBSDINFO: c_int = 3;
    pub const PROC_PIDTASKINFO: c_int = 4;
    pub const PROC_PIDTHREADINFO: c_int = 5;
    pub const PROX_FDTYPE_SOCKET: c_int = 2;
    pub const SZOMB: u32 = 5;
    pub const CTL_KERN: c_int = 1;
    pub const KERN_PROCARGS2: c_int = 49;
    pub const THREAD_BASIC_INFO: c_int = 3;
    pub const THREAD_EXTENDED_INFO: c_int = 5;
    pub const THREAD_BASIC_INFO_COUNT: u32 = 10;
    pub const THREAD_EXTENDED_INFO_COUNT: u32 = 20;
    pub const TH_STATE_RUNNING: c_int = 1;

    pub fn empty_sigset() -> libc::sigset_t {
        unsafe { std::mem::zeroed() }
    }
}

#[cfg(not(target_os = "macos"))]
pub use linux::*;

#[cfg(not(target_os = "macos"))]
unsafe fn super_error() -> *mut std::os::raw::c_int {
    aim_storage::host::__error()
}

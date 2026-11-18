//! Leave-line check for the synthetic binder guest.
//!
//! `linux-run --trace` prints a completed syscall as
//! `[linux] name(args) = result [pid=N tid=N call=N leave]`. `openat`
//! prints the directory fd first, so the binder open is
//! `openat(-100, "/dev/binder", 0x80002, 0x0) = <fd>` (`-100` is
//! `AT_FDCWD`). A trace that only contains the path, or an `openat`
//! whose result is an errno, is not this guest.

use super::{trace_matches, Rewrites};

/// Which role of `binder_guest` the trace has to prove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestRole {
    Serve,
    Call,
    Dead,
}

const AT_FDCWD: i64 = -100;
const BINDER_OPEN_FLAGS: i64 = 0x80002;
const BINDER_WRITE_READ: i64 = 0xc0306201;
const BINDER_SET_CONTEXT_MGR_EXT: i64 = 0x4018620d;

/// `Ok` only when `stderr` is a completed trace of `role` for `pid`.
///
/// The load line has to name `/bin/binder-guest` and report `rewrites`.
/// Every leave line has to be one syscall this role actually issues, with
/// a successful result. `Serve` must read five bytes from the fd the
/// driver installed. `Call` must write five bytes into a pipe, close that
/// end, and `getpid` equal to `pid`. `Dead` must not install a context
/// manager or move an fd.
pub fn accept_binder_trace(
    stderr: &str,
    role: GuestRole,
    pid: u32,
    rewrites: Rewrites,
) -> Result<(), String> {
    if !stderr.contains("/bin/binder-guest")
        || !stderr.contains("from load-time rewrite")
        || !trace_matches(stderr, rewrites)
    {
        return Err(
            "load-time rewrite line is not /bin/binder-guest with this file's svc count".into(),
        );
    }
    let mut leaves = Vec::new();
    for line in stderr.lines() {
        if let Some(leave) = parse_leave(line)? {
            if leave.pid != pid || leave.tid != pid {
                return Err(format!("trace pid/tid is not {pid}: {}", leave.line));
            }
            leaves.push(leave);
        }
    }
    check_role(&leaves, role, pid)
}

struct Leave {
    line: String,
    name: String,
    args: Vec<Value>,
    result: i64,
    pid: u32,
    tid: u32,
}

enum Value {
    Int(i64),
    Str(String),
}

fn parse_leave(line: &str) -> Result<Option<Leave>, String> {
    let Some(rest) = line.strip_prefix("[linux] ") else {
        return Ok(None);
    };
    if rest.ends_with(" enter]") {
        return Ok(None);
    }
    let Some(rest) = rest.strip_suffix(" leave]") else {
        return Err(format!("unparsed linux trace line: {line}"));
    };
    let Some((body, meta)) = rest.rsplit_once(" [pid=") else {
        return Err(format!("trace leave has no pid: {line}"));
    };
    let mut meta = meta.split_whitespace();
    let pid = parse_u32(meta.next().unwrap_or(""), "pid")?;
    let tid = parse_u32(
        meta.next()
            .and_then(|part| part.strip_prefix("tid="))
            .unwrap_or(""),
        "tid",
    )?;
    let call = meta
        .next()
        .and_then(|part| part.strip_prefix("call="))
        .unwrap_or("");
    if call.parse::<u32>().is_err() || meta.next().is_some() {
        return Err(format!("trace leave has a bad call trailer: {line}"));
    }
    let Some((invocation, result)) = body.rsplit_once(" = ") else {
        return Err(format!("trace leave has no result: {line}"));
    };
    let result = parse_i64(result.split_whitespace().next().unwrap_or(""))?;
    let Some((name, args)) = invocation.split_once('(') else {
        return Err(format!("trace leave has no arguments: {line}"));
    };
    let Some(args) = args.strip_suffix(')') else {
        return Err(format!("trace leave arguments are not closed: {line}"));
    };
    Ok(Some(Leave {
        line: line.to_string(),
        name: name.to_string(),
        args: parse_args(args)?,
        result,
        pid,
        tid,
    }))
}

fn parse_args(text: &str) -> Result<Vec<Value>, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && (bytes[index] == b' ' || bytes[index] == b',') {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        if bytes[index] == b'"' {
            index += 1;
            let start = index;
            while index < bytes.len() && bytes[index] != b'"' {
                index += 1;
            }
            if index >= bytes.len() {
                return Err(format!("unterminated string in trace arguments: {text}"));
            }
            out.push(Value::Str(text[start..index].to_string()));
            index += 1;
        } else {
            let start = index;
            while index < bytes.len() && bytes[index] != b',' {
                index += 1;
            }
            out.push(Value::Int(parse_i64(text[start..index].trim())?));
        }
    }
    Ok(out)
}

fn parse_u32(text: &str, what: &str) -> Result<u32, String> {
    text.parse()
        .map_err(|_| format!("trace {what} is not a decimal pid: {text}"))
}

fn parse_i64(text: &str) -> Result<i64, String> {
    if let Some(hex) = text.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).map_err(|_| format!("trace value is not an integer: {text}"))
    } else {
        text.parse()
            .map_err(|_| format!("trace value is not an integer: {text}"))
    }
}

fn arg_int(leave: &Leave, index: usize) -> Option<i64> {
    match leave.args.get(index) {
        Some(Value::Int(value)) => Some(*value),
        _ => None,
    }
}

fn arg_str(leave: &Leave, index: usize) -> Option<&str> {
    match leave.args.get(index) {
        Some(Value::Str(value)) => Some(value),
        _ => None,
    }
}

fn check_role(leaves: &[Leave], role: GuestRole, pid: u32) -> Result<(), String> {
    let mut opens = leaves.iter().filter(|leave| leave.name == "openat");
    let Some(open) = opens.next() else {
        return Err("no openat(-100, \"/dev/binder\", 0x80002, 0x0) = fd leave".into());
    };
    if opens.next().is_some() {
        return Err("more than one openat leave".into());
    }
    let open_shape = arg_int(open, 0) == Some(AT_FDCWD)
        && arg_str(open, 1) == Some("/dev/binder")
        && arg_int(open, 2) == Some(BINDER_OPEN_FLAGS)
        && arg_int(open, 3) == Some(0);
    if !open_shape {
        return Err(format!(
            "openat leave is not AT_FDCWD /dev/binder O_RDWR|O_CLOEXEC: {}",
            open.line
        ));
    }
    if !(3..=0xffff).contains(&open.result) {
        return Err(format!(
            "openat of /dev/binder returned {}, not a binder fd: {}",
            open.result, open.line
        ));
    }
    let fd = open.result;
    let mut binder_map = false;
    let mut scratch_map = false;
    let mut context_mgr = 0;
    let mut write_read = 0;
    let mut pipe = 0;
    let mut fd_write = None;
    let mut fd_read = 0;
    let mut closed = None;
    let mut got_pid = 0;
    let mut stdout_writes = 0;
    for leave in leaves {
        if leave.name == "openat" {
            continue;
        }
        match leave.name.as_str() {
            "mmap" => classify_mmap(leave, fd, &mut binder_map, &mut scratch_map)?,
            "ioctl" => classify_ioctl(leave, fd, &mut context_mgr, &mut write_read)?,
            "write" => classify_write(leave, fd, &mut stdout_writes, &mut fd_write)?,
            "read" => classify_read(leave, fd, &mut fd_read)?,
            "pipe2" => {
                if leave.args.len() < 2 || arg_int(leave, 1) != Some(0) || leave.result != 0 {
                    return Err(format!("pipe2 did not succeed: {}", leave.line));
                }
                pipe += 1;
            }
            "close" => {
                if arg_int(leave, 0).is_none() || leave.result != 0 {
                    return Err(format!("close did not succeed: {}", leave.line));
                }
                if closed.is_some() {
                    return Err(format!("more than one close: {}", leave.line));
                }
                closed = arg_int(leave, 0);
            }
            "getpid" => {
                if leave.result != pid as i64 {
                    return Err(format!(
                        "getpid returned {:#x}, not {pid}: {}",
                        leave.result, leave.line
                    ));
                }
                got_pid += 1;
            }
            _ => {
                return Err(format!("unexpected {}: {}", leave.name, leave.line));
            }
        }
    }
    if !binder_map || !scratch_map {
        return Err("missing the binder receive mmap or the scratch mmap".into());
    }
    if write_read < 1 {
        return Err("no successful BINDER_WRITE_READ ioctl".into());
    }
    if stdout_writes < 1 {
        return Err("no completed write to stdout".into());
    }
    match role {
        GuestRole::Serve => {
            if context_mgr != 1 {
                return Err(format!(
                    "serve needs one successful BINDER_SET_CONTEXT_MGR_EXT, found {context_mgr}"
                ));
            }
            if pipe != 0 || closed.is_some() || got_pid != 0 || fd_write.is_some() {
                return Err("serve trace contains a caller-only syscall".into());
            }
            if fd_read != 1 {
                return Err(format!(
                    "serve needs one read of 5 bytes from the translated fd, found {fd_read}"
                ));
            }
        }
        GuestRole::Call => {
            if context_mgr != 0 {
                return Err("call trace installed a context manager".into());
            }
            if pipe != 1 {
                return Err(format!("call needs one successful pipe2, found {pipe}"));
            }
            let Some(write_fd) = fd_write else {
                return Err("call did not write 5 bytes to the pipe".into());
            };
            if closed != Some(write_fd) {
                return Err("call did not close the pipe write end".into());
            }
            if got_pid != 1 {
                return Err(format!(
                    "call needs one getpid equal to {pid}, found {got_pid}"
                ));
            }
            if fd_read != 0 {
                return Err("call trace read a translated fd".into());
            }
        }
        GuestRole::Dead => {
            if context_mgr != 0
                || pipe != 0
                || closed.is_some()
                || got_pid != 0
                || fd_write.is_some()
                || fd_read != 0
            {
                return Err("dead trace is not a no-context-manager transaction".into());
            }
        }
    }
    Ok(())
}

fn classify_mmap(
    leave: &Leave,
    fd: i64,
    binder_map: &mut bool,
    scratch_map: &mut bool,
) -> Result<(), String> {
    let args = (
        arg_int(leave, 0),
        arg_int(leave, 1),
        arg_int(leave, 2),
        arg_int(leave, 3),
        arg_int(leave, 4),
        arg_int(leave, 5),
    );
    let mapped = leave.result > 0xffff;
    if args == (Some(0), Some(0x20000), Some(1), Some(2), Some(fd), Some(0)) && mapped {
        if *binder_map {
            return Err(format!("more than one binder mmap: {}", leave.line));
        }
        *binder_map = true;
        Ok(())
    } else if args
        == (
            Some(0),
            Some(0x4000),
            Some(3),
            Some(0x22),
            Some(-1),
            Some(0),
        )
        && mapped
    {
        if *scratch_map {
            return Err(format!("more than one scratch mmap: {}", leave.line));
        }
        *scratch_map = true;
        Ok(())
    } else {
        Err(format!(
            "mmap is not the binder receive buffer or the scratch mapping: {}",
            leave.line
        ))
    }
}

fn classify_ioctl(
    leave: &Leave,
    fd: i64,
    context_mgr: &mut usize,
    write_read: &mut usize,
) -> Result<(), String> {
    if arg_int(leave, 0) != Some(fd) || leave.result != 0 {
        return Err(format!(
            "ioctl did not succeed on the binder fd: {}",
            leave.line
        ));
    }
    match arg_int(leave, 1) {
        Some(BINDER_SET_CONTEXT_MGR_EXT) => *context_mgr += 1,
        Some(BINDER_WRITE_READ) => *write_read += 1,
        _ => {
            return Err(format!("unexpected ioctl request: {}", leave.line));
        }
    }
    Ok(())
}

fn classify_write(
    leave: &Leave,
    fd: i64,
    stdout_writes: &mut usize,
    fd_write: &mut Option<i64>,
) -> Result<(), String> {
    let Some(write_fd) = arg_int(leave, 0) else {
        return Err(format!("write has no fd: {}", leave.line));
    };
    let Some(len) = arg_int(leave, 2) else {
        return Err(format!("write has no length: {}", leave.line));
    };
    if leave.result != len || leave.result <= 0 {
        return Err(format!("write did not complete: {}", leave.line));
    }
    if write_fd == 1 {
        *stdout_writes += 1;
        Ok(())
    } else if write_fd > 2 && write_fd != fd && len == 5 {
        if fd_write.is_some() {
            return Err(format!("more than one 5-byte pipe write: {}", leave.line));
        }
        *fd_write = Some(write_fd);
        Ok(())
    } else {
        Err(format!("unexpected write: {}", leave.line))
    }
}

fn classify_read(leave: &Leave, fd: i64, fd_read: &mut usize) -> Result<(), String> {
    let Some(read_fd) = arg_int(leave, 0) else {
        return Err(format!("read has no fd: {}", leave.line));
    };
    if arg_int(leave, 2) != Some(5) || leave.result != 5 || read_fd <= 2 || read_fd == fd {
        return Err(format!(
            "read is not 5 bytes from the translated fd: {}",
            leave.line
        ));
    }
    *fd_read += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{binder_program, count_rewrites};
    use super::{accept_binder_trace, GuestRole};

    // Original stdout and stderr from the M4 run of 461f463. serve 83980,
    // call 83983 and dead 83992 exited 0. The formal harness of that commit
    // still exited 1, because it looked for `openat("/dev/binder"`.
    const SERVE_ERR: &str = include_str!("../fixtures/mac-461f463/serve.stderr");
    const SERVE_OUT: &str = include_str!("../fixtures/mac-461f463/serve.stdout");
    const CALL_ERR: &str = include_str!("../fixtures/mac-461f463/call.stderr");
    const CALL_OUT: &str = include_str!("../fixtures/mac-461f463/call.stdout");
    const DEAD_ERR: &str = include_str!("../fixtures/mac-461f463/dead.stderr");
    const DEAD_OUT: &str = include_str!("../fixtures/mac-461f463/dead.stdout");

    fn rewrites() -> super::super::Rewrites {
        count_rewrites(&binder_program())
    }

    #[test]
    fn captured_traces_match_their_roles() {
        let rewrites = rewrites();
        assert_eq!(rewrites.svc, 15);
        assert_eq!(rewrites.mrs_tpidr, 0);
        assert_eq!(rewrites.msr_tpidr, 0);
        assert_eq!(
            SERVE_OUT,
            "ready\ntxn pid=83983 euid=10001 code=7 marker=11223344 fd=hello\n"
        );
        assert_eq!(CALL_OUT, "reply=00000042 pid=83983\n");
        assert_eq!(DEAD_OUT, "dead code=00007205\n");
        // The tracer prints the directory fd. The old needle is not this line.
        assert!(!SERVE_ERR.contains("openat(\"/dev/binder\""));
        assert!(SERVE_ERR.contains(
            "openat(-100, \"/dev/binder\", 0x80002, 0x0) = 3 [pid=83980 tid=83980 call=0 leave]"
        ));
        assert!(SERVE_ERR
            .contains("read(0x40, 0x800486c600, 0x5) = 5 [pid=83980 tid=83980 call=7 leave]"));
        assert!(CALL_ERR.contains(
            "pipe2(0x800486c560, 0x0, 0x3, 0x22, -1, 0x0) = 0 [pid=83983 tid=83983 call=3 leave]"
        ));
        assert!(CALL_ERR
            .contains("write(0x5, 0x800486c600, 0x5) = 5 [pid=83983 tid=83983 call=4 leave]"));
        assert!(CALL_ERR.contains("getpid() = 0x1480f [pid=83983 tid=83983 call=8 leave]"));
        assert!(DEAD_ERR.contains(
            "ioctl(0x3, 0xc0306201, 0x800486c040) = 0 [pid=83992 tid=83992 call=3 leave]"
        ));
        assert!(accept_binder_trace(SERVE_ERR, GuestRole::Serve, 83980, rewrites).is_ok());
        assert!(accept_binder_trace(CALL_ERR, GuestRole::Call, 83983, rewrites).is_ok());
        assert!(accept_binder_trace(DEAD_ERR, GuestRole::Dead, 83992, rewrites).is_ok());
    }

    #[test]
    fn a_path_string_or_a_failed_open_is_not_success() {
        let rewrites = rewrites();
        let loose = "openat(\"/dev/binder\"\n[linux] ioctl(0x3, 0xc0306201, 0x1) [pid=1 tid=1 call=0 enter]\n";
        assert!(loose.contains("openat(\"/dev/binder\""));
        assert!(loose.contains("[linux] ioctl("));
        assert!(accept_binder_trace(loose, GuestRole::Serve, 1, rewrites).is_err());

        let denied = SERVE_ERR.replace(
            "= 3 [pid=83980 tid=83980 call=0 leave]",
            "= -13 (EACCES) [pid=83980 tid=83980 call=0 leave]",
        );
        assert!(accept_binder_trace(&denied, GuestRole::Serve, 83980, rewrites).is_err());

        let other_dir = SERVE_ERR.replace("openat(-100,", "openat(0x4,");
        assert!(accept_binder_trace(&other_dir, GuestRole::Serve, 83980, rewrites).is_err());

        let short_read = SERVE_ERR.replace(
            "read(0x40, 0x800486c600, 0x5) = 5",
            "read(0x40, 0x800486c600, 0x5) = 4",
        );
        assert!(accept_binder_trace(&short_read, GuestRole::Serve, 83980, rewrites).is_err());

        let failed_ioctl = SERVE_ERR.replacen(
            "ioctl(0x3, 0xc0306201, 0x800486c040) = 0",
            "ioctl(0x3, 0xc0306201, 0x800486c040) = -1 (EPERM)",
            1,
        );
        assert!(accept_binder_trace(&failed_ioctl, GuestRole::Serve, 83980, rewrites).is_err());

        let failed_mmap = SERVE_ERR.replace("= 0x800484c000", "= -12 (ENOMEM)");
        assert!(accept_binder_trace(&failed_mmap, GuestRole::Serve, 83980, rewrites).is_err());
    }

    #[test]
    fn roles_and_pids_do_not_substitute() {
        let rewrites = rewrites();
        assert!(accept_binder_trace(SERVE_ERR, GuestRole::Call, 83980, rewrites).is_err());
        assert!(accept_binder_trace(SERVE_ERR, GuestRole::Dead, 83980, rewrites).is_err());
        assert!(accept_binder_trace(CALL_ERR, GuestRole::Serve, 83983, rewrites).is_err());
        assert!(accept_binder_trace(DEAD_ERR, GuestRole::Serve, 83992, rewrites).is_err());
        assert!(accept_binder_trace(CALL_ERR, GuestRole::Call, 83980, rewrites).is_err());
        assert!(accept_binder_trace(SERVE_ERR, GuestRole::Serve, 1, rewrites).is_err());
    }
}

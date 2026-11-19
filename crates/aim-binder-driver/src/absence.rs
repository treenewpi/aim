//! What an original `service check` trace means when no context manager
//! is registered.
//!
//! Android 16's `defaultServiceManager` does not return null on that
//! path. It transacts to handle 0, and on `BR_DEAD_REPLY` it sleeps and
//! tries again. `Unable to get default service manager` is printed only
//! if that function returns null. A completed read of `BR_DEAD_REPLY`
//! followed by `nanosleep`, while the process is still running, is the
//! absence. A `BR_REPLY`, a "found" line, or a `BINDER_WRITE_READ` that
//! never returns is not.

/// `waiting` is the sleep loop. `exited` is the original null-manager
/// line after the process left. `None` is not an observed absence.
pub fn no_manager_outcome(stdout: &str, stderr: &str, exited: bool) -> Option<&'static str> {
    if stdout.contains("Service manager: found") || stdout.contains("IServiceManager") {
        return None;
    }
    if exited
        && stdout.contains("Unable to get default service manager")
        && binder_device_opened(stderr)
    {
        return Some("exited");
    }
    if !exited && dead_reply_then_sleep(stderr) {
        return Some("waiting");
    }
    None
}

/// Why the observation window did not see an absence. This is a missing
/// result, not a successful lookup.
pub fn absence_blocker(stdout: &str, stderr: &str, exited: bool) -> String {
    if stdout.contains("Service manager: found") || stdout.contains("IServiceManager") {
        return "service check reported a manager while no context manager was registered".into();
    }
    if !binder_device_opened(stderr) {
        return "service check did not complete openat of /dev/binder".into();
    }
    if saw_command(stderr, "BR_REPLY") {
        return "service check read BR_REPLY while no context manager was registered".into();
    }
    if !saw_command(stderr, "BR_DEAD_REPLY") {
        return "service check opened /dev/binder but no completed read returned BR_DEAD_REPLY"
            .into();
    }
    if !write_read_returned(stderr) {
        return "BINDER_WRITE_READ did not return 0".into();
    }
    if exited {
        return "service check exited without the original no-manager line".into();
    }
    "service check got BR_DEAD_REPLY but did not sleep and retry; the ioctl may still be parked"
        .into()
}

fn binder_read_commands(line: &str) -> Option<Vec<&str>> {
    let rest = line.strip_prefix("[linux-abi] binder-read ")?;
    let mut parts = rest.split_whitespace();
    let fd = parts.next()?;
    if !fd.starts_with("fd=") {
        return None;
    }
    Some(parts.collect())
}

fn saw_command(stderr: &str, name: &str) -> bool {
    stderr.lines().any(|line| {
        binder_read_commands(line).is_some_and(|commands| commands.iter().any(|c| *c == name))
    })
}

fn write_read_returned(stderr: &str) -> bool {
    stderr.lines().any(|line| {
        line.starts_with("[linux] ioctl(")
            && line.contains("0xc0306201")
            && line.contains(" = 0 ")
            && line.ends_with(" leave]")
    })
}

fn dead_reply_then_sleep(stderr: &str) -> bool {
    let mut dead = false;
    let mut write_read = false;
    for line in stderr.lines() {
        if let Some(commands) = binder_read_commands(line) {
            if commands.iter().any(|c| *c == "BR_REPLY") {
                return false;
            }
            if commands.iter().any(|c| *c == "BR_DEAD_REPLY") {
                dead = true;
            }
        }
        if line.starts_with("[linux] ioctl(")
            && line.contains("0xc0306201")
            && line.contains(" = 0 ")
            && line.ends_with(" leave]")
        {
            write_read = true;
        }
        if dead
            && write_read
            && line.starts_with("[linux] nanosleep(")
            && line.contains(" = 0 ")
            && line.ends_with(" leave]")
        {
            return binder_device_opened(stderr);
        }
    }
    false
}

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

#[cfg(test)]
mod tests {
    use super::{absence_blocker, binder_device_opened, dead_reply_then_sleep, no_manager_outcome};

    fn trace(open_dirfd: &str, extra: &str) -> String {
        format!(
            "[linux] openat({open_dirfd}, \"/dev/binder\", 0x80002, 0x0) = 3 [pid=1 tid=1 call=1 leave]\n\
             [linux-abi] binder-read fd=3 BR_NOOP BR_DEAD_REPLY\n\
             [linux] ioctl(0x3, 0xc0306201, 0x10) = 0 [pid=1 tid=1 call=2 leave]\n\
             {extra}"
        )
    }

    #[test]
    fn dead_reply_and_a_later_sleep_is_the_wait() {
        for dirfd in ["-100", "0xffffff9c"] {
            let stderr = trace(
                dirfd,
                "[linux] nanosleep(0x80049ef688, 0x80049ef688) = 0 [pid=1 tid=1 call=3 leave]\n",
            );
            assert!(binder_device_opened(&stderr), "{dirfd}");
            assert!(dead_reply_then_sleep(&stderr), "{dirfd}");
            assert_eq!(
                no_manager_outcome("", &stderr, false),
                Some("waiting"),
                "{dirfd}"
            );
            assert_eq!(no_manager_outcome("", &stderr, true), None, "{dirfd}");
        }
    }

    #[test]
    fn a_reply_or_a_found_line_is_not_absence() {
        let replied = trace(
            "0xffffff9c",
            "[linux-abi] binder-read fd=3 BR_REPLY\n\
             [linux] nanosleep(0x20, 0x20) = 0 [pid=1 tid=1 call=4 leave]\n",
        );
        assert!(!dead_reply_then_sleep(&replied));
        assert!(absence_blocker("", &replied, false).contains("BR_REPLY"));
        let stderr = trace(
            "-100",
            "[linux] nanosleep(0x20, 0x20) = 0 [pid=1 tid=1 call=3 leave]\n",
        );
        assert_eq!(
            no_manager_outcome("Service manager: found\n", &stderr, false),
            None
        );
    }

    #[test]
    fn the_original_no_manager_line_counts_only_after_exit() {
        let stderr =
            "[linux] openat(-100, \"/dev/binder\", 0x80002, 0x0) = 3 [pid=1 tid=1 call=1 leave]\n";
        let stdout = "Unable to get default service manager!\n";
        assert_eq!(no_manager_outcome(stdout, stderr, true), Some("exited"));
        assert_eq!(no_manager_outcome(stdout, stderr, false), None);
    }

    #[test]
    fn sleep_before_the_dead_reply_does_not_count() {
        let stderr = "\
[linux] nanosleep(0x20, 0x20) = 0 [pid=1 tid=1 call=1 leave]
[linux] openat(0xffffff9c, \"/dev/binder\", 0x80002, 0x0) = 3 [pid=1 tid=1 call=2 leave]
[linux-abi] binder-read fd=3 BR_NOOP BR_DEAD_REPLY
[linux] ioctl(0x3, 0xc0306201, 0x10) = 0 [pid=1 tid=1 call=3 leave]
";
        assert!(!dead_reply_then_sleep(stderr));
        assert!(absence_blocker("", stderr, false).contains("did not sleep"));
    }

    #[test]
    fn an_ioctl_that_does_not_return_is_not_the_wait() {
        let stderr = "\
[linux] openat(0xffffff9c, \"/dev/binder\", 0x80002, 0x0) = 3 [pid=1 tid=1 call=1 leave]
[linux] ioctl(0x3, 0xc0306201, 0x10) [pid=1 tid=1 call=2 enter]
";
        assert_eq!(no_manager_outcome("", stderr, false), None);
        let why = absence_blocker("", stderr, false);
        assert!(why.contains("BR_DEAD_REPLY"), "{why}");
    }
}

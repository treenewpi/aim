//! `reboot` (arm64 142) inside this process's pid namespace.
//!
//! Linux `reboot_pid_ns` does not reboot the machine when the caller is
//! outside the initial pid namespace. `LINUX_REBOOT_CMD_RESTART` and
//! `RESTART2` kill the namespace init with `SIGHUP`. `POWER_OFF` and
//! `HALT` kill it with `SIGINT`. The syscall does not return success.
//! Any other command is `EINVAL`. This process is that namespace init.

use crate::errno::{EINVAL, EPERM};

const MAGIC1: u32 = 0xfee1_dead;
const MAGIC2: u32 = 672_274_793;
const MAGIC2A: u32 = 85_072_278;
const MAGIC2B: u32 = 369_367_448;
const MAGIC2C: u32 = 537_993_216;

const CMD_RESTART: u32 = 0x0123_4567;
const CMD_HALT: u32 = 0xcdef_0123;
const CMD_POWER_OFF: u32 = 0x4321_fedc;
const CMD_RESTART2: u32 = 0xa1b2_c3d4;

const SIGHUP: i32 = 1;
const SIGINT: i32 = 2;

pub(crate) enum NamespaceReboot {
    Invalid,
    NotPermitted,
    Kill { signal: i32, reason: String },
}

pub(crate) fn namespace_reboot(
    magic1: u32,
    magic2: u32,
    cmd: u32,
    arg: &str,
    capable: bool,
) -> NamespaceReboot {
    if magic1 != MAGIC1 || !matches!(magic2, MAGIC2 | MAGIC2A | MAGIC2B | MAGIC2C) {
        return NamespaceReboot::Invalid;
    }
    if !capable {
        return NamespaceReboot::NotPermitted;
    }
    let (signal, reason) = match cmd {
        CMD_RESTART => (SIGHUP, "restart".to_string()),
        CMD_RESTART2 => (
            SIGHUP,
            if arg.is_empty() {
                "restart".to_string()
            } else {
                arg.to_string()
            },
        ),
        CMD_POWER_OFF => (SIGINT, "power-off".to_string()),
        CMD_HALT => (SIGINT, "halt".to_string()),
        _ => return NamespaceReboot::Invalid,
    };
    NamespaceReboot::Kill { signal, reason }
}

pub fn reboot(a: [u64; 6]) -> i64 {
    let magic1 = a[0] as u32;
    let magic2 = a[1] as u32;
    let cmd = a[2] as u32;
    let arg = if cmd == CMD_RESTART2 && a[3] != 0 {
        match super::user_memory::read_cstr(a[3], 256) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(error) => return -(error as i64),
        }
    } else {
        String::new()
    };
    match namespace_reboot(
        magic1,
        magic2,
        cmd,
        &arg,
        super::cred::capable(super::cred::CAP_SYS_BOOT),
    ) {
        NamespaceReboot::Invalid => -(EINVAL as i64),
        NamespaceReboot::NotPermitted => -(EPERM as i64),
        NamespaceReboot::Kill { signal, reason } => {
            let line = format!("guest-requested reboot: {reason}");
            crate::diag!("linux-run: {line}");
            if let Some(runtime) = crate::vfs::runtime_dir() {
                let _ = std::fs::write(runtime.join("reboot-reason"), format!("{line}\n"));
            }
            super::signal::die(signal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart2_records_the_arg_and_kills_init_with_sighup() {
        let effect = namespace_reboot(
            MAGIC1,
            MAGIC2,
            CMD_RESTART2,
            "reboot,bootloader,bootstrap-apexd-failed",
            true,
        );
        match effect {
            NamespaceReboot::Kill { signal, reason } => {
                assert_eq!(signal, SIGHUP);
                assert_eq!(reason, "reboot,bootloader,bootstrap-apexd-failed");
            }
            NamespaceReboot::Invalid | NamespaceReboot::NotPermitted => {
                panic!("restart2 must kill the namespace init")
            }
        }
    }

    #[test]
    fn power_off_is_sigint_and_a_bad_magic_is_einval() {
        match namespace_reboot(MAGIC1, MAGIC2, CMD_POWER_OFF, "", true) {
            NamespaceReboot::Kill { signal, reason } => {
                assert_eq!(signal, SIGINT);
                assert_eq!(reason, "power-off");
            }
            NamespaceReboot::Invalid | NamespaceReboot::NotPermitted => panic!("power off"),
        }
        assert!(matches!(
            namespace_reboot(0, MAGIC2, CMD_RESTART, "", true),
            NamespaceReboot::Invalid
        ));
        assert!(matches!(
            namespace_reboot(MAGIC1, MAGIC2, CMD_RESTART, "", false),
            NamespaceReboot::NotPermitted
        ));
        assert!(matches!(
            namespace_reboot(MAGIC1, MAGIC2, 0, "", true),
            NamespaceReboot::Invalid
        ));
    }
}

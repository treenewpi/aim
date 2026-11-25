//! Fetch the pinned reDroid arm64 layer, stage original `linker64` and
//! toybox, and run them under `linux-run`.
//!
//! Pass `--fetch` to download the pinned layer, `--prepare` to stage it,
//! and `--linux-run` to execute. A missing layer, a hash mismatch, a
//! missing library, or a guest that does not print the original program's
//! output exits nonzero. This does not boot reDroid.

use std::path::PathBuf;
use std::process::ExitCode;

use aim_bionic_smoke::{
    execute, fetch, prepare, prepare_init, prepare_integrated, prepare_property, require_layer,
    run_init, run_property, DIFF_ID, LAYER_DIGEST, LAYER_SIZE, MANIFEST_DIGEST, REPOSITORY, TAG,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bionic-smoke: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut linux_run: Option<PathBuf> = None;
    let mut do_fetch = false;
    let mut prepare_only = false;
    let mut prepare_manager = false;
    let mut prepare_property_root = false;
    let mut prepare_integrated_root = false;
    let mut prepare_init_root = false;
    let mut property: Option<PathBuf> = None;
    let mut init_probe: Option<PathBuf> = None;
    let mut init_timeout = std::time::Duration::from_secs(8);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--linux-run" => {
                linux_run = Some(PathBuf::from(
                    args.next().ok_or("--linux-run needs a path")?,
                ));
            }
            "--fetch" => do_fetch = true,
            "--prepare" => prepare_only = true,
            "--prepare-servicemanager" => prepare_manager = true,
            "--prepare-property" => prepare_property_root = true,
            "--prepare-integrated" => prepare_integrated_root = true,
            "--prepare-init" => prepare_init_root = true,
            "--property" => {
                property = Some(PathBuf::from(args.next().ok_or("--property needs linux-run")?));
            }
            "--init" => {
                init_probe = Some(PathBuf::from(args.next().ok_or("--init needs linux-run")?));
            }
            "--init-timeout" => {
                let text = args.next().ok_or("--init-timeout needs seconds")?;
                let secs: u64 = text
                    .parse()
                    .map_err(|_| "--init-timeout needs a whole number of seconds")?;
                if secs == 0 {
                    return Err("--init-timeout must be at least 1".into());
                }
                init_timeout = std::time::Duration::from_secs(secs);
            }
            "--help" | "-h" => {
                println!(
                    "\
usage: bionic-smoke --linux-run PATH
       bionic-smoke --fetch
       bionic-smoke --prepare
       bionic-smoke --prepare-servicemanager
       bionic-smoke --prepare-property
       bionic-smoke --property LINUX_RUN
       bionic-smoke --prepare-integrated
       bionic-smoke --prepare-init
       bionic-smoke --init LINUX_RUN [--init-timeout SECONDS]

Pinned image: {REPOSITORY}:{TAG}
  manifest {MANIFEST_DIGEST}
  layer    {LAYER_DIGEST} ({LAYER_SIZE} bytes)
  diff_id  {DIFF_ID}
This is the reDroid Android 16 64-bit image, not the Play Store image.
It does not boot reDroid.
--prepare-servicemanager only stages the original servicemanager and
service binaries, plus a generated /dev/__properties__ where
servicemanager.ready is true. That value lets the original client leave
WaitForProperty. It is not a binder result and it does not register a
service or run a transaction.
--prepare-property stages original getprop, setprop and libbase.so on a
copy of the bionic root, plus generated system/bin/property-wait. It does
not write servicemanager.ready. --property starts the property socket and
runs those programs. That command is not accepted until a real Apple
Silicon Mac runs it.
--prepare-integrated copies the servicemanager root, deletes its
generated servicemanager.ready area, and adds original getprop. The
android and libbinder roots stay seeded. aim-binder-proc integrated
starts the property service and the binder daemon, starts the original
service client first, then the original servicemanager. Ready has to
come from that servicemanager's SetProperty.
--prepare-init stages original /system/bin/init and the libraries it
needs. --init runs it for at most --init-timeout seconds (default 8)
and prints the trace.
init-probe: not a boot is the result. A historical list of mremap,
SOCK_SEQPACKET, and rt_tgsigqueueinfo is not that observation.
linux-run probes every round's guest root. That includes
_build/redroid-16-property/root and the other _build roots, plus
TMPDIR. Those directories and the worktree have to sit on one
case-sensitive APFS sparse image. An image mounted only on
_build/redroid-16-init leaves the other roots on the default volume.
Acceptance of that stage is a real Apple Silicon Mac running them under
linux-run on XNU. A Linux compile, unit test, this staging, a Linux VM,
or a Linux container is not that run. A Mac log has to include the host
sysname, machine, release, version, and pagesize, the exact commit, the
commands, each pid and exit code, the original stdout and stderr, and
the transaction text from the original service binary."
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if linux_run.is_none()
        && property.is_none()
        && init_probe.is_none()
        && !prepare_only
        && !prepare_manager
        && !prepare_property_root
        && !prepare_integrated_root
        && !prepare_init_root
        && !do_fetch
    {
        return Err(
            "pass --fetch, --prepare, --prepare-servicemanager, --prepare-property, --prepare-integrated, --prepare-init, --property PATH, --init PATH, or --linux-run PATH; --help prints the pinned digest"
                .into(),
        );
    }
    if prepare_integrated_root {
        if prepare_only {
            let layer = if do_fetch { fetch()? } else { require_layer()? };
            prepare(&layer)?;
        }
        prepare_integrated()?;
        return Ok(());
    }
    if prepare_init_root || init_probe.is_some() {
        if prepare_init_root || prepare_only {
            let layer = if do_fetch { fetch()? } else { require_layer()? };
            if prepare_only {
                prepare(&layer)?;
            }
            prepare_init()?;
        }
        if let Some(linux_run) = init_probe {
            run_init(&linux_run, init_timeout)?;
        }
        return Ok(());
    }
    if prepare_property_root || property.is_some() {
        if prepare_only || prepare_property_root {
            let layer = if do_fetch { fetch()? } else { require_layer()? };
            if prepare_only {
                prepare(&layer)?;
            }
            prepare_property()?;
        }
        if let Some(linux_run) = property {
            run_property(&linux_run)?;
        }
        return Ok(());
    }
    if prepare_manager {
        let layer = if do_fetch { fetch()? } else { require_layer()? };
        if prepare_only {
            prepare(&layer)?;
        }
        aim_bionic_smoke::prepare_manager()?;
        return Ok(());
    }
    let layer = if do_fetch { fetch()? } else { require_layer()? };
    if linux_run.is_none() && !prepare_only {
        println!(
            "bionic-smoke: layer ready {} ({LAYER_SIZE} bytes); pass --linux-run to execute",
            layer.display()
        );
        return Ok(());
    }
    let guest = prepare(&layer)?;
    if prepare_only && linux_run.is_none() {
        println!("bionic-smoke: prepared {} (not executed)", guest.display());
        return Ok(());
    }
    let Some(linux_run) = linux_run else {
        return Err(
            "pass --linux-run PATH to execute linker64 and toybox; --fetch and --prepare stop before execution"
                .into(),
        );
    };
    execute(&linux_run, &guest)
}

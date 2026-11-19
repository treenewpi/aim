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
    execute, fetch, prepare, require_layer, DIFF_ID, LAYER_DIGEST, LAYER_SIZE, MANIFEST_DIGEST,
    REPOSITORY, TAG,
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
            "--help" | "-h" => {
                println!(
                    "\
usage: bionic-smoke --linux-run PATH
       bionic-smoke --fetch
       bionic-smoke --prepare
       bionic-smoke --prepare-servicemanager

Pinned image: {REPOSITORY}:{TAG}
  manifest {MANIFEST_DIGEST}
  layer    {LAYER_DIGEST} ({LAYER_SIZE} bytes)
  diff_id  {DIFF_ID}
This is the reDroid Android 16 64-bit image, not the Play Store image.
It does not boot reDroid.
--prepare-servicemanager only stages the original servicemanager and
service binaries. It does not register a service or run a transaction.
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
    if linux_run.is_none() && !prepare_only && !prepare_manager && !do_fetch {
        return Err(
            "pass --fetch, --prepare, --prepare-servicemanager, or --linux-run PATH; --help prints the pinned digest"
                .into(),
        );
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

//! Run the synthetic Linux AArch64 ELF under `linux-run`.
//!
//! This is not an Android userspace and not a reDroid boot. It checks that
//! one static PIE is loaded, that `svc #0` and `tpidr_el0` are rewritten,
//! and that mmap, munmap, getpid and write return Linux results.
//!
//! `--self-check` only audits the fixture bytes and exits 0. It does not
//! execute the ELF. A missing `linux-run` or a guest that does not produce
//! the line exits nonzero.

use std::path::{Path, PathBuf};
use std::process::Command;

use aim_elf_smoke::{install, program, trace_matches, PAGE_LINE, TLS_LINE};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut linux_run: Option<PathBuf> = None;
    let mut self_check = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--self-check" => self_check = true,
            "--linux-run" => {
                linux_run = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    fail(2, "--linux-run needs a path");
                })));
            }
            "--help" | "-h" => {
                println!("usage: elf-smoke --self-check\n       elf-smoke --linux-run PATH");
                return;
            }
            other => fail(2, &format!("unknown argument {other}")),
        }
    }
    let (elf, rewrites) = program();
    if rewrites.mrs_tpidr != 1 || rewrites.msr_tpidr != 1 || rewrites.svc < 7 {
        fail(2, &format!("fixture rewrite sites are wrong: {rewrites:?}"));
    }
    if self_check {
        println!(
            "elf-smoke self-check: {} bytes, {} svc, {} mrs, {} msr; not executed",
            elf.len(),
            rewrites.svc,
            rewrites.mrs_tpidr,
            rewrites.msr_tpidr
        );
        return;
    }
    let Some(linux_run) = linux_run else {
        fail(
            2,
            "pass --linux-run PATH, or --self-check to audit the fixture only",
        );
    };
    if !linux_run.is_file() {
        fail(
            2,
            &format!(
                "linux-run is not a file at {} (build it with cargo build -p aim-linux-abi --release --bin linux-run --locked)",
                linux_run.display()
            ),
        );
    }

    let root = std::env::temp_dir().join(format!("aim-elf-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("bin")).unwrap_or_else(|error| {
        fail(2, &format!("cannot create {}: {error}", root.display()));
    });
    let guest = root.join("bin/elf-smoke");
    install(&guest, &elf).unwrap_or_else(|error| {
        fail(2, &format!("cannot install {}: {error}", guest.display()));
    });

    reject_non_elf(&linux_run, &root);
    let output = run(&linux_run, &root, &["/bin/elf-smoke"]);
    if !output.status.success() {
        fail(
            output.code(),
            &format!(
                "guest exited {}\nstdout:\n{}\nstderr:\n{}",
                output.code(),
                output.stdout,
                output.stderr
            ),
        );
    }
    if !output.stdout.contains(PAGE_LINE) || !output.stdout.contains(TLS_LINE) {
        fail(
            1,
            &format!(
                "guest did not print the lines it writes after the checks\nstdout:\n{}",
                output.stdout
            ),
        );
    }
    let pid_line = output
        .stdout
        .lines()
        .find(|line| line.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or("");
    if pid_line != output.pid {
        fail(
            1,
            &format!(
                "getpid printed {pid_line:?}, linux-run pid is {}\nstdout:\n{}",
                output.pid, output.stdout
            ),
        );
    }
    if !trace_matches(&output.stderr, rewrites) {
        fail(
            1,
            &format!(
                "load-time trace does not show the fixture's svc/mrs/msr sites\nstderr:\n{}",
                output.stderr
            ),
        );
    }
    println!("{}", output.stdout.trim_end());
    println!(
        "elf-smoke: linux-run pid {} matched getpid; trace has the rewrite counts",
        output.pid
    );
    let _ = std::fs::remove_dir_all(&root);
}

struct Output {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
    pid: String,
}

impl Output {
    fn code(&self) -> i32 {
        self.status.code().unwrap_or(101)
    }
}

fn run(linux_run: &Path, root: &Path, guest_args: &[&str]) -> Output {
    // `--no-cache` forces load-time rewriting, so the trace carries this
    // file's svc/mrs/msr counts instead of a cached image with zero of them.
    let mut child = Command::new(linux_run);
    child
        .arg("--no-cache")
        .arg("--trace")
        .arg("--root")
        .arg(root)
        .args(guest_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let process = child.spawn().unwrap_or_else(|error| {
        fail(2, &format!("cannot start linux-run: {error}"));
    });
    let pid = process.id().to_string();
    let output = process.wait_with_output().unwrap_or_else(|error| {
        fail(2, &format!("linux-run wait: {error}"));
    });
    Output {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        pid,
    }
}

fn reject_non_elf(linux_run: &Path, root: &Path) {
    let junk = root.join("bin/not-elf");
    // Executable, so the failure is ENOEXEC from the ELF check. Mode 0644
    // stops at EACCES before that check and does not cover it.
    install(&junk, b"this is not an elf").unwrap_or_else(|error| {
        fail(2, &format!("cannot install {}: {error}", junk.display()));
    });
    let output = run(linux_run, root, &["/bin/not-elf"]);
    expect_exec_errno(&output, 8, "non-ELF");
    let missing = run(linux_run, root, &["/bin/does-not-exist"]);
    expect_exec_errno(&missing, 2, "missing path");
}

fn expect_exec_errno(output: &Output, errno: i32, what: &str) {
    let marker = format!("cannot execute (errno {errno})");
    if output.status.success()
        || output.stdout.contains(PAGE_LINE)
        || !output.stderr.contains(&marker)
    {
        fail(
            1,
            &format!(
                "{what} was not rejected with {marker}\nstdout:\n{}\nstderr:\n{}",
                output.stdout, output.stderr
            ),
        );
    }
}

fn fail(code: i32, message: &str) -> ! {
    eprintln!("elf-smoke: {message}");
    std::process::exit(code);
}

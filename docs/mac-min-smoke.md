# Minimum Mac checks

These commands do not boot Android and do not run reDroid. They exercise
the binder driver in one host process, then one synthetic Linux AArch64
ELF under `linux-run`. Rust 1.88 or newer is required (`&& let`, edition
2024). `cargo fetch -p` is not a Cargo command; fetch the lockfile with
`cargo fetch --locked`.

The binder tests need a compiler and the crates in `Cargo.lock` for
`aim-binder-host` (`libc`, `sha2` and their default-feature dependencies).
They do not need Xcode, the NDK, an Android image, or ANGLE. The ELF smoke
does not need those either. It is not bionic, `linker64`, ART, or a
reDroid image.

## Binder, after the fd-table fix

From a clean checkout of this commit, with `CARGO_HOME` and
`RUSTUP_HOME` pointed at a disposable toolchain if the system Rust is not
1.88:

```sh
cargo fetch --locked
cargo test --locked -p aim-binder-driver -- --nocapture
cargo test --locked -p aim-binder-host --test transport -- --nocapture
cargo test --locked -p aim-binder-host --test transport concurrent_servers_pass_fds_without_crossing_descriptors -- --exact --nocapture
```

The default `transport` run is the one that failed and hung at
`2f3f43ae` when several tests shared a process. `--test-threads=1` passing
is not the fix. Expect every `transport` test to pass, including
`typed_fd_import_failure_rolls_back_delivery_before_copyout_and_unblocks_sender`
(`Err(22)` from the typed import) and the two fd tests that previously
stayed inside `BINDER_WRITE_READ`. A stuck ioctl prints
`binder transport ioctl still blocked after 15s` and the test process
exits 101.

`cargo test --locked -p aim-binder-host -- --nocapture` is the wider host
suite. It is still one process per test binary. It is not cross-process
IPC and not an Android boot.

## Synthetic ELF

Stage 1 only: a PIE with no interpreter, built from the encodings in
`crates/aim-elf-smoke`. Linux can audit the bytes. Execution is macOS,
because `linux-run` is the XNU syscall layer.

```sh
cargo test --locked -p aim-elf-smoke -- --nocapture
cargo run --locked -p aim-elf-smoke --release --bin elf-smoke -- --self-check
cargo build --locked -p aim-linux-abi --release --bin linux-run
cargo run --locked -p aim-elf-smoke --release --bin elf-smoke -- --linux-run target/release/linux-run
```

`--self-check` exits 0 without running the ELF. The last command exits 0
only when all of these are true:

- a non-ELF file and a missing guest path make `linux-run` fail, and do
  not print `elf-smoke page=16384`
- the guest exits 0
- stdout contains `elf-smoke page=16384` and `tls=ok mmap=ok`
- the digit line is the `linux-run` process id (`getpid`)
- stderr contains `load-time rewrites:` with this file's `svc`, `mrs` and
  `msr tpidr_el0` counts

Anything else exits nonzero. Later stages, not claimed here, are an
NDK-built Android ELF (NDK `28.2.13676358`, its license accepted
explicitly) and the pinned image's `linker64` after
`image/original.lock`'s sha256 check. `cargo test -p aim-linux-abi` still
compiles `aim-services` and the generated AIDL; do not use it for this
smoke. Do not run `cargo aim`.

# Minimum Mac checks

These commands do not boot Android and do not run reDroid. They exercise
the binder driver in one host process, one synthetic Linux AArch64 ELF
under `linux-run`, then the original reDroid `linker64` and toybox. Rust
1.88 or newer is required (`&& let`, edition 2024). `cargo fetch -p` is
not a Cargo command; fetch the lockfile with `cargo fetch --locked`.

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

A fresh SSH session on the M4 has `RLIMIT_NOFILE` soft 256 and hard
unlimited. Soft 256 makes `pipe()` return -1; the 15s ioctl watchdog then
exits 101. That is a descriptor limit, not a binder assertion failure.
The transport test binary reads the soft and hard limits. When the hard
limit allows it, the binary raises **this process only** to soft 4096
with `setrlimit` and prints both numbers. It does not change the shell,
`launchctl`, or any global limit, and it does not use sudo. If the hard
limit is below 4096 it exits 2 and prints `ulimit -Sn 4096` for this
process tree. A new SSH session stays at 256 until a test process raises
itself.

These tests are still one process. They do not prove independent
process IPC.

Expect every `transport` test to pass, including
`typed_fd_import_failure_rolls_back_delivery_before_copyout_and_unblocks_sender`
(`Err(22)` from the typed import). A stuck ioctl prints
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

`--self-check` exits 0 without running the ELF. Pass `--linux-run` the
absolute path of the release `linux-run` just built. Do not `chmod` the
fixture. The runner writes it, and the non-ELF control, as mode `0755`.
`0644` stops in `cannot execute (errno 13)` (`EACCES`) before the ELF
header is read, which is not a loader result. A standalone `linux-run`
is its own POSIX lock holder when `aim-lock-holder` is not beside it;
the pid-namespace watcher still starts and must write its ready byte.
Stderr that contains `pid namespace watcher` or `stage=watcher-startup`
means the guest ELF was not loaded. A missing path or a non-ELF file is
not a negative control until that line is absent.

The syscall bridge follows the Linux AArch64 rule: a normal `svc` returns
in x0 and preserves the other general registers (`trampoline.S` saves
them on the full path, and the per-site stub restores the x16/x17/x30 it
uses as scratch). A fault at `/bin/elf-smoke+0x160` with `x17 == 0` and
`x20` holding the bytes of `elf-smok` was the fixture encoding `mov x17,
sp` as `orr x17, xzr, xzr` (register 31 is XZR in `ORR`, and SP only in
`ADD`/`SUB` immediate). That run had already completed mmap, munmap and
getpid, with guest `TPIDR_EL0` set. It is not a pass.

The last command exits 0 only when all of these are true:

- stderr does not contain `pid namespace watcher` or `stage=watcher-startup`
- the non-ELF file is rejected with `cannot execute (errno 8)` and the
  missing path with `cannot execute (errno 2)`, and neither prints
  `elf-smoke page=16384`
- the guest exits 0, with no fatal signal
- stdout contains `elf-smoke page=16384` and `tls=ok mmap=ok`
- the digit line is the `linux-run` process id (`getpid`)
- stderr contains `load-time rewrites:` with this file's `svc`, `mrs` and
  `msr tpidr_el0` counts

Anything else exits nonzero. `cargo test -p aim-linux-abi` still
compiles `aim-services` and the generated AIDL; do not use it for this
smoke. Do not run `cargo aim`. The synthetic ELF is not linker64, bionic,
or a reDroid boot.

## Original linker64 and toybox

`bionic-smoke` stages two original binaries from the reDroid Android 16
64-bit image and runs them with `linux-run --no-cache --trace`. It does
not use `image/original.lock` (the Play Store emulator image) and it does
not accept an SDK license. The NDK is not required.

The image is the arm64 manifest of `redroid/redroid:16.0.0_64only-latest`,
pinned by digest so the tag is not resolved again:

- index `sha256:7b1e389bd15f37af3bcd06138f5b2ffa7cfba4332bd5ef54c53e99c2f160a15b`
- manifest `sha256:e194edc99aa364358d1f8c214acb18b6d006c74fa0561f39259a20173ec30b66`
- layer `sha256:efbc1c6b9440932189927a386ba3fc991f8a6b88bb8f56f1fd9b26ee8d7475b6`,
  exactly 733630886 bytes, gzip-compressed OCI layer
- uncompressed diff id `sha256:a234387365bc615147261cd5c7dce4747c0b8a2ba678d88e34f2ccfbce69c379`

`--fetch` downloads that one layer from `registry-1.docker.io` and checks
the sha256 before renaming it into `_build/downloads/`. A CDN redirect is
followed without the registry bearer token. Nothing is downloaded unless
`--fetch` is present. The reDroid project sources are Apache-2.0. This
layer is an AOSP userspace image published by that project, identified by
the digest above; the registry config does not name an AOSP commit. It is
not a GMS image and not the Play Store emulator archive in
`image/original.lock`. The Early Access GSI zip is a different license and
is not used. This is not a legal determination, and the tool does not
accept an SDK license. The tool then keeps only the toybox closure and
`system/apex/com.android.runtime.apex` (8110080 bytes,
`ff43fdc2469f458a6fdf0e5184a34ebbb187a7ec26ab6d70b198d41f75e2921b`). The
rest of the layer is not unpacked. `/apex` is empty in the image;
`system/bin/linker64` is a symlink to
`/apex/com.android.runtime/bin/linker64` inside that apex. The apex
linker64 is 2213304 bytes,
`5fb80c2306d63523bc4c4c5fcfd4e58eb1ea9df90efbdf4a5399be3793f5e20a`.
toybox is 578392 bytes,
`9c64305664c6acde487a4f815e668e3540e55123503076b7ef111a6c05924976`.
Original bytes are copied. The guest root also gets a generated
`linkerconfig/ld.config.txt` (reDroid ships that directory empty until
init runs `linkerconfig`) and a mode `0755` non-ELF control. Neither is
an image file.

Disk for this step is the 733630886-byte layer plus a few tens of
megabytes of extracted files, not the unpacked image.

```sh
cargo test --locked -p aim-bionic-smoke -- --nocapture
cargo build --locked -p aim-linux-abi --release --bin linux-run
cargo build --locked -p aim-bionic-smoke --release --bin bionic-smoke
./target/release/bionic-smoke --fetch
./target/release/bionic-smoke --linux-run "$PWD/target/release/linux-run"
```

A missing layer, a hash mismatch, a missing `DT_NEEDED` library, or a
guest that does not match the checks below exits nonzero. The tests do
not skip when the layer is absent; they never download it. `cargo check`
of this crate on aarch64-apple-darwin is a compile check, not a Mac run.

Pass requires all of the following. A fatal signal is not a pass.

- stderr of the two successful guests contains `from load-time rewrite`
  and `load-time rewrites:`, and does not contain `pid namespace watcher`
- `/apex/com.android.runtime/bin/linker64` exits 0 and stdout starts with
  `Usage: /apex/com.android.runtime/bin/linker64`
- `/system/bin/toybox echo bionic-ok` exits 0 and stdout is exactly
  `bionic-ok` plus a newline
- `/system/bin/not-elf` is rejected with `cannot execute (errno 8)`
- `/system/bin/does-not-exist` is rejected with `cannot execute (errno 2)`
- neither negative prints `bionic-ok`
- the printed audit lines show `machine 183` and no `PT_LOAD` align below
  16384

The program prints `bionic-smoke: original linker64 and toybox ran; this is not a reDroid boot`.
That line is the tool, not the guest. ART, zygote, system services, and
cross-process binder are later milestones. Whether this Android 16 linker
accepts the generated `ld.config.txt`, and whether `libselinux` or
`liblog` constructors abort without policy or logd, is decided by the
Mac run's stderr. Do not treat a Linux compile as that result.

`bc811359` stopped in `WriteProtected`: `mprotect` of `__libc_globals`
(4 KiB at vaddr `0x18e000`, and the same shape in toybox) inside a 16 KiB
page that also holds writable globals. The host page stays 16 KiB.
`AT_PAGESZ` stays 16 KiB, and Bionic is not rebuilt for this. The call
succeeds; the page's protection is the union of its 4 KiB slices, so the
writable globals keep working. A request that gives every slice the same
protection updates the whole page.

`a1d5909` then ran linker64. toybox stopped in
`mmap(0, 0x12c0, PROT_READ, MAP_PRIVATE, libcrypto.so, 0x17a000)`: the
dynamic section's file offset is 8 KiB into a 16 KiB page. A 16 KiB-aligned
private file offset stays a host file mapping. This offset is copied into a
fresh host page, the returned pointer's first byte is file offset
`0x17a000`, and munmap drops that whole host page. Bytes past EOF in the
page are zero.

`67dfb88` then parsed that section. toybox stopped while placing the next
library: `munmap(0x8005d3d000, 0x1e000)` and
`mmap(0x8005da5000, 0xdd0, PROT_READ, MAP_PRIVATE|MAP_FIXED, fd, 0)`.
The formal smoke hit the same shape in a different library
(`mmap(0x8005d4b000, 0x4e44, ...)`). Bionic reserves one anonymous region,
unmaps the padding off both ends, then `MAP_FIXED`s each segment. Those
edges are 4 KiB-aligned. A range with both ends 16 KiB-aligned is unchanged.
Otherwise only the 4 KiB slices inside the request are punched or replaced;
a host page is really unmapped only when every slice is in the request.
`MAP_FIXED` returns the requested address and copies the file into the
covered slices. The page's protection is the union of the slices that are
still present, and a punched slice stays readable until the whole page is
unmapped. A shared `MAP_FIXED` of a partial page is `EINVAL`.

`8a46cb5` placed those file segments. toybox then stopped on
`mmap(0x800619f000, 0x8000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0)`,
`libcrypto.so`'s `.bss`. The formal smoke was the same call at
`0x8005de7000` for `libc++.so`. The whole pages inside that range are
anonymous zeros, so the offset passed for them is 0, not the distance from
the unaligned start. The 4 KiB file slice just before the `.bss` is not
part of the call and keeps its bytes. `MAP_ANONYMOUS` ignores the guest
offset and the descriptor.

`34418cb` mapped those `.bss` ranges. Two later `mprotect` calls are
different. Direct toybox: `mprotect(0x8005fb3000, 0x1000, PROT_READ)` is
`libz.so` GNU RELRO, one 4 KiB data slice beside the text. Formal smoke:
`mprotect(0x8005ee2000, 0x80000, PROT_READ|PROT_EXEC|PROT_BTI)` is
`libc++.so`'s text, already rewritten. Both starts are 4 KiB-aligned.
Execute is part of the host-page union, and `PROT_BTI` is not a host bit.
The RELRO slice is recorded read-only; the text beside it keeps the page
executable, so that data is not a private read-only page. A `mprotect`
whose start and end are both 16 KiB-aligned stays one host call. A 4 KiB
length at a 16 KiB-aligned address does not: rounding it up write-protects
the next three slices.

The layer is already in `_build/downloads`. Do not pass `--fetch` again.
Rebuild `linux-run` from this commit; the existing `bionic-smoke` binary
can call it. The `guest4k_` tests are the regression and do not need the
generated AIDL tree. A passing run of those tests is not a Mac guest run.

```sh
git fetch origin cursor/binder-fd-elf-smoke-602d
git checkout cursor/binder-fd-elf-smoke-602d
cargo test --locked -p aim-guest-page --lib -- --nocapture
cargo build --locked -p aim-linux-abi --release --bin linux-run
./target/release/linux-run --no-cache --trace --root "$PWD/_build/redroid-16-runtime/root" /apex/com.android.runtime/bin/linker64
./target/release/linux-run --no-cache --trace --root "$PWD/_build/redroid-16-runtime/root" /system/bin/toybox echo bionic-ok
./target/release/bionic-smoke --linux-run "$PWD/target/release/linux-run"
```

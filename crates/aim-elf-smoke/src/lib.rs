//! A static position-independent Linux AArch64 ELF built from documented
//! encodings. It is not an Android or bionic program: there is no
//! interpreter, no relocations and no libc. `linux-run` has to translate
//! `svc #0` and `mrs`/`msr tpidr_el0` and answer the Linux syscalls or the
//! process cannot print its line and exit 0.
//!
//! Stages this does not claim: an NDK-built Android ELF, the original
//! `linker64` and bionic, ART, or a reDroid boot.

/// Guest page the loader publishes as `AT_PAGESZ` and this program requires.
pub const PAGE: u64 = 16384;

/// Linux errno-style exit statuses the program uses. 0 is the only success.
pub mod exit {
    pub const PAGE: i32 = 2;
    pub const MMAP: i32 = 3;
    pub const MEMORY: i32 = 4;
    pub const MUNMAP: i32 = 5;
    pub const TLS: i32 = 6;
    pub const PID: i32 = 7;
    pub const WRITE: i32 = 8;
}

/// Substring that is printed only after the page-size check, and only by
/// `write`. A harness that skips the guest must not emit it.
pub const PAGE_LINE: &str = "elf-smoke page=16384\n";
pub const TLS_LINE: &str = "tls=ok mmap=ok\n";

mod binder_guest;
pub use binder_guest::binder_program;

/// `svc #0`, `mrs Xt, tpidr_el0`, `msr tpidr_el0, Xt` as the translator matches them.
const SVC0: u32 = 0xd400_0001;
const MRS_TPIDR: u32 = 0xd53b_d040;
const MSR_TPIDR: u32 = 0xd51b_d040;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rewrites {
    pub svc: usize,
    pub mrs_tpidr: usize,
    pub msr_tpidr: usize,
}

/// The ELF, and how many translator sites it contains.
pub fn program() -> (Vec<u8>, Rewrites) {
    let code = assemble();
    let elf = link(&code);
    let rewrites = count_rewrites(&elf);
    (elf, rewrites)
}

pub fn count_rewrites(elf: &[u8]) -> Rewrites {
    let mut rewrites = Rewrites {
        svc: 0,
        mrs_tpidr: 0,
        msr_tpidr: 0,
    };
    for word in elf.chunks_exact(4) {
        let word = u32::from_le_bytes(word.try_into().unwrap());
        if word == SVC0 {
            rewrites.svc += 1;
        } else if word & !0x1f == MRS_TPIDR {
            rewrites.mrs_tpidr += 1;
        } else if word & !0x1f == MSR_TPIDR {
            rewrites.msr_tpidr += 1;
        }
    }
    rewrites
}

/// Write `bytes` at `path` and set mode `0755`.
///
/// `std::fs::write` creates `0666 & !umask` (`0644` with a normal umask).
/// `linux-run` checks `X_OK` before the ELF header, so that mode is
/// `EACCES` (13) and never reaches the loader. The non-ELF control has to
/// be executable as well, or it fails the same check instead of `ENOEXEC`
/// (8). `set_permissions` applies the mode after the umask.
pub fn install(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// True when `text` is the loader's load-time line for this program.
pub fn trace_matches(text: &str, rewrites: Rewrites) -> bool {
    text.contains(&format!(
        "load-time rewrites: {} svc, {} mrs/{} msr tpidr_el0, 0 scs, 0 ctr_el0 (0 brk fallbacks)",
        rewrites.svc, rewrites.mrs_tpidr, rewrites.msr_tpidr
    ))
}

pub(crate) fn link(code: &[u32]) -> Vec<u8> {
    let code_off = 0x80u64;
    let mut code_bytes = Vec::with_capacity(code.len() * 4);
    for word in code {
        code_bytes.extend_from_slice(&word.to_le_bytes());
    }
    let filesz = code_off + code_bytes.len() as u64;
    let mut elf = vec![0u8; filesz as usize];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    put16(&mut elf, 16, 3); // ET_DYN
    put16(&mut elf, 18, 183); // EM_AARCH64
    put32(&mut elf, 20, 1); // EV_CURRENT
    put64(&mut elf, 24, code_off); // e_entry
    put64(&mut elf, 32, 64); // e_phoff
    put16(&mut elf, 52, 64); // e_ehsize
    put16(&mut elf, 54, 56); // e_phentsize
    put16(&mut elf, 56, 1); // e_phnum
                            // PT_LOAD at file offset 0, vaddr 0, so the headers are mapped and
                            // p_offset ≡ p_vaddr (mod 16 KiB). RX, not RWX.
    let ph = 64;
    put32(&mut elf, ph, 1); // PT_LOAD
    put32(&mut elf, ph + 4, 5); // PF_R | PF_X
    put64(&mut elf, ph + 8, 0); // p_offset
    put64(&mut elf, ph + 16, 0); // p_vaddr
    put64(&mut elf, ph + 24, 0); // p_paddr
    put64(&mut elf, ph + 32, filesz);
    put64(&mut elf, ph + 40, filesz);
    put64(&mut elf, ph + 48, PAGE);
    elf[code_off as usize..].copy_from_slice(&code_bytes);
    elf
}

fn put16(buf: &mut [u8], at: usize, value: u16) {
    buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(buf: &mut [u8], at: usize, value: u32) {
    buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(buf: &mut [u8], at: usize, value: u64) {
    buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub(crate) struct Asm {
    words: Vec<u32>,
    fixes: Vec<(usize, String, i64)>,
    labels: Vec<(String, usize)>,
}

impl Asm {
    pub(crate) fn new() -> Self {
        Self {
            words: Vec::new(),
            fixes: Vec::new(),
            labels: Vec::new(),
        }
    }
    pub(crate) fn label(&mut self, name: impl Into<String>) {
        self.labels.push((name.into(), self.words.len()));
    }
    pub(crate) fn emit(&mut self, word: u32) {
        self.words.push(word);
    }
    pub(crate) fn b(&mut self, label: impl Into<String>) {
        // 0x100 is `B`. Kind 0 is `B.EQ`; the two cannot share a fix kind.
        self.fixes.push((self.words.len(), label.into(), 0x100));
        self.emit(0);
    }
    pub(crate) fn bl(&mut self, label: impl Into<String>) {
        // 0x400 is BL. B.cond stays in 1..=15 and CBZ/CBNZ in 0x200/0x300.
        self.fixes.push((self.words.len(), label.into(), 0x400));
        self.emit(0);
    }
    pub(crate) fn cond(&mut self, label: impl Into<String>, cond: u32) {
        self.fixes
            .push((self.words.len(), label.into(), cond as i64));
        self.emit(0);
    }
    pub(crate) fn cb(&mut self, label: impl Into<String>, nonzero: bool, reg: u32) {
        // 0x200/0x300 stay above the B.cond kinds 1..=15. Bit 8 selects CBNZ.
        let kind = (if nonzero { 0x300 } else { 0x200 }) + reg as i64;
        self.fixes.push((self.words.len(), label.into(), kind));
        self.emit(0);
    }
    pub(crate) fn finish(mut self) -> Vec<u32> {
        for (at, label, kind) in &self.fixes {
            let to = self
                .labels
                .iter()
                .find(|(name, _)| name == label)
                .unwrap_or_else(|| panic!("missing {label}"))
                .1 as i64;
            self.words[*at] = encode_fix(*kind, to - *at as i64);
        }
        self.words
    }
}

/// `kind` 0x100 is an unconditional branch. 0..=15 are B.cond (`0` is B.EQ).
/// 0x200+reg is CBZ, 0x300+reg is CBNZ, and 0x400 is BL.
fn encode_fix(kind: i64, off: i64) -> u32 {
    if kind == 0x100 {
        0x1400_0000 | (off as u32 & 0x03ff_ffff)
    } else if kind == 0x400 {
        0x9400_0000 | (off as u32 & 0x03ff_ffff)
    } else if kind < 0x20 {
        0x5400_0000 | ((off as u32 & 0x7_ffff) << 5) | (kind as u32)
    } else {
        let reg = (kind as u32) & 0x1f;
        let base = if kind & 0x100 != 0 {
            0xb500_0000
        } else {
            0xb400_0000
        };
        base | ((off as u32 & 0x7_ffff) << 5) | reg
    }
}

pub(crate) fn add_imm(rd: u32, rn: u32, imm: u32) -> u32 {
    0x9100_0000 | (imm << 10) | (rn << 5) | rd
}
pub(crate) fn sub_imm(rd: u32, rn: u32, imm: u32) -> u32 {
    0xd100_0000 | (imm << 10) | (rn << 5) | rd
}
pub(crate) fn add_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8b00_0000 | (rm << 16) | (rn << 5) | rd
}
pub(crate) fn ldr(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xf940_0000 | ((byte_off / 8) << 10) | (rn << 5) | rt
}
pub(crate) fn str(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xf900_0000 | ((byte_off / 8) << 10) | (rn << 5) | rt
}
/// `LDR Wt, [Xn, #byte_off]`. Zero-extends into Xt.
pub(crate) fn ldrw(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xb940_0000 | ((byte_off / 4) << 10) | (rn << 5) | rt
}
/// `STR Wt, [Xn, #byte_off]`.
pub(crate) fn strw(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xb900_0000 | ((byte_off / 4) << 10) | (rn << 5) | rt
}
/// `STUR Xt, [Xn, #byte_off]`. `byte_off` is a signed 9-bit byte offset, so
/// the store can sit at a 4-byte boundary inside a write buffer.
pub(crate) fn stur(rt: u32, rn: u32, byte_off: i32) -> u32 {
    0xf800_0000 | (((byte_off as u32) & 0x1ff) << 12) | (rn << 5) | rt
}
pub(crate) fn strb(rt: u32, rn: u32) -> u32 {
    0x3900_0000 | (rn << 5) | rt
}
pub(crate) fn strb_off(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0x3900_0000 | (byte_off << 10) | (rn << 5) | rt
}
pub(crate) fn ldrb(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0x3940_0000 | (byte_off << 10) | (rn << 5) | rt
}
/// `UBFM Xd, Xn, #shift, #63`, which is `LSR Xd, Xn, #shift`.
pub(crate) fn lsr(rd: u32, rn: u32, shift: u32) -> u32 {
    0xd340_fc00 | (shift << 16) | (rn << 5) | rd
}
/// `AND Xd, Xn, #0x3fff`. The logical immediate is a 64-bit element of 14 ones.
pub(crate) fn and_3fff(rd: u32, rn: u32) -> u32 {
    0x9240_3400 | (rn << 5) | rd
}
/// `AND Xd, Xn, #0xf`.
pub(crate) fn and_15(rd: u32, rn: u32) -> u32 {
    0x9240_0c00 | (rn << 5) | rd
}
pub(crate) fn movz(rd: u32, imm: u32) -> u32 {
    0xd280_0000 | (imm << 5) | rd
}
pub(crate) fn movk(rd: u32, imm: u32, hw: u32) -> u32 {
    0xf280_0000 | (hw << 21) | (imm << 5) | rd
}
pub(crate) fn movn(rd: u32, imm: u32) -> u32 {
    0x9280_0000 | (imm << 5) | rd
}
fn movn0(rd: u32) -> u32 {
    movn(rd, 0)
}
pub(crate) fn mov_reg(rd: u32, rm: u32) -> u32 {
    // ORR (register) reads register 31 as XZR, never SP.
    0xaa00_03e0 | (rm << 16) | rd
}

/// `mov xd, sp`. The ARM ARM alias is `add xd, sp, #0`. `mov_reg` cannot
/// encode it: the same register field 31 is XZR there, so `mov_reg(rd, SP)`
/// is `mov xd, xzr`.
pub(crate) fn mov_from_sp(rd: u32) -> u32 {
    add_imm(rd, SP, 0)
}
pub(crate) fn cmp_imm(rn: u32, imm: u32) -> u32 {
    0xf100_001f | (imm << 10) | (rn << 5)
}
pub(crate) fn cmp_reg(rn: u32, rm: u32) -> u32 {
    0xeb00_001f | (rm << 16) | (rn << 5)
}
pub(crate) fn udiv(rd: u32, rn: u32, rm: u32) -> u32 {
    0x9ac0_0800 | (rm << 16) | (rn << 5) | rd
}
pub(crate) fn msub(rd: u32, rn: u32, rm: u32, ra: u32) -> u32 {
    0x9b00_8000 | (rm << 16) | (ra << 10) | (rn << 5) | rd
}
pub(crate) fn svc() -> u32 {
    SVC0
}
pub(crate) fn ret() -> u32 {
    0xd65f_03c0
}
fn msr_tp(rn: u32) -> u32 {
    MSR_TPIDR | rn
}
fn mrs_tp(rt: u32) -> u32 {
    MRS_TPIDR | rt
}

pub(crate) const SP: u32 = 31;
const XZR: u32 = 31;

pub(crate) fn mov_imm64(a: &mut Asm, rd: u32, value: u64) {
    a.emit(movz(rd, (value & 0xffff) as u32));
    for hw in 1..4 {
        let part = ((value >> (hw * 16)) & 0xffff) as u32;
        if part != 0 {
            a.emit(movk(rd, part, hw));
        }
    }
}

fn store_bytes(a: &mut Asm, base: u32, bytes: &[u8]) {
    let mut at = 0;
    while at < bytes.len() {
        let mut chunk = [0u8; 8];
        let n = (bytes.len() - at).min(8);
        chunk[..n].copy_from_slice(&bytes[at..at + n]);
        let value = u64::from_le_bytes(chunk);
        mov_imm64(a, 20, value);
        a.emit(str(20, base, at as u32));
        at += 8;
    }
}

fn assemble() -> Vec<u32> {
    let mut a = Asm::new();
    // Walk the Linux initial stack to AT_PAGESZ. x0..x30 are zero; sp is set.
    a.emit(add_imm(9, SP, 0));
    a.emit(ldr(10, 9, 0)); // argc
    a.emit(add_imm(10, 10, 1));
    a.emit(add_imm(9, 9, 8));
    a.emit(add_reg(10, 10, 10));
    a.emit(add_reg(10, 10, 10));
    a.emit(add_reg(10, 10, 10));
    a.emit(add_reg(9, 9, 10));
    a.label("env");
    a.emit(ldr(10, 9, 0));
    a.emit(add_imm(9, 9, 8));
    a.cb("env", true, 10);
    a.label("aux");
    a.emit(ldr(10, 9, 0));
    a.emit(ldr(11, 9, 8));
    a.emit(add_imm(9, 9, 16));
    a.cb("bad_page", false, 10);
    a.emit(cmp_imm(10, 6));
    a.cond("aux", 1); // B.NE
    a.emit(movz(12, 16384));
    a.emit(cmp_reg(11, 12));
    a.cond("bad_page", 1);

    a.emit(mov_reg(0, XZR));
    a.emit(movz(1, 16384));
    a.emit(movz(2, 3)); // PROT_READ|PROT_WRITE
    a.emit(movz(3, 0x22)); // MAP_PRIVATE|MAP_ANONYMOUS
    a.emit(movn0(4));
    a.emit(mov_reg(5, XZR));
    a.emit(movz(8, 222)); // mmap
    a.emit(svc());
    a.emit(cmp_imm(0, 0));
    a.cond("bad_mmap", 0xd); // B.LE
    a.emit(mov_reg(13, 0));
    a.emit(movz(14, 0xa11));
    a.emit(str(14, 13, 0));
    a.emit(ldr(15, 13, 0));
    a.emit(cmp_reg(15, 14));
    a.cond("bad_mem", 1);

    a.emit(mov_reg(0, 13));
    a.emit(movz(1, 16384));
    a.emit(movz(8, 215)); // munmap
    a.emit(svc());
    a.cb("bad_unmap", true, 0);

    a.emit(msr_tp(14));
    a.emit(mrs_tp(15));
    a.emit(cmp_reg(15, 14));
    a.cond("bad_tls", 1);

    a.emit(movz(8, 172)); // getpid
    a.emit(svc());
    a.emit(cmp_imm(0, 0));
    a.cond("bad_pid", 0xd);
    a.emit(mov_reg(16, 0));

    a.emit(sub_imm(SP, SP, 128));
    // Linux keeps every GPR except x0 across `svc #0` (the kernel restores
    // pt_regs; `trampoline.S` does the same, and only scratches x16/x17/x30
    // inside the stub). The length in x2 is still live after `write`. The
    // buffer pointer has to be SP, not the XZR `mov_reg` would produce.
    a.emit(mov_from_sp(17));
    store_bytes(&mut a, 17, PAGE_LINE.as_bytes());
    a.emit(movz(0, 1));
    a.emit(mov_reg(1, 17));
    a.emit(movz(2, PAGE_LINE.len() as u32));
    a.emit(movz(8, 64)); // write
    a.emit(svc());
    a.emit(cmp_reg(0, 2));
    a.cond("bad_write", 1);

    // Decimal pid, then a newline, at sp+64.
    a.emit(add_imm(3, SP, 96));
    a.emit(movz(21, 0x0a));
    a.emit(strb(21, 3));
    a.emit(sub_imm(3, 3, 1));
    a.emit(movz(4, 0)); // digits
    a.emit(movz(2, 10));
    a.label("digit");
    a.emit(udiv(5, 16, 2));
    a.emit(msub(6, 5, 2, 16));
    a.emit(add_imm(6, 6, b'0' as u32));
    a.emit(strb(6, 3));
    a.emit(sub_imm(3, 3, 1));
    a.emit(add_imm(4, 4, 1));
    a.emit(mov_reg(16, 5));
    a.cb("digit", true, 16);
    a.emit(add_imm(3, 3, 1));
    a.emit(add_imm(4, 4, 1)); // newline
    a.emit(movz(0, 1));
    a.emit(mov_reg(1, 3));
    a.emit(mov_reg(2, 4));
    a.emit(movz(8, 64));
    a.emit(svc());
    a.emit(cmp_reg(0, 2));
    a.cond("bad_write", 1);

    a.emit(mov_from_sp(17));
    store_bytes(&mut a, 17, TLS_LINE.as_bytes());
    a.emit(movz(0, 1));
    a.emit(mov_reg(1, 17));
    a.emit(movz(2, TLS_LINE.len() as u32));
    a.emit(movz(8, 64));
    a.emit(svc());
    a.emit(cmp_reg(0, 2));
    a.cond("bad_write", 1);

    a.emit(mov_reg(0, XZR));
    a.b("exit");
    a.label("bad_page");
    a.emit(movz(0, exit::PAGE as u32));
    a.b("exit");
    a.label("bad_mmap");
    a.emit(movz(0, exit::MMAP as u32));
    a.b("exit");
    a.label("bad_mem");
    a.emit(movz(0, exit::MEMORY as u32));
    a.b("exit");
    a.label("bad_unmap");
    a.emit(movz(0, exit::MUNMAP as u32));
    a.b("exit");
    a.label("bad_tls");
    a.emit(movz(0, exit::TLS as u32));
    a.b("exit");
    a.label("bad_pid");
    a.emit(movz(0, exit::PID as u32));
    a.b("exit");
    a.label("bad_write");
    a.emit(movz(0, exit::WRITE as u32));
    a.label("exit");
    a.emit(movz(8, 94)); // exit_group
    a.emit(svc());
    a.b("exit");
    a.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings_match_the_architecture_reference() {
        assert_eq!(add_imm(9, 31, 0), 0x9100_03e9);
        assert_eq!(movz(12, 16384), 0xd288_000c);
        assert_eq!(svc(), 0xd400_0001);
        assert_eq!(msr_tp(14), 0xd51b_d04e);
        assert_eq!(mrs_tp(15), 0xd53b_d04f);
        assert_eq!(encode_fix(0x100, 1), 0x1400_0001);
        assert_eq!(encode_fix(0, 1), 0x5400_0020);
        assert_eq!(encode_fix(1, 2), 0x5400_0041);
        assert_eq!(encode_fix(0x200 + 10, -1), 0xb4ff_ffea);
        assert_eq!(encode_fix(0x300 + 10, 1), 0xb500_002a);
    }

    #[test]
    fn fixture_is_a_static_aarch64_pie_with_real_syscall_sites() {
        let (elf, rewrites) = program();
        assert_eq!(&elf[..4], b"\x7fELF");
        assert_eq!(elf[4], 2);
        assert_eq!(elf[5], 1);
        assert_eq!(u16::from_le_bytes(elf[16..18].try_into().unwrap()), 3);
        assert_eq!(u16::from_le_bytes(elf[18..20].try_into().unwrap()), 183);
        assert_eq!(u16::from_le_bytes(elf[56..58].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(elf[64..68].try_into().unwrap()), 1);
        assert_eq!(
            (rewrites.svc, rewrites.mrs_tpidr, rewrites.msr_tpidr),
            (7, 1, 1),
            "{rewrites:?}"
        );
        assert!(trace_matches(
            &format!(
                "[linux-abi] /bin/elf-smoke loaded at bias 0x0 from load time; load-time rewrites: {} svc, {} mrs/{} msr tpidr_el0, 0 scs, 0 ctr_el0 (0 brk fallbacks)",
                rewrites.svc, rewrites.mrs_tpidr, rewrites.msr_tpidr
            ),
            rewrites
        ));
        // The success lines exist only as data immediates, not as a
        // pre-baked "test passed" string the runner can print on its own
        // without the guest storing them.
        assert!(!String::from_utf8_lossy(&elf).contains(PAGE_LINE));
        assert_eq!(mov_from_sp(17), 0x9100_03f1);
        assert_eq!(mov_reg(17, 31), 0xaa1f_03f1);
        assert!(
            elf.windows(4)
                .filter(|w| w == &0x9100_03f1u32.to_le_bytes())
                .count()
                >= 2
        );
        assert!(!elf.windows(4).any(|w| w == &0xaa1f_03f1u32.to_le_bytes()));
    }

    #[test]
    fn install_sets_the_executable_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "aim-elf-smoke-mode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("bin/elf-smoke");
        let (elf, _) = program();
        install(&path, &elf).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "mode {mode:#o}");
        install(&dir.join("bin/not-elf"), b"this is not an elf").unwrap();
        let junk = std::fs::metadata(dir.join("bin/not-elf"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(junk & 0o777, 0o755, "mode {junk:#o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The Mac fault at file offset `0x160` was `str x20, [x17]` with x17
    /// still 0. Under the Linux GPR contract (only x0 changes at `svc`),
    /// that store is the first eight bytes of [`PAGE_LINE`] at the live
    /// stack pointer, and the guest then exits 0.
    #[test]
    fn page_line_store_uses_the_stack_and_the_guest_exits_zero() {
        let code = assemble();
        let at = (0x160 - 0x80) / 4;
        assert_eq!(
            code[at],
            str(20, 17, 0),
            "insn at +0x160 is {:#x}",
            code[at]
        );
        let (writes, store_at) = super::simulate(&code);
        assert_eq!(store_at, 0x8004_8400_00 - 128);
        assert_eq!(writes[0], PAGE_LINE.as_bytes());
        assert_eq!(writes[1], b"81168\n");
        assert_eq!(writes[2], TLS_LINE.as_bytes());
    }
}

/// `svc` result in x0 only. Other GPRs, including the arguments and x8,
/// stay as Linux's `arch/arm64` restore and `trampoline.S` leave them.
#[cfg(test)]
fn simulate(code: &[u32]) -> (Vec<Vec<u8>>, u64) {
    use std::collections::HashMap;

    let mut x = [0u64; 31];
    let mut sp: u64 = 0x8004_8400_00;
    let mut mem = HashMap::<u64, u8>::new();
    let mut tp = 0u64;
    let mut n = false;
    let mut z = false;
    let mut c = false;
    let mut v = false;
    let mut pc: i64 = 0;
    let mut writes = Vec::new();
    let mut page_store = None;
    // argc, argv[0], argv NULL, empty env, AT_PAGESZ = 16384, AT_NULL.
    for (i, word) in [1u64, 0x1, 0, 0, 6, 16384, 0, 0].into_iter().enumerate() {
        store64(&mut mem, sp + i as u64 * 8, word);
    }
    for _ in 0..5000 {
        let here = pc;
        let w = code[here as usize];
        pc = here + 1;
        match decode(w) {
            Op::AddImm { rd, rn, imm, sub } => {
                let base = gsp(&x, sp, rn);
                let value = if sub {
                    base.wrapping_sub(imm)
                } else {
                    base.wrapping_add(imm)
                };
                ssp(&mut x, &mut sp, rd, value);
            }
            Op::AddReg { rd, rn, rm } => {
                x[rd as usize] = x[rn as usize].wrapping_add(xzr(&x, rm));
            }
            Op::Ldr { rt, rn, off } => {
                let addr = gsp(&x, sp, rn).wrapping_add(off);
                ssp(&mut x, &mut sp, rt, load64(&mem, addr));
            }
            Op::Str { rt, rn, off } => {
                let addr = gsp(&x, sp, rn).wrapping_add(off);
                let value = xzr(&x, rt);
                if value == 0x6b6f_6d73_2d66_6c65 {
                    assert_eq!(page_store, None);
                    assert_ne!(addr, 0, "page line stored through a null base");
                    page_store = Some(addr);
                }
                store64(&mut mem, addr, value);
            }
            Op::Strb { rt, rn } => {
                let addr = gsp(&x, sp, rn);
                assert_ne!(addr, 0);
                mem.insert(addr, x[rt as usize] as u8);
            }
            Op::MovZ { rd, imm } => x[rd as usize] = imm,
            Op::MovK { rd, imm, shift } => {
                let clear = !(0xffffu64 << shift);
                x[rd as usize] = (x[rd as usize] & clear) | (imm << shift);
            }
            Op::MovN { rd, imm } => x[rd as usize] = !imm,
            Op::Orr { rd, rm } => x[rd as usize] = xzr(&x, rm),
            Op::CmpImm { rn, imm } => flags(gsp(&x, sp, rn), imm, &mut n, &mut z, &mut c, &mut v),
            Op::CmpReg { rn, rm } => {
                flags(xzr(&x, rn), xzr(&x, rm), &mut n, &mut z, &mut c, &mut v)
            }
            Op::Udiv { rd, rn, rm } => {
                let d = x[rm as usize];
                assert_ne!(d, 0);
                x[rd as usize] = x[rn as usize] / d;
            }
            Op::Msub { rd, rn, rm, ra } => {
                x[rd as usize] =
                    x[ra as usize].wrapping_sub(x[rn as usize].wrapping_mul(x[rm as usize]));
            }
            Op::Svc => {
                let kept = x;
                match x[8] {
                    222 => {
                        assert_eq!(
                            (x[1], x[2], x[3], x[4], x[5]),
                            (16384, 3, 0x22, u64::MAX, 0)
                        );
                        x[0] = 0x8004_84c0_00;
                    }
                    215 => x[0] = 0,
                    172 => x[0] = 81168,
                    64 => {
                        let ptr = x[1];
                        let len = x[2] as usize;
                        assert_ne!(ptr, 0);
                        let bytes = (0..len).map(|i| mem[&(ptr + i as u64)]).collect();
                        writes.push(bytes);
                        x[0] = len as u64;
                    }
                    94 => {
                        assert_eq!(x[0], 0);
                        assert_eq!(writes.len(), 3, "{writes:?}");
                        return (writes, page_store.expect("page line was not stored"));
                    }
                    other => panic!("unexpected syscall {other} at {here}"),
                }
                assert_eq!(&x[1..], &kept[1..], "syscall clobbered a GPR other than x0");
            }
            Op::MsrTp { rn } => tp = xzr(&x, rn),
            Op::MrsTp { rt } => x[rt as usize] = tp,
            Op::B { off } => pc = here + off,
            Op::BCond { off, cond } => {
                if takes(cond, n, z, c, v) {
                    pc = here + off;
                }
            }
            Op::Cb { off, rt, nonzero } => {
                let zero = xzr(&x, rt) == 0;
                if zero != nonzero {
                    pc = here + off;
                }
            }
        }
    }
    panic!("exit_group was not reached");
}

#[cfg(test)]
enum Op {
    AddImm {
        rd: u32,
        rn: u32,
        imm: u64,
        sub: bool,
    },
    AddReg {
        rd: u32,
        rn: u32,
        rm: u32,
    },
    Ldr {
        rt: u32,
        rn: u32,
        off: u64,
    },
    Str {
        rt: u32,
        rn: u32,
        off: u64,
    },
    Strb {
        rt: u32,
        rn: u32,
    },
    MovZ {
        rd: u32,
        imm: u64,
    },
    MovK {
        rd: u32,
        imm: u64,
        shift: u32,
    },
    MovN {
        rd: u32,
        imm: u64,
    },
    Orr {
        rd: u32,
        rm: u32,
    },
    CmpImm {
        rn: u32,
        imm: u64,
    },
    CmpReg {
        rn: u32,
        rm: u32,
    },
    Udiv {
        rd: u32,
        rn: u32,
        rm: u32,
    },
    Msub {
        rd: u32,
        rn: u32,
        rm: u32,
        ra: u32,
    },
    Svc,
    MsrTp {
        rn: u32,
    },
    MrsTp {
        rt: u32,
    },
    B {
        off: i64,
    },
    BCond {
        off: i64,
        cond: u32,
    },
    Cb {
        off: i64,
        rt: u32,
        nonzero: bool,
    },
}

#[cfg(test)]
fn decode(w: u32) -> Op {
    let rd = w & 0x1f;
    let rn = (w >> 5) & 0x1f;
    let rm = (w >> 16) & 0x1f;
    let imm12 = ((w >> 10) & 0xfff) as u64;
    let imm = if w & (1 << 22) == 0 {
        imm12
    } else {
        imm12 << 12
    };
    if w & 0xff00_0000 == 0x9100_0000 {
        return Op::AddImm {
            rd,
            rn,
            imm,
            sub: false,
        };
    }
    if w & 0xff00_0000 == 0xd100_0000 {
        return Op::AddImm {
            rd,
            rn,
            imm,
            sub: true,
        };
    }
    if w & 0xffe0_fc00 == 0x8b00_0000 {
        return Op::AddReg { rd, rn, rm };
    }
    if w & 0xffc0_0000 == 0xf940_0000 {
        return Op::Ldr {
            rt: rd,
            rn,
            off: imm12 * 8,
        };
    }
    if w & 0xffc0_0000 == 0xf900_0000 {
        return Op::Str {
            rt: rd,
            rn,
            off: imm12 * 8,
        };
    }
    if w & 0xffc0_0000 == 0x3900_0000 {
        return Op::Strb { rt: rd, rn };
    }
    if w & 0xff80_0000 == 0xd280_0000 {
        return Op::MovZ { rd, imm: imm16(w) };
    }
    if w & 0xff80_0000 == 0xf280_0000 {
        return Op::MovK {
            rd,
            imm: ((w >> 5) & 0xffff) as u64,
            shift: ((w >> 21) & 3) * 16,
        };
    }
    if w & 0xff80_0000 == 0x9280_0000 {
        return Op::MovN { rd, imm: imm16(w) };
    }
    if w & 0xffe0_fc00 == 0xaa00_0000 && rn == 31 {
        return Op::Orr { rd, rm };
    }
    if w & 0xff00_001f == 0xf100_001f && rd == 31 {
        return Op::CmpImm { rn, imm };
    }
    if w & 0xffe0_fc1f == 0xeb00_001f && rd == 31 {
        return Op::CmpReg { rn, rm };
    }
    if w & 0xffe0_fc00 == 0x9ac0_0800 {
        return Op::Udiv { rd, rn, rm };
    }
    if w & 0xffe0_8000 == 0x9b00_8000 {
        return Op::Msub {
            rd,
            rn,
            rm,
            ra: (w >> 10) & 0x1f,
        };
    }
    if w == SVC0 {
        return Op::Svc;
    }
    if w & !0x1f == MSR_TPIDR {
        return Op::MsrTp { rn: rd };
    }
    if w & !0x1f == MRS_TPIDR {
        return Op::MrsTp { rt: rd };
    }
    if w & 0xfc00_0000 == 0x1400_0000 {
        return Op::B {
            off: sign(w & 0x03ff_ffff, 26),
        };
    }
    if w & 0xff00_0010 == 0x5400_0000 {
        return Op::BCond {
            off: sign((w >> 5) & 0x7_ffff, 19),
            cond: rd,
        };
    }
    // 64-bit CBZ is 0xb4...... and CBNZ is 0xb5......; bit 24 selects CBNZ.
    if w & 0xfe00_0000 == 0xb400_0000 {
        return Op::Cb {
            off: sign((w >> 5) & 0x7_ffff, 19),
            rt: rd,
            nonzero: w & 0x0100_0000 != 0,
        };
    }
    panic!("unknown instruction {w:#x}");
}

#[cfg(test)]
fn imm16(w: u32) -> u64 {
    (((w >> 5) & 0xffff) as u64) << (((w >> 21) & 3) * 16)
}

#[cfg(test)]
fn sign(value: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    ((value << shift) as i32 >> shift) as i64
}

#[cfg(test)]
fn xzr(x: &[u64; 31], r: u32) -> u64 {
    if r == 31 {
        0
    } else {
        x[r as usize]
    }
}

#[cfg(test)]
fn gsp(x: &[u64; 31], sp: u64, r: u32) -> u64 {
    if r == 31 {
        sp
    } else {
        x[r as usize]
    }
}

#[cfg(test)]
fn ssp(x: &mut [u64; 31], sp: &mut u64, r: u32, value: u64) {
    if r == 31 {
        *sp = value;
    } else {
        x[r as usize] = value;
    }
}

#[cfg(test)]
fn store64(mem: &mut std::collections::HashMap<u64, u8>, addr: u64, value: u64) {
    for (i, byte) in value.to_le_bytes().into_iter().enumerate() {
        mem.insert(addr + i as u64, byte);
    }
}

#[cfg(test)]
fn load64(mem: &std::collections::HashMap<u64, u8>, addr: u64) -> u64 {
    let mut buf = [0u8; 8];
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = mem.get(&(addr + i as u64)).copied().unwrap_or(0);
    }
    u64::from_le_bytes(buf)
}

#[cfg(test)]
fn flags(a: u64, b: u64, n: &mut bool, z: &mut bool, c: &mut bool, v: &mut bool) {
    let (result, borrow) = a.overflowing_sub(b);
    *n = (result as i64) < 0;
    *z = result == 0;
    *c = !borrow;
    let (sa, sb, sr) = ((a as i64) < 0, (b as i64) < 0, (result as i64) < 0);
    *v = (sa != sb) && (sa != sr);
}

#[cfg(test)]
fn takes(cond: u32, n: bool, z: bool, _c: bool, v: bool) -> bool {
    match cond {
        0 => z,
        1 => !z,
        13 => z || n != v,
        other => panic!("unhandled condition {other}"),
    }
}

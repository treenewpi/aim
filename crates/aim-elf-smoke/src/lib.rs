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

/// True when `text` is the loader's load-time line for this program.
pub fn trace_matches(text: &str, rewrites: Rewrites) -> bool {
    text.contains(&format!(
        "load-time rewrites: {} svc, {} mrs/{} msr tpidr_el0, 0 scs, 0 ctr_el0 (0 brk fallbacks)",
        rewrites.svc, rewrites.mrs_tpidr, rewrites.msr_tpidr
    ))
}

fn link(code: &[u32]) -> Vec<u8> {
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

struct Asm {
    words: Vec<u32>,
    fixes: Vec<(usize, &'static str, i64)>,
    labels: Vec<(&'static str, usize)>,
}

impl Asm {
    fn new() -> Self {
        Self {
            words: Vec::new(),
            fixes: Vec::new(),
            labels: Vec::new(),
        }
    }
    fn label(&mut self, name: &'static str) {
        self.labels.push((name, self.words.len()));
    }
    fn emit(&mut self, word: u32) {
        self.words.push(word);
    }
    fn b(&mut self, label: &'static str) {
        self.fixes.push((self.words.len(), label, 0));
        self.emit(0);
    }
    fn cond(&mut self, label: &'static str, cond: u32) {
        self.fixes.push((self.words.len(), label, cond as i64));
        self.emit(0);
    }
    fn cb(&mut self, label: &'static str, nonzero: bool, reg: u32) {
        // 0x200/0x300 stay above the B.cond kinds 1..=15. Bit 8 selects CBNZ.
        let kind = (if nonzero { 0x300 } else { 0x200 }) + reg as i64;
        self.fixes.push((self.words.len(), label, kind));
        self.emit(0);
    }
    fn finish(mut self) -> Vec<u32> {
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

/// `kind` 0 is an unconditional branch. 1..=15 are B.cond. 0x200+reg is CBZ
/// and 0x300+reg is CBNZ.
fn encode_fix(kind: i64, off: i64) -> u32 {
    if kind == 0 {
        0x1400_0000 | (off as u32 & 0x03ff_ffff)
    } else if kind < 0x20 {
        0x5400_0000 | ((off as u32 & 0x7_ffff) << 5) | (kind as u32)
    } else {
        let reg = (kind as u32) & 0x1f;
        let base = if kind & 0x100 != 0 { 0xb500_0000 } else { 0xb400_0000 };
        base | ((off as u32 & 0x7_ffff) << 5) | reg
    }
}

fn add_imm(rd: u32, rn: u32, imm: u32) -> u32 {
    0x9100_0000 | (imm << 10) | (rn << 5) | rd
}
fn sub_imm(rd: u32, rn: u32, imm: u32) -> u32 {
    0xd100_0000 | (imm << 10) | (rn << 5) | rd
}
fn add_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8b00_0000 | (rm << 16) | (rn << 5) | rd
}
fn ldr(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xf940_0000 | ((byte_off / 8) << 10) | (rn << 5) | rt
}
fn str(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xf900_0000 | ((byte_off / 8) << 10) | (rn << 5) | rt
}
fn strb(rt: u32, rn: u32) -> u32 {
    0x3900_0000 | (rn << 5) | rt
}
fn movz(rd: u32, imm: u32) -> u32 {
    0xd280_0000 | (imm << 5) | rd
}
fn movk(rd: u32, imm: u32, hw: u32) -> u32 {
    0xf280_0000 | (hw << 21) | (imm << 5) | rd
}
fn movn0(rd: u32) -> u32 {
    0x9280_0000 | rd
}
fn mov_reg(rd: u32, rm: u32) -> u32 {
    0xaa00_03e0 | (rm << 16) | rd
}
fn cmp_imm(rn: u32, imm: u32) -> u32 {
    0xf100_001f | (imm << 10) | (rn << 5)
}
fn cmp_reg(rn: u32, rm: u32) -> u32 {
    0xeb00_001f | (rm << 16) | (rn << 5)
}
fn udiv(rd: u32, rn: u32, rm: u32) -> u32 {
    0x9ac0_0800 | (rm << 16) | (rn << 5) | rd
}
fn msub(rd: u32, rn: u32, rm: u32, ra: u32) -> u32 {
    0x9b00_8000 | (rm << 16) | (ra << 10) | (rn << 5) | rd
}
fn svc() -> u32 {
    SVC0
}
fn msr_tp(rn: u32) -> u32 {
    MSR_TPIDR | rn
}
fn mrs_tp(rt: u32) -> u32 {
    MRS_TPIDR | rt
}

const SP: u32 = 31;
const XZR: u32 = 31;

fn mov_imm64(a: &mut Asm, rd: u32, value: u64) {
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
    a.emit(mov_reg(17, SP));
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

    a.emit(mov_reg(17, SP));
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
        assert_eq!(encode_fix(0, 1), 0x1400_0001);
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
    }
}

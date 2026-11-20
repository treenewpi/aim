//! Synthetic Linux AArch64 PIE that speaks the binder protocol.
//!
//! This is not an Android library, not bionic, and not `libbinder`. It has
//! no interpreter and no relocations. `linux-run --binder NAME` has to
//! service `openat("/dev/binder")`, `mmap` and `ioctl` or the process
//! cannot observe a reply. The bytes it prints are values it loaded from
//! the driver's buffers and from a passed file descriptor.

use crate::{
    add_imm, add_reg, and_15, and_3fff, cmp_imm, cmp_reg, ldr, ldrb, ldrw, link, lsr, mov_from_sp,
    mov_imm64, mov_reg, movn, movz, msub, ret, str, strb, strb_off, strw, stur, sub_imm, svc, udiv,
    Asm, SP, XZR,
};

const OPENAT: u32 = 56;
const CLOSE: u32 = 57;
const PIPE2: u32 = 59;
const READ: u32 = 63;
const WRITE: u32 = 64;
const EXIT: u32 = 94;
const IOCTL: u32 = 29;
const GETPID: u32 = 172;
const MMAP: u32 = 222;

const fn io(typ: u64, nr: u64) -> u64 {
    (typ << 8) | nr
}
const fn ior(typ: u64, nr: u64, size: u64) -> u64 {
    (2 << 30) | (size << 16) | io(typ, nr)
}
const fn iow(typ: u64, nr: u64, size: u64) -> u64 {
    (1 << 30) | (size << 16) | io(typ, nr)
}
const fn iowr(typ: u64, nr: u64, size: u64) -> u64 {
    (3 << 30) | (size << 16) | io(typ, nr)
}

/// Linux `_IOWR('b', 1, binder_write_read)`.
pub const BINDER_WRITE_READ: u64 = iowr(b'b' as u64, 1, 48);
/// Linux `_IOW('b', 13, flat_binder_object)`.
pub const BINDER_SET_CONTEXT_MGR_EXT: u64 = iow(b'b' as u64, 13, 24);
pub const BC_TRANSACTION: u64 = iow(b'c' as u64, 0, 64);
pub const BC_REPLY: u64 = iow(b'c' as u64, 1, 64);
pub const BC_FREE_BUFFER: u64 = iow(b'c' as u64, 3, 8);
pub const BC_ENTER_LOOPER: u64 = io(b'c' as u64, 12);
pub const BR_TRANSACTION: u64 = ior(b'r' as u64, 2, 64);
pub const BR_TRANSACTION_SEC_CTX: u64 = ior(b'r' as u64, 2, 72);
pub const BR_REPLY: u64 = ior(b'r' as u64, 3, 64);
pub const BR_DEAD_REPLY: u64 = io(b'r' as u64, 5);
pub const BR_FAILED_REPLY: u64 = io(b'r' as u64, 17);

const MARKER: u64 = 0x1122_3344;
const REPLY_WORD: u64 = 0x42;
const BINDER_TYPE_BINDER: u64 = 0x7362_2a85;
const BINDER_TYPE_FD: u64 = 0x6664_2a85;
const NODE_FLAGS: u64 = 0x1100;

/// The ELF. Execution is a Linux `argv`: `serve`, `call` or `dead`.
pub fn binder_program() -> Vec<u8> {
    link(&assemble())
}

fn syscall(a: &mut Asm, nr: u32) {
    a.emit(movz(8, nr));
    a.emit(svc());
}

fn mi(a: &mut Asm, label: &str) {
    a.emit(cmp_imm(0, 0));
    a.cond(label, 4);
}

fn put_at(a: &mut Asm, base: u32, off: u32, bytes: &[u8]) {
    a.emit(add_imm(11, base, off));
    for (i, byte) in bytes.iter().enumerate() {
        a.emit(movz(9, u32::from(*byte)));
        a.emit(strb_off(9, 11, i as u32));
    }
}

fn say(a: &mut Asm, text: &str) {
    put_at(a, 19, 0x620, text.as_bytes());
    a.emit(add_imm(0, 19, 0x620));
    a.emit(movz(1, text.len() as u32));
    a.bl("append");
}

fn write_stdout(a: &mut Asm) {
    a.emit(movz(0, 1));
    a.emit(add_imm(1, 19, 0x700));
    a.emit(mov_reg(2, 23));
    syscall(a, WRITE);
    a.emit(cmp_reg(0, 2));
    a.cond("fail_write", 1);
}

fn assemble() -> Vec<u32> {
    let mut a = Asm::new();
    // argv[1] selects the role. x22 survives every svc.
    a.emit(ldr(9, SP, 16));
    a.cb("fail_argv", false, 9);
    a.emit(ldrb(10, 9, 0));
    a.emit(cmp_imm(10, u32::from(b's')));
    a.cond("set_serve", 0);
    a.emit(cmp_imm(10, u32::from(b'c')));
    a.cond("set_call", 0);
    a.emit(cmp_imm(10, u32::from(b'd')));
    a.cond("set_dead", 0);
    a.b("fail_argv");
    a.label("set_serve");
    a.emit(movz(22, 1));
    a.b("open_dev");
    a.label("set_call");
    a.emit(movz(22, 2));
    a.b("open_dev");
    a.label("set_dead");
    a.emit(movz(22, 3));

    a.label("open_dev");
    a.emit(sub_imm(SP, SP, 16));
    put_at(&mut a, SP, 0, b"/dev/binder\0");
    a.emit(movn(0, 99));
    a.emit(mov_from_sp(1));
    mov_imm64(&mut a, 2, 0x8_0002);
    a.emit(mov_reg(3, XZR));
    syscall(&mut a, OPENAT);
    mi(&mut a, "fail_open");
    a.emit(mov_reg(21, 0));

    a.emit(mov_reg(0, XZR));
    mov_imm64(&mut a, 1, 128 * 1024);
    a.emit(movz(2, 1));
    a.emit(movz(3, 2));
    a.emit(mov_reg(4, 21));
    a.emit(mov_reg(5, XZR));
    syscall(&mut a, MMAP);
    mi(&mut a, "fail_mmap");
    a.emit(mov_reg(20, 0));

    a.emit(mov_reg(0, XZR));
    a.emit(movz(1, 16384));
    a.emit(movz(2, 3));
    a.emit(movz(3, 0x22));
    a.emit(movn(4, 0));
    a.emit(mov_reg(5, XZR));
    syscall(&mut a, MMAP);
    mi(&mut a, "fail_mmap");
    a.emit(mov_reg(19, 0));

    a.emit(mov_reg(0, 19));
    a.emit(movz(1, 16384));
    a.label("zero");
    a.emit(str(XZR, 0, 0));
    a.emit(add_imm(0, 0, 8));
    a.emit(sub_imm(1, 1, 8));
    a.cb("zero", true, 1);

    a.emit(cmp_imm(22, 1));
    a.cond("serve", 0);
    a.emit(cmp_imm(22, 2));
    a.cond("call", 0);
    a.b("dead");

    emit_serve(&mut a);
    emit_call(&mut a);
    emit_dead(&mut a);
    emit_fails(&mut a);
    emit_subs(&mut a);
    a.finish()
}

fn emit_serve(a: &mut Asm) {
    a.label("serve");
    let object = (NODE_FLAGS << 32) | BINDER_TYPE_BINDER;
    mov_imm64(a, 0, object);
    a.emit(str(0, 19, 0));
    a.emit(movz(0, 0x1234));
    a.emit(str(0, 19, 8));
    a.emit(movz(0, 0x5678));
    a.emit(str(0, 19, 16));
    a.emit(mov_reg(0, 21));
    mov_imm64(a, 1, BINDER_SET_CONTEXT_MGR_EXT);
    a.emit(mov_reg(2, 19));
    syscall(a, IOCTL);
    mi(a, "fail_ioctl");

    mov_imm64(a, 0, BC_ENTER_LOOPER);
    a.emit(strw(0, 19, 0x80));
    a.emit(movz(0, 4));
    a.emit(mov_reg(1, XZR));
    a.bl("fill_bwr");
    a.bl("ioctl_bwr");
    mi(a, "fail_ioctl");

    put_at(a, 19, 0x600, b"ready\n");
    a.emit(movz(0, 1));
    a.emit(add_imm(1, 19, 0x600));
    a.emit(movz(2, 6));
    syscall(a, WRITE);
    a.emit(cmp_imm(0, 6));
    a.cond("fail_write", 1);

    a.emit(mov_reg(26, XZR));
    a.label("serve_wait");
    a.emit(mov_reg(0, XZR));
    a.emit(movz(1, 512));
    a.bl("fill_bwr");
    a.bl("ioctl_bwr");
    mi(a, "fail_ioctl");
    a.emit(ldr(1, 19, 0x60));
    a.emit(add_imm(0, 19, 0x180));
    a.bl("scan");
    a.emit(cmp_imm(0, 1));
    a.cond("serve_got", 0);
    a.emit(add_imm(26, 26, 1));
    a.emit(cmp_imm(26, 4));
    a.cond("serve_wait", 3);
    a.b("fail_proto");

    a.label("serve_got");
    a.emit(ldrw(14, 1, 16));
    a.emit(ldrw(12, 1, 24));
    a.emit(ldrw(13, 1, 28));
    a.emit(ldr(15, 1, 48));
    a.emit(ldrw(10, 15, 0));
    a.emit(ldrw(11, 15, 16));
    a.emit(mov_reg(0, 11));
    a.emit(add_imm(1, 19, 0x600));
    a.emit(movz(2, 5));
    syscall(a, READ);
    a.emit(cmp_imm(0, 5));
    a.cond("fail_fd", 1);

    a.emit(movz(0, REPLY_WORD as u32));
    a.emit(strw(0, 19, 0x450));
    a.emit(add_imm(9, 19, 0x80));
    mov_imm64(a, 0, BC_FREE_BUFFER);
    a.emit(strw(0, 9, 0));
    a.emit(stur(15, 9, 4));
    mov_imm64(a, 0, BC_REPLY);
    a.emit(strw(0, 9, 12));
    a.emit(add_imm(7, 9, 16));
    a.emit(str(XZR, 7, 0));
    a.emit(str(XZR, 7, 8));
    a.emit(str(XZR, 7, 16));
    a.emit(str(XZR, 7, 24));
    a.emit(movz(0, 4));
    a.emit(str(0, 7, 32));
    a.emit(str(XZR, 7, 40));
    a.emit(add_imm(0, 19, 0x450));
    a.emit(str(0, 7, 48));
    a.emit(str(XZR, 7, 56));
    a.emit(movz(0, 80));
    a.emit(movz(1, 512));
    a.bl("fill_bwr");
    a.bl("ioctl_bwr");
    mi(a, "fail_ioctl");

    a.emit(mov_reg(23, XZR));
    say(a, "txn pid=");
    a.emit(mov_reg(0, 12));
    a.bl("decimal");
    a.bl("append");
    say(a, " euid=");
    a.emit(mov_reg(0, 13));
    a.bl("decimal");
    a.bl("append");
    say(a, " code=");
    a.emit(mov_reg(0, 14));
    a.bl("decimal");
    a.bl("append");
    say(a, " marker=");
    a.emit(mov_reg(0, 10));
    a.bl("hex8");
    a.emit(add_imm(0, 19, 0x680));
    a.emit(movz(1, 8));
    a.bl("append");
    say(a, " fd=");
    a.emit(add_imm(0, 19, 0x600));
    a.emit(movz(1, 5));
    a.bl("append");
    say(a, "\n");
    write_stdout(a);
    a.emit(mov_reg(0, XZR));
    a.b("die");
}

fn emit_call(a: &mut Asm) {
    a.label("call");
    emit_pipe(a);
    emit_txn(a, true, 32, "call_wait", "call_got");
    a.label("call_got");
    a.emit(ldr(15, 1, 48));
    a.emit(ldrw(10, 15, 0));
    syscall(a, GETPID);
    a.emit(mov_reg(12, 0));
    a.emit(mov_reg(23, XZR));
    say(a, "reply=");
    a.emit(mov_reg(0, 10));
    a.bl("hex8");
    a.emit(add_imm(0, 19, 0x680));
    a.emit(movz(1, 8));
    a.bl("append");
    say(a, " pid=");
    a.emit(mov_reg(0, 12));
    a.bl("decimal");
    a.bl("append");
    say(a, "\n");
    write_stdout(a);
    a.emit(mov_reg(0, XZR));
    a.b("die");
}

fn emit_dead(a: &mut Asm) {
    a.label("dead");
    emit_txn(a, false, 4, "dead_wait", "dead_got");
    a.label("dead_got");
    // x0 is 3 and x2 is the command word scan loaded.
    a.emit(mov_reg(10, 2));
    a.emit(mov_reg(23, XZR));
    say(a, "dead code=");
    a.emit(mov_reg(0, 10));
    a.bl("hex8");
    a.emit(add_imm(0, 19, 0x680));
    a.emit(movz(1, 8));
    a.bl("append");
    say(a, "\n");
    write_stdout(a);
    a.emit(mov_reg(0, XZR));
    a.b("die");
}

fn emit_pipe(a: &mut Asm) {
    a.emit(add_imm(0, 19, 0x560));
    a.emit(mov_reg(1, XZR));
    syscall(a, PIPE2);
    mi(a, "fail_pipe");
    a.emit(ldrw(24, 19, 0x560));
    a.emit(ldrw(25, 19, 0x564));
    // `put_at` writes each byte through x9, so the pipe fds stay in x24/x25.
    put_at(a, 19, 0x600, b"hello");
    a.emit(mov_reg(0, 25));
    a.emit(add_imm(1, 19, 0x600));
    a.emit(movz(2, 5));
    syscall(a, WRITE);
    a.emit(cmp_imm(0, 5));
    a.cond("fail_write", 1);
    a.emit(mov_reg(0, 25));
    syscall(a, CLOSE);
}

/// Build one `BC_TRANSACTION` and read until `got` (a reply or a dead reply).
fn emit_txn(a: &mut Asm, with_fd: bool, data_size: u32, wait: &str, got: &str) {
    mov_imm64(a, 0, MARKER);
    a.emit(strw(0, 19, 0x400));
    if with_fd {
        mov_imm64(a, 0, BINDER_TYPE_FD);
        a.emit(strw(0, 19, 0x408));
        a.emit(strw(24, 19, 0x410));
        a.emit(movz(0, 8));
        a.emit(str(0, 19, 0x440));
    }
    a.emit(str(XZR, 19, 0x380));
    a.emit(str(XZR, 19, 0x388));
    a.emit(movz(0, 7));
    a.emit(str(0, 19, 0x390));
    a.emit(str(XZR, 19, 0x398));
    a.emit(movz(0, data_size));
    a.emit(str(0, 19, 0x3a0));
    if with_fd {
        a.emit(movz(0, 8));
    } else {
        a.emit(mov_reg(0, XZR));
    }
    a.emit(str(0, 19, 0x3a8));
    a.emit(add_imm(0, 19, 0x400));
    a.emit(str(0, 19, 0x3b0));
    if with_fd {
        a.emit(add_imm(0, 19, 0x440));
    } else {
        a.emit(mov_reg(0, XZR));
    }
    a.emit(str(0, 19, 0x3b8));

    a.emit(add_imm(9, 19, 0x80));
    mov_imm64(a, 0, BC_TRANSACTION);
    a.emit(strw(0, 9, 0));
    a.emit(add_imm(0, 9, 4));
    a.emit(add_imm(1, 19, 0x380));
    a.emit(movz(2, 64));
    a.bl("memcpy");

    a.emit(movz(27, 68));
    a.emit(mov_reg(26, XZR));
    a.label(wait);
    a.emit(mov_reg(0, 27));
    a.emit(movz(1, 512));
    a.bl("fill_bwr");
    a.bl("ioctl_bwr");
    mi(a, "fail_ioctl");
    a.emit(mov_reg(27, XZR));
    a.emit(ldr(1, 19, 0x60));
    a.emit(add_imm(0, 19, 0x180));
    a.bl("scan");
    if with_fd {
        a.emit(cmp_imm(0, 2));
        a.cond(got, 0);
        a.emit(cmp_imm(0, 3));
        a.cond("fail_proto", 0);
        a.emit(cmp_imm(0, 4));
        a.cond("fail_proto", 0);
    } else {
        a.emit(cmp_imm(0, 3));
        a.cond(got, 0);
        a.emit(cmp_imm(0, 1));
        a.cond("fail_proto", 0);
        a.emit(cmp_imm(0, 2));
        a.cond("fail_proto", 0);
    }
    a.emit(add_imm(26, 26, 1));
    a.emit(cmp_imm(26, 4));
    a.cond(wait, 3);
    a.b("fail_proto");
}

fn emit_fails(a: &mut Asm) {
    for (label, code) in [
        ("fail_argv", 2),
        ("fail_open", 3),
        ("fail_mmap", 4),
        ("fail_ioctl", 5),
        ("fail_pipe", 6),
        ("fail_fd", 7),
        ("fail_write", 8),
        ("fail_proto", 1),
    ] {
        a.label(label);
        a.emit(movz(0, code));
        a.b("die");
    }
    a.label("die");
    syscall(a, EXIT);
}

fn emit_subs(a: &mut Asm) {
    a.label("ioctl_bwr");
    a.emit(mov_reg(0, 21));
    mov_imm64(a, 1, BINDER_WRITE_READ);
    a.emit(add_imm(2, 19, 0x40));
    syscall(a, IOCTL);
    a.emit(ret());

    a.label("fill_bwr");
    a.emit(str(0, 19, 0x40));
    a.emit(str(XZR, 19, 0x48));
    a.emit(add_imm(2, 19, 0x80));
    a.emit(str(2, 19, 0x50));
    a.emit(str(1, 19, 0x58));
    a.emit(str(XZR, 19, 0x60));
    a.emit(add_imm(2, 19, 0x180));
    a.emit(str(2, 19, 0x68));
    a.emit(ret());

    // x0 read base, x1 length. Returns kind in x0, transaction pointer in
    // x1, and the command word in x2. Kind 1 is a transaction, 2 a reply,
    // 3 BR_DEAD_REPLY, 4 BR_FAILED_REPLY.
    a.label("scan");
    a.emit(mov_reg(3, XZR));
    a.label("scan_loop");
    a.emit(cmp_reg(3, 1));
    a.cond("scan_none", 2);
    a.emit(add_reg(4, 0, 3));
    a.emit(ldrw(5, 4, 0));
    cmp_u32(a, 5, BR_TRANSACTION, "scan_txn");
    cmp_u32(a, 5, BR_TRANSACTION_SEC_CTX, "scan_sec");
    cmp_u32(a, 5, BR_REPLY, "scan_reply");
    cmp_u32(a, 5, BR_DEAD_REPLY, "scan_dead");
    cmp_u32(a, 5, BR_FAILED_REPLY, "scan_failed");
    a.emit(lsr(6, 5, 16));
    a.emit(and_3fff(6, 6));
    a.emit(add_imm(3, 3, 4));
    a.emit(add_reg(3, 3, 6));
    a.b("scan_loop");
    a.label("scan_txn");
    a.emit(add_imm(1, 4, 4));
    a.emit(movz(0, 1));
    a.emit(mov_reg(2, 5));
    a.emit(ret());
    a.label("scan_sec");
    // This driver writes the transaction data first and the secctx word
    // after it (`read.rs`). The data starts at the same place as
    // BR_TRANSACTION; the extra eight bytes are past the 64-byte struct.
    a.emit(add_imm(1, 4, 4));
    a.emit(movz(0, 1));
    a.emit(mov_reg(2, 5));
    a.emit(ret());
    a.label("scan_reply");
    a.emit(add_imm(1, 4, 4));
    a.emit(movz(0, 2));
    a.emit(mov_reg(2, 5));
    a.emit(ret());
    a.label("scan_dead");
    a.emit(movz(0, 3));
    a.emit(mov_reg(2, 5));
    a.emit(ret());
    a.label("scan_failed");
    a.emit(movz(0, 4));
    a.emit(mov_reg(2, 5));
    a.emit(ret());
    a.label("scan_none");
    a.emit(mov_reg(0, XZR));
    a.emit(ret());

    a.label("decimal");
    a.emit(add_imm(3, 19, 0x69f));
    a.emit(mov_reg(4, XZR));
    a.emit(movz(2, 10));
    a.label("digit");
    a.emit(udiv(5, 0, 2));
    a.emit(msub(6, 5, 2, 0));
    a.emit(add_imm(6, 6, u32::from(b'0')));
    a.emit(strb(6, 3));
    a.emit(sub_imm(3, 3, 1));
    a.emit(add_imm(4, 4, 1));
    a.emit(mov_reg(0, 5));
    a.cb("digit", true, 0);
    a.emit(add_imm(0, 3, 1));
    a.emit(mov_reg(1, 4));
    a.emit(ret());

    a.label("append");
    a.label("append_loop");
    a.cb("append_ret", false, 1);
    a.emit(ldrb(2, 0, 0));
    a.emit(add_imm(3, 19, 0x700));
    a.emit(add_reg(3, 3, 23));
    a.emit(strb(2, 3));
    a.emit(add_imm(0, 0, 1));
    a.emit(add_imm(23, 23, 1));
    a.emit(sub_imm(1, 1, 1));
    a.b("append_loop");
    a.label("append_ret");
    a.emit(ret());

    a.label("hex8");
    a.emit(add_imm(3, 19, 0x680));
    for i in 0..8 {
        let shift = (7 - i) * 4;
        if shift == 0 {
            a.emit(and_15(6, 0));
        } else {
            a.emit(lsr(6, 0, shift));
            a.emit(and_15(6, 6));
        }
        a.emit(cmp_imm(6, 10));
        a.cond(format!("hex_digit_{i}"), 3);
        a.emit(add_imm(6, 6, u32::from(b'a') - 10));
        a.b(format!("hex_put_{i}"));
        a.label(format!("hex_digit_{i}"));
        a.emit(add_imm(6, 6, u32::from(b'0')));
        a.label(format!("hex_put_{i}"));
        a.emit(add_imm(5, 3, i));
        a.emit(strb(6, 5));
    }
    a.emit(ret());

    a.label("memcpy");
    a.label("memcpy_loop");
    a.cb("memcpy_ret", false, 2);
    a.emit(ldrb(3, 1, 0));
    a.emit(strb(3, 0));
    a.emit(add_imm(0, 0, 1));
    a.emit(add_imm(1, 1, 1));
    a.emit(sub_imm(2, 2, 1));
    a.b("memcpy_loop");
    a.label("memcpy_ret");
    a.emit(ret());
}

fn cmp_u32(a: &mut Asm, reg: u32, value: u64, equal: &str) {
    mov_imm64(a, 6, value);
    a.emit(cmp_reg(reg, 6));
    a.cond(equal, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn encodings_match_the_arm_forms() {
        assert_eq!(lsr(3, 4, 16), 0xd350_fc00 | (4 << 5) | 3);
        assert_eq!(and_3fff(0, 1), 0x9240_3400 | (1 << 5));
        assert_eq!(and_15(0, 1), 0x9240_0c00 | (1 << 5));
        assert_eq!(stur(0, 1, 4), 0xf800_4020);
        assert_eq!(ldrw(0, 1, 0), 0xb940_0020);
        assert_eq!(strw(0, 1, 0), 0xb900_0020);
        assert_eq!(ldrb(0, 1, 0), 0x3940_0020);
        assert_eq!(ret(), 0xd65f_03c0);
        assert_eq!(BINDER_WRITE_READ, 0xc030_6201);
        assert_eq!(BINDER_SET_CONTEXT_MGR_EXT, 0x4018_620d);
        assert_eq!(BC_TRANSACTION, 0x4040_6300);
        assert_eq!(BR_DEAD_REPLY, 0x7205);
        assert_eq!(BR_TRANSACTION_SEC_CTX, 0x8048_7202);
        assert_eq!(BR_REPLY, 0x8040_7203);
    }

    #[test]
    fn serve_and_call_exchange_a_real_payload() {
        let mut world = World::new();
        let serve = world.spawn("serve", 222, 1000);
        let call = world.spawn("call", 111, 10_001);
        assert_eq!(
            world.run(serve),
            Run::Block,
            "serve stdout {}",
            world.out(serve)
        );
        assert!(world.out(serve).contains("ready\n"), "{}", world.out(serve));
        assert_eq!(
            world.run(call),
            Run::Block,
            "call stdout {}",
            world.out(call)
        );
        assert!(!world.procs[serve].blocked, "call did not deliver");
        assert_eq!(world.run(serve), Run::Exit(0), "{}", world.out(serve));
        assert!(!world.procs[call].blocked);
        assert_eq!(world.run(call), Run::Exit(0), "{}", world.out(call));
        let serve_out = world.out(serve);
        let call_out = world.out(call);
        assert!(
            serve_out.contains("txn pid=4242 euid=10001 code=7 marker=11223344 fd=hello\n"),
            "{serve_out}"
        );
        assert!(call_out.contains("reply=00000042 pid=111\n"), "{call_out}");
        assert!(
            world.procs[serve]
                .reads
                .iter()
                .any(|r| r.0 == 50 && r.1 == b"hello"),
            "server did not read the translated fd: {:?}",
            world.procs[serve].reads
        );
        assert!(world.opened_binder[serve] && world.opened_binder[call]);
    }

    #[test]
    fn dead_reply_is_the_command_the_guest_loaded() {
        let mut world = World::new();
        let dead = world.spawn("dead", 333, 10_001);
        assert_eq!(world.run(dead), Run::Exit(0), "{}", world.out(dead));
        assert_eq!(world.out(dead), "dead code=00007205\n");
        assert!(world.opened_binder[dead]);
        assert!(world.procs[dead].ioctl_write_read > 0);
    }

    struct World {
        procs: Vec<Proc>,
        code: Vec<u32>,
        manager: Option<usize>,
        parcel: Vec<u8>,
        opened_binder: Vec<bool>,
    }

    struct Proc {
        mem: HashMap<u64, u8>,
        x: [u64; 31],
        sp: u64,
        pc: i64,
        n: bool,
        z: bool,
        c: bool,
        v: bool,
        pid: u64,
        euid: u32,
        stdout: Vec<u8>,
        recv: u64,
        scratch: u64,
        binder_fd: i32,
        blocked: bool,
        bwr: u64,
        reads: Vec<(i32, Vec<u8>)>,
        ioctl_write_read: u32,
        exit: Option<u64>,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Run {
        Block,
        Exit(u64),
    }

    impl World {
        fn new() -> Self {
            let elf = binder_program();
            let mut code = Vec::new();
            let mut at = 0x80;
            while at + 4 <= elf.len() {
                code.push(u32::from_le_bytes(elf[at..at + 4].try_into().unwrap()));
                at += 4;
            }
            Self {
                procs: Vec::new(),
                code,
                manager: None,
                parcel: Vec::new(),
                opened_binder: Vec::new(),
            }
        }

        fn spawn(&mut self, role: &str, pid: u64, euid: u32) -> usize {
            let id = self.procs.len();
            let mut proc = Proc {
                mem: HashMap::new(),
                x: [0; 31],
                sp: 0x8000_0000,
                pc: 0,
                n: false,
                z: false,
                c: false,
                v: false,
                pid,
                euid,
                stdout: Vec::new(),
                recv: 0,
                scratch: 0,
                binder_fd: -1,
                blocked: false,
                bwr: 0,
                reads: Vec::new(),
                ioctl_write_read: 0,
                exit: None,
            };
            let arg = 0x7000_0000u64;
            store_bytes(&mut proc.mem, arg, role.as_bytes());
            store_bytes(&mut proc.mem, arg + 16, b"\0");
            // argc, argv[0], argv[1], NULL, env NULL.
            for (i, word) in [2u64, 0x10, arg, 0, 0].into_iter().enumerate() {
                store64(&mut proc.mem, proc.sp + i as u64 * 8, word);
            }
            self.procs.push(proc);
            self.opened_binder.push(false);
            id
        }

        fn out(&self, id: usize) -> String {
            String::from_utf8_lossy(&self.procs[id].stdout).into_owned()
        }

        fn run(&mut self, id: usize) -> Run {
            for _ in 0..200_000 {
                if self.procs[id].blocked {
                    return Run::Block;
                }
                if let Some(code) = self.procs[id].exit {
                    return Run::Exit(code);
                }
                self.step(id);
            }
            panic!(
                "step limit pc {} stdout {}",
                self.procs[id].pc,
                self.out(id)
            );
        }

        fn step(&mut self, id: usize) {
            let pc = self.procs[id].pc;
            let word = self
                .code
                .get(pc as usize)
                .copied()
                .unwrap_or_else(|| panic!("pc {pc} left the guest"));
            self.procs[id].pc = pc + 1;
            match decode(word) {
                Op::AddImm { rd, rn, imm, sub } => {
                    let base = self.gpr(id, rn);
                    let value = if sub {
                        base.wrapping_sub(imm)
                    } else {
                        base.wrapping_add(imm)
                    };
                    self.set_gpr(id, rd, value);
                }
                Op::AddReg { rd, rn, rm } => {
                    let value = self.reg(id, rn).wrapping_add(self.reg(id, rm));
                    self.procs[id].x[rd as usize] = value;
                }
                Op::Ldr { rt, rn, off, size } => {
                    let addr = self.gpr(id, rn).wrapping_add(off);
                    let value = load_size(&self.procs[id].mem, addr, size);
                    self.set_gpr(id, rt, value);
                }
                Op::Str { rt, rn, off, size } => {
                    let addr = self.gpr(id, rn).wrapping_add(off);
                    let value = self.reg(id, rt);
                    store_size(&mut self.procs[id].mem, addr, value, size);
                }
                Op::MovZ { rd, imm } => self.procs[id].x[rd as usize] = imm,
                Op::MovK { rd, imm, shift } => {
                    let clear = !(0xffffu64 << shift);
                    let value = (self.procs[id].x[rd as usize] & clear) | (imm << shift);
                    self.procs[id].x[rd as usize] = value;
                }
                Op::MovN { rd, imm } => self.procs[id].x[rd as usize] = !imm,
                Op::Orr { rd, rm } => self.procs[id].x[rd as usize] = self.reg(id, rm),
                Op::CmpImm { rn, imm } => {
                    let (n, z, c, v) = flags(self.gpr(id, rn), imm);
                    self.set_flags(id, n, z, c, v);
                }
                Op::CmpReg { rn, rm } => {
                    let (n, z, c, v) = flags(self.reg(id, rn), self.reg(id, rm));
                    self.set_flags(id, n, z, c, v);
                }
                Op::Lsr { rd, rn, shift } => {
                    self.procs[id].x[rd as usize] = self.reg(id, rn) >> shift;
                }
                Op::And { rd, rn, mask } => {
                    self.procs[id].x[rd as usize] = self.reg(id, rn) & mask;
                }
                Op::Udiv { rd, rn, rm } => {
                    let divisor = self.reg(id, rm);
                    assert_ne!(divisor, 0);
                    self.procs[id].x[rd as usize] = self.reg(id, rn) / divisor;
                }
                Op::Msub { rd, rn, rm, ra } => {
                    let value = self
                        .reg(id, ra)
                        .wrapping_sub(self.reg(id, rn).wrapping_mul(self.reg(id, rm)));
                    self.procs[id].x[rd as usize] = value;
                }
                Op::Svc => self.syscall(id),
                Op::Ret => self.procs[id].pc = self.procs[id].x[30] as i64,
                Op::B { off } => self.procs[id].pc = pc + off,
                Op::Bl { off } => {
                    self.procs[id].x[30] = (pc + 1) as u64;
                    self.procs[id].pc = pc + off;
                }
                Op::BCond { off, cond } => {
                    let p = &self.procs[id];
                    if takes(cond, p.n, p.z, p.c, p.v) {
                        self.procs[id].pc = pc + off;
                    }
                }
                Op::Cb { off, rt, nonzero } => {
                    let zero = self.reg(id, rt) == 0;
                    if zero != nonzero {
                        self.procs[id].pc = pc + off;
                    }
                }
            }
        }

        fn syscall(&mut self, id: usize) {
            let nr = self.procs[id].x[8];
            let arg = self.procs[id].x;
            match nr {
                56 => {
                    let path = read_cstr(&self.procs[id].mem, arg[1]);
                    assert_eq!(path, b"/dev/binder", "openat path {path:?}");
                    self.opened_binder[id] = true;
                    self.procs[id].binder_fd = 3;
                    self.procs[id].x[0] = 3;
                }
                222 => {
                    let fd = arg[4] as i64;
                    if fd == 3 {
                        assert_eq!((arg[2], arg[3]), (1, 2), "binder mmap prot/flags");
                        self.procs[id].recv = 0x2000_0000 + (id as u64) * 0x10_0000;
                        self.procs[id].x[0] = self.procs[id].recv;
                    } else {
                        assert_eq!(fd, -1, "scratch mmap fd");
                        self.procs[id].scratch = 0x1000_0000 + (id as u64) * 0x10_0000;
                        self.procs[id].x[0] = self.procs[id].scratch;
                    }
                }
                29 => self.ioctl(id, arg[1], arg[2]),
                59 => {
                    store32(&mut self.procs[id].mem, arg[0], 4);
                    store32(&mut self.procs[id].mem, arg[0] + 4, 5);
                    self.procs[id].x[0] = 0;
                }
                64 => {
                    let bytes = read_bytes(&self.procs[id].mem, arg[1], arg[2] as usize);
                    if arg[0] == 1 {
                        self.procs[id].stdout.extend_from_slice(&bytes);
                    } else if arg[0] == 5 {
                        self.parcel = bytes;
                    } else {
                        panic!("write fd {}", arg[0]);
                    }
                    self.procs[id].x[0] = arg[2];
                }
                63 => {
                    let fd = arg[0] as i32;
                    assert_eq!(fd, 50, "read fd {fd}, expected the translated descriptor");
                    assert_eq!(arg[2], 5);
                    let bytes = self.parcel.clone();
                    assert_eq!(bytes, b"hello");
                    store_bytes(&mut self.procs[id].mem, arg[1], &bytes);
                    self.procs[id].reads.push((fd, bytes));
                    self.procs[id].x[0] = 5;
                }
                57 => self.procs[id].x[0] = 0,
                172 => self.procs[id].x[0] = self.procs[id].pid,
                94 => self.procs[id].exit = Some(arg[0]),
                other => panic!("unexpected syscall {other}"),
            }
        }

        fn ioctl(&mut self, id: usize, request: u64, arg: u64) {
            if request == BINDER_SET_CONTEXT_MGR_EXT {
                let kind = load32(&self.procs[id].mem, arg);
                let flags = load32(&self.procs[id].mem, arg + 4);
                assert_eq!(kind, BINDER_TYPE_BINDER as u32);
                assert_eq!(flags, NODE_FLAGS as u32);
                self.manager = Some(id);
                self.procs[id].x[0] = 0;
                return;
            }
            assert_eq!(request, BINDER_WRITE_READ, "ioctl {request:#x}");
            self.procs[id].ioctl_write_read += 1;
            self.procs[id].bwr = arg;
            let write_size = load64(&self.procs[id].mem, arg) as usize;
            let write_buf = load64(&self.procs[id].mem, arg + 16);
            let read_size = load64(&self.procs[id].mem, arg + 24);
            let read_buf = load64(&self.procs[id].mem, arg + 40);
            let write = read_bytes(&self.procs[id].mem, write_buf, write_size);
            store64(&mut self.procs[id].mem, arg + 8, write_size as u64);
            let mut produced = Vec::new();
            let mut at = 0;
            let mut block = false;
            while at + 4 <= write.len() {
                let cmd = u32::from_le_bytes(write[at..at + 4].try_into().unwrap());
                at += 4;
                let size = ((cmd >> 16) & 0x3fff) as usize;
                let payload = &write[at..at + size];
                at += size;
                if cmd as u64 == BC_ENTER_LOOPER {
                    continue;
                }
                if cmd as u64 == BC_FREE_BUFFER {
                    continue;
                }
                if cmd as u64 == BC_TRANSACTION {
                    block = self.transaction(id, payload, &mut produced);
                } else if cmd as u64 == BC_REPLY {
                    self.reply(id, payload);
                    produced.extend_from_slice(&br_complete());
                } else {
                    panic!("unexpected binder command {cmd:#x}");
                }
            }
            if block {
                self.procs[id].blocked = true;
                return;
            }
            if produced.is_empty() && read_size > 0 && self.manager == Some(id) {
                self.procs[id].blocked = true;
                return;
            }
            self.deliver(id, read_buf, read_size, &produced);
            self.procs[id].x[0] = 0;
        }

        fn transaction(&mut self, id: usize, payload: &[u8], produced: &mut Vec<u8>) -> bool {
            let data_size = u64::from_le_bytes(payload[32..40].try_into().unwrap()) as usize;
            let buffer = u64::from_le_bytes(payload[48..56].try_into().unwrap());
            let data = read_bytes(&self.procs[id].mem, buffer, data_size);
            if self.manager.is_none() {
                produced.extend_from_slice(&br_complete());
                produced.extend_from_slice(&(BR_DEAD_REPLY as u32).to_le_bytes());
                return false;
            }
            let manager = self.manager.unwrap();
            assert_ne!(manager, id);
            assert!(
                self.procs[manager].blocked,
                "context manager was not waiting for the transaction"
            );
            let dest = self.procs[manager].recv + 0x100;
            let mut copied = data;
            if copied.len() >= 20
                && u32::from_le_bytes(copied[8..12].try_into().unwrap()) == BINDER_TYPE_FD as u32
            {
                copied[16..20].copy_from_slice(&50u32.to_le_bytes());
            }
            store_bytes(&mut self.procs[manager].mem, dest, &copied);
            let mut body = Vec::new();
            // An acquire the guest must skip by `_IOC_SIZE`, then the
            // security-context transaction the node flags ask for.
            body.extend_from_slice(&0x8010_7208u32.to_le_bytes());
            body.extend_from_slice(&[0; 16]);
            body.extend_from_slice(&(BR_TRANSACTION_SEC_CTX as u32).to_le_bytes());
            let mut tr = vec![0u8; 64];
            tr[16..20].copy_from_slice(&7u32.to_le_bytes());
            tr[24..28].copy_from_slice(&4242u32.to_le_bytes());
            tr[28..32].copy_from_slice(&self.procs[id].euid.to_le_bytes());
            tr[32..40].copy_from_slice(&(copied.len() as u64).to_le_bytes());
            tr[48..56].copy_from_slice(&dest.to_le_bytes());
            // `read.rs` appends the secctx word after the transaction data.
            body.extend_from_slice(&tr);
            body.extend_from_slice(&0x1111u64.to_le_bytes());
            if self.procs[manager].blocked {
                let bwr = self.procs[manager].bwr;
                let read_buf = load64(&self.procs[manager].mem, bwr + 40);
                let read_size = load64(&self.procs[manager].mem, bwr + 24);
                self.deliver(manager, read_buf, read_size, &body);
                self.procs[manager].blocked = false;
                self.procs[manager].x[0] = 0;
            }
            true
        }

        fn reply(&mut self, id: usize, payload: &[u8]) {
            let data_size = u64::from_le_bytes(payload[32..40].try_into().unwrap()) as usize;
            let buffer = u64::from_le_bytes(payload[48..56].try_into().unwrap());
            let data = read_bytes(&self.procs[id].mem, buffer, data_size);
            let caller = (0..self.procs.len()).find(|p| *p != id).unwrap();
            let dest = self.procs[caller].recv + 0x200;
            store_bytes(&mut self.procs[caller].mem, dest, &data);
            let mut body = br_complete();
            body.extend_from_slice(&(BR_REPLY as u32).to_le_bytes());
            let mut tr = vec![0u8; 64];
            tr[32..40].copy_from_slice(&(data.len() as u64).to_le_bytes());
            tr[48..56].copy_from_slice(&dest.to_le_bytes());
            body.extend_from_slice(&tr);
            let bwr = self.procs[caller].bwr;
            let read_buf = load64(&self.procs[caller].mem, bwr + 40);
            let read_size = load64(&self.procs[caller].mem, bwr + 24);
            self.deliver(caller, read_buf, read_size, &body);
            self.procs[caller].blocked = false;
            self.procs[caller].x[0] = 0;
        }

        fn deliver(&mut self, id: usize, buf: u64, size: u64, bytes: &[u8]) {
            let n = bytes.len().min(size as usize);
            let bwr = self.procs[id].bwr;
            store_bytes(&mut self.procs[id].mem, buf, &bytes[..n]);
            store64(&mut self.procs[id].mem, bwr + 32, n as u64);
        }

        fn gpr(&self, id: usize, reg: u32) -> u64 {
            if reg == 31 {
                self.procs[id].sp
            } else {
                self.procs[id].x[reg as usize]
            }
        }

        fn set_gpr(&mut self, id: usize, reg: u32, value: u64) {
            if reg == 31 {
                self.procs[id].sp = value;
            } else {
                self.procs[id].x[reg as usize] = value;
            }
        }

        fn reg(&self, id: usize, reg: u32) -> u64 {
            if reg == 31 {
                0
            } else {
                self.procs[id].x[reg as usize]
            }
        }

        fn set_flags(&mut self, id: usize, n: bool, z: bool, c: bool, v: bool) {
            let proc = &mut self.procs[id];
            proc.n = n;
            proc.z = z;
            proc.c = c;
            proc.v = v;
        }
    }

    fn br_complete() -> Vec<u8> {
        0x7206u32.to_le_bytes().to_vec()
    }

    fn store64(mem: &mut HashMap<u64, u8>, addr: u64, value: u64) {
        store_bytes(mem, addr, &value.to_le_bytes());
    }
    fn store_size(mem: &mut HashMap<u64, u8>, addr: u64, value: u64, size: u32) {
        store_bytes(mem, addr, &value.to_le_bytes()[..size as usize]);
    }
    fn store32(mem: &mut HashMap<u64, u8>, addr: u64, value: u32) {
        store_bytes(mem, addr, &value.to_le_bytes());
    }
    fn store_bytes(mem: &mut HashMap<u64, u8>, addr: u64, bytes: &[u8]) {
        for (i, byte) in bytes.iter().enumerate() {
            mem.insert(addr + i as u64, *byte);
        }
    }
    fn load64(mem: &HashMap<u64, u8>, addr: u64) -> u64 {
        load_size(mem, addr, 8)
    }
    fn load32(mem: &HashMap<u64, u8>, addr: u64) -> u32 {
        load_size(mem, addr, 4) as u32
    }
    fn load_size(mem: &HashMap<u64, u8>, addr: u64, size: u32) -> u64 {
        let mut buf = [0u8; 8];
        for i in 0..size as usize {
            buf[i] = mem.get(&(addr + i as u64)).copied().unwrap_or(0);
        }
        u64::from_le_bytes(buf)
    }
    fn read_bytes(mem: &HashMap<u64, u8>, addr: u64, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| mem.get(&(addr + i as u64)).copied().unwrap_or(0))
            .collect()
    }
    fn read_cstr(mem: &HashMap<u64, u8>, addr: u64) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..64 {
            let byte = mem.get(&(addr + i)).copied().unwrap_or(0);
            if byte == 0 {
                break;
            }
            out.push(byte);
        }
        out
    }

    fn flags(a: u64, b: u64) -> (bool, bool, bool, bool) {
        let (result, borrow) = a.overflowing_sub(b);
        let n = (result as i64) < 0;
        let z = result == 0;
        let c = !borrow;
        let (sa, sb, sr) = ((a as i64) < 0, (b as i64) < 0, (result as i64) < 0);
        let v = (sa != sb) && (sa != sr);
        (n, z, c, v)
    }

    fn takes(cond: u32, n: bool, z: bool, c: bool, v: bool) -> bool {
        match cond {
            0 => z,
            1 => !z,
            2 => c,
            3 => !c,
            4 => n,
            11 => n != v,
            13 => z || n != v,
            other => panic!("condition {other}"),
        }
    }

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
            size: u32,
        },
        Str {
            rt: u32,
            rn: u32,
            off: u64,
            size: u32,
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
        Lsr {
            rd: u32,
            rn: u32,
            shift: u32,
        },
        And {
            rd: u32,
            rn: u32,
            mask: u64,
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
        Ret,
        B {
            off: i64,
        },
        Bl {
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
                size: 8,
            };
        }
        if w & 0xffc0_0000 == 0xf900_0000 {
            return Op::Str {
                rt: rd,
                rn,
                off: imm12 * 8,
                size: 8,
            };
        }
        if w & 0xffc0_0000 == 0xb940_0000 {
            return Op::Ldr {
                rt: rd,
                rn,
                off: imm12 * 4,
                size: 4,
            };
        }
        if w & 0xffc0_0000 == 0xb900_0000 {
            return Op::Str {
                rt: rd,
                rn,
                off: imm12 * 4,
                size: 4,
            };
        }
        if w & 0xffc0_0000 == 0x3940_0000 {
            return Op::Ldr {
                rt: rd,
                rn,
                off: imm12,
                size: 1,
            };
        }
        if w & 0xffc0_0000 == 0x3900_0000 {
            return Op::Str {
                rt: rd,
                rn,
                off: imm12,
                size: 1,
            };
        }
        if w & 0xffe0_0c00 == 0xf800_0000 {
            let imm9 = ((w >> 12) & 0x1ff) as i32;
            let off = ((imm9 << 23) >> 23) as i64;
            return Op::Str {
                rt: rd,
                rn,
                off: off as u64,
                size: 8,
            };
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
        if w & 0xffc0_fc00 == 0xd340_fc00 {
            return Op::Lsr {
                rd,
                rn,
                shift: (w >> 16) & 0x3f,
            };
        }
        if w & 0xffff_fc00 == 0x9240_3400 {
            return Op::And {
                rd,
                rn,
                mask: 0x3fff,
            };
        }
        if w & 0xffff_fc00 == 0x9240_0c00 {
            return Op::And { rd, rn, mask: 0xf };
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
        if w == 0xd400_0001 {
            return Op::Svc;
        }
        if w == 0xd65f_03c0 {
            return Op::Ret;
        }
        if w & 0xfc00_0000 == 0x1400_0000 {
            return Op::B {
                off: sign(w & 0x03ff_ffff, 26),
            };
        }
        if w & 0xfc00_0000 == 0x9400_0000 {
            return Op::Bl {
                off: sign(w & 0x03ff_ffff, 26),
            };
        }
        if w & 0xff00_0010 == 0x5400_0000 {
            return Op::BCond {
                off: sign((w >> 5) & 0x7_ffff, 19),
                cond: rd,
            };
        }
        if w & 0xfe00_0000 == 0xb400_0000 {
            return Op::Cb {
                off: sign((w >> 5) & 0x7_ffff, 19),
                rt: rd,
                nonzero: w & 0x0100_0000 != 0,
            };
        }
        panic!("unknown instruction {w:#x}");
    }

    fn imm16(w: u32) -> u64 {
        (((w >> 5) & 0xffff) as u64) << (((w >> 21) & 3) * 16)
    }

    fn sign(value: u32, bits: u32) -> i64 {
        let shift = 32 - bits;
        ((value << shift) as i32 >> shift) as i64
    }
}

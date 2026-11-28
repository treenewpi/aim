//! The image check for the commpage retry. It does not execute the
//! fallback: that path runs only when the two offset loads disagree, which
//! a host whose commpage is stable does not do.

#[test]
fn commpage_retries_are_bounded() {
    let text = aim_linux_abi::vdso::translated_text();
    aim_linux_abi::vdso::commpage_retry_is_bounded(&text).unwrap();
}

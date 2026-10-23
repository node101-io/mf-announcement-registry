//! The announcement number, from a first line that is exactly `MF Announcement #N`
//! or `Announcement #N`. Mirrors `announcement_number` in lib/src/lib.rs.

global MAX_DIGITS: u32 = 20;

pub fn number<let N: u32>(text: [u8; N], len: u32) -> u64 {
    let mf = starts_with(text, "MF Announcement #".as_bytes());
    let plain = starts_with(text, "Announcement #".as_bytes());
    assert(mf | plain);
    let start: u32 = if mf { 17 } else { 14 };

    let mut n: Field = 0;
    let mut digits: u32 = 0;
    let mut in_number = true;
    for j in 0..MAX_DIGITS + 1 {
        let i = start + j;
        let c = text[i];
        let line_end = (i >= len) | (c == 0x0a);
        if in_number & !line_end {
            assert((c >= 0x30) & (c <= 0x39));
            n = n * 10 + (c - 0x30) as Field;
            digits += 1;
        } else {
            in_number = false;
        }
    }
    assert(!in_number);
    assert(digits >= 1);
    assert((digits == 1) | (text[start] != 0x30)); // no leading zeros
    n.assert_max_bit_size::<64>();
    n as u64
}

/// Text past its length is zero, so a prefix longer than the text never matches.
fn starts_with<let N: u32, let P: u32>(text: [u8; N], prefix: [u8; P]) -> bool {
    let mut matches = true;
    for i in 0..P {
        matches &= text[i] == prefix[i];
    }
    matches
}

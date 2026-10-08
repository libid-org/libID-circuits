// Witness builders the identity circuits' tests share. No circuit's main
// calls them, so they are not part of any circuit's constraints.

use crate::BLINDER_LEN;

/// The blinder `from, from + 1, ..., from + 15`.
pub fn blinder(from: u8) -> [u8; BLINDER_LEN] {
    let mut b: [u8; BLINDER_LEN] = [0; BLINDER_LEN];
    for i in 0..BLINDER_LEN {
        b[i] = from + i as u8;
    }
    b
}

/// `value` in an `N`-byte buffer, the tail zero: how a prover pads a value.
pub fn padded<let N: u32, let M: u32>(value: [u8; M]) -> [u8; N] {
    assert(M <= N, "value longer than its buffer");
    let mut out: [u8; N] = [0; N];
    for i in 0..M {
        out[i] = value[i];
    }
    out
}

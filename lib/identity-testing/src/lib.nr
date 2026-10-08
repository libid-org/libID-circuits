// Witness builders the identity circuits' tests share.
//
// Nargo has no test-only dependencies, so a package that uses these declares
// this library as an ordinary dependency and imports it in its tests alone.
// It is kept out of libid_identity so that no circuit reaches it through the
// library its main calls.

/// The `N`-byte blinder `from, from + 1, ...`.
pub fn blinder<let N: u32>(from: u8) -> [u8; N] {
    let mut b: [u8; N] = [0; N];
    for i in 0..N {
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

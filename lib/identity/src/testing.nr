// Witness builders the identity circuits' tests share. Nothing in a circuit's
// main calls them, so they compile into no circuit.

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

/// A tag as bearer-link's public input: its bytes from the top of a Field.
pub fn packed_tag<let N: u32>(tag: [u8; N]) -> Field {
    let mut packed: Field = 0;
    for i in 0..31 {
        packed = packed * 256 + if i < N { tag[i] as Field } else { 0 };
    }
    packed
}

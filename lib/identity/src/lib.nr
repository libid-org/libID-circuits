// libID identity: what the identity circuits share, and `identity_link`.
// `table.nr` and `table_tests.nr` are generated from libID-contracts' handles.json.

pub mod table;
mod table_tests;
pub mod testing;
mod tests;

use sha256::sha256_var;

/// Blinder width of a tlsn hash commitment.
pub global BLINDER_LEN: u32 = 16;

/// The widest tag a public input carries: one Field holds 31 bytes.
pub global MAX_TAG_LEN: u32 = 31;

/// bearer-link's buffers: GitHub's 39-byte login, and 20 id digits.
pub global MAX_HANDLE_BEARER_LINK: u32 = 39;
pub global MAX_ID_BEARER_LINK: u32 = 20;

/// The bearer cap, the opening's main cost (REQ-PLAT-30/36 allow 4096).
/// A live X bearer measured 91 bytes, a GitHub `gho_` token is 40.
pub global MAX_BEARER_LEN: u32 = 128;

/// An opened bearer: nonempty, printable ASCII (REQ-PLAT-30, REQ-PLAT-36,
/// REQ-COMMON-20). No CR or LF, so REQ-COMMON-37 holds. The tail is not read.
pub fn constrain_bearer<let MAX: u32>(bearer: [u8; MAX], bearer_len: u32) {
    assert(bearer_len != 0, "bearer must not be empty");
    assert(bearer_len <= MAX, "bearer too long");
    for i in 0..MAX {
        let b = bearer[i];
        if i < bearer_len {
            assert(b >= 0x20, "bearer byte below printable ASCII");
            assert(b <= 0x7e, "bearer byte above printable ASCII");
        }
    }
}

/// A tlsn hash commitment of a nonempty value, `SHA256(plaintext[0..plaintext_len] || blinder)`.
pub fn hash_commit<let MAX_PLAIN: u32>(
    plaintext_padded: [u8; MAX_PLAIN],
    plaintext_len: u32,
    blinder: [u8; BLINDER_LEN],
) -> [u8; 32] {
    assert(plaintext_len != 0, "committed value is empty");
    assert(plaintext_len <= MAX_PLAIN, "committed value longer than its buffer");

    let mut input: [u8; MAX_PLAIN + BLINDER_LEN] = [0; MAX_PLAIN + BLINDER_LEN];
    for i in 0..MAX_PLAIN {
        input[i] = plaintext_padded[i];
    }
    for i in 0..BLINDER_LEN {
        input[plaintext_len + i] = blinder[i];
    }
    sha256_var(input, plaintext_len + BLINDER_LEN)
}

/// A tag as a public input carries it: its bytes big-endian from the top of
/// the Field. `node_halves` requires zeros past its length.
pub fn tag_bytes(packed: Field) -> [u8; MAX_TAG_LEN] {
    packed.to_be_bytes()
}

/// A compiled tag in the shape `node_halves` takes.
pub fn tag_of<let N: u32>(tag: [u8; N]) -> ([u8; MAX_TAG_LEN], u32) {
    let mut out: [u8; MAX_TAG_LEN] = [0; MAX_TAG_LEN];
    for i in 0..N {
        out[i] = tag[i];
    }
    (out, N)
}

/// A 32-byte value as two big-endian 16-byte Fields, `[high, low]`.
pub fn halves(digest: [u8; 32]) -> [Field; 2] {
    let mut high: Field = 0;
    let mut low: Field = 0;
    for i in 0..16 {
        high = high * 256 + digest[i] as Field;
        low = low * 256 + digest[i + 16] as Field;
    }
    [high, low]
}

/// A node under a compiled tag, hashed over `TAG + MAX` bytes rather than
/// `MAX_TAG_LEN + MAX`, so a short value keeps to fewer SHA-256 blocks.
pub fn fixed_node_halves<let TAG: u32, let MAX: u32>(
    tag: [u8; TAG],
    value: [u8; MAX],
    len: u32,
) -> [Field; 2] {
    let mut preimage: [u8; TAG + MAX] = [0; TAG + MAX];
    for i in 0..TAG {
        preimage[i] = tag[i];
    }
    for i in 0..MAX {
        preimage[TAG + i] = value[i];
    }
    assert(len <= MAX, "value longer than its buffer");
    halves(sha256_var(preimage, TAG + len))
}

/// `SHA256(tag[0..tag_len] || value[0..len])` as the public inputs carry it.
/// The tag is nonempty and zero past `tag_len`, so one Field encodes it.
/// The caller checks `value` first.
pub fn node_halves<let MAX: u32>(
    tag: [u8; MAX_TAG_LEN],
    tag_len: u32,
    value: [u8; MAX],
    len: u32,
) -> [Field; 2] {
    assert(tag_len != 0, "tag is empty");
    assert(tag_len <= MAX_TAG_LEN, "tag longer than a Field");
    assert(len <= MAX, "value longer than its buffer");
    let mut preimage: [u8; MAX_TAG_LEN + MAX] = [0; MAX_TAG_LEN + MAX];
    for i in 0..MAX_TAG_LEN {
        if i >= tag_len {
            assert(tag[i] == 0, "tag byte past its length");
        }
        preimage[i] = tag[i];
    }
    for i in 0..MAX {
        preimage[tag_len + i] = value[i];
    }
    halves(sha256_var(preimage, tag_len + len))
}

/// A byte of a JSON string as sent: printable ASCII, not `"` or `\`. A value
/// of such bytes between revealed quotes is exactly one string.
fn is_string_byte(b: u8) -> bool {
    (b >= 0x20) & (b <= 0x7e) & (b != 0x22) & (b != 0x5c)
}

/// A handle as sent, folded A-Z to a-z, zero past `len`.
pub fn fold_handle<let MAX: u32>(raw: [u8; MAX], len: u32) -> [u8; MAX] {
    assert(len != 0, "handle is empty");
    assert(len <= MAX, "handle too long");
    let mut out: [u8; MAX] = [0; MAX];
    for i in 0..MAX {
        let b = raw[i];
        if i < len {
            assert(is_string_byte(b), "handle byte not allowed");
            out[i] = if (b >= 0x41) & (b <= 0x5a) {
                b + 0x20
            } else {
                b
            };
        }
    }
    out
}

/// An id as sent, never folded: decimal digits, or a JSON string's bytes.
pub fn check_id<let MAX: u32>(raw: [u8; MAX], len: u32, digits: bool) {
    assert(len != 0, "id is empty");
    assert(len <= MAX, "id too long");
    for i in 0..MAX {
        let b = raw[i];
        if i < len {
            let ok = if digits {
                (b >= 0x30) & (b <= 0x39)
            } else {
                is_string_byte(b)
            };
            assert(ok, "id byte not allowed");
        }
    }
}

/// The bearer-link relation: one bearer opens both bearer commitments, the id
/// and handle open theirs, and the nodes are `SHA256(id_tag || id)` and
/// `SHA256(handle_tag || fold(handle))` under the tags the verifier passes.
pub fn identity_link(
    bearer: [u8; MAX_BEARER_LEN],
    bearer_len: u32,
    blinder_token: [u8; BLINDER_LEN],
    blinder_identity: [u8; BLINDER_LEN],
    id: [u8; MAX_ID_BEARER_LINK],
    id_len: u32,
    blinder_id: [u8; BLINDER_LEN],
    handle: [u8; MAX_HANDLE_BEARER_LINK],
    handle_len: u32,
    blinder_handle: [u8; BLINDER_LEN],
    token_commitment: [Field; 2],
    identity_commitment: [Field; 2],
    id_commitment: [Field; 2],
    handle_commitment: [Field; 2],
    id_node: [Field; 2],
    handle_node: [Field; 2],
    id_tag: Field,
    id_tag_len: u32,
    handle_tag: Field,
    handle_tag_len: u32,
) {
    // 1. The bearer link.
    constrain_bearer(bearer, bearer_len);
    assert(
        halves(hash_commit(bearer, bearer_len, blinder_token)) == token_commitment,
        "token bearer commitment mismatch",
    );
    assert(
        halves(hash_commit(bearer, bearer_len, blinder_identity)) == identity_commitment,
        "identity bearer commitment mismatch",
    );

    // 2. The values as sent: whole JSON tokens, so no commitment runs past one.
    check_id(id, id_len, true);
    let folded = fold_handle(handle, handle_len);
    assert(halves(hash_commit(id, id_len, blinder_id)) == id_commitment, "id commitment mismatch");
    assert(
        halves(hash_commit(handle, handle_len, blinder_handle)) == handle_commitment,
        "handle commitment mismatch",
    );

    // 3. The keys.
    assert(node_halves(tag_bytes(id_tag), id_tag_len, id, id_len) == id_node, "id node mismatch");
    assert(
        node_halves(tag_bytes(handle_tag), handle_tag_len, folded, handle_len) == handle_node,
        "handle node mismatch",
    );
}

// libID identity: what the identity circuits share, and `identity_link`.
// `table.nr` and `table_tests.nr` are generated from libID-contracts' handles.json.

pub mod table;
mod table_tests;
pub mod testing;
mod tests;

use sha256::sha256_var;

/// Blinder width of a tlsn hash commitment.
pub global BLINDER_LEN: u32 = 16;

/// What a platform allows in a handle, as `handles.json` states it.
/// `bytes` maps each raw byte to its fold, or to 0 where the platform
/// refuses it.
pub struct HandleRules {
    pub max_len: u32,
    pub allow_hyphen: bool,
    pub is_email: bool,
    pub bytes: [u8; 256],
}

/// What a platform allows in an id. `bytes` says whether each byte may
/// appear in one.
pub struct IdRules {
    pub max_len: u32,
    pub leading_zero: bool,
    pub bytes: [bool; 256],
}

/// Each circuit's bearer cap, the opening's main cost (REQ-PLAT-30/36 allow 4096).
/// GitHub's 47 keeps bearer || blinder in one SHA-256 block; live X bearers are 91 bytes.
pub global MAX_BEARER_LEN_X: u32 = 128;
pub global MAX_BEARER_LEN_GITHUB: u32 = 47;

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

/// A tlsn hash commitment, `SHA256(plaintext[0..plaintext_len] || blinder)`.
/// `TOTAL` is `MAX_PLAIN + BLINDER_LEN`; Noir array types cannot express the sum.
pub fn hash_commit<let MAX_PLAIN: u32, let TOTAL: u32>(
    plaintext_padded: [u8; MAX_PLAIN],
    plaintext_len: u32,
    blinder: [u8; BLINDER_LEN],
) -> [u8; 32] {
    assert(TOTAL == MAX_PLAIN + BLINDER_LEN, "TOTAL must equal MAX_PLAIN + BLINDER_LEN");
    assert(plaintext_len <= MAX_PLAIN, "committed value longer than its buffer");

    let mut input: [u8; TOTAL] = [0; TOTAL];
    for i in 0..MAX_PLAIN {
        input[i] = plaintext_padded[i];
    }
    for i in 0..BLINDER_LEN {
        input[plaintext_len + i] = blinder[i];
    }
    sha256_var(input, plaintext_len + BLINDER_LEN)
}

/// `SHA256(tag || value[0..len])`, the node of a checked value. `TOTAL` is `TAG + MAX`.
pub fn tagged_hash<let TAG: u32, let MAX: u32, let TOTAL: u32>(
    tag: [u8; TAG],
    value: [u8; MAX],
    len: u32,
) -> [u8; 32] {
    assert(TOTAL == TAG + MAX, "TOTAL must equal TAG + MAX");
    let mut preimage: [u8; TOTAL] = [0; TOTAL];
    for i in 0..TAG {
        preimage[i] = tag[i];
    }
    for i in 0..MAX {
        preimage[TAG + i] = value[i];
    }
    sha256_var(preimage, TAG + len)
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

/// A node as the public inputs carry it: `halves(SHA256(tag || value[0..len]))`.
/// The caller checks `value` first.
pub fn node_halves<let TAG: u32, let MAX: u32>(
    tag: [u8; TAG],
    value: [u8; MAX],
    len: u32,
) -> [Field; 2] {
    halves(tagged_hash::<TAG, MAX, TAG + MAX>(tag, value, len))
}

/// Check a handle as the platform sent it and return it folded, zero past `len`.
/// Refuses, never repairs; checks run in every language's order: empty, too
/// long, byte, shape.
pub fn normalize_handle<let MAX: u32>(raw: [u8; MAX], len: u32, rules: HandleRules) -> [u8; MAX] {
    assert(len != 0, "handle is empty");
    assert((len <= MAX) & (len <= rules.max_len), "handle too long");

    let mut out: [u8; MAX] = [0; MAX];
    let mut ats: u32 = 0;
    let mut at: u32 = 0;
    let mut doubled = false;
    let mut previous_hyphen = false;
    for i in 0..MAX {
        let b = raw[i];
        if i < len {
            let c = rules.bytes[b as u32];
            assert(c != 0, "handle byte not allowed");
            out[i] = c;
            if c == 0x40 {
                ats += 1;
                at = i;
            }
            let hyphen = c == 0x2d;
            if hyphen & previous_hyphen {
                doubled = true;
            }
            previous_hyphen = hyphen;
        }
    }

    if rules.is_email {
        assert((ats == 1) & (at != 0) & (at != len - 1), "handle shape not allowed");
    } else if rules.allow_hyphen {
        assert((out[0] != 0x2d) & (out[len - 1] != 0x2d) & !doubled, "handle shape not allowed");
    }
    out
}

/// Check an id exactly as the platform sent it. Ids are never folded.
pub fn check_id<let MAX: u32>(raw: [u8; MAX], len: u32, rules: IdRules) {
    assert(len != 0, "id is empty");
    assert((len <= MAX) & (len <= rules.max_len), "id too long");
    for i in 0..MAX {
        let b = raw[i];
        if i < len {
            assert(rules.bytes[b as u32], "id byte not allowed");
        }
    }
    if !rules.leading_zero {
        assert((len == 1) | (raw[0] != 0x30), "id shape not allowed");
    }
}

/// The bearer-link relation: one bearer opens both bearer commitments, the raw
/// id and handle open theirs and meet the rules, and the nodes are
/// SHA256(id_tag || id) and SHA256(handle_tag || fold(handle)).
pub fn identity_link<let ID_TAG: u32, let HANDLE_TAG: u32, let MAX_BEARER: u32, let MAX_ID: u32, let MAX_HANDLE: u32>(
    id_tag: [u8; ID_TAG],
    handle_tag: [u8; HANDLE_TAG],
    id_rules: IdRules,
    handle_rules: HandleRules,
    bearer: [u8; MAX_BEARER],
    bearer_len: u32,
    blinder_token: [u8; BLINDER_LEN],
    blinder_identity: [u8; BLINDER_LEN],
    id: [u8; MAX_ID],
    id_len: u32,
    blinder_id: [u8; BLINDER_LEN],
    handle: [u8; MAX_HANDLE],
    handle_len: u32,
    blinder_handle: [u8; BLINDER_LEN],
    token_commitment: [Field; 2],
    identity_commitment: [Field; 2],
    id_commitment: [Field; 2],
    handle_commitment: [Field; 2],
    id_node: [Field; 2],
    handle_node: [Field; 2],
) {
    // 1. The bearer link.
    constrain_bearer(bearer, bearer_len);
    assert(
        halves(hash_commit::<MAX_BEARER, MAX_BEARER + BLINDER_LEN>(
            bearer,
            bearer_len,
            blinder_token,
        ))
            == token_commitment,
        "token bearer commitment mismatch",
    );
    assert(
        halves(hash_commit::<MAX_BEARER, MAX_BEARER + BLINDER_LEN>(
            bearer,
            bearer_len,
            blinder_identity,
        ))
            == identity_commitment,
        "identity bearer commitment mismatch",
    );

    // 2-3. The raw values, checked as the platform sent them.
    check_id(id, id_len, id_rules);
    let folded = normalize_handle(handle, handle_len, handle_rules);
    assert(
        halves(
            hash_commit::<MAX_ID, MAX_ID + BLINDER_LEN>(id, id_len, blinder_id),
        )
            == id_commitment,
        "id commitment mismatch",
    );
    assert(
        halves(hash_commit::<MAX_HANDLE, MAX_HANDLE + BLINDER_LEN>(
            handle,
            handle_len,
            blinder_handle,
        ))
            == handle_commitment,
        "handle commitment mismatch",
    );

    // 4. The keys.
    assert(node_halves(id_tag, id, id_len) == id_node, "id node mismatch");
    assert(node_halves(handle_tag, folded, handle_len) == handle_node, "handle node mismatch");
}

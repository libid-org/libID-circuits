// libID identity: the relation every identity circuit shares.
//
// A platform's id and handle become keys here and nowhere else. The circuit
// opens the values the platform sent, checks them against the platform's
// rules, folds the handle, and outputs
//
//   idNode     = SHA256(id tag     || id)
//   handleNode = SHA256(handle tag || fold(handle))
//
// The rules, the tags and the vector table are generated from libid-contracts'
// `solidity/contracts/identity/handles.json` into `table.nr`; the algorithm
// below is written by hand, as it is in Solidity, Rust and TypeScript, and the
// generated tests run it against the same table those languages run.

pub mod table;

use sha256::sha256_var;

/// Blinder width of a tlsn hash commitment. The notary secret-shares this
/// value and appends it to the committed range before SHA-256.
pub global BLINDER_LEN: u32 = 16;

/// What a platform allows in a handle, as `handles.json` states it.
pub struct HandleRules {
    pub max_len: u32,
    pub allow_underscore: bool,
    pub allow_hyphen: bool,
    pub is_email: bool,
}

/// What a platform allows in an id. `decimal` ids are ASCII digits;
/// otherwise printable ASCII without `"` or `\`.
pub struct IdRules {
    pub max_len: u32,
    pub decimal: bool,
    pub leading_zero: bool,
}

/// Bearer hard cap.
///
/// REQ-PLAT-30 and REQ-PLAT-36 permit up to 4096 bytes. The circuits pin 128,
/// which live X ceremonies produce; GitHub `gho_` tokens are 40 bytes. The
/// bound is the bearer opening's whole cost driver, so it is set to the
/// smallest value the platforms are known to fit.
pub global MAX_BEARER_LEN: u32 = 128;

/// Constrain an opened bearer: nonempty, printable ASCII, zero-padded tail
/// (REQ-PLAT-30, REQ-PLAT-36, REQ-COMMON-20). `0x20`-`0x7e` excludes CR and
/// LF, so REQ-COMMON-37 holds by construction -- the identity session sends
/// this range inside an HTTP header.
pub fn constrain_bearer(bearer: [u8; MAX_BEARER_LEN], bearer_len: u32) {
    assert(bearer_len != 0, "bearer must not be empty");
    assert(bearer_len <= MAX_BEARER_LEN, "bearer too long");
    for i in 0..MAX_BEARER_LEN {
        let b = bearer[i];
        if i < bearer_len {
            assert(b >= 0x20, "bearer byte below printable ASCII");
            assert(b <= 0x7e, "bearer byte above printable ASCII");
        } else {
            assert(b == 0, "bearer tail must be zero-padded");
        }
    }
}

/// A tlsn hash commitment, `SHA256(plaintext[0..plaintext_len] || blinder)`.
///
/// `TOTAL` is the caller's `MAX_PLAIN + BLINDER_LEN`; Noir array types cannot
/// express the sum. The bytes past `plaintext_len` are not hashed, so a caller
/// constrains them (every caller here requires them zero).
pub fn hash_commit<let MAX_PLAIN: u32, let TOTAL: u32>(
    plaintext_padded: [u8; MAX_PLAIN],
    plaintext_len: u32,
    blinder: [u8; BLINDER_LEN],
) -> [u8; 32] {
    assert(TOTAL == MAX_PLAIN + BLINDER_LEN, "TOTAL must equal MAX_PLAIN + BLINDER_LEN");
    assert(plaintext_len <= MAX_PLAIN, "committed value longer than its buffer");

    let mut input: [u8; TOTAL] = [0; TOTAL];
    for i in 0..MAX_PLAIN {
        if i < plaintext_len {
            input[i] = plaintext_padded[i];
        }
    }
    for i in 0..BLINDER_LEN {
        input[plaintext_len + i] = blinder[i];
    }
    sha256_var(input, plaintext_len + BLINDER_LEN)
}

/// `SHA256(tag || value[0..len])`, the node of a checked value.
///
/// `TOTAL` is `TAG + MAX`. The value's tail is not hashed; the checks below
/// require it zero, so a padded buffer has one node.
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

/// A 32-byte value as two big-endian 16-byte Fields, `[high, low]`, the
/// form a verifier writes a hash or a commitment into the public inputs in.
/// Each half is below 2^128 by construction.
pub fn halves(digest: [u8; 32]) -> [Field; 2] {
    let mut high: Field = 0;
    let mut low: Field = 0;
    for i in 0..16 {
        high = high * 256 + digest[i] as Field;
        low = low * 256 + digest[i + 16] as Field;
    }
    [high, low]
}

/// A-Z down to a-z; every other byte unchanged.
pub fn fold(b: u8) -> u8 {
    if (b >= 0x41) & (b <= 0x5a) {
        b + 0x20
    } else {
        b
    }
}

fn handle_byte_allowed(c: u8, rules: HandleRules) -> bool {
    let lower = (c >= 0x61) & (c <= 0x7a);
    let digit = (c >= 0x30) & (c <= 0x39);
    let email =
        rules.is_email & ((c == 0x2e) | (c == 0x2b) | (c == 0x2d) | (c == 0x5f) | (c == 0x40));
    let underscore = rules.allow_underscore & (c == 0x5f);
    let hyphen = rules.allow_hyphen & (c == 0x2d);
    lower | digit | email | underscore | hyphen
}

/// Check a handle exactly as the platform sent it and return it folded.
///
/// Refuses, never repairs: no byte is trimmed and no `@` is stripped, so a
/// value that is not already a handle has no node. The checks run in the
/// order every language runs them -- empty, too long, each byte, shape -- so
/// a refused vector is refused for the same reason everywhere.
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
            let c = fold(b);
            assert(handle_byte_allowed(c, rules), "handle byte not allowed");
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
        } else {
            assert(b == 0, "handle tail must be zero-padded");
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
            let ok = if rules.decimal {
                (b >= 0x30) & (b <= 0x39)
            } else {
                (b >= 0x20) & (b <= 0x7e) & (b != 0x22) & (b != 0x5c)
            };
            assert(ok, "id byte not allowed");
        } else {
            assert(b == 0, "id tail must be zero-padded");
        }
    }
    if !rules.leading_zero {
        assert((len == 1) | (raw[0] != 0x30), "id shape not allowed");
    }
}

/// The bearer-link relation with the account as keys, for one platform's
/// tags and rules:
///
///   1. one hidden bearer opens both bearer commitments, the token session's
///      and the identity session's;
///   2. the RAW id and the RAW handle open their commitments -- the bytes the
///      platform sent, before any transform;
///   3. the raw id meets `id_rules` and the raw handle meets `handle_rules`;
///      both checks also require a zero tail, so the bytes the commitments
///      do not hash are not free;
///   4. id_node     = SHA256(id_tag     || raw id)
///      handle_node = SHA256(handle_tag || fold(raw handle)),
///      the fold applied byte by byte to the same witness that opened (2).
///
/// So the signed commitment and the output node are tied through the
/// constrained fold: a node is a key only for the handle the platform
/// returned. A circuit's main passes its own inputs through in order and
/// selects the platform's constants; the public inputs are main's.
pub fn identity_link<let ID_TAG: u32, let HANDLE_TAG: u32, let MAX_ID: u32, let MAX_HANDLE: u32>(
    id_tag: [u8; ID_TAG],
    handle_tag: [u8; HANDLE_TAG],
    id_rules: IdRules,
    handle_rules: HandleRules,
    bearer: [u8; MAX_BEARER_LEN],
    bearer_len: u32,
    blinder_token: [u8; BLINDER_LEN],
    blinder_identity: [u8; BLINDER_LEN],
    id: [u8; MAX_ID],
    id_len: u32,
    blinder_id: [u8; BLINDER_LEN],
    handle: [u8; MAX_HANDLE],
    handle_len: u32,
    blinder_handle: [u8; BLINDER_LEN],
    token_commitment: [u8; 32],
    identity_commitment: [u8; 32],
    id_commitment: [Field; 2],
    handle_commitment: [Field; 2],
    id_node: [Field; 2],
    handle_node: [Field; 2],
) {
    // 1. The bearer link.
    constrain_bearer(bearer, bearer_len);
    assert(
        hash_commit::<MAX_BEARER_LEN, MAX_BEARER_LEN + BLINDER_LEN>(
            bearer,
            bearer_len,
            blinder_token,
        )
            == token_commitment,
        "token bearer commitment mismatch",
    );
    assert(
        hash_commit::<MAX_BEARER_LEN, MAX_BEARER_LEN + BLINDER_LEN>(
            bearer,
            bearer_len,
            blinder_identity,
        )
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
    assert(
        halves(
            tagged_hash::<ID_TAG, MAX_ID, ID_TAG + MAX_ID>(id_tag, id, id_len),
        )
            == id_node,
        "id node mismatch",
    );
    assert(
        halves(tagged_hash::<HANDLE_TAG, MAX_HANDLE, HANDLE_TAG + MAX_HANDLE>(
            handle_tag,
            folded,
            handle_len,
        ))
            == handle_node,
        "handle node mismatch",
    );
}

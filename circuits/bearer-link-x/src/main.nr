// libID bearer-link circuit for X: the bearer link, plus the account's id
// and handle as keys.
//
// The ceremony notarizes two TLS sessions: the token session
// (`/2/oauth2/token`) and the identity session (`/2/users/me`). Each commits
// the same OAuth bearer behind its own blinder. The identity response reveals
// only the anchors around `id` and `username`; the two VALUES are committed,
// each as its own range.
//
// This circuit proves:
//   1. one hidden bearer opens both bearer commitments (REQ-PLAT-32);
//   2. the RAW id and the RAW handle open their commitments -- the bytes X
//      sent, before any transform;
//   3. the raw id is X's id shape, and the raw handle is an X handle;
//   4. idNode     = SHA256("libid.x.user-id" || raw id)
//      handleNode = SHA256("libid.x.handle"  || fold(raw handle)),
//      the fold applied byte by byte to the same witness that opened (2).
//
// So the signed commitment and the output node are tied through the
// constrained fold: a node is a key only for the handle X returned.
//
// Public inputs, in order (72 fields):
//   0-31   token_commitment     one byte per field
//   32-63  identity_commitment  one byte per field
//   64-65  id_commitment        [high, low] 16-byte big-endian halves
//   66-67  handle_commitment    halves
//   68-69  id_node              halves
//   70-71  handle_node          halves
// The Platform Verifier writes 0-67 from the signed records and 68-71 from
// the claim it returns; nothing here is read from a payload.

use libid_identity::{
    BLINDER_LEN,
    check_id,
    constrain_bearer,
    halves,
    hash_commit,
    MAX_BEARER_LEN,
    normalize_handle,
    table::{HANDLE_RULES_X, HANDLE_TAG_X, ID_RULES_X, MAX_HANDLE_X, MAX_ID_X, USER_ID_TAG_X},
    tagged_hash,
    verify_hash_commit,
};

global BEARER_COMMIT_LEN: u32 = 144; // MAX_BEARER_LEN + BLINDER_LEN
global ID_COMMIT_LEN: u32 = 36; // MAX_ID_X + BLINDER_LEN
global HANDLE_COMMIT_LEN: u32 = 31; // MAX_HANDLE_X + BLINDER_LEN
global ID_NODE_LEN: u32 = 35; // len(USER_ID_TAG_X) + MAX_ID_X
global HANDLE_NODE_LEN: u32 = 29; // len(HANDLE_TAG_X) + MAX_HANDLE_X

fn main(
    // --- Private ---
    bearer: [u8; MAX_BEARER_LEN],
    bearer_len: u32,
    blinder_token: [u8; BLINDER_LEN],
    blinder_identity: [u8; BLINDER_LEN],
    id: [u8; MAX_ID_X],
    id_len: u32,
    blinder_id: [u8; BLINDER_LEN],
    handle: [u8; MAX_HANDLE_X],
    handle_len: u32,
    blinder_handle: [u8; BLINDER_LEN],
    // --- Public ---
    token_commitment: pub [u8; 32],
    identity_commitment: pub [u8; 32],
    id_commitment: pub [Field; 2],
    handle_commitment: pub [Field; 2],
    id_node: pub [Field; 2],
    handle_node: pub [Field; 2],
) {
    // 1. The bearer link.
    constrain_bearer(bearer, bearer_len);
    verify_hash_commit::<MAX_BEARER_LEN, BEARER_COMMIT_LEN>(
        bearer,
        bearer_len,
        blinder_token,
        token_commitment,
    );
    verify_hash_commit::<MAX_BEARER_LEN, BEARER_COMMIT_LEN>(
        bearer,
        bearer_len,
        blinder_identity,
        identity_commitment,
    );

    // 2-3. The raw values, checked as X sent them. Both checks also require a
    // zero tail, so the bytes the commitments do not hash are not free.
    check_id(id, id_len, ID_RULES_X);
    let folded = normalize_handle(handle, handle_len, HANDLE_RULES_X);
    assert(
        halves(
            hash_commit::<MAX_ID_X, ID_COMMIT_LEN>(id, id_len, blinder_id),
        )
            == id_commitment,
        "id commitment mismatch",
    );
    assert(
        halves(
            hash_commit::<MAX_HANDLE_X, HANDLE_COMMIT_LEN>(handle, handle_len, blinder_handle),
        )
            == handle_commitment,
        "handle commitment mismatch",
    );

    // 4. The keys.
    assert(
        halves(
            tagged_hash::<15, MAX_ID_X, ID_NODE_LEN>(USER_ID_TAG_X, id, id_len),
        )
            == id_node,
        "id node mismatch",
    );
    assert(
        halves(
            tagged_hash::<14, MAX_HANDLE_X, HANDLE_NODE_LEN>(HANDLE_TAG_X, folded, handle_len),
        )
            == handle_node,
        "handle node mismatch",
    );
}

// --- Tests ----------------------------------------------------------------
//
// Every expected value comes from an independent Python computation (hashlib
// over the bytes written out below), not from this circuit:
//
//   bearer "tok-123", blinders bytes(0..16), (16..32), (32..48), (48..64)
//   id "2244994945", handle "Al_1" -- mixed case, as X returns handles
//   handle node = SHA256("libid.x.handle" || "al_1")

struct Case {
    bearer: [u8; MAX_BEARER_LEN],
    id: [u8; MAX_ID_X],
    handle: [u8; MAX_HANDLE_X],
    handle_len: u32,
    token_commitment: [u8; 32],
    identity_commitment: [u8; 32],
    id_commitment: [Field; 2],
    handle_commitment: [Field; 2],
    id_node: [Field; 2],
    handle_node: [Field; 2],
}

fn blinder(from: u8) -> [u8; BLINDER_LEN] {
    let mut b: [u8; BLINDER_LEN] = [0; BLINDER_LEN];
    for i in 0..BLINDER_LEN {
        b[i] = from + i as u8;
    }
    b
}

fn case() -> Case {
    let mut bearer: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    let tok = "tok-123".as_bytes();
    for i in 0..7 {
        bearer[i] = tok[i];
    }
    let mut id: [u8; MAX_ID_X] = [0; MAX_ID_X];
    let digits = "2244994945".as_bytes();
    for i in 0..10 {
        id[i] = digits[i];
    }
    let mut handle: [u8; MAX_HANDLE_X] = [0; MAX_HANDLE_X];
    let name = "Al_1".as_bytes();
    for i in 0..4 {
        handle[i] = name[i];
    }
    Case {
        bearer,
        id,
        handle,
        handle_len: 4,
        token_commitment: [
            13, 195, 106, 174, 167, 138, 231, 116, 69, 94, 154, 13, 119, 74, 173, 82, 8, 74, 171,
            124, 164, 174, 2, 135, 110, 6, 74, 231, 193, 128, 226, 253,
        ],
        identity_commitment: [
            154, 239, 70, 3, 22, 146, 248, 48, 167, 68, 88, 44, 176, 247, 149, 202, 48, 22, 213, 85,
            245, 110, 223, 118, 86, 36, 246, 209, 76, 216, 24, 41,
        ],
        id_commitment: [
            180882572271038392724240957031789911607,
            54180230646233245715970256313862784354,
        ],
        handle_commitment: [
            198322726903418736804699640699405223113,
            241770853389097985508516863549713034451,
        ],
        id_node: [138453090876486342079439112189991629410, 68569463062552354167696804669992816532],
        handle_node: [
            169904273960443994800052718057341968900,
            182742246427322026301030621552550382480,
        ],
    }
}

fn run(c: Case) {
    main(
        c.bearer,
        7,
        blinder(0),
        blinder(16),
        c.id,
        10,
        blinder(32),
        c.handle,
        c.handle_len,
        blinder(48),
        c.token_commitment,
        c.identity_commitment,
        c.id_commitment,
        c.handle_commitment,
        c.id_node,
        c.handle_node,
    );
}

#[test]
fn a_mixed_case_handle_proves_its_folded_node() {
    run(case());
}

#[test(should_fail_with = "handle node mismatch")]
fn the_node_of_the_unfolded_handle_is_refused() {
    // SHA256("libid.x.handle" || "Al_1"): the bytes as sent, not folded.
    let mut c = case();
    c.handle_node =
        [267300311448676971478191245684082975980, 285947479440947337369846851958243551472];
    run(c);
}

#[test(should_fail_with = "id commitment mismatch")]
fn swapped_value_commitments_are_refused() {
    let mut c = case();
    let id_commitment = c.id_commitment;
    c.id_commitment = c.handle_commitment;
    c.handle_commitment = id_commitment;
    run(c);
}

#[test(should_fail_with = "handle commitment mismatch")]
fn a_handle_other_than_the_committed_one_is_refused() {
    // "al_1" folds to the same node, but it is not the value X committed.
    let mut c = case();
    c.handle[0] = 0x61;
    run(c);
}

#[test(should_fail_with = "hash commit mismatch")]
fn another_session_s_bearer_commitment_is_refused() {
    let mut c = case();
    c.identity_commitment = c.token_commitment;
    run(c);
}

#[test(should_fail_with = "id node mismatch")]
fn the_handle_node_in_the_id_position_is_refused() {
    let mut c = case();
    c.id_node = c.handle_node;
    run(c);
}

#[test(should_fail_with = "handle byte not allowed")]
fn a_handle_outside_x_s_rules_is_refused_before_any_hash() {
    // A hyphen is GitHub's, not X's.
    let mut c = case();
    c.handle[2] = 0x2d;
    run(c);
}

#[test(should_fail_with = "handle tail must be zero-padded")]
fn bytes_past_the_handle_are_refused() {
    let mut c = case();
    c.handle[5] = 0x61;
    run(c);
}

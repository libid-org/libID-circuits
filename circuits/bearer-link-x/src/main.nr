// libID bearer-link circuit for X: `libid_identity::identity_link` with X's
// tags and rules (REQ-PLAT-32).
//
// The ceremony notarizes two TLS sessions: the token session
// (`/2/oauth2/token`) and the identity session (`/2/users/me`). Each commits
// the same OAuth bearer behind its own blinder. The identity response reveals
// only the anchors around `id` and `username`; the two values are committed,
// each as its own range.
//
// Public inputs, in order (72 fields):
//   0-31   token_commitment     one byte per field
//   32-63  identity_commitment  one byte per field
//   64-65  id_commitment        [high, low] 16-byte big-endian halves
//   66-67  handle_commitment    halves
//   68-69  id_node              halves
//   70-71  handle_node          halves
// The Platform Verifier writes 0-67 from the records the notary signed, never
// from the payload. 68-71 are the nodes the payload claims and the claim
// returns; this proof is what binds them to the committed values.

use libid_identity::{
    BLINDER_LEN,
    identity_link,
    MAX_BEARER_LEN,
    table::{HANDLE_RULES_X, HANDLE_TAG_X, ID_RULES_X, MAX_HANDLE_X, MAX_ID_X, USER_ID_TAG_X},
};

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
    identity_link(
        USER_ID_TAG_X,
        HANDLE_TAG_X,
        ID_RULES_X,
        HANDLE_RULES_X,
        bearer,
        bearer_len,
        blinder_token,
        blinder_identity,
        id,
        id_len,
        blinder_id,
        handle,
        handle_len,
        blinder_handle,
        token_commitment,
        identity_commitment,
        id_commitment,
        handle_commitment,
        id_node,
        handle_node,
    );
}

// --- Tests ----------------------------------------------------------------

use libid_identity::testing::{blinder, padded};
//
// Every expected value comes from an independent Python computation (hashlib
// over the bytes written out below), not from this circuit:
//
//   bearer "tok-123", blinders bytes(0..16), (16..32), (32..48), (48..64)
//   id "2244994945", handle "Al_1" -- mixed case, as X returns handles
//   handle node = SHA256("libid.x.handle" || "al_1")

struct Case {
    bearer: [u8; MAX_BEARER_LEN],
    bearer_len: u32,
    id: [u8; MAX_ID_X],
    id_len: u32,
    handle: [u8; MAX_HANDLE_X],
    handle_len: u32,
    token_commitment: [u8; 32],
    identity_commitment: [u8; 32],
    id_commitment: [Field; 2],
    handle_commitment: [Field; 2],
    id_node: [Field; 2],
    handle_node: [Field; 2],
}

fn case() -> Case {
    Case {
        bearer: padded("tok-123".as_bytes()),
        bearer_len: 7,
        id: padded("2244994945".as_bytes()),
        id_len: 10,
        handle: padded("Al_1".as_bytes()),
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
        c.bearer_len,
        blinder(0),
        blinder(16),
        c.id,
        c.id_len,
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

#[test(should_fail_with = "token bearer commitment mismatch")]
fn the_identity_session_s_commitment_as_the_token_s_is_refused() {
    let mut c = case();
    c.token_commitment = c.identity_commitment;
    run(c);
}

#[test(should_fail_with = "identity bearer commitment mismatch")]
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

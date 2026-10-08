// libID bearer-link circuit for GitHub: the bearer link, plus the account's
// id and login as keys.
//
// The ceremony notarizes two TLS sessions: the token exchange
// (`/login/oauth/access_token`) and the identity read (`/user`). Each commits
// the same OAuth bearer behind its own blinder. The identity response reveals
// only the anchors around `id` and `login`; the two VALUES are committed,
// each as its own range -- the id's digits alone, its `,` or `}` revealed.
//
// This circuit proves:
//   1. one hidden bearer opens both bearer commitments (REQ-PLAT-52);
//   2. the RAW id and the RAW login open their commitments -- the bytes
//      GitHub sent, before any transform;
//   3. the raw id is a JSON integer without a leading zero, and the raw login
//      is a GitHub login;
//   4. idNode     = SHA256("libid.github.user-id" || raw id)
//      handleNode = SHA256("libid.github.handle"  || fold(raw login)),
//      the fold applied byte by byte to the same witness that opened (2).
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
    table::{
        HANDLE_RULES_GITHUB, HANDLE_TAG_GITHUB, ID_RULES_GITHUB, MAX_HANDLE_GITHUB, MAX_ID_GITHUB,
        USER_ID_TAG_GITHUB,
    },
    tagged_hash,
    verify_hash_commit,
};

global BEARER_COMMIT_LEN: u32 = 144; // MAX_BEARER_LEN + BLINDER_LEN
global ID_COMMIT_LEN: u32 = 36; // MAX_ID_GITHUB + BLINDER_LEN
global HANDLE_COMMIT_LEN: u32 = 55; // MAX_HANDLE_GITHUB + BLINDER_LEN
global ID_NODE_LEN: u32 = 40; // len(USER_ID_TAG_GITHUB) + MAX_ID_GITHUB
global HANDLE_NODE_LEN: u32 = 58; // len(HANDLE_TAG_GITHUB) + MAX_HANDLE_GITHUB

fn main(
    // --- Private ---
    bearer: [u8; MAX_BEARER_LEN],
    bearer_len: u32,
    blinder_token: [u8; BLINDER_LEN],
    blinder_identity: [u8; BLINDER_LEN],
    id: [u8; MAX_ID_GITHUB],
    id_len: u32,
    blinder_id: [u8; BLINDER_LEN],
    handle: [u8; MAX_HANDLE_GITHUB],
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

    // 2-3. The raw values, checked as GitHub sent them. Both checks also require a
    // zero tail, so the bytes the commitments do not hash are not free.
    check_id(id, id_len, ID_RULES_GITHUB);
    let folded = normalize_handle(handle, handle_len, HANDLE_RULES_GITHUB);
    assert(
        halves(
            hash_commit::<MAX_ID_GITHUB, ID_COMMIT_LEN>(id, id_len, blinder_id),
        )
            == id_commitment,
        "id commitment mismatch",
    );
    assert(
        halves(hash_commit::<MAX_HANDLE_GITHUB, HANDLE_COMMIT_LEN>(
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
            tagged_hash::<20, MAX_ID_GITHUB, ID_NODE_LEN>(USER_ID_TAG_GITHUB, id, id_len),
        )
            == id_node,
        "id node mismatch",
    );
    assert(
        halves(tagged_hash::<19, MAX_HANDLE_GITHUB, HANDLE_NODE_LEN>(
            HANDLE_TAG_GITHUB,
            folded,
            handle_len,
        ))
            == handle_node,
        "handle node mismatch",
    );
}

// --- Tests ----------------------------------------------------------------
//
// Every expected value comes from an independent Python computation (hashlib
// over the bytes written out below), not from this circuit:
//
//   bearer "gho_tok", blinders bytes(0..16), (16..32), (32..48), (48..64)
//   id "583231", login "Octo-Cat" -- mixed case, as GitHub returns logins
//   handle node = SHA256("libid.github.handle" || "octo-cat")

struct Case {
    bearer: [u8; MAX_BEARER_LEN],
    id: [u8; MAX_ID_GITHUB],
    id_len: u32,
    handle: [u8; MAX_HANDLE_GITHUB],
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

fn padded<let N: u32, let M: u32>(value: [u8; M]) -> [u8; N] {
    let mut out: [u8; N] = [0; N];
    for i in 0..M {
        out[i] = value[i];
    }
    out
}

fn case() -> Case {
    Case {
        bearer: padded("gho_tok".as_bytes()),
        id: padded("583231".as_bytes()),
        id_len: 6,
        handle: padded("Octo-Cat".as_bytes()),
        token_commitment: [
            207, 83, 93, 174, 152, 218, 205, 138, 32, 116, 63, 118, 148, 60, 162, 49, 146, 117, 24,
            80, 183, 204, 31, 63, 28, 72, 222, 122, 37, 29, 22, 5,
        ],
        identity_commitment: [
            135, 89, 105, 31, 8, 117, 147, 97, 156, 20, 24, 212, 126, 245, 194, 145, 152, 69, 21,
            189, 48, 78, 137, 216, 83, 105, 245, 241, 249, 166, 7, 21,
        ],
        id_commitment: [
            236842316908673321235639020295625166279,
            56934867329343602065661787444362119410,
        ],
        handle_commitment: [
            120995736630130927221836013721711599969,
            82415666527885809701827448153484464537,
        ],
        id_node: [94837356826185273297015099372743338583, 77876476914942338291790918663550801991],
        handle_node: [
            79778013590199783157327299585846572160,
            144831525398659596121816034652479840622,
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
        c.id_len,
        blinder(32),
        c.handle,
        8,
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
fn a_mixed_case_login_proves_its_folded_node() {
    run(case());
}

#[test(should_fail_with = "handle node mismatch")]
fn the_node_of_the_unfolded_login_is_refused() {
    // SHA256("libid.github.handle" || "Octo-Cat"): the bytes as sent.
    let mut c = case();
    c.handle_node =
        [166433837506924129893015763218344751655, 186004512142464271077159688134279535625];
    run(c);
}

#[test(should_fail_with = "id shape not allowed")]
fn an_id_with_a_leading_zero_is_refused_even_when_committed() {
    // "0583231", committed and hashed consistently: not a JSON integer.
    let mut c = case();
    c.id = padded("0583231".as_bytes());
    c.id_len = 7;
    c.id_commitment =
        [11364554627551030261063107494096248855, 309832452746394448749041413548173428871];
    c.id_node = [228151375693883442844628562124697340868, 260186918581112710436133118553218934712];
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

#[test(should_fail_with = "handle byte not allowed")]
fn an_underscore_is_x_s_not_github_s() {
    let mut c = case();
    c.handle[4] = 0x5f;
    run(c);
}

#[test(should_fail_with = "handle shape not allowed")]
fn a_doubled_hyphen_is_refused() {
    let mut c = case();
    c.handle[5] = 0x2d;
    run(c);
}

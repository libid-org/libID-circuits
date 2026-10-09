// libID bearer-link circuit for GitHub: `libid_identity::identity_link` with
// GitHub's tags and rules (REQ-PLAT-52). The login is the handle.
//
// The ceremony notarizes two TLS sessions: the token exchange
// (`/login/oauth/access_token`) and the identity read (`/user`). Each commits
// the same OAuth bearer behind its own blinder. The identity response reveals
// only the anchors around `id` and `login`; the two values are committed,
// each as its own range -- the id's digits alone, its `,` or `}` revealed.
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
    MAX_BEARER_LEN_GITHUB,
    table::{
        HANDLE_RULES_GITHUB, HANDLE_TAG_GITHUB, ID_RULES_GITHUB, MAX_HANDLE_GITHUB, MAX_ID_GITHUB,
        USER_ID_TAG_GITHUB,
    },
};

fn main(
    // --- Private ---
    bearer: [u8; MAX_BEARER_LEN_GITHUB],
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
    identity_link(
        USER_ID_TAG_GITHUB,
        HANDLE_TAG_GITHUB,
        ID_RULES_GITHUB,
        HANDLE_RULES_GITHUB,
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
//   bearer "gho_tok", blinders bytes(0..16), (16..32), (32..48), (48..64)
//   id "583231", login "Octo-Cat" -- mixed case, as GitHub returns logins
//   handle node = SHA256("libid.github.handle" || "octo-cat")

struct Case {
    bearer: [u8; MAX_BEARER_LEN_GITHUB],
    bearer_len: u32,
    id: [u8; MAX_ID_GITHUB],
    id_len: u32,
    handle: [u8; MAX_HANDLE_GITHUB],
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
        bearer: padded("gho_tok".as_bytes()),
        bearer_len: 7,
        id: padded("583231".as_bytes()),
        id_len: 6,
        handle: padded("Octo-Cat".as_bytes()),
        handle_len: 8,
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

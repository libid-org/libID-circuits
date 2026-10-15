// libID bearer-link circuit for X and GitHub: `identity_link` under the tags
// the verifier passes (REQ-PLAT-32, REQ-PLAT-52).
//
// Public inputs, in order (16 fields), each 32-byte value as [high, low] halves:
//   0-1    token_commitment
//   2-3    identity_commitment
//   4-5    id_commitment
//   6-7    handle_commitment
//   8-9    id_node
//   10-11  handle_node
//   12-13  id_tag, id_tag_len
//   14-15  handle_tag, handle_tag_len
// 0-7 come from the notary-signed records, 8-11 are the claimed nodes, and
// 12-15 name the platform. A tag is its bytes from the top of one Field.

use libid_identity::{
    BLINDER_LEN, identity_link, MAX_BEARER_LEN, MAX_HANDLE_BEARER_LINK, MAX_ID_BEARER_LINK,
};

fn main(
    // --- Private ---
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
    // --- Public ---
    token_commitment: pub [Field; 2],
    identity_commitment: pub [Field; 2],
    id_commitment: pub [Field; 2],
    handle_commitment: pub [Field; 2],
    id_node: pub [Field; 2],
    handle_node: pub [Field; 2],
    id_tag: pub Field,
    id_tag_len: pub u32,
    handle_tag: pub Field,
    handle_tag_len: pub u32,
) {
    identity_link(
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
        id_tag,
        id_tag_len,
        handle_tag,
        handle_tag_len,
    );
}

// --- Tests ----------------------------------------------------------------

use libid_identity::{table, testing::{blinder, packed_tag, padded}};

// Expected values are Python hashlib's over: blinders bytes(0..16) to
// (48..64); X: bearer "tok-123", id "2244994945", handle "Al_1" (node of
// "al_1"); GitHub: bearer "gho_tok", id "583231", login "Octo-Cat" (node of
// "octo-cat"). The tags are the table's, so a changed tag fails the nodes.

struct Case {
    bearer: [u8; MAX_BEARER_LEN],
    bearer_len: u32,
    id: [u8; MAX_ID_BEARER_LINK],
    id_len: u32,
    handle: [u8; MAX_HANDLE_BEARER_LINK],
    handle_len: u32,
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
}

fn x() -> Case {
    Case {
        bearer: padded("tok-123".as_bytes()),
        bearer_len: 7,
        id: padded("2244994945".as_bytes()),
        id_len: 10,
        handle: padded("Al_1".as_bytes()),
        handle_len: 4,
        token_commitment: [
            18294625605588383709122521013680778578,
            11021532101111187078447128780644344573,
        ],
        identity_commitment: [
            205943490313409956820245415027323409866,
            63921501292160984142515395269079078953,
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
        id_tag: packed_tag(table::USER_ID_TAG_X),
        id_tag_len: table::USER_ID_TAG_X.len(),
        handle_tag: packed_tag(table::HANDLE_TAG_X),
        handle_tag_len: table::HANDLE_TAG_X.len(),
    }
}

fn github() -> Case {
    Case {
        bearer: padded("gho_tok".as_bytes()),
        bearer_len: 7,
        id: padded("583231".as_bytes()),
        id_len: 6,
        handle: padded("Octo-Cat".as_bytes()),
        handle_len: 8,
        token_commitment: [
            275583055863835631426238934984850973233,
            194675279290012306279782582067549509125,
        ],
        identity_commitment: [
            179910025963072684256461617793699529361,
            202401364762220735308855968515813148437,
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
        id_tag: packed_tag(table::USER_ID_TAG_GITHUB),
        id_tag_len: table::USER_ID_TAG_GITHUB.len(),
        handle_tag: packed_tag(table::HANDLE_TAG_GITHUB),
        handle_tag_len: table::HANDLE_TAG_GITHUB.len(),
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
        c.id_tag,
        c.id_tag_len,
        c.handle_tag,
        c.handle_tag_len,
    );
}

#[test]
fn an_x_handle_proves_its_folded_node() {
    run(x());
}

#[test]
fn a_github_login_proves_its_folded_node() {
    run(github());
}

#[test]
fn a_login_outside_github_s_format_proves() {
    // "Octo--Cat-": the platform's format is the platform's to keep.
    let mut c = github();
    c.handle = padded("Octo--Cat-".as_bytes());
    c.handle_len = 10;
    c.handle_commitment =
        [58081046720187252107041816619799824658, 330150028494759561900771335358262296315];
    c.handle_node =
        [111837190478384659515512478441602654172, 284058410769708376762635998426047724677];
    run(c);
}

#[test(should_fail_with = "handle node mismatch")]
fn the_node_of_the_unfolded_handle_is_refused() {
    // SHA256("libid.x.handle" || "Al_1"): the bytes as sent, not folded.
    let mut c = x();
    c.handle_node =
        [267300311448676971478191245684082975980, 285947479440947337369846851958243551472];
    run(c);
}

#[test(should_fail_with = "id node mismatch")]
fn another_platform_s_tags_are_refused() {
    let mut c = x();
    c.id_tag = packed_tag(table::USER_ID_TAG_GITHUB);
    c.id_tag_len = table::USER_ID_TAG_GITHUB.len();
    c.handle_tag = packed_tag(table::HANDLE_TAG_GITHUB);
    c.handle_tag_len = table::HANDLE_TAG_GITHUB.len();
    run(c);
}

#[test(should_fail_with = "id node mismatch")]
fn the_handle_tag_in_the_id_position_is_refused() {
    let mut c = x();
    c.id_tag = packed_tag(table::HANDLE_TAG_X);
    c.id_tag_len = table::HANDLE_TAG_X.len();
    run(c);
}

#[test(should_fail_with = "tag byte past its length")]
fn a_tag_one_byte_short_is_refused() {
    let mut c = x();
    c.handle_tag_len = table::HANDLE_TAG_X.len() - 1;
    run(c);
}

#[test(should_fail_with = "tag is empty")]
fn an_empty_tag_is_refused() {
    let mut c = x();
    c.id_tag = 0;
    c.id_tag_len = 0;
    run(c);
}

#[test(should_fail_with = "handle byte not allowed")]
fn a_handle_running_past_its_closing_quote_is_refused() {
    // `Al_1","name":"x`: a commitment stretched to a later quote.
    let mut c = x();
    c.handle = padded("Al_1\",\"n".as_bytes());
    c.handle_len = 8;
    run(c);
}

#[test(should_fail_with = "id byte not allowed")]
fn an_id_running_past_its_digits_is_refused() {
    // `583231, "login"`: a JSON integer stretched past its terminator.
    let mut c = github();
    c.id = padded("583231,".as_bytes());
    c.id_len = 7;
    run(c);
}

#[test(should_fail_with = "id byte not allowed")]
fn an_id_with_its_leading_whitespace_is_refused() {
    // `"id": 583231`: the space belongs to the JSON, not the id.
    let mut c = github();
    c.id = padded(" 583231".as_bytes());
    c.id_len = 7;
    run(c);
}

#[test(should_fail_with = "id commitment mismatch")]
fn swapped_value_commitments_are_refused() {
    let mut c = x();
    let id_commitment = c.id_commitment;
    c.id_commitment = c.handle_commitment;
    c.handle_commitment = id_commitment;
    run(c);
}

#[test(should_fail_with = "handle commitment mismatch")]
fn a_handle_other_than_the_committed_one_is_refused() {
    // "al_1" folds to the same node, but it is not the value X committed.
    let mut c = x();
    c.handle[0] = 0x61;
    run(c);
}

#[test(should_fail_with = "token bearer commitment mismatch")]
fn the_identity_session_s_commitment_as_the_token_s_is_refused() {
    let mut c = x();
    c.token_commitment = c.identity_commitment;
    run(c);
}

#[test(should_fail_with = "identity bearer commitment mismatch")]
fn another_session_s_bearer_commitment_is_refused() {
    let mut c = x();
    c.identity_commitment = c.token_commitment;
    run(c);
}

#[test(should_fail_with = "id node mismatch")]
fn the_handle_node_in_the_id_position_is_refused() {
    let mut c = x();
    c.id_node = c.handle_node;
    run(c);
}

#[test(should_fail_with = "id node mismatch")]
fn an_id_node_off_in_its_low_half_is_refused() {
    let mut c = x();
    c.id_node[1] += 1;
    run(c);
}

#[test(should_fail_with = "handle node mismatch")]
fn a_handle_node_off_in_its_low_half_is_refused() {
    let mut c = x();
    c.handle_node[1] += 1;
    run(c);
}

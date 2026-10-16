// Tests of lib.nr. Expected hashes are Python hashlib's, not this library's.

use crate::{
    BLINDER_LEN, check_id, constrain_bearer, fixed_node_halves, fold_handle, hash_commit,
    MAX_BEARER_LEN, MAX_HANDLE_BEARER_LINK, MAX_ID_BEARER_LINK, MAX_TAG_LEN, node_halves, table,
    tag_of,
};
use crate::testing::{blinder, padded};

// --- constrain_bearer -------------------------------------------------------

#[test(should_fail_with = "bearer must not be empty")]
fn an_empty_bearer_is_refused() {
    let bearer: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    constrain_bearer(bearer, 0);
}

#[test(should_fail_with = "bearer byte below printable ASCII")]
fn a_carriage_return_is_refused() {
    // REQ-COMMON-37: a CR would add a header line.
    let mut bearer: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    bearer[0] = 0x61;
    bearer[1] = 0x0d;
    bearer[2] = 0x61;
    constrain_bearer(bearer, 3);
}

#[test(should_fail_with = "bearer byte above printable ASCII")]
fn delete_is_refused() {
    let mut bearer: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    bearer[0] = 0x7f;
    constrain_bearer(bearer, 1);
}

#[test]
fn the_bytes_past_the_bearer_change_nothing() {
    // python3 -c "import hashlib; print(hashlib.sha256(b'a' + bytes(range(16))).hexdigest())"
    // The tail is not the bearer: its CR and 0xff are neither refused nor hashed.
    let mut bearer: [u8; MAX_BEARER_LEN] = [0xff; MAX_BEARER_LEN];
    bearer[0] = 0x61;
    bearer[1] = 0x0d;
    constrain_bearer(bearer, 1);
    let expected: [u8; 32] = [
        0xa6, 0x7c, 0x72, 0x8b, 0x8e, 0x81, 0xd6, 0x43, 0xdb, 0x8f, 0x83, 0x5a, 0x69, 0xc2, 0x85,
        0xc4, 0x39, 0x22, 0x4e, 0x93, 0x7b, 0x37, 0xd3, 0x20, 0x08, 0xf5, 0x76, 0x9b, 0x4f, 0x1a,
        0xac, 0x66,
    ];
    assert(hash_commit(bearer, 1, blinder(0)) == expected);
}

#[test(should_fail_with = "bearer too long")]
fn a_length_past_the_buffer_is_refused() {
    let bearer: [u8; MAX_BEARER_LEN] = [0x61; MAX_BEARER_LEN];
    constrain_bearer(bearer, MAX_BEARER_LEN + 1);
}

#[test]
fn the_shortest_and_longest_bearers_are_accepted() {
    let mut shortest: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    shortest[0] = 0x20; // the low edge of the permitted set
    constrain_bearer(shortest, 1);

    // 128 bytes, the whole buffer, at the high edge.
    let longest: [u8; MAX_BEARER_LEN] = [0x7e; MAX_BEARER_LEN];
    constrain_bearer(longest, MAX_BEARER_LEN);
}

#[test]
fn a_github_bearer_fits_the_cap() {
    // A `gho_` token is 40 bytes.
    let token: [u8; MAX_BEARER_LEN] = padded("gho_0123456789abcdefABCDEF0123456789abcd".as_bytes());
    constrain_bearer(token, 40);
}

// --- hash_commit ------------------------------------------------------------

#[test]
fn hash_commit_matches_an_independent_vector() {
    // python3 -c "import hashlib; print(hashlib.sha256(b'abcd' + b'\x42'*16).hexdigest())"
    let plaintext: [u8; 4] = [0x61, 0x62, 0x63, 0x64];
    let blinder: [u8; BLINDER_LEN] = [0x42; BLINDER_LEN];
    let expected: [u8; 32] = [
        0x00, 0x7d, 0x4d, 0x44, 0x55, 0xa6, 0x83, 0x32, 0x06, 0xac, 0x7c, 0x94, 0x59, 0xd5, 0x6b,
        0x96, 0x6d, 0x79, 0x72, 0x44, 0x47, 0x6b, 0xb3, 0xb5, 0x4e, 0xba, 0xcd, 0xef, 0x26, 0x7e,
        0xc1, 0x3d,
    ];
    assert(hash_commit(plaintext, 4, blinder) == expected);
}

#[test(should_fail_with = "committed value is empty")]
fn hash_commit_refuses_an_empty_value() {
    let plaintext: [u8; 4] = [0x61; 4];
    let _ = hash_commit(plaintext, 0, blinder(0));
}

#[test]
fn hash_commit_covers_the_shortest_and_longest_bearer() {
    // python3 -c "import hashlib; print(hashlib.sha256(b' ' + bytes(range(16))).hexdigest())"
    let mut shortest: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    shortest[0] = 0x20;
    let expected_shortest: [u8; 32] = [
        0x69, 0x32, 0x2d, 0x7a, 0x78, 0x71, 0x90, 0x8c, 0xe8, 0x91, 0x2c, 0x6f, 0x96, 0xe4, 0xa4,
        0xa3, 0x7d, 0x53, 0xdc, 0xc7, 0xd5, 0xd4, 0x3d, 0x5b, 0x5d, 0x28, 0xa1, 0x9e, 0x12, 0x73,
        0xf9, 0x48,
    ];
    assert(hash_commit(shortest, 1, blinder(0)) == expected_shortest);

    // python3 -c "import hashlib; print(hashlib.sha256(b'~'*128 + bytes(range(16))).hexdigest())"
    let longest: [u8; MAX_BEARER_LEN] = [0x7e; MAX_BEARER_LEN];
    let expected_longest: [u8; 32] = [
        0xb1, 0x04, 0xc2, 0x2e, 0xdf, 0xd0, 0xe8, 0xdc, 0x11, 0x2d, 0xd4, 0x87, 0x1a, 0xd4, 0xfc,
        0xc1, 0xcb, 0x37, 0xce, 0xc7, 0x2d, 0xd6, 0xf7, 0xa6, 0xd2, 0x56, 0x65, 0xb9, 0xfb, 0xe2,
        0x81, 0x3f,
    ];
    assert(hash_commit(longest, MAX_BEARER_LEN, blinder(0)) == expected_longest);
}

#[test]
fn independent_blinders_give_different_commitments() {
    // REQ-COMMON-44: nothing outside a proof links the two sessions.
    let bearer: [u8; MAX_BEARER_LEN] = [0x7e; MAX_BEARER_LEN];
    let other: [u8; BLINDER_LEN] = [0x42; BLINDER_LEN];
    let a = hash_commit(bearer, MAX_BEARER_LEN, blinder(0));
    let b = hash_commit(bearer, MAX_BEARER_LEN, other);
    assert(a != b);
}

// --- check_id ---------------------------------------------------------------

#[test]
fn the_bytes_past_the_id_change_nothing() {
    // A letter past the id is not checked, and the node is still
    // SHA256("libid.x.user-id" || "2244994945"), handles.json's vector.
    let mut id: [u8; table::MAX_ID_X] = padded("2244994945".as_bytes());
    id[10] = 0x61;
    id[19] = 0xff;
    check_id(id, 10, table::ID_DECIMAL_X);
    let (tag, tag_len) = tag_of(table::USER_ID_TAG_X);
    assert(
        node_halves(tag, tag_len, id, 10)
            == [0x68291869976ffad2abf3e933ec9ab262, 0x3395ff8b3b9242e655e1da3ef43d4f94],
    );
}

// --- fold_handle ------------------------------------------------------------

#[test]
fn the_bytes_past_the_handle_change_nothing() {
    // python3 -c "import hashlib; print(hashlib.sha256(b'libid.x.handle' + b'al_1').hexdigest())"
    // A quote past the handle is not checked; the folded handle is zero there.
    let mut handle: [u8; table::MAX_HANDLE_X] = padded("Al_1".as_bytes());
    handle[4] = 0x22;
    handle[38] = 0xff;
    let out = fold_handle(handle, 4);
    let expected: [u8; table::MAX_HANDLE_X] = padded("al_1".as_bytes());
    assert(out == expected);
    let (tag, tag_len) = tag_of(table::HANDLE_TAG_X);
    assert(
        node_halves(tag, tag_len, out, 4)
            == [0x7fd25f75b7b97e348f2fadca95dde204, 0x897ae05f053c911eff907d6931108b90],
    );
}

// --- Nodes ------------------------------------------------------------------

#[test]
fn fixed_node_halves_agrees_with_node_halves() {
    // The table's vectors check node_halves; oidc-google proves with fixed_node_halves.
    let sub: [u8; table::MAX_ID_GOOGLE] = padded("100000000000000000001".as_bytes());
    let (id_tag, id_tag_len) = tag_of(table::USER_ID_TAG_GOOGLE);
    assert(
        fixed_node_halves(table::USER_ID_TAG_GOOGLE, sub, 21)
            == node_halves(id_tag, id_tag_len, sub, 21),
    );
    let email: [u8; table::MAX_HANDLE_GOOGLE] = padded("fixture@example.com".as_bytes());
    let (handle_tag, handle_tag_len) = tag_of(table::HANDLE_TAG_GOOGLE);
    assert(
        fixed_node_halves(table::HANDLE_TAG_GOOGLE, email, 19)
            == node_halves(handle_tag, handle_tag_len, email, 19),
    );
}

// --- Tags -------------------------------------------------------------------

#[test]
fn a_packed_tag_is_its_bytes_from_the_top() {
    // python3 -c "print(int.from_bytes(b'libid.x.handle'.ljust(31, b'\0'), 'big'))"
    let packed: Field = 191546819536254810227069963542963682822352149726751247095476095263271026688;
    let (tag, _) = tag_of(table::HANDLE_TAG_X);
    let bytes: [u8; MAX_TAG_LEN] = packed.to_be_bytes();
    assert(bytes == tag);
}

#[test(should_fail_with = "tag is empty")]
fn an_empty_tag_is_refused() {
    // An untagged node, SHA256(value), would be any platform's.
    let id: [u8; table::MAX_ID_X] = padded("2244994945".as_bytes());
    let _ = node_halves([0; MAX_TAG_LEN], 0, id, 10);
}

#[test(should_fail_with = "tag byte past its length")]
fn a_tag_with_bytes_past_its_length_is_refused() {
    // "libid.x.handle" with a 13-byte length: the Field and length disagree.
    let (tag, tag_len) = tag_of(table::HANDLE_TAG_X);
    let handle: [u8; table::MAX_HANDLE_X] = padded("al_1".as_bytes());
    let _ = node_halves(tag, tag_len - 1, handle, 4);
}

// --- The table's buffers ----------------------------------------------------

#[test]
fn bearer_link_s_buffers_are_the_table_s() {
    assert(table::MAX_HANDLE_X == MAX_HANDLE_BEARER_LINK);
    assert(table::MAX_HANDLE_GITHUB == MAX_HANDLE_BEARER_LINK);
    assert(table::MAX_ID_X == MAX_ID_BEARER_LINK);
    assert(table::MAX_ID_GITHUB == MAX_ID_BEARER_LINK);
    assert(table::ID_DECIMAL_X & table::ID_DECIMAL_GITHUB);
}

// Tests of lib.nr beside the generated vector table. Every expected hash
// comes from an independent Python computation (hashlib over the bytes
// written out in the comment), not from this library.

use crate::{
    BLINDER_LEN, check_id, constrain_bearer, hash_commit, MAX_BEARER_LEN, normalize_handle, table,
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
    // REQ-COMMON-37: the identity session sends this range inside a header,
    // so a CR would smuggle a second header line into it.
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

#[test(should_fail_with = "bearer tail must be zero-padded")]
fn a_dirty_tail_is_refused() {
    // The commitment hashes only `bearer_len` bytes; the zero tail makes the
    // padded witness canonical.
    let mut bearer: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    bearer[0] = 0x61;
    bearer[5] = 0x62;
    constrain_bearer(bearer, 1);
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
    assert(hash_commit::<4, 20>(plaintext, 4, blinder) == expected);
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
    assert(
        hash_commit::<MAX_BEARER_LEN, MAX_BEARER_LEN + BLINDER_LEN>(shortest, 1, blinder(0))
            == expected_shortest,
    );

    // python3 -c "import hashlib; print(hashlib.sha256(b'~'*128 + bytes(range(16))).hexdigest())"
    let longest: [u8; MAX_BEARER_LEN] = [0x7e; MAX_BEARER_LEN];
    let expected_longest: [u8; 32] = [
        0xb1, 0x04, 0xc2, 0x2e, 0xdf, 0xd0, 0xe8, 0xdc, 0x11, 0x2d, 0xd4, 0x87, 0x1a, 0xd4, 0xfc,
        0xc1, 0xcb, 0x37, 0xce, 0xc7, 0x2d, 0xd6, 0xf7, 0xa6, 0xd2, 0x56, 0x65, 0xb9, 0xfb, 0xe2,
        0x81, 0x3f,
    ];
    assert(
        hash_commit::<MAX_BEARER_LEN, MAX_BEARER_LEN + BLINDER_LEN>(
            longest,
            MAX_BEARER_LEN,
            blinder(0),
        )
            == expected_longest,
    );
}

#[test]
fn independent_blinders_give_different_commitments() {
    // The same bearer commits to two values, so nothing outside a proof links
    // the two sessions (REQ-COMMON-44).
    let bearer: [u8; MAX_BEARER_LEN] = [0x7e; MAX_BEARER_LEN];
    let other: [u8; BLINDER_LEN] = [0x42; BLINDER_LEN];
    let a = hash_commit::<MAX_BEARER_LEN, MAX_BEARER_LEN + BLINDER_LEN>(
        bearer,
        MAX_BEARER_LEN,
        blinder(0),
    );
    let b =
        hash_commit::<MAX_BEARER_LEN, MAX_BEARER_LEN + BLINDER_LEN>(bearer, MAX_BEARER_LEN, other);
    assert(a != b);
}

// --- check_id ---------------------------------------------------------------

#[test(should_fail_with = "id tail must be zero-padded")]
fn bytes_past_the_id_are_refused() {
    // The commitment and the node hash only `len` bytes; the zero tail makes
    // the padded witness canonical.
    let mut id: [u8; table::MAX_ID_X] = padded("2244994945".as_bytes());
    id[11] = 0x31;
    check_id(id, 10, table::ID_RULES_X);
}

// --- normalize_handle -------------------------------------------------------

#[test(should_fail_with = "handle tail must be zero-padded")]
fn bytes_past_the_handle_are_refused() {
    let mut handle: [u8; table::MAX_HANDLE_X] = padded("Al_1".as_bytes());
    handle[5] = 0x61;
    let _ = normalize_handle(handle, 4, table::HANDLE_RULES_X);
}

// --- The table's buffers ----------------------------------------------------

#[test]
fn each_platform_s_buffers_are_its_rules_lengths() {
    // table.nr states each length twice, as a buffer size and in the rules;
    // the circuits size their inputs by the first and check by the second.
    assert(table::MAX_HANDLE_X == table::HANDLE_RULES_X.max_len);
    assert(table::MAX_ID_X == table::ID_RULES_X.max_len);
    assert(table::MAX_HANDLE_GITHUB == table::HANDLE_RULES_GITHUB.max_len);
    assert(table::MAX_ID_GITHUB == table::ID_RULES_GITHUB.max_len);
    assert(table::MAX_HANDLE_GOOGLE == table::HANDLE_RULES_GOOGLE.max_len);
    assert(table::MAX_ID_GOOGLE == table::ID_RULES_GOOGLE.max_len);
}

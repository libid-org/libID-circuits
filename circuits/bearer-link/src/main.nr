// libID bearer-link circuit -- X and GitHub.
//
// The ceremony notarizes two TLS sessions: a token session (X
// `/2/oauth2/token`, GitHub's token exchange) and an identity session (X
// `/2/users/me`, GitHub `/user`). Each session commits the same OAuth bearer
// behind its OWN blinder, so the two commitment values differ and nothing on
// chain can tell they open to one credential.
//
// This circuit proves exactly that and nothing else: one hidden bearer opens
// both commitments (REQ-PLAT-32 for X, REQ-PLAT-52 for GitHub).
//
// Everything else the ceremony needs is checked where it can be seen. The
// Platform Verifier binds the Authorization Digest by recomputing the PKCE
// verifier, and reads the client identifier, evidence time, method, path and
// identity fields out of revealed attestation bytes. A fact that can be
// checked in the open does not belong in a proof, so the circuit carries no
// copy of any of them (REQ-PLAT-32B, REQ-PLAT-52A).
//
// X and GitHub state the same relation, so one circuit serves both. The
// Verifier Governance Process registers it separately per profile, which is
// what REQ-PLAT-01A asks for -- an exact artifact per profile, not a
// different one.

use sha256::sha256_var;

/// Blinder width of a tlsn hash commitment. The notary secret-shares this
/// value and appends it to the committed range before SHA-256.
global BLINDER_LEN: u32 = 16;

/// Bearer hard cap.
///
/// REQ-PLAT-30 and REQ-PLAT-36 permit up to 4096 bytes. This circuit pins
/// 128, which is what the deployed X circuit has always enforced and what
/// live X ceremonies produce; GitHub `gho_` tokens are 40 bytes. The bound is
/// the circuit's whole cost driver -- measured 42,008 gates here against
/// 690,362 at 4096 -- so it is set to the smallest value the platforms are
/// known to fit rather than to the specification ceiling. Raising it is one
/// constant plus a verifier regeneration.
global MAX_BEARER_LEN: u32 = 128;

/// `MAX_BEARER_LEN + BLINDER_LEN`, spelled out because Noir array types
/// cannot express the sum.
global COMMIT_INPUT_LEN: u32 = 144;

/// Verify a tlsn hash commitment: assert
/// `SHA256(plaintext[0..plaintext_len] || blinder) == expected`.
///
/// Generic over `MAX_PLAIN` and `TOTAL` (the caller's
/// `MAX_PLAIN + BLINDER_LEN`). The first assertion catches a wrong `TOTAL`
/// when the witness is solved rather than silently hashing padding.
fn verify_hash_commit<let MAX_PLAIN: u32, let TOTAL: u32>(
    plaintext_padded: [u8; MAX_PLAIN],
    plaintext_len: u32,
    blinder: [u8; BLINDER_LEN],
    expected: [u8; 32],
) {
    assert(TOTAL == MAX_PLAIN + BLINDER_LEN, "TOTAL must equal MAX_PLAIN + BLINDER_LEN");

    let mut input: [u8; TOTAL] = [0; TOTAL];
    for i in 0..MAX_PLAIN {
        if i < plaintext_len {
            input[i] = plaintext_padded[i];
        }
    }
    for i in 0..BLINDER_LEN {
        input[plaintext_len + i] = blinder[i];
    }
    let computed = sha256_var(input, plaintext_len + BLINDER_LEN);
    assert(computed == expected, "hash commit mismatch");
}

/// Constrain the opened bearer range: nonempty, printable ASCII, zero-padded
/// tail (REQ-PLAT-30, REQ-PLAT-36, REQ-COMMON-20).
///
/// The permitted set `0x20`-`0x7e` excludes carriage return and line feed, so
/// REQ-COMMON-37 holds by construction -- the identity session sends this range
/// inside an HTTP header, where a CRLF would carry a second header with it.
///
/// The specification says nonempty and no more. The deployed circuit also
/// demanded 22 bytes, which is a bound no requirement states; a stricter
/// circuit rejects evidence the chain would accept, so it is not carried over.
fn constrain_bearer(bearer: [u8; MAX_BEARER_LEN], bearer_len: u32) {
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

fn main(
    // --- Private ---
    bearer: [u8; MAX_BEARER_LEN],
    bearer_len: u32,
    blinder_token: [u8; BLINDER_LEN],
    blinder_identity: [u8; BLINDER_LEN],
    // --- Public ---
    // Matched by the Platform Verifier against the verified token (X) or
    // token-exchange (GitHub) attestation.
    token_commitment: pub [u8; 32],
    // Matched by the Platform Verifier against the verified `/2/users/me` (X)
    // or `/user` (GitHub) attestation.
    identity_commitment: pub [u8; 32],
) {
    constrain_bearer(bearer, bearer_len);

    // One bearer, two independent blinders, two commitments. REQ-COMMON-44
    // draws the blinders per session, so these two values differ even though
    // the credential is the same -- which is the reason this circuit exists.
    verify_hash_commit::<MAX_BEARER_LEN, COMMIT_INPUT_LEN>(
        bearer,
        bearer_len,
        blinder_token,
        token_commitment,
    );
    verify_hash_commit::<MAX_BEARER_LEN, COMMIT_INPUT_LEN>(
        bearer,
        bearer_len,
        blinder_identity,
        identity_commitment,
    );
}

// --- Tests ----------------------------------------------------------------
//
// Every expected hash below comes from an independent Python computation, not
// from this circuit, so a wrong preimage layout is caught rather than mirrored.

/// A 100-byte bearer, the shape the on-chain X fixtures model.
fn sample_bearer() -> ([u8; MAX_BEARER_LEN], u32) {
    let mut bearer: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    for i in 0..4 {
        bearer[i] = 0x41; // 'A'
    }
    for i in 4..100 {
        bearer[i] = 0x78; // 'x'
    }
    (bearer, 100)
}

fn blinder_token() -> [u8; BLINDER_LEN] {
    let mut b: [u8; BLINDER_LEN] = [0; BLINDER_LEN];
    for i in 0..BLINDER_LEN {
        b[i] = i as u8;
    }
    b
}

fn blinder_identity() -> [u8; BLINDER_LEN] {
    let mut b: [u8; BLINDER_LEN] = [0; BLINDER_LEN];
    for i in 0..BLINDER_LEN {
        b[i] = (i + 16) as u8;
    }
    b
}

// python3 -c "import hashlib; print(hashlib.sha256(b'AAAA'+b'x'*96+bytes(range(16))).hexdigest())"
fn token_commitment() -> [u8; 32] {
    [
        0x70, 0x5e, 0x0e, 0x2b, 0x21, 0x19, 0x19, 0x6a, 0xea, 0x72, 0x72, 0xae, 0xba, 0x3b, 0xea,
        0xae, 0x86, 0x34, 0xc7, 0xd3, 0x8e, 0x62, 0x47, 0x04, 0x56, 0x44, 0xe8, 0xff, 0xa6, 0x8f,
        0x99, 0x1f,
    ]
}

// python3 -c "import hashlib; print(hashlib.sha256(b'AAAA'+b'x'*96+bytes(range(16,32))).hexdigest())"
fn identity_commitment() -> [u8; 32] {
    [
        0xa1, 0x3d, 0xbd, 0xf1, 0xde, 0xf6, 0xd4, 0xb7, 0xa5, 0xe5, 0xa3, 0x49, 0xf6, 0x13, 0x7f,
        0xb8, 0xa8, 0x1d, 0x8d, 0x48, 0xdc, 0xb1, 0xc4, 0x66, 0x3e, 0x5e, 0x8d, 0x28, 0x2d, 0x72,
        0xf7, 0x9f,
    ]
}

#[test]
fn one_bearer_opens_both_commitments() {
    let (bearer, len) = sample_bearer();
    main(
        bearer,
        len,
        blinder_token(),
        blinder_identity(),
        token_commitment(),
        identity_commitment(),
    );
}

#[test]
fn independent_blinders_give_different_commitments() {
    // The whole premise: the same credential commits to two different values,
    // so nothing outside a proof can link the two sessions (REQ-COMMON-44).
    let t = token_commitment();
    let i = identity_commitment();
    let mut differs = false;
    for k in 0..32 {
        if t[k] != i[k] {
            differs = true;
        }
    }
    assert(differs, "blinders did not separate the commitments");
}

#[test(should_fail_with = "hash commit mismatch")]
fn rejects_a_wrong_token_commitment() {
    let (bearer, len) = sample_bearer();
    main(
        bearer,
        len,
        blinder_token(),
        blinder_identity(),
        [0xff; 32],
        identity_commitment(),
    );
}

#[test(should_fail_with = "hash commit mismatch")]
fn rejects_a_wrong_identity_commitment() {
    let (bearer, len) = sample_bearer();
    main(
        bearer,
        len,
        blinder_token(),
        blinder_identity(),
        token_commitment(),
        [0xff; 32],
    );
}

#[test(should_fail_with = "hash commit mismatch")]
fn rejects_a_second_bearer_for_the_identity_session() {
    // A prover holding two different credentials cannot link them: the single
    // private `bearer` has to open both commitments.
    let (mut bearer, len) = sample_bearer();
    bearer[0] = 0x42; // 'B' -- one byte away from the committed value
    main(
        bearer,
        len,
        blinder_token(),
        blinder_identity(),
        token_commitment(),
        identity_commitment(),
    );
}

#[test(should_fail_with = "bearer must not be empty")]
fn rejects_an_empty_bearer() {
    let bearer: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    constrain_bearer(bearer, 0);
}

#[test(should_fail_with = "bearer byte below printable ASCII")]
fn rejects_a_carriage_return() {
    // REQ-COMMON-37: the identity session sends this range inside a header,
    // so a CR would smuggle a second header line into it.
    let mut bearer: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    bearer[0] = 0x61;
    bearer[1] = 0x0d;
    bearer[2] = 0x61;
    constrain_bearer(bearer, 3);
}

#[test(should_fail_with = "bearer byte below printable ASCII")]
fn rejects_a_line_feed() {
    let mut bearer: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    bearer[0] = 0x61;
    bearer[1] = 0x0a;
    bearer[2] = 0x61;
    constrain_bearer(bearer, 3);
}

#[test(should_fail_with = "bearer byte above printable ASCII")]
fn rejects_a_byte_above_ascii() {
    let mut bearer: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    bearer[0] = 0xc3;
    constrain_bearer(bearer, 1);
}

#[test(should_fail_with = "bearer tail must be zero-padded")]
fn rejects_a_dirty_tail() {
    // Padding a prover controls is padding a prover can hide bytes in.
    let mut bearer: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    bearer[0] = 0x61;
    bearer[5] = 0x62;
    constrain_bearer(bearer, 1);
}

#[test]
fn accepts_the_shortest_and_longest_bearers() {
    let mut shortest: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    shortest[0] = 0x20; // the low edge of the permitted set
    constrain_bearer(shortest, 1);

    let mut longest: [u8; MAX_BEARER_LEN] = [0; MAX_BEARER_LEN];
    for i in 0..MAX_BEARER_LEN {
        longest[i] = 0x7e; // the high edge
    }
    constrain_bearer(longest, MAX_BEARER_LEN);
}

#[test]
fn verify_hash_commit_matches_an_independent_vector() {
    // python3 -c "import hashlib; print(hashlib.sha256(b'abcd' + b'\x42'*16).hexdigest())"
    let plaintext: [u8; 4] = [0x61, 0x62, 0x63, 0x64];
    let blinder: [u8; BLINDER_LEN] = [0x42; BLINDER_LEN];
    let expected: [u8; 32] = [
        0x00, 0x7d, 0x4d, 0x44, 0x55, 0xa6, 0x83, 0x32, 0x06, 0xac, 0x7c, 0x94, 0x59, 0xd5, 0x6b,
        0x96, 0x6d, 0x79, 0x72, 0x44, 0x47, 0x6b, 0xb3, 0xb5, 0x4e, 0xba, 0xcd, 0xef, 0x26, 0x7e,
        0xc1, 0x3d,
    ];
    verify_hash_commit::<4, 20>(plaintext, 4, blinder, expected);
}

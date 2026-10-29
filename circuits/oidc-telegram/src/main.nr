use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use libid_identity::{
    check_id,
    fixed_node_halves,
    fold_handle,
    halves,
    table::{
        HANDLE_TAG_TELEGRAM, ID_DECIMAL_TELEGRAM, MAX_HANDLE_TELEGRAM, MAX_ID_TELEGRAM,
        USER_ID_TAG_TELEGRAM,
    },
};
use noir_base64::BASE64_URL_ENCODER;
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use sha256::sha256_var;

global SIGNING_INPUT_MAX: u32 = 2624;
global AUDIENCE_MAX: u32 = 20;
global HANDLE_MIN: u32 = 5;
global MAX_IAT_DIGITS: u32 = 12;
global DIGEST_LEN: u32 = 32;
global NONCE_LEN: u32 = 43; // BASE64URL_NOPAD(32 bytes)
global NUM_LIMBS: u32 = 18;
global MOD_BITS: u32 = 2048;

// Each claim is read from a window of whole 3-byte payload groups: its
// pattern and longest value, closing bytes, and 2 bytes of alignment.
global ISS_WINDOW: u32 = 39;
global AUD_WINDOW: u32 = 33;
global IAT_WINDOW: u32 = 21;
global ID_WINDOW: u32 = 30;
global USERNAME_WINDOW: u32 = 60;
global NONCE_WINDOW: u32 = 57;

global ISS_PATTERN: [u8; 36] = "\"iss\":\"https:\\/\\/oauth.telegram.org\"".as_bytes();
global AUD_PREFIX: [u8; 7] = "\"aud\":\"".as_bytes();
global IAT_PREFIX: [u8; 6] = "\"iat\":".as_bytes();
global ID_PREFIX: [u8; 6] = "\"id\":\"".as_bytes();
global USERNAME_PREFIX: [u8; 22] = "\"preferred_username\":\"".as_bytes();
global NONCE_PREFIX: [u8; 9] = "\"nonce\":\"".as_bytes();

// Binds `window` to the signed base64url of the payload groups from the one
// holding byte `offset`. Returns `offset`'s index in the window and how many
// leading window bytes the signed characters fix.
fn bind_window<let W: u32>(
    signing_input: [u8; SIGNING_INPUT_MAX],
    payload_start: u32,
    payload_b64_len: u32,
    window: [u8; W],
    offset: u32,
) -> (u32, u32) {
    let group = offset / 3;
    let start = 4 * group;
    assert(start + 4 <= payload_b64_len, "window starts outside the payload");
    let encoded = BASE64_URL_ENCODER::encode(window);
    let rest = payload_b64_len - start;
    let signed = if rest < encoded.len() {
        rest
    } else {
        encoded.len()
    };
    for i in 0..encoded.len() {
        if i < signed {
            assert(
                signing_input[payload_start + start + i] == encoded[i],
                "window does not match the signed input",
            );
        }
    }
    (offset - 3 * group, signed * 3 / 4)
}

fn match_at<let W: u32, let P: u32>(w: [u8; W], at: u32, pattern: [u8; P]) -> u32 {
    for i in 0..P {
        assert(w[at + i] == pattern[i], "claim pattern mismatch");
    }
    at + P
}

// The claim ends at `end` with ',' or '}', inside the signed bytes.
fn close<let W: u32>(w: [u8; W], end: u32, bound: u32) {
    assert((w[end] == 44) | (w[end] == 125), "claim not followed by ',' or '}'");
    assert(end < bound, "claim outside the signed bytes");
}

// The `len`-byte value of `<prefix><value>"` at `at`, then closed.
fn string_claim<let W: u32, let P: u32, let M: u32>(
    w: [u8; W],
    at: u32,
    prefix: [u8; P],
    len: u32,
    bound: u32,
) -> [u8; M] {
    let start = match_at(w, at, prefix);
    assert(len <= M, "claim longer than its buffer");
    let mut value: [u8; M] = [0; M];
    for i in 0..M {
        if i < len {
            value[i] = w[start + i];
        }
    }
    assert(w[start + len] == 34, "claim value not closed");
    close(w, start + len + 1, bound);
    value
}

fn main(
    signing_input: [u8; SIGNING_INPUT_MAX],
    signing_input_len: u32,
    header_b64_len: u32,
    iss_window: [u8; ISS_WINDOW],
    iss_offset: u32,
    aud_window: [u8; AUD_WINDOW],
    aud_offset: u32,
    audience_len: u32,
    iat_window: [u8; IAT_WINDOW],
    iat_offset: u32,
    iat_len: u32,
    id_window: [u8; ID_WINDOW],
    id_offset: u32,
    id_len: u32,
    username_window: [u8; USERNAME_WINDOW],
    username_offset: u32,
    username_len: u32,
    nonce_window: [u8; NONCE_WINDOW],
    nonce_offset: u32,
    signature: [u128; NUM_LIMBS],
    redc: [u128; NUM_LIMBS],
    authorization_digest: pub [u8; DIGEST_LEN],
    // SHA-256(aud) as halves.
    audience_hash: pub [Field; 2],
    // SHA-256(`libid.telegram.user-id` || id) as halves.
    id_node: pub [Field; 2],
    // SHA-256(`libid.telegram.handle` || folded username) as halves.
    handle_node: pub [Field; 2],
    iat: pub u64,
    modulus: pub [u128; NUM_LIMBS],
) {
    assert(signing_input_len <= SIGNING_INPUT_MAX, "signing input longer than its buffer");
    let hash = sha256_var(signing_input, signing_input_len);
    let params: BigNumParams<NUM_LIMBS, MOD_BITS> = BigNumParams::new(false, modulus, redc);
    let sig: RuntimeBigNum<NUM_LIMBS, MOD_BITS> = RuntimeBigNum { params, limbs: signature };
    assert(verify_sha256_pkcs1v15(hash, sig, 65537));

    // The payload follows the only '.'; base64url has none.
    assert(header_b64_len + 1 < signing_input_len);
    assert(signing_input[header_b64_len] == 46);
    let p0 = header_b64_len + 1;
    let b64_len = signing_input_len - p0;
    assert(b64_len % 4 != 1, "malformed base64url length");

    let (at, bound) = bind_window(signing_input, p0, b64_len, iss_window, iss_offset);
    close(iss_window, match_at(iss_window, at, ISS_PATTERN), bound);

    let (at, bound) = bind_window(signing_input, p0, b64_len, aud_window, aud_offset);
    assert(audience_len != 0, "aud is empty");
    let audience: [u8; AUDIENCE_MAX] =
        string_claim(aud_window, at, AUD_PREFIX, audience_len, bound);
    for i in 0..AUDIENCE_MAX {
        assert((audience[i] != 34) & (audience[i] != 92), "aud byte not allowed");
    }
    assert(halves(sha256_var(audience, audience_len)) == audience_hash, "audience mismatch");

    let (at, bound) = bind_window(signing_input, p0, b64_len, iat_window, iat_offset);
    let start = match_at(iat_window, at, IAT_PREFIX);
    assert((iat_len != 0) & (iat_len <= MAX_IAT_DIGITS), "iat length");
    assert((iat_len == 1) | (iat_window[start] != 48), "leading zero in iat");
    let mut parsed: u64 = 0;
    for i in 0..MAX_IAT_DIGITS {
        if i < iat_len {
            let digit = iat_window[start + i];
            assert((digit >= 48) & (digit <= 57), "iat byte not a digit");
            parsed = parsed * 10 + (digit - 48) as u64;
        }
    }
    close(iat_window, start + iat_len, bound);
    assert(parsed == iat, "iat mismatch");

    let (at, bound) = bind_window(signing_input, p0, b64_len, id_window, id_offset);
    let id: [u8; MAX_ID_TELEGRAM] = string_claim(id_window, at, ID_PREFIX, id_len, bound);
    check_id(id, id_len, ID_DECIMAL_TELEGRAM);
    assert((id_len == 1) | (id[0] != 48), "leading zero in id");
    assert(fixed_node_halves(USER_ID_TAG_TELEGRAM, id, id_len) == id_node, "id node mismatch");

    let (at, bound) = bind_window(signing_input, p0, b64_len, username_window, username_offset);
    let username: [u8; MAX_HANDLE_TELEGRAM] =
        string_claim(username_window, at, USERNAME_PREFIX, username_len, bound);
    assert(username_len >= HANDLE_MIN, "username shorter than 5");
    for i in 0..MAX_HANDLE_TELEGRAM {
        if i < username_len {
            assert(is_username_byte(username[i]), "username byte not allowed");
        }
    }
    let folded = fold_handle(username, username_len);
    assert(
        fixed_node_halves(HANDLE_TAG_TELEGRAM, folded, username_len) == handle_node,
        "handle node mismatch",
    );

    let (at, bound) = bind_window(signing_input, p0, b64_len, nonce_window, nonce_offset);
    let nonce: [u8; NONCE_LEN] = string_claim(nonce_window, at, NONCE_PREFIX, NONCE_LEN, bound);
    let expected: [u8; NONCE_LEN] = BASE64_URL_ENCODER::encode(authorization_digest);
    assert(nonce == expected, "nonce does not encode the authorization digest");
}

// [A-Za-z0-9_]
fn is_username_byte(b: u8) -> bool {
    ((b >= 48) & (b <= 57)) | ((b >= 65) & (b <= 90)) | ((b >= 97) & (b <= 122)) | (b == 95)
}

// --- Tests ----------------------------------------------------------------

#[test]
fn each_window_holds_its_longest_claim_at_any_alignment() {
    let widths = [ISS_WINDOW, AUD_WINDOW, IAT_WINDOW, ID_WINDOW, USERNAME_WINDOW, NONCE_WINDOW];
    let needs = [
        36 + 1,
        7 + AUDIENCE_MAX + 2,
        6 + MAX_IAT_DIGITS + 1,
        6 + MAX_ID_TELEGRAM + 2,
        22 + MAX_HANDLE_TELEGRAM + 2,
        9 + NONCE_LEN + 2,
    ];
    for i in 0..6 {
        assert((widths[i] % 3 == 0) & (widths[i] >= needs[i] + 2));
    }
}

// `x.` then base64url(`{"a":1}`): the last group is a 2-character tail.
global TINY: [u8; 12] = "x.eyJhIjoxfQ".as_bytes();

fn tiny_input() -> [u8; SIGNING_INPUT_MAX] {
    let mut si: [u8; SIGNING_INPUT_MAX] = [0; SIGNING_INPUT_MAX];
    for i in 0..12 {
        si[i] = TINY[i];
    }
    si
}

#[test]
fn a_window_past_the_payload_fixes_only_the_signed_bytes() {
    let window: [u8; 9] = "{\"a\":1}\0\0".as_bytes();
    let (at, bound) = bind_window(tiny_input(), 2, 10, window, 1);
    assert((at == 1) & (bound == 7));
    close(window, 6, bound);
}

#[test(should_fail_with = "claim outside the signed bytes")]
fn a_claim_closed_past_the_signed_bytes_is_refused() {
    let window: [u8; 9] = "{\"a\":1}\0}".as_bytes();
    let (_, bound) = bind_window(tiny_input(), 2, 10, window, 0);
    close(window, 8, bound);
}

#[test(should_fail_with = "window does not match the signed input")]
fn a_window_other_than_the_signed_bytes_is_refused() {
    let window: [u8; 9] = "{\"a\":2}\0\0".as_bytes();
    let _ = bind_window(tiny_input(), 2, 10, window, 0);
}

#[test]
fn every_username_byte_outside_the_alphabet_is_refused() {
    let mut allowed = 0;
    for b in 0..256 {
        if is_username_byte(b as u8) {
            allowed += 1;
        }
    }
    assert((allowed == 63) & !is_username_byte(45) & is_username_byte(95));
}

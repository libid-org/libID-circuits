use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use noir_base64::BASE64_URL_ENCODER;
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use sha256::sha256_var;

// Sizes are fixed at compile time. Variable-length JWTs are zero-padded by the prover.
global SIGNING_INPUT_MAX: u32 = 1280;
global PAYLOAD_JSON_MAX: u32 = 768; // must be divisible by 3 (encoder output size formula).
global PAYLOAD_B64_MAX: u32 = 1024; // = 4 * (PAYLOAD_JSON_MAX / 3) when divisible by 3
global EMAIL_MAX: u32 = 62; // 2 packed Fields x 31 bytes
global DIGEST_LEN: u32 = 32; // Authorization Digest, common REQ-COMMON-01
global NONCE_B64_LEN: u32 = 43; // BASE64URL_NOPAD(32 bytes)
global SUB_MAX: u32 = 31; // 1 packed Field x 31 bytes (Google `sub` is ~21 digits)
global AUDIENCE_MAX: u32 = 128;
global NUM_LIMBS: u32 = 18;
global MOD_BITS: u32 = 2048;
global EMAIL_PREFIX_LEN: u32 = 9; // length of `"email":"`
global NONCE_PREFIX_LEN: u32 = 9; // length of `"nonce":"`
global SUB_PREFIX_LEN: u32 = 7; // length of `"sub":"`
global EMAIL_VERIFIED_LEN: u32 = 21; // length of `"email_verified":true`
global EXP_PREFIX_LEN: u32 = 6; // length of `"exp":`
global MAX_EXP_DIGITS: u32 = 12; // unix timestamp fits in 10 digits until year 2286
global ISS_PATTERN_LEN: u32 = 35; // length of `"iss":"https://accounts.google.com"`
global AUD_PREFIX_LEN: u32 = 7; // length of `"aud":"`

// Encode the 32-byte Authorization Digest the way REQ-PLAT-10 requires the
// runtime to place it in the OIDC `nonce`: base64url, no padding, 43 chars.
//
// The circuit encodes rather than decodes. Both bind the same pair, and
// encoding is the cheaper direction: 32 bytes are 10 whole three-byte groups
// plus a two-byte tail, so `noir_base64`'s length formula fixes the output at
// 43 characters with no padding branch to constrain.
fn b64url_encode_digest(d: [u8; DIGEST_LEN]) -> [u8; NONCE_B64_LEN] {
    BASE64_URL_ENCODER::encode(d)
}

// Length of base64url-encoded output (no padding) for `input_len` bytes of input.
fn b64_encoded_len(input_len: u32) -> u32 {
    let chunks_full = input_len / 3;
    let tail = input_len - chunks_full * 3;
    let extra = if tail == 0 { 0 } else { tail + 1 };
    chunks_full * 4 + extra
}

// REQ-COMMON-19 / REQ-COMMON-19D: every claim match must end at a JSON
// structural byte -- `,` (44) or `}` (125). A claim-shaped substring sitting
// inside a longer signed string value is followed by ordinary string
// content, never a bare structural byte, so this is the assertion that
// rejects such a partial match; without it, JSON escaping of attacker-typed
// content is the only thing preventing one.
fn assert_structural(byte: u8) {
    assert((byte == 44) | (byte == 125), "claim not followed by ',' or '}'");
}

// REQ-COMMON-19D: a canonical decimal (`0|[1-9][0-9]*`) starts with '0'
// only when it IS the single digit `0`. "0123" passes a bare digit-run
// check and parses to the same u64 as "123" -- a second signed encoding of
// one exp value, which the spec explicitly rejects.
fn assert_no_leading_zero(first_digit: u8, len: u32) {
    assert((len == 1) | (first_digit != 48), "leading zero in exp");
}

fn main(
    // ---- private inputs ----
    signing_input: [u8; SIGNING_INPUT_MAX],
    signing_input_len: u32,
    header_b64_len: u32,
    payload_json: [u8; PAYLOAD_JSON_MAX],
    payload_json_len: u32,
    email_offset: u32,
    nonce_offset: u32,
    sub_offset: u32,
    email_verified_offset: u32,
    exp_offset: u32,
    exp_len: u32,
    iss_offset: u32,
    aud_offset: u32,
    email_bytes: [u8; EMAIL_MAX],
    email_len: u32,
    sub_bytes: [u8; SUB_MAX],
    sub_len: u32,
    audience_bytes: [u8; AUDIENCE_MAX],
    audience_len: u32,
    signature: [u128; NUM_LIMBS],
    redc: [u128; NUM_LIMBS],
    // ---- public inputs ----
    // Exactly the public inputs REQ-PLAT-16B fixes, in the order it lists.
    // The Authorization Digest binds the operation, chain and verifier
    // version, which is why no chain id or registry address appears here.
    authorization_digest: pub [u8; DIGEST_LEN],
    // Full SHA-256(client_id), packed as two big-endian 16-byte Fields.
    audience_hash: pub [Field; 2],
    sub_packed: pub [Field; 1],
    email_packed: pub [Field; 2],
    exp: pub u64,
    modulus: pub [u128; NUM_LIMBS],
) {
    // 1. Hash the JWT signing input (header_b64 . payload_b64).
    let hash: [u8; 32] = sha256_var(signing_input, signing_input_len);

    // 2. Verify Google's RSA-2048 PKCS#1 v1.5 SHA-256 signature.
    let params: BigNumParams<NUM_LIMBS, MOD_BITS> = BigNumParams::new(false, modulus, redc);
    let sig: RuntimeBigNum<NUM_LIMBS, MOD_BITS> = RuntimeBigNum { params, limbs: signature };
    assert(verify_sha256_pkcs1v15(hash, sig, 65537));

    // 3. BIND payload_json to signing_input by re-encoding it to base64url
    //    using the official noir_base64 library, then asserting the bytes
    //    after the dot match.
    let computed_b64: [u8; PAYLOAD_B64_MAX] = BASE64_URL_ENCODER::encode(payload_json);
    let payload_b64_len = b64_encoded_len(payload_json_len);

    assert(signing_input_len == header_b64_len + 1 + payload_b64_len);
    assert(signing_input[header_b64_len] == 46); // '.'
    for i in 0..PAYLOAD_B64_MAX {
        if i < payload_b64_len {
            assert(signing_input[header_b64_len + 1 + i] == computed_b64[i]);
        }
    }

    // 4. Email substring at email_offset in payload_json.
    //    Pattern bytes: `"email":"` = [34, 101, 109, 97, 105, 108, 34, 58, 34]
    let email_prefix: [u8; 9] = [34, 101, 109, 97, 105, 108, 34, 58, 34];
    for i in 0..EMAIL_PREFIX_LEN {
        assert(payload_json[email_offset + i] == email_prefix[i]);
    }
    for i in 0..EMAIL_MAX {
        if i < email_len {
            assert(payload_json[email_offset + EMAIL_PREFIX_LEN + i] == email_bytes[i]);
            // Quote-exclusion: no interior `"` in the email body. Without
            // this a prover could pick a longer notarized range like
            // `"email":"a@b.com","name":"x` and set email_len so the
            // closing-quote check (below) lands on the NEXT value's quote,
            // smuggling `","name":"x` into the on-chain handle. The
            // contract does no character-class validation, so enforce it
            // here.
            assert(email_bytes[i] != 34);
        } else {
            // Tail past email_len is folded verbatim into the public
            // email_packed below. Unconstrained, a prover stuffs garbage
            // here and registers the handle `real_email || garbage`. Pin
            // the padding to zero so the packing is canonical.
            assert(email_bytes[i] == 0);
        }
    }
    assert(payload_json[email_offset + EMAIL_PREFIX_LEN + email_len] == 34); // closing `"`
    assert_structural(
        payload_json[email_offset + EMAIL_PREFIX_LEN + email_len + 1],
    );

    // 5. Nonce substring at nonce_offset in payload_json.
    //    Pattern bytes: `"nonce":"` = [34, 110, 111, 110, 99, 101, 34, 58, 34]
    let nonce_prefix: [u8; 9] = [34, 110, 111, 110, 99, 101, 34, 58, 34];
    for i in 0..NONCE_PREFIX_LEN {
        assert(payload_json[nonce_offset + i] == nonce_prefix[i]);
    }
    // REQ-PLAT-18: the signed nonce IS the Authorization Digest. The digest
    // is a public input and the nonce is its base64url encoding, so the two
    // are bound by re-encoding the digest and comparing byte for byte. The
    // length is fixed at 43, which leaves the prover no room to witness a
    // longer nonce and hide bytes in it.
    let expected_nonce = b64url_encode_digest(authorization_digest);
    for i in 0..NONCE_B64_LEN {
        assert(
            payload_json[nonce_offset + NONCE_PREFIX_LEN + i] == expected_nonce[i],
            "nonce does not encode the authorization digest",
        );
    }
    assert(payload_json[nonce_offset + NONCE_PREFIX_LEN + NONCE_B64_LEN] == 34); // closing `"`
    assert_structural(
        payload_json[nonce_offset + NONCE_PREFIX_LEN + NONCE_B64_LEN + 1],
    );

    // 5b. `sub` substring at sub_offset in payload_json - the immutable
    //     Google account id, revealed as a public input (mirrors email/nonce).
    //     Pattern bytes: `"sub":"` = [34, 115, 117, 98, 34, 58, 34]
    let sub_prefix: [u8; 7] = [34, 115, 117, 98, 34, 58, 34];
    for i in 0..SUB_PREFIX_LEN {
        assert(payload_json[sub_offset + i] == sub_prefix[i]);
    }
    for i in 0..SUB_MAX {
        if i < sub_len {
            assert(payload_json[sub_offset + SUB_PREFIX_LEN + i] == sub_bytes[i]);
            // Same quote-exclusion as email/nonce: no interior `"` in the sub.
            assert(sub_bytes[i] != 34);
        } else {
            // Zero the padding so sub_packed is canonical.
            assert(sub_bytes[i] == 0);
        }
    }
    assert(payload_json[sub_offset + SUB_PREFIX_LEN + sub_len] == 34); // closing `"`
    assert_structural(payload_json[sub_offset + SUB_PREFIX_LEN + sub_len + 1]);

    // 6. `email_verified`:true must be present in the payload.
    //    Pattern bytes: `"email_verified":true`
    //    [34, 101, 109, 97, 105, 108, 95, 118, 101, 114, 105, 102, 105, 101, 100, 34, 58, 116, 114, 117, 101]
    let ev_pattern: [u8; 21] = [
        34, 101, 109, 97, 105, 108, 95, 118, 101, 114, 105, 102, 105, 101, 100, 34, 58, 116, 114,
        117, 101,
    ];
    for i in 0..EMAIL_VERIFIED_LEN {
        assert(payload_json[email_verified_offset + i] == ev_pattern[i]);
    }
    assert_structural(payload_json[email_verified_offset + EMAIL_VERIFIED_LEN]);

    // 7. `exp` claim: parse digits, assert equals public `exp`.
    //    The contract is responsible for asserting `exp > block.timestamp` off-circuit.
    let exp_prefix: [u8; 6] = [34, 101, 120, 112, 34, 58]; // `"exp":`
    for i in 0..EXP_PREFIX_LEN {
        assert(payload_json[exp_offset + i] == exp_prefix[i]);
    }
    let mut parsed_exp: u64 = 0;
    for i in 0..MAX_EXP_DIGITS {
        if i < exp_len {
            let digit = payload_json[exp_offset + EXP_PREFIX_LEN + i];
            assert(digit >= 48); // '0'
            assert(digit <= 57); // '9'
            let digit_val: u64 = (digit - 48) as u64;
            parsed_exp = parsed_exp * 10 + digit_val;
        }
    }
    assert_structural(payload_json[exp_offset + EXP_PREFIX_LEN + exp_len]);
    assert_no_leading_zero(payload_json[exp_offset + EXP_PREFIX_LEN], exp_len);
    assert(parsed_exp == exp);
    assert(exp_len > 0);
    assert(exp_len <= MAX_EXP_DIGITS);

    // 8. `iss` claim hardcoded - only Google JWTs (`https://accounts.google.com`).
    //    Pattern bytes: `"iss":"https://accounts.google.com"` (35 bytes, includes
    //    both opening and closing quotes around the value).
    let iss_pattern: [u8; 35] = [
        34, 105, 115, 115, 34, 58, 34, // "iss":"
        104, 116, 116, 112, 115, 58, 47, 47, // https://
        97, 99, 99, 111, 117, 110, 116, 115, 46, // accounts.
        103, 111, 111, 103, 108, 101, 46, // google.
        99, 111, 109, 34, // com"
    ];
    for i in 0..ISS_PATTERN_LEN {
        assert(payload_json[iss_offset + i] == iss_pattern[i]);
    }
    assert_structural(payload_json[iss_offset + ISS_PATTERN_LEN]);

    // 8b. Bind the variable `aud` claim to the supplied client id.
    let aud_prefix: [u8; 7] = [34, 97, 117, 100, 34, 58, 34]; // `"aud":"`
    for i in 0..AUD_PREFIX_LEN {
        assert(payload_json[aud_offset + i] == aud_prefix[i]);
    }
    for i in 0..AUDIENCE_MAX {
        if i < audience_len {
            assert(payload_json[aud_offset + AUD_PREFIX_LEN + i] == audience_bytes[i]);
            assert(audience_bytes[i] != 34);
        } else {
            assert(audience_bytes[i] == 0);
        }
    }
    assert(payload_json[aud_offset + AUD_PREFIX_LEN + audience_len] == 34);
    assert_structural(payload_json[aud_offset + AUD_PREFIX_LEN + audience_len + 1]);

    let computed_audience_hash: [u8; 32] = sha256_var(audience_bytes, audience_len);
    let mut audience_h0: Field = 0;
    let mut audience_h1: Field = 0;
    for i in 0..16 {
        audience_h0 = audience_h0 * 256 + computed_audience_hash[i] as Field;
        audience_h1 = audience_h1 * 256 + computed_audience_hash[i + 16] as Field;
    }
    assert(audience_h0 == audience_hash[0]);
    assert(audience_h1 == audience_hash[1]);

    // 9. Offset bounds: every claimed pattern -- including its trailing
    //    structural byte (REQ-COMMON-19B: the whole match, inside the
    //    authenticated length) -- must lie inside the real payload_json, not
    //    in the zero-padded region the prover controls. payload_json_len
    //    itself is bound by the base64 length check above, so it cannot be
    //    inflated.
    assert(email_offset + EMAIL_PREFIX_LEN + email_len + 2 <= payload_json_len);
    assert(nonce_offset + NONCE_PREFIX_LEN + NONCE_B64_LEN + 2 <= payload_json_len);
    assert(sub_offset + SUB_PREFIX_LEN + sub_len + 2 <= payload_json_len);
    assert(email_verified_offset + EMAIL_VERIFIED_LEN + 1 <= payload_json_len);
    assert(exp_offset + EXP_PREFIX_LEN + exp_len + 1 <= payload_json_len);
    assert(iss_offset + ISS_PATTERN_LEN + 1 <= payload_json_len);
    assert(aud_offset + AUD_PREFIX_LEN + audience_len + 2 <= payload_json_len);
    // Defense against offset 0 + underflow / starting before JSON: realistic
    // payloads always have `{` at index 0.
    assert(email_offset >= 1);
    assert(nonce_offset >= 1);
    assert(sub_offset >= 1);
    assert(email_verified_offset >= 1);
    assert(exp_offset >= 1);
    assert(iss_offset >= 1);
    assert(aud_offset >= 1);

    // 9. Pack email_bytes (62 bytes, zero-padded past the real length) into
    //    [Field; 2], big-endian, 31 bytes per Field, and sub_bytes into one.
    //    Assert the public-input packed values match. The contract reverses
    //    this: takes the user-supplied plaintext, zero-pads to 62, packs the
    //    same way, compares.
    let mut email_f0: Field = 0;
    let mut email_f1: Field = 0;
    let mut sub_f0: Field = 0;
    for i in 0..31 {
        email_f0 = email_f0 * 256 + email_bytes[i] as Field;
        email_f1 = email_f1 * 256 + email_bytes[i + 31] as Field;
        sub_f0 = sub_f0 * 256 + sub_bytes[i] as Field;
    }
    assert(email_f0 == email_packed[0]);
    assert(email_f1 == email_packed[1]);
    assert(sub_f0 == sub_packed[0]);

    // 10. Type bounds.
    assert(signing_input_len <= SIGNING_INPUT_MAX);
    assert(payload_json_len <= PAYLOAD_JSON_MAX);
    assert(email_len <= EMAIL_MAX);
    assert(sub_len <= SUB_MAX);
    assert(audience_len > 0);
    assert(audience_len <= AUDIENCE_MAX);
}

// --- Tests ----------------------------------------------------------------

#[test]
fn nonce_encoding_matches_the_published_vector() {
    // The Authorization Digest and Google nonce published together in
    // platform-ceremonies.md section 3.1, which is itself the digest of the
    // conformance vector in ceremony-common.md section 5. Getting both from
    // the specification rather than from this circuit is what makes the test
    // a check instead of a mirror.
    let digest: [u8; DIGEST_LEN] = [
        0xb3, 0x18, 0xfb, 0x55, 0x9e, 0x16, 0xa1, 0x79, 0xb8, 0x53, 0xed, 0x28, 0x53, 0x57, 0x6c,
        0xda, 0x16, 0x03, 0x2d, 0x93, 0xb0, 0x83, 0x9b, 0xb8, 0x1a, 0x55, 0x13, 0x5d, 0x33, 0x4c,
        0x0a, 0xf5,
    ];
    // "sxj7VZ4WoXm4U-0oU1ds2hYDLZOwg5u4GlUTXTNMCvU"
    let expected: [u8; NONCE_B64_LEN] = [
        115, 120, 106, 55, 86, 90, 52, 87, 111, 88, 109, 52, 85, 45, 48, 111, 85, 49, 100, 115, 50,
        104, 89, 68, 76, 90, 79, 119, 103, 53, 117, 52, 71, 108, 85, 84, 88, 84, 78, 77, 67, 118,
        85,
    ];
    let got = b64url_encode_digest(digest);
    for i in 0..NONCE_B64_LEN {
        assert(got[i] == expected[i], "nonce encoding disagrees with the published vector");
    }
}

#[test]
fn nonce_encoding_separates_distinct_digests() {
    let a: [u8; DIGEST_LEN] = [0; DIGEST_LEN];
    let mut b: [u8; DIGEST_LEN] = [0; DIGEST_LEN];
    // Differ in the final byte, which only the tail characters cover -- the
    // case a group-only encoder would miss.
    b[31] = 1;
    let ea = b64url_encode_digest(a);
    let eb = b64url_encode_digest(b);
    let mut differs = false;
    for i in 0..NONCE_B64_LEN {
        if ea[i] != eb[i] {
            differs = true;
        }
    }
    assert(differs, "two digests encoded to one nonce");
}

#[test]
fn nonce_encoding_matches_external_vectors() {
    // Computed with Python `base64.urlsafe_b64encode(...).rstrip(b"=")`, so
    // this checks `noir_base64` against an oracle outside the Noir ecosystem
    // rather than against itself. The all-ones case is the sharp one: it ends
    // in `8`, not `_`, because a two-byte tail forces the final character's low
    // two bits to zero. An encoder that emitted a fourth tail character, or
    // padding, would fail here.
    let zeros: [u8; DIGEST_LEN] = [0; DIGEST_LEN];
    let zeros_expected: [u8; NONCE_B64_LEN] = [65; NONCE_B64_LEN]; // "AAA..."
    let got = b64url_encode_digest(zeros);
    for i in 0..NONCE_B64_LEN {
        assert(got[i] == zeros_expected[i], "zero digest encoded wrong");
    }

    let ones: [u8; DIGEST_LEN] = [255; DIGEST_LEN];
    let got = b64url_encode_digest(ones);
    for i in 0..42 {
        assert(got[i] == 95, "expected `_` across the body of the all-ones digest");
    }
    assert(got[42] == 56, "two-byte tail must end in `8`, not `_`");

    let mut counting: [u8; DIGEST_LEN] = [0; DIGEST_LEN];
    for i in 0..DIGEST_LEN {
        counting[i] = i as u8;
    }
    // "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    let counting_expected: [u8; NONCE_B64_LEN] = [
        65, 65, 69, 67, 65, 119, 81, 70, 66, 103, 99, 73, 67, 81, 111, 76, 68, 65, 48, 79, 68, 120,
        65, 82, 69, 104, 77, 85, 70, 82, 89, 88, 71, 66, 107, 97, 71, 120, 119, 100, 72, 104, 56,
    ];
    let got = b64url_encode_digest(counting);
    for i in 0..NONCE_B64_LEN {
        assert(got[i] == counting_expected[i], "counting digest encoded wrong");
    }
}

#[test]
fn claim_followed_by_a_structural_byte_is_accepted() {
    // Both legal continuations after a claim's closing quote: another member
    // (`,`) and end of object (`}`). Indexed the way main() indexes the
    // email claim: offset + prefix + value_len reaches the closing quote,
    // one more reaches the structural byte.
    let email_len = 7; // a@b.com
    let mid = "{\"email\":\"a@b.com\",\"x\":1}".as_bytes();
    assert(mid[1 + EMAIL_PREFIX_LEN + email_len] == 34);
    assert_structural(mid[1 + EMAIL_PREFIX_LEN + email_len + 1]);
    let last = "{\"email\":\"a@b.com\"}".as_bytes();
    assert(last[1 + EMAIL_PREFIX_LEN + email_len] == 34);
    assert_structural(last[1 + EMAIL_PREFIX_LEN + email_len + 1]);
}

#[test(should_fail_with = "claim not followed by ',' or '}'")]
fn claim_shaped_substring_without_structural_byte_is_rejected() {
    // The shape REQ-COMMON-19's trailing-byte rule exists to reject: bytes
    // that match `"email":"<value>"` exactly but sit inside a longer signed
    // string value, so the byte after the apparent closing quote is ordinary
    // string content. Every check main() ran before this fix passes here --
    // the delimiter, the value, the closing quote:
    let payload = "{\"email\":\"a@b.com\" is my address}".as_bytes();
    let email_offset = 1;
    let email_len = 7; // a@b.com
    let email_prefix: [u8; 9] = [34, 101, 109, 97, 105, 108, 34, 58, 34];
    for i in 0..EMAIL_PREFIX_LEN {
        assert(payload[email_offset + i] == email_prefix[i]);
    }
    assert(payload[email_offset + EMAIL_PREFIX_LEN + email_len] == 34);
    // -- so the trailing structural byte (here: a space) must be what fails.
    assert_structural(payload[email_offset + EMAIL_PREFIX_LEN + email_len + 1]);
}

#[test]
fn canonical_exp_values_are_accepted() {
    // A realistic ten-digit timestamp, and the lone `0` -- the one canonical
    // value whose first digit is '0'.
    let payload = "{\"exp\":1754000000}".as_bytes();
    let exp_offset = 1;
    assert_no_leading_zero(payload[exp_offset + EXP_PREFIX_LEN], 10);
    let zero = "{\"exp\":0}".as_bytes();
    assert_no_leading_zero(zero[exp_offset + EXP_PREFIX_LEN], 1);
}

#[test(should_fail_with = "leading zero in exp")]
fn exp_with_a_leading_zero_is_rejected() {
    // REQ-COMMON-19D: `0|[1-9][0-9]*`, leading-zero explicitly listed among
    // the rejects. "01754000000" satisfies the digit-run and trailing-byte
    // checks and parses to the same u64 as "1754000000" -- a second signed
    // encoding of one exp value.
    let payload = "{\"exp\":01754000000}".as_bytes();
    let exp_offset = 1;
    assert_no_leading_zero(payload[exp_offset + EXP_PREFIX_LEN], 11);
}

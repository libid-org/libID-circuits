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

global B64URL_ALPHABET: [u8; 64] = [
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
    115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95,
];

// Encode the 32-byte Authorization Digest the way REQ-PLAT-10 requires the
// runtime to place it in the OIDC `nonce`: base64url, no padding, 43 chars.
//
// The circuit encodes rather than decodes. Both bind the same pair, and
// encoding is the cheaper direction: 32 bytes are 10 whole three-byte groups
// plus a two-byte tail, so the output is fixed at 43 characters with no
// padding branch to constrain.
fn b64url_encode_digest(d: [u8; DIGEST_LEN]) -> [u8; NONCE_B64_LEN] {
    let mut out: [u8; NONCE_B64_LEN] = [0; NONCE_B64_LEN];
    for g in 0..10 {
        let b0 = d[3 * g] as u32;
        let b1 = d[3 * g + 1] as u32;
        let b2 = d[3 * g + 2] as u32;
        out[4 * g] = B64URL_ALPHABET[b0 >> 2];
        out[4 * g + 1] = B64URL_ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
        out[4 * g + 2] = B64URL_ALPHABET[((b1 & 15) << 2) | (b2 >> 6)];
        out[4 * g + 3] = B64URL_ALPHABET[b2 & 63];
    }
    // Tail: the last two bytes make three characters, with no padding byte.
    let t0 = d[30] as u32;
    let t1 = d[31] as u32;
    out[40] = B64URL_ALPHABET[t0 >> 2];
    out[41] = B64URL_ALPHABET[((t0 & 3) << 4) | (t1 >> 4)];
    out[42] = B64URL_ALPHABET[(t1 & 15) << 2];
    out
}

// Length of base64url-encoded output (no padding) for `input_len` bytes of input.
fn b64_encoded_len(input_len: u32) -> u32 {
    let chunks_full = input_len / 3;
    let tail = input_len - chunks_full * 3;
    let extra = if tail == 0 { 0 } else { tail + 1 };
    chunks_full * 4 + extra
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
    // Trailing byte must be `,` (44) or `}` (125): defends against partial match.
    let ev_trailing = payload_json[email_verified_offset + EMAIL_VERIFIED_LEN];
    assert((ev_trailing == 44) | (ev_trailing == 125));

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
    let exp_trailing = payload_json[exp_offset + EXP_PREFIX_LEN + exp_len];
    assert((exp_trailing == 44) | (exp_trailing == 125));
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

    let computed_audience_hash: [u8; 32] = sha256_var(audience_bytes, audience_len);
    let mut audience_h0: Field = 0;
    let mut audience_h1: Field = 0;
    for i in 0..16 {
        audience_h0 = audience_h0 * 256 + computed_audience_hash[i] as Field;
        audience_h1 = audience_h1 * 256 + computed_audience_hash[i + 16] as Field;
    }
    assert(audience_h0 == audience_hash[0]);
    assert(audience_h1 == audience_hash[1]);

    // 9. Offset bounds: every claimed pattern must lie inside the real
    //    payload_json (not in the zero-padded region the prover controls).
    //    payload_json_len itself is bound by the base64 length check above,
    //    so it cannot be inflated.
    assert(email_offset + EMAIL_PREFIX_LEN + email_len + 1 <= payload_json_len);
    assert(nonce_offset + NONCE_PREFIX_LEN + NONCE_B64_LEN + 1 <= payload_json_len);
    assert(sub_offset + SUB_PREFIX_LEN + sub_len + 1 <= payload_json_len);
    assert(email_verified_offset + EMAIL_VERIFIED_LEN + 1 <= payload_json_len);
    assert(exp_offset + EXP_PREFIX_LEN + exp_len + 1 <= payload_json_len);
    assert(iss_offset + ISS_PATTERN_LEN <= payload_json_len);
    assert(aud_offset + AUD_PREFIX_LEN + audience_len + 1 <= payload_json_len);
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
fn nonce_encoding_uses_the_url_alphabet() {
    // An all-ones digest exercises the two characters that separate base64url
    // from base64: `-` and `_` stand where `+` and `/` would.
    let d: [u8; DIGEST_LEN] = [0xff; DIGEST_LEN];
    let got = b64url_encode_digest(d);
    for i in 0..NONCE_B64_LEN {
        assert(got[i] != 43, "encoder emitted `+`, not base64url");
        assert(got[i] != 47, "encoder emitted `/`, not base64url");
        assert(got[i] != 61, "encoder emitted padding");
    }
}

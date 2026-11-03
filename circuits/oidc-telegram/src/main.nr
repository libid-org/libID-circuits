use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use libid_identity::{
    block_node_halves,
    check_id,
    fold_handle,
    halves,
    sha256_block,
    table::{
        HANDLE_TAG_TELEGRAM, ID_DECIMAL_TELEGRAM, MAX_HANDLE_TELEGRAM, MAX_ID_TELEGRAM,
        USER_ID_TAG_TELEGRAM,
    },
};
use noir_base64::BASE64_URL_ENCODER;
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use sha256::sha256_var;

global SIGNING_INPUT_MAX: u32 = 2688;
global AUDIENCE_MAX: u32 = 20;
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

// Telegram escapes `/` as `\/`.
global ISS_PATTERN: [u8; 36] = "\"iss\":\"https:\\/\\/oauth.telegram.org\"".as_bytes();
global AUD_PREFIX: [u8; 7] = "\"aud\":\"".as_bytes();
global IAT_PREFIX: [u8; 6] = "\"iat\":".as_bytes();
global ID_PREFIX: [u8; 6] = "\"id\":\"".as_bytes();
global USERNAME_PREFIX: [u8; 22] = "\"preferred_username\":\"".as_bytes();
global NONCE_PREFIX: [u8; 9] = "\"nonce\":\"".as_bytes();

// The base64url payload: `b64_len` characters of `signing_input` from `start`.
struct Payload {
    signing_input: [u8; SIGNING_INPUT_MAX],
    start: u32,
    b64_len: u32,
}

// A claim's window: `at` is the claim's index in `bytes`, and the signed
// characters fix the first `bound` bytes.
struct Window<let W: u32, let N: u32> {
    claim: str<N>,
    bytes: [u8; W],
    at: u32,
    bound: u32,
}

impl Payload {
    // Binds `window` to the signed base64url of the payload groups from the
    // one holding byte `offset`.
    fn window<let W: u32, let N: u32>(
        self,
        claim: str<N>,
        window: [u8; W],
        offset: u32,
    ) -> Window<W, N> {
        let group = offset / 3;
        let start = 4 * group;
        assert(start + 4 <= self.b64_len, f"{claim} window starts outside the payload");
        let encoded = BASE64_URL_ENCODER::encode(window);
        let rest = self.b64_len - start;
        let signed = if rest < encoded.len() {
            rest
        } else {
            encoded.len()
        };
        for i in 0..encoded.len() {
            if i < signed {
                assert(
                    self.signing_input[self.start + start + i] == encoded[i],
                    f"{claim} window does not match the signed input",
                );
            }
        }
        Window { claim, bytes: window, at: offset - 3 * group, bound: signed * 3 / 4 }
    }
}

impl<let W: u32, let N: u32> Window<W, N> {
    // `pattern` at the claim; returns the index past it.
    fn pattern<let P: u32>(self, pattern: [u8; P]) -> u32 {
        let claim = self.claim;
        for i in 0..P {
            assert(self.bytes[self.at + i] == pattern[i], f"{claim} claim pattern mismatch");
        }
        self.at + P
    }

    // The claim ends at `end` with ',' or '}', inside the signed bytes.
    fn close(self, end: u32) {
        let claim = self.claim;
        let w = self.bytes;
        assert((w[end] == 44) | (w[end] == 125), f"{claim} claim not followed by ',' or '}}'");
        assert(end < self.bound, f"{claim} claim outside the signed bytes");
    }

    // The `len`-byte value of `<prefix><value>"` at the claim, then closed.
    fn string<let P: u32, let M: u32>(self, prefix: [u8; P], len: u32) -> [u8; M] {
        let claim = self.claim;
        let start = self.pattern(prefix);
        assert(len <= M, f"{claim} value longer than its buffer");
        let mut value: [u8; M] = [0; M];
        for i in 0..M {
            if i < len {
                value[i] = self.bytes[start + i];
            }
        }
        assert(self.bytes[start + len] == 34, f"{claim} value not closed");
        self.close(start + len + 1);
        value
    }
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
    assert(signing_input[header_b64_len] == 46, "no '.' before the payload");
    let p0 = header_b64_len + 1;
    let payload = Payload { signing_input, start: p0, b64_len: signing_input_len - p0 };
    assert(payload.b64_len % 4 != 1, "malformed base64url length");

    let iss = payload.window("iss", iss_window, iss_offset);
    iss.close(iss.pattern(ISS_PATTERN));

    let aud = payload.window("aud", aud_window, aud_offset);
    assert(audience_len != 0, "aud is empty");
    let audience: [u8; AUDIENCE_MAX] = aud.string(AUD_PREFIX, audience_len);
    for i in 0..AUDIENCE_MAX {
        assert((audience[i] != 34) & (audience[i] != 92), "aud byte not allowed");
    }
    assert(halves(sha256_block(audience, audience_len)) == audience_hash, "audience mismatch");

    let iat_claim = payload.window("iat", iat_window, iat_offset);
    let start = iat_claim.pattern(IAT_PREFIX);
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
    iat_claim.close(start + iat_len);
    assert(parsed == iat, "iat mismatch");

    let id: [u8; MAX_ID_TELEGRAM] =
        payload.window("id", id_window, id_offset).string(ID_PREFIX, id_len);
    check_id(id, id_len, ID_DECIMAL_TELEGRAM);
    assert(block_node_halves(USER_ID_TAG_TELEGRAM, id, id_len) == id_node, "id node mismatch");

    let username: [u8; MAX_HANDLE_TELEGRAM] = payload
        .window("username", username_window, username_offset)
        .string(USERNAME_PREFIX, username_len);
    let folded = fold_handle(username, username_len);
    assert(
        block_node_halves(HANDLE_TAG_TELEGRAM, folded, username_len) == handle_node,
        "handle node mismatch",
    );

    let nonce: [u8; NONCE_LEN] =
        payload.window("nonce", nonce_window, nonce_offset).string(NONCE_PREFIX, NONCE_LEN);
    let expected: [u8; NONCE_LEN] = BASE64_URL_ENCODER::encode(authorization_digest);
    assert(nonce == expected, "nonce does not encode the authorization digest");
}

// --- Tests ----------------------------------------------------------------

#[test]
fn each_window_holds_its_longest_claim_at_any_alignment() {
    let widths = [ISS_WINDOW, AUD_WINDOW, IAT_WINDOW, ID_WINDOW, USERNAME_WINDOW, NONCE_WINDOW];
    let needs = [
        ISS_PATTERN.len() + 1,
        AUD_PREFIX.len() + AUDIENCE_MAX + 2,
        IAT_PREFIX.len() + MAX_IAT_DIGITS + 1,
        ID_PREFIX.len() + MAX_ID_TELEGRAM + 2,
        USERNAME_PREFIX.len() + MAX_HANDLE_TELEGRAM + 2,
        NONCE_PREFIX.len() + NONCE_LEN + 2,
    ];
    for i in 0..6 {
        assert((widths[i] % 3 == 0) & (widths[i] >= needs[i] + 2));
    }
}

#[test]
fn the_audience_hash_is_sha256_at_its_shortest_and_longest() {
    let audience: [u8; AUDIENCE_MAX] = [0x37; AUDIENCE_MAX];
    for len in [1, AUDIENCE_MAX] {
        assert(sha256_block(audience, len) == sha256_var(audience, len));
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
    let w = Payload { signing_input: tiny_input(), start: 2, b64_len: 10 }.window("a", window, 1);
    assert((w.at == 1) & (w.bound == 7));
    w.close(6);
}

#[test(should_fail_with = "a claim outside the signed bytes")]
fn a_claim_closed_past_the_signed_bytes_is_refused() {
    let window: [u8; 9] = "{\"a\":1}\0}".as_bytes();
    Payload { signing_input: tiny_input(), start: 2, b64_len: 10 }.window("a", window, 0).close(8);
}

#[test(should_fail_with = "a window does not match the signed input")]
fn a_window_other_than_the_signed_bytes_is_refused() {
    let window: [u8; 9] = "{\"a\":2}\0\0".as_bytes();
    let _ = Payload { signing_input: tiny_input(), start: 2, b64_len: 10 }.window("a", window, 0);
}

// `x.` then base64url(`{"a":"1"`): the 3-character tail fixes a following
// ',' only in its top 2 bits, so a claim may not close there.
#[test(should_fail_with = "a claim outside the signed bytes")]
fn a_claim_closed_at_the_signed_bound_is_refused() {
    let tail: [u8; 13] = "x.eyJhIjoiMSI".as_bytes();
    let mut si: [u8; SIGNING_INPUT_MAX] = [0; SIGNING_INPUT_MAX];
    for i in 0..13 {
        si[i] = tail[i];
    }
    let window: [u8; 9] = "{\"a\":\"1\",".as_bytes();
    Payload { signing_input: si, start: 2, b64_len: 11 }.window("a", window, 0).close(8);
}

//! 已知答案测试（KAT）：用标准文档中的测试向量校验底层原语与本 crate 的封装。
//!
//! 来源：
//! - RFC 5869 附录 A.1–A.3（HKDF-SHA-256）
//! - RFC 9106 §5.3（Argon2id v0x13）
//! - draft-irtf-cfrg-xchacha-03 附录 A.1（AEAD_XChaCha20_Poly1305）

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::hkdf::hkdf_sha256;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s.replace([' ', '\n'], "")).unwrap()
}

#[test]
fn hkdf_rfc5869_a1() {
    let mut okm = [0u8; 42];
    hkdf_sha256(
        &h("0b").repeat(22),
        &h("000102030405060708090a0b0c"),
        &h("f0f1f2f3f4f5f6f7f8f9"),
        &mut okm,
    )
    .unwrap();
    assert_eq!(
        okm.to_vec(),
        h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
}

#[test]
fn hkdf_rfc5869_a2() {
    let ikm: Vec<u8> = (0x00..=0x4f).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();
    let mut okm = [0u8; 82];
    hkdf_sha256(&ikm, &salt, &info, &mut okm).unwrap();
    assert_eq!(
        okm.to_vec(),
        h(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c
           59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71
           cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )
    );
}

#[test]
fn hkdf_rfc5869_a3_empty_salt_and_info() {
    let mut okm = [0u8; 42];
    hkdf_sha256(&h("0b").repeat(22), &[], &[], &mut okm).unwrap();
    assert_eq!(
        okm.to_vec(),
        h("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    );
}

#[test]
fn argon2id_rfc9106_5_3() {
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&[0x04; 12]).unwrap())
        .build()
        .unwrap();
    let secret = [0x03u8; 8];
    let argon =
        Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut tag = [0u8; 32];
    argon
        .hash_password_into(&[0x01; 32], &[0x02; 16], &mut tag)
        .unwrap();
    assert_eq!(
        tag.to_vec(),
        h("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}

#[test]
fn xchacha20poly1305_draft03_a1() {
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let aad = h("50515253c0c1c2c3c4c5c6c7");
    let key = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let iv: [u8; 24] = h("404142434445464748494a4b4c4d4e4f5051525354555657")
        .try_into()
        .unwrap();
    let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    let out = cipher
        .encrypt(
            &XNonce::from(iv),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .unwrap();
    let expected_ct = h(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
                         731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
                         2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
                         21f9664c97637da9768812f615c68b13b52e",
    );
    let expected_tag = h("c0875924c1c7987947deafd8780acf49");
    assert_eq!(out[..out.len() - 16], expected_ct[..]);
    assert_eq!(out[out.len() - 16..], expected_tag[..]);
}

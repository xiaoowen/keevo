//! 跨实现测试向量：`spec/test-vectors/crypto-v1.json` 由独立的 Python 参考实现
//! （`spec/reference/generate_vectors.py`，基于 argon2-cffi 与 libsodium）生成。
//! 本实现必须逐字节复现全部向量。

use serde_json::Value;

use crate::envelope::{self, AadContext, ObjectType, Part};
use crate::error::CryptoError;
use crate::id::Id128;
use crate::kdf::KdfParams;
use crate::key::SymmetricKey;
use crate::keyset::{self, AccountKeyset};
use crate::padding;
use crate::secret_key::AccountSecretKey;
use crate::two_skd;

const VECTORS: &str = include_str!("../../../spec/test-vectors/crypto-v1.json");

fn doc() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    bytes(v).try_into().unwrap()
}

fn id(v: &Value) -> Id128 {
    Id128::from_bytes(arr(v))
}

fn object_type(v: &Value) -> ObjectType {
    match v.as_u64().unwrap() {
        0x01 => ObjectType::AccountKeyset,
        0x02 => ObjectType::Vault,
        0x03 => ObjectType::Item,
        0x04 => ObjectType::Attachment,
        0x05 => ObjectType::SyncSegment,
        0x06 => ObjectType::SyncSnapshot,
        0x07 => ObjectType::DeviceName,
        other => panic!("未知 object_type {other}"),
    }
}

fn part(v: &Value) -> Part {
    match v.as_u64().unwrap() {
        0x01 => Part::Content,
        0x02 => Part::WrappedKey,
        0x03 => Part::Overview,
        0x04 => Part::Details,
        0x05 => Part::Chunk,
        other => panic!("未知 part {other}"),
    }
}

#[test]
fn spec_version_matches() {
    assert_eq!(doc()["spec_version"], "0.1");
}

#[test]
fn secret_key_encoding() {
    let d = doc();
    for case in d["secret_key"]["encode"].as_array().unwrap() {
        let sk = AccountSecretKey::from_bytes(arr(&case["bytes"]));
        assert_eq!(
            sk.to_display_string().as_str(),
            case["display"].as_str().unwrap()
        );
    }
    for case in d["secret_key"]["parse_ok"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let sk = AccountSecretKey::parse(input).unwrap_or_else(|e| panic!("{input:?}: {e}"));
        assert_eq!(sk.expose().to_vec(), bytes(&case["bytes"]), "{input:?}");
    }
    for case in d["secret_key"]["parse_err"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let err = AccountSecretKey::parse(input).err().unwrap();
        assert_eq!(err.code(), case["error"].as_str().unwrap(), "{input:?}");
    }
}

#[test]
fn kdf_params() {
    for case in doc()["kdf_params"].as_array().unwrap() {
        let encoded = bytes(&case["encoded"]);
        match (KdfParams::decode(&encoded), case["error"].as_str()) {
            (Ok(p), None) => assert_eq!(p.encode().to_vec(), encoded),
            (Err(e), Some(code)) => assert_eq!(e.code(), code, "{}", case["name"]),
            (got, want) => panic!("{}: got {:?}, want {want:?}", case["name"], got.err()),
        }
    }
}

#[test]
fn two_skd() {
    for case in doc()["two_skd"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let password = case["password"].as_str().unwrap();
        let sk = AccountSecretKey::from_bytes(arr(&case["secret_key"]));
        let account_id = id(&case["account_id"]);
        let params = KdfParams::decode(&bytes(&case["kdf_params"])).unwrap();

        let normalized = two_skd::normalize_password(password).unwrap();
        assert_eq!(
            normalized.as_bytes(),
            bytes(&case["password_nfkd"]),
            "{name}: NFKD"
        );

        let k_p = params.argon2id(normalized.as_bytes()).unwrap();
        assert_eq!(k_p.to_vec(), bytes(&case["k_p"]), "{name}: K_p");
        let k_s = two_skd::derive_k_s(&sk, &account_id).unwrap();
        assert_eq!(k_s.to_vec(), bytes(&case["k_s"]), "{name}: K_s");

        let auk = two_skd::derive_account_unlock_key(password, &sk, &account_id, &params).unwrap();
        assert_eq!(auk.expose().to_vec(), bytes(&case["auk"]), "{name}: AUK");
        assert_eq!(
            auk.id().as_bytes().to_vec(),
            bytes(&case["auk_kid"]),
            "{name}: kid(AUK)"
        );
    }
}

#[test]
fn padding_lengths() {
    for case in doc()["padding"].as_array().unwrap() {
        let len = usize::try_from(case["plaintext_len"].as_u64().unwrap()).unwrap();
        let want = usize::try_from(case["padded_len"].as_u64().unwrap()).unwrap();
        assert_eq!(padding::padded_len(4 + len).unwrap(), want, "len {len}");
    }
}

#[test]
fn envelopes() {
    for case in doc()["envelope"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let key = SymmetricKey::from_raw(arr(&case["kid"]), arr(&case["key"]));
        let ctx = AadContext {
            object_type: object_type(&case["object_type"]),
            part: part(&case["part"]),
            part_index: u32::try_from(case["part_index"].as_u64().unwrap()).unwrap(),
            account_id: id(&case["account_id"]),
            vault_id: id(&case["vault_id"]),
            object_id: id(&case["object_id"]),
            rev_id: id(&case["rev_id"]),
            binding: arr(&case["binding"]),
        };
        let plaintext = bytes(&case["plaintext"]);
        assert_eq!(ctx.aad_bytes(&key.id()), bytes(&case["aad"]), "{name}: AAD");

        let sealed =
            envelope::seal_with_nonce(&key, &ctx, &plaintext, arr(&case["nonce"])).unwrap();
        assert_eq!(sealed, bytes(&case["envelope"]), "{name}: envelope");
        assert_eq!(
            envelope::open(&key, &ctx, &sealed).unwrap().as_slice(),
            plaintext.as_slice()
        );
    }
}

#[test]
fn keyset() {
    for case in doc()["keyset"].as_array().unwrap() {
        let account_id = id(&case["account_id"]);
        let auk = SymmetricKey::from_raw(arr(&case["auk_kid"]), arr(&case["auk"]));
        let epoch = case["epoch"].as_u64().unwrap();
        let params = KdfParams::decode(&bytes(&case["kdf_params"])).unwrap();
        assert_eq!(
            keyset::binding(epoch, &params).to_vec(),
            bytes(&case["binding"])
        );

        let ks = AccountKeyset::from_keys(
            SymmetricKey::from_raw(arr(&case["ask_kid"]), arr(&case["ask"])),
            SymmetricKey::from_raw(arr(&case["syk_kid"]), arr(&case["syk"])),
            SymmetricKey::from_raw(arr(&case["sign_kid"]), arr(&case["sign_seed"])),
        );
        let sealed = ks
            .seal_with_nonce(&auk, &account_id, epoch, &params, arr(&case["nonce"]))
            .unwrap();
        assert_eq!(sealed, bytes(&case["envelope"]));

        let opened = AccountKeyset::open(&auk, &account_id, epoch, &params, &sealed).unwrap();
        assert_eq!(opened.account_key().expose().to_vec(), bytes(&case["ask"]));
        assert_eq!(
            opened.sync_key().id().as_bytes().to_vec(),
            bytes(&case["syk_kid"])
        );
        assert_eq!(
            opened.signing_seed().expose().to_vec(),
            bytes(&case["sign_seed"])
        );

        // 用错误的 AUK（kid 相同、字节不同）解开必须失败
        let wrong = SymmetricKey::from_raw(arr(&case["auk_kid"]), [0u8; 32]);
        assert_eq!(
            AccountKeyset::open(&wrong, &account_id, epoch, &params, &sealed).err(),
            Some(CryptoError::DecryptionFailed)
        );
    }
}

/// 加密导出文件（`spec/export.md` §3，草案）：独立实现生成的 `export-v1.json`。写出逐字节相同；
/// NFKD 等价的口令都能打开；反例按期望的错误失败。
#[test]
fn export_files() {
    const EXPORT: &str = include_str!("../../../spec/test-vectors/export-v1.json");
    let doc: Value = serde_json::from_str(EXPORT).unwrap();
    for case in doc["valid"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let password = case["password"].as_str().unwrap();
        let params = KdfParams::decode(&bytes(&case["kdf_params"])).unwrap();
        let plaintext = bytes(&case["plaintext"]);
        let file = bytes(&case["file"]);
        let sealed = crate::export::seal_export_with_nonce(
            password,
            &params,
            &plaintext,
            arr(&case["nonce"]),
        )
        .unwrap();
        assert_eq!(sealed, file, "{name}: 写出");
        assert_eq!(&file[..62], bytes(&case["aad"]).as_slice(), "{name}: AAD");
        assert_eq!(
            crate::open_export(password, &file).unwrap().as_slice(),
            plaintext.as_slice(),
            "{name}"
        );
        if let Some(other) = case.get("equivalent_password").and_then(Value::as_str) {
            assert_eq!(
                crate::open_export(other, &file).unwrap().as_slice(),
                plaintext.as_slice(),
                "{name}: NFKD 等价的口令"
            );
        }
    }
    let invalid = doc["invalid"].as_array().unwrap();
    assert!(invalid.len() >= 8);
    for case in invalid {
        let name = case["name"].as_str().unwrap();
        let err = crate::open_export(case["password"].as_str().unwrap(), &bytes(&case["file"]))
            .err()
            .unwrap_or_else(|| panic!("{name} 应当失败"));
        let ok = match case["error"].as_str().unwrap() {
            "malformed" => err == CryptoError::Malformed,
            "unsupported_version" => err == CryptoError::UnsupportedVersion,
            "decryption_failed" => err == CryptoError::DecryptionFailed,
            "kdf_invalid" => matches!(
                err,
                CryptoError::KdfBelowMinimum
                    | CryptoError::KdfAboveMaximum
                    | CryptoError::UnsupportedAlgorithm
            ),
            other => panic!("未知的错误码 {other}"),
        };
        assert!(ok, "{name}: {err:?}");
    }
}

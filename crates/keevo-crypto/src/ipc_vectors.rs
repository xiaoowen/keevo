//! 本地通信协议的跨实现测试向量：`spec/test-vectors/ipc-v1.json` 由独立的 Python 参考实现
//! （`spec/reference/ipc_vectors.py`，只依赖标准库）生成。本实现必须逐字节复现：配对承诺、prologue（含协议版本）、
//! XX 与 IK 的每一条握手消息、握手哈希、SAS，以及握手之后每个方向的第一条传输消息。

use serde_json::Value;
use zeroize::Zeroizing;

use crate::noise::{Handshake, StaticKeypair, pairing_commitment};

const VECTORS: &str = include_str!("../../../spec/test-vectors/ipc-v1.json");

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn arr(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}

fn keypair(v: &Value) -> StaticKeypair {
    StaticKeypair::from_private(Zeroizing::new(arr(v)))
}

#[test]
fn commitments() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    for c in doc["commitments"].as_array().unwrap() {
        let commit = pairing_commitment(&arr(&c["extension_static_public"]), &bytes(&c["third"]));
        assert_eq!(
            hex::encode(commit),
            c["commitment"].as_str().unwrap(),
            "{}",
            c["name"]
        );
    }
}

#[test]
fn handshakes() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let handshakes = doc["handshakes"].as_array().unwrap();
    assert_eq!(handshakes.len(), 4);
    for v in handshakes {
        let name = v["name"].as_str().unwrap();
        let xx = v["pattern"] == "Noise_XX_25519_ChaChaPoly_SHA256";
        let version = u32::try_from(v["protocol_version"].as_u64().unwrap()).unwrap();
        let origin = v["extension_origin"].as_str().unwrap();
        let ext = keypair(&v["initiator_static_private"]);
        let svc = keypair(&v["responder_static_private"]);
        assert_eq!(
            hex::encode(ext.public_key()),
            v["initiator_static_public"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(svc.public_key()),
            v["responder_static_public"].as_str().unwrap()
        );
        let svc_public = svc.public_key();
        let remote = (!xx).then_some(&svc_public);
        let mut i = Handshake::for_vector(
            xx,
            &ext,
            remote,
            origin,
            version,
            true,
            &arr(&v["initiator_ephemeral_private"]),
        )
        .unwrap();
        let mut r = Handshake::for_vector(
            xx,
            &svc,
            None,
            origin,
            version,
            false,
            &arr(&v["responder_ephemeral_private"]),
        )
        .unwrap();
        for (n, m) in v["messages"].as_array().unwrap().iter().enumerate() {
            let (sender, receiver) = if m["sender"] == "initiator" {
                (&mut i, &mut r)
            } else {
                (&mut r, &mut i)
            };
            let payload = bytes(&m["payload"]);
            let message = sender.write(&payload).unwrap();
            assert_eq!(
                hex::encode(&message),
                m["message"].as_str().unwrap(),
                "{name} 第 {} 条握手消息",
                n + 1
            );
            assert_eq!(
                receiver.read(&message).unwrap().as_slice(),
                payload.as_slice()
            );
        }
        assert!(i.is_finished() && r.is_finished());
        assert_eq!(
            hex::encode(i.handshake_hash()),
            v["handshake_hash"].as_str().unwrap(),
            "{name} 握手哈希"
        );
        assert_eq!(i.handshake_hash(), r.handshake_hash());
        assert_eq!(r.remote_static(), Some(ext.public_key()));
        if xx {
            assert_eq!(
                hex::encode(i.sas().unwrap()),
                v["sas"].as_str().unwrap(),
                "{name} SAS"
            );
            assert_eq!(i.sas().unwrap(), r.sas().unwrap());
        }
        let mut it = i.into_transport().unwrap();
        let mut rt = r.into_transport().unwrap();
        for f in v["transport"].as_array().unwrap() {
            let (sender, receiver) = if f["sender"] == "initiator" {
                (&mut it, &mut rt)
            } else {
                (&mut rt, &mut it)
            };
            let plaintext = f["plaintext"].as_str().unwrap().as_bytes();
            let message = sender.encrypt(plaintext).unwrap();
            assert_eq!(
                hex::encode(&message),
                f["message"].as_str().unwrap(),
                "{name} 传输消息"
            );
            assert_eq!(receiver.decrypt(&message).unwrap().as_slice(), plaintext);
        }
    }
}

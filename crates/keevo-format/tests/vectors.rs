//! 跨实现测试向量：`spec/test-vectors/vault-format-v1.json`、`vault-format-v2.json` 与 `revisions-v1.json` 由独立的
//! Python 参考实现（`spec/reference/format_vectors.py`）只依据规范生成。本实现必须逐字节复现。
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use keevo_crypto::Id128;
use keevo_format::{
    FormatError, HeadState, ItemDoc, ItemOverview, Merged, RecordValue, RevisionGraph, VaultMeta,
    from_json, merge_heads, to_json,
};
use serde_json::Value;

const FORMAT: &str = include_str!("../../../spec/test-vectors/vault-format-v1.json");
const REVISIONS: &str = include_str!("../../../spec/test-vectors/revisions-v1.json");
const FORMAT_V2: &str = include_str!("../../../spec/test-vectors/vault-format-v2.json");

fn load(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("缺少字段 {key}"))
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn id(s: &str) -> Id128 {
    Id128::from_bytes(unhex(s).try_into().unwrap())
}

/// 向量中的文档：通常是 `doc` 字符串；非 UTF-8 的输入用 `doc_hex` 给出原始字节。
fn doc_bytes(v: &Value) -> Vec<u8> {
    v["doc"]
        .as_str()
        .map_or_else(|| unhex(str_of(v, "doc_hex")), |s| s.as_bytes().to_vec())
}

#[test]
fn canonical_values() {
    let doc = load(FORMAT);
    let cases = doc["canonical_values"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = str_of(case, "name");
        let value: RecordValue = from_json(str_of(case, "loose").as_bytes())
            .unwrap_or_else(|e| panic!("{name}：宽松写法无法解析：{e}"));
        let canonical = to_json(&value).unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            str_of(case, "canonical"),
            "{name}"
        );
    }
}

fn check_documents<T>(
    section: &Value,
    decode: impl Fn(&[u8]) -> Result<T, FormatError>,
    encode: impl Fn(&T) -> Vec<u8>,
) {
    for case in section["valid"].as_array().unwrap() {
        let name = str_of(case, "name");
        let bytes = doc_bytes(case);
        let value =
            decode(&bytes).unwrap_or_else(|e| panic!("{name}：应当接受，却返回 {}", e.code()));
        assert_eq!(encode(&value), bytes, "{name}：重新编码后不同");
    }
    for case in section["invalid"].as_array().unwrap() {
        let name = str_of(case, "name");
        let expected = str_of(case, "error");
        match decode(&doc_bytes(case)) {
            Ok(_) => panic!("{name}：应当返回 {expected}，却被接受"),
            Err(e) => assert_eq!(e.code(), expected, "{name}"),
        }
    }
}

#[test]
fn item_details() {
    let doc = load(FORMAT);
    check_documents(&doc["item_details"], ItemDoc::decode, |d| {
        d.encode().unwrap().to_vec()
    });
}

/// 条目详情 v2（附件字段）。
#[test]
fn item_details_v2() {
    let doc = load(FORMAT_V2);
    check_documents(&doc["item_details"], ItemDoc::decode, |d| {
        d.encode().unwrap().to_vec()
    });
}

#[test]
fn overview() {
    let doc = load(FORMAT);
    check_documents(&doc["overview"], ItemOverview::decode, |o| {
        o.encode().unwrap().to_vec()
    });
}

#[test]
fn vault_meta() {
    let doc = load(FORMAT);
    check_documents(&doc["vault_meta"], VaultMeta::decode, |m| {
        m.encode().unwrap().to_vec()
    });
}

fn summarize(result: &Result<Merged, FormatError>) -> Value {
    match result {
        Err(e) => serde_json::json!({ "error": e.code() }),
        Ok(m) => serde_json::json!({
            "deleted": m.doc.is_none(),
            "doc": m.doc.as_ref().map(|d| String::from_utf8(d.encode().unwrap().to_vec()).unwrap()),
            "resurrected": m.resurrected,
            "conflicts": m.conflicts.iter().map(|c| c.key.to_string()).collect::<Vec<_>>(),
            "integrity_issues": m.integrity_issues.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }),
    }
}

#[test]
fn merges() {
    let doc = load(REVISIONS);
    let cases = doc["merges"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = str_of(case, "name");
        let mut graph = RevisionGraph::new();
        for r in case["revisions"].as_array().unwrap() {
            let parents = r["parents"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| id(p.as_str().unwrap()))
                .collect();
            graph
                .insert(id(str_of(r, "rev")), parents, id(str_of(r, "origin")))
                .unwrap_or_else(|e| panic!("{name}：修订图：{}", e.code()));
        }
        let heads: Vec<(Id128, Option<ItemDoc>)> = case["heads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                let doc = h["doc"].as_str().map(|d| {
                    ItemDoc::decode(d.as_bytes())
                        .unwrap_or_else(|e| panic!("{name}：头无法解码：{}", e.code()))
                });
                (id(str_of(h, "rev")), doc)
            })
            .collect();
        let states: Vec<HeadState<'_>> = heads
            .iter()
            .map(|(rev, doc)| match doc {
                Some(doc) => HeadState::Live { rev: *rev, doc },
                None => HeadState::Deleted { rev: *rev },
            })
            .collect();
        let expected = &case["expected"];
        assert_eq!(
            &summarize(&merge_heads(&states, &graph)),
            expected,
            "{name}"
        );
        let reversed: Vec<HeadState<'_>> = states.iter().rev().copied().collect();
        assert_eq!(
            &summarize(&merge_heads(&reversed, &graph)),
            expected,
            "{name}：与头的顺序无关"
        );
    }
}

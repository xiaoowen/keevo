use std::collections::HashSet;

use super::*;

const TSV: &str = include_str!("../../../../spec/sas-wordlist-v1.tsv");

/// 代码中的词表与发布的 `spec/sas-wordlist-v1.tsv` 逐行一致。
#[test]
fn matches_the_published_wordlist() {
    let lines: Vec<&str> = TSV.lines().collect();
    assert_eq!(lines.len(), 256);
    for (i, line) in lines.iter().enumerate() {
        let b = u8::try_from(i).unwrap();
        let w = word(b);
        assert_eq!(*line, format!("{b:02x}\t{}\t{}", w.en, w.zh));
    }
    assert!(
        TSV.ends_with('\n') && !TSV.contains('\r'),
        "LF 换行，末尾有换行"
    );
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != *cb);
            cur.push(sub.min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// 词表的性质（`spec/ipc.md` §4.2）：英文词 3–9 个小写字母、前 3 个字母互不相同、两两编辑距离至少为 2；
/// 中文词恰好两个汉字，512 个字互不重复。拼音不重复由 `scripts/check-sas-wordlist.swift` 检查。
#[test]
fn words_are_distinct() {
    let words: Vec<SasWord> = (0..=255u8).map(word).collect();
    let mut prefixes = HashSet::new();
    let mut chars = HashSet::new();
    for w in &words {
        assert!(
            (3..=9).contains(&w.en.len()) && w.en.bytes().all(|c| c.is_ascii_lowercase()),
            "{}",
            w.en
        );
        assert!(prefixes.insert(&w.en[..3]), "英文前缀重复：{}", w.en);
        let zh: Vec<char> = w.zh.chars().collect();
        assert_eq!(zh.len(), 2, "{}", w.zh);
        for c in zh {
            assert!(('\u{4e00}'..='\u{9fff}').contains(&c), "{}", w.zh);
            assert!(chars.insert(c), "汉字重复：{c}（{}）", w.zh);
        }
    }
    for (i, a) in words.iter().enumerate() {
        for b in &words[i + 1..] {
            assert!(levenshtein(a.en, b.en) >= 2, "{} / {}", a.en, b.en);
        }
    }
    let mut sorted: Vec<&str> = words.iter().map(|w| w.en).collect();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        words.iter().map(|w| w.en).collect::<Vec<_>>(),
        "按英文字母顺序排列"
    );
}

#[test]
fn bytes_map_to_fixed_words() {
    let w = sas_words(&[0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]);
    let got: Vec<(&str, &str)> = w.iter().map(|w| (w.zh, w.en)).collect();
    assert_eq!(
        got,
        [
            ("相册", "album"),
            ("胡同", "alley"),
            ("门锁", "lock"),
            ("桂圆", "longan"),
            ("瑜伽", "yoga"),
            ("斑马", "zebra"),
        ]
    );
    assert_eq!(WORDLIST_VERSION, 1);
}

/// 跨实现向量（spec/test-vectors/ipc-v1.json）中的 SAS 与词表映射：由 Python 参考实现直接读取发布的词表生成。
#[test]
fn matches_the_ipc_vectors() {
    let doc: serde_json::Value =
        serde_json::from_str(include_str!("../../../../spec/test-vectors/ipc-v1.json")).unwrap();
    let mut checked = 0;
    for h in doc["handshakes"].as_array().unwrap() {
        let Some(sas) = h["sas"].as_str() else {
            continue;
        };
        let bytes: Vec<u8> = (0..6)
            .map(|i| u8::from_str_radix(&sas[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let got = sas_words(&bytes.try_into().unwrap());
        let want = h["sas_words"].as_array().unwrap();
        for (g, w) in got.iter().zip(want) {
            assert_eq!(
                (g.zh, g.en),
                (w["zh"].as_str().unwrap(), w["en"].as_str().unwrap())
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 2);
}

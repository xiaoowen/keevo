//! 浏览器扩展使用的 IPC 客户端（WASM）。
//!
//! 只是 [`keevo_ipc::client::ExtensionClient`] 的薄封装：帧与事件都以 JSON 字符串进出，
//! 由扩展的 Service Worker 负责收发（`chrome.runtime.connectNative`）。

use keevo_crypto::StaticKeypair;
use keevo_ipc::client::{ClientEvent, ExtensionClient};
use keevo_ipc::message::{Call, sanitize_display_name};
use keevo_ipc::sas::sas_words;
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn js_err(e: impl core::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> Result<[u8; 32], JsError> {
    if s.len() != 64 {
        return Err(JsError::new("expected 64 hex characters"));
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        let pair = core::str::from_utf8(pair).map_err(js_err)?;
        *slot = u8::from_str_radix(pair, 16).map_err(js_err)?;
    }
    Ok(out)
}

fn frame_string(bytes: Vec<u8>) -> Result<String, JsError> {
    String::from_utf8(bytes).map_err(js_err)
}

/// 生成密码（弹窗的"生成密码"与"新建登录"）。与 Keevo.app 用同一份实现（`keevo-generator`），只在扩展内进行。
///
/// `recipe_json`：
/// - `{"kind":"password","length":20,"digits":true,"symbols":true}`：随机字符，总是含大小写字母；
/// - `{"kind":"passphrase","words":5,"capitalize":false,"number":true}`：口令短语，单词以 `-` 分隔。
///
/// 返回 `{"value":"…","entropy_bits":126.4}`。
///
/// # Errors
/// 格式错误、参数超出范围或随机数不可用时返回错误。
#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password(recipe_json: &str) -> Result<String, JsError> {
    use keevo_generator::{Recipe, generate};
    let v: Value = serde_json::from_str(recipe_json).map_err(js_err)?;
    let flag = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
    let num = |k: &str| {
        v.get(k)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| JsError::new("missing number"))
    };
    let recipe = match v.get("kind").and_then(Value::as_str) {
        Some("password") => Recipe::Password {
            length: num("length")?,
            lowercase: true,
            uppercase: true,
            digits: flag("digits"),
            symbols: flag("symbols"),
            avoid_ambiguous: false,
        },
        Some("passphrase") => Recipe::Passphrase {
            words: num("words")?,
            separator: "-".into(),
            capitalize: flag("capitalize"),
            include_number: flag("number"),
        },
        _ => return Err(JsError::new("unknown recipe")),
    };
    let g = generate(&recipe).map_err(js_err)?;
    Ok(json!({ "value": g.value.as_str(), "entropy_bits": g.entropy_bits }).to_string())
}

/// 扩展一侧的连接。
#[wasm_bindgen]
pub struct KeevoClient {
    inner: ExtensionClient,
}

#[wasm_bindgen]
impl KeevoClient {
    /// 新客户端。`private_key_hex` 为空时生成新的静态密钥（首次配对）。`version` 为空时使用最新的协议版本；
    /// 服务返回 `unsupported_version` 时，用低一个的版本重新连接（`spec/ipc.md` §5.5）。
    ///
    /// # Errors
    /// 私钥格式错误、版本不支持或随机数不可用时返回错误。
    #[wasm_bindgen(constructor)]
    pub fn new(
        private_key_hex: Option<String>,
        origin: &str,
        name: &str,
        version: Option<u32>,
    ) -> Result<Self, JsError> {
        let key = match private_key_hex {
            Some(h) => StaticKeypair::from_private(Zeroizing::new(unhex32(&h)?)),
            None => StaticKeypair::generate().map_err(js_err)?,
        };
        let inner = ExtensionClient::new(key, origin, name);
        let inner = match version {
            Some(v) => inner.with_version(v).map_err(js_err)?,
            None => inner,
        };
        Ok(Self { inner })
    }

    /// 这条连接使用的协议版本。
    #[must_use]
    pub fn version(&self) -> u32 {
        self.inner.version()
    }

    /// 静态私钥（十六进制），用于写入 `chrome.storage.local`。
    #[must_use]
    #[wasm_bindgen(js_name = privateKeyHex)]
    pub fn private_key_hex(&self) -> String {
        hex(self.inner.export_private_key().as_ref())
    }

    /// 清洗后的显示名，与 Keevo.app 中显示的一致（`spec/ipc.md` §4.2）。
    #[must_use]
    #[wasm_bindgen(js_name = displayName)]
    pub fn display_name(raw: &str) -> String {
        sanitize_display_name(raw)
    }

    /// 发给 native host 的第一帧。
    ///
    /// # Errors
    /// 序列化失败时返回错误。
    pub fn hello(&self) -> Result<String, JsError> {
        frame_string(self.inner.hello().map_err(js_err)?)
    }

    /// 开始配对，返回要发送的帧。
    ///
    /// # Errors
    /// 状态不符时返回错误。
    #[wasm_bindgen(js_name = startPairing)]
    pub fn start_pairing(&mut self) -> Result<String, JsError> {
        frame_string(self.inner.start_pairing().map_err(js_err)?)
    }

    /// 用已保存的服务公钥（十六进制）开始会话，返回要发送的帧。
    ///
    /// # Errors
    /// 公钥格式错误或状态不符时返回错误。
    #[wasm_bindgen(js_name = startSession)]
    pub fn start_session(&mut self, service_public_hex: &str) -> Result<String, JsError> {
        let key = unhex32(service_public_hex)?;
        frame_string(self.inner.start_session(&key).map_err(js_err)?)
    }

    /// 发送请求。`call_json` 形如 `{"method":"candidates","params":{"url":"…"}}`。
    /// 返回 `{"id": 1, "frame": "…"}`。
    ///
    /// # Errors
    /// 请求格式错误或会话未建立时返回错误。
    pub fn request(&mut self, call_json: &str) -> Result<String, JsError> {
        let call: Call = serde_json::from_str(call_json).map_err(js_err)?;
        let (id, frame) = self.inner.request(call).map_err(js_err)?;
        Ok(json!({ "id": id, "frame": frame_string(frame)? }).to_string())
    }

    /// 处理收到的一帧。返回 `{"frames": ["…"], "events": [{"type": "…", …}]}`。
    ///
    /// # Errors
    /// 帧格式错误或解密失败时返回错误，连接应断开。
    #[wasm_bindgen(js_name = onFrame)]
    pub fn on_frame(&mut self, frame: &str) -> Result<String, JsError> {
        let (frames, events) = self.inner.on_frame(frame.as_bytes()).map_err(js_err)?;
        let frames: Vec<String> = frames
            .into_iter()
            .map(frame_string)
            .collect::<Result<_, _>>()?;
        let events: Vec<Value> = events
            .into_iter()
            .map(|e| match e {
                // 词与 Keevo.app 中显示的出自同一份词表（spec/sas-wordlist-v1.tsv）
                ClientEvent::ShowSas(sas) => json!({
                    "type": "show_sas",
                    "sas": hex(&sas),
                    "words": sas_words(&sas).map(|w| json!({ "zh": w.zh, "en": w.en })),
                }),
                ClientEvent::Paired { service_public } => {
                    json!({ "type": "paired", "service_public": hex(&service_public) })
                }
                ClientEvent::Established => json!({ "type": "established" }),
                ClientEvent::Message(m) => json!({ "type": "message", "message": m }),
                ClientEvent::Error(code) => json!({ "type": "error", "code": code.as_str() }),
            })
            .collect();
        Ok(json!({ "frames": frames, "events": events }).to_string())
    }
}

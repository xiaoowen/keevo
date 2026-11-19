//! 密码生成器。实现在 `keevo-generator`（浏览器扩展的 WASM 也用它），这里转换错误类型。

use keevo_generator::GeneratorError;
pub use keevo_generator::{
    Generated, PASSPHRASE_WORDS, PASSWORD_LENGTH, PIN_LENGTH, Recipe, WORDLIST_LEN,
};

use crate::error::{CoreError, Result};

impl From<GeneratorError> for CoreError {
    fn from(e: GeneratorError) -> Self {
        match e {
            GeneratorError::OutOfRange => Self::OutOfRange,
            GeneratorError::Crypto(c) => c.into(),
        }
    }
}

/// 按 `recipe` 生成。
///
/// # Errors
/// 参数超出范围或没有选中任何字符类别时返回 [`CoreError::OutOfRange`]；随机数不可用时返回对应错误。
pub fn generate(recipe: &Recipe) -> Result<Generated> {
    keevo_generator::generate(recipe).map_err(Into::into)
}

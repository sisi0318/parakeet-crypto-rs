use crate::crypto::tencent::tail::metadata::{TailParseError, TailParseResult};
use crate::crypto::tencent::tail::parse_android_stag::parse_android_stag;
use crate::crypto::tencent::tail::parse_pc_v1::parse_pc_v1;
use crate::crypto::tencent::tail::parse_pc_v2::parse_pc_v2;

macro_rules! parse_helper {
    ($parser:expr, $data:expr) => {
        let result = $parser($data);
        if result.is_ok() || matches!(result, Err(TailParseError::NeedMoreBytes(_))) {
            return result;
        }
    };
}

pub fn parse(raw: &[u8]) -> Result<TailParseResult, TailParseError> {
    parse_helper!(parse_pc_v2, raw);
    parse_helper!(parse_android_stag, raw);

    // Fallback to the behaviour of V1 parser, the most ambiguous of them all.
    parse_pc_v1(raw)
}

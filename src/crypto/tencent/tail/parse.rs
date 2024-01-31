use super::metadata::{TailParseError, TailParseResult};
use super::parse_pc_v1::parse_pc_v1;
use super::parse_pc_v2::parse_pc_v2;

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

    // Fallback to the behaviour of V1 parser, the most ambiguous of them all.
    parse_pc_v1(raw)
}

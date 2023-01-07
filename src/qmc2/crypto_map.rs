use std::io::{Read, Seek, Write};

use crate::{interfaces::DecryptorError, utils::decrypt_full_stream, QmcV1};

pub fn decrypt_map<R, W>(
    embed_key: &[u8],
    trim_right: usize,
    from: &mut R,
    to: &mut W,
) -> Result<(), DecryptorError>
where
    R: Read + Seek,
    W: Write,
{
    let mut qmc1 = QmcV1::new_map(embed_key).ok_or(DecryptorError::QMCv1InitFailed)?;
    decrypt_full_stream(&mut qmc1, from, to, Some(trim_right))
}

use crate::crypto::ximalaya_pc::{Error, Header};
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as Base64, DecodeError, Engine as _};

type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const STAGE_1_KEY: &[u8; 32] = include_bytes!("data/stage_1.bin");

fn decode_deciphered_content<T: AsRef<[u8]>>(buf: T) -> Result<Vec<u8>, DecodeError> {
    Base64.decode(buf)
}

fn stage_1_decipher<T: AsRef<[u8]>>(buf: T, iv: &[u8; 16]) -> Result<Vec<u8>, Error> {
    let mut temp = Vec::from(buf.as_ref());

    // aes-256-cbc decryption
    let buf = Aes256CbcDec::new(STAGE_1_KEY.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut temp)
        .map_err(Error::Stage1PadError)?;

    decode_deciphered_content(buf).map_err(Error::Stage1CipherDecodeError)
}

fn stage_2_decipher<T: AsRef<[u8]>>(buf: T, key_iv: &[u8; 24]) -> Result<Vec<u8>, Error> {
    let mut temp = Vec::from(buf.as_ref());

    // aes-192-cbc decryption
    let buf = Aes192CbcDec::new(key_iv.into(), key_iv[..16].into())
        .decrypt_padded_mut::<Pkcs7>(&mut temp)
        .map_err(Error::Stage2PadError)?;

    decode_deciphered_content(buf).map_err(Error::Stage2CipherDecodeError)
}

/// Decrypt header
/// `part_2_data` should contain at least `hdr.encrypted_header_len` bytes.
/// Note:
/// - Read & parse header from file
/// - Seek to `hdr.data_start_offset`, read `hdr.encrypted_header_len`.
/// - call `decipher_header` to decrypt.
/// - build the final file:
///   - File header - `hdr.stolen_header_bytes`
///   - Decrypted `part_2_data` after calling this method
///   - Seek to `hdr.data_start_offset + hdr.encrypted_header_len`, copy till EOF.
pub fn decipher_part_2(hdr: &Header, part_2_data: &[u8]) -> Result<Vec<u8>, Error> {
    if part_2_data.len() < hdr.encrypted_header_len {
        Err(Error::InputTooSmall(
            hdr.encrypted_header_len,
            part_2_data.len(),
        ))?;
    }

    let buf = &part_2_data[..hdr.encrypted_header_len];
    let buf = stage_1_decipher(buf, &hdr.stage_1_iv)?;
    let buf = stage_2_decipher(buf, &hdr.stage_2_key)?;
    Ok(buf)
}

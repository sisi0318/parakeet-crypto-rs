use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};

use crate::crypto::byte_offset_cipher::{ByteOffsetDecipher, ByteOffsetEncipher};
use crate::utils::md5;

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct Mode4 {
    slot_key_table: Box<[u8]>,
    file_key_table: Box<[u8]>,
}

const V4_DIGEST_SIZE: usize = 31;
const V4_DIGEST_INDEXES: [usize; V4_DIGEST_SIZE] = [
    0x05, 0x0e, 0x0d, 0x02, 0x0c, 0x0a, 0x0f, 0x0b, //
    0x03, 0x08, 0x05, 0x06, 0x09, 0x04, 0x03, 0x07, //
    0x00, 0x0e, 0x0d, 0x06, 0x02, 0x0c, 0x0a, 0x0f, //
    0x01, 0x0b, 0x08, 0x07, 0x09, 0x04, 0x01,
];

impl Mode4 {
    pub fn new<T: AsRef<[u8]>, T2: AsRef<[u8]>>(slot_key: T, file_key: T2) -> Self {
        let slot_key = Base64.encode(hex::encode(md5(slot_key)));
        let slot_key_salt = include_bytes!("../data/mode4_slot_key_salt.bin");
        let file_key_salt = include_bytes!("../data/mode4_file_key_salt.bin");

        Self {
            slot_key_table: Self::table_expansion(slot_key, slot_key_salt),
            file_key_table: Self::table_expansion(file_key, file_key_salt),
        }
    }

    fn hash_key<T: AsRef<[u8]>>(buffer: T) -> [u8; V4_DIGEST_SIZE] {
        let digest = md5(buffer);
        let digest = V4_DIGEST_INDEXES
            .iter()
            .map(|&idx| digest[idx])
            .collect::<Vec<_>>();
        let mut result = [0u8; V4_DIGEST_SIZE];
        result.copy_from_slice(&digest);
        result
    }

    fn table_expansion<K: AsRef<[u8]>, S: AsRef<[u8]>>(key: K, salt: S) -> Box<[u8]> {
        let key = key.as_ref();
        let salt = salt.as_ref();
        let md5_final = Self::hash_key(key);

        let final_key_size = 4 * (md5_final.len() - 1) * (key.len() - 1);
        let mut expanded_key = Vec::with_capacity(final_key_size);
        for (i, &j) in md5_final.iter().enumerate().skip(1) {
            let temp = (i as u32).wrapping_mul(j as u32);

            for (k, &l) in salt.iter().enumerate().skip(1) {
                let temp = temp.wrapping_mul(k as u32).wrapping_mul(l as u32);
                let bytes = temp.to_le_bytes();

                // (LittleEndian)   0x12345678
                // Memory:  [78] [56] [34] [12]
                //
                //    SHR:   00   08   10   18
                //       = 0x78 0x56 0x34 0x12
                //  Index:    0    1    2    3

                expanded_key.push(bytes[0]); // temp >> 0x00
                expanded_key.push(bytes[3]); // temp >> 0x18
                expanded_key.push(bytes[2]); // temp >> 0x10
                expanded_key.push(bytes[1]); // temp >> 0x08
            }
        }

        expanded_key.into_boxed_slice()
    }

    fn get_key(&self, offset: usize) -> (u8, u8, u8) {
        let n = self.slot_key_table.len();
        let slot_key = self.slot_key_table[offset % n];
        let file_key = self.file_key_table[offset / n];
        let offset_checksum = offset.to_ne_bytes().iter().fold(0, |acc, x| acc ^ x);
        (slot_key, file_key, offset_checksum)
    }
}

impl ByteOffsetEncipher for Mode4 {
    fn encipher_byte(&self, offset: usize, datum: u8) -> u8 {
        let (slot_key, file_key, offset_checksum) = self.get_key(offset);

        let mut datum = datum;
        datum ^= offset_checksum;
        datum ^= slot_key;
        datum ^= datum << 4;
        datum ^= file_key;
        datum
    }
}

impl ByteOffsetDecipher for Mode4 {
    fn decipher_byte(&self, offset: usize, datum: u8) -> u8 {
        let (slot_key, file_key, offset_checksum) = self.get_key(offset);

        let mut datum = datum;
        datum ^= file_key;
        datum ^= datum << 4;
        datum ^= slot_key;
        datum ^= offset_checksum;
        datum
    }
}

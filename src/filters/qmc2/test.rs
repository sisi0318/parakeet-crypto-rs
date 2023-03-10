use std::{
    fs::{self, File},
    path::PathBuf,
};

use crate::filters::{QMC2Map, QMC2Reader, QMCFooterParser, QMC2RC4};

const TEST_KEY_SEED: u8 = 123;
const TEST_KEY_STAGE1: &[u8; 16] = &[
    11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28,
];
const TEST_KEY_STAGE2: &[u8; 16] = &[
    31, 32, 33, 34, 35, 36, 37, 38, 41, 42, 43, 44, 45, 46, 47, 48,
];

fn test_qmc2_file(qmc2_type: &str) {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path_encrypted = d.join(format!("sample/test_qmc2_{}.mgg", qmc2_type));
    let path_source = d.join("sample/test_121529_32kbps.ogg");
    let mut decrypted_content = Vec::new();
    let mut file_encrypted = File::open(path_encrypted).unwrap();
    let source_content = fs::read(path_source.as_path()).unwrap();

    let mut qmc2_map = QMC2Map::new_default();
    let mut qmc2_rc4 = QMC2RC4::new_default();
    let mut parser = QMCFooterParser::new_enc_v2(TEST_KEY_SEED, *TEST_KEY_STAGE1, *TEST_KEY_STAGE2);
    let mut qmc2_decryption_reader = QMC2Reader::new(
        &mut parser,
        &mut qmc2_map,
        &mut qmc2_rc4,
        &mut file_encrypted,
    )
    .unwrap();

    std::io::copy(&mut qmc2_decryption_reader, &mut decrypted_content).unwrap();
    assert_eq!(source_content, decrypted_content, "mismatched content");
}

#[test]
fn test_qmc2_rc4_enc_v2() {
    test_qmc2_file("rc4_EncV2");
}

#[test]
fn test_qmc2_rc4() {
    test_qmc2_file("rc4");
}

#[test]
fn test_qmc2_map() {
    test_qmc2_file("map");
}

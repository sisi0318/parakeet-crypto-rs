use std::{
    fs::{self, File},
    io::copy,
    path::PathBuf,
};

use super::*;

const TEST_SLOT_KEY1: [u8; 4] = *b"09AZ";

fn test_kgm_file(kgm_type: &str) {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path_encrypted = d.join(format!("sample/test_kgm_{}.kgm", kgm_type));
    let path_source = d.join("sample/test_121529_32kbps.ogg");

    let mut decrypted_content = Vec::new();

    let mut file_encrypted = File::open(path_encrypted).unwrap();
    let source_content = fs::read(path_source.as_path()).unwrap();
    let v4_filekey_table = include_bytes!("../../../sample/test_kgm_v4_filekey_table.bin");
    let v4_slotkey_table = include_bytes!("../../../sample/test_kgm_v4_slotkey_table.bin");

    let mut config = KGMCryptoConfig::default();
    config.slot_keys.insert(1, TEST_SLOT_KEY1.into());
    config.v4_file_key_expand_table = v4_filekey_table.to_vec();
    config.v4_slot_key_expand_table = v4_slotkey_table.to_vec();

    let mut kgm_decrypt = super::KugouDecryptReader::new(&config, &mut file_encrypted).unwrap();
    copy(&mut kgm_decrypt, &mut decrypted_content).unwrap();

    assert_eq!(source_content, decrypted_content, "mismatched content");
}

#[test]
fn test_kgm_enc_v2() {
    test_kgm_file("v2");
}

#[test]
fn test_kgm_enc_v3() {
    test_kgm_file("v3");
}

#[test]
fn test_kgm_enc_v4() {
    test_kgm_file("v4");
}

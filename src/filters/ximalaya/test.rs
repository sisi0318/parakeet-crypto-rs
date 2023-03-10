use std::{
    fs::{self, File},
    path::PathBuf,
};

use crate::filters::ximalaya::{XimalayaCrypto, XimalayaReader};

use super::SCRAMBLE_HEADER_LEN;

const TEST_SCRAMBLE_KEY: [u16; 1024] = {
    let scramble_table_bin = include_bytes!("../../../sample/test_xmly_scramble_table.bin");

    // read key from file
    let mut scramble_table = [0u16; SCRAMBLE_HEADER_LEN];

    let mut opt_i = Some(0usize);
    while let Some(i) = opt_i {
        if i >= SCRAMBLE_HEADER_LEN {
            break;
        }

        let hi8 = scramble_table_bin[i * 2 + 1] as u16;
        let lo8 = scramble_table_bin[i * 2] as u16;
        scramble_table[i] = (hi8 << 8) | lo8;

        opt_i = Some(i + 1);
    }

    scramble_table
};

fn test_xmly_file(xmly_type: &str, content_key: &[u8]) {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path_encrypted = d.join(format!("sample/test_xmly.{}", xmly_type));
    let path_source = d.join("sample/test_121529_32kbps.ogg");

    let mut decrypted_content = Vec::new();

    let mut file_encrypted = File::open(path_encrypted).unwrap();
    let source_content = fs::read(path_source.as_path()).unwrap();

    let mut xmly_reader = XimalayaReader::new_decrypt(
        XimalayaCrypto::new(content_key, &TEST_SCRAMBLE_KEY),
        &mut file_encrypted,
    );

    std::io::copy(&mut xmly_reader, &mut decrypted_content).unwrap();

    assert_eq!(source_content, decrypted_content, "mismatched content");
}

#[test]
fn test_x2m() {
    test_xmly_file("x2m", include_bytes!("../../../sample/test_x2m_key.bin"));
}

#[test]
fn test_x3m() {
    test_xmly_file("x3m", include_bytes!("../../../sample/test_x3m_key.bin"));
}

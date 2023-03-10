use std::{
    fs::{self, File},
    io::copy,
    path::PathBuf,
};

use super::{QMC1Static, QMC1StaticReader};

const TEST_KEY128: &[u8; 128] = include_bytes!("__fixture__/test_key_128.bin");

#[test]
fn run_test_qmc1_static() {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path_encrypted = d.join("sample/test_qmc1.qmcogg");
    let path_source = d.join("sample/test_121529_32kbps.ogg");

    let mut file_encrypted = File::open(path_encrypted).unwrap();
    let source_content = fs::read(path_source.as_path()).unwrap();

    let mut qmc1_reader = QMC1StaticReader::new(QMC1Static::new(TEST_KEY128), &mut file_encrypted);
    let mut decrypted_content = vec![0u8; 0];
    copy(&mut qmc1_reader, &mut decrypted_content).unwrap();

    assert_eq!(source_content, decrypted_content, "mismatched content");
}

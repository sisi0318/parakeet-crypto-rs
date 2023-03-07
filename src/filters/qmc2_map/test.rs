use super::QMC2Map;

#[test]
fn test_key_transformation() {
    let result = QMC2Map::to_qmc1_static_key128(include_bytes!("__fixture__/test_key_256.bin"));
    assert_eq!(
        &result,
        include_bytes!("__fixture__/test_key_128.bin"),
        "reduced key128 should match"
    );
}

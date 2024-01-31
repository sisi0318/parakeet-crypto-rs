#[inline]
pub(super) fn map_l(key: &[u8; 128], idx: usize) -> u8 {
    let idx = if idx > 0x7FFF { idx % 0x7FFF } else { idx };
    key[idx & 0x7F]
}

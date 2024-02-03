use crate::crypto::tencent::{QMCv2Map, QMCv2RC4};

pub enum QMCv2 {
    Map(QMCv2Map),
    RC4(QMCv2RC4),
}

/// A wrapper for QMCv2 decryption support
impl QMCv2 {
    pub fn from_key<T: AsRef<[u8]>>(key: T) -> Self {
        let key = key.as_ref();
        if key.len() > 300 {
            QMCv2::RC4(QMCv2RC4::new(key))
        } else {
            QMCv2::Map(QMCv2Map::new(key))
        }
    }

    pub fn decrypt<T: AsMut<[u8]>>(&self, offset: usize, buffer: &mut T) {
        match self {
            Self::Map(d) => d.decrypt(offset, buffer.as_mut()),
            Self::RC4(d) => d.decrypt(offset, buffer.as_mut()),
        }
    }
}

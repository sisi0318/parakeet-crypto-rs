use std::io::{ErrorKind, Read, Seek};

use crate::interfaces::DecryptorError;

use super::{footer::QMCFooterParser, qmc2_stream::QMC2Crypto};

#[derive(Debug)]
enum DecryptionModule {
    Map,
    Rc4,
}

#[derive(Debug)]
pub struct QMC2Reader<'a, R, MAP, RC4>
where
    R: Read + Seek,
    MAP: QMC2Crypto,
    RC4: QMC2Crypto,
{
    new_stream_size: usize,
    qmc2_module: DecryptionModule,
    qmc2_map: &'a mut MAP,
    qmc2_rc4: &'a mut RC4,
    reader: &'a mut R,
}

impl<'a, R, MAP, RC4> QMC2Reader<'a, R, MAP, RC4>
where
    R: Read + Seek,
    MAP: QMC2Crypto,
    RC4: QMC2Crypto,
{
    pub fn new(
        footer_parser: &mut QMCFooterParser,
        qmc2_map: &'a mut MAP,
        qmc2_rc4: &'a mut RC4,
        prev_reader: &'a mut R,
    ) -> Result<Self, DecryptorError> {
        let start_pos = prev_reader.stream_position()?;
        let full_stream_len = prev_reader.seek(std::io::SeekFrom::End(0))?;
        let (footer_len, key) = footer_parser.parse_from_stream(prev_reader)?;
        prev_reader.seek(std::io::SeekFrom::Start(start_pos))?;

        let qmc2_module = if key.len() > 300 {
            qmc2_rc4.set_file_key(&key)?;
            DecryptionModule::Rc4
        } else {
            qmc2_map.set_file_key(&key)?;
            DecryptionModule::Map
        };

        Ok(Self {
            new_stream_size: (full_stream_len as usize) - (start_pos as usize) - footer_len,
            qmc2_module,
            qmc2_map,
            qmc2_rc4,
            reader: prev_reader,
        })
    }
}

impl<R, MAP, RC4> Read for QMC2Reader<'_, R, MAP, RC4>
where
    R: Read + Seek,
    MAP: QMC2Crypto,
    RC4: QMC2Crypto,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let offset = match self.qmc2_module {
            DecryptionModule::Map => self.qmc2_map.get_offset(),
            DecryptionModule::Rc4 => self.qmc2_rc4.get_offset(),
        };

        let buf_len = std::cmp::min(self.new_stream_size - offset, buf.len());
        let buf = &mut buf[..buf_len];
        let read_amount = self.reader.read(buf)?;
        let buf = &mut buf[..read_amount];

        match self.qmc2_module {
            DecryptionModule::Map => self.qmc2_map.transform(buf),
            DecryptionModule::Rc4 => self.qmc2_rc4.transform(buf),
        }
        .map_err(|err| std::io::Error::new(ErrorKind::Other, err))
    }
}

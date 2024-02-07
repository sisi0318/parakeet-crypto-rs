use std::cmp::min;
use std::io::Read;

pub enum StreamControlState {
    Continue,
    Stop,
}

impl<E> From<Option<E>> for StreamControlState {
    fn from(value: Option<E>) -> Self {
        match value {
            Some(_) => Self::Continue,
            None => Self::Stop,
        }
    }
}

impl<T, E> From<Result<T, E>> for StreamControlState {
    fn from(value: Result<T, E>) -> Self {
        match value {
            Ok(_) => Self::Continue,
            Err(_) => Self::Stop,
        }
    }
}

const DEFAULT_CIPHER_BUFFER_LEN: usize = 1024 * 1024;

fn handler_buffer<T, P>(offset: usize, buffer: &mut T, transform: P)
where
    T: AsMut<[u8]> + ?Sized,
    P: Fn(usize, u8) -> u8,
{
    let mut offset = offset;
    for datum in buffer.as_mut() {
        *datum = transform(offset, *datum);
        offset += 1;
    }
}

fn handler_stream_ex<F, R, P>(
    buffer: &mut [u8],
    offset: usize,
    reader: &mut R,
    max_read: Option<usize>,
    transform: P,
    mut write_callback: F,
) -> Result<usize, std::io::Error>
where
    F: FnMut(&[u8]) -> StreamControlState,
    R: Read + ?Sized,
    P: Fn(usize, &mut [u8]),
{
    let mut bytes_processed = 0usize;
    let mut offset = offset;
    loop {
        let block_len = match max_read {
            None => buffer.len(),
            Some(max_read) => min(max_read - bytes_processed, buffer.len()),
        };

        if block_len == 0 {
            break; // Reach max read limit? buffer is empty?
        }
        let read_len = reader.read(&mut buffer[..block_len])?;
        if read_len == 0 {
            break; // EOF?
        }

        let block = &mut buffer[..read_len];
        transform(offset, block);
        match write_callback(block) {
            StreamControlState::Stop => break,
            StreamControlState::Continue => {}
        };

        offset += read_len;
        bytes_processed += read_len;
    }

    Ok(bytes_processed)
}

fn handler_stream<R, P>(
    offset: usize,
    reader: &mut R,
    max_read: Option<usize>,
    transform: P,
) -> Result<(Vec<u8>, usize), std::io::Error>
where
    R: Read + ?Sized,
    P: Fn(usize, &mut [u8]),
{
    let mut result = vec![];
    let mut buffer = vec![0u8; DEFAULT_CIPHER_BUFFER_LEN];
    let n = handler_stream_ex(&mut buffer, offset, reader, max_read, transform, |buf| {
        result.extend(buf);
        StreamControlState::Continue
    })?;
    Ok((result, n))
}

macro_rules! impl_byte_offset_cipher {
    ($name:ident, $byte_method:ident, $buffer_method:ident, $stream_method:ident, $stream_ex_method:ident) => {
        pub trait $name {
            fn $byte_method(&self, offset: usize, datum: u8) -> u8;

            fn $buffer_method<T: AsMut<[u8]> + ?Sized>(&self, offset: usize, buffer: &mut T) {
                handler_buffer(offset, buffer, |offset, datum| {
                    self.$byte_method(offset, datum)
                })
            }

            fn $stream_method<R>(
                &self,
                offset: usize,
                reader: &mut R,
                max_read: Option<usize>,
            ) -> Result<(Vec<u8>, usize), std::io::Error>
            where
                R: Read + ?Sized,
            {
                handler_stream(offset, reader, max_read, |offset, buffer| {
                    self.$buffer_method(offset, buffer)
                })
            }

            fn $stream_ex_method<F, R>(
                &self,
                buffer: &mut [u8],
                offset: usize,
                reader: &mut R,
                max_read: Option<usize>,
                write_callback: F,
            ) -> Result<usize, std::io::Error>
            where
                F: FnMut(&[u8]) -> StreamControlState,
                R: Read + ?Sized,
            {
                handler_stream_ex(
                    buffer,
                    offset,
                    reader,
                    max_read,
                    |offset, buffer| self.$buffer_method(offset, buffer),
                    write_callback,
                )
            }
        }
    };
}

impl_byte_offset_cipher!(
    ByteOffsetEncipher,
    encipher_byte,
    encipher_buffer,
    encipher_stream,
    encipher_stream_ex
);
impl_byte_offset_cipher!(
    ByteOffsetDecipher,
    decipher_byte,
    decipher_buffer,
    decipher_stream,
    decipher_stream_ex
);

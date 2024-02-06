use lazy_static::lazy_static;

pub const SCRAMBLED_HEADER_LEN: usize = 0x400;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Type {
    X2M,
    X3M,
}

pub type ContentKey = [u8; 32];
pub type ScrambleTable = [usize; SCRAMBLED_HEADER_LEN];

pub fn gen_scramble_table<const N: usize>(initial: f64, multiplier: f64) -> [usize; N] {
    let mut scramble_key = [0; N];
    let mut values = [0f64; N];

    let mut value = initial;
    values.iter_mut().for_each(|x| {
        *x = value;
        value = value * multiplier * (1.0 - value);
        debug_assert!(value >= 0.0);
    });

    let mut sorted_values = values;
    sorted_values.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());

    scramble_key
        .iter_mut()
        .zip(values)
        .for_each(|(result, search)| {
            let index = sorted_values.iter().position(|x| *x == search).unwrap();

            // Remove this value from search
            sorted_values[index] = -1.0;
            *result = index;
        });

    scramble_key
}

// X2M for Ximalaya Android (Legacy format)
lazy_static! {
    pub static ref X2M_CONTENT_KEY: ContentKey = {
        let mut result = [0u8; 32];
        result
            .chunks_exact_mut(4)
            .for_each(|chunk| chunk.copy_from_slice(b"xmly"));
        result
    };
    pub static ref X2M_SCRAMBLE_TABLE: ScrambleTable = gen_scramble_table(0.615243, 3.837465);
}

// X3M for Ximalaya Android
lazy_static! {
    pub static ref X3M_CONTENT_KEY: ContentKey = *b"3989d111aad5613940f4fc44b639b292";
    pub static ref X3M_SCRAMBLE_TABLE: ScrambleTable = gen_scramble_table(0.726354, 3.948576);
}

pub fn get_key(key_type: Type) -> (&'static ContentKey, &'static ScrambleTable) {
    match key_type {
        Type::X2M => (&X2M_CONTENT_KEY, &X2M_SCRAMBLE_TABLE),
        Type::X3M => (&X3M_CONTENT_KEY, &X3M_SCRAMBLE_TABLE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scramble_key() {
        let expected = [1, 3, 2, 4, 0];
        assert_eq!(expected, gen_scramble_table(0.334455, 3.998877));
    }
}

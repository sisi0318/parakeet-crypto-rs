pub fn create_scramble_key(scramble_key: &mut [u16], mul_init: f64, mul_step: f64) {
    let mut vec_unsorted = vec![0f64; scramble_key.len()];

    let mut value = mul_init;
    for item in vec_unsorted.iter_mut() {
        *item = value;
        value = value * mul_step * (1.0 - value);
    }

    let mut vec_sorted = vec_unsorted.clone();
    vec_sorted.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());

    for (i, key_item) in scramble_key.iter_mut().enumerate() {
        let search_value = vec_unsorted[i];
        if let Some(scrambled_index) = vec_sorted.iter().position(|&x| x == search_value) {
            *key_item = scrambled_index as u16;

            // When the value duplicates, use the next index.
            // This value cannot be negative.
            vec_sorted[scrambled_index] = -1.0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::create_scramble_key;

    #[test]
    fn test_scramble_key() {
        let mut scramble_key = [0xffffu16; 5];
        let expected = [1u16, 3, 2, 4, 0];
        create_scramble_key(&mut scramble_key, 0.334455, 3.998877);
        assert_eq!(expected, scramble_key);
    }
}

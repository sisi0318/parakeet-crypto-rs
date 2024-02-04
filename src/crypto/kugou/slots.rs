use std::collections::HashMap;

use lazy_static::lazy_static;

lazy_static! {
    static ref KEYS: HashMap<u32, Box<[u8]>> = {
        let mut m = HashMap::new();
        m.insert(1, Box::from(*include_bytes!("./data/slot_01.bin")));
        m
    };
}

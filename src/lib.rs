pub mod helper;
pub mod interfaces;

pub mod kugou;
pub mod qmc2;
pub mod ximalaya;

mod qmc1;
pub use qmc1::QmcV1;

pub(crate) mod utils;

use argh::FromArgs;

use crate::cli::cli_handle_kugou::KugouOptions;
use crate::cli::cli_handle_qmc1::QMC1Options;
use crate::cli::cli_handle_qmc2::QMC2Options;
use crate::cli::cli_handle_ximalaya_android::XimalayaAndroidOptions;

/// Test CLI tool for parakeet_crypto.
#[derive(FromArgs, PartialEq, Debug)]
pub struct ParakeetCLIArgRoot {
    #[argh(subcommand)]
    pub command: ParakeetCryptoName,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
pub enum ParakeetCryptoName {
    ModuleQMC1(QMC1Options),
    ModuleQMC2(QMC2Options),
    ModuleKGM(KugouOptions),
    ModuleXimalayaAndroid(XimalayaAndroidOptions),
}

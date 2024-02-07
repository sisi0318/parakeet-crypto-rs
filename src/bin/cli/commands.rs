use argh::FromArgs;

use crate::cli::*;

/// Test CLI tool for parakeet_crypto.
#[derive(FromArgs, PartialEq, Debug)]
pub struct ParakeetCLIArgRoot {
    #[argh(subcommand)]
    pub command: ParakeetCryptoName,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
pub enum ParakeetCryptoName {
    ModuleQMC1(cli_handle_qmc1::Options),
    ModuleQMC2(cli_handle_qmc2::Options),
    ModuleKGM(cli_handle_kugou::Options),
    ModuleKuwo(cli_handle_kuwo::Options),
    ModuleXimalayaAndroid(cli_handle_ximalaya_android::Options),
}

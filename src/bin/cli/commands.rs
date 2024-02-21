use argh::FromArgs;

use crate::cli::*;

/// Test CLI tool for parakeet_crypto.
#[derive(FromArgs, PartialEq, Debug)]
pub struct CliOptions {
    #[argh(subcommand)]
    pub command: Command,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
pub enum Command {
    TencentQMCv1(cli_handle_qmc1::Options),
    TencentQMCv2(cli_handle_qmc2::Options),
    Kugou(cli_handle_kugou::Options),
    Kuwo(cli_handle_kuwo::Options),
    XimalayaAndroid(cli_handle_ximalaya_android::Options),
    XimalayaPc(cli_handle_ximalaya_pc::Options),
}

# parakeet-crypto-rs

使用 Rust 重新实现 [Parakeet][project_parakeet] 所支持的算法。

## 目前已实现的算法

- QQ 音乐
  - QMCv1 (static_map)
    - `qmcflac` / `qmc3` 等
  - QMCv2 (map / rc4)
    - `mflac` / `mgg` 等 [^qm_mflac]
- 酷狗音乐
  - `kgm` / `vpr`
- 酷我音乐
  - `kwm` / AI 升频 `mflac` [^kuwo_mflac]
- 喜马拉雅
  - 安卓客户端 `x2m` / `x3m` [^x3m]
  - PC 客户端 `xm`

[^qm_mflac]: 安卓需要提取密钥数据库；PC 端需要提供密钥数据库以及解密密钥。
[^kuwo_mflac]: 需要在有特权的安卓设备提取密钥文件: `/data/data/cn.kuwo.player/files/mmkv/cn.kuwo.player.mmkv.defaultconfig`
[^x3m]: 文件名为“乱码”，获取对应名称则需要手动提取数据库进行处理。

## 命令行调用

你可以在项目百科查看[命令行调用][wiki_cli]相关的帮助内容。

## 致谢

部分项目参考了其他人现有的项目，你可以点击下述链接查看：

- [`Presburger/qmc-decoder`](https://github.com/Presburger/qmc-decoder)
- [`nukemiko/libtakiyasha`](https://github.com/nukemiko/libtakiyasha)
- [`unlock-music/cli`](https://github.com/unlock-music/cli)

## 声明

> 我们 "Parakeet-RS 小组" 不支持亦不提倡盗版。
> 我们认为人们能够选择如何享用购买的内容。
> 小鹦鹉软件的使用者应保留解密后的副本仅做个人使用，而非进行二次分发。
> 因使用该软件产生的任何问题都与软件作者无关。
>
> We "Team Parakeet-RS" do not endorse nor encourage piracy.
> We believe that people should have a choice when consuming purchased content.
> Parakeet users should keep their decrypted copies for private use, not to re-distribute them.
> We are not liable for any damage caused by the use of this software.

[project_parakeet]: https://github.com/jixunmoe/parakeet

[wiki_cli]: https://github.com/parakeet-rs/parakeet-crypto-rs/wiki/%E5%91%BD%E4%BB%A4%E8%A1%8C%E8%B0%83%E7%94%A8

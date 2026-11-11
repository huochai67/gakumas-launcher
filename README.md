# Gakumas 公开解密工具与启动器

本目录为公开仓库（`public/`），提供基于已发布版本 Profile 的 `GameAssembly.dll` 离线解密工具、各版本 Profile 以及专用 Rust 启动器。

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `status.json` | 当前游戏版本、更新时间（`updated_at`）、解密状态（`decrypted`: `true`/`false`）、Profile 路径与原始 `packed_sha256` |
| `profile/<version>/` | 对应版本的解密材料（`manifest.json`、`key.bin`、`sbox.bin`、`pass3.bin`、`records.bin`） |
| `decrypt.py` | 使用已发布 Profile 解密 `GameAssembly.dll` 的命令行脚本 |
| `decryptor/` | Profile 解码与可加载 PE 重建模块（`ga_static_decrypt.py`）及稳定导入表清单（`decoded-imports.json`） |
| `launcher/` | 专用 Rust 启动器（登录、下载、脱壳、可选安装 BepInEx、启动游戏），详见 [`launcher/README.md`](launcher/README.md) |
| `.github/workflows/build.yml` | GitHub Actions 工作流：构建 x64 Linux / Windows 启动器（`gakumas-launcher`）与 Windows 原生宿主（`gakumas.exe`） |

## Python 解密工具用法

安装依赖：

```sh
python3 -m pip install -r requirements.txt
```

使用对应版本的 Profile 将加壳的 `GameAssembly.dll` 解密为可加载 DLL：

```sh
python3 decrypt.py /path/to/packed/GameAssembly.dll /path/to/output/GameAssembly.dll \
  --profile profile/<version>
```

脚本会校验输入 `GameAssembly.dll` 的 SHA-256 与 `manifest.json` 中的 `packed_sha256` 及四项材料（`key.bin`、`sbox.bin`、`pass3.bin`、`records.bin`）哈希一致后，执行正文流解码、Stock LibCpp2IL 注册结构注入与 `.idata` 导入表重建，输出可直接加载的 `GameAssembly.dll`。

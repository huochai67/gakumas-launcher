# gakumas-launcher 启动器

《学园偶像大师》（Gakumas）专用命令行启动器（Rust），支持 x64 Windows 与 Linux（通过 Wine 启动）。包含两个二进制目标：

- **`gakumas-launcher`**：命令行启动器，无参数直接运行时自动完成 **登录 → 下载/校验更新 → 使用 Profile 脱壳 → 部署宿主 → 启动游戏** 全流程。
- **`gakumas`（编译为 `gakumas.exe`）**：无完整性壳的自定义 Windows x64 Unity 启动宿主，替换官方 `gakumas.exe` 直接引导脱壳后的 `GameAssembly.dll` 与 `UnityPlayer.dll`。

## 构建

构建启动器 CLI（`gakumas-launcher`）：

```sh
cargo build --release --manifest-path public/launcher/Cargo.toml --bin gakumas-launcher
```

构建 Windows x64 启动宿主（`gakumas.exe`）：

```sh
# Windows (MSVC)
cargo build --release --manifest-path public/launcher/Cargo.toml --target x86_64-pc-windows-msvc --bin gakumas

# Linux 交叉编译 (MinGW-w64)
cargo build --release --manifest-path public/launcher/Cargo.toml --target x86_64-pc-windows-gnu --bin gakumas
```

## 用法

### 1. 一键全流程启动（推荐）

直接运行 `gakumas-launcher`（无需任何子命令）：

```sh
# 自动检测登录状态（未登录则引导登录） -> 下载/校验游戏文件 -> 匹配 Profile 脱壳并部署宿主 -> 启动游戏
gakumas-launcher

# 指定游戏目录与可选安装 BepInEx (Windows x64 IL2CPP zip)
gakumas-launcher --dir /path/to/game --bepinex /path/to/BepInEx-Unity.IL2CPP-win-x64.zip

# 从远端公开仓库自动拉取最新 status.json 与对应版本 Profile
gakumas-launcher --dir /path/to/game --profile-base-url https://raw.githubusercontent.com/<owner>/<repo>/main
```

- 脱壳时自动将原始文件备份为 `GameAssembly.dll.bak` 与 `gakumas.exe.bak`；若后续运行游戏未发生版本更新，启动器会直接复用已脱壳文件跳过重复解密。
- 若未指定 `--profile` 或 `--profile-base-url`，启动器会自动在 `./profile`、`./public/profile` 或可执行文件同级的 `profile/` 目录中按 `packed_sha256` 查找匹配的本地 Profile。

### 2. 分步子命令（可选）

```sh
# 单独登录 / 退出登录
gakumas-launcher login
gakumas-launcher logout

# 仅下载或校验客户端文件（--dry-run 仅列出待更新文件）
gakumas-launcher --dir /path/to/game download --jobs 8
gakumas-launcher --dir /path/to/game download --dry-run

# 仅使用 Profile 解密 GameAssembly.dll
gakumas-launcher --dir /path/to/game --profile public/profile/3.5.3 decrypt

# 下载、脱壳并部署宿主（不启动游戏）
gakumas-launcher --dir /path/to/game --profile public/profile/3.5.3 prepare

# 仅获取 DMM 启动参数并拉起已准备好的游戏（Linux 下通过 --wine / WINEPREFIX 调用 Wine）
gakumas-launcher --dir /path/to/game launch
gakumas-launcher --dir /path/to/game launch --dry-run
```

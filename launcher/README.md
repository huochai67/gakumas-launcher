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

## 数据目录与配置文件（`$HOME/.config/gakumas`）

启动器使用 `$HOME/.config/gakumas` 作为数据与配置目录：

- **`$HOME/.config/gakumas/session.json`**：保存 DMM 登录凭证（`access_token`、`expires_in_seconds`、`stored_at`）。
- **`$HOME/.config/gakumas/config.json`**：可选配置文件，用于设置默认游戏目录、远程 Profile 仓库地址等参数（命令行参数优先级高于 `config.json`）：

```json
{
  "dir": "/path/to/game",
  "profile_base_url": "https://raw.githubusercontent.com/<owner>/<repo>/main",
  "bepinex": "/path/to/BepInEx-Unity.IL2CPP-win-x64.zip",
  "host": "/path/to/gakumas.exe",
  "wine": "wine",
  "wine_prefix": "/path/to/wineprefix"
}
```

（其中 `dir` 也支持别名 `game_dir`，`profile_base_url` 支持别名 `profile_repo` / `profile_url`。）

## 用法

### 1. 一键全流程启动（推荐）

配置好 `$HOME/.config/gakumas/config.json` 后直接运行 `gakumas-launcher`（无需任何参数）：

```sh
# 自动检测登录状态（未登录则引导登录） -> 下载/校验游戏文件 -> 匹配 Profile 脱壳并部署宿主 -> 启动游戏
gakumas-launcher

# 或通过命令行参数指定
gakumas-launcher --dir /path/to/game --profile-base-url https://raw.githubusercontent.com/<owner>/<repo>/main
```

- 脱壳时自动将原始文件备份为 `GameAssembly.dll.bak` 与 `gakumas.exe.bak`；若后续运行游戏未发生版本更新，启动器会直接复用已脱壳文件跳过重复解密。
- 若未指定 `--profile` 或 `profile_base_url`，启动器会自动在 `./profile`、`./public/profile` 或可执行文件同级的 `profile/` 目录中按 `packed_sha256` 查找匹配的本地 Profile。

### 2. 分步子命令（可选）

```sh
# 单独登录 / 退出登录
gakumas-launcher login
gakumas-launcher logout

# 仅下载或校验客户端文件（--dry-run 仅列出待更新文件）
gakumas-launcher download --jobs 8
gakumas-launcher download --dry-run

# 仅使用 Profile 解密 GameAssembly.dll
gakumas-launcher decrypt

# 下载、脱壳并部署宿主（不启动游戏）
gakumas-launcher prepare

# 仅获取 DMM 启动参数并拉起已准备好的游戏
gakumas-launcher launch
gakumas-launcher launch --dry-run
```

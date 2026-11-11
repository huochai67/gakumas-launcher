# gakumas-launcher 启动器

基于 `dmm-cli` 与 `GakumasAuto` 整合的《学园偶像大师》专用命令行启动器（Rust），支持 x64 Windows 与 Linux（通过 Wine 启动）。包含两个二进制目标：

- **`gakumas-launcher`**：命令行启动器，负责 DMM 登录、客户端下载、基于已发布 Profile 的 `GameAssembly.dll` 脱壳、部署宿主、可选安装 BepInEx 以及启动游戏。
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

## 命令行用法

### 1. 登录与查看游戏列表

```sh
# 浏览器登录 DMM 并粘贴回调 URL 或授权码
gakumas-launcher login

# 查看已拥有游戏的 product_id 与 game_type
gakumas-launcher games
gakumas-launcher games --json

# 退出登录并清除本地会话
gakumas-launcher logout
```

本地会话保存在状态目录（Windows 为 `%LOCALAPPDATA%\gakumas`，Linux 为 `$XDG_STATE_HOME/gakumas` 或 `~/.local/state/gakumas`，可通过环境变量 `GAKUMAS_STATE_DIR` 覆盖）。

### 2. 查询清单与下载客户端

```sh
# 输出当前版本与文件列表 JSON
gakumas-launcher --product-id <PRODUCT_ID> --dir /path/to/game manifest

# 下载或校验修复客户端文件
gakumas-launcher --product-id <PRODUCT_ID> --dir /path/to/game download --jobs 8

# 仅检查需要更新的文件列表，不实际下载
gakumas-launcher --product-id <PRODUCT_ID> --dir /path/to/game download --dry-run
```

### 3. 使用 Profile 脱壳与准备运行环境

`decrypt` 和 `prepare` 需要指定本地 `--profile <DIR>` 或公开仓库 raw 根地址 `--profile-base-url <URL>`（自动读取远端 `status.json` 并下载匹配的 Profile）：

```sh
# 仅使用本地或远端 Profile 解密 GameAssembly.dll（原始文件备份为 GameAssembly.dll.bak）
gakumas-launcher --dir /path/to/game --profile public/profile/<version> decrypt
gakumas-launcher --dir /path/to/game --profile-base-url https://raw.githubusercontent.com/<owner>/<repo>/main decrypt

# 下载更新、解密 GameAssembly.dll、部署宿主 gakumas.exe（原始 exe 备份为 gakumas.exe.bak）
gakumas-launcher --product-id <PRODUCT_ID> --dir /path/to/game --profile public/profile/<version> --host /path/to/gakumas.exe prepare

# 可选：同时解压安装 BepInEx (Windows x64 IL2CPP zip)
gakumas-launcher --product-id <PRODUCT_ID> --dir /path/to/game --profile public/profile/<version> --host /path/to/gakumas.exe prepare --bepinex /path/to/BepInEx-Unity.IL2CPP-win-x64.zip
```

当后续再次运行 `download` 或 `prepare` 时，启动器会自动将 `.bak` 备份还原后再与 DMM 清单比对，避免重复下载未变化的原始文件。

### 4. 启动游戏

```sh
# Windows 直接启动
gakumas-launcher --product-id <PRODUCT_ID> --dir C:\Games\gakumas launch

# Linux 通过 Wine 启动
gakumas-launcher --product-id <PRODUCT_ID> --dir /path/to/game --wine wine --wine-prefix /path/to/wineprefix launch

# 仅获取并打印启动命令行，不启动进程
gakumas-launcher --product-id <PRODUCT_ID> --dir /path/to/game launch --dry-run
```

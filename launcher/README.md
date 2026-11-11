# gakumas-launcher 启动器

《学园偶像大师》（Gakumas）专用命令行启动器（Rust），支持 x64 Windows 与 Linux（通过 Wine 启动）。

## 架构特性

- **内置纯 Rust 静态脱壳引擎（`src/decrypt.rs`）**：无需安装 Python 或 `pycryptodome`，直接根据版本 Profile（`key.bin`、`sbox.bin`、`pass3.bin`、`records.bin`）在内存中完成 `GameAssembly.dll` 解密、Il2Cpp 注册结构对齐与 `.idata`/CRT 入口重建。
- **Windows 单二进制自举（`src/host.rs`）**：Windows 下 `gakumas-launcher.exe` 自身内置无壳 Unity 启动宿主逻辑；被复制为游戏目录下的 `gakumas.exe` 启动时会自动进入 Unity 宿主模式（加载 `GameAssembly.dll` 与 `UnityPlayer.dll!UnityMain`），无需额外可执行文件。
- **Linux / Wine 自动获取与缓存宿主 `gakumas.exe`**：按 `--host` → 启动器同级目录 → `$HOME/.config/gakumas/gakumas.exe` 顺序查找；若本地不存在，自动从远程 Profile 仓库对应的 GitHub Release（或 `host_url`）下载并缓存至 `$HOME/.config/gakumas/gakumas.exe`。

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
  "host_url": "https://github.com/<owner>/<repo>/releases/latest/download/gakumas.exe",
  "wine": "wine",
  "wine_prefix": "/path/to/wineprefix"
}
```

（其中 `dir` 兼容别名 `game_dir`，`profile_base_url` 兼容别名 `profile_repo` / `profile_url`。）

## 用法

### 1. 一键全流程启动（推荐）

配置好 `$HOME/.config/gakumas/config.json` 后直接运行 `gakumas-launcher`（无需任何参数）：

```sh
# 自动检测登录状态（未登录则引导登录） -> 下载/校验游戏文件 -> 匹配 Profile 脱壳并部署宿主 -> 启动游戏
gakumas-launcher
```

### 2. 分步子命令（可选）

```sh
gakumas-launcher login
gakumas-launcher logout
gakumas-launcher download --jobs 8
gakumas-launcher decrypt
gakumas-launcher prepare
gakumas-launcher launch
```

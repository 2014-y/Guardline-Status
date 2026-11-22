# Guardline Status (v3.3.1)

软路由全景状态监控、一键无线桥接、双频 Wi‑Fi 管理、环境纯净度体检与分流流量统计桌面控制台。

---

## 一、普通用户直接安装（推荐）

无需安装 Python 或任何开发环境，支持 **Windows 10 / 11 (64 位)**：

1. 直接双击运行压缩包根目录下的 **`Guardline Status-安装包.exe`**。
2. 按向导提示一键完成部署（全程无需管理员权限；若系统缺少微软 Edge WebView2 运行时，安装程序会自动引导补齐）。
3. 首次启动会自动扫描当前局域网内的软路由网关（如 `192.168.89.1` / `192.168.88.1` / `192.168.1.1`），输入软路由后台登录密码即可连接（密码经本机 Windows DPAPI 加密存储，不落明文）。

---

## 二、开发者从源码运行与重新打包

源码位于 `路由器面板-源码` 目录（或本项目 `router-panel` 根目录），环境要求 **Python 3.11+ (Windows x64)**。可以直接双击 **`启动源码版.bat`** 运行源码版，或双击 **`一键打包安装器.bat`** 重新编译打包；也可在终端执行：

```powershell
# 1. 安装依赖
pip install -r requirements.txt

# 2. 直接源码运行桌面面板
python router_panel.py

# 3. 命令行快速连通性自检（可选）
python router_panel.py --check

# 4. 重新编译打包生成单文件安装器「Guardline Status-安装包.exe」
python build_package.py
```

---

## 三、核心目录文件说明

| 文件 | 说明 |
| :--- | :--- |
| `router_panel.py` | 桌面端核心后端（SSH 长连接快慢双频遥测、HTTP/1.1 Keep-Alive 增量通道、DPAPI 加密、SQLite 流量库、系统托盘与环境体检） |
| `ui.html` | 无边框全景前端界面（状态面板、无线桥接、无线管理、代理节点、流量统计、实时连接、终端管控、全局隐私脱敏小眼睛等） |
| `installer_main.py` / `installer_ui.html` | 图形化单文件安装向导（支持 `--silent` 静默升级安装） |
| `build_package.py` | PyInstaller 自动化双阶段构建与桌面安装器打包脚本 |
| `*.woff2` / `icon.*` | 内嵌字体与多分辨率高清应用图标资源 |

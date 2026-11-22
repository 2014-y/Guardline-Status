@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ================================================
echo   Guardline Status (v3.3.1) · 一键编译打包安装器
echo ================================================
python -c "import paramiko, webview, PyInstaller" 2>nul || (
    echo [提示] 正在补齐编译依赖...
    python -m pip install -r requirements.txt
)
python build_package.py
echo.
echo 打包结束！Guardline Status-安装包.exe 已输出到当前目录及桌面。
pause

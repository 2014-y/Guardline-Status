@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -c "import paramiko, webview" 2>nul || (
    echo [提示] 正在首次安装 Python 依赖...
    python -m pip install -r requirements.txt
)
start "" pythonw router_panel.py

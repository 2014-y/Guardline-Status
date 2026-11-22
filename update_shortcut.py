# -*- coding: utf-8 -*-
"""更新桌面快捷方式「Guardline Status.lnk」，使用新图标文件名刷新 Windows 图标缓存。"""
import base64
import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    home = Path(os.environ["LOCALAPPDATA"]) / "RouterPanel"
    home.mkdir(parents=True, exist_ok=True)
    # 清理旧图标并使用全新文件名破除 Windows Explorer 图标缓存
    for old in home.glob("*.ico"):
        try:
            old.unlink()
        except Exception:
            pass
    ico_dst = home / "guardline_v7.ico"
    shutil.copy2(HERE / "icon.ico", ico_dst)

    (home / "launch.pyw").write_text(
        "import runpy\n"
        f"runpy.run_path(r'{HERE / 'router_panel.py'}', run_name='__main__')\n",
        encoding="utf-8",
    )
    pyw = Path(sys.executable).with_name("pythonw.exe")
    ps = f"""
$desk = [Environment]::GetFolderPath('Desktop')
foreach ($oldName in @('TR3000 面板.lnk', '路由器面板.lnk', 'Guardline Panel.lnk')) {{
    $old = Join-Path $desk $oldName
    if (Test-Path $old) {{ Remove-Item $old -Force }}
}}
$lnk = Join-Path $desk 'Guardline Status.lnk'
if (Test-Path $lnk) {{ Remove-Item $lnk -Force }}
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
$s.TargetPath = '{pyw}'
$s.Arguments = '"{home / "launch.pyw"}"'
$s.WorkingDirectory = '{home}'
$s.IconLocation = '{ico_dst},0'
$s.Description = 'Guardline Status — 软路由全景状态与无线桥接终端'
$s.Save()
$c = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
Write-Output ($c.TargetPath + ' | ' + $c.IconLocation)
"""
    enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
                       capture_output=True, text=True, check=True)
    # 通知 Windows Shell 刷新桌面图标缓存
    ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None)
    print(r.stdout.strip().splitlines()[-1])


if __name__ == "__main__":
    main()

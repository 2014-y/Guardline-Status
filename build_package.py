# -*- coding: utf-8 -*-
"""使用 PyInstaller 构建独立版 RouterPanel.exe，并打包生成桌面单文件安装器「Guardline Status-安装包.exe」。"""
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

EXCLUDES = [
    "numpy", "PIL", "tornado", "psutil", "matplotlib",
    "scipy", "pandas", "pytest", "tkinter", "pygments",
]


def build_filtered(spec_dir: Path, dist_dir: Path, work_dir: Path, name: str, script: Path, onefile: bool, datas: list[str]):
    """先生成 .spec 并剔除系统 UCRT/API-Set 兼容桩与无关重型包，再执行 PyInstaller 编译。"""
    cmd_spec = [
        sys.executable, "-m", "PyInstaller.utils.cliutils.makespec",
        "--noconsole",
        "--onefile" if onefile else "--onedir",
        "--name", name,
        "--icon", str(HERE / "icon.ico"),
        "--specpath", str(spec_dir),
    ]
    for d in datas:
        cmd_spec += ["--add-data", d]
    for ex in EXCLUDES:
        cmd_spec += ["--exclude-module", ex]
    cmd_spec.append(str(script))
    print(">>", " ".join(cmd_spec))
    subprocess.run(cmd_spec, cwd=str(HERE), check=True)

    spec_file = spec_dir / f"{name}.spec"
    spec_txt = spec_file.read_text(encoding="utf-8")
    assert "pyz = PYZ(a.pure)" in spec_txt, f"Unexpected spec format in {spec_file}"
    filter_block = (
        "import os as _os\n"
        "_BAD_PFX = ('api-ms-win-', 'ext-ms-win-')\n"
        "a.binaries = [\n"
        "    _b for _b in a.binaries\n"
        "    if _os.path.basename(_b[0]).lower() != 'ucrtbase.dll'\n"
        "    and not _os.path.basename(_b[0]).lower().startswith(_BAD_PFX)\n"
        "]\n"
        "pyz = PYZ(a.pure)"
    )
    spec_file.write_text(spec_txt.replace("pyz = PYZ(a.pure)", filter_block, 1), encoding="utf-8")

    cmd_build = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--distpath", str(dist_dir),
        "--workpath", str(work_dir),
        str(spec_file),
    ]
    print(">>", " ".join(cmd_build))
    subprocess.run(cmd_build, cwd=str(HERE), check=True)


def main():
    BUILD = Path(tempfile.mkdtemp(prefix="rp_pyinst_"))
    try:
        _build_in(BUILD)
    finally:
        shutil.rmtree(BUILD, ignore_errors=True)


def _build_in(BUILD: Path):
    dist_app = BUILD / "dist_app"
    work_app = BUILD / "work_app"
    spec_dir = BUILD / "spec"
    spec_dir.mkdir(parents=True, exist_ok=True)

    # 1. 编译主程序 RouterPanel.exe（--onedir 保证安装后秒开 0.3s 启动）
    build_filtered(
        spec_dir=spec_dir,
        dist_dir=dist_app,
        work_dir=work_app,
        name="RouterPanel",
        script=HERE / "router_panel.py",
        onefile=False,
        datas=[
            f"{HERE / 'ui.html'};.",
            f"{HERE / 'icon.ico'};.",
            f"{HERE / 'icon.png'};.",
            f"{HERE / 'InterVariable-Latin.woff2'};.",
            f"{HERE / 'JetBrainsMono-Latin.woff2'};.",
            f"{HERE / 'JetBrainsMono-Medium.woff2'};.",
        ],
    )

    app_bundle = dist_app / "RouterPanel"
    payload_zip = BUILD / "payload.zip"
    print("Compressing payload.zip ...")
    with zipfile.ZipFile(payload_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for f in app_bundle.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(app_bundle))

    # 2. 编译单文件图形安装器「Guardline Status-安装包.exe」
    dist_inst = BUILD / "dist_inst"
    work_inst = BUILD / "work_inst"
    build_filtered(
        spec_dir=spec_dir,
        dist_dir=dist_inst,
        work_dir=work_inst,
        name="Guardline Status-安装包",
        script=HERE / "installer_main.py",
        onefile=True,
        datas=[
            f"{payload_zip};.",
            f"{HERE / 'installer_ui.html'};.",
            f"{HERE / 'icon.ico'};.",
            f"{HERE / 'icon.png'};.",
            f"{HERE / 'InterVariable-Latin.woff2'};.",
            f"{HERE / 'JetBrainsMono-Latin.woff2'};.",
        ],
    )

    installer_exe = dist_inst / "Guardline Status-安装包.exe"
    # 复制到项目目录和用户桌面（先删除旧文件并刷新 Windows 图标缓存，避免资源管理器缓存旧图标）
    for legacy_here in (HERE / "TR3000 面板-安装包.exe", HERE / "路由器面板-安装包.exe", HERE / "Guardline Panel-安装包.exe"):
        if legacy_here.exists():
            try:
                legacy_here.unlink()
            except Exception:
                pass
    shutil.copy2(installer_exe, HERE / "Guardline Status-安装包.exe")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", "[Environment]::GetFolderPath('Desktop')"],
                       capture_output=True, text=True, check=True)
    desk = Path(r.stdout.strip())
    for legacy_desk in (desk / "TR3000 面板-安装包.exe", desk / "路由器面板-安装包.exe", desk / "Guardline Panel-安装包.exe"):
        if legacy_desk.exists():
            try:
                legacy_desk.unlink()
            except PermissionError:
                subprocess.run(["taskkill", "/F", "/T", "/IM", legacy_desk.name],
                               capture_output=True, creationflags=0x08000000)
                import time
                time.sleep(0.6)
                legacy_desk.unlink()
    desk_installer = desk / "Guardline Status-安装包.exe"
    if desk_installer.exists():
        try:
            desk_installer.unlink()
        except PermissionError:
            subprocess.run(["taskkill", "/F", "/T", "/IM", "Guardline Status-安装包.exe"],
                           capture_output=True, creationflags=0x08000000)
            import time
            time.sleep(0.6)
            desk_installer.unlink()
    shutil.copy2(installer_exe, desk_installer)
    try:
        import ctypes
        sh = ctypes.windll.shell32
        sh.SHChangeNotify(0x00002000, 0x0005, ctypes.c_wchar_p(str(desk_installer)), None)
        sh.SHChangeNotify(0x00008000, 0x0003, ctypes.byref(ctypes.c_int(-1)), None)
        sh.SHChangeNotify(0x08000000, 0x0000, None, None)
        subprocess.Popen(["ie4uinit.exe", "-show"], creationflags=0x08000000)
    except Exception:
        pass
    print(f"SUCCESS: {desk_installer} ({desk_installer.stat().st_size / 1048576:.1f} MB)")


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""Guardline Status Windows 现代化无边框安装向导（支持图形向导与 --silent 静默安装）。"""
import base64
import ctypes
import ctypes.wintypes
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import winreg
import zipfile
from pathlib import Path

RES = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
PAYLOAD = RES / "payload.zip"
ICON_ICO = RES / "icon.ico"
ICON_PNG = RES / "icon.png"
UI_HTML = RES / "installer_ui.html"

APP_NAME = "Guardline Status"
LEGACY_APP_NAMES = ("TR3000 面板", "路由器面板", "Guardline Panel")
APP_VERSION = "3.3.2"
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\RouterPanel"
DEFAULT_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Programs" / "RouterPanel"


def _installed_version() -> str:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as k:
            v, _ = winreg.QueryValueEx(k, "DisplayVersion")
            return str(v or "").strip()
    except Exception:
        return ""


def _payload_size() -> int:
    try:
        if PAYLOAD.exists():
            with zipfile.ZipFile(PAYLOAD, "r") as zf:
                return sum(int(m.file_size or 0) for m in zf.infolist())
    except Exception:
        pass
    return 0


def _free_bytes(path_str: str) -> int:
    try:
        p = Path((path_str or "").strip() or str(DEFAULT_DIR))
        try:
            p = p.resolve(strict=False)
        except Exception:
            pass
        for cand in (p, *p.parents):
            if cand.exists():
                return int(shutil.disk_usage(cand).free)
        if p.drive:
            root = Path(p.drive + "\\")
            if root.exists():
                return int(shutil.disk_usage(root).free)
    except Exception:
        pass
    return -1


def _data_uri(path: Path, mime: str) -> str:
    if not path.exists():
        return ""
    return f"data:{mime};base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def create_shortcut(lnk_path: Path, target: Path, workdir: Path, icon: Path, desc: str):
    """创建桌面/开始菜单快捷方式；若精简系统禁用 PowerShell 则回退至 VBScript。"""
    try:
        ps = f"""
$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{lnk_path}')
$s.TargetPath = '{target}'
$s.WorkingDirectory = '{workdir}'
$s.IconLocation = '{icon},0'
$s.Description = '{desc}'
$s.Save()
"""
        enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
                       capture_output=True, check=True, creationflags=0x08000000)
        return
    except Exception as e:
        print("shortcut ps fallback:", e)
    vbs_path = None
    try:
        import tempfile
        esc = lambda v: str(v).replace('"', '""')
        vbs = (
            'Set s = CreateObject("WScript.Shell").CreateShortcut("' + esc(lnk_path) + '")\n'
            's.TargetPath = "' + esc(target) + '"\n'
            's.WorkingDirectory = "' + esc(workdir) + '"\n'
            's.IconLocation = "' + esc(icon) + ',0"\n'
            's.Description = "' + esc(desc) + '"\n'
            's.Save\n'
        )
        with tempfile.NamedTemporaryFile("w", suffix=".vbs", encoding="mbcs", delete=False) as tf:
            tf.write(vbs)
            vbs_path = tf.name
        subprocess.run(["cscript", "//Nologo", vbs_path], capture_output=True, check=True, creationflags=0x08000000)
    except Exception as e:
        print("shortcut vbs fallback failed:", e)
    finally:
        if vbs_path:
            try:
                os.unlink(vbs_path)
            except Exception:
                pass


def register_uninstall(install_dir: Path, exe_path: Path):
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as k:
            winreg.SetValueEx(k, "DisplayName", 0, winreg.REG_SZ, "Guardline Status")
            winreg.SetValueEx(k, "DisplayIcon", 0, winreg.REG_SZ, f"{exe_path},0")
            winreg.SetValueEx(k, "DisplayVersion", 0, winreg.REG_SZ, APP_VERSION)
            winreg.SetValueEx(k, "Publisher", 0, winreg.REG_SZ, "Guardline")
            winreg.SetValueEx(k, "InstallLocation", 0, winreg.REG_SZ, str(install_dir))
            uninst = (
                f'powershell -NoProfile -WindowStyle Hidden -Command "'
                f"Stop-Process -Name RouterPanel -Force -ErrorAction SilentlyContinue; Start-Sleep 1; "
                f"Remove-Item '{install_dir}' -Recurse -Force; "
                f"Remove-Item \\\"$([Environment]::GetFolderPath('Desktop'))\\{APP_NAME}.lnk\\\" -Force -ErrorAction SilentlyContinue; "
                f"Remove-Item \\\"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\{APP_NAME}.lnk\\\" -Force -ErrorAction SilentlyContinue; "
                f"Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'GuardlineStatus' -ErrorAction SilentlyContinue; "
                f"Remove-Item 'HKCU:\\{UNINSTALL_KEY}' -Force -ErrorAction SilentlyContinue\""
            )
            winreg.SetValueEx(k, "UninstallString", 0, winreg.REG_SZ, uninst)
            winreg.SetValueEx(k, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "NoRepair", 0, winreg.REG_DWORD, 1)
    except Exception:
        pass


def _kill_running():
    """关闭正在运行的旧版面板并等待释放文件句柄。"""
    for _ in range(20):
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq RouterPanel.exe", "/NH"],
                           capture_output=True, creationflags=0x08000000)
        if b"RouterPanel.exe" not in (r.stdout or b""):
            return
        subprocess.run(["taskkill", "/F", "/T", "/IM", "RouterPanel.exe"],
                       capture_output=True, creationflags=0x08000000)
        time.sleep(0.45)


def _extract_with_retry(zf, member, dest):
    for _ in range(10):
        try:
            zf.extract(member, dest)
            return
        except PermissionError:
            _kill_running()
            time.sleep(0.55)
    zf.extract(member, dest)


def do_install(install_dir: Path, make_desktop: bool = True, progress_cb=None, make_start_menu: bool = True) -> Path:
    if progress_cb:
        progress_cb(6, "正在关闭正在运行的旧版本", "")
    _kill_running()
    install_dir.mkdir(parents=True, exist_ok=True)
    if not PAYLOAD.exists():
        raise FileNotFoundError(f"未找到安装包组件：{PAYLOAD}")

    old_internal = install_dir / "_internal"
    if old_internal.exists():
        for _ in range(8):
            try:
                shutil.rmtree(old_internal)
                break
            except PermissionError:
                _kill_running()
                time.sleep(0.5)
        else:
            shutil.rmtree(old_internal, ignore_errors=True)

    with zipfile.ZipFile(PAYLOAD, "r") as zf:
        members = zf.infolist()
        total = max(1, len(members))
        last_cb = 0.0
        for i, m in enumerate(members, 1):
            _extract_with_retry(zf, m, install_dir)
            if progress_cb:
                now = time.monotonic()
                if i == total or (now - last_cb) >= 0.05:
                    last_cb = now
                    pct = 8 + int(i * 82 / total)
                    progress_cb(pct, "正在复制文件", m.filename)

    exe_path = install_dir / "RouterPanel.exe"
    for old_ico in install_dir.glob("guardline_router_v*.ico"):
        try:
            old_ico.unlink()
        except Exception:
            pass
    ico_v = install_dir / "guardline_router_v7.ico"
    if ICON_ICO.exists():
        shutil.copy2(ICON_ICO, ico_v)
    else:
        ico_v = exe_path

    if progress_cb:
        progress_cb(93, "正在创建快捷方式", "")

    if make_desktop:
        desk_ps = "[Environment]::GetFolderPath('Desktop')"
        r = subprocess.run(["powershell", "-NoProfile", "-Command", desk_ps],
                           capture_output=True, text=True, creationflags=0x08000000)
        desk = Path(r.stdout.strip() or (Path.home() / "Desktop"))
        for nm in (*LEGACY_APP_NAMES, APP_NAME):
            old_lnk = desk / f"{nm}.lnk"
            if old_lnk.exists():
                try:
                    old_lnk.unlink()
                except Exception:
                    pass
        lnk = desk / f"{APP_NAME}.lnk"
        create_shortcut(lnk, exe_path, install_dir, ico_v, "Guardline Status — 软路由全景状态与无线桥接终端")

    if make_start_menu:
        start_menu = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs"
        if start_menu.exists():
            for nm in (*LEGACY_APP_NAMES, APP_NAME):
                old_sm = start_menu / f"{nm}.lnk"
                if old_sm.exists():
                    try:
                        old_sm.unlink()
                    except Exception:
                        pass
            create_shortcut(start_menu / f"{APP_NAME}.lnk", exe_path, install_dir, ico_v,
                            "Guardline Status — 软路由全景状态与无线桥接终端")

    if progress_cb:
        progress_cb(97, "正在注册应用", "")
    register_uninstall(install_dir, exe_path)
    ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None)
    ctypes.windll.shell32.SHChangeNotify(0x00008000, 0x0003, ctypes.byref(ctypes.c_int(-1)), None)
    if progress_cb:
        progress_cb(100, "安装完成", "")
    return exe_path


class InstallerApi:
    def __init__(self):
        self._win = None
        self._dragging = False
        self._installed_exe: Path | None = None
        self._installed_dir: Path | None = None

    def init_info(self):
        return {
            "default_dir": str(DEFAULT_DIR),
            "exists": (DEFAULT_DIR / "RouterPanel.exe").exists(),
            "installed_version": _installed_version(),
            "version": APP_VERSION,
            "required_bytes": _payload_size(),
            "free_bytes": _free_bytes(str(DEFAULT_DIR)),
            "debug_page": os.environ.get("RP_INSTALLER_PAGE", ""),
        }

    def disk_info(self, dir_str: str):
        try:
            p = Path((dir_str or "").strip() or str(DEFAULT_DIR))
            ex = (p / "RouterPanel.exe").exists()
        except Exception:
            ex = False
        return {"free_bytes": _free_bytes(dir_str), "exists": ex}

    def check_existing(self, dir_str: str):
        try:
            p = Path((dir_str or "").strip() or str(DEFAULT_DIR))
            return (p / "RouterPanel.exe").exists()
        except Exception:
            return False

    def pick_folder(self, current: str = ""):
        if not self._win:
            return None
        import webview
        start_dir = (current or "").strip() or str(DEFAULT_DIR.parent)
        if not os.path.isdir(start_dir):
            start_dir = str(Path.home())
        res = self._win.create_file_dialog(webview.FOLDER_DIALOG, directory=start_dir)
        if res and len(res) > 0:
            chosen = Path(res[0])
            if chosen.name.lower() != "routerpanel":
                chosen = chosen / "RouterPanel"
            return str(chosen)
        return None

    def start_install(self, dir_str: str, make_desk: bool = True, make_start: bool = True, launch_after: bool = True):
        target_dir = Path((dir_str or "").strip() or str(DEFAULT_DIR))

        def push(pct: int, msg: str, state: str = "running", detail: str = ""):
            if not self._win:
                return
            try:
                js = (
                    f"window.__onInstallProgress("
                    f"{json.dumps(int(pct))}, {json.dumps(msg)}, {json.dumps(state)}, {json.dumps(detail)})"
                )
                self._win.evaluate_js(js)
            except Exception:
                pass

        def worker():
            try:
                exe = do_install(
                    target_dir,
                    make_desktop=bool(make_desk),
                    progress_cb=lambda p, m, d="": push(p, m, "running", d),
                    make_start_menu=bool(make_start),
                )
                self._installed_exe = exe
                self._installed_dir = target_dir
                push(100, "安装完成", "done", "")
            except Exception as e:
                push(0, str(e), "error", "")

        threading.Thread(target=worker, daemon=True).start()
        return True

    def finish_and_exit(self, launch: bool = True):
        if launch and self._installed_exe and self._installed_exe.exists():
            try:
                subprocess.Popen([str(self._installed_exe)], cwd=str(self._installed_dir))
            except Exception:
                pass
        if self._win:
            self._win.destroy()
        return True

    def win_min(self):
        if self._win:
            self._win.minimize()
        return True

    def win_close(self):
        if self._win:
            self._win.destroy()
        return True

    def win_start_drag(self):
        if not self._win or self._dragging:
            return False
        hwnd = int(self._win.native.Handle.ToInt64())
        u32 = ctypes.windll.user32
        vk = 0x02 if u32.GetSystemMetrics(23) else 0x01
        if not (u32.GetAsyncKeyState(vk) & 0x8000):
            return False
        pt0 = ctypes.wintypes.POINT()
        rc0 = ctypes.wintypes.RECT()
        u32.GetCursorPos(ctypes.byref(pt0))
        u32.GetWindowRect(ctypes.c_void_p(hwnd), ctypes.byref(rc0))

        def _loop():
            self._dragging = True
            try:
                moving = False
                last = (pt0.x, pt0.y)
                pt = ctypes.wintypes.POINT()
                while u32.GetAsyncKeyState(vk) & 0x8000:
                    u32.GetCursorPos(ctypes.byref(pt))
                    cur = (pt.x, pt.y)
                    if not moving:
                        if abs(pt.x - pt0.x) + abs(pt.y - pt0.y) < 3:
                            time.sleep(0.005)
                            continue
                        moving = True
                    if cur != last:
                        last = cur
                        u32.SetWindowPos(
                            ctypes.c_void_p(hwnd), None,
                            rc0.left + pt.x - pt0.x,
                            rc0.top + pt.y - pt0.y,
                            0, 0, 0x4015,
                        )
                    time.sleep(0.004)
            finally:
                self._dragging = False

        threading.Thread(target=_loop, daemon=True).start()
        return True


def _center_native_form(win, margin: int = 24):
    """在窗口显示前（GUI 线程内）把窗口精确居中到鼠标所在显示器的工作区，并在超出时自动缩小，兼容多屏/150% 缩放。"""
    try:
        from System.Windows.Forms import FormStartPosition
        from System.Drawing import Point, Size
        form = win.native
        u32 = ctypes.windll.user32

        class _MI(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.wintypes.DWORD), ("rcMonitor", ctypes.wintypes.RECT),
                        ("rcWork", ctypes.wintypes.RECT), ("dwFlags", ctypes.wintypes.DWORD)]

        pt = ctypes.wintypes.POINT()
        u32.GetCursorPos(ctypes.byref(pt))
        u32.MonitorFromPoint.restype = ctypes.c_void_p
        hmon = u32.MonitorFromPoint(pt, 1)  # MONITOR_DEFAULTTOPRIMARY
        mi = _MI()
        mi.cbSize = ctypes.sizeof(_MI)
        if not u32.GetMonitorInfoW(ctypes.c_void_p(hmon), ctypes.byref(mi)):
            return
        wa = mi.rcWork
        # 目标显示器 DPI 与窗口当前 DPI 不同（例如副屏 100%）时，WinForms 会在移动后按比例缩放窗口，提前换算
        mdpi = ctypes.c_uint(96)
        _y = ctypes.c_uint(96)
        try:
            ctypes.windll.shcore.GetDpiForMonitor(ctypes.c_void_p(hmon), 0, ctypes.byref(mdpi), ctypes.byref(_y))
        except Exception:
            pass
        try:
            wdpi = u32.GetDpiForWindow(ctypes.c_void_p(int(form.Handle.ToInt64()))) or 96
        except Exception:
            wdpi = 96
        ratio = (mdpi.value or 96) / float(wdpi)
        work_w, work_h = wa.right - wa.left, wa.bottom - wa.top
        w = int(form.Size.Width * ratio)
        h = int(form.Size.Height * ratio)
        max_w, max_h = work_w - 2 * margin, work_h - 2 * margin
        if w > max_w or h > max_h:
            w, h = min(w, max_w), min(h, max_h)
            mw, mh = form.MinimumSize.Width, form.MinimumSize.Height
            form.MinimumSize = Size(min(mw, int(w / ratio)), min(mh, int(h / ratio)))
            form.Size = Size(int(w / ratio), int(h / ratio))
        x = wa.left + max(0, (work_w - w) // 2)
        y = wa.top + max(0, (work_h - h) // 2)
        form.StartPosition = FormStartPosition.Manual
        form.Location = Point(int(x), int(y))
    except Exception as e:
        print("center window:", e)


def _is_webview_painted(hwnd: int) -> bool:
    """用 PrintWindow 采样 4x4 网格，确认 WebView2 已绘制多色 UI 像素而非纯底色。"""
    g = bmp = None
    try:
        from System.Drawing import Bitmap, Graphics
        u32 = ctypes.windll.user32
        r = ctypes.wintypes.RECT()
        if not u32.GetWindowRect(ctypes.c_void_p(hwnd), ctypes.byref(r)):
            return False
        w, h = r.right - r.left, r.bottom - r.top
        if w < 120 or h < 120:
            return False
        bmp = Bitmap(w, h)
        g = Graphics.FromImage(bmp)
        hdc = g.GetHdc()
        try:
            u32.PrintWindow(ctypes.c_void_p(hwnd), ctypes.c_void_p(int(hdc.ToInt64())), 2)
        finally:
            g.ReleaseHdc(hdc)
        colors = set()
        for ix in range(4):
            sx = min(w - 20, max(20, int(w * (0.12 + 0.25 * ix))))
            for iy in range(4):
                sy = min(h - 20, max(20, int(h * (0.12 + 0.25 * iy))))
                c = bmp.GetPixel(sx, sy)
                colors.add((c.R, c.G, c.B))
                if len(colors) >= 4:
                    return True
        return False
    except Exception:
        return False
    finally:
        if g is not None:
            try:
                g.Dispose()
            except Exception:
                pass
        if bmp is not None:
            try:
                bmp.Dispose()
            except Exception:
                pass


def _bind_splashless_reveal(win):
    """在 before_show 阶段设 alpha=1（99.6% 透明，避免 GPU 判遮挡停绘），待首帧绘制就绪再显形。"""
    state = {"hwnd": 0, "revealed": False}
    lock = threading.Lock()
    u32 = ctypes.windll.user32
    GWL_EXSTYLE = -20
    WS_EX_LAYERED = 0x00080000
    LWA_ALPHA = 0x2

    def on_before_show():
        _center_native_form(win)
        try:
            hwnd = int(win.native.Handle.ToInt64())
            state["hwnd"] = hwnd
            ex = u32.GetWindowLongW(ctypes.c_void_p(hwnd), GWL_EXSTYLE)
            u32.SetWindowLongW(ctypes.c_void_p(hwnd), GWL_EXSTYLE, ex | WS_EX_LAYERED)
            u32.SetLayeredWindowAttributes(ctypes.c_void_p(hwnd), 0, 1, LWA_ALPHA)
        except Exception:
            pass

    def reveal():
        with lock:
            if state["revealed"]:
                return
            state["revealed"] = True
        hwnd = state["hwnd"]
        if not hwnd:
            try:
                hwnd = int(win.native.Handle.ToInt64())
            except Exception:
                return
        try:
            u32.SetLayeredWindowAttributes(ctypes.c_void_p(hwnd), 0, 255, LWA_ALPHA)
            ex = u32.GetWindowLongW(ctypes.c_void_p(hwnd), GWL_EXSTYLE)
            u32.SetWindowLongW(ctypes.c_void_p(hwnd), GWL_EXSTYLE, ex & ~WS_EX_LAYERED)
            u32.RedrawWindow(ctypes.c_void_p(hwnd), None, None, 0x0585)
            u32.SetForegroundWindow(ctypes.c_void_p(hwnd))
        except Exception:
            pass

    def wait_and_reveal():
        hwnd = state["hwnd"]
        if not hwnd:
            try:
                hwnd = int(win.native.Handle.ToInt64())
                state["hwnd"] = hwnd
            except Exception:
                hwnd = 0
        for _ in range(44):
            if state["revealed"]:
                return
            if hwnd and _is_webview_painted(hwnd):
                break
            time.sleep(0.025)
        reveal()

    win.events.before_show += on_before_show
    win.events.shown += lambda: (
        _setup_native_window(win),
        threading.Timer(1.8, reveal).start(),
    )
    win.events.loaded += lambda: threading.Thread(target=wait_and_reveal, daemon=True).start()


def _setup_native_window(win):
    try:
        hwnd = int(win.native.Handle.ToInt64())
        u32 = ctypes.windll.user32
        GWL_STYLE = -16
        WS_MINIMIZEBOX = 0x00020000
        WS_SYSMENU = 0x00080000
        style = u32.GetWindowLongW(ctypes.c_void_p(hwnd), GWL_STYLE)
        u32.SetWindowLongW(ctypes.c_void_p(hwnd), GWL_STYLE, style | WS_MINIMIZEBOX | WS_SYSMENU)
        val = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(ctypes.c_void_p(hwnd), 20, ctypes.byref(val), 4)
        # Windows 11 原生圆角窗口属性 (DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2)
        corner = ctypes.c_int(2)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(ctypes.c_void_p(hwnd), 33, ctypes.byref(corner), 4)
        if ICON_ICO.exists():
            u32.LoadImageW.restype = ctypes.c_void_p
            for size, which in ((16, 0), (32, 0), (48, 1), (256, 1)):
                h = u32.LoadImageW(None, str(ICON_ICO), 1,
                                   size if which == 0 else 0,
                                   size if which == 0 else 0,
                                   0x10 | (0x40 if which else 0))
                if h:
                    u32.SendMessageW(ctypes.c_void_p(hwnd), 0x80, which, ctypes.c_void_p(h))
    except Exception:
        pass


def _has_webview2_runtime() -> bool:
    guid = r"{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    for root, sub in (
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{guid}"),
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{guid}"),
        (winreg.HKEY_CURRENT_USER, rf"Software\Microsoft\EdgeUpdate\Clients\{guid}"),
    ):
        try:
            with winreg.OpenKey(root, sub) as k:
                v, _ = winreg.QueryValueEx(k, "pv")
                if v and v != "0.0.0.0":
                    return True
        except Exception:
            pass
    return False


def ensure_webview2_runtime() -> bool:
    """若目标电脑为缺少 WebView2 的精简版 Win10，提供一键自动下载微软官方运行时或直接静默安装。"""
    if _has_webview2_runtime():
        return True
    import urllib.request
    ans = ctypes.windll.user32.MessageBoxW(
        None,
        "检测到当前电脑尚未安装微软 Edge WebView2 渲染组件。\n\n点击「是」将自动为您下载补齐官方组件并继续图形安装；\n点击「否」将直接为您一键快速安装 Guardline Status。",
        "Guardline Status 安装向导",
        0x00000004 | 0x00000040,
    )
    if ans == 6:
        try:
            bs = Path(os.environ.get("TEMP", ".")) / "MicrosoftEdgeWebview2Setup.exe"
            urllib.request.urlretrieve("https://go.microsoft.com/fwlink/p/?LinkId=2124703", str(bs))
            subprocess.run([str(bs), "/silent", "/install"], check=False)
            if _has_webview2_runtime():
                return True
        except Exception as e:
            print("webview2 install failed:", e)
    # 兜底保底：即使断网或取消 UAC 无法拉取 WebView2，也能直接完成程序安装！
    exe = do_install(DEFAULT_DIR, make_desktop=True)
    ctypes.windll.user32.MessageBoxW(None, f"Guardline Status 已安装至：\n{exe.parent}", "安装完成", 0x40)
    return False


def run_wizard():
    if not ensure_webview2_runtime():
        return
    try:
        import webview
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Guardline.RouterPanel.Installer.v3")
        except Exception:
            pass
        api = InstallerApi()
        html = (
            UI_HTML.read_text("utf-8")
            .replace("__ICON_DATA_URI__", _data_uri(ICON_PNG, "image/png"))
            .replace("__FONT_INTER__", _data_uri(RES / "InterVariable-Latin.woff2", "font/woff2"))
            .replace("__FONT_MONO_400__", _data_uri(RES / "JetBrainsMono-Latin.woff2", "font/woff2"))
        )
        win = webview.create_window(
            "Guardline Status 安装向导",
            html=html,
            js_api=api,
            width=840,
            height=546,
            resizable=False,
            frameless=True,
            easy_drag=False,
            shadow=True,
            background_color="#141416",
            text_select=False,
        )
        api._win = win
        _bind_splashless_reveal(win)
        webview.start(icon=str(ICON_ICO) if ICON_ICO.exists() else None)
    except Exception:
        import traceback
        traceback.print_exc()
        ans = ctypes.windll.user32.MessageBoxW(
            None,
            "当前系统缺少图形界面运行组件，是否直接为您一键完成安装？",
            "Guardline Status 安装向导",
            0x00000004 | 0x00000030,
        )
        if ans == 6:
            try:
                exe = do_install(DEFAULT_DIR, make_desktop=True)
                ctypes.windll.user32.MessageBoxW(None, f"Guardline Status 已安装至：\n{exe.parent}", "安装完成", 0x40)
            except Exception as e2:
                ctypes.windll.user32.MessageBoxW(None, f"安装失败：{e2}", "Guardline 安装向导", 0x10)


if __name__ == "__main__":
    if sys.stderr is None or sys.stdout is None:
        try:
            _log = open(Path(os.environ.get("TEMP", ".")) / "RouterPanel-installer.log", "a", encoding="utf-8", buffering=1)
            if sys.stdout is None:
                sys.stdout = _log
            if sys.stderr is None:
                sys.stderr = _log
        except Exception:
            pass
    if "--silent" in sys.argv:
        try:
            exe = do_install(DEFAULT_DIR, make_desktop=True)
            print("Installed:", exe)
        except Exception as e:
            log = Path(os.environ.get("TEMP", ".")) / "RouterPanel-install.log"
            log.write_text(f"install failed: {e!r}\n", "utf-8")
            sys.exit(1)
    else:
        run_wizard()

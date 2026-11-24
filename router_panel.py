# -*- coding: utf-8 -*-
"""路由器桌面面板（软路由旗舰版）—— 支持多网关自动发现、自定义账号密码登录、一键无线桥接与 OpenClash 全景监控。

运行：  pythonw router_panel.py
自检：  python router_panel.py --check
界面：  ui.html（pywebview / Edge WebView2 无边框全景窗口渲染）
密码使用 Windows DPAPI 加密保存在 %APPDATA%\\RouterPanel\\config.json，仅当前 Windows 账户可解密。
无线桥接仅操作 wwan 上游接口，全程绝不触碰 OpenClash 配置、分流规则及出口防护。
"""
import base64
import calendar
from concurrent.futures import ThreadPoolExecutor
import contextlib
import csv
import ctypes
import ctypes.wintypes
import datetime
import http.server
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
import winreg
from collections import deque
from pathlib import Path

import paramiko

HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
APP_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "RouterPanel"
CFG_PATH = APP_DIR / "config.json"
KNOWN_HOSTS = APP_DIR / "known_hosts"
TRAFFIC_DB = APP_DIR / "traffic.db"
ICON = HERE / "icon.ico"
ICON_PNG = HERE / "icon.png"

FAST_INTERVAL = 2.0      # 秒：网速 / CPU / 内存 / 无线终端 / 代理连接
SLOW_EVERY = 8           # 每 N 次快速刷新做一次完整刷新（约 16 秒）
SECTION_RE = re.compile(r"^[A-Za-z0-9_]+$")


# ----------------------------------------------------------------- DPAPI 加密
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, encrypt: bool) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    inp = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = _Blob()
    fn = ctypes.windll.crypt32.CryptProtectData if encrypt else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("DPAPI 加解密失败")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def protect(s: str) -> str:
    return base64.b64encode(_dpapi(s.encode("utf-8"), True)).decode()


def unprotect(s: str) -> str:
    return _dpapi(base64.b64decode(s), False).decode("utf-8")


def load_cfg() -> dict:
    try:
        return json.loads(CFG_PATH.read_text("utf-8"))
    except Exception:
        return {}


def save_cfg(cfg: dict):
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CFG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), "utf-8")


RUN_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_REG_NAME = "GuardlineStatus"


def _autostart_cmd() -> str:
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        return f'"{exe}" --autostart'
    py_exe = Path(sys.executable).resolve()
    pyw = py_exe.with_name("pythonw.exe")
    runner = pyw if pyw.exists() else py_exe
    script = Path(__file__).resolve()
    return f'"{runner}" "{script}" --autostart'


def is_autostart_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_KEY, 0, winreg.KEY_READ) as k:
            val, _ = winreg.QueryValueEx(k, RUN_REG_NAME)
            return bool(str(val or "").strip())
    except Exception:
        return False


def apply_autostart(enabled: bool) -> bool:
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_REG_KEY) as k:
            if enabled:
                winreg.SetValueEx(k, RUN_REG_NAME, 0, winreg.REG_SZ, _autostart_cmd())
            else:
                try:
                    winreg.DeleteValue(k, RUN_REG_NAME)
                except FileNotFoundError:
                    pass
        return bool(enabled)
    except Exception as e:
        print("apply_autostart failed:", e)
        return is_autostart_enabled()


def icon_data_uri() -> str:
    p = ICON_PNG if ICON_PNG.exists() else (HERE / "icon_96.png")
    if p.exists():
        return "data:image/png;base64," + base64.b64encode(p.read_bytes()).decode("ascii")
    return ""


def font_data_uri(filename: str) -> str:
    p = HERE / filename
    if p.exists():
        return "data:font/woff2;base64," + base64.b64encode(p.read_bytes()).decode("ascii")
    return ""


# ----------------------------------------------------------------- 软路由网关自动发现 & UBUS 登录验证
def parse_host_port(raw: str, default_port: int = 22) -> tuple[str, int]:
    raw = (raw or "").strip()
    raw = re.sub(r"^https?://", "", raw).split("/")[0].strip()
    if ":" in raw and raw.count(":") == 1:
        h, p = raw.rsplit(":", 1)
        if p.isdigit() and 1 <= int(p) <= 65535:
            return h.strip(), int(p)
    return raw, int(default_port or 22)


def _win_default_gateways() -> list[str]:
    gws = []
    try:
        r = subprocess.run(["route", "print", "-4"], capture_output=True,
                           timeout=3, creationflags=0x08000000)
        txt = (r.stdout or b"").decode("ascii", "ignore")
        for line in txt.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gw = parts[2]
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", gw) and gw not in gws:
                    gws.append(gw)
    except Exception:
        pass
    # 根据本机网卡网段补充 `.1` 候选网关
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip.startswith(("192.168.", "10.", "172.")):
                cand = ip.rsplit(".", 1)[0] + ".1"
                if cand not in gws:
                    gws.append(cand)
    except Exception:
        pass
    return gws


def _probe_gateway(ip: str, is_default: bool) -> dict | None:
    ssh_ok = False
    try:
        with socket.create_connection((ip, 22), timeout=0.65):
            ssh_ok = True
    except Exception:
        pass
    title = ""
    is_openwrt = False
    for path in ("/cgi-bin/luci/", "/"):
        try:
            req = urllib.request.Request(f"http://{ip}{path}", headers={"User-Agent": "RouterPanel/3"})
            with urllib.request.urlopen(req, timeout=0.8) as resp:
                body = resp.read(8192).decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            try:
                body = e.read(8192).decode("utf-8", "ignore")
            except Exception:
                body = ""
        except Exception:
            body = ""
        if body:
            m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
            if m:
                title = m.group(1).split("|")[0].split("-")[0].strip()
            if any(k in body.lower() for k in ("luci", "openwrt", "guardline", "istoreos", "immortalwrt")):
                is_openwrt = True
            if title:
                break
    if not (ssh_ok or is_openwrt or is_default):
        return None
    return {"host": ip, "title": title or ("软路由网关" if is_openwrt else "默认网关"),
            "is_default": is_default, "openwrt": is_openwrt, "ssh": ssh_ok}


def detect_gateways() -> list[dict]:
    defaults = _win_default_gateways()
    cands = list(defaults)
    for common in ("192.168.88.1", "192.168.89.1", "192.168.1.1", "192.168.5.1", "192.168.31.1", "10.0.0.1"):
        if common not in cands:
            cands.append(common)
    out = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(_probe_gateway, ip, ip in defaults) for ip in cands[:10]]
        for f in futs:
            try:
                r = f.result()
                if r and (r["ssh"] or r["openwrt"] or r["is_default"]):
                    out.append(r)
            except Exception:
                pass
    out.sort(key=lambda x: (not x["is_default"], not x["openwrt"], not x["ssh"], x["host"]))
    return out


def verify_ubus_web_login(host: str, username: str, password: str) -> bool:
    """兼容仅在 OpenWrt rpcd/LuCI 中修改了登录账号名（而系统 SSH 底层仍为 root 同密码）的软路由。"""
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "call",
        "params": ["00000000000000000000000000000000", "session", "login",
                   {"username": username, "password": password}],
    }).encode("utf-8")
    for scheme in ("http", "https"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/ubus", data=payload,
                                         headers={"Content-Type": "application/json"})
            ctx = None
            if scheme == "https":
                import ssl
                ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                res = json.loads(resp.read().decode("utf-8", "ignore"))
                code_and_data = res.get("result") or []
                if len(code_and_data) >= 2 and code_and_data[0] == 0 and code_and_data[1].get("ubus_rpc_session"):
                    return True
        except Exception:
            continue
    return False


# ----------------------------------------------------------------- SSH 连接
class _TrustOnLoginPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, allow_replace: bool = False):
        self.allow_replace = allow_replace

    def missing_host_key(self, client, hostname, key):
        client.get_host_keys().add(hostname, key.get_name(), key)
        APP_DIR.mkdir(parents=True, exist_ok=True)
        client.save_host_keys(str(KNOWN_HOSTS))


class Router:
    def __init__(self, host, user, password, port=22, ssh_user=None, trust_new_key=False):
        self.host = host
        self.port = int(port or 22)
        self.user = user                 # 界面展示的登录用户名
        self.ssh_user = ssh_user or user # 实际 SSH 认证用户名
        self.password = password
        self.trust_new_key = trust_new_key
        self.cli = None
        self.lock = threading.Lock()

    def _connect(self):
        c = paramiko.SSHClient()
        if KNOWN_HOSTS.exists() and not self.trust_new_key:
            c.load_host_keys(str(KNOWN_HOSTS))
        c.set_missing_host_key_policy(_TrustOnLoginPolicy(self.trust_new_key))
        try:
            c.connect(self.host, port=self.port, username=self.ssh_user, password=self.password,
                      timeout=8, banner_timeout=8, auth_timeout=8, look_for_keys=False, allow_agent=False)
        except paramiko.BadHostKeyException:
            if not self.trust_new_key:
                raise
            # 用户主动登录新刷机/换机的同 IP 软路由时，更新该 IP 指纹
            hk = c.get_host_keys()
            hk.clear()
            c.connect(self.host, port=self.port, username=self.ssh_user, password=self.password,
                      timeout=8, banner_timeout=8, auth_timeout=8, look_for_keys=False, allow_agent=False)
        self.trust_new_key = False
        c.get_transport().set_keepalive(15)
        self.cli = c

    def close(self):
        try:
            if self.cli:
                self.cli.close()
        except Exception:
            pass
        self.cli = None

    def run(self, cmd, timeout=20, stdin_data=None):
        with self.lock:
            t = self.cli.get_transport() if self.cli else None
            if not t or not t.is_active():
                self.close()
                self._connect()
            try:
                sin, out, err = self.cli.exec_command(cmd, timeout=timeout)
                if stdin_data is not None:
                    raw = stdin_data.encode("utf-8") if isinstance(stdin_data, str) else stdin_data
                    sin.channel.sendall(raw)
                    sin.channel.shutdown_write()
                data = out.read().decode("utf-8", "replace")
                edata = err.read().decode("utf-8", "replace")
                return out.channel.recv_exit_status(), data, edata
            except Exception:
                self.close()
                raise


# ----------------------------------------------------------------- 采集脚本
CLASH_API = r"""
S=$(uci -q get openclash.config.dashboard_password); P=$(uci -q get openclash.config.cn_port)
c_alive() { pidof clash clash_meta mihomo >/dev/null 2>&1; }
capi() { c_alive && curl -s -m 4 -H "Authorization: Bearer $S" "http://127.0.0.1:${P:-9090}$1"; }
"""

FAST_CMD = CLASH_API + r"""
echo @@NETDEV; cat /proc/net/dev
echo @@STAT; head -n1 /proc/stat
echo @@MEM; head -n5 /proc/meminfo
echo @@LOAD; cat /proc/loadavg
echo @@UPTIME; cat /proc/uptime
echo @@TEMP; cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null
echo @@CONNTRACK; cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null
echo @@BRSTATE; cat /tmp/rp_bridge.state 2>/dev/null
echo @@GATE; if [ ! -x /etc/openclash/custom/ipguard.sh ]; then echo none; elif [ -f /tmp/ipguard.open ]; then echo open; elif [ -d /tmp/ipguard.run ]; then echo checking; else echo closed; fi
echo @@IPGUARD; cat /tmp/ipguard.last 2>/dev/null
for o in $(ubus list 'hostapd.*' 2>/dev/null); do echo "@@HOSTAPD ${o#hostapd.}"; ubus call "$o" get_clients 2>/dev/null; done
echo @@NFTCNT; nft list counters table inet rp_traffic 2>/dev/null
echo @@RPTSTATE; cat /tmp/rp_traffic/prev.state 2>/dev/null
echo @@CLASHCONN; capi /connections
echo
echo @@END
"""

SLOW_CMD = CLASH_API + r"""
PF="/tmp/rp_ping.$$"
( ping -c1 -W1 223.5.5.5 2>&1 | tail -n1 > "$PF" ) &
CP=$(uci -q get openclash.config.config_path); CP=${CP:-/etc/openclash/config/sub.yaml}
echo @@BOARD; ubus call system board
echo @@IFACES; ubus call network.interface dump
echo @@WIRELESS; ubus call network.wireless status
echo @@LEASES; cat /tmp/dhcp.leases 2>/dev/null
echo @@NEIGH; ip neigh show dev br-lan
for i in $(iwinfo 2>/dev/null | awk '/ESSID/{print $1}'); do echo "@@IWINFO $i"; iwinfo "$i" info; done
echo @@CLASH; if [ -x /etc/init.d/openclash ]; then if c_alive; then echo running; else echo stopped; fi; else echo none; fi
echo @@MACFILTER; uci -q show wireless | grep -E '\.(macfilter|maclist)='
echo @@UCIWIFI; uci -q show wireless
echo @@CLASHVER; capi /version
echo
echo @@CLASHCFG; capi /configs
echo
echo @@CLASHPROXIES; capi /proxies
echo
echo @@CLASHRULES
RM=$(date -r "$CP" +%s 2>/dev/null)
if [ -n "$RM" ] && [ -f /tmp/rp_rcnt ] && [ "$(head -n1 /tmp/rp_rcnt 2>/dev/null)" = "$RM" ]; then
  tail -n1 /tmp/rp_rcnt 2>/dev/null
else
  RC=$(capi /rules | tr '{' '\n' | grep -c '"proxy":')
  [ -n "$RM" ] && [ "${RC:-0}" -gt 0 ] 2>/dev/null && printf "%s\n%s\n" "$RM" "$RC" > /tmp/rp_rcnt
  echo "${RC:-0}"
fi
echo @@CLASHUCI; uci -q get openclash.config.en_mode; echo "$CP"
echo @@CLASHSUB
echo "sub_url=$(uci -q get openclash.@config_subscribe[0].address)"
echo "sub_name=$(uci -q get openclash.@config_subscribe[0].name)"
echo "sub_ua=$(uci -q get openclash.@config_subscribe[0].sub_ua)"
echo "cfg_path=$CP"
echo "cfg_mtime=$(date -r "$CP" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
echo "cfg_size=$(wc -c < "$CP" 2>/dev/null | tr -d ' ')"
echo "guardline=$([ -x /usr/sbin/guard-unlock ] && [ -f /etc/openclash/custom/mainland-policy.rb ] && echo 1 || echo 0)"
echo "expected_ip=$(sed -n 's/^EXPECTED=//p' /etc/openclash/custom/ipguard.sh 2>/dev/null | head -n1)"
echo "seal_gen=$(cat /etc/guard-seal/CURRENT 2>/dev/null)"
echo @@IPV6OFF; cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null
echo @@USBNET; for n in /sys/class/net/*; do d=$(basename "$n"); readlink -f "$n/device" 2>/dev/null | grep -q '/usb' && echo "$d"; done
echo @@RPBLOCK; cat /etc/rp_traffic/blocked_macs.txt 2>/dev/null
echo @@UCINET; uci -q show network.lan; uci -q show network.wan; uci -q show network.wwan
echo @@UCIDHCP; uci -q show dhcp.lan
wait
echo @@PING; cat "$PF" 2>/dev/null; rm -f "$PF"
echo @@END
"""


def split_sections(text):
    secs, cur, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith("@@"):
            if cur:
                secs.setdefault(cur[0], []).append((cur[1], "\n".join(buf)))
            name, _, arg = line[2:].partition(" ")
            cur, buf = (name, arg.strip()), []
        else:
            buf.append(line)
    if cur:
        secs.setdefault(cur[0], []).append((cur[1], "\n".join(buf)))
    return secs


def _one(secs, name):
    return secs.get(name, [("", "")])[0][1]


def _json(s, default):
    try:
        return json.loads(s)
    except Exception:
        return default


def parse_fast(text):
    s = split_sections(text)
    ipg_raw = _one(s, "IPGUARD").strip()
    ipg = {}
    if ipg_raw:
        m_ip = re.search(r"\bip=([^\s]+)", ipg_raw)
        m_exp = re.search(r"\bexpected=([^\s]+)", ipg_raw)
        m_grp = re.search(r"\bgroup=([^\s]+)", ipg_raw)
        m_lock = re.search(r"\blocked=(\d)", ipg_raw)
        parts = m_ip.group(1).split("/") if m_ip else []
        probes = [x for x in parts if x and x not in ("-", "none")]
        expected = m_exp.group(1) if m_exp else ""
        uniq = []
        for x in probes:
            if x not in uniq:
                uniq.append(x)
        wrong = [x for x in uniq if expected and x != expected]
        matched = sum(1 for x in probes if expected and x == expected)
        if wrong:
            exit_ip = max(wrong, key=lambda z: probes.count(z))
        else:
            exit_ip = probes[0] if probes else expected
        if wrong:
            reason = "mismatch"
        elif not probes:
            reason = "no_data"
        else:
            reason = ""
        ipg = {
            "exit_ip": exit_ip,
            "expected": expected,
            "probe_ips": uniq,
            "mismatch": bool(wrong),
            "reason": reason,
            "locked": bool(m_lock and m_lock.group(1) == "1"),
            "probes_ok": matched if expected else len(probes),
            "probes_total": len(parts) if parts else 5,
            "group": m_grp.group(1) if m_grp else "",
            "time": ipg_raw[:19] if len(ipg_raw) >= 19 else "",
        }
    r = {"t": time.time(), "netdev": {}, "cpu": None, "mem": {}, "load": [], "uptime": 0,
         "temp": None, "conntrack": None, "clients": {}, "clash_conn": None,
         "br_state": _one(s, "BRSTATE").strip(), "gate": _one(s, "GATE").strip(), "ipguard": ipg}
    for line in _one(s, "NETDEV").splitlines()[2:]:
        if ":" in line:
            name, rest = line.split(":", 1)
            f = rest.split()
            if len(f) >= 9:
                r["netdev"][name.strip()] = (int(f[0]), int(f[8]))
    try:
        r["cpu"] = [int(x) for x in _one(s, "STAT").split()[1:]]
    except Exception:
        pass
    for line in _one(s, "MEM").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            try:
                r["mem"][k.strip()] = int(v.split()[0])
            except Exception:
                pass
    r["load"] = _one(s, "LOAD").split()[:3]
    try:
        r["uptime"] = float(_one(s, "UPTIME").split()[0])
    except Exception:
        pass
    t = _one(s, "TEMP").strip()
    if t.lstrip("-").isdigit():
        r["temp"] = int(t) / 1000
    c = _one(s, "CONNTRACK").strip()
    if c.isdigit():
        r["conntrack"] = int(c)
    for ifn, body in s.get("HOSTAPD", []):
        r["clients"][ifn] = {k.lower(): v for k, v in _json(body, {}).get("clients", {}).items()}
    nft_raw = _one(s, "NFTCNT")
    if nft_raw:
        cnts = {}
        cur_nm = ""
        for ln in nft_raw.splitlines():
            p = ln.split()
            if len(p) >= 2 and p[0] == "counter":
                cur_nm = p[1]
            elif cur_nm and len(p) >= 4 and p[0] == "packets" and p[2] == "bytes" and p[3].isdigit():
                cnts[cur_nm] = int(p[3])
                cur_nm = ""
        if cnts:
            r["nft_cnt"] = (
                cnts.get("rx_proxy", 0),
                cnts.get("tx_proxy", 0),
                cnts.get("rx_direct", 0),
                cnts.get("tx_direct", 0),
            )
    rpt_prev = _one(s, "RPTSTATE").split()
    if len(rpt_prev) >= 4 and all(x.isdigit() for x in rpt_prev[:4]):
        r["rpt_prev"] = tuple(int(x) for x in rpt_prev[:4])
    r["clash_conn"] = _json(_one(s, "CLASHCONN").strip(), None)
    return r


def parse_iwinfo(body):
    d = {}
    for key, pat in [("essid", r'ESSID: "(.*)"'), ("bssid", r"Access Point: ([0-9A-Fa-f:]{17})"),
                     ("mode", r"Mode: (\S+)"), ("channel", r"Channel: (\d+)"),
                     ("htmode", r"HT Mode: (\S+)"), ("signal", r"Signal: (-?\d+) dBm"),
                     ("bitrate", r"Bit Rate: (.+)"), ("txpower", r"Tx-Power: (\d+) dBm"),
                     ("quality", r"Link Quality: (\S+)")]:
        m = re.search(pat, body)
        if m:
            d[key] = m.group(1).strip()
    return d


def parse_slow(text):
    s = split_sections(text)
    csub = {}
    for line in _one(s, "CLASHSUB").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            csub[k.strip()] = v.strip()
    r = {"board": _json(_one(s, "BOARD"), {}),
         "ifaces": _json(_one(s, "IFACES"), {}).get("interface", []),
         "wireless": _json(_one(s, "WIRELESS"), {}),
         "leases": [], "neigh": {}, "iwinfo": {}, "ping": None, "clash": None, "macfilter": {},
         "clash_ver": _json(_one(s, "CLASHVER").strip(), {}),
         "clash_cfg": _json(_one(s, "CLASHCFG").strip(), {}),
         "clash_proxies": _json(_one(s, "CLASHPROXIES").strip(), {}).get("proxies", {}),
         "clash_rules": int(_one(s, "CLASHRULES").strip()) if _one(s, "CLASHRULES").strip().isdigit() else 0,
         "clash_uci": _one(s, "CLASHUCI").split(),
         "clash_sub": csub,
         "ipv6_off": _one(s, "IPV6OFF").strip() == "1",
         "usb_net": set(_one(s, "USBNET").split()),
         "rp_blocked": {
             ln.strip().lower()
             for ln in _one(s, "RPBLOCK").splitlines()
             if re.match(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$", ln.strip())
         },
         "uci_wifi": parse_uci_show(_one(s, "UCIWIFI"), "wireless"),
         "uci_net": parse_uci_show(_one(s, "UCINET"), "network"),
         "uci_dhcp": parse_uci_show(_one(s, "UCIDHCP"), "dhcp")}
    for line in _one(s, "LEASES").splitlines():
        f = line.split()
        if len(f) >= 4:
            r["leases"].append({"mac": f[1].lower(), "ip": f[2], "host": "" if f[3] == "*" else f[3]})
    for line in _one(s, "NEIGH").splitlines():
        f = line.split()
        if "lladdr" in f:
            r["neigh"][f[f.index("lladdr") + 1].lower()] = (f[0], f[-1])
    for ifn, body in s.get("IWINFO", []):
        r["iwinfo"][ifn] = parse_iwinfo(body)
    m = re.search(r"= [\d.]+/([\d.]+)/", _one(s, "PING"))
    r["ping"] = float(m.group(1)) if m else None
    r["clash"] = _one(s, "CLASH").strip() or None
    for line in _one(s, "MACFILTER").splitlines():
        m = re.match(r"wireless\.([^.]+)\.(macfilter|maclist)=(.*)", line)
        if m:
            sec, key, val = m.groups()
            d = r["macfilter"].setdefault(sec, {"macfilter": "", "maclist": []})
            vals = [v.lower() for v in re.findall(r"'([^']*)'", val)] or [val]
            d["macfilter" if key == "macfilter" else "maclist"] = vals[0] if key == "macfilter" else vals
    return r


def ap_list(slow):
    """从 UCI 读取全部本机发射 AP（含已临时关闭的频段），并补充运行时接口状态。"""
    slow = slow or {}
    uci = slow.get("uci_wifi") or {}
    if uci:
        runtime = {}
        for radio, rd in (slow.get("wireless") or {}).items():
            for itf in rd.get("interfaces", []):
                runtime[itf.get("section")] = (itf.get("ifname"), rd)
        out = []
        for sec, d in uci.items():
            if d.get(".type") != "wifi-iface" or d.get("mode") != "ap":
                continue
            radio = d.get("device", "")
            r_uci = uci.get(radio) or {}
            band = r_uci.get("band", "")
            cfg = {
                "ssid": d.get("ssid", ""),
                "encryption": d.get("encryption", "psk2"),
                "key": d.get("key", ""),
                "hidden": str(d.get("hidden", "0")) == "1",
                "disabled": str(d.get("disabled", "0")) == "1" or str(r_uci.get("disabled", "0")) == "1",
                "device": radio,
            }
            ifname, rd = runtime.get(sec, (None, (slow.get("wireless") or {}).get(radio, {})))
            out.append((sec, ifname, band, radio, cfg, rd))
        if out:
            return out
    out = []
    for radio, rd in (slow.get("wireless") or {}).items():
        band = rd.get("config", {}).get("band", "")
        for itf in rd.get("interfaces", []):
            cfg = itf.get("config", {})
            if cfg.get("mode") == "ap":
                out.append((itf.get("section"), itf.get("ifname"), band, radio, cfg, rd))
    return out


def parse_uci_show(text, pkg):
    """解析 `uci show <pkg>` 输出为 {section: {".type": t, opt: 值或列表}}，保持原顺序。"""
    secs = {}
    for line in (text or "").splitlines():
        m = re.match(rf"^{pkg}\.([^.=]+)(?:\.([^=]+))?=(.*)$", line.strip())
        if not m:
            continue
        sec, opt, raw = m.groups()
        vals = re.findall(r"'((?:[^']|'\\'')*)'", raw)
        vals = [v.replace("'\\''", "'") for v in vals] or [raw]
        d = secs.setdefault(sec, {})
        if opt is None:
            d[".type"] = vals[0]
        else:
            d[opt] = vals[0] if len(vals) == 1 else vals
    return secs


def sta_list(slow):
    """从 UCI 读取全部 STA（含已禁用的），并补充运行时接口名。
    注意：netifd 的 network.wireless status 不会列出已禁用接口，不能只靠它判断。"""
    slow = slow or {}
    uci = slow.get("uci_wifi") or {}
    runtime = {}
    for radio, rd in slow.get("wireless", {}).items():
        for itf in rd.get("interfaces", []):
            runtime[itf.get("section")] = (itf.get("ifname"), rd)
    out = []
    for sec, d in uci.items():
        if d.get(".type") != "wifi-iface" or d.get("mode") != "sta":
            continue
        radio = d.get("device", "")
        band = (uci.get(radio) or {}).get("band", "")
        net = d.get("network", "")
        cfg = {"ssid": d.get("ssid", ""), "encryption": d.get("encryption", "none"), "key": d.get("key", ""),
               "disabled": d.get("disabled", "0") == "1", "network": net if isinstance(net, list) else [net],
               "device": radio}
        ifname, rd = runtime.get(sec, (None, slow.get("wireless", {}).get(radio, {})))
        out.append((sec, ifname, band, radio, cfg, rd))
    return out


def _legacy_sta_list(slow):
    out = []
    for radio, rd in (slow or {}).get("wireless", {}).items():
        band = rd.get("config", {}).get("band", "")
        for itf in rd.get("interfaces", []):
            cfg = itf.get("config", {})
            if cfg.get("mode") == "sta":
                out.append((itf.get("section"), itf.get("ifname"), band, radio, cfg, rd))
    return out


def band_name(b):
    return {"2g": "2.4G", "5g": "5G", "6g": "6G", "60g": "60G", 2: "2.4G", 5: "5G", 6: "6G"}.get(b, str(b or "?"))


def local_ips():
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    return ips


IFACE_LABEL = {"wan": "有线 WAN", "wwan": "无线桥接", "wan6": "IPv6 WAN", "lan": "局域网"}
GROUP_TYPES = {"Selector", "URLTest", "Fallback", "LoadBalance", "Relay", "Smart"}
BUILTIN_TYPES = {"Direct", "Reject", "RejectDrop", "Pass", "PassRule", "Compatible", "Dns"}
PROTO_NAME = {"Vless": "VLESS", "Vmess": "VMess", "Trojan": "Trojan", "Shadowsocks": "SS", "ShadowsocksR": "SSR",
              "Hysteria": "Hysteria", "Hysteria2": "Hysteria2", "Tuic": "TUIC", "AnyTLS": "AnyTLS",
              "WireGuard": "WireGuard", "Socks5": "SOCKS5", "Http": "HTTP", "Snell": "Snell", "Ssh": "SSH"}
GROUP_NAME = {"Selector": "手动选择", "URLTest": "自动测速", "Fallback": "故障转移", "LoadBalance": "负载均衡",
              "Relay": "链式代理", "Smart": "智能策略"}


def node_history(p):
    hist = p.get("history") or []
    if not hist:
        for v in (p.get("extra") or {}).values():
            if v.get("history"):
                hist = v["history"]
                break
    return hist


def node_delay(p):
    hist = node_history(p)
    return None if not hist else hist[-1].get("delay", 0)


def node_region(name):
    n = re.sub(r"[\U0001F1E6-\U0001F1FF]", "", name).strip()
    m = re.match(r"([^\d\s\-_|·]+)", n)
    return m.group(1) if m else "其他"


def pad_series(seq, min_len=24):
    lst = list(seq)
    if not lst:
        return [(0, 0)] * min_len
    if len(lst) < min_len:
        return [(0, 0)] * (min_len - len(lst)) + lst
    return lst


def normalize_scan_signal(sig, qual, qual_max):
    """修复部分 MT7981 驱动近距离 >0dBm 时溢出为 -254 或偏高的问题，返回 (dBm, 0~100 质量百分比)。"""
    qpct = int(round((qual or 0) * 100 / max(1, qual_max or 70)))
    qpct = max(0, min(100, qpct))
    if sig is None or sig < -115 or sig > -20:
        sig = int(-92 + qpct * 0.60)
    return max(-96, min(-25, int(sig))), qpct


def parse_scan_encryption(enc: dict) -> tuple[str, str]:
    """将 iwinfo scan 的加密结构转为 (uci_encryption, 友好说明)。"""
    if not enc or not enc.get("enabled"):
        return "none", "开放免密"
    auth = [a.lower() for a in (enc.get("authentication") or [])]
    wpa = enc.get("wpa") or []
    if "8021x" in auth or "eap" in auth:
        return "eap", "企业认证 (802.1X)"
    if "sae" in auth and "psk" not in auth:
        return "sae", "WPA3"
    if 2 in wpa and 3 in wpa:
        return "psk2", "WPA2 / WPA3"
    if 2 in wpa:
        return "psk2", "WPA2"
    if 1 in wpa:
        return "psk", "WPA"
    return "psk2", "WPA2"


def _iw_escape_ssid(ssid: str) -> str:
    """生成与 Linux `iw dev <if> link` (print_ssid_escaped) 完全一致的十六进制转义字符串，兼容中文/Emoji/首尾空格/反斜杠。"""
    raw = (ssid or "").encode("utf-8")
    out = []
    n = len(raw)
    for i, b in enumerate(raw):
        if 0x21 <= b <= 0x7E and b != 0x5C:
            out.append(chr(b))
        elif b == 0x20 and 0 < i < n - 1:
            out.append(" ")
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


_CDN_NETS = [ipaddress.ip_network(x) for x in (
    "104.16.0.0/12", "172.64.0.0/13", "173.245.48.0/20", "108.162.192.0/18",
    "190.93.240.0/20", "198.41.128.0/17", "162.158.0.0/15", "188.114.96.0/20",
    "197.234.240.0/22", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14",
    "3.160.0.0/11", "143.204.0.0/16", "52.84.0.0/15", "99.84.0.0/16",
    "205.251.192.0/19",
)]
_FAKEIP_NET = ipaddress.ip_network("198.18.0.0/15")
_UDP_PROXY_TYPES = {"hysteria", "hysteria2", "tuic", "wireguard"}


def _is_valid_ipv4(s: str, public_only: bool = False) -> bool:
    try:
        ip = ipaddress.IPv4Address((s or "").strip())
    except Exception:
        return False
    if public_only:
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip in _FAKEIP_NET:
            return False
    return True


def _is_cdn_ipv4(s: str) -> bool:
    try:
        ip = ipaddress.IPv4Address((s or "").strip())
        return any(ip in net for net in _CDN_NETS)
    except Exception:
        return False


def mask_ip_text(s: str) -> str:
    if not s:
        return ""
    return re.sub(
        r"(?<![vV\d.])\b((?:25[0-5]|2[0-4]\d|1?\d?\d))\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.((?:25[0-5]|2[0-4]\d|1?\d?\d))\b(?![.\d])",
        r"\1.***.***.\2",
        str(s),
    )


def parse_sub_headers(hdr_text: str) -> dict:
    """解析 Clash 订阅响应头中的流量信息 (subscription-userinfo) 与配置名。"""
    meta = {}
    for raw in (hdr_text or "").splitlines():
        if ":" not in raw:
            continue
        k, v = raw.split(":", 1)
        kl = k.strip().lower()
        val = v.strip()
        if kl == "subscription-userinfo":
            info = {}
            for part in val.split(";"):
                if "=" in part:
                    pk, pv = part.split("=", 1)
                    pk, pv = pk.strip().lower(), pv.strip()
                    if pv.isdigit():
                        info[pk] = int(pv)
            if info:
                meta["userinfo"] = info
        elif kl == "profile-title":
            if val.lower().startswith("base64:"):
                try:
                    meta["profile_title"] = base64.b64decode(val[7:].strip()).decode("utf-8", "ignore").strip()
                except Exception:
                    pass
            elif val:
                meta["profile_title"] = val
    return meta


def build_guardline_nodes_list(
    new_proxies: list[dict],
    old_proxy_names: set[str],
    old_nodes_lines: list[str],
    dns_resolver,
) -> str:
    """按 Guardline 封条规范生成 /etc/openclash/custom/mainland-nodes.list，并保留非代理白名单行（如网盘隧道）。"""
    old_ip_by_name: dict[str, str] = {}
    extra_lines: list[str] = []
    new_name_set = {p["name"] for p in new_proxies}

    for raw in old_nodes_lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        ip_s, _, nm = parts[0], parts[1], parts[2].strip()
        if _is_valid_ipv4(ip_s, public_only=True) and nm not in old_ip_by_name:
            old_ip_by_name[nm] = ip_s
        if nm not in old_proxy_names and nm not in new_name_set and line not in extra_lines:
            extra_lines.append(line)

    dns_cache: dict[str, str] = {}
    direct_lines: list[str] = []
    cdn_lines: list[str] = []

    for p in new_proxies:
        name = p["name"].strip()
        ptype = p["type"].strip().lower()
        srv = p["server"].strip()
        port = int(p["port"])
        ports_hop = (p.get("ports") or "").strip()
        sni = (p.get("sni") or "").strip()
        host_hdr = (p.get("host") or "").strip()

        if _is_valid_ipv4(srv):
            ip = srv
            srv_is_domain = False
        else:
            srv_is_domain = True
            if srv not in dns_cache:
                resolved = dns_resolver(srv) if dns_resolver else ""
                dns_cache[srv] = resolved or ""
            ip = dns_cache[srv] or old_ip_by_name.get(name, "")
            if not _is_valid_ipv4(ip, public_only=True):
                raise ValueError(f"无法解析代理节点域名 {srv}（{name}）的真实 IPv4 地址")

        if ptype in _UDP_PROXY_TYPES:
            direct_lines.append(f"{ip} {port}/udp {name}")
            if ports_hop:
                for seg in ports_hop.split(","):
                    seg = seg.strip()
                    if re.match(r"^\d{1,5}(-\d{1,5})?$", seg) and seg != str(port):
                        direct_lines.append(f"{ip} {seg}/udp {name}")
        else:
            is_cdn = (
                _is_cdn_ipv4(ip)
                or (srv_is_domain and (
                    bool(re.search(r"(cloudfront|cloudflare|cdn|^cf[-.])", srv, re.I))
                    or bool(re.search(r"(CF|CDN|AWS|优选)", name, re.I))
                ))
                or (bool(re.search(r"(CF优选|CF-|CDN|AWS)", name, re.I)) and bool(sni or host_hdr))
            )
            if is_cdn:
                cdn_lines.append(f"{ip} {port}/cdn {name}")
            else:
                direct_lines.append(f"{ip} {port} {name}")

    header = [
        "# 住宅出口中继清单 —— 由 Guardline 面板按订阅自动同步生成。格式：IP 端口[/udp|/cdn] 节点名（不带后缀 = TCP 且设直连；/cdn = 经 CDN，不设直连）",
        "# 用途：第 19 道内核出口白名单（只放行这些服务器）、Clash relay-nodes 直连与嗅探跳过（不含 /cdn）—— 受封条保护。",
    ]
    return "\n".join(header + direct_lines + cdn_lines + extra_lines) + "\n"


# ================================================================== 路由器端内核分流流量采集脚本 & 本机历史数据库
RP_TRAFFIC_VERSION = "# rp-traffic-v2"

RP_TRAFFIC_SCRIPT = r"""#!/bin/sh
# rp-traffic-v3
# 纯只读 nftables 旁路分流字节计量 + 终端禁网持久化，零丢包、不影响任何封条与防火墙规则
RAM_DIR="/tmp/rp_traffic"
PERSIST_DIR="/etc/rp_traffic"
LOCK_DIR="$RAM_DIR/.lock"
mkdir -p "$RAM_DIR" "$PERSIST_DIR"

acquire_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo $$ > "$LOCK_DIR/pid"
        return 0
    fi
    lpid=$(cat "$LOCK_DIR/pid" 2>/dev/null)
    if [ -n "$lpid" ] && ! kill -0 "$lpid" 2>/dev/null; then
        rm -rf "$LOCK_DIR" 2>/dev/null
        if mkdir "$LOCK_DIR" 2>/dev/null; then
            echo $$ > "$LOCK_DIR/pid"
            return 0
        fi
    fi
    return 1
}

release_lock() {
    rm -rf "$LOCK_DIR" 2>/dev/null || true
}

build_wan_elements() {
    LAN_DEVS=$( {
        uci -q get network.lan.device
        ubus call network.interface.lan status 2>/dev/null | jsonfilter -e '@.l3_device' -e '@.device' 2>/dev/null
    } | tr ' ' '\n' | sort -u | tr '\n' ' ' )
    {
        ubus call network.interface dump 2>/dev/null | jsonfilter \
            -e '@.interface[@.interface!="lan" && @.interface!="loopback"].l3_device' \
            -e '@.interface[@.interface!="lan" && @.interface!="loopback"].device' 2>/dev/null
        uci -q get network.wan.device
        uci -q get network.wwan.device
        for n in /sys/class/net/*; do
            d=$(basename "$n")
            [ -e "$n/master" ] && continue
            case "$d" in
                lo|br-*|lan*|utun*|Meta*|tun*|tap*|wg*|docker*|veth*|virbr*|ifb*|sit*|gre*|ip6*) continue ;;
                eth*|wan*|wwan*|phy*-sta*|wlan*-sta*|usb*|pppoe-*|rmnet*|ccmni*) echo "$d" ;;
            esac
        done
    } | awk -v landevs=" $LAN_DEVS " '
        NF == 1 && length($1) <= 15 && $1 !~ /^@/ && $1 != "lo" && $1 != "br-lan" && $1 != "utun" && $1 != "Meta" {
            if (index(landevs, " " $1 " ") > 0) next
            if (!seen[$1]++) list = (list ? list ", " : "") "\"" $1 "\""
        }
        END { print (list ? list : "\"eth0\"") }
    '
}

build_proxy_elements() {
    CP=$(uci -q get openclash.config.config_path 2>/dev/null)
    [ -z "$CP" ] && CP="/etc/openclash/config/sub.yaml"
    {
        [ -f /etc/openclash/custom/mainland-nodes.list ] && awk '!/^#/ && NF>=1 {print $1}' /etc/openclash/custom/mainland-nodes.list
        [ -f "$CP" ] && sed -n 's/.*server:[[:space:]]*["'\'']\{0,1\}\([0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}\)["'\'']\{0,1\}.*/\1/p' "$CP"
        [ -f "$PERSIST_DIR/extra_proxy_ips.txt" ] && cat "$PERSIST_DIR/extra_proxy_ips.txt"
        echo "255.255.255.254"
    } | awk '
        /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            n = split($1, o, ".")
            if (n == 4 && o[1]<=255 && o[2]<=255 && o[3]<=255 && o[4]<=255) {
                if (o[1]==0 || o[1]==10 || o[1]==127) next
                if (o[1]==192 && o[2]==168) next
                if (o[1]==198 && (o[2]==18 || o[2]==19)) next
                if (!seen[$1]++) list = (list ? list ", " : "") $1
            }
        }
        END { print (list ? list : "255.255.255.254") }
    '
}

ensure_table() {
    if nft list table inet rp_traffic >/dev/null 2>&1; then
        return 0
    fi
    WAN_ELS=$(build_wan_elements)
    PRX_ELS=$(build_proxy_elements)
    nft -f - <<EOF
table inet rp_traffic {
    counter rx_proxy {}
    counter tx_proxy {}
    counter rx_direct {}
    counter tx_direct {}
    set wan_devs {
        type ifname
        elements = { $WAN_ELS }
    }
    set private_nets {
        type ipv4_addr
        flags interval
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
            169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16,
            198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4
        }
    }
    set proxy_ips {
        type ipv4_addr
        elements = { $PRX_ELS }
    }
    chain prerouting {
        type filter hook prerouting priority filter + 10; policy accept;
        iifname @wan_devs ip saddr != @private_nets ip saddr @proxy_ips counter name "rx_proxy"
        iifname @wan_devs ip saddr != @private_nets ip saddr != @proxy_ips counter name "rx_direct"
    }
    chain postrouting {
        type filter hook postrouting priority srcnat + 10; policy accept;
        oifname @wan_devs ip daddr != @private_nets ip daddr @proxy_ips counter name "tx_proxy"
        oifname @wan_devs ip daddr != @private_nets ip daddr != @proxy_ips counter name "tx_direct"
    }
}
EOF
    echo "0 0 0 0" > "$RAM_DIR/prev.state"
}

sync_ips() {
    if ! nft list table inet rp_traffic >/dev/null 2>&1; then
        ensure_table
        return $?
    fi
    WAN_ELS=$(build_wan_elements)
    PRX_ELS=$(build_proxy_elements)
    nft -f - <<EOF
flush set inet rp_traffic wan_devs
add element inet rp_traffic wan_devs { $WAN_ELS }
flush set inet rp_traffic proxy_ips
add element inet rp_traffic proxy_ips { $PRX_ELS }
EOF
}

restore_or_seed() {
    if [ -f "$RAM_DIR/hourly.tsv" ]; then
        return 0
    fi
    if [ -f "$PERSIST_DIR/hourly.tsv" ]; then
        for fn in min5.tsv hourly.tsv daily.tsv; do
            [ -f "$PERSIST_DIR/$fn" ] && cp -f "$PERSIST_DIR/$fn" "$RAM_DIR/$fn"
        done
        date +%s > "$RAM_DIR/last_flush"
        return 0
    fi
    UP_S=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
    NOW=$(date +%s)
    : > "$RAM_DIR/min5.tsv"
    : > "$RAM_DIR/hourly.tsv"
    : > "$RAM_DIR/daily.tsv"
    if [ -n "$UP_S" ] && [ "$UP_S" -gt 0 ] && [ "$UP_S" -lt 43200 ]; then
        WAN_ELS=$(build_wan_elements | tr -d '",')
        WAN_TOT=$(awk -v devs=" $WAN_ELS " '
            NR > 2 && index($0, ":") > 0 {
                sub(/^[[:space:]]+/, "", $0)
                split($0, a, ":")
                d = a[1]
                if (index(devs, " " d " ") > 0) {
                    split(a[2], f, /[[:space:]]+/)
                    j = (f[1] == "" ? 2 : 1)
                    rx += f[j] + 0
                    tx += f[j+8] + 0
                }
            }
            END { printf "%.0f %.0f\n", rx+0, tx+0 }
        ' /proc/net/dev 2>/dev/null)
        M_OUT=$(nft list chain inet mainland_guard MAINLAND_OUT 2>/dev/null | awk '
            /KERNEL-EGRESS-WHITELIST/ { for(i=1;i<=NF;i++) if($i=="bytes") ptx += $(i+1)+0 }
            /MAINLAND-RETURN|CLASH-CN-UDP-GUARD|DNSMASQ-EGRESS-GUARD/ { for(i=1;i<=NF;i++) if($i=="bytes") dtx += $(i+1)+0 }
            END { printf "%.0f %.0f\n", ptx+0, dtx+0 }
        ')
        SEED=$(awk -v wt="$WAN_TOT" -v mo="$M_OUT" 'BEGIN {
            split(wt, w, " "); split(mo, m, " ")
            wrx = w[1]+0; wtx = w[2]+0; ptx = m[1]+0; dtx = m[2]+0
            if (wrx + wtx <= 0) { print "0 0 0 0"; exit }
            if (ptx + dtx > 0) {
                ratio = ptx / (ptx + dtx)
                if (ratio > 0.98) ratio = 0.98
                if (ratio < 0.02) ratio = 0.02
            } else {
                ratio = 0.85
            }
            srxp = int(wrx * ratio); srxd = wrx - srxp
            stxp = int(wtx * ratio); stxd = wtx - stxp
            printf "%.0f %.0f %.0f %.0f\n", srxp, stxp, srxd, stxd
        }')
        set -- $SEED
        if [ "$1" != "0" ] || [ "$2" != "0" ] || [ "$3" != "0" ] || [ "$4" != "0" ]; then
            B5=$(awk -v n="$NOW" 'BEGIN { printf "%.0f", int(n / 300) * 300 }')
            B1H=$(awk -v n="$NOW" 'BEGIN { printf "%.0f", int(n / 3600) * 3600 }')
            B1D=$(awk -v n="$NOW" 'BEGIN { printf "%.0f", int((n + 28800) / 86400) * 86400 - 28800 }')
            printf "%s\t%s\t%s\t%s\t%s\n" "$B5" "$1" "$2" "$3" "$4" > "$RAM_DIR/min5.tsv"
            printf "%s\t%s\t%s\t%s\t%s\n" "$B1H" "$1" "$2" "$3" "$4" > "$RAM_DIR/hourly.tsv"
            printf "%s\t%s\t%s\t%s\t%s\n" "$B1D" "$1" "$2" "$3" "$4" > "$RAM_DIR/daily.tsv"
        fi
    fi
    for fn in min5.tsv hourly.tsv daily.tsv; do
        cp -f "$RAM_DIR/$fn" "$PERSIST_DIR/$fn" 2>/dev/null || true
    done
    echo "$NOW" > "$RAM_DIR/last_flush"
}

update_tsv() {
    f="$1"; b="$2"; cut="$3"
    [ -f "$f" ] || : > "$f"
    awk -F'\t' -v OFS='\t' -v b="$b" -v cut="$cut" \
        -v p1="$4" -v p2="$5" -v d1="$6" -v d2="$7" '
        BEGIN { found = 0 }
        NF >= 5 && ($1 + 0) >= (cut + 0) {
            if (($1 + 0) == (b + 0)) {
                printf "%.0f\t%.0f\t%.0f\t%.0f\t%.0f\n", b, $2 + p1, $3 + p2, $4 + d1, $5 + d2
                found = 1
            } else {
                print $0
            }
        }
        END {
            if (!found) {
                printf "%.0f\t%.0f\t%.0f\t%.0f\t%.0f\n", b, p1, p2, d1, d2
            }
        }
    ' "$f" > "$f.tmp" && mv -f "$f.tmp" "$f"
}

collect_once() {
    force_flush="$1"
    acquire_lock || return 0
    trap 'release_lock' EXIT INT TERM
    restore_or_seed
    ensure_table

    CUR=$(nft list counters table inet rp_traffic 2>/dev/null | awk '
        $1 == "counter" { name = $2 }
        $1 == "packets" && $3 == "bytes" && name != "" { b[name] = $4; name = "" }
        END { printf "%.0f %.0f %.0f %.0f\n", b["rx_proxy"]+0, b["tx_proxy"]+0, b["rx_direct"]+0, b["tx_direct"]+0 }
    ')
    [ -z "$CUR" ] && { release_lock; trap - EXIT INT TERM; return 0; }
    PREV=$(cat "$RAM_DIR/prev.state" 2>/dev/null)
    [ -z "$PREV" ] && PREV="0 0 0 0"
    echo "$CUR" > "$RAM_DIR/prev.state"

    DELTAS=$(awk -v c="$CUR" -v p="$PREV" 'BEGIN {
        split(c, ca, " "); split(p, pa, " ")
        for (i=1; i<=4; i++) {
            cv = ca[i] + 0; pv = pa[i] + 0
            d[i] = (cv >= pv) ? (cv - pv) : cv
        }
        tot = d[1] + d[2] + d[3] + d[4]
        printf "%.0f %.0f %.0f %.0f %.0f\n", tot, d[1], d[2], d[3], d[4]
    }')
    set -- $DELTAS
    TOT="$1"; DRXP="$2"; DTXP="$3"; DRXD="$4"; DTXD="$5"

    NOW=$(date +%s)
    if [ "$TOT" != "0" ] && [ -n "$TOT" ]; then
        B5=$(awk -v n="$NOW" 'BEGIN { printf "%.0f", int(n / 300) * 300 }')
        B1H=$(awk -v n="$NOW" 'BEGIN { printf "%.0f", int(n / 3600) * 3600 }')
        B1D=$(awk -v n="$NOW" 'BEGIN { printf "%.0f", int((n + 28800) / 86400) * 86400 - 28800 }')
        CUT5=$(awk -v b="$B5" 'BEGIN { printf "%.0f", b - 14 * 86400 }')
        CUT1H=$(awk -v b="$B1H" 'BEGIN { printf "%.0f", b - 1100 * 86400 }')
        CUT1D=$(awk -v b="$B1D" 'BEGIN { printf "%.0f", b - 5500 * 86400 }')
        update_tsv "$RAM_DIR/min5.tsv" "$B5" "$CUT5" "$DRXP" "$DTXP" "$DRXD" "$DTXD"
        update_tsv "$RAM_DIR/hourly.tsv" "$B1H" "$CUT1H" "$DRXP" "$DTXP" "$DRXD" "$DTXD"
        update_tsv "$RAM_DIR/daily.tsv" "$B1D" "$CUT1D" "$DRXP" "$DTXP" "$DRXD" "$DTXD"
    fi

    LAST_F=$(cat "$RAM_DIR/last_flush" 2>/dev/null)
    [ -z "$LAST_F" ] && LAST_F=0
    NEED_F=$(awk -v n="$NOW" -v lf="$LAST_F" -v ff="$force_flush" 'BEGIN { print (ff == "1" || (n - lf) >= 900) ? 1 : 0 }')
    if [ "$NEED_F" = "1" ]; then
        for fn in min5.tsv hourly.tsv daily.tsv; do
            [ -f "$RAM_DIR/$fn" ] && cp -f "$RAM_DIR/$fn" "$PERSIST_DIR/$fn.tmp" && mv -f "$PERSIST_DIR/$fn.tmp" "$PERSIST_DIR/$fn"
        done
        echo "$NOW" > "$RAM_DIR/last_flush"
    fi

    release_lock
    trap - EXIT INT TERM
}

reset_all() {
    acquire_lock || return 1
    trap 'release_lock' EXIT INT TERM
    nft reset counters table inet rp_traffic >/dev/null 2>&1 || true
    echo "0 0 0 0" > "$RAM_DIR/prev.state"
    for fn in min5.tsv hourly.tsv daily.tsv; do
        : > "$RAM_DIR/$fn"
        : > "$PERSIST_DIR/$fn"
    done
    date +%s > "$RAM_DIR/last_flush"
    release_lock
    trap - EXIT INT TERM
}

sync_devctl() {
    nft delete table inet rp_devctl >/dev/null 2>&1 || true
    [ -f "$PERSIST_DIR/blocked_macs.txt" ] || return 0
    MACS=$(awk '/^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/ { m = tolower($1); if (!seen[m]++) list = (list ? list ", " : "") m } END { print list }' "$PERSIST_DIR/blocked_macs.txt")
    [ -z "$MACS" ] && return 0
    nft -f - <<EOF
table inet rp_devctl {
    set blocked_macs {
        type ether_addr
        elements = { $MACS }
    }
    chain forward {
        type filter hook forward priority filter - 2; policy accept;
        iifname "br-lan" ether saddr @blocked_macs counter reject
    }
    chain input {
        type filter hook input priority filter - 2; policy accept;
        iifname "br-lan" udp dport { 67, 68 } accept
        iifname "br-lan" tcp dport 22 accept
        iifname "br-lan" ether saddr @blocked_macs counter reject
    }
}
EOF
}

case "$1" in
    init)
        acquire_lock && { restore_or_seed; ensure_table; sync_devctl; release_lock; }
        ;;
    sync-ips)
        acquire_lock && { sync_ips; release_lock; }
        ;;
    sync-devctl)
        acquire_lock && { sync_devctl; release_lock; }
        ;;
    flush)
        collect_once 1
        ;;
    reset)
        reset_all
        ;;
    *)
        collect_once 0
        ;;
esac
"""

RP_TRAFFIC_INITD = r"""#!/bin/sh /etc/rc.common
# rp-traffic-v2
START=95
STOP=10

start() {
    /usr/sbin/rp-traffic-collect init >/dev/null 2>&1 || true
}

stop() {
    /usr/sbin/rp-traffic-collect flush >/dev/null 2>&1 || true
}
"""

_WEEKDAY_ZH = ("周一", "周二", "周三", "周四", "周五", "周六", "周日")
_QUARTER_MONTHS = {1: "1–3月", 2: "4–6月", 3: "7–9月", 4: "10–12月"}


def _parse_local_dt(raw: str, is_end: bool = False) -> datetime.datetime | None:
    s = (raw or "").strip().replace(" ", "T")
    if not s:
        return None
    try:
        if len(s) == 10:
            d = datetime.date.fromisoformat(s)
            return datetime.datetime(d.year, d.month, d.day, 23, 59, 59) if is_end else datetime.datetime(d.year, d.month, d.day, 0, 0, 0)
        dt = datetime.datetime.fromisoformat(s[:19])
        if len(s) <= 16:
            return dt.replace(second=59 if is_end else 0, microsecond=0)
        return dt.replace(microsecond=0)
    except Exception:
        return None


def _shift_months(year: int, month: int, delta_months: int) -> tuple[int, int]:
    total = (year * 12 + (month - 1)) + delta_months
    return total // 12, (total % 12) + 1


class TrafficStore:
    """本机 SQLite 持久层：同步软路由 5m/1h/1d 分流桶，支持 5分钟/时/天/月/季/年 及任意起止日期时间查询。"""

    def __init__(self, db_path: Path = TRAFFIC_DB):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    @contextlib.contextmanager
    def _conn(self):
        APP_DIR.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=8)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self):
        with self._lock:
            try:
                with self._conn() as conn:
                    for tbl in ("buckets_5m", "buckets_1h", "buckets_1d"):
                        conn.execute(
                            f"CREATE TABLE IF NOT EXISTS {tbl} ("
                            "host TEXT NOT NULL, ts INTEGER NOT NULL, "
                            "rx_p INTEGER NOT NULL, tx_p INTEGER NOT NULL, "
                            "rx_d INTEGER NOT NULL, tx_d INTEGER NOT NULL, "
                            "PRIMARY KEY(host, ts))"
                        )
            except Exception as e:
                print("traffic db init:", e)

    def upsert_tsv(self, host: str, table: str, tsv_text: str):
        if not host or not tsv_text or table not in ("buckets_5m", "buckets_1h", "buckets_1d"):
            return
        rows = []
        for ln in tsv_text.splitlines():
            parts = ln.strip().split("\t")
            if len(parts) < 5:
                continue
            try:
                ts = int(float(parts[0]))
                rx_p = max(0, int(float(parts[1])))
                tx_p = max(0, int(float(parts[2])))
                rx_d = max(0, int(float(parts[3])))
                tx_d = max(0, int(float(parts[4])))
                if ts > 946684800 and (rx_p + tx_p + rx_d + tx_d) >= 0:
                    rows.append((host, ts, rx_p, tx_p, rx_d, tx_d))
            except Exception:
                continue
        if not rows:
            return
        sql = (
            f"INSERT INTO {table}(host, ts, rx_p, tx_p, rx_d, tx_d) VALUES (?, ?, ?, ?, ?, ?) "
            f"ON CONFLICT(host, ts) DO UPDATE SET "
            f"rx_p = MAX({table}.rx_p, excluded.rx_p), "
            f"tx_p = MAX({table}.tx_p, excluded.tx_p), "
            f"rx_d = MAX({table}.rx_d, excluded.rx_d), "
            f"tx_d = MAX({table}.tx_d, excluded.tx_d)"
        )
        with self._lock:
            try:
                with self._conn() as conn:
                    conn.executemany(sql, rows)
                    # Prune 5m older than 180 days on PC
                    if table == "buckets_5m":
                        conn.execute("DELETE FROM buckets_5m WHERE ts < ?", (int(time.time()) - 180 * 86400,))
            except Exception as e:
                print("traffic upsert:", e)

    def clear_host(self, host: str):
        if not host:
            return
        with self._lock:
            try:
                with self._conn() as conn:
                    for tbl in ("buckets_5m", "buckets_1h", "buckets_1d"):
                        conn.execute(f"DELETE FROM {tbl} WHERE host = ?", (host,))
            except Exception as e:
                print("traffic clear:", e)

    def quick_totals(self, host: str, live_delta: tuple[int, int, int, int] = (0, 0, 0, 0)) -> dict:
        now_dt = datetime.datetime.now()
        today_0 = datetime.datetime(now_dt.year, now_dt.month, now_dt.day).timestamp()
        d7_0 = (datetime.datetime(now_dt.year, now_dt.month, now_dt.day) - datetime.timedelta(days=6)).timestamp()
        month_0 = datetime.datetime(now_dt.year, now_dt.month, 1).timestamp()
        q_m0 = ((now_dt.month - 1) // 3) * 3 + 1
        quarter_0 = datetime.datetime(now_dt.year, q_m0, 1).timestamp()
        year_0 = datetime.datetime(now_dt.year, 1, 1).timestamp()

        acc = {k: [0, 0, 0, 0] for k in ("today", "d7", "month", "quarter", "year")}
        if host:
            with self._lock:
                try:
                    with self._conn() as conn:
                        cur = conn.execute(
                            "SELECT ts, rx_p, tx_p, rx_d, tx_d FROM buckets_1h WHERE host = ? AND ts >= ?",
                            (host, int(min(year_0, d7_0)) - 3600),
                        )
                        for ts, rxp, txp, rxd, txd in cur.fetchall():
                            for k, t0 in (("today", today_0), ("d7", d7_0), ("month", month_0), ("quarter", quarter_0), ("year", year_0)):
                                if ts >= t0:
                                    a = acc[k]
                                    a[0] += rxp
                                    a[1] += txp
                                    a[2] += rxd
                                    a[3] += txd
                except Exception:
                    pass
        lrxp, ltxp, lrxd, ltxd = live_delta
        for a in acc.values():
            a[0] += max(0, lrxp)
            a[1] += max(0, ltxp)
            a[2] += max(0, lrxd)
            a[3] += max(0, ltxd)

        out = {}
        for k, (rxp, txp, rxd, txd) in acc.items():
            pt = rxp + txp
            dt = rxd + txd
            out[k] = {
                "proxy_down": rxp, "proxy_up": txp, "proxy_total": pt,
                "direct_down": rxd, "direct_up": txd, "direct_total": dt,
                "total_down": rxp + rxd, "total_up": txp + txd, "grand_total": pt + dt,
            }
        return out

    def query(
        self,
        host: str,
        granularity: str = "day",
        start_dt_str: str = "",
        end_dt_str: str = "",
        preset: str = "",
        live_delta: tuple[int, int, int, int] = (0, 0, 0, 0),
    ) -> dict:
        gran = granularity if granularity in ("5min", "hour", "day", "month", "quarter", "year") else "day"
        now_dt = datetime.datetime.now().replace(microsecond=0)
        today_start = datetime.datetime(now_dt.year, now_dt.month, now_dt.day)

        min_db_ts = None
        if host:
            with self._lock:
                try:
                    with self._conn() as conn:
                        r1 = conn.execute("SELECT MIN(ts) FROM buckets_1h WHERE host = ?", (host,)).fetchone()
                        r2 = conn.execute("SELECT MIN(ts) FROM buckets_1d WHERE host = ?", (host,)).fetchone()
                        cands = [x[0] for x in (r1, r2) if x and x[0]]
                        min_db_ts = min(cands) if cands else None
                except Exception:
                    pass

        eff_preset = (preset or "").strip()
        s_dt = _parse_local_dt(start_dt_str, False) if eff_preset == "custom" or (start_dt_str and not eff_preset) else None
        e_dt = _parse_local_dt(end_dt_str, True) if eff_preset == "custom" or (end_dt_str and not eff_preset) else None

        if not (s_dt and e_dt):
            if not eff_preset or eff_preset == "custom":
                eff_preset = {
                    "5min": "6h",
                    "hour": "24h",
                    "day": "30d",
                    "month": "12m",
                    "quarter": "year",
                    "year": "5y",
                }[gran]
            e_dt = now_dt.replace(second=59)
            if eff_preset == "6h":
                s_dt = (now_dt - datetime.timedelta(hours=6)).replace(second=0)
            elif eff_preset == "today":
                s_dt = today_start
            elif eff_preset == "24h":
                s_dt = (now_dt - datetime.timedelta(hours=23)).replace(minute=0, second=0)
            elif eff_preset == "7d":
                s_dt = today_start - datetime.timedelta(days=6)
            elif eff_preset == "30d":
                s_dt = today_start - datetime.timedelta(days=29)
            elif eff_preset == "month":
                s_dt = datetime.datetime(now_dt.year, now_dt.month, 1)
            elif eff_preset == "12m":
                y0, m0 = _shift_months(now_dt.year, now_dt.month, -11)
                s_dt = datetime.datetime(y0, m0, 1)
            elif eff_preset == "quarter":
                qm0 = ((now_dt.month - 1) // 3) * 3 + 1
                s_dt = datetime.datetime(now_dt.year, qm0, 1)
            elif eff_preset == "year":
                s_dt = datetime.datetime(now_dt.year, 1, 1)
            elif eff_preset == "5y":
                s_dt = datetime.datetime(now_dt.year - 4, 1, 1)
            elif eff_preset == "all":
                if min_db_ts:
                    mdt = datetime.datetime.fromtimestamp(min_db_ts)
                    s_dt = datetime.datetime(mdt.year, mdt.month, mdt.day)
                else:
                    s_dt = today_start - datetime.timedelta(days=29)
            else:
                s_dt = today_start - datetime.timedelta(days=29)
        else:
            eff_preset = "custom"

        if s_dt > e_dt:
            s_dt, e_dt = e_dt.replace(second=0), s_dt.replace(second=59)

        t_start = s_dt.timestamp()
        t_end = e_dt.timestamp()

        # Fetch raw points cleanly without boundary overlap
        points: list[tuple[int, int, int, int, int]] = []
        if host:
            with self._lock:
                try:
                    with self._conn() as conn:
                        min_5m_row = conn.execute("SELECT MIN(ts) FROM buckets_5m WHERE host = ?", (host,)).fetchone()
                        min_5m = min_5m_row[0] if (min_5m_row and min_5m_row[0]) else None
                        min_1h_row = conn.execute("SELECT MIN(ts) FROM buckets_1h WHERE host = ?", (host,)).fetchone()
                        min_1h = min_1h_row[0] if (min_1h_row and min_1h_row[0]) else None

                        skew_pad = 900 if eff_preset != "custom" else 0
                        if gran == "5min":
                            q_s5 = (int(t_start) // 300) * 300
                            q_e5 = (int(t_end + skew_pad) // 300) * 300
                            if min_5m is not None and q_e5 >= min_5m:
                                points.extend(conn.execute(
                                    "SELECT ts, rx_p, tx_p, rx_d, tx_d FROM buckets_5m WHERE host = ? AND ts >= ? AND ts <= ?",
                                    (host, max(q_s5, min_5m), q_e5),
                                ).fetchall())
                                if q_s5 < min_5m:
                                    h_cut = (int(min_5m) // 3600) * 3600
                                    points.extend(conn.execute(
                                        "SELECT ts, rx_p, tx_p, rx_d, tx_d FROM buckets_1h WHERE host = ? AND ts >= ? AND ts < ?",
                                        (host, (int(t_start) // 3600) * 3600, h_cut),
                                    ).fetchall())
                            else:
                                points.extend(conn.execute(
                                    "SELECT ts, rx_p, tx_p, rx_d, tx_d FROM buckets_1h WHERE host = ? AND ts >= ? AND ts <= ?",
                                    (host, (int(t_start) // 3600) * 3600, (int(t_end + skew_pad) // 3600) * 3600),
                                ).fetchall())
                        else:
                            h_start = (int(t_start) // 3600) * 3600
                            h_end = (int(t_end + skew_pad) // 3600) * 3600
                            h_min5_floor = ((int(min_5m) // 3600) * 3600) if min_5m is not None else None
                            partial_head = (
                                eff_preset == "custom"
                                and (int(t_start) % 3600) != 0
                                and h_min5_floor is not None
                                and h_start >= h_min5_floor
                            )
                            partial_tail = (
                                eff_preset == "custom"
                                and (int(t_end) % 3600) < 3540
                                and h_end > h_start
                                and h_min5_floor is not None
                                and h_end >= h_min5_floor
                            )

                            full_h_from = h_start + 3600 if partial_head else h_start
                            full_h_to = h_end - 3600 if partial_tail else h_end

                            if partial_head:
                                points.extend(conn.execute(
                                    "SELECT ts, rx_p, tx_p, rx_d, tx_d FROM buckets_5m WHERE host = ? AND ts >= ? AND ts < ?",
                                    (host, (int(t_start) // 300) * 300, min(h_start + 3600, (int(t_end) // 300) * 300 + 300)),
                                ).fetchall())
                            if full_h_from <= full_h_to:
                                points.extend(conn.execute(
                                    "SELECT ts, rx_p, tx_p, rx_d, tx_d FROM buckets_1h WHERE host = ? AND ts >= ? AND ts <= ?",
                                    (host, full_h_from, full_h_to),
                                ).fetchall())
                                if min_1h is not None:
                                    d_cut = ((int(min_1h) + 28800) // 86400) * 86400 - 28800
                                    if full_h_from < d_cut:
                                        points.extend(conn.execute(
                                            "SELECT ts, rx_p, tx_p, rx_d, tx_d FROM buckets_1d WHERE host = ? AND ts >= ? AND ts < ?",
                                            (host, int(t_start) - 86400, d_cut),
                                        ).fetchall())
                            if partial_tail:
                                points.extend(conn.execute(
                                    "SELECT ts, rx_p, tx_p, rx_d, tx_d FROM buckets_5m WHERE host = ? AND ts >= ? AND ts <= ?",
                                    (host, h_end, (int(t_end) // 300) * 300),
                                ).fetchall())
                except Exception as e:
                    print("traffic query:", e)

        now_ts = int(time.time())
        lrxp, ltxp, lrxd, ltxd = live_delta
        if t_start <= now_ts <= t_end + 120 and (lrxp + ltxp + lrxd + ltxd) > 0:
            points.append((now_ts, max(0, lrxp), max(0, ltxp), max(0, lrxd), max(0, ltxd)))

        span_same_day = (s_dt.date() == e_dt.date())
        span_hours = (t_end - t_start) / 3600.0

        def make_meta(dt_obj: datetime.datetime) -> tuple[str, str, str]:
            if gran == "5min":
                m5 = (dt_obj.minute // 5) * 5
                bdt = dt_obj.replace(minute=m5, second=0, microsecond=0)
                edt = bdt + datetime.timedelta(minutes=5)
                key = bdt.strftime("%Y-%m-%d %H:%M")
                lbl = bdt.strftime("%H:%M") if span_same_day else bdt.strftime("%m-%d %H:%M")
                full = f"{bdt.strftime('%Y-%m-%d %H:%M')} ~ {edt.strftime('%H:%M')}"
                return key, lbl, full
            if gran == "hour":
                bdt = dt_obj.replace(minute=0, second=0, microsecond=0)
                key = bdt.strftime("%Y-%m-%d %H")
                lbl = bdt.strftime("%H:00") if span_hours <= 28 else bdt.strftime("%m-%d %H时")
                full = f"{bdt.strftime('%Y-%m-%d %H:00')} ~ {bdt.strftime('%H:59')}"
                return key, lbl, full
            if gran == "day":
                key = dt_obj.strftime("%Y-%m-%d")
                lbl = dt_obj.strftime("%m-%d")
                full = f"{key} ({_WEEKDAY_ZH[dt_obj.weekday()]})"
                return key, lbl, full
            if gran == "month":
                key = dt_obj.strftime("%Y-%m")
                lbl = f"{dt_obj.month}月" if s_dt.year == e_dt.year else key
                full = f"{dt_obj.year} 年 {dt_obj.month:02d} 月"
                return key, lbl, full
            if gran == "quarter":
                q = (dt_obj.month - 1) // 3 + 1
                key = f"{dt_obj.year}-Q{q}"
                lbl = f"{dt_obj.year} Q{q}"
                full = f"{dt_obj.year} 年第 {q} 季度 ({_QUARTER_MONTHS[q]})"
                return key, lbl, full
            # year
            key = f"{dt_obj.year}"
            lbl = f"{dt_obj.year}年"
            full = f"{dt_obj.year} 年度 (1–12月)"
            return key, lbl, full

        buckets: dict[str, list] = {}

        def ensure_bucket(dt_obj: datetime.datetime):
            k, lbl, full = make_meta(dt_obj)
            if k not in buckets:
                buckets[k] = [k, lbl, full, 0, 0, 0, 0]

        # Pre-populate continuous timeline skeleton
        if gran == "5min":
            n_steps = int((t_end - t_start) // 300) + 1
            if n_steps <= 576:
                cur_t = (int(t_start) // 300) * 300
                end_t = (int(t_end) // 300) * 300
                while cur_t <= end_t:
                    ensure_bucket(datetime.datetime.fromtimestamp(cur_t))
                    cur_t += 300
        elif gran == "hour":
            n_steps = int((t_end - t_start) // 3600) + 1
            if n_steps <= 744:
                cur_dt = s_dt.replace(minute=0, second=0, microsecond=0)
                end_h = e_dt.replace(minute=0, second=0, microsecond=0)
                while cur_dt <= end_h:
                    ensure_bucket(cur_dt)
                    cur_dt += datetime.timedelta(hours=1)
        elif gran == "day":
            n_days = (e_dt.date() - s_dt.date()).days + 1
            if n_days <= 400:
                cur_d = datetime.datetime(s_dt.year, s_dt.month, s_dt.day)
                end_d = datetime.datetime(e_dt.year, e_dt.month, e_dt.day)
                while cur_d <= end_d:
                    ensure_bucket(cur_d)
                    cur_d += datetime.timedelta(days=1)
        elif gran == "month":
            cy, cm = s_dt.year, s_dt.month
            ey, em = e_dt.year, e_dt.month
            for _ in range(240):
                if (cy, cm) > (ey, em):
                    break
                ensure_bucket(datetime.datetime(cy, cm, 1))
                cy, cm = _shift_months(cy, cm, 1)
        elif gran == "quarter":
            cy, cq = s_dt.year, (s_dt.month - 1) // 3 + 1
            ey, eq = e_dt.year, (e_dt.month - 1) // 3 + 1
            if eff_preset == "year" and cy == ey:
                eq = 4
            for _ in range(120):
                if (cy, cq) > (ey, eq):
                    break
                ensure_bucket(datetime.datetime(cy, (cq - 1) * 3 + 1, 1))
                cq += 1
                if cq > 4:
                    cq = 1
                    cy += 1
        elif gran == "year":
            for yy in range(s_dt.year, min(s_dt.year + 50, e_dt.year + 1)):
                ensure_bucket(datetime.datetime(yy, 1, 1))

        for ts, rxp, txp, rxd, txd in points:
            eff_ts = min(ts, int(t_end)) if eff_preset != "custom" else ts
            dt_obj = datetime.datetime.fromtimestamp(eff_ts)
            k, lbl, full = make_meta(dt_obj)
            b = buckets.get(k)
            if b is None:
                b = [k, lbl, full, 0, 0, 0, 0]
                buckets[k] = b
            b[3] += rxp
            b[4] += txp
            b[5] += rxd
            b[6] += txd

        series = []
        tot_pd = tot_pu = tot_dd = tot_du = 0
        peak_item = None
        active_cnt = 0
        for k in sorted(buckets.keys()):
            _, lbl, full, pd, pu, dd, du = buckets[k]
            pt = pd + pu
            dt_bytes = dd + du
            gt = pt + dt_bytes
            p_pct = round(pt * 100.0 / gt, 1) if gt > 0 else 0.0
            item = {
                "key": k,
                "label": lbl,
                "full_label": full,
                "proxy_down": pd,
                "proxy_up": pu,
                "proxy_total": pt,
                "direct_down": dd,
                "direct_up": du,
                "direct_total": dt_bytes,
                "total_down": pd + dd,
                "total_up": pu + du,
                "total": gt,
                "proxy_pct": p_pct,
            }
            series.append(item)
            tot_pd += pd
            tot_pu += pu
            tot_dd += dd
            tot_du += du
            if gt > 0:
                active_cnt += 1
            if peak_item is None or gt > peak_item["total"]:
                peak_item = item

        proxy_tot = tot_pd + tot_pu
        direct_tot = tot_dd + tot_du
        grand_tot = proxy_tot + direct_tot
        p_ratio = round(proxy_tot * 100.0 / grand_tot, 1) if grand_tot > 0 else 0.0
        d_ratio = round(100.0 - p_ratio, 1) if grand_tot > 0 else 0.0

        summary = {
            "proxy_down": tot_pd,
            "proxy_up": tot_pu,
            "proxy_total": proxy_tot,
            "direct_down": tot_dd,
            "direct_up": tot_du,
            "direct_total": direct_tot,
            "total_down": tot_pd + tot_dd,
            "total_up": tot_pu + tot_du,
            "grand_total": grand_tot,
            "proxy_pct": p_ratio,
            "direct_pct": d_ratio,
            "active_buckets": active_cnt,
            "bucket_count": len(series),
            "peak": peak_item if (peak_item and peak_item["total"] > 0) else None,
        }

        return {
            "ok": True,
            "granularity": gran,
            "preset": eff_preset,
            "start_dt": s_dt.strftime("%Y-%m-%dT%H:%M"),
            "end_dt": e_dt.strftime("%Y-%m-%dT%H:%M"),
            "range_label": f"{s_dt.strftime('%Y-%m-%d %H:%M')} 至 {e_dt.strftime('%Y-%m-%d %H:%M')}",
            "summary": summary,
            "series": series,
            "quick": self.quick_totals(host, live_delta),
        }


# ================================================================== 后台引擎
class Backend:
    def __init__(self):
        self._cfg = load_cfg()
        self._cfg.setdefault("aliases", {})
        self._cfg.setdefault("theme", "dark")
        if not self._cfg.get("claude_theme_migrated"):
            self._cfg["accent"] = "claude"
            self._cfg["claude_theme_migrated"] = True
            save_cfg(self._cfg)
        self._cfg.setdefault("accent", "claude")
        self._cfg.setdefault("saved_routers", [])
        if self._cfg.get("password") and not self._cfg["saved_routers"]:
            self._cfg["saved_routers"] = [{
                "host": self._cfg.get("host", "192.168.88.1"),
                "port": int(self._cfg.get("port", 22)),
                "user": self._cfg.get("user", "root"),
                "ssh_user": self._cfg.get("ssh_user", self._cfg.get("user", "root")),
                "pw": self._cfg["password"],
            }]
        self._cfg.setdefault("saved_wifi", [])
        self._cfg.setdefault("auto_connect_wifi", False)
        self._cfg.setdefault("alerts_enabled", True)
        self._cfg.setdefault("privacy_mode", False)
        if "auto_start" in self._cfg:
            apply_autostart(bool(self._cfg["auto_start"]))
        else:
            self._cfg["auto_start"] = is_autostart_enabled()
        self._lock = threading.Lock()
        self._router = None
        self._stop = threading.Event()
        self._force = threading.Event()
        self._session = None  # {"host", "port", "user", "ssh_user", "pw"}
        self._my_ips = local_ips()
        gws = _win_default_gateways()
        self._default_gw = gws[0] if gws else "192.168.88.1"
        self._status, self._error, self._updated = "idle", "", ""
        self._sub_lock = threading.Lock()
        self._sub_meta = {}
        self._sub_task = {"running": False, "pct": 0, "step": "", "ok": None, "error": "", "summary": "", "ts": 0}
        self._traffic_store = TrafficStore()
        self._slow_seq = 0
        self._wifi_scan_seq = 0
        self._reset()

    def _reset(self):
        self._fast = self._slow = None
        self._slow_seq = getattr(self, "_slow_seq", 0) + 1
        self._conn_start_ts = {}
        self._hist = deque(maxlen=90)
        self._clash_hist = deque(maxlen=90)
        self._client_prev, self._client_rate = {}, {}
        self._conn_prev, self._rate = {}, {}
        self._cpu = 0
        self._clash_rate = (0, 0)
        self._proxy_rate = (0.0, 0.0)
        self._direct_rate = (0.0, 0.0)
        self._traffic_collector_ready = False
        self._traffic_quick_cache = {}
        self._traffic_quick_ts = 0.0
        self._wifi_scan_cache = []
        self._wifi_scan_seq = getattr(self, "_wifi_scan_seq", 0) + 1
        self._wifi_scan_ts = 0.0
        self._wifi_scan_inflight = 0.0
        self._auto_conn_last_ts = 0.0
        self._auto_conn_target = None
        self._auto_conn_fail_until = {}
        self._manual_disc_ts = 0.0
        self._prev_wwan_up = False
        self._sub_hdr_ts = 0.0

    # ---------------------------------------------------------- 账号与多设备管理
    def _active_creds(self):
        if self._session:
            return self._session
        if self._cfg.get("password"):
            try:
                pw = unprotect(self._cfg["password"])
                host = self._cfg.get("host") or self._default_gw
                port = int(self._cfg.get("port", 22))
                user = self._cfg.get("user", "root")
                ssh_user = self._cfg.get("ssh_user", user)
                return {"host": host, "port": port, "user": user, "ssh_user": ssh_user, "pw": pw}
            except Exception:
                return None
        return None

    def start(self, trust_new_key=False):
        self.stop()
        creds = self._active_creds()
        if not creds:
            self._status = "logged_out"
            return False
        self._reset()
        self._router = Router(creds["host"], creds["user"], creds["pw"],
                              port=creds["port"], ssh_user=creds["ssh_user"], trust_new_key=trust_new_key)
        self._stop = threading.Event()
        self._status, self._error = "connecting", ""
        threading.Thread(target=self._loop, args=(self._router, self._stop), daemon=True).start()
        return True

    def stop(self):
        self._stop.set()
        if self._router:
            self._router.close()
        self._router = None

    def login(self, host_raw, user, pw, remember=True, port=22):
        host, parsed_port = parse_host_port(host_raw, port or 22)
        user = (user or "").strip()
        if not (host and user and pw):
            return {"ok": False, "error": "请填写完整的网关地址、登录账号和密码"}

        ssh_user = user
        try:
            r = Router(host, user, pw, port=parsed_port, ssh_user=ssh_user, trust_new_key=True)
            r.run("true", timeout=10)
            r.close()
        except paramiko.AuthenticationException:
            # 兼容仅在 LuCI/rpcd 修改了网页登录账号名、而底层系统账号仍为 root 的软路由
            if user != "root" and verify_ubus_web_login(host, user, pw):
                try:
                    r2 = Router(host, user, pw, port=parsed_port, ssh_user="root", trust_new_key=True)
                    r2.run("true", timeout=10)
                    r2.close()
                    ssh_user = "root"
                except Exception:
                    return {"ok": False, "error": "网页账号验证通过，但该路由器未放通对应 SSH 密码登录"}
            else:
                return {"ok": False, "error": "账号名称或密码错误，请核对软路由登录凭据"}
        except Exception as e:
            return {"ok": False, "error": f"无法连接 {host}:{parsed_port}（{e}）"}

        self._cfg.update(host=host, port=parsed_port, user=user, ssh_user=ssh_user)
        if remember:
            enc_pw = protect(pw)
            self._cfg["password"] = enc_pw
            self._session = None
            # 保存到多设备记忆列表
            saved = [x for x in self._cfg.get("saved_routers", [])
                     if not (x.get("host") == host and int(x.get("port", 22)) == parsed_port and x.get("user") == user)]
            saved.insert(0, {"host": host, "port": parsed_port, "user": user, "ssh_user": ssh_user, "pw": enc_pw})
            self._cfg["saved_routers"] = saved[:8]
        else:
            self._cfg.pop("password", None)
            self._session = {"host": host, "port": parsed_port, "user": user, "ssh_user": ssh_user, "pw": pw}
        save_cfg(self._cfg)
        self.start(trust_new_key=True)
        return {"ok": True}

    def quick_switch_router(self, host, port, user):
        for item in self._cfg.get("saved_routers", []):
            if item.get("host") == host and int(item.get("port", 22)) == int(port or 22) and item.get("user") == user:
                try:
                    pw = unprotect(item["pw"])
                except Exception:
                    return {"ok": False, "error": "已保存凭据失效，请重新输入密码"}
                return self.login(host, user, pw, remember=True, port=port)
        return {"ok": False, "error": "未找到该设备记录"}

    def remove_saved_router(self, host, port, user):
        self._cfg["saved_routers"] = [
            x for x in self._cfg.get("saved_routers", [])
            if not (x.get("host") == host and int(x.get("port", 22)) == int(port or 22) and x.get("user") == user)
        ]
        save_cfg(self._cfg)
        return True

    def logout(self):
        self.stop()
        self._session = None
        self._cfg.pop("password", None)
        save_cfg(self._cfg)
        with self._lock:
            self._reset()
        self._status = "logged_out"

    # ---------------------------------------------------------- 无线桥接核心能力
    def _sync_current_sta_to_saved(self, slow):
        """自动把路由器当前已配置的无线桥接热点同步进本机常用热点库，免去重复输入密码。"""
        changed = False
        saved = self._cfg.setdefault("saved_wifi", [])
        wwan_up = any(i.get("interface") == "wwan" and i.get("up") and i.get("ipv4-address")
                      for i in slow.get("ifaces", []))
        for sec, ifn, band, radio, cfg, rd in sta_list(slow):
            ssid = (cfg.get("ssid") or "").replace("\r", "").replace("\n", "")
            # 只导入「启用中且已经连上」的桥接，避免把测试用 / 连不上的配置存进常用列表
            if not ssid.strip() or cfg.get("disabled") or not wwan_up:
                continue
            bname = band_name(band)
            enc = cfg.get("encryption", "psk2")
            key = cfg.get("key", "")
            existing = next((x for x in saved if x.get("ssid") == ssid and x.get("band") == bname), None)
            if not existing and (enc == "none" or key):
                saved.insert(0, {
                    "ssid": ssid, "band": bname, "encryption": enc,
                    "pw": protect(key) if key else "",
                    "updated": time.strftime("%Y-%m-%d %H:%M"),
                })
                changed = True
        if changed:
            self._cfg["saved_wifi"] = saved[:20]
            save_cfg(self._cfg)

    def _parse_wifi_scan_output(self, out: str, slow: dict | None) -> list[dict]:
        own_bssids = {v.get("bssid", "").upper() for v in (slow or {}).get("iwinfo", {}).values() if v.get("bssid")}
        cur_stas = {(cfg.get("ssid", ""), band_name(band)) for _, _, band, _, cfg, _ in sta_list(slow) if not cfg.get("disabled")}
        saved_keys = {(x.get("ssid"), x.get("band")): x for x in self._cfg.get("saved_wifi", [])}

        secs = split_sections(out)
        best_by_key = {}
        for radio, body in secs.get("SCAN", []):
            results = _json(body, {}).get("results") or []
            for item in results:
                ssid = (item.get("ssid") or "").replace("\r", "").replace("\n", "")
                bssid = (item.get("bssid") or "").upper()
                if not ssid.strip() or bssid in own_bssids:
                    continue
                bname = band_name(item.get("band", 2))
                sig, qpct = normalize_scan_signal(item.get("signal"), item.get("quality"), item.get("quality_max"))
                enc_code, enc_label = parse_scan_encryption(item.get("encryption") or {})
                key = (ssid, bname)
                cand = {
                    "ssid": ssid, "bssid": bssid, "band": bname, "channel": item.get("channel", ""),
                    "signal": sig, "quality": qpct, "encryption": enc_code, "enc_label": enc_label,
                    "current": key in cur_stas,
                    "saved": key in saved_keys,
                }
                prev = best_by_key.get(key)
                if not prev or cand["quality"] > prev["quality"] or (cand["quality"] == prev["quality"] and cand["signal"] > prev["signal"]):
                    best_by_key[key] = cand

        return sorted(best_by_key.values(), key=lambda x: (not x["current"], not x["saved"], -x["quality"], -x["signal"], x["ssid"]))

    def _start_bg_wifi_scan(self, router, radios: list[str] | None = None):
        radios = [r for r in (radios or ["radio0", "radio1"]) if SECTION_RE.match(r)]
        if not radios:
            return
        steps = ["mkdir -p /tmp/rp_wscan_cache"]
        for idx, r in enumerate(radios):
            steps.append(
                f"ubus call iwinfo scan {shlex.quote(json.dumps({'device': r}))} > /tmp/rp_wscan/{r}.tmp 2>/dev/null "
                f"&& cp -f /tmp/rp_wscan/{r}.tmp /tmp/rp_wscan_cache/{r} "
                f"&& mv -f /tmp/rp_wscan/{r}.tmp /tmp/rp_wscan/{r}"
            )
            if idx == 0 and len(radios) > 1:
                steps.append("touch /tmp/rp_wscan/.part")
        seq_sh = "; ".join(steps) + "; date +%s > /tmp/rp_wscan_cache/.ts; touch /tmp/rp_wscan/.done"
        start_cmd = (
            "if [ \"$(cat /tmp/rp_bridge.state 2>/dev/null)\" != \"connecting\" ]; then "
            f"rm -rf /tmp/rp_wscan && mkdir -p /tmp/rp_wscan && ( {seq_sh} ) </dev/null >/dev/null 2>&1 & "
            "fi"
        )
        try:
            router.run(start_cmd, timeout=8)
            self._wifi_scan_inflight = time.monotonic()
        except Exception:
            pass

    def _is_wwan_connected_or_busy(self, slow, fast) -> tuple[bool, bool]:
        wwan = next((i for i in (slow or {}).get("ifaces", []) if i.get("interface") == "wwan"), {})
        stas = sta_list(slow)
        active_sta = next((x for x in stas if not x[4].get("disabled")), None)
        br_state = (fast or {}).get("br_state", "")
        wwan_up = bool(active_sta and wwan.get("up") and wwan.get("ipv4-address"))
        busy = bool(br_state == "connecting" or (active_sta and wwan.get("pending")))
        return wwan_up, busy

    def _maybe_auto_connect_wifi(self) -> bool:
        """若用户勾选了「自动扫描连接记忆库 Wi-Fi」，当未桥接连接且扫描发现记忆库热点时自动触发免密桥接。"""
        if not self._cfg.get("auto_connect_wifi", False) or not self._router:
            return False
        with self._lock:
            slow = self._slow
            fast = self._fast
            scan_items = list(self._wifi_scan_cache or [])
            scan_ts = self._wifi_scan_ts
        if not slow or not fast:
            return False

        wwan_up, busy = self._is_wwan_connected_or_busy(slow, fast)
        if wwan_up:
            self._auto_conn_target = None
            return False
        if busy:
            return False

        now_m = time.monotonic()
        br_state = (fast or {}).get("br_state", "")
        if br_state.startswith("failed:") and self._auto_conn_target:
            self._auto_conn_fail_until[self._auto_conn_target] = now_m + 90.0
            self._auto_conn_target = None

        if now_m - self._manual_disc_ts < 6.0:
            return False
        if now_m - self._auto_conn_last_ts < 36.0:
            return False
        if not scan_items or scan_ts <= 0 or (now_m - scan_ts) > 35.0:
            return False

        saved_list = list(self._cfg.get("saved_wifi", []) or [])
        if not saved_list:
            return False

        by_exact = {}
        by_ssid = {}
        for prof in saved_list:
            s_ssid = (prof.get("ssid") or "").replace("\r", "").replace("\n", "")
            s_band = prof.get("band") if prof.get("band") in ("2.4G", "5G") else "2.4G"
            s_enc = prof.get("encryption", "psk2")
            if not s_ssid.strip():
                continue
            if s_enc != "none":
                try:
                    pw_plain = unprotect(prof["pw"]) if prof.get("pw") else ""
                except Exception:
                    pw_plain = ""
                pw_bytes = len(pw_plain.encode("utf-8"))
                if not ((8 <= pw_bytes <= 63) or re.fullmatch(r"[0-9a-fA-F]{64}", pw_plain)):
                    continue
            else:
                pw_plain = ""
            entry = (prof, pw_plain)
            by_exact.setdefault((s_ssid, s_band), entry)
            by_ssid.setdefault(s_ssid, entry)

        if not by_ssid:
            return False

        uci = dict((slow or {}).get("uci_wifi") or {})
        avail_bands = set()
        for n, d in uci.items():
            if d.get(".type") == "wifi-device" and SECTION_RE.match(n):
                if d.get("band") == "2g":
                    avail_bands.add("2.4G")
                elif d.get("band") == "5g":
                    avail_bands.add("5G")

        candidates = []
        for item in scan_items:
            ssid = (item.get("ssid") or "").replace("\r", "").replace("\n", "")
            band = item.get("band") if item.get("band") in ("2.4G", "5G") else "2.4G"
            scan_enc = item.get("encryption") or "psk2"
            if not ssid.strip() or scan_enc == "eap":
                continue
            if avail_bands and band not in avail_bands:
                continue
            if self._auto_conn_fail_until.get((ssid, band), 0.0) > now_m:
                continue
            exact = (ssid, band) in by_exact
            matched = by_exact.get((ssid, band)) or by_ssid.get(ssid)
            if not matched:
                continue
            prof, pw_plain = matched
            prof_enc = prof.get("encryption", "psk2")
            enc = scan_enc if scan_enc in ("psk2", "sae", "psk", "none") else prof_enc
            if (enc == "none") != (prof_enc == "none"):
                continue
            score = (1 if exact else 0, int(item.get("quality") or 0), int(item.get("signal") or -100))
            candidates.append((score, ssid, band, enc, pw_plain))

        if not candidates:
            return False

        candidates.sort(key=lambda x: x[0], reverse=True)
        _, ssid, band, enc, pw_plain = candidates[0]
        self._auto_conn_last_ts = now_m
        self._auto_conn_target = (ssid, band)
        res = self.connect_bridge(ssid, band, enc, pw_plain, save_profile=False)
        if not res.get("ok"):
            self._auto_conn_fail_until[(ssid, band)] = now_m + 30.0
            self._auto_conn_target = None
            return False
        return True

    def _tick_bg_wifi_scan(self, router):
        """后台非阻塞自动预扫描周边 2.4G/5G 热点，并优先秒读路由器端热缓存，切到「无线桥接」零等待。"""
        with self._lock:
            slow = self._slow
            fast = self._fast
            br_state = (fast or {}).get("br_state", "")
        if not slow or br_state == "connecting":
            return
        radios = [r for r in (list((slow or {}).get("wireless", {}).keys()) or ["radio0", "radio1"]) if SECTION_RE.match(r)]
        if not radios:
            return
        wwan_up, _ = self._is_wwan_connected_or_busy(slow, fast)
        auto_on = bool(self._cfg.get("auto_connect_wifi", False))
        scan_interval = 20.0 if (auto_on and not wwan_up) else 90.0
        now_m = time.monotonic()
        if not self._wifi_scan_cache and not self._wifi_scan_inflight:
            cache_parts = ["TS=$(cat /tmp/rp_wscan_cache/.ts 2>/dev/null); NOW=$(date +%s); echo \"@@AGE $((NOW - ${TS:-0}))\""]
            for r in radios:
                cache_parts.append(f"[ -f /tmp/rp_wscan_cache/{r} ] && {{ echo @@SCAN {r}; cat /tmp/rp_wscan_cache/{r} 2>/dev/null; }}")
            cache_parts.append("echo @@END")
            try:
                _, c_out, _ = router.run("\n".join(cache_parts), timeout=8)
                c_items = self._parse_wifi_scan_output(c_out, slow)
                if c_items:
                    m_age = re.search(r"@@AGE\s+(\d+)", c_out)
                    age_s = int(m_age.group(1)) if m_age else 999
                    with self._lock:
                        self._wifi_scan_cache = c_items
                        self._wifi_scan_seq += 1
                        if age_s < scan_interval:
                            self._wifi_scan_ts = now_m - age_s
                    if age_s < scan_interval:
                        self._maybe_auto_connect_wifi()
                        return
            except Exception:
                pass

        if self._wifi_scan_inflight:
            if now_m - self._wifi_scan_inflight > 28.0:
                self._wifi_scan_inflight = 0.0
                return
            read_parts = [
                "if [ -f /tmp/rp_wscan/.done ]; then echo @@STATE done; "
                "elif [ -f /tmp/rp_wscan/.part ]; then echo @@STATE part; rm -f /tmp/rp_wscan/.part; fi"
            ]
            for r in radios:
                read_parts.append(f"[ -f /tmp/rp_wscan/{r} ] && {{ echo @@SCAN {r}; cat /tmp/rp_wscan/{r} 2>/dev/null; }}")
            read_parts.append("[ -f /tmp/rp_wscan/.done ] && rm -rf /tmp/rp_wscan\necho @@END")
            try:
                _, out, _ = router.run("\n".join(read_parts), timeout=8)
                if "@@STATE done" in out or "@@STATE part" in out:
                    items = self._parse_wifi_scan_output(out, slow)
                    is_done = "@@STATE done" in out
                    with self._lock:
                        if items or is_done:
                            self._wifi_scan_cache = items
                            self._wifi_scan_seq += 1
                        if is_done:
                            self._wifi_scan_ts = now_m
                            self._wifi_scan_inflight = 0.0
                    if is_done:
                        self._maybe_auto_connect_wifi()
            except Exception:
                self._wifi_scan_inflight = 0.0
            return

        if not self._wifi_scan_cache or (now_m - self._wifi_scan_ts) >= scan_interval:
            self._start_bg_wifi_scan(router, radios)
        else:
            self._maybe_auto_connect_wifi()

    def scan_wifi(self):
        if not self._router:
            return {"ok": False, "error": "尚未连接路由器"}
        with self._lock:
            slow = self._slow
        radios = [r for r in (list((slow or {}).get("wireless", {}).keys()) or ["radio0", "radio1"]) if SECTION_RE.match(r)]
        cmd_parts = ["mkdir -p /tmp/rp_wscan_cache"]
        for r in radios:
            arg = json.dumps({"device": r})
            cmd_parts.append(
                f"echo @@SCAN {r}; ubus call iwinfo scan {shlex.quote(arg)} 2>/dev/null | tee /tmp/rp_wscan_cache/{r}"
            )
        cmd_parts.append("date +%s > /tmp/rp_wscan_cache/.ts\necho @@END")
        try:
            _, out, _ = self._router.run("\n".join(cmd_parts), timeout=25)
        except Exception as e:
            return {"ok": False, "error": f"无线扫描失败：{e}"}

        items = self._parse_wifi_scan_output(out, slow)
        with self._lock:
            self._wifi_scan_cache = items
            self._wifi_scan_seq += 1
            self._wifi_scan_ts = time.monotonic()
        self._maybe_auto_connect_wifi()
        return {"ok": True, "networks": items}

    def connect_bridge(self, ssid, band, encryption, password, save_profile=True):
        if not self._router:
            return {"ok": False, "error": "尚未连接路由器"}
        ssid = (ssid or "").replace("\r", "").replace("\n", "")
        if not ssid.strip():
            return {"ok": False, "error": "Wi‑Fi 名称不能为空"}
        band = band if band in ("2.4G", "5G") else "2.4G"
        encryption = encryption if encryption in ("psk2", "sae", "sae-mixed", "psk", "psk-mixed", "none") else "psk2"
        if not (1 <= len(ssid.encode("utf-8")) <= 32):
            return {"ok": False, "error": "Wi‑Fi 名称长度需在 1～32 字节之间（中文每个字占 3 字节）"}

        if password == "__USE_SAVED__":
            prof = next((x for x in self._cfg.get("saved_wifi", []) if x.get("ssid") == ssid and x.get("band") == band), None)
            if not prof:
                return {"ok": False, "error": "未找到已保存的热点密码，请重新输入"}
            encryption = prof.get("encryption", encryption)
            password = unprotect(prof["pw"]) if prof.get("pw") else ""

        if encryption != "none":
            pw_str = password or ""
            pw_bytes = len(pw_str.encode("utf-8"))
            if not ((8 <= pw_bytes <= 63) or re.fullmatch(r"[0-9a-fA-F]{64}", pw_str)):
                return {"ok": False, "error": "Wi‑Fi 密码长度需为 8～63 字节（或 64 位十六进制密钥）"}

        # 查找目标频段对应的无线射频（以 UCI 为准，兼容不同软路由射频命名）
        with self._lock:
            uci = dict((self._slow or {}).get("uci_wifi") or {})
            stas = sta_list(self._slow)
            cur_state = (self._fast or {}).get("br_state", "")
        if cur_state == "connecting":
            return {"ok": False, "error": "上一次桥接切换还在进行中，请等它完成（最多约 1 分钟）"}
        target_band_code = "5g" if band == "5G" else "2g"
        target_radio = next((n for n, d in uci.items()
                             if d.get(".type") == "wifi-device" and d.get("band") == target_band_code and SECTION_RE.match(n)), None)
        if not target_radio:
            return {"ok": False, "error": f"这台路由器没有 {band} 无线射频"}

        # 复用已有 STA section（优先启用中的那个），其余 STA 一律禁用，避免同一射频上出现多个 STA
        stas_ok = [x for x in stas if x[0] and SECTION_RE.match(x[0])]
        primary_sec = next((x[0] for x in stas_ok if not x[4].get("disabled")), None) \
            or (stas_ok[0][0] if stas_ok else "sta_bridge")
        extra_secs = [x[0] for x in stas_ok if x[0] != primary_sec]

        if save_profile:
            saved = [x for x in self._cfg.get("saved_wifi", []) if not (x.get("ssid") == ssid and x.get("band") == band)]
            saved.insert(0, {
                "ssid": ssid, "band": band, "encryption": encryption,
                "pw": protect(password) if (encryption != "none" and password) else "",
                "updated": time.strftime("%Y-%m-%d %H:%M"),
            })
            self._cfg["saved_wifi"] = saved[:20]
            save_cfg(self._cfg)

        q_ssid = shlex.quote(ssid)
        q_ssid_iw = shlex.quote(_iw_escape_ssid(ssid))
        q_band = shlex.quote(target_band_code)
        q_enc = shlex.quote(encryption)
        q_key = shlex.quote(password or "")

        # 终止上一轮残留守护进程，且仅当当前存在启用中的 STA 时才更新备份（防止断开后再连接时把 disabled=1 写进回滚备份）
        cmds = [
            "if [ -f /tmp/rp_bridge.pid ]; then kill $(cat /tmp/rp_bridge.pid) >/dev/null 2>&1 || true; rm -f /tmp/rp_bridge.pid; fi",
            "rm -f /tmp/rp_bridge.state",
            "has_on=0; for s in $(uci -q show wireless | sed -n \"s/^wireless\\.\\([^.]*\\)\\.mode='sta'$/\\1/p\"); do [ \"$(uci -q get wireless.$s.disabled)\" != '1' ] && has_on=1; done; { [ $has_on = 1 ] || [ ! -f /tmp/rp_wireless.bak ]; } && cp /etc/config/wireless /tmp/rp_wireless.bak || true",
            "uci -q get network.wwan >/dev/null || { uci set network.wwan=interface; uci set network.wwan.proto='dhcp'; uci set network.wwan.metric='30'; uci set network.wwan.peerdns='0'; uci commit network; /etc/init.d/network reload >/dev/null 2>&1; }",
            "for z in $(uci -q show firewall | sed -n \"s/^firewall\\.\\([^.]*\\)\\.name='wan'$/\\1/p\"); do uci -q get firewall.$z.network | tr ' ' '\\n' | grep -qx wwan || { uci add_list firewall.$z.network='wwan'; uci commit firewall; /etc/init.d/firewall reload >/dev/null 2>&1; }; done",
            f"uci set wireless.{primary_sec}=wifi-iface",
            f"uci set wireless.{primary_sec}.device='{target_radio}'",
            f"uci set wireless.{primary_sec}.mode='sta'",
            f"uci set wireless.{primary_sec}.network='wwan'",
            f"uci set wireless.{primary_sec}.ssid={q_ssid}",
            f"uci set wireless.{primary_sec}.encryption={q_enc}",
            f"uci -q delete wireless.{primary_sec}.bssid",
            f"uci set wireless.{primary_sec}.disabled='0'",
        ]
        if encryption == "none":
            cmds.append(f"uci -q delete wireless.{primary_sec}.key")
        else:
            cmds.append(f"uci set wireless.{primary_sec}.key={q_key}")
        for es in extra_secs:
            cmds.append(f"uci set wireless.{es}.disabled='1'")
        cmds.append("uci commit wireless")

        # 后台守护（全部在路由器上执行，电脑断线也不影响）：
        #  兼容所有 mac80211 无线接口命名及中文/Emoji/特殊字符 SSID（iw 会将非 ASCII 字节转义为 \xHH）。
        watchdog = f"""
echo $$ > /tmp/rp_bridge.pid
trap 'rm -f /tmp/rp_bridge.pid' EXIT INT TERM
T={q_ssid}
T_IW={q_ssid_iw}
TB={q_band}
echo connecting > /tmp/rp_bridge.state
wifi reload
ssid_match() {{
  [ -z "$3" ] && return 0
  [ "$1" = "$3" ] && return 0
  [ -n "$4" ] && [ "$1" = "$4" ] && return 0
  dec=$(printf '%b' "$1" 2>/dev/null)
  [ -n "$dec" ] && [ "$dec" = "$3" ] && return 0
  iws=$(ubus call iwinfo info "{{\\"device\\":\\"$2\\"}}" 2>/dev/null | jsonfilter -e '@.ssid' 2>/dev/null)
  [ -n "$iws" ] && [ "$iws" = "$3" ] && return 0
  return 1
}}
linked_dev() {{
  for d in $(iw dev 2>/dev/null | awk '$1=="Interface"{{i=$2}} $1=="type"&&$2=="managed"{{print i}}'); do
    lk=$(iw dev "$d" link 2>/dev/null)
    printf '%s\\n' "$lk" | grep -q '^Connected to ' || continue
    if [ -n "$3" ]; then
      fq=$(printf '%s\\n' "$lk" | awk '$1=="freq:"{{printf "%d",$2}}')
      if [ -n "$fq" ] && [ "$fq" -gt 0 ] 2>/dev/null; then
        [ "$3" = "5g" ] && [ "$fq" -lt 4900 ] && continue
        [ "$3" = "2g" ] && [ "$fq" -ge 4900 ] && continue
      fi
    fi
    s=$(printf '%s\\n' "$lk" | sed -n 's/^[[:space:]]*SSID: //p')
    if ssid_match "$s" "$d" "$1" "$2"; then
      printf '%s' "$d"
      return 0
    fi
  done
  return 1
}}
ok=0; i=0; wip=""
while [ $i -lt 22 ]; do
  sleep 2; i=$((i+1))
  ldev=$(linked_dev "$T" "$T_IW" "$TB") || continue
  wst=$(ubus call network.interface.wwan status 2>/dev/null)
  wip=$(printf '%s\\n' "$wst" | jsonfilter -e '@["ipv4-address"][0].address' 2>/dev/null)
  wdev=$(printf '%s\\n' "$wst" | jsonfilter -e '@.l3_device' 2>/dev/null)
  if [ -n "$wip" ] && {{ [ -z "$wdev" ] || [ "$wdev" = "$ldev" ]; }}; then
    ok=1; break
  fi
done
if [ $ok = 1 ]; then
  lip=$(uci -q get network.lan.ipaddr | cut -d/ -f1)
  if [ -n "$lip" ] && [ "${{wip%.*}}" = "${{lip%.*}}" ]; then
    echo "failed:已连上热点，但上级热点 (${{wip%.*}}.x) 与本路由 LAN (${{lip}}) 网段冲突，请更换热点或修改路由网段。" > /tmp/rp_bridge.state
  else
    echo ok > /tmp/rp_bridge.state
    [ -x /etc/openclash/custom/ipguard.sh ] && ( /etc/openclash/custom/ipguard.sh >/dev/null 2>&1 & )
  fi
else
  if [ -f /tmp/rp_wireless.bak ]; then
    cp /tmp/rp_wireless.bak /etc/config/wireless
    wifi reload
  fi
  up2=0; i=0
  while [ $i -lt 12 ]; do sleep 2; i=$((i+1)); if linked_dev "" "" "" >/dev/null; then up2=1; break; fi; done
  if [ $up2 = 0 ]; then
    for s in $(uci -q show wireless | sed -n "s/^wireless\\.\\([^.]*\\)\\.mode='sta'$/\\1/p"); do uci set wireless.$s.disabled='1'; done
    uci commit wireless; wifi reload
    echo 'failed:没能连上目标 Wi-Fi（密码错误或信号太弱）。原桥接也连不上，已暂停无线桥接，路由器自身 Wi-Fi 正常。' > /tmp/rp_bridge.state
  else
    echo 'failed:没能连上目标 Wi-Fi（密码错误或信号太弱），已自动恢复成切换前的桥接。' > /tmp/rp_bridge.state
    [ -x /etc/openclash/custom/ipguard.sh ] && ( /etc/openclash/custom/ipguard.sh >/dev/null 2>&1 & )
  fi
fi
"""
        # 守护脚本用 heredoc 写入路由器 /tmp（路由器没有 base64），再后台执行
        full_cmd = "; ".join(cmds) + (
            "\ncat > /tmp/rp_bridge.sh <<'RP_BRIDGE_EOF'\n" + watchdog.strip("\n") + "\nRP_BRIDGE_EOF\n"
            "( /bin/sh /tmp/rp_bridge.sh ) </dev/null >/dev/null 2>&1 &\n")
        try:
            self._router.run(full_cmd, timeout=15)
        except Exception:
            # Wi-Fi 重载瞬间若本机正连着同一射频，SSH 可能短暂闪断，属正常现象
            pass
        self._force.set()
        return {"ok": True}

    def disconnect_bridge(self):
        if not self._router:
            return {"ok": False, "error": "尚未连接路由器"}
        stas = [sec for sec, *_ in sta_list(self._slow) if sec and SECTION_RE.match(sec)]
        if not stas:
            return {"ok": True}
        cmds = [
            "if [ -f /tmp/rp_bridge.pid ]; then kill $(cat /tmp/rp_bridge.pid) >/dev/null 2>&1 || true; rm -f /tmp/rp_bridge.pid; fi",
            "rm -f /tmp/rp_bridge.state",
            "has_on=0; for s in $(uci -q show wireless | sed -n \"s/^wireless\\.\\([^.]*\\)\\.mode='sta'$/\\1/p\"); do [ \"$(uci -q get wireless.$s.disabled)\" != '1' ] && has_on=1; done; [ $has_on = 1 ] && cp /etc/config/wireless /tmp/rp_wireless.bak || true",
        ] + [f"uci set wireless.{s}.disabled='1'" for s in stas] + [
            "uci commit wireless",
            "( sleep 1; wifi reload ) </dev/null >/dev/null 2>&1 &",
        ]
        try:
            self._router.run("; ".join(cmds), timeout=12)
        except Exception:
            pass
        self._manual_disc_ts = time.monotonic()
        self._wifi_scan_ts = 0.0
        self._auto_conn_target = None
        self._force.set()
        return {"ok": True}

    def delete_saved_wifi(self, ssid, band):
        self._cfg["saved_wifi"] = [
            x for x in self._cfg.get("saved_wifi", [])
            if not (x.get("ssid") == ssid and x.get("band") == band)
        ]
        save_cfg(self._cfg)
        return True

    def clear_bridge_msg(self):
        if self._router:
            try:
                self._router.run("rm -f /tmp/rp_bridge.state", timeout=5)
            except Exception:
                pass
        self._force.set()
        return True

    # ---------------------------------------------------------- 路由器端内核分流流量守护与同步
    def _ensure_router_traffic_collector(self, router):
        if self._traffic_collector_ready:
            return
        try:
            _, chk, _ = router.run(
                "if grep -q '^# rp-traffic-v3$' /usr/sbin/rp-traffic-collect 2>/dev/null "
                "&& [ -x /usr/sbin/rp-traffic-collect ] "
                "&& [ -x /etc/init.d/rp-traffic ]; then echo ok; else echo missing; fi",
                timeout=10,
            )
            if chk.strip() != "ok":
                router.run(
                    "cat > /usr/sbin/rp-traffic-collect && chmod 0755 /usr/sbin/rp-traffic-collect",
                    timeout=12,
                    stdin_data=RP_TRAFFIC_SCRIPT.replace("\r\n", "\n"),
                )
                router.run(
                    "cat > /etc/init.d/rp-traffic && chmod 0755 /etc/init.d/rp-traffic && /etc/init.d/rp-traffic enable >/dev/null 2>&1 || true",
                    timeout=12,
                    stdin_data=RP_TRAFFIC_INITD.replace("\r\n", "\n"),
                )
                hotplug_sh = (
                    "#!/bin/sh\n"
                    "# rp-traffic-v1\n"
                    "[ \"$ACTION\" = \"ifup\" ] && [ -x /usr/sbin/rp-traffic-collect ] && ( /usr/sbin/rp-traffic-collect sync-ips >/dev/null 2>&1 & )\n"
                )
                router.run(
                    "mkdir -p /etc/hotplug.d/iface && cat > /etc/hotplug.d/iface/95-rp-traffic && chmod 0644 /etc/hotplug.d/iface/95-rp-traffic",
                    timeout=10,
                    stdin_data=hotplug_sh,
                )
            router.run(
                "mkdir -p /etc/crontabs; touch /etc/crontabs/root; "
                "grep -q '/usr/sbin/rp-traffic-collect' /etc/crontabs/root || "
                "{ echo '*/1 * * * * /usr/sbin/rp-traffic-collect collect >/dev/null 2>&1' >> /etc/crontabs/root; /etc/init.d/cron reload >/dev/null 2>&1 || true; }; "
                "/usr/sbin/rp-traffic-collect init >/dev/null 2>&1 || true",
                timeout=15,
            )
            self._traffic_collector_ready = True
        except Exception as e:
            print("ensure_router_traffic_collector:", e)

    def _sync_traffic_from_router(self, router, full: bool = False):
        host = getattr(router, "host", "")
        if not host:
            return
        try:
            self._ensure_router_traffic_collector(router)
            if full:
                cmd = (
                    "/usr/sbin/rp-traffic-collect collect >/dev/null 2>&1 || true\n"
                    "echo @@T5M; cat /tmp/rp_traffic/min5.tsv 2>/dev/null\n"
                    "echo @@T1H; cat /tmp/rp_traffic/hourly.tsv 2>/dev/null\n"
                    "echo @@T1D; cat /tmp/rp_traffic/daily.tsv 2>/dev/null\n"
                    "echo @@END\n"
                )
            else:
                cmd = (
                    "/usr/sbin/rp-traffic-collect collect >/dev/null 2>&1 || true\n"
                    "echo @@T5M; tail -n 36 /tmp/rp_traffic/min5.tsv 2>/dev/null\n"
                    "echo @@T1H; tail -n 8 /tmp/rp_traffic/hourly.tsv 2>/dev/null\n"
                    "echo @@T1D; tail -n 4 /tmp/rp_traffic/daily.tsv 2>/dev/null\n"
                    "echo @@END\n"
                )
            _, out, _ = router.run(cmd, timeout=15)
            secs = split_sections(out)
            self._traffic_store.upsert_tsv(host, "buckets_5m", _one(secs, "T5M"))
            self._traffic_store.upsert_tsv(host, "buckets_1h", _one(secs, "T1H"))
            self._traffic_store.upsert_tsv(host, "buckets_1d", _one(secs, "T1D"))
            self._traffic_quick_ts = 0.0
        except Exception as e:
            print("sync_traffic_from_router:", e)

    def _live_traffic_delta(self) -> tuple[int, int, int, int]:
        f = self._fast or {}
        cnt = f.get("nft_cnt")
        prv = f.get("rpt_prev")
        if not cnt or not prv:
            return (0, 0, 0, 0)
        return tuple(max(0, cnt[i] - prv[i]) if cnt[i] >= prv[i] else cnt[i] for i in range(4))

    def _tick_sub_userinfo(self, router):
        """后台静默同步订阅响应头中的流量账单与到期时间，免去必须点击更新才显示。"""
        now_m = time.monotonic()
        if self._sub_hdr_ts and (now_m - self._sub_hdr_ts) < 1800:
            return
        with self._lock:
            csub = dict((self._slow or {}).get("clash_sub") or {})
        sub_url = (csub.get("sub_url") or "").strip()
        if not sub_url.startswith(("http://", "https://")):
            self._sub_hdr_ts = now_m
            return
        ua = (csub.get("sub_ua") or "clash.meta").strip() or "clash.meta"
        self._sub_hdr_ts = now_m
        try:
            _, hdr, _ = router.run(
                f"curl -sIL -m 6 -A {shlex.quote(ua)} {shlex.quote(sub_url)} 2>/dev/null || "
                f"curl -s -m 6 -D - -o /dev/null -A {shlex.quote(ua)} {shlex.quote(sub_url)} 2>/dev/null",
                timeout=10,
            )
            parsed = parse_sub_headers(hdr)
            if parsed:
                with self._lock:
                    self._sub_meta.update(parsed)
                    self._slow_seq += 1
        except Exception:
            pass

    # ---------------------------------------------------------- 轮询循环
    def _loop(self, router, stop):
        n = 0
        while not stop.is_set():
            try:
                if n == 0:
                    self._sync_traffic_from_router(router, full=True)
                elif n % 15 == 0:
                    self._sync_traffic_from_router(router, full=False)
                if n % SLOW_EVERY == 0 or self._force.is_set():
                    self._force.clear()
                    slow = parse_slow(router.run(SLOW_CMD, timeout=30)[1])
                    if stop.is_set():
                        return
                    with self._lock:
                        self._slow = slow
                        self._slow_seq += 1
                        self._sync_current_sta_to_saved(slow)
                        cur_wwan_up, _ = self._is_wwan_connected_or_busy(slow, self._fast)
                        if self._prev_wwan_up and not cur_wwan_up:
                            self._wifi_scan_ts = 0.0
                        self._prev_wwan_up = cur_wwan_up
                fast = parse_fast(router.run(FAST_CMD)[1])
                if stop.is_set():
                    return
                if fast.get("br_state") and (not self._fast or fast.get("br_state") != self._fast.get("br_state")):
                    self._force.set()
                with self._lock:
                    self._on_fast(fast)
                self._tick_bg_wifi_scan(router)
                self._tick_sub_userinfo(router)
                self._status, self._error = "online", ""
                self._updated = time.strftime("%H:%M:%S")
                n += 1
            except paramiko.AuthenticationException:
                if not stop.is_set():
                    self._status, self._error = "auth_failed", "软路由登录账号或密码已变更，请重新登录"
                return
            except paramiko.BadHostKeyException:
                if not stop.is_set():
                    self._status, self._error = "auth_failed", "检测到该 IP 路由器已重刷固件（SSH 密钥变更），请重新确认密码登录"
                return
            except Exception as e:
                if stop.is_set():
                    return
                self._status, self._error = "offline", str(e) or e.__class__.__name__
                router.close()
                n = 0
                stop.wait(2.5)
                continue
            for _ in range(int(FAST_INTERVAL * 10)):
                if stop.is_set() or self._force.is_set():
                    break
                time.sleep(0.1)

    def _wan_devs(self):
        return {i["l3_device"] for i in (self._slow or {}).get("ifaces", [])
                if i.get("up") and i.get("interface") not in ("lan", "loopback") and i.get("l3_device")}

    def _on_fast(self, f):
        prev, self._fast = self._fast, f
        if not prev:
            return
        dt = max(0.1, f["t"] - prev["t"])
        wan = self._wan_devs()
        nd, pd = f["netdev"], prev["netdev"]
        down = sum(max(0, nd[d][0] - pd[d][0]) for d in wan if d in nd and d in pd) / dt
        up = sum(max(0, nd[d][1] - pd[d][1]) for d in wan if d in nd and d in pd) / dt
        self._hist.append((down, up))
        self._rate = {"down": down, "up": up}
        nc, pnc = f.get("nft_cnt"), prev.get("nft_cnt")
        if nc and pnc:
            self._proxy_rate = (
                max(0, nc[0] - pnc[0]) / dt if nc[0] >= pnc[0] else 0.0,
                max(0, nc[1] - pnc[1]) / dt if nc[1] >= pnc[1] else 0.0,
            )
            self._direct_rate = (
                max(0, nc[2] - pnc[2]) / dt if nc[2] >= pnc[2] else 0.0,
                max(0, nc[3] - pnc[3]) / dt if nc[3] >= pnc[3] else 0.0,
            )
        if prev.get("cpu") and f.get("cpu"):
            a, b = prev["cpu"], f["cpu"]
            tot = sum(b) - sum(a)
            idle = (b[3] + b[4]) - (a[3] + a[4])
            self._cpu = 100 * (1 - idle / tot) if tot > 0 else 0
        for cl in f["clients"].values():
            for mac, c in cl.items():
                rx, tx = c.get("bytes", {}).get("rx", 0), c.get("bytes", {}).get("tx", 0)
                p = self._client_prev.get(mac)
                if p and f["t"] > p[0]:
                    self._client_rate[mac] = (max(0, tx - p[2]) / (f["t"] - p[0]), max(0, rx - p[1]) / (f["t"] - p[0]))
                self._client_prev[mac] = (f["t"], rx, tx)
        cc, pc = f.get("clash_conn"), prev.get("clash_conn")
        if cc and pc:
            cd = max(0, cc.get("downloadTotal", 0) - pc.get("downloadTotal", 0)) / dt
            cu = max(0, cc.get("uploadTotal", 0) - pc.get("uploadTotal", 0)) / dt
            self._clash_rate = (cd, cu)
            self._clash_hist.append((cd, cu))
        else:
            self._clash_hist.append((0, 0))
        if cc:
            now, newprev = f["t"], {}
            for c in cc.get("connections") or []:
                cid = c.get("id")
                p = self._conn_prev.get(cid)
                if p:
                    c["_ds"] = max(0, c.get("download", 0) - p[1]) / max(0.1, now - p[0])
                    c["_us"] = max(0, c.get("upload", 0) - p[2]) / max(0.1, now - p[0])
                newprev[cid] = (now, c.get("download", 0), c.get("upload", 0))
            self._conn_prev = newprev

    # ---------------------------------------------------------- 给界面的快照
    def tray_status(self) -> dict:
        with self._lock:
            f = self._fast or {}
            ipg = f.get("ipguard") or {}
            return {
                "status": self._status,
                "gate": f.get("gate") or "",
                "exit_ip": ipg.get("exit_ip") or "",
                "privacy_mode": bool(self._cfg.get("privacy_mode", False)),
            }

    def snapshot(self):
        return self.snapshot_delta(0, 0, "", True)

    def snapshot_delta(self, client_slow_seq: int = 0, client_scan_seq: int = 0, page: str = "", drawer_open: bool = False):
        creds = self._active_creds() or {}
        saved_routers = [
            {"host": x.get("host"), "port": int(x.get("port", 22)), "user": x.get("user")}
            for x in self._cfg.get("saved_routers", [])
        ]
        base = {
            "status": self._status, "error": self._error, "updated": self._updated,
            "host": creds.get("host") or self._cfg.get("host") or self._default_gw,
            "default_gw": self._default_gw,
            "port": int(creds.get("port") or self._cfg.get("port", 22)),
            "user": creds.get("user") or self._cfg.get("user", "root"),
            "saved_routers": saved_routers,
            "topmost": bool(self._cfg.get("topmost")),
            "close_to_tray": bool(self._cfg.get("close_to_tray", True)),
            "auto_connect_wifi": bool(self._cfg.get("auto_connect_wifi", False)),
            "auto_start": bool(self._cfg.get("auto_start", False)),
            "alerts_enabled": bool(self._cfg.get("alerts_enabled", True)),
            "privacy_mode": bool(self._cfg.get("privacy_mode", False)),
            "theme": self._cfg.get("theme", "dark"),
            "accent": self._cfg.get("accent", "claude"),
            "font_scale": float(self._cfg.get("font_scale", 1.0)),
            "logged_in": self._router is not None,
            "slow_seq": self._slow_seq,
        }
        with self._lock:
            if not (self._slow and self._fast):
                return base
            try:
                base["slow_seq"] = self._slow_seq
                need_nodes = (not page) or (page == "proxy") or drawer_open or (client_slow_seq != self._slow_seq)
                conn_limit = 260 if (not page or page == "conns" or drawer_open) else (35 if page == "overview" else 0)
                need_scan = (not client_scan_seq) or (client_scan_seq != self._wifi_scan_seq)
                base.update(self._build(need_nodes=need_nodes, conn_limit=conn_limit, need_scan=need_scan))
            except Exception as e:
                base["build_error"] = repr(e)
        return base

    def _build(self, need_nodes: bool = True, conn_limit: int = 300, need_scan: bool = True):
        s, f = self._slow, self._fast
        b = s.get("board", {})
        m = f["mem"]
        mem_total = m.get("MemTotal", 0)
        mem_used = mem_total - m.get("MemAvailable", m.get("MemFree", 0))
        wan = self._wan_devs()
        lan_ip = next((a["address"] for i in s.get("ifaces", []) if i.get("interface") == "lan"
                       for a in i.get("ipv4-address", [])), self._cfg.get("host") or self._default_gw)
        router = {"hostname": b.get("hostname", ""), "model": b.get("model", ""),
                  "arch": b.get("system", ""), "lan_ip": lan_ip,
                  "version": b.get("release", {}).get("version", ""), "kernel": b.get("kernel", ""),
                  "target": b.get("release", {}).get("target", ""),
                  "uptime": f["uptime"], "cpu": self._cpu, "mem_used": mem_used * 1024, "mem_total": mem_total * 1024,
                  "temp": f["temp"], "load": f["load"], "conntrack": f["conntrack"], "ping": s.get("ping"),
                  "gate": f.get("gate", ""), "ipguard": f.get("ipguard") or {}}
        hist_padded = pad_series(self._hist, min_len=24)
        speed = {"down": self._rate.get("down", 0), "up": self._rate.get("up", 0),
                 "peak_down": max((x[0] for x in self._hist), default=0),
                 "peak_up": max((x[1] for x in self._hist), default=0),
                 "total_down": sum(f["netdev"].get(d, (0, 0))[0] for d in wan),
                 "total_up": sum(f["netdev"].get(d, (0, 0))[1] for d in wan),
                 "hist": hist_padded, "samples": len(self._hist)}
        links = self._links()
        bridge = self._bridge()
        modes = {
            "wired": {"up": False, "current": False, "ip": "", "detail": "未接入网线"},
            "wifi": {"up": False, "current": False, "ip": "", "ssid": "", "detail": "未连接现场 Wi-Fi"},
            "cellular": {"up": False, "current": False, "ip": "", "detail": "未插入 4G/5G 上网卡"},
        }
        active_kind = ""
        for lk in links:
            k = lk.get("kind")
            if k not in modes:
                continue
            m_item = modes[k]
            if lk.get("up") or not m_item["up"]:
                m_item["up"] = bool(lk.get("up")) or m_item["up"]
                if lk.get("current"):
                    m_item["current"] = True
                    active_kind = k
                if lk.get("ip") and (lk.get("current") or not m_item["ip"]):
                    m_item["ip"] = lk["ip"]
                if k == "wifi":
                    ssid = lk.get("ssid") or bridge.get("ssid") or ""
                    m_item["ssid"] = ssid
                    m_item["detail"] = f"{ssid} ({lk.get('ip') or '已连接'})" if lk.get("up") else "未连接现场 Wi-Fi"
                elif k == "wired":
                    m_item["detail"] = f"已接通 ({lk.get('ip')})" if lk.get("up") else "网口未插线或未获 IP"
                elif k == "cellular":
                    m_item["detail"] = f"已拨号 ({lk.get('ip')})" if lk.get("up") else "上网卡待拨号"
        if not active_kind:
            for k in ("wired", "wifi", "cellular"):
                if modes[k]["up"]:
                    active_kind = k
                    break
        net_mode = {"active": active_kind, "modes": modes}
        cur_host = (self._active_creds() or {}).get("host") or self._cfg.get("host") or self._default_gw
        now_m = time.monotonic()
        if not self._traffic_quick_cache or (now_m - self._traffic_quick_ts) >= 8.0:
            self._traffic_quick_cache = self._traffic_store.quick_totals(cur_host, (0, 0, 0, 0))
            self._traffic_quick_ts = now_m
        ld = self._live_traffic_delta()
        base_today = self._traffic_quick_cache.get("today") or {}
        t_pd = base_today.get("proxy_down", 0) + ld[0]
        t_pu = base_today.get("proxy_up", 0) + ld[1]
        t_dd = base_today.get("direct_down", 0) + ld[2]
        t_du = base_today.get("direct_up", 0) + ld[3]
        traffic_live = {
            "proxy_down_rate": self._proxy_rate[0],
            "proxy_up_rate": self._proxy_rate[1],
            "direct_down_rate": self._direct_rate[0],
            "direct_up_rate": self._direct_rate[1],
            "today": {
                "proxy_down": t_pd,
                "proxy_up": t_pu,
                "proxy_total": t_pd + t_pu,
                "direct_down": t_dd,
                "direct_up": t_du,
                "direct_total": t_dd + t_du,
                "total_down": t_pd + t_dd,
                "total_up": t_pu + t_du,
                "grand_total": t_pd + t_pu + t_dd + t_du,
            },
            "d7_total": (self._traffic_quick_cache.get("d7") or {}).get("grand_total", 0) + sum(ld),
            "quarter_total": (self._traffic_quick_cache.get("quarter") or {}).get("grand_total", 0) + sum(ld),
            "year_total": (self._traffic_quick_cache.get("year") or {}).get("grand_total", 0) + sum(ld),
        }
        devs = self._devices()
        out_dict = {
            "router": router, "router_cfg": self._router_cfg(), "speed": speed, "links": links,
            "bridge": bridge, "net_mode": net_mode,
            "wifi": self._wifi(), "wifi_scan_seq": self._wifi_scan_seq,
            "wifi_scanning": bool(self._wifi_scan_inflight and not self._wifi_scan_cache),
            "devices": devs,
            "clash": self._clash(len(hist_padded), devs=devs, need_nodes=need_nodes, conn_limit=conn_limit),
            "traffic_live": traffic_live,
        }
        if need_scan:
            out_dict["wifi_scan"] = self._wifi_scan_cache
        else:
            out_dict["wifi_scan_omitted"] = True
        return out_dict

    def _bridge(self):
        s, f = self._slow, self._fast
        wwan = next((i for i in s.get("ifaces", []) if i.get("interface") == "wwan"), {})
        stas = sta_list(s)
        active_sta = next((x for x in stas if not x[4].get("disabled")), stas[0] if stas else None)
        br_state = f.get("br_state", "")
        saved = [
            {"ssid": x.get("ssid"), "band": x.get("band"), "encryption": x.get("encryption", "psk2"),
             "updated": x.get("updated", "")}
            for x in self._cfg.get("saved_wifi", [])
        ]
        if not active_sta:
            return {"configured": False, "enabled": False, "up": False, "pending": br_state == "connecting",
                    "state_msg": br_state[7:] if br_state.startswith("failed:") else "", "saved": saved}

        sec, ifn, band, radio, cfg, rd = active_sta
        iw = s.get("iwinfo", {}).get(ifn, {})
        enabled = not cfg.get("disabled")
        up = bool(enabled and wwan.get("up"))
        ip = ", ".join(a["address"] for a in wwan.get("ipv4-address", [])) if up else ""
        gw = next((r["nexthop"] for r in wwan.get("route", []) if r.get("target") == "0.0.0.0"), "") if up else ""
        qual = iw.get("quality", "")
        return {
            "configured": True, "enabled": enabled, "up": up,
            "pending": bool((enabled and wwan.get("pending")) or br_state == "connecting"),
            "ssid": cfg.get("ssid", ""), "band": band_name(band),
            "encryption": cfg.get("encryption", "psk2"),
            "ip": ip, "gw": gw, "uptime": wwan.get("uptime", 0) if up else 0,
            "quality": qual, "bitrate": iw.get("bitrate", ""), "channel": iw.get("channel", ""),
            "state_msg": br_state[7:] if br_state.startswith("failed:") else "",
            "saved": saved,
        }

    def _links(self):
        s = self._slow
        usb_net = s.get("usb_net") or set()
        stas = {}
        for x in sta_list(s):
            nk = (x[4].get("network") or [""])[0]
            if nk and (nk not in stas or not x[4].get("disabled")):
                stas[nk] = x
        out, best = [], None
        for itf in s.get("ifaces", []):
            name = itf.get("interface")
            if name in ("lan", "loopback"):
                continue
            gw = next((r["nexthop"] for r in itf.get("route", []) if r.get("target") == "0.0.0.0"), "")
            if itf.get("up") and gw and (best is None or itf.get("metric", 99) < best[1]):
                best = (name, itf.get("metric", 99))
            proto = itf.get("proto", "")
            is_v6 = proto in ("dhcpv6", "6in4", "6to4", "6rd") or name.endswith("6")
            dev_raw = itf.get("l3_device") or itf.get("device") or ""
            dev_base = dev_raw.split(".")[0].split("@")[0]
            if is_v6:
                kind = "ipv6"
            elif name == "wwan" or name in stas:
                kind = "wifi"
            elif (dev_base in usb_net or dev_raw in usb_net
                  or proto in ("qmi", "ncm", "mbim", "3g", "modemmanager", "rndis")
                  or any(k in (name or "").lower() for k in ("usb", "modem", "4g", "5g", "lte", "tether"))):
                kind = "cellular"
            else:
                kind = "wired"
            v6_off = bool(is_v6 and s.get("ipv6_off"))
            raw_pending = bool(itf.get("pending")) and not v6_off
            note = "已关闭 IPv6（防泄露保护）" if v6_off else ("上级未分配 IPv6（不影响上网）" if (is_v6 and not itf.get("up") and raw_pending) else "")
            label = "4G/5G 上网卡" if (kind == "cellular" and name not in IFACE_LABEL) else IFACE_LABEL.get(name, name)
            d = {"name": name, "label": label, "kind": kind, "up": bool(itf.get("up")),
                 "pending": False if is_v6 else raw_pending, "proto": proto, "note": note,
                 "ip": ", ".join(a["address"] for a in itf.get("ipv4-address", [])) or ", ".join(a["address"] for a in itf.get("ipv6-address", [])),
                 "gw": gw, "uptime": itf.get("uptime", 0) if itf.get("up") else 0, "device": itf.get("l3_device", "")}
            if name in stas:
                sec, ifn, band, radio, cfg, rd = stas[name]
                iw = s.get("iwinfo", {}).get(ifn, {})
                d.update(ssid=cfg.get("ssid", ""), bitrate=iw.get("bitrate", ""), quality=iw.get("quality", ""))
            out.append(d)
        for d in out:
            d["current"] = bool(best and best[0] == d["name"])
        out.sort(key=lambda d: (not d["current"], not d["up"], d["name"]))
        return out

    def _router_cfg(self):
        s = self._slow or {}
        unet = s.get("uci_net") or {}
        udhcp = s.get("uci_dhcp") or {}
        uwifi = s.get("uci_wifi") or {}
        lan = unet.get("lan") or {}
        wan = unet.get("wan") or {}
        wwan = unet.get("wwan") or {}
        dlan = udhcp.get("lan") or {}
        raw_ip = str(lan.get("ipaddr") or "").strip()
        if isinstance(lan.get("ipaddr"), list) and lan["ipaddr"]:
            raw_ip = str(lan["ipaddr"][0]).strip()
        lan_ip = raw_ip.split("/")[0] if raw_ip else (self._cfg.get("host") or self._default_gw)
        try:
            d_start = int(dlan.get("start") or 100)
        except Exception:
            d_start = 100
        try:
            d_limit = int(dlan.get("limit") or 150)
        except Exception:
            d_limit = 150
        d_lease = str(dlan.get("leasetime") or "12h").strip() or "12h"
        d_en = str(dlan.get("ignore", "0")) != "1"
        try:
            wan_m = int(wan.get("metric") or 10)
        except Exception:
            wan_m = 10
        try:
            wwan_m = int(wwan.get("metric") or 30)
        except Exception:
            wwan_m = 30
        country = "KR"
        for _, d in uwifi.items():
            if d.get(".type") == "wifi-device" and d.get("country"):
                country = str(d.get("country")).strip().upper()
                break
        return {
            "lan_ip": lan_ip,
            "dhcp_enabled": d_en,
            "dhcp_start": d_start,
            "dhcp_limit": d_limit,
            "dhcp_lease": d_lease,
            "wan_metric": wan_m,
            "wwan_metric": wwan_m,
            "prefer_wan": "wifi" if (wwan and wwan_m < wan_m) else "wired",
            "country": country,
        }

    def _wifi(self):
        out = []
        s = self._slow or {}
        uci = s.get("uci_wifi") or {}
        clients = self._fast.get("clients", {})
        sta_radios = {x[3] for x in sta_list(s) if x[3] and not x[4].get("disabled")}
        for sec, ifn, band, radio, cfg, rd in ap_list(s):
            iw = s.get("iwinfo", {}).get(ifn, {})
            d_uci = uci.get(sec) or {}
            r_uci = uci.get(radio) or {}
            raw_enc = cfg.get("encryption", "psk2")
            cfg_en = not bool(cfg.get("disabled"))
            b_label = band_name(band)
            def_ht = "HE80" if b_label == "5G" else "HE20"
            out.append({
                "section": sec or "",
                "ifname": ifn or "",
                "radio": radio or "",
                "band": b_label,
                "ssid": cfg.get("ssid", ""),
                "key": cfg.get("key", ""),
                "raw_enc": raw_enc,
                "hidden": bool(cfg.get("hidden")),
                "isolate": str(d_uci.get("isolate", "0")) == "1",
                "roaming": str(d_uci.get("ieee80211k", "0")) == "1" or str(d_uci.get("bss_transition", "0")) == "1",
                "cfg_enabled": cfg_en,
                "enabled": bool(cfg_en and (rd.get("up", True) if rd else True)),
                "channel": iw.get("channel") or (rd or {}).get("config", {}).get("channel", ""),
                "cfg_channel": str(r_uci.get("channel") or "auto"),
                "htmode": iw.get("htmode") or str(r_uci.get("htmode") or ""),
                "cfg_htmode": str(r_uci.get("htmode") or iw.get("htmode") or def_ht),
                "txpower": iw.get("txpower", ""),
                "cfg_txpower": str(r_uci.get("txpower") or "auto"),
                "country": str(r_uci.get("country") or "KR").upper(),
                "shared_sta": bool(radio in sta_radios),
                "bssid": iw.get("bssid") or "",
                "bitrate": iw.get("bitrate") or "",
                "encryption": {
                    "psk2": "WPA2", "sae": "WPA3", "sae-mixed": "WPA2/3", "psk-mixed": "WPA/WPA2",
                    "none": "无密码",
                }.get(raw_enc, raw_enc),
                "clients": len(clients.get(ifn, {})) if ifn else 0,
            })
        return out

    def _devices(self):
        s, f = self._slow, self._fast
        band_of = {ifn: band for _, ifn, band, *_ in ap_list(s) if ifn}
        wl = {mac: (ifn, c) for ifn, cl in f.get("clients", {}).items() for mac, c in cl.items()}
        blocked = set(s.get("rp_blocked") or set())
        for d in s.get("macfilter", {}).values():
            if d.get("macfilter") == "deny":
                blocked.update(d.get("maclist", []))
        proxy_by_ip = {}
        clash_bytes_by_ip = {}
        for c in (f.get("clash_conn") or {}).get("connections") or []:
            ip = c.get("metadata", {}).get("sourceIP", "")
            if ip:
                proxy_by_ip[ip] = proxy_by_ip.get(ip, 0) + 1
                cb = clash_bytes_by_ip.setdefault(ip, [0, 0])
                cb[0] += c.get("download", 0)
                cb[1] += c.get("upload", 0)
        devs = {}
        for l in s.get("leases", []):
            devs[l["mac"]] = {"mac": l["mac"], "ip": l["ip"], "host": l["host"]}
        for mac, (ip, st) in s.get("neigh", {}).items():
            if st in ("FAILED", "INCOMPLETE") and mac not in devs:
                continue
            devs.setdefault(mac, {"mac": mac, "ip": ip, "host": ""})["neigh"] = st
        for mac in list(wl) + list(blocked):
            devs.setdefault(mac, {"mac": mac, "ip": "", "host": ""})
        out = []
        for mac, d in devs.items():
            alias = self._cfg["aliases"].get(mac, "")
            is_blk = mac in blocked
            cb_d, cb_u = clash_bytes_by_ip.get(d["ip"], [0, 0])
            row = {"mac": mac, "ip": d["ip"], "host": d["host"], "alias": alias,
                   "name": alias or d["host"] or "未知设备", "me": d["ip"] in self._my_ips,
                   "blocked": is_blk,
                   "conn": "", "signal": None, "down": 0, "up": 0, "total_down": cb_d, "total_up": cb_u,
                   "proxy_conns": proxy_by_ip.get(d["ip"], 0)}
            if mac in wl:
                ifn, c = wl[mac]
                row["conn"] = f"{band_name(band_of.get(ifn, ''))} Wi‑Fi"
                row["signal"] = c.get("signal")
                row["down"], row["up"] = self._client_rate.get(mac, (0, 0))
                w_down, w_up = c.get("bytes", {}).get("tx", 0), c.get("bytes", {}).get("rx", 0)
                row["total_down"] = max(w_down, cb_d)
                row["total_up"] = max(w_up, cb_u)
                row["state"] = "online"
            else:
                row["conn"] = "有线/其他" if d.get("neigh") else ""
                st = d.get("neigh")
                row["state"] = "online" if st in ("REACHABLE", "DELAY", "PROBE", "PERMANENT") else "idle" if st == "STALE" else "offline"
            if is_blk:
                row["state"] = "blocked"
            row["total_bytes"] = row["total_down"] + row["total_up"]
            out.append(row)
        rank = {"online": 0, "idle": 1, "offline": 2, "blocked": 3}
        out.sort(key=lambda r: (rank[r["state"]], -(r["down"] + r["up"]), -r["total_bytes"], r["name"].lower()))
        return out

    def _clash(self, hist_len=24, devs=None, need_nodes: bool = True, conn_limit: int = 300):
        s, f = self._slow, self._fast
        state = s.get("clash")
        csub = dict(s.get("clash_sub") or {})
        sub_info = {
            "url": csub.get("sub_url", ""),
            "name": csub.get("sub_name") or "sub",
            "ua": csub.get("sub_ua") or "clash.meta",
            "cfg_path": csub.get("cfg_path") or "/etc/openclash/config/sub.yaml",
            "mtime": csub.get("cfg_mtime", ""),
            "size": int(csub["cfg_size"]) if (csub.get("cfg_size") or "").isdigit() else 0,
            "guardline": csub.get("guardline") == "1",
            "expected_ip": csub.get("expected_ip", ""),
            "seal_gen": csub.get("seal_gen", ""),
            **self._sub_meta,
            "task": dict(self._sub_task),
        }
        res = {"state": state, "version": s.get("clash_ver", {}).get("version", ""),
               "meta": s.get("clash_ver", {}).get("meta", False),
               "mode": s.get("clash_cfg", {}).get("mode", ""),
               "dns_mode": (s.get("clash_uci") or [""])[0],
               "config": os.path.basename((s.get("clash_uci") or ["", ""])[1]) if len(s.get("clash_uci") or []) > 1 else "",
               "rule_count": s.get("clash_rules", 0),
               "down": self._clash_rate[0], "up": self._clash_rate[1],
               "hist": pad_series(self._clash_hist, min_len=hist_len),
               "sub": sub_info}
        proxies = s.get("clash_proxies") or {}
        cc = f.get("clash_conn") or {}
        conns = cc.get("connections") or []
        res["total_down"], res["total_up"] = cc.get("downloadTotal", 0), cc.get("uploadTotal", 0)
        res["conn_count"] = len(conns)
        if not proxies:
            res.update(groups=[], nodes=[], conns=[], usage=[], chains=[], stats={})
            return res

        usage = {}
        ip_name = {d["ip"]: d["name"] for d in (devs if devs is not None else self._devices())}
        now = time.time()
        conn_rows = []
        top_groups = {}
        live_cids = set()
        for c in conns:
            cid = c.get("id", "")
            live_cids.add(cid)
            chains = c.get("chains") or ["?"]
            node = chains[0]
            u = usage.setdefault(node, {"node": node, "conns": 0, "down": 0, "up": 0, "ds": 0, "us": 0})
            u["conns"] += 1
            u["down"] += c.get("download", 0)
            u["up"] += c.get("upload", 0)
            u["ds"] += c.get("_ds", 0)
            u["us"] += c.get("_us", 0)
            top_groups[chains[-1]] = top_groups.get(chains[-1], 0) + 1
            if conn_limit > 0:
                md = c.get("metadata", {})
                st = self._conn_start_ts.get(cid)
                if st is None:
                    try:
                        st = time.mktime(time.strptime(c.get("start", "")[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
                    except Exception:
                        st = now
                    if cid:
                        self._conn_start_ts[cid] = st
                conn_rows.append({"id": cid,
                                  "host": md.get("host") or md.get("sniffHost") or md.get("destinationIP") or md.get("remoteDestination", ""),
                                  "dst_ip": md.get("remoteDestination") or md.get("destinationIP") or "",
                                  "port": md.get("destinationPort", ""),
                                  "src_port": md.get("sourcePort", ""),
                                  "inbound": f"{md.get('type', '')} :{md.get('inboundPort', '')}".strip(),
                                  "network": md.get("network", ""),
                                  "src": ip_name.get(md.get("sourceIP", ""), md.get("sourceIP", "")),
                                  "src_ip": md.get("sourceIP", ""), "node": node, "chain": list(reversed(chains)),
                                  "rule": c.get("rule", ""), "payload": c.get("rulePayload", ""),
                                  "ds": c.get("_ds", 0), "us": c.get("_us", 0),
                                  "down": c.get("download", 0), "up": c.get("upload", 0), "age": max(0, now - st)})
        if len(self._conn_start_ts) > 600:
            self._conn_start_ts = {k: v for k, v in self._conn_start_ts.items() if k in live_cids}
        if conn_limit > 0:
            conn_rows.sort(key=lambda r: (-(r["ds"] + r["us"]), r["age"]))
            res["conns"] = conn_rows[:conn_limit]
        else:
            res["conns"] = []
            res["conns_omitted"] = True
        res["usage"] = sorted(usage.values(), key=lambda u: (-(u["ds"] + u["us"]), -u["conns"]))

        def resolve(name, depth=0):
            p = proxies.get(name, {})
            if p.get("type") in GROUP_TYPES and p.get("now") and depth < 10:
                return [name] + resolve(p["now"], depth + 1)
            return [name]

        groups = {n: p for n, p in proxies.items() if p.get("type") in GROUP_TYPES}
        referenced = {m for n, p in groups.items() if n != "GLOBAL" for m in p.get("all", [])}
        vis_order = [g for g in proxies.get("GLOBAL", {}).get("all", []) if g in groups and not groups[g].get("hidden")]
        hid_order = [g for g in proxies.get("GLOBAL", {}).get("all", []) if g in groups and groups[g].get("hidden")]
        order = vis_order + hid_order
        order += sorted((g for g in groups if g not in order and g != "GLOBAL"), key=lambda k: (bool(groups[k].get("hidden")), k))
        if res["mode"] == "global" and "GLOBAL" in groups:
            order = ["GLOBAL"] + order
        res["groups"] = []
        for g in order:
            p = groups[g]
            path = resolve(g)
            res["groups"].append({"name": g, "type": p.get("type"), "type_name": GROUP_NAME.get(p.get("type"), p.get("type")),
                                  "now": p.get("now", ""), "final": path[-1], "path": path,
                                  "members": p.get("all", []), "count": len(p.get("all", [])),
                                  "top": g not in referenced, "conns": top_groups.get(g, 0),
                                  "delay": node_delay(proxies.get(path[-1], {}))})
        tops = [g for g in res["groups"] if g["top"] and g["name"] != "GLOBAL"]
        tops.sort(key=lambda g: -g["conns"])
        res["chains"] = [{"entry": g["name"], "path": g["path"], "conns": g["conns"], "delay": g["delay"]} for g in tops]

        if not need_nodes:
            total_nodes = sum(1 for p in proxies.values() if p.get("type") not in GROUP_TYPES and p.get("type") not in BUILTIN_TYPES)
            res["nodes_omitted"] = True
            res["node_count"] = total_nodes
            return res

        member_of = {}
        for g in res["groups"]:
            for m in g["members"]:
                member_of.setdefault(m, []).append(g["name"])
        selected = {g["final"] for g in res["groups"]}
        nodes = []
        for n, p in proxies.items():
            if p.get("type") in GROUP_TYPES or p.get("type") in BUILTIN_TYPES:
                continue
            u = usage.get(n, {})
            hist = node_history(p)
            nodes.append({"name": n, "type": PROTO_NAME.get(p.get("type"), p.get("type")), "alive": p.get("alive", True),
                          "delay": node_delay(p), "history": [h.get("delay", 0) for h in hist[-12:]],
                          "region": node_region(n), "server": re.split(r"\s*[·|]\s*", n)[0].strip(),
                          "udp": bool(p.get("udp")), "tfo": bool(p.get("tfo")), "xudp": bool(p.get("xudp")),
                          "conns": u.get("conns", 0), "ds": u.get("ds", 0), "us": u.get("us", 0),
                          "down": u.get("down", 0), "up": u.get("up", 0),
                          "selected": n in selected, "groups": member_of.get(n, [])})
        nodes.sort(key=lambda x: (not x["selected"], not x["conns"], x["delay"] in (None, 0), x["delay"] or 0, x["name"]))
        res["nodes"] = nodes
        tested = [x["delay"] for x in nodes if x["delay"]]
        by_type, by_region, by_server = {}, {}, {}
        for x in nodes:
            by_type[x["type"]] = by_type.get(x["type"], 0) + 1
            by_region[x["region"]] = by_region.get(x["region"], 0) + 1
            by_server[x["server"]] = by_server.get(x["server"], 0) + 1
        res["stats"] = {"total": len(nodes), "ok": len(tested),
                        "fast": sum(1 for d in tested if d < 150),
                        "mid": sum(1 for d in tested if 150 <= d < 300),
                        "slow": sum(1 for d in tested if d >= 300),
                        "timeout": sum(1 for x in nodes if x["delay"] == 0),
                        "untested": sum(1 for x in nodes if x["delay"] is None),
                        "avg": sum(tested) / len(tested) if tested else None,
                        "best": min(tested) if tested else None,
                        "in_use": sum(1 for x in nodes if x["conns"]),
                        "by_type": sorted(by_type.items(), key=lambda kv: -kv[1]),
                        "by_region": sorted(by_region.items(), key=lambda kv: -kv[1]),
                        "by_server": sorted(by_server.items(), key=lambda kv: kv[0])}
        return res

    # ---------------------------------------------------------- 代理节点更新 / 测速 / 切换
    def _set_sub_task(self, running: bool, pct: int, step: str, ok=None, error: str = "", summary: str = ""):
        self._sub_task = {
            "running": bool(running),
            "pct": int(pct),
            "step": step,
            "ok": ok,
            "error": error,
            "summary": summary,
            "ts": time.time(),
        }

    def proxy_update_status(self):
        return dict(self._sub_task)

    def test_proxy_delays(self, group_name: str = "", node_name: str = ""):
        if not self._router:
            return {"ok": False, "error": "尚未连接路由器"}
        enc_url = urllib.parse.quote("http://www.gstatic.com/generate_204", safe="")
        try:
            if (node_name or "").strip():
                enc_n = urllib.parse.quote(node_name.strip(), safe="")
                cmd = CLASH_API + (
                    f'c_alive && curl -s -m 9 -H "Authorization: Bearer $S" '
                    f'"http://127.0.0.1:${{P:-9090}}/proxies/{enc_n}/delay?timeout=4500&url={enc_url}"'
                )
                _, out, _ = self._router.run(cmd, timeout=14)
                data = _json(out.strip(), {})
                self._force.set()
                if "delay" in data:
                    return {"ok": True, "node": node_name.strip(), "delay": data["delay"]}
                return {"ok": False, "error": data.get("message") or "节点测速超时"}

            target_grp = (group_name or "").strip()
            if not target_grp or target_grp == "all":
                with self._lock:
                    proxies = dict((self._slow or {}).get("clash_proxies") or {})
                if "住宅固定出口" in proxies:
                    target_grp = "住宅固定出口"
                else:
                    for gname, gobj in proxies.items():
                        if gname != "GLOBAL" and gobj.get("type") in GROUP_TYPES and gobj.get("all"):
                            target_grp = gname
                            break
                    target_grp = target_grp or "GLOBAL"

            enc_g = urllib.parse.quote(target_grp, safe="")
            cmd = CLASH_API + (
                f'c_alive && curl -s -m 15 -H "Authorization: Bearer $S" '
                f'"http://127.0.0.1:${{P:-9090}}/group/{enc_g}/delay?timeout=4500&url={enc_url}"'
            )
            _, out, _ = self._router.run(cmd, timeout=20)
            delays = _json(out.strip(), {})
            self._force.set()
            valid = [v for v in delays.values() if isinstance(v, (int, float)) and v > 0]
            return {
                "ok": True,
                "group": target_grp,
                "tested": len(valid),
                "best": min(valid) if valid else None,
            }
        except Exception as e:
            return {"ok": False, "error": f"测速请求失败：{e}"}

    def select_proxy_node(self, group_name: str, node_name: str):
        if not self._router:
            return {"ok": False, "error": "尚未连接路由器"}
        group_name = (group_name or "").strip()
        node_name = (node_name or "").strip()
        if not (group_name and node_name):
            return {"ok": False, "error": "缺少策略组或节点名称"}
        with self._lock:
            csub = dict((self._slow or {}).get("clash_sub") or {})
            proxies = dict((self._slow or {}).get("clash_proxies") or {})
        if csub.get("guardline") == "1" and group_name in ("节点选择", "家宽优先", "GLOBAL"):
            return {"ok": False, "error": "Guardline 防泄露策略锁定主出口组，由「住宅固定出口」自动测速择优"}
        grp = proxies.get(group_name) or {}
        if grp.get("type") != "Selector":
            return {"ok": False, "error": f"策略组「{group_name}」为自动策略（{grp.get('type') or '非手动'}），请使用一键测速触发择优"}
        enc_g = urllib.parse.quote(group_name, safe="")
        payload = shlex.quote(json.dumps({"name": node_name}, ensure_ascii=False))
        cmd = CLASH_API + (
            f'c_alive && curl -s -o /dev/null -w "%{{http_code}}" -m 6 -X PUT '
            f'-H "Authorization: Bearer $S" -H "Content-Type: application/json" '
            f'-d {payload} "http://127.0.0.1:${{P:-9090}}/proxies/{enc_g}"'
        )
        try:
            _, out, _ = self._router.run(cmd, timeout=10)
            if out.strip() in ("200", "204"):
                self._force.set()
                return {"ok": True}
            return {"ok": False, "error": f"内核返回状态码 {out.strip() or '未知'}"}
        except Exception as e:
            return {"ok": False, "error": f"切换节点失败：{e}"}

    def start_update_proxy(self, sub_url: str = "", expected_ip: str = "", auto_detect_ip: bool = False, yaml_content: str = ""):
        if not self._router:
            return {"ok": False, "error": "尚未连接路由器"}
        if self._sub_task.get("running"):
            return {"ok": False, "error": "代理节点更新任务正在执行中，请稍候"}
        self._set_sub_task(True, 5, "准备开始更新代理节点...")

        def _worker():
            self.update_proxy_nodes_sync(
                sub_url=sub_url,
                expected_ip=expected_ip,
                auto_detect_ip=bool(auto_detect_ip),
                yaml_content=yaml_content,
            )

        threading.Thread(target=_worker, daemon=True).start()
        return {"ok": True, "started": True}

    def update_proxy_nodes_sync(
        self,
        sub_url: str = "",
        expected_ip: str = "",
        auto_detect_ip: bool = False,
        yaml_content: str = "",
        sub_ua: str = "",
    ) -> dict:
        if not self._sub_lock.acquire(blocking=False):
            return {"ok": False, "error": "代理节点更新任务正在执行中，请稍候"}
        try:
            if not self._router:
                self._set_sub_task(False, 0, "", ok=False, error="尚未连接路由器")
                return {"ok": False, "error": "尚未连接路由器"}
            creds = self._active_creds() or {}
            root_pw = creds.get("pw") or ""

            self._set_sub_task(True, 10, "正在读取软路由当前 OpenClash 与封条配置...")
            probe_cmd = r"""
CP=$(uci -q get openclash.config.config_path); CP=${CP:-/etc/openclash/config/sub.yaml}
echo "@@META"
echo "cfg_path=$CP"
echo "sub_url=$(uci -q get openclash.@config_subscribe[0].address)"
echo "sub_ua=$(uci -q get openclash.@config_subscribe[0].sub_ua)"
echo "guardline=$([ -x /usr/sbin/guard-unlock ] && [ -f /etc/openclash/custom/mainland-policy.rb ] && echo 1 || echo 0)"
echo "expected_ip=$(sed -n 's/^EXPECTED=//p' /etc/openclash/custom/ipguard.sh 2>/dev/null | head -n1)"
echo "@@OLDNODES"
cat /etc/openclash/custom/mainland-nodes.list 2>/dev/null
echo "@@OLDPROXIES"
if [ -f "$CP" ]; then
  ruby -ryaml -e 'c = (YAML.load_file(ARGV[0], aliases: true) rescue nil); (c.is_a?(Hash) ? (c["proxies"] || []) : []).each { |p| puts p["name"].to_s.strip if p.is_a?(Hash) }' "$CP" 2>/dev/null
fi
echo "@@END"
"""
            _, p_out, _ = self._router.run(probe_cmd, timeout=20)
            psecs = split_sections(p_out)
            meta_kv = {}
            for ln in _one(psecs, "META").splitlines():
                if "=" in ln:
                    k, v = ln.split("=", 1)
                    meta_kv[k.strip()] = v.strip()

            cfg_path = meta_kv.get("cfg_path") or "/etc/openclash/config/sub.yaml"
            cur_url = meta_kv.get("sub_url", "")
            ua = (sub_ua or "").strip() or meta_kv.get("sub_ua") or "clash.meta"
            is_guardline = meta_kv.get("guardline") == "1"
            cur_expected = meta_kv.get("expected_ip", "")
            old_nodes_lines = _one(psecs, "OLDNODES").splitlines()
            old_proxy_names = {x.strip() for x in _one(psecs, "OLDPROXIES").splitlines() if x.strip()}

            raw_yaml = (yaml_content or "").strip()
            target_url = (sub_url or "").strip() or cur_url

            target_expected = cur_expected
            if is_guardline and not auto_detect_ip and (expected_ip or "").strip():
                cand_ip = expected_ip.strip()
                if not _is_valid_ipv4(cand_ip, public_only=True):
                    err = f"出口门禁预期 IP「{cand_ip}」不是有效的公网 IPv4 地址"
                    self._set_sub_task(False, 0, "", ok=False, error=err)
                    return {"ok": False, "error": err}
                target_expected = cand_ip

            if raw_yaml:
                self._set_sub_task(True, 26, "正在上传自定义 Clash 节点配置...")
                self._router.run(
                    "rm -f /tmp/rp_sub_raw.dat /tmp/rp_sub.hdr && cat > /tmp/rp_sub_raw.dat",
                    timeout=20,
                    stdin_data=raw_yaml.encode("utf-8"),
                )
            else:
                if not target_url or not re.match(r"^https?://\S+$", target_url, re.I):
                    err = "请填写有效的在线订阅链接（以 http:// 或 https:// 开头）"
                    self._set_sub_task(False, 0, "", ok=False, error=err)
                    return {"ok": False, "error": err}

                self._set_sub_task(True, 26, "正在从订阅服务器拉取最新节点配置...")
                q_url = shlex.quote(target_url)
                q_ua = shlex.quote(ua)
                dl_cmd = CLASH_API + f"""
rm -f /tmp/rp_sub_raw.dat /tmp/rp_sub.hdr
if curl -fsSL -k -D /tmp/rp_sub.hdr -m 25 -A {q_ua} {q_url} -o /tmp/rp_sub_raw.dat 2>/dev/null && [ -s /tmp/rp_sub_raw.dat ]; then
  echo OK_DIRECT
elif c_alive; then
  U=$(uci -q get openclash.@authentication[0].username)
  PW=$(uci -q get openclash.@authentication[0].password)
  MP=$(uci -q get openclash.config.mixed_port); MP=${{MP:-7893}}
  if [ -n "$U" ]; then PX="http://$U:$PW@127.0.0.1:$MP"; else PX="http://127.0.0.1:$MP"; fi
  if curl -fsSL -k -x "$PX" -D /tmp/rp_sub.hdr -m 25 -A {q_ua} {q_url} -o /tmp/rp_sub_raw.dat 2>/dev/null && [ -s /tmp/rp_sub_raw.dat ]; then
    echo OK_PROXY
  else
    echo FAIL
  fi
else
  echo FAIL
fi
cat /tmp/rp_sub.hdr 2>/dev/null
"""
                _, dl_out, _ = self._router.run(dl_cmd, timeout=35)
                first_line = (dl_out.splitlines() or [""])[0].strip()
                if not first_line.startswith("OK_"):
                    # 回退：从本机拉取订阅再通过 SSH 加密流上传至软路由
                    try:
                        ctx = ssl._create_unverified_context()
                        req = urllib.request.Request(target_url, headers={"User-Agent": ua})
                        with urllib.request.urlopen(req, timeout=25, context=ctx) as resp:
                            body_bytes = resp.read()
                            hdr_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                        if not body_bytes:
                            raise ValueError("订阅响应内容为空")
                        self._sub_meta = parse_sub_headers(hdr_str)
                        self._router.run("cat > /tmp/rp_sub_raw.dat", timeout=20, stdin_data=body_bytes)
                    except Exception as e:
                        err = f"拉取订阅链接失败，请核对订阅地址与网络连通性（{e}）"
                        self._set_sub_task(False, 0, "", ok=False, error=err)
                        return {"ok": False, "error": err}
                else:
                    hdr_txt = "\n".join(dl_out.splitlines()[1:])
                    parsed_hdr = parse_sub_headers(hdr_txt)
                    if parsed_hdr:
                        self._sub_meta = parsed_hdr

            self._set_sub_task(True, 45, "正在校验 Clash 订阅结构并解析代理节点...")
            ruby_validator = r"""
require 'yaml'
raw = File.binread('/tmp/rp_sub_raw.dat')
bom = "\xEF\xBB\xBF".b
raw = raw.byteslice(3..) if raw.start_with?(bom)
txt = raw.dup.force_encoding('UTF-8')
doc = nil
used_dec = false
begin
  cand = YAML.load(txt, aliases: true)
  doc = cand if cand.is_a?(Hash) && cand['proxies'].is_a?(Array)
rescue Exception
end
if doc.nil?
  begin
    dec = raw.gsub(/\s+/, '').unpack1('m').force_encoding('UTF-8')
    cand = YAML.load(dec, aliases: true)
    if cand.is_a?(Hash) && cand['proxies'].is_a?(Array)
      doc = cand
      txt = dec
      used_dec = true
    end
  rescue Exception
  end
end
if doc.nil? || !doc['proxies'].is_a?(Array) || doc['proxies'].empty?
  STDERR.puts 'ERR_MSG:订阅内容未包含有效的 Clash proxies 节点列表（请确认订阅为 Clash / Clash.Meta 格式）'
  exit 2
end
File.binwrite('/tmp/rp_sub_new.yaml', used_dec ? txt : raw)
doc['proxies'].each do |p|
  next unless p.is_a?(Hash)
  nm = p['name'].to_s.gsub(/[\r\n\t]+/, ' ').strip
  tp = p['type'].to_s.strip
  sv = p['server'].to_s.strip
  pt = p['port'].to_i
  pts = p['ports'].to_s.strip
  sni = (p['servername'] || p['sni'] || '').to_s.strip
  ws_h = (p['ws-opts'].is_a?(Hash) && p['ws-opts']['headers'].is_a?(Hash)) ? (p['ws-opts']['headers']['Host'] || p['ws-opts']['headers']['host']) : nil
  xh_h = p['xhttp-opts'].is_a?(Hash) ? p['xhttp-opts']['host'] : nil
  hst = (ws_h || xh_h || '').to_s.strip
  next if nm.empty? || tp.empty? || sv.empty? || pt <= 0 || pt > 65535
  puts [nm, tp, sv, pt, pts, sni, hst].join("\t")
end
"""
            self._router.run("cat > /tmp/rp_validate_sub.rb", timeout=12, stdin_data=ruby_validator)
            v_rc, v_out, v_err = self._router.run("ruby -E UTF-8 /tmp/rp_validate_sub.rb", timeout=20)
            if v_rc != 0:
                err_lines = [ln[8:].strip() for ln in (v_err or "").splitlines() if ln.startswith("ERR_MSG:")]
                err = err_lines[-1] if err_lines else (v_err or v_out or "订阅配置校验失败").strip().splitlines()[0]
                self._set_sub_task(False, 0, "", ok=False, error=err)
                return {"ok": False, "error": err}

            new_proxies = []
            seen_names = set()
            for row in v_out.splitlines():
                cols = row.split("\t")
                if len(cols) < 4:
                    continue
                nm = cols[0].strip()
                if not nm or nm in seen_names:
                    continue
                seen_names.add(nm)
                new_proxies.append({
                    "name": nm,
                    "type": cols[1].strip(),
                    "server": cols[2].strip(),
                    "port": int(cols[3].strip()),
                    "ports": cols[4].strip() if len(cols) > 4 else "",
                    "sni": cols[5].strip() if len(cols) > 5 else "",
                    "host": cols[6].strip() if len(cols) > 6 else "",
                })
            if not new_proxies:
                err = "订阅配置中未解析到可用节点"
                self._set_sub_task(False, 0, "", ok=False, error=err)
                return {"ok": False, "error": err}

            q_cfg = shlex.quote(cfg_path)
            cfg_dir = shlex.quote(os.path.dirname(cfg_path) or "/etc/openclash/config")
            cfg_stem = shlex.quote(os.path.splitext(os.path.basename(cfg_path))[0] or "sub")

            if is_guardline:
                self._set_sub_task(True, 62, f"正在解析域名并同步 Guardline 封条白名单（共 {len(new_proxies)} 个节点）...")
                if not root_pw:
                    err = "缺少软路由 root 凭据，无法执行 Guardline 封条解锁（请重新登录面板）"
                    self._set_sub_task(False, 0, "", ok=False, error=err)
                    return {"ok": False, "error": err}

                def _resolve_domain(dom: str) -> str:
                    enc_d = urllib.parse.quote(dom, safe="")
                    rc_d, d_out, _ = self._router.run(
                        CLASH_API + f'capi "/dns/query?name={enc_d}&type=A"', timeout=10
                    )
                    if rc_d == 0 and d_out.strip():
                        ans = _json(d_out.strip(), {}).get("Answer") or []
                        for item in ans:
                            cand = str(item.get("data") or "").strip()
                            if item.get("type") == 1 and _is_valid_ipv4(cand, public_only=True):
                                return cand
                    try:
                        for info in socket.getaddrinfo(dom, None, socket.AF_INET):
                            cand = info[4][0]
                            if _is_valid_ipv4(cand, public_only=True):
                                return cand
                    except Exception:
                        pass
                    return ""

                try:
                    nodes_txt = build_guardline_nodes_list(new_proxies, old_proxy_names, old_nodes_lines, _resolve_domain)
                except Exception as e:
                    err = str(e)
                    self._set_sub_task(False, 0, "", ok=False, error=err)
                    return {"ok": False, "error": err}

                self._router.run("cat > /tmp/rp_nodes_new.list", timeout=15, stdin_data=nodes_txt)

                prep_cmds = [
                    f"mkdir -p {cfg_dir}",
                    f"[ -f {q_cfg} ] && cp -p {q_cfg} /tmp/rp_sub_prev.bak || true",
                    "cp -p /etc/openclash/custom/mainland-nodes.list /tmp/rp_nodes_prev.bak 2>/dev/null || true",
                    "cp -p /etc/openclash/custom/ipguard.sh /tmp/rp_ipguard_prev.bak 2>/dev/null || true",
                    f"cp /tmp/rp_sub_new.yaml {q_cfg} && chmod 600 {q_cfg}",
                ]
                if not raw_yaml and target_url:
                    prep_cmds += [
                        "uci -q get openclash.@config_subscribe[0] >/dev/null || uci add openclash config_subscribe >/dev/null",
                        "uci set openclash.@config_subscribe[0].enabled='1'",
                        f"uci set openclash.@config_subscribe[0].name={cfg_stem}",
                        f"uci set openclash.@config_subscribe[0].sub_ua={shlex.quote(ua)}",
                        f"uci set openclash.@config_subscribe[0].address={shlex.quote(target_url)}",
                        f"uci set openclash.config.config_path={q_cfg}",
                        "uci commit openclash",
                    ]
                self._router.run("; ".join(prep_cmds), timeout=15)

                unlock_ops = [
                    "cp /tmp/rp_nodes_new.list /etc/openclash/custom/mainland-nodes.list",
                    "chmod 644 /etc/openclash/custom/mainland-nodes.list",
                ]
                if target_expected and target_expected != cur_expected:
                    unlock_ops.append(f"sed -i 's/^EXPECTED=.*/EXPECTED={target_expected}/' /etc/openclash/custom/ipguard.sh")

                u_rc, u_out, u_err = self._router.run(
                    f"/usr/sbin/guard-unlock -c {shlex.quote(' && '.join(unlock_ops))}",
                    timeout=30,
                    stdin_data=root_pw + "\n",
                )
                if u_rc != 0:
                    self._router.run(f"[ -f /tmp/rp_sub_prev.bak ] && cp -p /tmp/rp_sub_prev.bak {q_cfg} || true", timeout=8)
                    err = f"Guardline 封条同步失败：{(u_err or u_out).strip()}"
                    self._set_sub_task(False, 0, "", ok=False, error=err)
                    return {"ok": False, "error": err}

                # 预跑 mainland-policy.rb 干跑校验，确保不会触发 FAIL-CLOSED
                p_rc, p_out2, p_err2 = self._router.run(
                    f"cp {q_cfg} /tmp/rp_policy_test.yaml && ruby -E UTF-8 /etc/openclash/custom/mainland-policy.rb /tmp/rp_policy_test.yaml && rm -f /tmp/rp_policy_test.yaml",
                    timeout=25,
                )
                if p_rc != 0:
                    rb_ops = "cp -p /tmp/rp_nodes_prev.bak /etc/openclash/custom/mainland-nodes.list && cp -p /tmp/rp_ipguard_prev.bak /etc/openclash/custom/ipguard.sh"
                    self._router.run(f"[ -f /tmp/rp_sub_prev.bak ] && cp -p /tmp/rp_sub_prev.bak {q_cfg} || true", timeout=8)
                    self._router.run(f"/usr/sbin/guard-unlock -c {shlex.quote(rb_ops)}", timeout=25, stdin_data=root_pw + "\n")
                    err = f"Guardline 策略预检未通过，已安全回滚原配置：{(p_err2 or p_out2).strip()}"
                    self._set_sub_task(False, 0, "", ok=False, error=err)
                    return {"ok": False, "error": err}
            else:
                self._set_sub_task(True, 62, f"正在写入 OpenClash 订阅配置（共 {len(new_proxies)} 个节点）...")
                std_cmds = [
                    f"mkdir -p {cfg_dir}",
                    f"[ -f {q_cfg} ] && cp -p {q_cfg} /tmp/rp_sub_prev.bak || true",
                    f"cp /tmp/rp_sub_new.yaml {q_cfg} && chmod 600 {q_cfg}",
                ]
                if not raw_yaml and target_url:
                    std_cmds += [
                        "uci -q get openclash.@config_subscribe[0] >/dev/null || uci add openclash config_subscribe >/dev/null",
                        "uci set openclash.@config_subscribe[0].enabled='1'",
                        f"uci set openclash.@config_subscribe[0].name={cfg_stem}",
                        f"uci set openclash.@config_subscribe[0].sub_ua={shlex.quote(ua)}",
                        f"uci set openclash.@config_subscribe[0].address={shlex.quote(target_url)}",
                        f"uci set openclash.config.config_path={q_cfg}",
                        "uci commit openclash",
                    ]
                self._router.run("; ".join(std_cmds), timeout=15)

            self._set_sub_task(True, 76, "正在刷新路由表白名单并重启 OpenClash 内核...")
            runtime_cfg = shlex.quote("/etc/openclash/" + os.path.basename(cfg_path))
            _, old_pid_out, _ = self._router.run("pidof clash clash_meta mihomo 2>/dev/null || true", timeout=6)
            old_pid = old_pid_out.strip()

            restart_cmds = []
            if is_guardline:
                restart_cmds += [
                    "/etc/openclash/custom/mainland-guard.sh >/dev/null 2>&1 || true",
                    "/etc/openclash/custom/mainland-route-guard.sh >/dev/null 2>&1 || true",
                    f"rm -f {runtime_cfg} /tmp/ipguard.locked /tmp/ipguard.none",
                ]
            restart_cmds.append("( /etc/init.d/openclash restart </dev/null >/dev/null 2>&1 & )")
            self._router.run("; ".join(restart_cmds), timeout=25)

            time.sleep(3.0)
            clash_ready = False
            t0 = time.monotonic()
            for _ in range(20):
                elapsed = time.monotonic() - t0
                _, chk_out, _ = self._router.run(
                    CLASH_API + 'NP=$(pidof clash clash_meta mihomo 2>/dev/null); echo "PID=$NP"; [ -n "$NP" ] && capi /version',
                    timeout=8,
                )
                lines = chk_out.strip().splitlines()
                cur_pid = lines[0][4:].strip() if lines and lines[0].startswith("PID=") else ""
                ver_body = "\n".join(lines[1:]).strip()
                if cur_pid and ver_body and "version" in ver_body and (cur_pid != old_pid or elapsed >= 7.5):
                    clash_ready = True
                    break
                time.sleep(1.4)

            if not clash_ready:
                err = "OpenClash 内核重启等待超时，请稍后刷新查看状态"
                self._set_sub_task(False, 0, "", ok=False, error=err)
                self._force.set()
                return {"ok": False, "error": err}

            self._set_sub_task(True, 88, "正在并发测速择优并校验出口安全门禁...")
            self.test_proxy_delays()

            gate_state = "none"
            verified_ip = ""
            seal_gen = ""
            if is_guardline:
                if auto_detect_ip:
                    det_cmd = r"""
U=$(uci -q get openclash.@authentication[0].username)
P=$(uci -q get openclash.@authentication[0].password)
PORT=$(uci -q get openclash.config.mixed_port); PORT=${PORT:-7893}
if [ -n "$U" ]; then PX="http://$U:$P@127.0.0.1:$PORT"; else PX="http://127.0.0.1:$PORT"; fi
PD=/tmp/rp_autodet_ip; rm -rf "$PD"; mkdir -p "$PD"
p1() { r=$(curl -s -m 8 -x "$PX" "$2" 2>/dev/null); case "$2" in */trace) r=$(echo "$r" | sed -n 's/^ip=//p') ;; esac; echo "$r" | tr -d ' \r\n' > "$PD/$1"; }
p1 1 https://checkip.amazonaws.com &
p1 2 https://ifconfig.me/ip &
p1 3 https://api.ipify.org &
p1 4 https://ipinfo.io/ip &
p1 5 https://one.one.one.one/cdn-cgi/trace &
wait
for i in 1 2 3 4 5; do cat "$PD/$i" 2>/dev/null; echo; done
rm -rf "$PD"
"""
                    _, det_out, _ = self._router.run(det_cmd, timeout=16)
                    probed = [x.strip() for x in det_out.splitlines() if _is_valid_ipv4(x.strip(), public_only=True)]
                    if len(probed) >= 2 and len(set(probed)) == 1:
                        det_ip = probed[0]
                        if det_ip != target_expected:
                            self._router.run(
                                f"/usr/sbin/guard-unlock -c {shlex.quote(f'sed -i s/^EXPECTED=.*/EXPECTED={det_ip}/ /etc/openclash/custom/ipguard.sh')}",
                                timeout=20,
                                stdin_data=root_pw + "\n",
                            )
                            target_expected = det_ip
                    elif len(set(probed)) > 1:
                        err = f"多源探针返回出口 IP 不一致（{' / '.join(sorted(set(probed)))}），门禁保持关闭保护"
                        self._router.run("/etc/openclash/custom/ipguard.sh || true", timeout=15)
                        self._force.set()
                        self._set_sub_task(False, 0, "", ok=False, error=err)
                        return {"ok": False, "error": err}

                for _ in range(3):
                    _, g_out, _ = self._router.run(
                        "/etc/openclash/custom/ipguard.sh >/dev/null 2>&1; "
                        "echo GATE=$([ -f /tmp/ipguard.open ] && echo open || echo closed); "
                        "cat /tmp/ipguard.last 2>/dev/null; echo; cat /etc/guard-seal/CURRENT 2>/dev/null",
                        timeout=20,
                    )
                    glines = [x.strip() for x in g_out.splitlines() if x.strip()]
                    gate_state = "open" if any(x == "GATE=open" for x in glines) else "closed"
                    for gl in glines:
                        m_ip = re.search(r"\bip=([^\s]+)", gl)
                        if m_ip:
                            pts = [z for z in m_ip.group(1).split("/") if z and z != "none" and z != "-"]
                            if pts:
                                verified_ip = pts[0]
                        if re.match(r"^\d{8}-\d{6}$", gl):
                            seal_gen = gl
                    if gate_state == "open":
                        break
                    time.sleep(2.0)

            self._router.run(
                "rm -f /tmp/rp_sub_raw.dat /tmp/rp_sub_new.yaml /tmp/rp_sub.hdr /tmp/rp_validate_sub.rb /tmp/rp_nodes_new.list /tmp/rp_policy_test.yaml; "
                "[ -x /usr/sbin/rp-traffic-collect ] && /usr/sbin/rp-traffic-collect sync-ips >/dev/null 2>&1 || true",
                timeout=10,
            )
            self._force.set()

            if is_guardline and gate_state != "open":
                msg = (
                    f"已同步 {len(new_proxies)} 个节点，但实测出口 IP（{verified_ip or '未测通'}）与门禁预期（{target_expected}）不符，放行闸保持关闭保护"
                )
                self._set_sub_task(False, 100, "节点已同步，等待出口门禁核验", ok=False, error=msg)
                return {"ok": False, "error": msg, "node_count": len(new_proxies), "gate": gate_state}

            summary = (
                f"已成功同步 {len(new_proxies)} 个代理节点"
                + (f" · 出口 {verified_ip} 门禁已放行" if gate_state == "open" else "")
            )
            self._set_sub_task(False, 100, summary, ok=True, summary=summary)
            return {
                "ok": True,
                "node_count": len(new_proxies),
                "gate": gate_state,
                "exit_ip": verified_ip or target_expected,
                "seal_gen": seal_gen,
                "summary": summary,
            }
        except Exception as e:
            err = f"更新代理节点异常：{e}"
            self._set_sub_task(False, 0, "", ok=False, error=err)
            return {"ok": False, "error": err}
        finally:
            self._sub_lock.release()

    # ---------------------------------------------------------- 流量统计（代理 / 直连 / 总流量 · 时/天/月/季/年/自定义时间段）
    def _current_host(self) -> str:
        return (self._active_creds() or {}).get("host") or self._cfg.get("host") or self._default_gw

    def query_traffic(self, granularity: str = "day", start_dt: str = "", end_dt: str = "", preset: str = "", sync_now: bool = False) -> dict:
        host = self._current_host()
        if sync_now and self._router:
            self._sync_traffic_from_router(self._router, full=False)
        with self._lock:
            ld = (0, 0, 0, 0) if sync_now else self._live_traffic_delta()
        return self._traffic_store.query(
            host=host,
            granularity=granularity,
            start_dt_str=start_dt,
            end_dt_str=end_dt,
            preset=preset,
            live_delta=ld,
        )

    def export_traffic_csv(self, granularity: str = "day", start_dt: str = "", end_dt: str = "", preset: str = "") -> dict:
        data = self.query_traffic(granularity=granularity, start_dt=start_dt, end_dt=end_dt, preset=preset, sync_now=True)
        if not data.get("ok"):
            return {"ok": False, "error": data.get("error") or "查询失败"}
        desk = Path(os.path.expanduser("~")) / "Desktop"
        if not desk.exists():
            desk = APP_DIR
        ts_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        gran_zh = {"5min": "5分钟", "hour": "按时", "day": "按天", "month": "按月", "quarter": "按季", "year": "按年"}.get(
            data.get("granularity", "day"), "按天"
        )
        out_file = desk / f"Guardline流量统计_{gran_zh}_{ts_tag}.csv"
        try:
            with open(out_file, "w", encoding="utf-8-sig", newline="") as fp:
                w = csv.writer(fp)
                w.writerow([
                    "统计周期",
                    "代理下载(字节)", "代理上传(字节)", "代理总计(字节)",
                    "直连下载(字节)", "直连上传(字节)", "直连总计(字节)",
                    "总下载(字节)", "总上传(字节)", "总流量(字节)",
                    "代理占比(%)",
                ])
                for r in data.get("series") or []:
                    w.writerow([
                        r["full_label"],
                        r["proxy_down"], r["proxy_up"], r["proxy_total"],
                        r["direct_down"], r["direct_up"], r["direct_total"],
                        r["total_down"], r["total_up"], r["total"],
                        r["proxy_pct"],
                    ])
                sm = data.get("summary") or {}
                w.writerow([
                    f"合计 ({data.get('range_label', '')})",
                    sm.get("proxy_down", 0), sm.get("proxy_up", 0), sm.get("proxy_total", 0),
                    sm.get("direct_down", 0), sm.get("direct_up", 0), sm.get("direct_total", 0),
                    sm.get("total_down", 0), sm.get("total_up", 0), sm.get("grand_total", 0),
                    sm.get("proxy_pct", 0),
                ])
            return {"ok": True, "path": str(out_file)}
        except Exception as e:
            return {"ok": False, "error": f"导出 CSV 失败：{e}"}

    def clear_traffic_history(self) -> dict:
        host = self._current_host()
        if self._router:
            try:
                self._router.run("[ -x /usr/sbin/rp-traffic-collect ] && /usr/sbin/rp-traffic-collect reset", timeout=10)
            except Exception as e:
                return {"ok": False, "error": f"重置路由器端计数器失败：{e}"}
        self._traffic_store.clear_host(host)
        with self._lock:
            self._traffic_quick_cache = {}
            self._traffic_quick_ts = 0.0
            if self._fast:
                self._fast["nft_cnt"] = (0, 0, 0, 0)
                self._fast["rpt_prev"] = (0, 0, 0, 0)
        self._force.set()
        return {"ok": True}

    # ---------------------------------------------------------- 环境纯净度体检 / AP 热点管理 / 终端管控 / 故障自愈
    def run_security_audit(self) -> dict:
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        audit_sh = r"""
U=$(uci -q get openclash.@authentication[0].username)
P=$(uci -q get openclash.@authentication[0].password)
PORT=$(uci -q get openclash.config.mixed_port); PORT=${PORT:-7893}
if [ -n "$U" ]; then PX="http://$U:$P@127.0.0.1:$PORT"; else PX="http://127.0.0.1:$PORT"; fi
AD="/tmp/rp_audit_$$"
rm -rf "$AD" && mkdir -p "$AD"

curl -s -m 7 -x "$PX" "http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,timezone,isp,org,as,mobile,proxy,hosting,query" > "$AD/ipapi" 2>/dev/null &
curl -s -m 7 -x "$PX" "https://ipinfo.io/json" > "$AD/ipinfo" 2>/dev/null &

p_ip() {
    r=$(curl -s -m 6 -x "$PX" "$2" 2>/dev/null)
    case "$2" in */trace) r=$(echo "$r" | sed -n 's/^ip=//p') ;; esac
    echo "$r" | tr -d ' \r\n' > "$AD/ip_$1"
}
p_ip 1 "https://checkip.amazonaws.com" &
p_ip 2 "https://ifconfig.me/ip" &
p_ip 3 "https://api.ipify.org" &
p_ip 4 "https://ipinfo.io/ip" &
p_ip 5 "https://one.one.one.one/cdn-cgi/trace" &

p_site() {
    res=$(curl -s -o /dev/null -m 8 -x "$PX" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -w "%{http_code} %{time_starttransfer}" "$2" 2>/dev/null)
    case "$res" in
        000*|"")
            if [ -n "$3" ]; then
                res=$(curl -s -o /dev/null -m 7 -x "$PX" -A "Mozilla/5.0" -w "%{http_code} %{time_starttransfer}" "$3" 2>/dev/null)
            fi
            ;;
    esac
    [ -z "$res" ] && res="000 0"
    echo "$res" > "$AD/site_$1"
}
p_site claude "https://claude.ai" "https://api.anthropic.com" &
p_site chatgpt "https://chatgpt.com" "https://api.openai.com/v1/models" &
p_site google "https://www.google.com/generate_204" "" &
p_site tiktok "https://www.tiktok.com" "" &
p_site github "https://github.com" "" &
wait

echo "@@IPAPI"; cat "$AD/ipapi" 2>/dev/null; echo
echo "@@IPINFO"; cat "$AD/ipinfo" 2>/dev/null; echo
echo "@@PROBES"
for i in 1 2 3 4 5; do echo "$i=$(cat "$AD/ip_$i" 2>/dev/null)"; done
echo "@@SITES"
for s in claude chatgpt google tiktok github; do echo "$s=$(cat "$AD/site_$s" 2>/dev/null)"; done
echo "@@GUARDS"
echo "ipv6_off=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)"
echo "gate=$(if [ ! -x /etc/openclash/custom/ipguard.sh ]; then echo none; elif [ -f /tmp/ipguard.open ]; then echo open; else echo closed; fi)"
echo "expected_ip=$(sed -n 's/^EXPECTED=//p' /etc/openclash/custom/ipguard.sh 2>/dev/null | head -n1)"
echo "webrtc=$(nft list chain inet mainland_guard MAINLAND_OUT 2>/dev/null | grep -c 'WEBRTC-STUN-GUARD')"
echo "dns_guard=$(nft list chain inet mainland_guard MAINLAND_OUT 2>/dev/null | grep -c 'DNSMASQ-EGRESS-GUARD')"
if [ -x /usr/sbin/guard-seal ]; then
    /usr/sbin/guard-seal status 2>/dev/null | sed 's/^/seal_/'
fi
echo "@@END"
rm -rf "$AD"
"""
        try:
            _, out, _ = self._router.run(audit_sh, timeout=22)
        except Exception as e:
            return {"ok": False, "error": f"执行体检超时或失败：{e}"}

        secs = split_sections(out)
        ipapi = _json(_one(secs, "IPAPI").strip(), {})
        ipinfo = _json(_one(secs, "IPINFO").strip(), {})

        probes = []
        for ln in _one(secs, "PROBES").splitlines():
            if "=" in ln:
                _, v = ln.split("=", 1)
                v = v.strip()
                if _is_valid_ipv4(v, public_only=True):
                    probes.append(v)

        gkv = {}
        for ln in _one(secs, "GUARDS").splitlines():
            if ":" in ln and ln.startswith("seal_"):
                k, v = ln.split(":", 1)
                gkv[k.strip()] = v.strip()
            elif "=" in ln:
                k, v = ln.split("=", 1)
                gkv[k.strip()] = v.strip()

        exit_ip = (
            ipapi.get("query")
            or ipinfo.get("ip")
            or (probes[0] if probes else "")
            or gkv.get("expected_ip", "")
        )
        asn_raw = ipapi.get("as") or ipinfo.get("org") or ""
        isp_name = ipapi.get("isp") or asn_raw
        country_code = (ipapi.get("countryCode") or ipinfo.get("country") or "").upper()
        country_name = ipapi.get("country") or country_code
        city = ipapi.get("city") or ipinfo.get("city") or ""
        region = ipapi.get("regionName") or ipinfo.get("region") or ""
        tz = ipapi.get("timezone") or ipinfo.get("timezone") or ""

        is_hosting = bool(ipapi.get("hosting", False))
        is_proxy_flag = bool(ipapi.get("proxy", False))
        is_mobile = bool(ipapi.get("mobile", False))
        has_ip_meta = bool(ipapi.get("status") == "success" or ipinfo.get("ip"))
        is_residential = bool(has_ip_meta and not is_hosting and not is_proxy_flag)

        unique_ips = sorted(set(probes))
        probes_consistent = len(probes) >= 3 and len(unique_ips) == 1
        ipv6_ok = gkv.get("ipv6_off") == "1"
        webrtc_ok = int(gkv.get("webrtc") or "0") > 0
        dns_ok = int(gkv.get("dns_guard") or "0") > 0
        seal_state = gkv.get("seal_state", "")
        seal_gen = gkv.get("seal_generation", "")
        gate_st = gkv.get("gate", "none")

        site_labels = [
            ("claude", "Claude AI"),
            ("chatgpt", "ChatGPT / OpenAI"),
            ("google", "Google 搜索"),
            ("tiktok", "TikTok 国际版"),
            ("github", "GitHub"),
        ]
        raw_sites = {}
        for ln in _one(secs, "SITES").splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                raw_sites[k.strip()] = v.strip()

        platforms = []
        ok_sites = 0
        for skey, sname in site_labels:
            parts = (raw_sites.get(skey) or "000 0").split()
            code = parts[0] if parts else "000"
            try:
                ms = int(round(float(parts[1]) * 1000)) if len(parts) > 1 else 0
            except Exception:
                ms = 0
            ok = code != "000" and code.isdigit() and int(code) > 0
            if ok:
                ok_sites += 1
            platforms.append({"key": skey, "name": sname, "ok": ok, "code": code, "ms": ms if ok else None})

        guards = [
            {
                "name": "多源出口 IP 一致性",
                "ok": probes_consistent,
                "detail": f"{len(probes)}/5 探针源一致 ({exit_ip})" if probes_consistent else (f"返回 {' / '.join(unique_ips)}" if unique_ips else "探针超时"),
            },
            {
                "name": "住宅 ISP 原生属性",
                "ok": is_residential,
                "detail": "原生家庭宽带 (非 IDC 机房 / 非公开代理)" if is_residential else ("检测到机房托管或代理标记" if has_ip_meta else "待获取 ASN 信息"),
            },
            {
                "name": "IPv6 彻底阻断防泄露",
                "ok": ipv6_ok,
                "detail": "内核已禁用 IPv6 栈" if ipv6_ok else "IPv6 未关闭，存在旁路风险",
            },
            {
                "name": "WebRTC / STUN 防穿透",
                "ok": webrtc_ok or gate_st == "none",
                "detail": "内核已拦截 STUN 3478/19302 端口" if webrtc_ok else "标准转发模式",
            },
            {
                "name": "DNS / DoH 防抢答污染",
                "ok": dns_ok or gate_st == "none",
                "detail": "内核级 DNS/DoH 出口管控生效" if dns_ok else "标准 DNS 分流",
            },
            {
                "name": "Guardline 封条与安全闸",
                "ok": (gate_st == "open" and seal_state == "locked") if seal_state else (gate_st != "closed"),
                "detail": f"门禁已放行 · 封条 {seal_gen or 'locked'}" if (gate_st == "open" and seal_state == "locked") else f"门禁: {gate_st}",
            },
        ]

        score = 0
        if probes_consistent:
            score += 25
        elif len(probes) >= 1 and len(unique_ips) == 1:
            score += 15
        if is_residential:
            score += 25
        elif has_ip_meta and not is_hosting:
            score += 14
        if ipv6_ok:
            score += 15
        if webrtc_ok:
            score += 10
        if dns_ok:
            score += 10
        score += int(round(15 * (ok_sites / max(1, len(site_labels)))))
        score = max(0, min(100, score))
        grade = "极佳 · 原生纯净住宅环境" if score >= 90 else ("良好 · 安全可用" if score >= 75 else "提示 · 建议检查网络或节点")

        return {
            "ok": True,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "score": score,
            "grade": grade,
            "ip_info": {
                "ip": exit_ip or "—",
                "country": country_name or "—",
                "country_code": country_code or "—",
                "region": region,
                "city": city,
                "isp": isp_name or "—",
                "asn": asn_raw or "—",
                "timezone": tz or "—",
                "is_residential": is_residential,
                "is_hosting": is_hosting,
                "is_proxy": is_proxy_flag,
                "is_mobile": is_mobile,
            },
            "guards": guards,
            "platforms": platforms,
        }

    def update_ap_wifi(self, configs: list[dict], allow_all_off: bool = False) -> dict:
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        if not isinstance(configs, list) or not configs:
            return {"ok": False, "error": "未收到有效的热点配置"}
        with self._lock:
            uci = dict((self._slow or {}).get("uci_wifi") or {})
        valid_ap_secs = {sec for sec, d in uci.items() if d.get(".type") == "wifi-iface" and d.get("mode") == "ap" and SECTION_RE.match(sec)}
        if not valid_ap_secs:
            return {"ok": False, "error": "未找到可编辑的路由器 AP 热点配置段"}

        cmds = []
        any_enabled = False
        notes = []
        for item in configs:
            sec = str(item.get("section") or "").strip()
            if sec not in valid_ap_secs:
                return {"ok": False, "error": f"非法的热点配置段：{sec}"}
            en = bool(item.get("enabled", True))
            if en:
                any_enabled = True
            ssid = str(item.get("ssid") or "").strip()
            enc = str(item.get("encryption") or "psk2").strip()
            if enc not in ("psk2", "sae-mixed", "sae", "psk-mixed", "none"):
                enc = "psk2"
            key = str(item.get("key") or "")
            hid = "1" if item.get("hidden") else "0"

            if not (1 <= len(ssid.encode("utf-8")) <= 32):
                return {"ok": False, "error": f"Wi‑Fi 名称「{ssid}」长度需在 1～32 字节之间"}
            if enc != "none" and not (8 <= len(key) <= 63):
                return {"ok": False, "error": f"热点「{ssid}」的 Wi‑Fi 密码需为 8～63 位字符"}

            radio = str((uci.get(sec) or {}).get("device") or "")
            r_uci = uci.get(radio) or {}
            is_5g = str(r_uci.get("band") or "") == "5g"
            if en and radio and SECTION_RE.match(radio):
                cmds.append(f"uci set wireless.{radio}.disabled='0'")
            cmds.append(f"uci set wireless.{sec}.ssid={shlex.quote(ssid)}")
            cmds.append(f"uci set wireless.{sec}.encryption={shlex.quote(enc)}")
            cmds.append(f"uci set wireless.{sec}.hidden='{hid}'")
            cmds.append(f"uci set wireless.{sec}.disabled='{'0' if en else '1'}'")
            if enc == "none":
                cmds.append(f"uci -q delete wireless.{sec}.key")
            else:
                cmds.append(f"uci set wireless.{sec}.key={shlex.quote(key)}")

            if "isolate" in item:
                if item.get("isolate"):
                    cmds.append(f"uci set wireless.{sec}.isolate='1'")
                else:
                    cmds.append(f"uci -q delete wireless.{sec}.isolate")

            if "roaming" in item:
                if item.get("roaming"):
                    cmds.append(f"uci set wireless.{sec}.ieee80211k='1'")
                else:
                    cmds.append(f"uci -q delete wireless.{sec}.ieee80211k")
            # 清理 wpad-basic-mbedtls 不支持的 802.11v WNM 参数，避免 hostapd 拒绝启动 AP
            cmds.append(f"uci -q delete wireless.{sec}.bss_transition")
            cmds.append(f"uci -q delete wireless.{sec}.wnm_sleep_mode")

            if radio and SECTION_RE.match(radio):
                ht = str(item.get("htmode") or "").strip().upper()
                ch = str(item.get("channel") or "").strip().lower()
                txp = str(item.get("txpower") or "").strip().lower()
                ctry = str(item.get("country") or "").strip().upper()

                valid_ht = (
                    {"HE20", "HE40", "HE80", "HE160", "VHT20", "VHT40", "VHT80", "VHT160", "HT20", "HT40"}
                    if is_5g else {"HE20", "HE40", "HT20", "HT40"}
                )
                if ht in valid_ht:
                    if is_5g and ht in ("HE160", "VHT160") and ch in ("144", "149", "153", "157", "161", "165"):
                        ch = "36"
                        notes.append("5G 160MHz 频宽不支持 149+ 信道，已自动匹配至 36 信道")
                    cmds.append(f"uci set wireless.{radio}.htmode='{ht}'")

                if ch:
                    if ch == "auto":
                        cmds.append(f"uci set wireless.{radio}.channel='auto'")
                        if is_5g:
                            cmds.append(f"uci set wireless.{radio}.acs_exclude_dfs='1'")
                    elif ch.isdigit():
                        ch_n = int(ch)
                        if (is_5g and ch_n in (36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165)) or (not is_5g and 1 <= ch_n <= 13):
                            cmds.append(f"uci set wireless.{radio}.channel='{ch_n}'")

                if "txpower" in item:
                    if not txp or txp == "auto":
                        cmds.append(f"uci -q delete wireless.{radio}.txpower")
                    elif txp.isdigit() and 5 <= int(txp) <= 23:
                        cmds.append(f"uci set wireless.{radio}.txpower='{int(txp)}'")

                if ctry and re.match(r"^[A-Z]{2}$", ctry):
                    cmds.append(f"uci set wireless.{radio}.country='{ctry}'")

        if not any_enabled and not allow_all_off:
            return {"ok": False, "error": "请至少保留开启一个 Wi‑Fi 频段，或确认关闭全部无线发射"}

        cmds.append("uci commit wireless")
        cmds.append("( sleep 1; wifi reload ) </dev/null >/dev/null 2>&1 &")
        try:
            self._router.run("; ".join(cmds), timeout=12)
        except Exception:
            pass
        self._force.set()
        return {"ok": True, "note": "；".join(notes)}

    def reload_wifi_service(self) -> dict:
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        try:
            self._router.run("( wifi reload ) </dev/null >/dev/null 2>&1 &", timeout=8)
        except Exception:
            pass
        self._force.set()
        return {"ok": True}

    def reload_dhcp_dns(self) -> dict:
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        try:
            self._router.run("(/etc/init.d/dnsmasq reload || /etc/init.d/dnsmasq restart) >/dev/null 2>&1 &", timeout=10)
        except Exception as e:
            return {"ok": False, "error": f"重载 DHCP/DNS 失败：{e}"}
        self._force.set()
        return {"ok": True}

    def save_lan_dhcp_settings(self, dhcp_enabled: bool, dhcp_start: int, dhcp_limit: int, dhcp_lease: str, country: str = "") -> dict:
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        try:
            st = int(dhcp_start)
            lim = int(dhcp_limit)
        except Exception:
            return {"ok": False, "error": "DHCP 起始地址与分配数量需为整数"}
        if not (2 <= st <= 250):
            return {"ok": False, "error": "DHCP 起始地址号需在 2～250 之间"}
        if not (5 <= lim <= 250) or (st + lim > 254):
            return {"ok": False, "error": f"DHCP 分配数量需在 5～{254 - st} 之间（避免超出网段上限 .254）"}
        lease = str(dhcp_lease or "12h").strip().lower()
        if not re.match(r"^\d+[mhd]$", lease):
            return {"ok": False, "error": "租期格式示例：2h、12h、24h、7d"}

        cmds = [
            f"uci set dhcp.lan.start='{st}'",
            f"uci set dhcp.lan.limit='{lim}'",
            f"uci set dhcp.lan.leasetime='{lease}'",
        ]
        if dhcp_enabled:
            cmds.append("uci -q delete dhcp.lan.ignore")
        else:
            cmds.append("uci set dhcp.lan.ignore='1'")
        cmds.append("uci commit dhcp")

        ctry = str(country or "").strip().upper()
        need_wifi_reload = False
        if ctry and re.match(r"^[A-Z]{2}$", ctry):
            with self._lock:
                uci_w = dict((self._slow or {}).get("uci_wifi") or {})
            for rname, rd in uci_w.items():
                if rd.get(".type") == "wifi-device" and SECTION_RE.match(rname):
                    if str(rd.get("country") or "").upper() != ctry:
                        need_wifi_reload = True
                    cmds.append(f"uci set wireless.{rname}.country='{ctry}'")
            cmds.append("uci commit wireless")

        cmds.append("(/etc/init.d/dnsmasq reload || /etc/init.d/dnsmasq restart) >/dev/null 2>&1 &")
        if need_wifi_reload:
            cmds.append("( sleep 1; wifi reload ) </dev/null >/dev/null 2>&1 &")

        try:
            self._router.run("; ".join(cmds), timeout=12)
        except Exception as e:
            return {"ok": False, "error": f"保存局域网设置失败：{e}"}
        self._force.set()
        return {"ok": True, "wifi_reloaded": need_wifi_reload}

    def set_wan_priority(self, prefer_kind: str) -> dict:
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        if prefer_kind not in ("wired", "wifi"):
            return {"ok": False, "error": "不支持的线路类型"}
        if prefer_kind == "wifi":
            cmd = (
                "uci -q get network.wwan >/dev/null || exit 2; "
                "uci set network.wwan.metric='5'; "
                "uci -q get network.wan >/dev/null && uci set network.wan.metric='25'; "
                "uci commit network; /etc/init.d/network reload >/dev/null 2>&1; "
                "[ -x /etc/openclash/custom/ipguard.sh ] && ( sleep 2; /etc/openclash/custom/ipguard.sh >/dev/null 2>&1 & ) || true"
            )
        else:
            cmd = (
                "uci -q get network.wan >/dev/null || exit 2; "
                "uci set network.wan.metric='10'; "
                "uci -q get network.wwan >/dev/null && uci set network.wwan.metric='30'; "
                "uci commit network; /etc/init.d/network reload >/dev/null 2>&1; "
                "[ -x /etc/openclash/custom/ipguard.sh ] && ( sleep 2; /etc/openclash/custom/ipguard.sh >/dev/null 2>&1 & ) || true"
            )
        try:
            rc, _, _ = self._router.run(cmd, timeout=15)
            if rc == 2:
                return {"ok": False, "error": "目标上网接口尚未配置"}
        except Exception as e:
            return {"ok": False, "error": f"切换主出口优先级失败：{e}"}
        self._force.set()
        return {"ok": True}

    def set_device_block(self, mac: str, block: bool) -> dict:
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        mac = (mac or "").strip().lower()
        if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac):
            return {"ok": False, "error": "无效的设备 MAC 地址"}
        with self._lock:
            devs = self._devices() if (self._slow and self._fast) else []
            cur_blocked = set((self._slow or {}).get("rp_blocked") or set())
        target = next((d for d in devs if d["mac"] == mac), None)
        if block and target and target.get("me"):
            return {"ok": False, "error": "安全保护：不能禁网当前正在操作面板的本机电脑"}

        if block:
            cur_blocked.add(mac)
        else:
            cur_blocked.discard(mac)
        body = "\n".join(sorted(cur_blocked)) + ("\n" if cur_blocked else "")
        try:
            self._traffic_collector_ready = False
            self._ensure_router_traffic_collector(self._router)
            rc_b, _, err_b = self._router.run(
                "mkdir -p /etc/rp_traffic && cat > /etc/rp_traffic/blocked_macs.txt && /usr/sbin/rp-traffic-collect sync-devctl",
                timeout=12,
                stdin_data=body,
            )
            if rc_b != 0:
                return {"ok": False, "error": f"下发防火墙禁网规则失败：{(err_b or '').strip() or rc_b}"}
            with self._lock:
                if self._slow is not None:
                    self._slow["rp_blocked"] = set(cur_blocked)
        except Exception as e:
            return {"ok": False, "error": f"操作终端联网权限失败：{e}"}
        self._force.set()
        return {"ok": True, "blocked": bool(block)}

    def recheck_exit_gate(self) -> dict:
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        try:
            _, out, _ = self._router.run(
                "if [ -x /etc/openclash/custom/ipguard.sh ]; then "
                "  /etc/openclash/custom/ipguard.sh >/dev/null 2>&1; "
                "  echo GATE=$([ -f /tmp/ipguard.open ] && echo open || echo closed); "
                "  cat /tmp/ipguard.last 2>/dev/null; "
                "else echo GATE=none; fi",
                timeout=22,
            )
        except Exception as e:
            return {"ok": False, "error": f"触发出口门禁核验失败：{e}"}
        gate = "none"
        exit_ip = ""
        expected = ""
        mismatch = False
        for ln in out.splitlines():
            ln = ln.strip()
            if ln.startswith("GATE="):
                gate = ln[5:].strip()
            if "ip=" in ln and "expected=" in ln:
                info = parse_fast("@@IPGUARD\n" + ln + "\n").get("ipguard") or {}
                exit_ip = info.get("exit_ip") or exit_ip
                expected = info.get("expected") or expected
                mismatch = bool(info.get("mismatch"))
        self._force.set()
        return {"ok": True, "gate": gate, "exit_ip": exit_ip, "expected": expected, "mismatch": mismatch}

    def _probe_exit_consensus(self) -> dict:
        """经代理并发 5 源探测出口 IP，并查询归属地；用于判断「采用新出口」是否安全（防止把真实 IP 泄露当成新出口）。"""
        det_cmd = r"""
U=$(uci -q get openclash.@authentication[0].username)
P=$(uci -q get openclash.@authentication[0].password)
PORT=$(uci -q get openclash.config.mixed_port); PORT=${PORT:-7893}
if [ -n "$U" ]; then PX="http://$U:$P@127.0.0.1:$PORT"; else PX="http://127.0.0.1:$PORT"; fi
PD=/tmp/rp_adopt_ip; rm -rf "$PD"; mkdir -p "$PD"
p1() { r=$(curl -s -m 8 -x "$PX" "$2" 2>/dev/null); case "$2" in */trace) r=$(echo "$r" | sed -n 's/^ip=//p') ;; esac; echo "$r" | tr -d ' \r\n' > "$PD/$1"; }
p1 1 https://checkip.amazonaws.com &
p1 2 https://ifconfig.me/ip &
p1 3 https://api.ipify.org &
p1 4 https://ipinfo.io/ip &
p1 5 https://one.one.one.one/cdn-cgi/trace &
curl -s -m 8 -x "$PX" "http://ip-api.com/json/?fields=status,country,countryCode,isp,org,as,hosting,proxy,query" > "$PD/geo" 2>/dev/null &
wait
echo "@@IPS"; for i in 1 2 3 4 5; do cat "$PD/$i" 2>/dev/null; echo; done
echo "@@GEO"; cat "$PD/geo" 2>/dev/null; echo
echo "@@EXP"; sed -n 's/^EXPECTED=//p' /etc/openclash/custom/ipguard.sh 2>/dev/null | head -n1
echo "@@CAP"; [ -x /usr/sbin/guard-unlock ] && [ -x /etc/openclash/custom/ipguard.sh ] && echo ok || echo no
rm -rf "$PD"
"""
        _, out, _ = self._router.run(det_cmd, timeout=20)
        secs = split_sections(out)
        probed = [x.strip() for x in _one(secs, "IPS").splitlines() if _is_valid_ipv4(x.strip(), public_only=True)]
        geo = _json(_one(secs, "GEO").strip(), {}) or {}
        uniq = sorted(set(probed))
        ip = probed[0] if len(uniq) == 1 else ""
        cc = str(geo.get("countryCode") or "").upper()
        geo_ip = str(geo.get("query") or "")
        if ip and geo_ip and geo_ip != ip:
            cc = ""
        res = {
            "ip": ip,
            "probe_ips": uniq,
            "probes": len(probed),
            "consistent": bool(ip) and len(probed) >= 3,
            "country_code": cc,
            "country": geo.get("country") or "",
            "isp": geo.get("isp") or geo.get("org") or "",
            "hosting": bool(geo.get("hosting")),
            "expected": _one(secs, "EXP").strip(),
            "capable": _one(secs, "CAP").strip() == "ok",
        }
        if not res["capable"]:
            res["verdict"], res["reason"] = "unsupported", "当前路由器未启用 Guardline 出口门禁"
        elif len(uniq) > 1:
            res["verdict"], res["reason"] = "unsafe", f"多源探测出口不一致（{' / '.join(uniq)}），疑似分流异常"
        elif len(probed) < 3:
            res["verdict"], res["reason"] = "unsafe", f"仅 {len(probed)} 个探测源有返回，无法确认出口"
        elif cc in ("CN", ""):
            res["verdict"] = "unsafe"
            res["reason"] = ("出口归属地为中国大陆，疑似代理失效导致真实 IP 外露" if cc == "CN"
                             else "无法查询出口归属地，暂不自动采用")
        elif ip == res["expected"]:
            res["verdict"], res["reason"] = "same", "出口与门禁预期一致"
        else:
            res["verdict"], res["reason"] = "safe", ""
        return res

    def inspect_exit_ip(self) -> dict:
        """只读：复核当前代理出口，供界面弹窗给用户确认是否采用为门禁预期 IP。"""
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        try:
            r = self._probe_exit_consensus()
            r["ok"] = True
            return r
        except Exception as e:
            return {"ok": False, "error": f"出口复核失败：{e}"}

    def adopt_exit_ip(self, new_ip: str) -> dict:
        """用户确认后，经 5 源一致性 + 非大陆归属地复核，把门禁预期 IP 改为当前实测出口并重新核验放行。"""
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        new_ip = (new_ip or "").strip()
        if not _is_valid_ipv4(new_ip, public_only=True):
            return {"ok": False, "error": "无效的出口 IP"}
        creds = self._active_creds() or {}
        root_pw = creds.get("pw") or ""
        if not root_pw:
            return {"ok": False, "error": "缺少路由器登录凭据，请重新登录后再试"}
        try:
            chk = self._probe_exit_consensus()
            if chk["verdict"] == "same":
                res = self.recheck_exit_gate()
                res.update(ok=True, adopted=new_ip, previous=chk["expected"], probes=chk["probes"])
                return res
            if chk["verdict"] != "safe":
                return {"ok": False, "error": chk["reason"] + "，门禁保持关闭"}
            if chk["ip"] != new_ip:
                return {"ok": False, "error": f"复核出口为 {chk['ip']}，与待采用的 {new_ip} 不同，已取消"}
            cur_expected = chk["expected"]
            u_rc, u_out, u_err = self._router.run(
                f"/usr/sbin/guard-unlock -c {shlex.quote(f'sed -i s/^EXPECTED=.*/EXPECTED={new_ip}/ /etc/openclash/custom/ipguard.sh')}",
                timeout=25,
                stdin_data=root_pw + "\n",
            )
            if u_rc != 0:
                return {"ok": False, "error": f"封条认证修改失败：{(u_err or u_out).strip() or u_rc}"}
            res = self.recheck_exit_gate()
            res.update(ok=True, adopted=new_ip, previous=cur_expected, probes=chk["probes"])
            return res
        except Exception as e:
            return {"ok": False, "error": f"采用新出口失败：{e}"}

    def flush_clash_connections(self, conn_id: str = "") -> dict:
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        cid = (conn_id or "").strip()
        if cid and not re.match(r"^[A-Za-z0-9_-]+$", cid):
            return {"ok": False, "error": "无效的连接 ID"}
        suffix = f"/{cid}" if cid else ""
        cmd = CLASH_API + f'\nc_alive && curl -s -m 6 -X DELETE -H "Authorization: Bearer $S" "http://127.0.0.1:${{P:-9090}}/connections{suffix}" >/dev/null 2>&1\n'
        try:
            self._router.run(cmd, timeout=10)
        except Exception as e:
            return {"ok": False, "error": f"断开连接失败：{e}"}
        self._force.set()
        return {"ok": True}

    def restart_openclash(self) -> dict:
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        cmd = (
            "if [ -x /etc/init.d/openclash ]; then "
            "( /etc/init.d/openclash restart >/dev/null 2>&1; sleep 6; "
            "[ -x /etc/openclash/custom/ipguard.sh ] && /etc/openclash/custom/ipguard.sh >/dev/null 2>&1 ) </dev/null >/dev/null 2>&1 & "
            "echo ok; else echo missing; fi"
        )
        try:
            _, out, _ = self._router.run(cmd, timeout=10)
            if "missing" in out:
                return {"ok": False, "error": "当前路由器未安装 OpenClash 服务"}
        except Exception as e:
            return {"ok": False, "error": f"重启 OpenClash 失败：{e}"}
        self._force.set()
        return {"ok": True}

    def reboot_router(self) -> dict:
        if not self._router:
            return {"ok": False, "error": "尚未连接软路由"}
        cmd = (
            "[ -x /usr/sbin/rp-traffic-collect ] && /usr/sbin/rp-traffic-collect flush >/dev/null 2>&1 || true; "
            "sync; ( sleep 1; reboot ) </dev/null >/dev/null 2>&1 &"
        )
        try:
            self._router.run(cmd, timeout=8)
        except Exception:
            pass
        return {"ok": True}

    # ---------------------------------------------------------- 本地设置
    def set_alias(self, mac, name):
        mac = (mac or "").lower()
        if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac):
            return False
        if (name or "").strip():
            self._cfg["aliases"][mac] = name.strip()[:40]
        else:
            self._cfg["aliases"].pop(mac, None)
        save_cfg(self._cfg)
        return True

    def set_topmost(self, v):
        self._cfg["topmost"] = bool(v)
        save_cfg(self._cfg)

    def set_close_to_tray(self, v):
        self._cfg["close_to_tray"] = bool(v)
        save_cfg(self._cfg)
        return self._cfg["close_to_tray"]

    def set_auto_connect_wifi(self, v):
        val = bool(v)
        self._cfg["auto_connect_wifi"] = val
        save_cfg(self._cfg)
        if val:
            self._auto_conn_fail_until.clear()
            self._auto_conn_last_ts = 0.0
            if time.monotonic() - self._wifi_scan_ts > 25.0:
                self._wifi_scan_ts = 0.0
            self._force.set()
            threading.Thread(target=self._maybe_auto_connect_wifi, daemon=True).start()
        return val

    def set_auto_start(self, v):
        applied = apply_autostart(bool(v))
        self._cfg["auto_start"] = bool(applied)
        save_cfg(self._cfg)
        return bool(applied)

    def set_alerts_enabled(self, v):
        self._cfg["alerts_enabled"] = bool(v)
        save_cfg(self._cfg)
        return self._cfg["alerts_enabled"]

    def set_privacy_mode(self, v):
        self._cfg["privacy_mode"] = bool(v)
        save_cfg(self._cfg)
        return self._cfg["privacy_mode"]

    def set_theme(self, t):
        if t in ("dark", "light"):
            self._cfg["theme"] = t
            save_cfg(self._cfg)
        return self._cfg.get("theme", "dark")

    def set_accent(self, a):
        if a in ("claude", "blue", "amber", "emerald", "violet"):
            self._cfg["accent"] = a
            save_cfg(self._cfg)
        return self._cfg.get("accent", "claude")

    def set_font_scale(self, sc):
        try:
            v = round(max(0.9, min(1.25, float(sc))), 2)
        except Exception:
            v = 1.0
        self._cfg["font_scale"] = v
        save_cfg(self._cfg)
        return v

    def refresh(self):
        self._force.set()


# ================================================================== 界面桥接（pywebview）
class Api:
    def __init__(self, backend):
        self._b = backend
        self._win = None
        self._max = False
        self._tray = None
        self._tray_refs = None
        self._force_quit = False
        self._tray_tip_shown = False
        self._woken_early = False

    def _gui_call(self, fn):
        if not self._win or not getattr(self._win, "native", None):
            return
        form = self._win.native
        try:
            if getattr(form, "IsDisposed", False):
                return
            from System import Action
            if form.InvokeRequired:
                form.Invoke(Action(fn))
            else:
                fn()
        except Exception as e:
            print("gui_call:", e)

    def _cleanup_tray(self):
        tray = self._tray
        self._tray = None
        self._tray_refs = None
        if tray is not None:
            try:
                tray.Visible = False
                tray.Dispose()
            except Exception:
                pass

    def state(self):
        return self._b.snapshot()

    # ---- 软路由网关发现 & 账号登录/切换 ----
    def detect_gateways(self):
        return detect_gateways()

    def login(self, host, user, pw, remember=True, port=22):
        return self._b.login(host, user, pw, remember, port=port)

    def switch_router(self, host, port, user):
        return self._b.quick_switch_router(host, port, user)

    def remove_router(self, host, port, user):
        return self._b.remove_saved_router(host, port, user)

    def logout(self):
        self._b.logout()
        return True

    # ---- 无线桥接 ----
    def scan_wifi(self):
        return self._b.scan_wifi()

    def connect_bridge(self, ssid, band, encryption, password, save_profile=True):
        return self._b.connect_bridge(ssid, band, encryption, password, save_profile)

    def disconnect_bridge(self):
        return self._b.disconnect_bridge()

    def delete_saved_wifi(self, ssid, band):
        return self._b.delete_saved_wifi(ssid, band)

    def clear_bridge_msg(self):
        return self._b.clear_bridge_msg()

    # ---- 代理节点更新 / 测速 / 切换 ----
    def start_update_proxy(self, sub_url="", expected_ip="", auto_detect_ip=False, yaml_content=""):
        return self._b.start_update_proxy(sub_url, expected_ip, auto_detect_ip, yaml_content)

    def proxy_update_status(self):
        return self._b.proxy_update_status()

    def test_proxy_delays(self, group_name="", node_name=""):
        return self._b.test_proxy_delays(group_name, node_name)

    def select_proxy_node(self, group_name, node_name):
        return self._b.select_proxy_node(group_name, node_name)

    # ---- 流量统计 ----
    def query_traffic(self, granularity="day", start_dt="", end_dt="", preset="", sync_now=False):
        return self._b.query_traffic(granularity, start_dt, end_dt, preset, bool(sync_now))

    def export_traffic_csv(self, granularity="day", start_dt="", end_dt="", preset=""):
        return self._b.export_traffic_csv(granularity, start_dt, end_dt, preset)

    def clear_traffic_history(self):
        return self._b.clear_traffic_history()

    # ---- 环境体检 / 本机热点 / 终端管控 / 线路优先级 / 故障自愈 ----
    def run_security_audit(self):
        return self._b.run_security_audit()

    def update_ap_wifi(self, configs, allow_all_off=False):
        return self._b.update_ap_wifi(configs, bool(allow_all_off))

    def reload_wifi_service(self):
        return self._b.reload_wifi_service()

    def reload_dhcp_dns(self):
        return self._b.reload_dhcp_dns()

    def save_lan_dhcp_settings(self, dhcp_enabled, dhcp_start, dhcp_limit, dhcp_lease, country=""):
        return self._b.save_lan_dhcp_settings(bool(dhcp_enabled), dhcp_start, dhcp_limit, dhcp_lease, country)

    def set_wan_priority(self, prefer_kind):
        return self._b.set_wan_priority(prefer_kind)

    def set_device_block(self, mac, block):
        return self._b.set_device_block(mac, bool(block))

    def recheck_exit_gate(self):
        return self._b.recheck_exit_gate()

    def adopt_exit_ip(self, new_ip=""):
        return self._b.adopt_exit_ip(new_ip)

    def inspect_exit_ip(self):
        return self._b.inspect_exit_ip()

    def flush_clash_connections(self, conn_id=""):
        return self._b.flush_clash_connections(conn_id)

    def restart_openclash(self):
        return self._b.restart_openclash()

    def reboot_router(self):
        return self._b.reboot_router()

    def set_alerts_enabled(self, v):
        return self._b.set_alerts_enabled(v)

    def set_privacy_mode(self, v):
        return self._b.set_privacy_mode(v)

    # ---- 界面设置与窗口控制 ----
    def set_alias(self, mac, name):
        return self._b.set_alias(mac, name)

    def refresh(self):
        self._b.refresh()
        return True

    def toggle_top(self):
        v = not self._b._cfg.get("topmost")
        self._b.set_topmost(v)
        if self._win:
            self._win.on_top = v
        return v

    def set_theme(self, t):
        return self._b.set_theme(t)

    def set_accent(self, a):
        return self._b.set_accent(a)

    def set_font_scale(self, sc):
        return self._b.set_font_scale(sc)

    def set_close_to_tray(self, v):
        return self._b.set_close_to_tray(v)

    def set_auto_connect_wifi(self, v):
        return self._b.set_auto_connect_wifi(v)

    def set_auto_start(self, v):
        return self._b.set_auto_start(v)

    def hide_to_tray(self):
        if not self._win:
            return False
        def _do():
            form = self._win.native
            form.Hide()
            if not self._tray_tip_shown and self._tray is not None:
                self._tray_tip_shown = True
                try:
                    from System.Windows.Forms import ToolTipIcon
                    self._tray.ShowBalloonTip(
                        2000, "Guardline Status",
                        "已转入系统托盘后台运行，点击托盘图标可恢复窗口。", ToolTipIcon.Info,
                    )
                except Exception:
                    pass
        self._gui_call(_do)
        return True

    def restore_from_tray(self):
        self._woken_early = True
        if not self._win:
            return False
        def _do():
            from System.Windows.Forms import FormWindowState
            form = self._win.native
            form.ShowInTaskbar = True
            try:
                u32 = ctypes.windll.user32
                hwnd = int(form.Handle.ToInt64())
                ex = u32.GetWindowLongW(ctypes.c_void_p(hwnd), -20)
                if ex & 0x00080000:
                    u32.SetLayeredWindowAttributes(ctypes.c_void_p(hwnd), 0, 255, 0x2)
                    u32.SetWindowLongW(ctypes.c_void_p(hwnd), -20, ex & ~0x00080000)
            except Exception:
                pass
            if not form.Visible:
                form.Show()
            if form.WindowState == FormWindowState.Minimized:
                form.WindowState = FormWindowState.Normal
            form.Activate()
            try:
                hwnd = int(form.Handle.ToInt64())
                ctypes.windll.user32.SetForegroundWindow(ctypes.c_void_p(hwnd))
            except Exception:
                pass
        self._gui_call(_do)
        return True

    def quit_app(self):
        self._force_quit = True
        if not self._win:
            return True
        self._gui_call(self._cleanup_tray)
        try:
            self._win.destroy()
        except Exception:
            pass
        return True

    def open_admin(self):
        host = (self._b._active_creds() or {}).get("host") or self._b._cfg.get("host") or self._b._default_gw
        webbrowser.open(f"http://{host}")
        return True

    def initial_page(self):
        return os.environ.get("PANEL_PAGE", "overview")

    def win_min(self):
        if self._win:
            self._win.minimize()
        return True

    def win_max(self):
        if not self._win:
            return False
        if self._max:
            self._win.restore()
            self._max = False
        else:
            self._win.maximize()
            self._max = True
        return self._max

    def win_toggle_max_fast(self):
        """最大化/还原：按真实窗口状态切换，并用 BeginInvoke 异步提交到 UI 线程，不阻塞调用方，双击标题栏即时响应。"""
        if not self._win or not getattr(self._win, "native", None):
            return False
        form = self._win.native
        try:
            hwnd = int(form.Handle.ToInt64())
            zoomed = bool(ctypes.windll.user32.IsZoomed(ctypes.c_void_p(hwnd)))
            from System import Action
            from System.Windows.Forms import FormWindowState

            def _apply():
                form.WindowState = FormWindowState.Normal if zoomed else FormWindowState.Maximized

            form.BeginInvoke(Action(_apply))
            self._max = not zoomed
            return self._max
        except Exception as e:
            print("win_toggle_max_fast:", e)
            return self.win_max()

    def win_close(self):
        if not self._win:
            return True
        if self._b._cfg.get("close_to_tray", True) and not self._force_quit:
            return self.hide_to_tray()
        return self.quit_app()

    def win_bounds(self):
        if not self._win:
            return None
        hwnd = int(self._win.native.Handle.ToInt64())
        r = ctypes.wintypes.RECT()
        ctypes.windll.user32.GetWindowRect(ctypes.c_void_p(hwnd), ctypes.byref(r))
        return {"x": r.left, "y": r.top, "w": r.right - r.left, "h": r.bottom - r.top, "max": self._max}

    def win_set_bounds(self, x, y, w, h):
        if not self._win or self._max:
            return False
        hwnd = int(self._win.native.Handle.ToInt64())
        w = max(940, int(w))
        h = max(620, int(h))
        ctypes.windll.user32.SetWindowPos(ctypes.c_void_p(hwnd), None, int(x), int(y), w, h, 0x4014)
        return True

    def win_start_drag(self):
        if not self._win or getattr(self, "_dragging", False):
            return False
        hwnd = int(self._win.native.Handle.ToInt64())
        u32 = ctypes.windll.user32
        vk = 0x02 if u32.GetSystemMetrics(23) else 0x01
        if not (u32.GetAsyncKeyState(vk) & 0x8000):
            return False
        pt0 = ctypes.wintypes.POINT()
        u32.GetCursorPos(ctypes.byref(pt0))

        def _loop():
            self._dragging = True
            try:
                moving = False
                rc0 = ctypes.wintypes.RECT()
                u32.GetWindowRect(ctypes.c_void_p(hwnd), ctypes.byref(rc0))
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
                        if self._max:
                            max_w = max(1, rc0.right - rc0.left)
                            ratio = min(0.85, max(0.15, (pt0.x - rc0.left) / max_w))
                            self._win.restore()
                            self._max = False
                            u32.GetWindowRect(ctypes.c_void_p(hwnd), ctypes.byref(rc0))
                            rw, rh = rc0.right - rc0.left, rc0.bottom - rc0.top
                            nx = int(pt.x - rw * ratio)
                            ny = max(0, int(pt.y - 18))
                            u32.SetWindowPos(ctypes.c_void_p(hwnd), None, nx, ny, rw, rh, 0x4014)
                            rc0.left, rc0.top = nx, ny
                            pt0.x, pt0.y = pt.x, pt.y
                    if cur != last:
                        last = cur
                        u32.SetWindowPos(
                            ctypes.c_void_p(hwnd), None,
                            rc0.left + pt.x - pt0.x,
                            rc0.top + pt.y - pt0.y,
                            0, 0, 0x4015,
                        )
                    time.sleep(0.008)
            finally:
                self._dragging = False

        threading.Thread(target=_loop, daemon=True).start()
        return True

    def win_start_resize(self, direction: str):
        if not self._win or self._max or getattr(self, "_dragging", False):
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
        bw, bh = rc0.right - rc0.left, rc0.bottom - rc0.top
        d = str(direction or "")

        def _loop():
            self._dragging = True
            try:
                last = (pt0.x, pt0.y)
                pt = ctypes.wintypes.POINT()
                while u32.GetAsyncKeyState(vk) & 0x8000:
                    u32.GetCursorPos(ctypes.byref(pt))
                    cur = (pt.x, pt.y)
                    if cur != last:
                        last = cur
                        dx, dy = pt.x - pt0.x, pt.y - pt0.y
                        x, y, w, h = rc0.left, rc0.top, bw, bh
                        if "e" in d:
                            w = max(940, bw + dx)
                        if "s" in d:
                            h = max(620, bh + dy)
                        if "w" in d:
                            w = max(940, bw - dx)
                            x = rc0.right - w
                        if "n" in d:
                            h = max(620, bh - dy)
                            y = rc0.bottom - h
                        u32.SetWindowPos(ctypes.c_void_p(hwnd), None, x, y, w, h, 0x0114)
                    time.sleep(0.015)
            finally:
                self._dragging = False

        threading.Thread(target=_loop, daemon=True).start()
        return True


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
        u32.LoadImageW.restype = ctypes.c_void_p
        for size, which in ((16, 0), (32, 0), (48, 1), (256, 1)):
            h = u32.LoadImageW(None, str(ICON), 1, size if which == 0 else 0, size if which == 0 else 0,
                               0x10 | (0x40 if which else 0))
            if h:
                u32.SendMessageW(ctypes.c_void_p(hwnd), 0x80, which, ctypes.c_void_p(h))
    except Exception as e:
        print("window setup:", e)


def ensure_webview2_runtime() -> bool:
    """检测本机是否具备 Edge WebView2 运行时；针对精简版 Win10 提供一键自动补齐。"""
    import winreg
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
    ans = ctypes.windll.user32.MessageBoxW(
        None,
        "检测到当前系统为精简版 Windows，缺少微软 Edge WebView2 界面组件。\n\n是否现在自动下载并安装官方运行库（约 1.8 MB，全自动完成）？",
        "Guardline Status · 环境补齐",
        0x00000004 | 0x00000040,
    )
    if ans != 6:
        return False
    try:
        bs = Path(os.environ.get("TEMP", ".")) / "MicrosoftEdgeWebview2Setup.exe"
        urllib.request.urlretrieve("https://go.microsoft.com/fwlink/p/?LinkId=2124703", str(bs))
        subprocess.run([str(bs), "/silent", "/install"], check=False)
        return True
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(None, f"自动下载 WebView2 失败：{e}\n请联网后重试。", "提示", 0x10)
        return False


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


def _bind_splashless_reveal(win, api=None, start_hidden=False):
    """在 before_show 阶段设 alpha=1（99.6% 透明，避免 GPU 判遮挡停绘），待首帧绘制就绪再显形或静默收入后台托盘。"""
    state = {"hwnd": 0, "revealed": False}
    lock = threading.Lock()
    u32 = ctypes.windll.user32
    GWL_EXSTYLE = -20
    WS_EX_LAYERED = 0x00080000
    LWA_ALPHA = 0x2

    def on_before_show():
        _center_native_form(win)
        try:
            if start_hidden:
                win.native.ShowInTaskbar = False
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
        if start_hidden and api is not None and not getattr(api, "_woken_early", False):
            def _hide_silent():
                try:
                    form = win.native
                    form.Hide()
                    form.ShowInTaskbar = True
                    u32.SetLayeredWindowAttributes(ctypes.c_void_p(hwnd), 0, 255, LWA_ALPHA)
                    ex = u32.GetWindowLongW(ctypes.c_void_p(hwnd), GWL_EXSTYLE)
                    u32.SetWindowLongW(ctypes.c_void_p(hwnd), GWL_EXSTYLE, ex & ~WS_EX_LAYERED)
                except Exception:
                    pass
            api._gui_call(_hide_silent)
            return
        try:
            if start_hidden:
                win.native.ShowInTaskbar = True
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


def _setup_tray(win, api):
    """挂载 Windows 系统托盘图标、动态绿/黄/红状态角标、右键菜单与异常状态主动通知。"""
    def _create():
        try:
            from System.Windows.Forms import NotifyIcon, ContextMenuStrip, ToolStripSeparator, MouseButtons, ToolTipIcon
            from System.Drawing import Icon as DrawingIcon, Bitmap, Graphics, SolidBrush, Pen, Color
            from System.Drawing.Drawing2D import SmoothingMode
            form = win.native
            tray = NotifyIcon()
            tray.Text = "Guardline Status"
            try:
                base_ico = DrawingIcon(str(ICON)) if ICON.exists() else form.Icon
            except Exception:
                base_ico = form.Icon
            tray.Icon = base_ico

            # Pre-generate 3 badged tray icons once (ok/warn/err) so zero GDI handles are allocated in the loop
            badged_icons = {}
            try:
                src_bmp = Bitmap(str(ICON_PNG)) if ICON_PNG.exists() else base_ico.ToBitmap()
                for key, (r, g, b) in (("ok", (16, 185, 129)), ("warn", (245, 158, 11)), ("err", (239, 68, 68))):
                    canvas = Bitmap(32, 32)
                    gr = Graphics.FromImage(canvas)
                    gr.SmoothingMode = SmoothingMode.AntiAlias
                    gr.DrawImage(src_bmp, 0, 0, 32, 32)
                    bg_pen = Pen(Color.FromArgb(245, 18, 18, 20), 2.6)
                    fill_br = SolidBrush(Color.FromArgb(255, r, g, b))
                    gr.FillEllipse(fill_br, 20, 20, 10, 10)
                    gr.DrawEllipse(bg_pen, 20, 20, 10, 10)
                    bg_pen.Dispose()
                    fill_br.Dispose()
                    gr.Dispose()
                    badged_icons[key] = DrawingIcon.FromHandle(canvas.GetHicon())
                    canvas.Dispose()
                src_bmp.Dispose()
            except Exception as e_ico:
                print("tray badge icons:", e_ico)

            menu = ContextMenuStrip()
            mi_show = menu.Items.Add("显示主界面")
            mi_admin = menu.Items.Add("打开路由后台")
            menu.Items.Add(ToolStripSeparator())
            mi_autowifi = menu.Items.Add("自动连接记忆库 Wi-Fi")
            mi_autostart = menu.Items.Add("开机自动启动")
            mi_alerts = menu.Items.Add("桌面守护异常通知")
            menu.Items.Add(ToolStripSeparator())
            mi_quit = menu.Items.Add("退出程序")

            def on_opening(sender, e):
                try:
                    mi_autowifi.Checked = bool(api._b._cfg.get("auto_connect_wifi", False))
                    mi_autostart.Checked = bool(api._b._cfg.get("auto_start", False))
                    mi_alerts.Checked = bool(api._b._cfg.get("alerts_enabled", True))
                except Exception:
                    pass

            def on_show(sender, e):
                threading.Thread(target=api.restore_from_tray, daemon=True).start()

            def on_admin(sender, e):
                threading.Thread(target=api.open_admin, daemon=True).start()

            def on_autowifi(sender, e):
                nxt = not bool(api._b._cfg.get("auto_connect_wifi", False))
                threading.Thread(target=api.set_auto_connect_wifi, args=(nxt,), daemon=True).start()

            def on_autostart(sender, e):
                nxt = not bool(api._b._cfg.get("auto_start", False))
                threading.Thread(target=api.set_auto_start, args=(nxt,), daemon=True).start()

            def on_alerts(sender, e):
                nxt = not bool(api._b._cfg.get("alerts_enabled", True))
                threading.Thread(target=api.set_alerts_enabled, args=(nxt,), daemon=True).start()

            def on_quit(sender, e):
                threading.Thread(target=api.quit_app, daemon=True).start()

            def on_click(sender, e):
                try:
                    if e.Button == MouseButtons.Left:
                        threading.Thread(target=api.restore_from_tray, daemon=True).start()
                except Exception:
                    pass

            def on_closing(sender, e):
                if (not api._force_quit
                        and api._b._cfg.get("close_to_tray", True)
                        and str(getattr(e, "CloseReason", "")) == "UserClosing"):
                    e.Cancel = True
                    threading.Thread(target=api.hide_to_tray, daemon=True).start()
                    return
                api._cleanup_tray()

            menu.Opening += on_opening
            mi_show.Click += on_show
            mi_admin.Click += on_admin
            mi_autowifi.Click += on_autowifi
            mi_autostart.Click += on_autostart
            mi_alerts.Click += on_alerts
            mi_quit.Click += on_quit
            tray.MouseClick += on_click
            tray.DoubleClick += on_show
            form.FormClosing += on_closing
            tray.ContextMenuStrip = menu
            tray.Visible = True
            api._tray = tray
            api._tray_refs = (
                tray, menu, mi_show, mi_admin, mi_autowifi, mi_autostart, mi_alerts, mi_quit,
                on_opening, on_show, on_admin, on_autowifi, on_autostart, on_alerts, on_quit, on_click, on_closing,
                base_ico, badged_icons,
            )

            def _tray_watch():
                last_lvl = ""
                last_tip = ""
                seen_online = False
                prev_gate = ""
                prev_ip = ""
                offline_since = 0.0
                offline_notified = False
                last_balloon_ts = 0.0

                def _notify(title_s: str, msg_s: str, is_warn: bool = False):
                    nonlocal last_balloon_ts
                    if not api._b._cfg.get("alerts_enabled", True):
                        return
                    now_t = time.monotonic()
                    if now_t - last_balloon_ts < 4.0:
                        return
                    last_balloon_ts = now_t
                    def _show_b():
                        if api._tray is not None:
                            try:
                                api._tray.ShowBalloonTip(
                                    3200, title_s, msg_s,
                                    ToolTipIcon.Warning if is_warn else ToolTipIcon.Info,
                                )
                            except Exception:
                                pass
                    api._gui_call(_show_b)

                while api._tray is not None and not api._force_quit:
                    try:
                        ts = api._b.tray_status()
                        st = ts.get("status", "idle")
                        gate = ts.get("gate") or ""
                        exit_ip = ts.get("exit_ip") or ""
                        priv = bool(ts.get("privacy_mode", False))
                        disp_ip = mask_ip_text(exit_ip) if priv else exit_ip
                        disp_prev_ip = mask_ip_text(prev_ip) if priv else prev_ip

                        if st == "online":
                            seen_online = True
                            offline_since = 0.0
                            if offline_notified:
                                offline_notified = False
                                _notify("Guardline Status · 已恢复连接", f"软路由已重新上线{f' · 出口 {disp_ip}' if disp_ip else ''}", False)
                            if gate == "closed":
                                lvl = "err"
                                tip = "Guardline Status · 出口门禁阻断保护中"
                            elif gate == "checking":
                                lvl = "warn"
                                tip = "Guardline Status · 正在核验出口门禁"
                            else:
                                lvl = "ok"
                                tip = f"Guardline Status · 守护正常 ({disp_ip})" if disp_ip else "Guardline Status · 在线运行中"

                            if prev_gate and gate != prev_gate:
                                if gate == "closed":
                                    _notify("出口安全闸已阻断保护", "检测到出口异常或切换中，已自动阻断防真实 IP 泄露。", True)
                                elif gate == "open" and prev_gate in ("closed", "checking"):
                                    _notify("出口安全闸已恢复放行", f"多源探针核验通过，当前纯净出口：{disp_ip or '已就绪'}", False)
                            if prev_ip and exit_ip and exit_ip != prev_ip and gate == "open":
                                _notify("出口公网 IP 变动提醒", f"出口 IP 已由 {disp_prev_ip} 变更为 {disp_ip}", True)
                            if gate:
                                prev_gate = gate
                            if exit_ip:
                                prev_ip = exit_ip
                        elif st in ("connecting", "idle"):
                            lvl = "warn"
                            tip = "Guardline Status · 正在连接软路由..."
                        else:
                            lvl = "err"
                            tip = "Guardline Status · 软路由离线或待登录"
                            if seen_online and st == "offline":
                                if not offline_since:
                                    offline_since = time.monotonic()
                                elif not offline_notified and (time.monotonic() - offline_since) >= 6.0:
                                    offline_notified = True
                                    _notify("软路由连接中断", "与路由器的监控连接暂时断开，后台正在自动重连。", True)

                        tip_safe = tip[:62]
                        if lvl != last_lvl or tip_safe != last_tip:
                            last_lvl, last_tip = lvl, tip_safe
                            ico_obj = badged_icons.get(lvl, base_ico)
                            def _upd(ic=ico_obj, tp=tip_safe):
                                if api._tray is not None:
                                    try:
                                        api._tray.Icon = ic
                                        api._tray.Text = tp
                                    except Exception:
                                        pass
                            api._gui_call(_upd)
                    except Exception:
                        pass
                    time.sleep(2.0)

            threading.Thread(target=_tray_watch, daemon=True).start()
        except Exception as e:
            print("setup tray:", e)

    try:
        from System import Action
        form = win.native
        if form.InvokeRequired:
            form.Invoke(Action(_create))
        else:
            _create()
    except Exception as e:
        print("invoke tray:", e)


PAGE_BG = {
    ("dark", "claude"): "#0f0d0b",
    ("dark", "blue"): "#121316",
    ("dark", "amber"): "#141210",
    ("dark", "emerald"): "#111514",
    ("dark", "violet"): "#131217",
    ("light", "claude"): "#f7f2ee",
    ("light", "blue"): "#eff2f7",
    ("light", "amber"): "#f6f2ed",
    ("light", "emerald"): "#eef5f2",
    ("light", "violet"): "#f2f0f8",
}


def start_local_fast_server(backend: Backend, api: Api) -> tuple[http.server.ThreadingHTTPServer, str, str]:
    """本机 127.0.0.1 HTTP/1.1 Keep-Alive 极速数据通道：完全绕开 pywebview WinForms UI 线程 Invoke 与 JS 字符串编译卡顿。"""
    token = secrets.token_hex(16)

    class _FastHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def _send_bytes(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            try:
                u = urllib.parse.urlsplit(self.path)
                qs = urllib.parse.parse_qs(u.query)
                if (qs.get("t") or [""])[0] != token:
                    self._send_bytes(403, b"{}")
                    return
                if u.path == "/state":
                    try:
                        s_seq = int((qs.get("ss") or qs.get("s") or ["0"])[0] or 0)
                    except Exception:
                        s_seq = 0
                    try:
                        w_seq = int((qs.get("ws") or qs.get("w") or ["0"])[0] or 0)
                    except Exception:
                        w_seq = 0
                    page = (qs.get("page") or qs.get("p") or [""])[0]
                    drw = (qs.get("drawer") or qs.get("d") or ["0"])[0] == "1"
                    data = backend.snapshot_delta(s_seq, w_seq, page, drw)
                    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    self._send_bytes(200, raw)
                    return
                if u.path == "/drag":
                    api.win_start_drag()
                    self._send_bytes(200, b'{"ok":true}')
                    return
                if u.path == "/max":
                    mx = api.win_toggle_max_fast()
                    self._send_bytes(200, b'{"ok":true,"max":true}' if mx else b'{"ok":true,"max":false}')
                    return
                if u.path == "/resize":
                    api.win_start_resize((qs.get("dir") or [""])[0])
                    self._send_bytes(200, b'{"ok":true}')
                    return
                self._send_bytes(404, b"{}")
            except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                try:
                    self._send_bytes(500, b"{}")
                except Exception:
                    pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FastHandler)
    srv.daemon_threads = True
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{port}", token


def build_ui_html(cfg: dict, fast_url: str = "", fast_token: str = "") -> tuple[str, str]:
    """按已保存的深浅外观、主题色和缩放比例生成首帧 HTML 及对应窗口底色，避免启动闪烁。"""
    cfg = cfg or {}
    theme = cfg.get("theme") if cfg.get("theme") in ("dark", "light") else "dark"
    accent = cfg.get("accent") if cfg.get("accent") in ("claude", "blue", "amber", "emerald", "violet") else "claude"
    try:
        fs = round(max(0.9, min(1.25, float(cfg.get("font_scale", 1.0) or 1.0))), 2)
    except Exception:
        fs = 1.0

    html = (
        (HERE / "ui.html")
        .read_text("utf-8")
        .replace("__ICON_DATA_URI__", icon_data_uri())
        .replace("__FONT_INTER__", font_data_uri("InterVariable-Latin.woff2"))
        .replace("__FONT_MONO_400__", font_data_uri("JetBrainsMono-Latin.woff2"))
        .replace("__FONT_MONO_500__", font_data_uri("JetBrainsMono-Medium.woff2"))
    )
    html = html.replace(
        '<html lang="zh-CN" data-theme="dark" data-accent="claude">',
        f'<html lang="zh-CN" data-theme="{theme}" data-accent="{accent}">',
        1,
    )
    priv_mode = bool(cfg.get("privacy_mode", False))
    boot_obj = {
        "theme": theme,
        "accent": accent,
        "font_scale": fs,
        "privacy_mode": priv_mode,
        "fast_url": fast_url,
        "fast_token": fast_token,
    }
    boot_script = "<script>window.__BOOT=" + json.dumps(boot_obj) + ";</script>"
    html = html.replace("</head>", boot_script + "\n</head>", 1)
    body_cls = ' class="privacy-on"' if priv_mode else ""
    zoom_style = f' style="zoom:{fs}"' if abs(fs - 1.0) > 0.005 else ""
    html = html.replace("<body>", f"<body{body_cls}{zoom_style}>", 1)
    bg = PAGE_BG.get((theme, accent), "#f7f2ee" if theme == "light" else "#0f0d0b")
    return html, bg


def _desktop_tag() -> str:
    """Return a kernel-object safe identifier for the current Windows ThreadDesktop."""
    try:
        u32 = ctypes.windll.user32
        k32 = ctypes.windll.kernel32
        u32.GetThreadDesktop.restype = ctypes.c_void_p
        hdesk = u32.GetThreadDesktop(k32.GetCurrentThreadId())
        if hdesk:
            buf = ctypes.create_unicode_buffer(256)
            needed = ctypes.c_uint(0)
            if u32.GetUserObjectInformationW(ctypes.c_void_p(hdesk), 2, buf, ctypes.sizeof(buf), ctypes.byref(needed)):
                tag = re.sub(r"[^A-Za-z0-9_.-]+", "_", buf.value).strip("_")
                if tag:
                    return tag
    except Exception:
        pass
    return "Default"


def run_gui(start_hidden: bool = False):
    _mutex = None
    _wake_evt = None
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateMutexW.restype = ctypes.c_void_p
    k32.CreateEventW.restype = ctypes.c_void_p
    k32.SetEvent.argtypes = [ctypes.c_void_p]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    is_single = not os.environ.get("PANEL_PAGE")
    if is_single:
        dtag = _desktop_tag()
        mutex_name = f"Local\\GuardlineRP_{dtag}"
        wake_name = f"Local\\GuardlineRPWake_{dtag}"
        _mutex = k32.CreateMutexW(None, False, mutex_name)
        already = ctypes.get_last_error() == 183
        _wake_evt = k32.CreateEventW(None, False, False, wake_name)
        if already:
            if start_hidden:
                if _wake_evt:
                    k32.CloseHandle(ctypes.c_void_p(_wake_evt))
                if _mutex:
                    k32.CloseHandle(ctypes.c_void_p(_mutex))
                return
            if _wake_evt:
                k32.SetEvent(ctypes.c_void_p(_wake_evt))
            u32 = ctypes.windll.user32
            u32.FindWindowW.restype = ctypes.c_void_p
            shown = False
            for _ in range(16):
                existing = (
                    u32.FindWindowW(None, "Guardline Status")
                    or u32.FindWindowW(None, "TR3000 面板")
                    or u32.FindWindowW(None, "路由器面板")
                )
                if existing:
                    if u32.IsIconic(ctypes.c_void_p(existing)):
                        u32.ShowWindow(ctypes.c_void_p(existing), 9)
                    if u32.IsWindowVisible(ctypes.c_void_p(existing)):
                        u32.SetForegroundWindow(ctypes.c_void_p(existing))
                        shown = True
                        break
                time.sleep(0.05)
            if _wake_evt:
                k32.CloseHandle(ctypes.c_void_p(_wake_evt))
                _wake_evt = None
            if _mutex:
                k32.CloseHandle(ctypes.c_void_p(_mutex))
                _mutex = None
            if shown:
                return
            # No visible window appeared after wake signal — clean stale zombie processes and self-heal.
            try:
                subprocess.run(
                    ["taskkill", "/F", "/FI", f"PID ne {os.getpid()}", "/IM", "RouterPanel.exe"],
                    capture_output=True,
                    creationflags=0x08000000,
                    timeout=5,
                )
            except Exception:
                pass
            time.sleep(0.3)
            _mutex = k32.CreateMutexW(None, False, mutex_name)
            _wake_evt = k32.CreateEventW(None, False, False, wake_name)
    if not ensure_webview2_runtime():
        if _wake_evt:
            k32.CloseHandle(ctypes.c_void_p(_wake_evt))
        if _mutex:
            k32.CloseHandle(ctypes.c_void_p(_mutex))
        return
    import webview
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Guardline.RouterPanel.v5")
    except Exception:
        pass
    backend = Backend()
    backend.start()
    api = Api(backend)
    fast_srv, fast_url, fast_token = start_local_fast_server(backend, api)
    html, bg = build_ui_html(backend._cfg, fast_url=fast_url, fast_token=fast_token)
    init_w, init_h = 1380, 868
    try:
        scr = webview.screens[0] if getattr(webview, "screens", None) else None
        if scr and scr.width and scr.height:
            init_w = max(1120, min(1420, int(scr.width * 0.84)))
            init_h = max(720, min(888, int(scr.height * 0.84)))
    except Exception:
        pass
    win = webview.create_window(
        "Guardline Status",
        html=html,
        js_api=api,
        width=init_w,
        height=init_h,
        min_size=(1000, 650),
        frameless=True,
        easy_drag=False,
        shadow=True,
        background_color=bg,
        on_top=bool(backend._cfg.get("topmost")),
        text_select=True,
    )
    api._win = win
    _bind_splashless_reveal(win, api=api, start_hidden=start_hidden)
    if is_single:
        win.events.shown += lambda: _setup_tray(win, api)

    stop_wake = threading.Event()
    if is_single and _wake_evt:
        def _wake_loop():
            while not stop_wake.is_set():
                if k32.WaitForSingleObject(ctypes.c_void_p(_wake_evt), 400) == 0:
                    if stop_wake.is_set():
                        break
                    api.restore_from_tray()
        threading.Thread(target=_wake_loop, daemon=True).start()

    try:
        webview.start(debug=bool(os.environ.get("PANEL_DEBUG")), icon=str(ICON) if ICON.exists() else None)
    finally:
        stop_wake.set()
        try:
            fast_srv.shutdown()
        except Exception:
            pass
        api._cleanup_tray()
        backend.stop()
        if _wake_evt:
            try:
                k32.CloseHandle(ctypes.c_void_p(_wake_evt))
            except Exception:
                pass
        if _mutex:
            try:
                k32.CloseHandle(ctypes.c_void_p(_mutex))
            except Exception:
                pass


# ================================================================== 命令行自检
def cli_check():
    print("探测局域网网关:", detect_gateways())
    b = Backend()
    if not b.start():
        sys.exit("未登录：请先打开面板登录")
    for _ in range(80):
        if b.snapshot().get("router"):
            break
        time.sleep(0.25)
    time.sleep(2.5)
    snap = b.snapshot()
    scan = b.scan_wifi()
    b.stop()
    print("状态:", snap["status"], snap.get("user"), "@", snap.get("host"), snap.get("build_error", ""))
    print("无线桥接状态:", snap.get("bridge"))
    print("扫描到热点数:", len(scan.get("networks", [])), "样例:", scan.get("networks", [])[:4])


if __name__ == "__main__":
    if sys.stderr is None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        sys.stdout = sys.stderr = open(APP_DIR / "panel.log", "a", encoding="utf-8", buffering=1)
    if len(sys.argv) >= 2 and sys.argv[1] == "--check":
        cli_check()
    else:
        run_gui(start_hidden=("--autostart" in sys.argv))

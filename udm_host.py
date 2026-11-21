"""
udm-host: Native Messaging host for Unlimited Download Manager.
The browser starts this program and talks to it over stdin/stdout (4-byte length + JSON).
It passes the requests to the running UDM (starting UDM if it is closed).
Only the Python standard library is used. Never print() to stdout: it is the protocol channel.
"""
import json
import os
import struct
import subprocess
import sys
import time
import urllib.request

HOME = os.path.join(os.path.expanduser("~"), ".udm")
CFG_FILE = os.path.join(HOME, "config.json")
LOG_FILE = os.path.join(HOME, "host.log")
DEFAULT_CHROMIUM_ID = "okdgjpnokajejolcokpongahgagnfogp"
FIREFOX_ID = "udm@unlimited.download.manager"
PATHS = {"add": "/add", "addmany": "/addmany", "detect": "/video/detect", "hello": "/ext/hello",
         "formats": "/video/formats", "get": "/video/get"}


def log(msg):
    try:
        os.makedirs(HOME, exist_ok=True)
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 200_000:
            os.remove(LOG_FILE)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + str(msg) + "\n")
    except Exception:
        pass


def read_cfg():
    try:
        with open(CFG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def read_msg():
    hdr = sys.stdin.buffer.read(4)
    if len(hdr) < 4:
        return None
    n = struct.unpack("<I", hdr)[0]
    if n > 8 * 1024 * 1024:
        return None
    return json.loads(sys.stdin.buffer.read(n).decode("utf-8"))


def send_msg(obj):
    data = json.dumps(obj).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(data)) + data)
    sys.stdout.buffer.flush()


def origin_allowed(cfg):
    """Defence in depth: the browser already enforces allowed_origins / allowed_extensions."""
    ids = {DEFAULT_CHROMIUM_ID} | set(cfg.get("ext_ids", []))
    args = " ".join(sys.argv[1:])
    if FIREFOX_ID in args:
        return True
    return any(f"chrome-extension://{i}/" in args for i in ids) or len(sys.argv) < 2   # started by hand


def call(cfg, method, path, body=None, timeout=10):
    base = f"http://127.0.0.1:{cfg.get('server_port', 6800)}"
    headers = {"X-UDM-Token": cfg.get("token", ""), "Content-Type": "application/json"}
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {"raw": raw.decode("utf-8", "replace")}


def app_alive(cfg):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{cfg.get('server_port', 6800)}/ping", timeout=1.5) as r:
            return r.read() == b"UDM"
    except Exception:
        return False


def ensure_app(cfg):
    if app_alive(cfg):
        return True
    exe = cfg.get("app_exe") or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.executable))), "UDM.exe")
    if not os.path.exists(exe):
        return False
    try:
        flags = (0x00000008 | 0x08000000) if os.name == "nt" else 0       # DETACHED_PROCESS | CREATE_NO_WINDOW
        subprocess.Popen([exe, "--minimized"], creationflags=flags, close_fds=True)
    except Exception as e:
        log(f"cannot start UDM: {e}")
        return False
    for _ in range(40):
        time.sleep(0.3)
        if app_alive(cfg):
            return True
    return False


def handle(cfg, msg):
    t, payload = msg.get("type"), msg.get("payload") or {}
    if t == "ping":
        return {"ok": True, "data": {"host": "udm-host", "app": app_alive(cfg)}}
    if not ensure_app(cfg):
        return {"ok": False, "err": "UDM is not running and could not be started"}
    if t == "rules":
        return {"ok": True, "data": call(cfg, "GET", "/rules?token=" + cfg.get("token", ""))}
    if t == "show":
        return {"ok": True, "data": call(cfg, "GET", "/show")}
    if t in PATHS:
        if t == "hello":
            payload["via"] = "native"
        payload["token"] = cfg.get("token", "")
        return {"ok": True, "data": call(cfg, "POST", PATHS[t], payload, timeout=170 if t == "formats" else 20)}
    return {"ok": False, "err": "unknown message type"}


def hide_console():
    if os.name == "nt":
        try:
            import ctypes
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)
        except Exception:
            pass


def main():
    hide_console()
    if os.name == "nt":
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    cfg = read_cfg()
    if not origin_allowed(cfg):
        log("rejected origin: " + " ".join(sys.argv[1:]))
        return
    while True:
        try:
            msg = read_msg()
        except Exception as e:
            log(f"bad message: {e}")
            return
        if msg is None:
            return
        cfg = read_cfg()                      # token / port may change while the browser stays open
        try:
            res = handle(cfg, msg)
        except Exception as e:
            log(f"error handling {msg.get('type')}: {e}")
            res = {"ok": False, "err": str(e)[:200]}
        res["id"] = msg.get("id")
        send_msg(res)


if __name__ == "__main__":
    main()

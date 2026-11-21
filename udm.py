#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unlimited Download Manager (UDM)
A multi-connection download manager for Windows (64-bit) written in pure
Python 3.8+ (standard library only; optional: pystray + Pillow for tray icon).
"""
import os, re, sys, io, json, time, uuid, shutil, fnmatch, base64, secrets, threading, queue, tempfile
import subprocess, zipfile, ftplib, http.cookiejar, html.parser, datetime, argparse, hashlib, email.utils
import urllib.request, urllib.parse, urllib.error
import http.server, http.client, socketserver
import ssl, socket, random, collections, types

try:
    import winreg
except ImportError:
    winreg = None
try:
    import winsound
except ImportError:
    winsound = None

APP_NAME = "Unlimited Download Manager"
APP_VER = "1.3"
IS_WIN = sys.platform == "win32"
APP_DIR = os.path.join(os.path.expanduser("~"), ".udm")
CFG_FILE = os.path.join(APP_DIR, "config.json")
STATE_FILE = os.path.join(APP_DIR, "state.json")
DEFAULT_DIR = os.path.join(os.path.expanduser("~"), "Downloads")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
CHUNK = 64 * 1024
MIN_SPLIT = 512 * 1024
UI_Q = queue.Queue()          # actions for the GUI thread (from server / tray / CLI)

# ------------------------------------------------------------------ config
DEFAULT_CATS = {
    "Uncategorized": {"exts": [], "sites": [], "folder": ""},
    "Musics": {"exts": "mp3 wav flac aac ogg m4a wma opus".split(), "sites": [], "folder": ""},
    "Compressed": {"exts": "zip rar 7z gz tar bz2 xz iso cab tgz".split(), "sites": [], "folder": ""},
    "Documents": {"exts": "pdf doc docx xls xlsx ppt pptx txt epub rtf csv odt".split(), "sites": [], "folder": ""},
    "Programs": {"exts": "exe msi dmg deb bat msix appx".split(), "sites": [], "folder": ""},
    "APKs": {"exts": ["apk", "xapk", "aab"], "sites": [], "folder": ""},
    "Videos": {"exts": "mp4 mkv avi mov wmv flv webm m4v mpg mpeg ts 3gp".split(), "sites": [], "folder": ""},
    "Images": {"exts": "jpg jpeg png gif bmp webp svg tif tiff ico".split(), "sites": [], "folder": ""},
}
ALL_COLS = [("name", "File name", 260), ("size", "Size", 80), ("done", "Downloaded", 90),
            ("pct", "Progress", 70), ("status", "Status", 100), ("speed", "Speed", 90),
            ("avg", "Avg speed", 80), ("eta", "Time left", 70), ("resume", "Resume", 60),
            ("conn", "Conn.", 50), ("cat", "Category", 90), ("queue", "Queue", 90),
            ("desc", "Description", 160), ("added", "Date added", 130), ("last", "Last try", 130)]
DEFAULT_CFG = {
    "language": "en", "theme": "dark", "palette": "default", "text_size": 100,
    "max_parallel": 0, "dup_action": "ask", "server_date": True, "open_after": False, "limit_saved": 500,
    "connections": 32, "conn_preset": "high", "timeout": 30, "retries": 6, "queue_parallel": 1,
    "speed_mode": "auto",            # auto = adaptive number of connections, manual = fixed number
    "host_max_conn": 32,             # safety: max simultaneous connections UDM opens to one website (0 = no limit)
    "write_buffer_kb": 1024,         # disk write buffer per connection
    "keepalive": True,               # reuse connections for many range requests
    "ssl_fallback": True,            # servers with an incomplete certificate chain (browsers cope, Python does not): still download
    "popup_dialog": True,            # small download window when a link is captured from the browser
    "speed_limit_kb": 0, "quota_mb": 0, "quota_period": "hour",
    "temp_dir": "", "user_agent": UA, "ignore_mtime": False, "ftp_passive": True,
    "server_limits": "", "proxy_mode": "none",
    "proxy_http": "", "proxy_https": "", "proxy_ftp": "",
    "proxy_user": "", "proxy_pass": "", "proxy_exclude": "localhost;127.0.0.1", "proxy_fallback": True,
    "clipboard_monitor": True,
    "capture_large_mb": 5,           # also capture any file bigger than this, whatever its type (0 = off)
    "capture_types": "zip rar 7z gz tar iso exe msi apk dmg deb pdf doc docx xls xlsx ppt pptx "
                     "mp3 wav flac aac m4a mp4 mkv avi mov wmv flv webm mpg mpeg",
    "excluded_types": "", "excluded_sites": "", "url_exceptions": "", "capture_enabled": True,
    "silent": False, "show_progress": True, "minimized_progress": False, "notify": True,
    "sounds": True, "sound_done": "", "sound_error": "", "sound_qstart": "", "sound_qstop": "", "confirm_delete": True,
    "confirm_stop": True, "show_complete": False, "cat_folder_follow": False,
    "startup": False, "tray": True, "remember_dir": True,
    "auto_update_check": True, "last_update_check": 0,
    "av_enabled": False, "av_command": "", "av_args": '"{file}"',
    "categories": DEFAULT_CATS, "logins": [],        # [{"pattern","user","pass"}]
    "columns": ["name", "size", "pct", "status", "speed", "eta", "resume", "cat", "queue", "added"],
    "server_port": 6800, "token": "", "last_dir": {},
}
CFG = {}


# ------------------------------------------------------------------ secret protection
# Windows: DPAPI (bound to the current Windows user, no extra library).
# Other systems: Fernet from `cryptography` if installed, otherwise Base64 (obfuscation only).
def _dpapi(data, protect):
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    fn.argtypes = [ctypes.POINTER(BLOB), ctypes.c_void_p, ctypes.POINTER(BLOB), ctypes.c_void_p,
                   ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(BLOB)]
    fn.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    buf = ctypes.create_string_buffer(data, len(data))
    src, out = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), BLOB()
    if not fn(ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("DPAPI failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def _fernet():
    from cryptography.fernet import Fernet
    kf = os.path.join(APP_DIR, "secret.key")
    if not os.path.exists(kf):
        os.makedirs(APP_DIR, exist_ok=True)
        with open(kf, "wb") as f:
            f.write(Fernet.generate_key())
        try:
            os.chmod(kf, 0o600)
        except OSError:
            pass
    with open(kf, "rb") as f:
        return Fernet(f.read())


def protect(text):
    if not text or not isinstance(text, str) or text.startswith(("dpapi:", "fernet:", "b64:")):
        return text
    raw = text.encode("utf-8")
    if IS_WIN:
        try:
            return "dpapi:" + base64.b64encode(_dpapi(raw, True)).decode()
        except Exception:
            pass
    try:
        return "fernet:" + _fernet().encrypt(raw).decode()
    except Exception:
        return "b64:" + base64.b64encode(raw).decode()


def unprotect(text):
    if not isinstance(text, str):
        return text
    try:
        if text.startswith("dpapi:"):
            return _dpapi(base64.b64decode(text[6:]), False).decode("utf-8")
        if text.startswith("fernet:"):
            return _fernet().decrypt(text[7:].encode()).decode("utf-8")
        if text.startswith("b64:"):
            return base64.b64decode(text[4:]).decode("utf-8")
    except Exception:
        return ""
    return text            # legacy plain text: re-encrypted on the next save


def load_cfg():
    global CFG
    CFG = json.loads(json.dumps(DEFAULT_CFG))
    try:
        with open(CFG_FILE, "r", encoding="utf-8") as f:
            CFG.update(json.load(f))
    except (OSError, ValueError):
        pass
    if not CFG.get("token"):
        CFG["token"] = secrets.token_hex(12)
    if not CFG.get("categories"):
        CFG["categories"] = json.loads(json.dumps(DEFAULT_CATS))
    CFG["proxy_pass"] = unprotect(CFG.get("proxy_pass", ""))
    for lg in CFG.get("logins", []):
        lg["pass"] = unprotect(lg.get("pass", ""))
    if CFG.get("cfg_v", 1) < 2:                      # migrate settings of older versions
        if CFG.get("connections") == 8:
            CFG["connections"] = 32
        cats = CFG["categories"]
        if "General" in cats and "Uncategorized" not in cats:
            CFG["categories"] = {("Uncategorized" if k == "General" else k): v for k, v in cats.items()}
        if CFG.get("theme") not in ("dark", "light") or "cfg_v" not in CFG:
            CFG["theme"] = CFG["theme"] if CFG.get("theme") == "dark" else "dark"
        CFG["cfg_v"] = 2
    if CFG.get("cfg_v", 1) < 3:                      # connections are 32 by default now
        if CFG.get("connections") in (8, 16):
            CFG["connections"] = 32
        if CFG.get("host_max_conn") == 16:
            CFG["host_max_conn"] = 32
        CFG["cfg_v"] = 3
    if CFG.get("cfg_v", 1) < 4:                      # tray must stay on: closing keeps UDM running
        CFG["tray"] = True
        CFG["cfg_v"] = 4
    if CFG.get("cfg_v", 1) < 5:                      # IDM-style settings: derive the connection preset from the current connections
        CFG["conn_preset"] = {32: "high", 16: "medium", 8: "low", 4: "mobile"}.get(CFG.get("connections"), "custom")
        CFG["cfg_v"] = 5
    save_cfg()


def save_cfg():
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        tmp = CFG_FILE + ".tmp"
        data = json.loads(json.dumps(CFG))
        data["proxy_pass"] = protect(data.get("proxy_pass", ""))
        for lg in data.get("logins", []):
            lg["pass"] = protect(lg.get("pass", ""))
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, CFG_FILE)
    except OSError:
        pass


# ------------------------------------------------------------------ i18n
AR = {
    "Add URL": "إضافة رابط", "Batch": "تحميل دفعة", "Resume": "استكمال", "Stop": "إيقاف",
    "Stop All": "إيقاف الكل", "Delete": "حذف", "Delete Completed": "حذف المكتمل",
    "Options": "الخيارات", "Scheduler": "الجدولة", "Grabber": "تنزيل المواقع",
    "Start Queue": "تشغيل القائمة", "Stop Queue": "إيقاف القائمة", "Tasks": "المهام",
    "View": "عرض", "Help": "مساعدة", "Exit": "خروج", "Search": "بحث", "File name": "اسم الملف",
    "Size": "الحجم", "Downloaded": "تم تحميله", "Progress": "التقدم", "Status": "الحالة",
    "Speed": "السرعة", "Avg speed": "متوسط السرعة", "Time left": "الوقت المتبقي",
    "Conn.": "الاتصالات", "Category": "التصنيف", "Queue": "القائمة", "Description": "الوصف",
    "Date added": "تاريخ الإضافة", "Last try": "آخر محاولة", "All Downloads": "كل التحميلات",
    "Unfinished": "غير مكتملة", "Finished": "مكتملة", "Categories": "التصنيفات",
    "Queues": "القوائم", "Queued": "في الانتظار", "Downloading": "جاري التحميل",
    "Paused": "متوقف", "Pausing": "جاري الإيقاف", "Completed": "مكتمل", "Error": "خطأ",
    "Open": "فتح", "Open Folder": "فتح المجلد", "Properties": "خصائص", "Copy Link": "نسخ الرابط",
    "Copy Info": "نسخ المعلومات", "Move to queue": "نقل إلى قائمة", "Segments": "الأجزاء",
    "ZIP Preview": "معاينة ZIP", "Change Location": "تغيير المكان", "Download Now": "حمّل الآن",
    "Download Later": "حمّل لاحقاً", "Cancel": "إلغاء", "OK": "موافق", "Save": "حفظ",
    "Save to": "حفظ في", "Browse": "استعراض", "Connections": "الاتصالات", "Auto": "تلقائي",
    "Language": "اللغة", "Theme": "المظهر", "General": "عام", "Connection": "الاتصال",
    "Proxy": "بروكسي", "File types & sites": "الأنواع والمواقع", "Logins": "تسجيل الدخول",
    "Antivirus": "مضاد الفيروسات", "Sounds": "الأصوات", "Columns": "الأعمدة",
    "Speed limit (KB/s, 0 = unlimited)": "حد السرعة (كيلوبايت/ث، 0 = بلا حد)",
    "Yes": "نعم", "No": "لا", "Unlimited Download Manager": "Unlimited Download Manager",
    "Download complete": "اكتمل التحميل", "Done": "تم", "Remove": "إزالة", "New": "جديد",
    "Start time": "وقت البدء", "Stop time": "وقت الإيقاف", "Max parallel downloads": "أقصى عدد تحميلات متزامنة",
    "Run now": "تشغيل الآن", "Apply": "تطبيق", "Add": "إضافة", "Edit": "تعديل", "Close": "إغلاق",
    "Dark": "داكن", "Light": "فاتح", "Pause": "إيقاف مؤقت", "Name": "الاسم",
    "Copy browser extension...": "تصدير إضافة المتصفح...", "Quick start": "بدء سريع",
    "Delete download(s)?": "حذف التحميل؟", "Also delete files from disk?": "حذف الملفات من القرص أيضاً؟",
    "Restart the program to apply the language.": "أعد تشغيل البرنامج لتطبيق اللغة.",
    "About": "حول البرنامج", "Total speed": "السرعة الكلية", "Active": "نشط", "Items": "العناصر",
}
_LANG = "en"


def _(s):
    return AR.get(s, s) if _LANG == "ar" else s


# ------------------------------------------------------------------ helpers
def human_size(n):
    if n is None or n < 0:
        return "?"
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def human_time(s):
    if s is None or s < 0 or s > 8640000:
        return "-"
    s = int(s)
    h, r = divmod(s, 3600)
    m, sec = divmod(r, 60)
    return f"{h}:{m:02d}:{sec:02d}" if h else f"{m:02d}:{sec:02d}"


def fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "-"


def safe_name(name):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    return name or "download"


def unique_path(folder, name):
    base, ext = os.path.splitext(name)
    p = os.path.join(folder, name)
    i = 1
    while os.path.exists(p) or os.path.exists(p + ".part"):
        p = os.path.join(folder, f"{base} ({i}){ext}")
        i += 1
    return p


def split_list(s):
    return [x.strip().lower() for x in re.split(r"[;\n, ]+", s or "") if x.strip()]


def match_any(patterns, text):
    text = (text or "").lower()
    return any(fnmatch.fnmatch(text, p) for p in split_list(patterns))


def url_host(url):
    return (urllib.parse.urlparse(url).hostname or "").lower()


def url_ext(url_or_name):
    p = urllib.parse.urlparse(url_or_name).path if "://" in url_or_name else url_or_name
    return os.path.splitext(p)[1].lstrip(".").lower()


def filename_from_headers(headers, url):
    cd = headers.get("Content-Disposition", "") or ""
    m = re.search(r"filename\*\s*=\s*[^']*'[^']*'([^;]+)", cd, re.I)
    if m:
        return safe_name(urllib.parse.unquote(m.group(1).strip().strip('"')))
    m = re.search(r'filename\s*=\s*"?([^";]+)"?', cd, re.I)
    if m:
        return safe_name(urllib.parse.unquote(m.group(1).strip()))
    name = urllib.parse.unquote(os.path.basename(urllib.parse.urlparse(url).path))
    return safe_name(name) if name else "download"


def expand_pattern(s, cap=5000):
    """http://x/file[01-10].zip  or  [a-e]  -> list of urls"""
    m = re.search(r"\[(\d+)-(\d+)\]", s)
    if m:
        a, b = m.group(1), m.group(2)
        w = len(a) if a.startswith("0") else 0
        out = []
        for i in range(int(a), min(int(b), int(a) + cap) + 1):
            out += expand_pattern(s[:m.start()] + str(i).zfill(w) + s[m.end():], cap)
            if len(out) >= cap:
                break
        return out[:cap]
    m = re.search(r"\[([A-Za-z])-([A-Za-z])\]", s)
    if m:
        out = []
        for c in range(ord(m.group(1)), ord(m.group(2)) + 1):
            out += expand_pattern(s[:m.start()] + chr(c) + s[m.end():], cap)
        return out[:cap]
    return [s]


def categorize(url, filename=None):
    host = url_host(url)
    ext = url_ext(filename or url)
    cats = CFG["categories"]
    for name, c in cats.items():
        if c.get("sites") and any(fnmatch.fnmatch(host, p.lower()) for p in c["sites"]):
            return name
    for name, c in cats.items():
        if ext and ext in [e.lower() for e in c.get("exts", [])]:
            return name
    return "Uncategorized"


def category_folder(cat):
    c = CFG["categories"].get(cat, {})
    if c.get("folder"):
        return c["folder"]
    return DEFAULT_DIR if cat in ("General", "Uncategorized") else os.path.join(DEFAULT_DIR, cat)


def should_capture(url, filename=None):
    """Rules used by the browser integration."""
    if not CFG["capture_enabled"]:
        return False
    host = url_host(url)
    if match_any(CFG["excluded_sites"], host) or match_any(CFG["url_exceptions"], url):
        return False
    ext = url_ext(filename or url)
    if ext in split_list(CFG["excluded_types"]):
        return False
    return ext in split_list(CFG["capture_types"])


def server_limit(url):
    host = url_host(url)
    for line in (CFG.get("server_limits") or "").splitlines():
        if "=" in line:
            pat, n = line.rsplit("=", 1)
            if fnmatch.fnmatch(host, pat.strip().lower()) and n.strip().isdigit():
                return max(1, int(n))
    return 999


def hash_algo(hexstr):
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len((hexstr or "").strip()))


def file_hash(path, algo="sha256"):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def play_sound(kind):
    if not CFG["sounds"]:
        return
    key = {"done": "sound_done", "error": "sound_error",
           "qstart": "sound_qstart", "qstop": "sound_qstop"}.get(kind, "sound_error")
    path = CFG.get(key, "")
    try:
        if winsound:
            if path and os.path.exists(path):
                winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_ASYNC)
            else:
                winsound.MessageBeep(winsound.MB_OK if kind != "error" else winsound.MB_ICONHAND)
    except Exception:
        pass


def open_path(p):
    try:
        if IS_WIN:
            os.startfile(p)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", p])
        else:
            subprocess.Popen(["xdg-open", p])
    except Exception:
        pass


# ------------------------------------------------------------------ networking
COOKIES = http.cookiejar.CookieJar()


def proxy_for(url, task=None):
    mode = CFG["proxy_mode"]
    if mode == "none" and not (task and getattr(task, "proxy_fallback", False)):
        return None
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if mode == "system" or (task and getattr(task, "proxy_fallback", False)):
        p = urllib.request.getproxies().get(scheme)
    else:
        p = CFG.get("proxy_" + scheme, "")
    if not p:
        return None
    if match_any(CFG["proxy_exclude"], url_host(url)):
        return None
    return p if "://" in p else "http://" + p


def split_creds(url):
    u = urllib.parse.urlparse(url)
    if u.username:
        netloc = u.hostname + (f":{u.port}" if u.port else "")
        clean = urllib.parse.urlunparse(u._replace(netloc=netloc))
        return clean, (urllib.parse.unquote(u.username), urllib.parse.unquote(u.password or ""))
    return url, None


def find_login(url):
    host = url_host(url)
    for lg in CFG.get("logins", []):
        if fnmatch.fnmatch(host, lg.get("pattern", "").lower()):
            return lg.get("user", ""), lg.get("pass", "")
    return None


SSL_RELAXED = set()                  # hosts whose certificate chain is incomplete (we already had to relax them)
_CTX = {}


def ssl_ctx(relaxed=False):
    if relaxed not in _CTX:
        if relaxed:
            c = ssl.create_default_context()
            c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
        else:
            c = ssl.create_default_context()
        _CTX[relaxed] = c
    return _CTX[relaxed]


def is_cert_error(e):
    return isinstance(e, ssl.SSLCertVerificationError) or isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError)


def ssl_state(url):
    """secure = verified HTTPS, relaxed = HTTPS but the server's certificate chain is incomplete, insecure = plain HTTP."""
    if urllib.parse.urlparse(url).scheme.lower() != "https":
        return "insecure"
    return "relaxed" if url_host(url) in SSL_RELAXED else "secure"


def http_open(url, headers=None, timeout=None, task=None):
    url, cred = split_creds(url)
    h = {"User-Agent": CFG["user_agent"] or UA, "Accept": "*/*", "Accept-Encoding": "identity"}
    if task:
        if task.referer:
            h["Referer"] = task.referer
        if task.cookies:
            h["Cookie"] = task.cookies
        if task.user:
            cred = (task.user, task.pwd)
    cred = cred or find_login(url)
    if cred:
        h["Authorization"] = "Basic " + base64.b64encode(f"{cred[0]}:{cred[1]}".encode()).decode()
    p = proxy_for(url, task)
    if p and CFG["proxy_user"]:
        h["Proxy-Authorization"] = "Basic " + base64.b64encode(
            f"{CFG['proxy_user']}:{CFG['proxy_pass']}".encode()).decode()
    if headers:
        h.update(headers)
    host = url_host(url)

    def attempt(relaxed):
        handlers = [urllib.request.HTTPCookieProcessor(COOKIES),
                    urllib.request.ProxyHandler({urllib.parse.urlparse(url).scheme: p} if p else {}),
                    urllib.request.HTTPSHandler(context=ssl_ctx(relaxed))]
        return urllib.request.build_opener(*handlers).open(urllib.request.Request(url, headers=h), timeout=timeout or CFG["timeout"])
    try:
        return attempt(host in SSL_RELAXED)
    except (urllib.error.URLError, ssl.SSLError) as e:
        # "unable to get issuer certificate": the site sends an incomplete chain (browsers repair it, Python cannot).
        # Download anyway, except when a password is sent (never relax then).
        if is_cert_error(e) and CFG.get("ssl_fallback", True) and "Authorization" not in h and host not in SSL_RELAXED:
            SSL_RELAXED.add(host)
            return attempt(True)
        raise


class Limiter:
    """Global speed limiter (token bucket style)."""
    def __init__(self):
        self.lock = threading.Lock()
        self.t = time.time()

    def consume(self, n, stop=None, kb=None):
        rate = (kb if kb is not None else CFG["speed_limit_kb"]) * 1024
        if rate <= 0:
            return
        with self.lock:
            now = time.time()
            wait = max(0.0, self.t - now)
            self.t = max(self.t, now) + n / rate
        end = time.time() + wait
        while time.time() < end:
            if stop is not None and stop.is_set():
                return
            time.sleep(min(0.1, end - time.time()))


class Quota:
    def __init__(self):
        self.lock = threading.Lock()
        self.start = time.time()
        self.used = 0

    def _roll(self):
        period = 3600 if CFG["quota_period"] == "hour" else 86400
        if time.time() - self.start >= period:
            self.start, self.used = time.time(), 0

    def add(self, n):
        with self.lock:
            self._roll()
            self.used += n

    def exceeded(self):
        with self.lock:
            self._roll()
            lim = CFG["quota_mb"] * 1048576
            return lim > 0 and self.used >= lim


LIMITER = Limiter()
QUOTA = Quota()


# ------------------------------------------------------------------ fast engine helpers
class HostGate:
    """Safety net shared by ALL downloads: how many connections UDM may hold to one website at once.
    A website that answers 429/503 lowers its own limit for a while, so we never hammer it into a ban."""

    def __init__(self):
        self.lock = threading.Lock()
        self.n = {}
        self.learned = {}          # host -> (limit, time)

    def limit(self, host, override=999):
        lim = CFG.get("host_max_conn", 16) or 999
        if override < 999:         # the user wrote an explicit rule for this site (Options > per-server limits)
            lim = override
        got = self.learned.get(host)
        if got and time.time() - got[1] < 600:
            lim = min(lim, got[0])
        return max(1, lim)

    def acquire(self, host, override=999):
        with self.lock:
            if self.n.get(host, 0) >= self.limit(host, override):
                return False
            self.n[host] = self.n.get(host, 0) + 1
            return True

    def release(self, host):
        with self.lock:
            self.n[host] = max(0, self.n.get(host, 0) - 1)

    def learn(self, host, n):
        with self.lock:
            self.learned[host] = (max(1, int(n)), time.time())


HOSTS = HostGate()


class _Conn(http.client.HTTPConnection):
    def connect(self):
        super().connect()
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass


class _SConn(http.client.HTTPSConnection):
    def connect(self):
        super().connect()
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass


class HttpFail(IOError):
    def __init__(self, status, reason="", retry_after=0):
        super().__init__(f"HTTP {status} {reason}".strip())
        self.status, self.retry_after = status, retry_after
        self.fatal = status in (400, 401, 403, 404, 410, 451)      # retrying will not help


class DiskFail(IOError):
    fatal = True


class _Leave(Exception):
    """The controller wants fewer connections: this worker hands its segment back and ends."""


class Link:
    """One persistent HTTP(S) connection of one worker. It is reused for many range requests (Keep-Alive),
    so there is no new TCP/TLS handshake for every part. With a proxy we fall back to urllib."""

    def __init__(self, task):
        self.task, self.conn, self.key, self.used, self.last = task, None, None, 0, None

    def close(self):
        for obj in (self.conn, self.last):
            try:
                if obj is not None:
                    obj.close()
            except Exception:
                pass
        self.conn, self.last, self.key, self.used = None, None, None, 0

    def _headers(self, url, extra):
        t = self.task
        h = {"User-Agent": CFG["user_agent"] or UA, "Accept": "*/*", "Accept-Encoding": "identity"}
        if t.referer:
            h["Referer"] = t.referer
        if t.cookies:
            h["Cookie"] = t.cookies
        cred = (t.user, t.pwd) if t.user else None
        cred = cred or find_login(url)
        if cred:
            h["Authorization"] = "Basic " + base64.b64encode(f"{cred[0]}:{cred[1]}".encode()).decode()
        if not h.get("Cookie"):
            rq = urllib.request.Request(url)
            COOKIES.add_cookie_header(rq)
            if rq.has_header("Cookie"):
                h["Cookie"] = rq.get_header("Cookie")
        if not CFG.get("keepalive", True):
            h["Connection"] = "close"
        if extra:
            h.update(extra)
        return h

    def get(self, url, extra=None):
        if proxy_for(url, self.task):                                   # proxies: classic path (no pooling)
            self.close()
            self.last = http_open(url, extra, task=self.task)
            return self.last
        for _ in range(6):                                   # redirects
            clean, _c = split_creds(url)
            u = urllib.parse.urlsplit(clean)
            port = u.port or (443 if u.scheme == "https" else 80)
            key = (u.scheme, u.hostname, port)
            path = (u.path or "/") + ("?" + u.query if u.query else "")
            h = self._headers(clean, extra)
            r = None
            for _try in (0, 1):
                fresh = self.conn is None or self.key != key or self.used == 0
                if self.conn is None or self.key != key:
                    self.close()
                    if u.scheme == "https":
                        self.conn = _SConn(u.hostname, port, timeout=CFG["timeout"], context=ssl_ctx(u.hostname in SSL_RELAXED))
                    else:
                        self.conn = _Conn(u.hostname, port, timeout=CFG["timeout"])
                    self.key = key
                try:
                    self.conn.request("GET", path, headers=h)
                    r = self.conn.getresponse()
                    self.used += 1
                    break
                except ssl.SSLCertVerificationError:
                    self.close()
                    if CFG.get("ssl_fallback", True) and "Authorization" not in h and u.hostname not in SSL_RELAXED:
                        SSL_RELAXED.add(u.hostname)          # incomplete certificate chain: retry once, relaxed
                        continue
                    raise
                except (http.client.HTTPException, OSError):
                    self.close()
                    if fresh:                                # a brand new connection failed: real error
                        raise                                # (a reused one may just have been closed by the server)
            if r.status in (301, 302, 303, 307, 308) and r.getheader("Location"):
                url = urllib.parse.urljoin(clean, r.getheader("Location"))
                try:
                    r.read()
                except Exception:
                    self.close()
                continue
            return r
        raise IOError("Too many redirects")

    def release(self, r):
        """After a request: keep the connection when the response was read completely (or nearly)."""
        try:
            if r.isclosed():
                return
            left = r.length
            if self.conn is not None and left is not None and 0 < left <= 262144:
                r.read(left)                                  # drain a small rest, connection stays reusable
            else:
                self.close()
        except Exception:
            self.close()



class StopDL(Exception):
    pass


# ------------------------------------------------------------------ download task
PERSIST = ["id", "url", "real_url", "referer", "cookies", "user", "pwd", "folder", "category",
           "queue", "description", "nconn", "filename", "final_path", "part_file", "fixed_name",
           "overwrite", "size", "resumable", "mtime", "segments", "status", "error", "added",
           "finished", "last_try", "auto_cat", "auto_folder", "grab", "speed_limit_kb", "expect_hash", "hash_result", "post_action"]


class Task:
    def __init__(self, url, folder=None, nconn=None, tid=None):
        self.id = tid or uuid.uuid4().hex[:8]
        self.url = url
        self.real_url = None
        self.referer = self.cookies = self.user = self.pwd = ""
        self.folder = folder or DEFAULT_DIR
        self.category = "Uncategorized"
        self.queue = ""
        self.description = ""
        self.nconn = nconn or CFG["connections"]
        self.filename = self.final_path = self.part_file = self.fixed_name = None
        self.proxy_fallback = False           # this download already failed once: retry it via the system proxy
        self.overwrite = False
        self.size = None
        self.resumable = False
        self.mtime = ""
        self.segments = []
        self.status = "Queued"
        self.error = ""
        self.added = time.time()
        self.finished = 0
        self.last_try = 0
        self.auto_cat = True
        self.auto_folder = True
        self.grab = ""                       # grabber project id, if any
        self.speed_limit_kb = 0              # limit for this download only (0 = none)
        self.expect_hash = ""                # optional MD5 / SHA-1 / SHA-256 to verify after download
        self.hash_result = ""
        # runtime only
        self.stop_event = threading.Event()
        self.runner = None
        self.lock = threading.RLock()
        self.failed = False
        self.quota_paused = False
        self.nworkers = 0
        self.last_bytes = 0
        self.last_time = time.time()
        self.speed = 0.0
        self.start_time = time.time()
        self.start_bytes = 0
        self.dialog = None
        self.on_complete = None
        self.tlim = Limiter()
        self.post_action, self.hist = "", []  # per-download "after it finishes" action / speed samples for the small window
        self.target = 1                      # connections the controller wants right now
        self.active, self.leaving = 0, 0     # connections really running / about to leave
        self.ws_list = []                    # runtime state of the workers (live byte counters)
        self.soft_cap, self.last_pen, self.err_times = None, 0.0, []

    # ---- persistence
    def to_dict(self):
        d = {k: getattr(self, k) for k in PERSIST}
        d["segments"] = [{"start": g["start"], "end": g["end"], "pos": g["pos"]} for g in list(self.segments)]
        d["pwd"], d["cookies"] = protect(d["pwd"]), protect(d["cookies"])
        return d

    @classmethod
    def from_dict(cls, d):
        t = cls(d["url"], d.get("folder"), d.get("nconn"), d.get("id"))
        for k in PERSIST:
            if k in d and k != "id":
                setattr(t, k, d[k])
        t.pwd, t.cookies = unprotect(t.pwd), unprotect(t.cookies)
        if t.category == "General":
            t.category = "Uncategorized"
        for s in t.segments:
            s.pop("owned", None)
            s.pop("rpos", None)
        if t.status not in ("Completed", "Error", "Queued"):
            t.status = "Paused"
        t.last_bytes = t.downloaded
        return t

    # ---- info
    @property
    def downloaded(self):
        if self.status == "Completed" and self.size:
            return self.size
        return sum(max(0, s["pos"] - s["start"]) for s in self.segments)

    @property
    def live_bytes(self):
        """Bytes received so far, including what still sits in the write buffers (used for the real speed)."""
        if self.status == "Completed":
            return self.downloaded
        return self.downloaded + sum(w.buf for w in list(self.ws_list))

    @property
    def part_path(self):
        return self.part_file or ((self.final_path or "") + ".part")

    @property
    def avg_speed(self):
        if self.status != "Downloading":
            return 0
        dt = time.time() - self.start_time
        return (self.downloaded - self.start_bytes) / dt if dt > 1 else 0

    @staticmethod
    def seg_done(s):
        return s["end"] is not None and s["pos"] > s["end"]

    # ---- control
    def start(self):
        if self.runner and self.runner.is_alive():
            return False
        if self.status in ("Completed", "Downloading", "Pausing"):
            return False
        self.stop_event = threading.Event()
        self.failed = False
        self.error = ""
        self.status = "Downloading"
        self.runner = threading.Thread(target=self._run, daemon=True)
        self.runner.start()
        return True

    def pause(self):
        if self.status == "Downloading":
            self.status = "Pausing"
            self.stop_event.set()

    def join(self, timeout=10):
        if self.runner:
            self.runner.join(timeout)

    # ---- file location helpers
    def relocate(self, new_folder=None, new_name=None):
        """Move/rename the file (completed) or its target (not started / paused)."""
        if self.status in ("Downloading", "Pausing"):
            raise RuntimeError("Stop the download first")
        folder = new_folder or self.folder
        name = safe_name(new_name) if new_name else (self.filename or None)
        os.makedirs(folder, exist_ok=True)
        if self.status == "Completed" and self.final_path:
            if not name:
                name = os.path.basename(self.final_path)
            dest = os.path.join(folder, name)
            if os.path.abspath(dest) != os.path.abspath(self.final_path):
                if os.path.exists(dest):
                    dest = unique_path(folder, name)
                shutil.move(self.final_path, dest)
                self.final_path = dest
        elif self.final_path:
            name = name or os.path.basename(self.final_path)
            dest = os.path.join(folder, name)
            if not CFG["temp_dir"] and os.path.exists(self.part_path):
                os.replace(self.part_path, dest + ".part")
                self.part_file = None
            self.final_path = dest
        else:
            self.fixed_name = new_name and safe_name(new_name) or self.fixed_name
        self.folder = folder
        self.auto_folder = False
        if name:
            self.filename = name
        return self.final_path

    def _choose_path(self):
        if self.overwrite:
            path = os.path.join(self.folder, self.filename)
        else:
            path = unique_path(self.folder, self.filename)
        self.final_path = path
        self.filename = os.path.basename(path)       # shows the numbered name when the file already exists
        if CFG["temp_dir"]:
            os.makedirs(CFG["temp_dir"], exist_ok=True)
            self.part_file = os.path.join(CFG["temp_dir"], f"{self.id}_{os.path.basename(path)}.part")
        else:
            self.part_file = None

    def _apply_auto(self):
        if self.auto_cat:
            self.category = categorize(self.url, self.filename)
        if self.auto_folder:
            self.folder = category_folder(self.category)
            os.makedirs(self.folder, exist_ok=True)

    def _open(self, headers=None, url=None):
        return http_open(url or self.real_url or self.url, headers, task=self)

    # ---- probing / segments
    def _probe(self):
        try:
            r = self._open({"Range": "bytes=0-0"}, url=self.url)
        except urllib.error.HTTPError as e:
            if e.code == 416:        # empty file or range not satisfiable
                r = self._open(url=self.url)
            else:
                raise IOError(f"HTTP {e.code} {e.reason}")
        with r:
            cr = r.headers.get("Content-Range", "")
            if r.status == 206 and "/" in cr and cr.rsplit("/", 1)[-1].isdigit():
                size, res = int(cr.rsplit("/", 1)[-1]), True
            else:
                cl = r.headers.get("Content-Length")
                size, res = (int(cl) if cl and cl.isdigit() else None), False
            name = filename_from_headers(r.headers, r.geturl())
            mt = r.headers.get("Last-Modified", "") or r.headers.get("ETag", "")
            return size, res, name, mt, r.geturl()

    # ---- connections: how many, and how big are the first parts
    @staticmethod
    def _auto():
        return CFG.get("speed_mode", "auto") != "manual"

    def _conn_cap(self):
        return max(1, min(int(self.nconn or CFG["connections"]), server_limit(self.url)))

    def _initial_conns(self):
        if not (self.resumable and self.size):
            return 1
        cap = self._conn_cap()
        if self._auto():
            sz = self.size
            n = 1 if sz < 2 * MIN_SPLIT else 2 if sz < 16 << 20 else 4 if sz < 64 << 20 else 6 if sz < 256 << 20 else 8
        else:
            n = cap
        return max(1, min(n, cap, self.size // MIN_SPLIT or 1))

    def _build_segments(self):
        if self.resumable and self.size:
            n = self._initial_conns()
            chunk = self.size // n
            self.segments = []
            for i in range(n):
                s = i * chunk
                e = (i + 1) * chunk - 1 if i < n - 1 else self.size - 1
                self.segments.append({"start": s, "end": e, "pos": s})
        else:
            self.segments = [{"start": 0, "end": self.size - 1 if self.size else None, "pos": 0}]

    def _prealloc(self):
        os.makedirs(os.path.dirname(self.part_path) or ".", exist_ok=True)
        with open(self.part_path, "wb") as f:
            if self.resumable and self.size:
                f.truncate(self.size)

    # ---- main runner
    def _run(self):
        try:
            self.last_try = time.time()
            os.makedirs(self.folder, exist_ok=True)
            if urllib.parse.urlparse(self.url).scheme.lower() == "ftp":
                self._run_ftp()
                return
            fresh = not (self.final_path and self.segments)
            size, res, name, mt, real = self._probe()
            self.real_url = real
            if fresh:
                self.size, self.resumable, self.mtime = size, res, mt
                self.filename = self.fixed_name or name
                self._apply_auto()
                self._choose_path()
                self._build_segments()
                self._prealloc()
            else:
                changed = (size != self.size) or (not CFG["ignore_mtime"] and mt and self.mtime and mt != self.mtime)
                if changed or not self.resumable or not os.path.exists(self.part_path):
                    self.size, self.resumable, self.mtime = size, res, mt
                    self._build_segments()
                    self._prealloc()
            self.start_time, self.start_bytes = time.time(), self.downloaded
            self._manage()
            self._finish()
        except Exception as e:
            self.status, self.error = "Error", str(e)

    def _post(self):
        """Server date for the finished file, and the optional checksum check."""
        if CFG["server_date"] and self.mtime:
            try:
                ts = email.utils.parsedate_to_datetime(self.mtime).timestamp()
                os.utime(self.final_path, (ts, ts))
            except Exception:
                pass
        algo = hash_algo(self.expect_hash)
        if algo:
            got = file_hash(self.final_path, algo)
            if got.lower() != self.expect_hash.strip().lower():
                self.hash_result = f"MISMATCH ({algo}): {got}"
                return False
            self.hash_result = f"OK ({algo})"
        return True

    def _finish(self):
        if self.failed:
            self.status = "Error"
        elif self.stop_event.is_set():
            self.status = "Paused"
        elif all(self.seg_done(s) for s in self.segments):
            if self.size is None:
                self.size = sum(s["pos"] for s in self.segments)
            try:
                have = os.path.getsize(self.part_path)
            except OSError:
                have = -1
            if self.size and have != self.size:           # never hand out a file that is not byte-complete
                self.status, self.error = "Error", f"Size check failed ({have} of {self.size} bytes). Use Redownload."
                return
            if os.path.exists(self.final_path) and self.overwrite:
                os.remove(self.final_path)
            shutil.move(self.part_path, self.final_path)
            self.part_file = None
            if not self._post():
                self.status, self.error = "Error", "Checksum does not match: " + self.hash_result
                return
            self.status, self.finished, self.queue = "Completed", time.time(), ""
            if self.on_complete:
                self.on_complete(self)
        else:
            self.status, self.error = "Error", self.error or "Incomplete download"

    # ---- the controller: starts / stops connections while the download runs
    def _rate(self, samples, window):
        """Real throughput (bytes/s) over the last `window` seconds, measured from the bytes that arrived."""
        if len(samples) < 2:
            return 0.0
        t1, b1 = samples[-1]
        t0, b0 = next(((t, b) for t, b in samples if t >= t1 - window), samples[0])
        return max(0.0, (b1 - b0) / (t1 - t0)) if t1 > t0 else 0.0

    def _penalize(self, host, throttled=False):
        """The server (or the line) is struggling: use fewer connections for a while (Auto mode)."""
        if not self._auto():
            return
        with self.lock:
            now = time.time()
            self.err_times = [t for t in self.err_times if now - t < 12] + [now]
            if throttled or len(self.err_times) >= 3:
                cur = max(1, self.active - self.leaving)
                self.soft_cap = max(1, int(cur * 0.6)) if cur > 1 else 1
                self.target = min(self.target, self.soft_cap)
                self.last_pen, self.err_times = now, []
                if throttled:
                    HOSTS.learn(host, self.soft_cap)

    def _manage(self):
        stop, auto = self.stop_event, self._auto()
        cap = self._conn_cap() if (self.resumable and self.size) else 1
        host, override = url_host(self.real_url or self.url), server_limit(self.url)
        self.soft_cap, self.last_pen, self.err_times = None, 0.0, []
        self.target = max(1, self._initial_conns() if auto else cap)
        self.active = self.leaving = 0
        self.ws_list, threads = [], []
        samples = collections.deque()
        phase, best, best_n = "ramp", 0.0, self.target
        t_change = hold_t = time.time()
        while True:
            now = time.time()
            if stop.is_set() or all(self.seg_done(s) for s in self.segments):
                break
            samples.append((now, self.live_bytes))
            while samples and now - samples[0][0] > 8:
                samples.popleft()
            if self.soft_cap is not None and now - self.last_pen > 45:     # slowly give the connections back
                self.soft_cap += 1
                self.last_pen = now
                if self.soft_cap >= cap:
                    self.soft_cap = None
            eff = cap if self.soft_cap is None else max(1, min(cap, self.soft_cap))
            if auto and now - t_change >= 2.0 and self.active > 0 and self.resumable:
                rate = self._rate(samples, 1.6)
                rem = (self.size or 0) - self.live_bytes
                if phase == "ramp":
                    best_prev = best
                    if rate >= best * 1.07:                       # more connections = clearly more speed: go on
                        best, best_n = rate, self.target
                        if self.target < eff and rem > rate * 4 and rem > self.target * MIN_SPLIT * 2:
                            strong = best_prev > 0 and rate >= best_prev * 1.5     # clearly scaling: grow faster
                            self.target = min(eff, max(self.target + 1, int(self.target * (2 if strong else 1.5))))
                        else:
                            phase, hold_t = "hold", now
                    else:                                         # no gain: the line / server is full, go back
                        self.target, phase, hold_t = best_n, "hold", now
                    t_change = now
                elif now - hold_t > 30 and self.target < eff and rem > rate * 10 and self.soft_cap is None:
                    best, best_n = rate, self.target              # look again, conditions may have changed
                    self.target, phase, t_change = min(eff, self.target + 2), "ramp", now
            if auto:
                self.target = max(1, min(self.target, eff))
            with self.lock:
                want = self.target - (self.active - self.leaving)
            spawned = 0
            while want > 0 and spawned < 2 and self._has_work():   # open new connections 2 at a time, not all at once
                if not HOSTS.acquire(host, override):
                    break
                ws = types.SimpleNamespace(buf=0, got=False, leaving=False, host=host, mv=None)
                with self.lock:
                    self.active += 1
                    self.nworkers = self.active
                    self.ws_list.append(ws)
                th = threading.Thread(target=self._worker, args=(ws,), daemon=True)
                th.start()
                threads.append(th)
                want -= 1
                spawned += 1
            if self.active == 0 and not self._has_work() and not stop.is_set():
                break
            stop.wait(0.2)
        for th in threads:
            th.join()
        self.nworkers = 0

    # ---- segments
    def _has_work(self):
        with self.lock:
            for s in self.segments:
                if not s.get("owned") and not self.seg_done(s):
                    return True
            if not self.resumable:
                return False
            return any(s.get("owned") and s["end"] is not None and
                       s["end"] - max(s["pos"], s.get("rpos") or 0) + 1 >= 2 * MIN_SPLIT for s in self.segments)

    def _claim(self):
        with self.lock:
            for s in self.segments:
                if not s.get("owned") and not self.seg_done(s):
                    s["owned"] = True
                    return s
            if not self.resumable:
                return None
            best, bestrem = None, 0
            for s in self.segments:
                if s.get("owned") and s["end"] is not None:
                    rem = s["end"] - max(s["pos"], s.get("rpos") or 0) + 1
                    if rem > bestrem:
                        best, bestrem = s, rem
            if best and bestrem >= 2 * MIN_SPLIT:                # split the biggest remaining part in two
                mid = max(best["pos"], best.get("rpos") or 0) + bestrem // 2
                new = {"start": mid, "end": best["end"], "pos": mid, "owned": True}
                best["end"] = mid - 1
                self.segments.append(new)
                return new
        return None

    def _retire(self, ws):
        with self.lock:
            if self.active - self.leaving > self.target and not ws.leaving:
                self.leaving += 1
                ws.leaving = True
                return True
        return False

    def _leave(self, ws):
        with self.lock:
            self.active -= 1
            if ws.leaving:
                self.leaving -= 1
            self.nworkers = self.active
            if ws in self.ws_list:
                self.ws_list.remove(ws)
        HOSTS.release(ws.host)

    def _worker(self, ws):
        link, f = Link(self), None
        try:
            ws.mv = memoryview(bytearray(max(65536, int(CFG.get("write_buffer_kb", 1024)) * 1024)))
            while not self.stop_event.is_set() and not self.failed:
                if self._retire(ws):
                    break
                seg = self._claim()
                if seg is None:
                    break
                try:
                    if f is None:
                        f = open(self.part_path, "r+b", buffering=0)      # one file handle per connection: no lock
                    self._seg_loop(ws, link, f, seg)
                except _Leave:
                    break
                finally:
                    seg["owned"] = False
                    seg.pop("rpos", None)
        except Exception as e:
            if not self.stop_event.is_set():
                self.failed, self.error = True, str(e)
                self.stop_event.set()
        finally:
            link.close()
            if f:
                try:
                    f.close()
                except OSError:
                    pass
            self._leave(ws)

    def _seg_loop(self, ws, link, f, seg):
        """Download one segment. Only THIS segment is retried after an error, from the exact byte where it stopped."""
        stop, fails = self.stop_event, 0
        host = ws.host
        while not stop.is_set() and not self.failed and not self.seg_done(seg):
            ws.got = False
            try:
                self._seg_request(ws, link, f, seg)
                return
            except _Leave:
                raise
            except Exception as e:
                link.close()
                if CFG.get("proxy_fallback") and CFG["proxy_mode"] == "none" and not self.proxy_fallback:
                    self.proxy_fallback = True        # next attempt goes through the system proxy (IDM behaviour)
                if stop.is_set():
                    return
                fails = 1 if ws.got else fails + 1                   # progress during the attempt resets the counter
                limit = CFG["retries"]
                try:
                    qr = G.mgr.queues.get(self.queue or {}).get("retries") if getattr(G, "mgr", None) else 0
                    if qr:
                        limit = qr
                except Exception:
                    pass
                if fails > (2 if getattr(e, "fatal", False) else limit):
                    self.failed, self.error = True, str(e)
                    stop.set()
                    return
                throttled = isinstance(e, HttpFail) and e.status in (429, 503)
                self._penalize(host, throttled)
                wait = e.retry_after if throttled and e.retry_after else min(0.5 * 2 ** (fails - 1), 10)
                stop.wait(wait + random.random() * 0.5)

    def _block(self):
        return (8 << 20) if (CFG.get("keepalive", True) and not proxy_for(self.url, self)) else (1 << 60)

    def _check(self, r, pos):
        st = r.status
        if st in (429, 503):
            try:
                ra = int(r.getheader("Retry-After") or 0)
            except ValueError:
                ra = 0
            raise HttpFail(st, r.reason, min(ra, 120))
        if st < 200 or st >= 300:
            raise HttpFail(st, r.reason)
        if self.resumable:
            if st != 206:
                raise IOError("Server ignored the range request")
            m = re.match(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", r.getheader("Content-Range") or "")
            if not m or int(m.group(1)) != pos:
                raise IOError("Server returned the wrong part of the file")
            if m.group(3) != "*" and self.size and int(m.group(3)) != self.size:
                raise IOError("The file changed on the server (size differs). Use Redownload.")

    def _seg_request(self, ws, link, f, seg):
        stop = self.stop_event
        blk = self._block()
        while not stop.is_set() and not self.seg_done(seg):
            if self._retire(ws):
                raise _Leave()
            if not self.resumable and seg["pos"] != seg["start"]:
                seg["pos"] = seg["start"]                            # no range support: a retry must start again
            pos, end = seg["pos"], seg["end"]
            if self.resumable and end is not None:
                rend = min(end, pos + blk - 1)
                hdr = {"Range": f"bytes={pos}-{rend}"}
            else:
                rend, hdr = end, None
            r = link.get(self.real_url or self.url, hdr)
            try:
                self._check(r, pos)
                self._pump(ws, r, f, seg)
                if stop.is_set():
                    return
                if seg["end"] is None:
                    seg["end"] = seg["pos"] - 1                      # unknown size: the stream has ended
                elif not self.seg_done(seg) and (rend is None or seg["pos"] <= rend):
                    raise IOError("Connection closed early")
            finally:
                link.release(r)

    def _pump(self, ws, r, f, seg):
        """Read from the socket into a big buffer, write it to the disk in large blocks (one seek + one write)."""
        stop, mv = self.stop_event, ws.mv
        st = {"b": seg["pos"], "n": 0}                               # file offset of the buffer / bytes in it

        def flush():
            n, b = st["n"], st["b"]
            if not n:
                return
            end = seg["end"]
            if end is not None:
                n = max(0, min(n, end - b + 1))                      # bytes past a split point belong to another part
            try:
                if n:
                    f.seek(b)
                    off = 0
                    while off < n:
                        off += f.write(mv[off:n])
            except OSError as e:
                raise DiskFail(f"Disk write failed: {e}")
            st["b"], st["n"], ws.buf = b + n, 0, 0
            seg["pos"] = st["b"]                                     # persisted position: only moves after a real write
        try:
            while not stop.is_set():
                end, have = seg["end"], st["n"]
                room = len(mv) - have
                if end is not None:
                    need = end - (st["b"] + have) + 1
                    if need <= 0:
                        break
                    room = min(room, need)
                chunk = r.read1(min(room, 262144))
                if not chunk:
                    break
                n = len(chunk)
                mv[have:have + n] = chunk
                st["n"] = have + n
                ws.buf, ws.got = st["n"], True
                seg["rpos"] = st["b"] + st["n"]
                LIMITER.consume(n, stop)
                if self.speed_limit_kb:
                    self.tlim.consume(n, stop, self.speed_limit_kb)
                QUOTA.add(n)
                if st["n"] >= len(mv):
                    flush()
        finally:
            flush()                                                  # keep every good byte, even after an error

    # ---- FTP
    def _run_ftp(self):
        u = urllib.parse.urlparse(self.url)
        user = urllib.parse.unquote(u.username) if u.username else (self.user or "anonymous")
        pwd = urllib.parse.unquote(u.password) if u.password else (self.pwd or "anonymous@")
        path = urllib.parse.unquote(u.path)
        ftp = ftplib.FTP()
        try:
            ftp.connect(u.hostname, u.port or 21, timeout=CFG["timeout"])
            ftp.login(user, pwd)
            ftp.set_pasv(bool(CFG["ftp_passive"]))
            ftp.voidcmd("TYPE I")
            if not (self.final_path and self.segments):
                try:
                    size = ftp.size(path)
                except Exception:
                    size = None
                self.size, self.resumable = size, True
                self.filename = self.fixed_name or safe_name(os.path.basename(path) or "download")
                self._apply_auto()
                self._choose_path()
                self.segments = [{"start": 0, "end": size - 1 if size else None, "pos": 0}]
                self._prealloc()
            seg = self.segments[0]
            self.start_time, self.start_bytes = time.time(), self.downloaded
            self.nworkers = 1

            def cb(data):
                if self.stop_event.is_set():
                    raise StopDL()
                LIMITER.consume(len(data), self.stop_event)
                if self.speed_limit_kb:
                    self.tlim.consume(len(data), self.stop_event, self.speed_limit_kb)
                f.write(data)
                seg["pos"] += len(data)
                QUOTA.add(len(data))

            with open(self.part_path, "r+b") as f:
                f.seek(seg["pos"])
                try:
                    ftp.retrbinary("RETR " + path, cb, CHUNK, rest=seg["pos"] or None)
                except ftplib.error_perm:
                    if seg["pos"] == 0:
                        raise
                    seg["pos"] = 0                     # server has no REST support
                    f.seek(0)
                    f.truncate(0)
                    ftp.retrbinary("RETR " + path, cb, CHUNK)
            seg["end"] = seg["pos"] - 1
            self._finish()
        except StopDL:
            self.status = "Paused"
        except Exception as e:
            self.status, self.error = "Error", str(e)
            if CFG.get("proxy_fallback") and CFG["proxy_mode"] == "none":
                self.proxy_fallback = True        # a retry goes through the system proxy (IDM behaviour)
        finally:
            self.nworkers = 0
            try:
                ftp.close()
            except Exception:
                pass


# ------------------------------------------------------------------ ZIP preview over HTTP ranges
class RangeFile(io.RawIOBase):
    BLOCK = 64 * 1024

    def __init__(self, url, size, task=None):
        self.url, self.size, self.pos, self.task = url, size, 0, task
        self.cache = {}

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else (self.pos + off if whence == 1 else self.size + off)
        return self.pos

    def _block(self, i):
        if i not in self.cache:
            a = i * self.BLOCK
            b = min(self.size - 1, a + self.BLOCK - 1)
            with http_open(self.url, {"Range": f"bytes={a}-{b}"}, task=self.task) as r:
                self.cache[i] = r.read()
        return self.cache[i]

    def read(self, n=-1):
        if n < 0 or self.pos + n > self.size:
            n = self.size - self.pos
        out = b""
        while n > 0:
            i, o = divmod(self.pos, self.BLOCK)
            blk = self._block(i)[o:o + n]
            if not blk:
                break
            out += blk
            self.pos += len(blk)
            n -= len(blk)
        return out

    def readinto(self, b):
        d = self.read(len(b))
        b[:len(d)] = d
        return len(d)


def zip_listing(url, task=None):
    """Return [(name, size, compressed)] without downloading the whole archive."""
    with http_open(url, {"Range": "bytes=0-0"}, task=task) as r:
        cr = r.headers.get("Content-Range", "")
        if r.status != 206 or "/" not in cr:
            raise IOError("Server does not support range requests; preview is not possible.")
        size = int(cr.rsplit("/", 1)[-1])
    with zipfile.ZipFile(RangeFile(url, size, task)) as z:
        return [(i.filename, i.file_size, i.compress_size) for i in z.infolist()]


# ------------------------------------------------------------------ site grabber
class LinkParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        for k in ("href", "src", "data-src", "poster"):
            if d.get(k):
                self.links.append(d[k])
        if d.get("srcset"):
            for part in d["srcset"].split(","):
                if part.strip():
                    self.links.append(part.strip().split()[0])


GRAB_PRESETS = {"Images": "jpg jpeg png gif bmp webp svg", "Audio": "mp3 wav flac aac ogg m4a",
                "Video": "mp4 mkv avi mov wmv flv webm mpg mpeg",
                "Archives": "zip rar 7z gz tar iso", "Documents": "pdf doc docx xls xlsx ppt pptx txt",
                "All files": "*"}


class Grabber(threading.Thread):
    def __init__(self, mgr, proj):
        super().__init__(daemon=True)
        self.mgr, self.proj = mgr, proj
        self.stop_flag = False

    def run(self):
        p = self.proj
        p["status"] = "Running"
        p["last_run"] = time.time()
        start = p["url"]
        base_host = url_host(start)
        base_path = urllib.parse.urlparse(start).path.rsplit("/", 1)[0] + "/"
        types = split_list(p.get("types", "*"))
        filters = split_list(p.get("filters", ""))
        seen, files = set([start]), []
        todo = [(start, 0)]
        pages = 0
        while todo and not self.stop_flag and pages < 400 and len(files) < 5000:
            url, depth = todo.pop(0)
            try:
                with http_open(url, timeout=20) as r:
                    ctype = r.headers.get("Content-Type", "")
                    final = r.geturl()
                    if "html" not in ctype:
                        continue
                    body = r.read(3_000_000).decode(r.headers.get_content_charset() or "utf-8", "replace")
            except Exception:
                continue
            pages += 1
            lp = LinkParser()
            try:
                lp.feed(body)
            except Exception:
                continue
            for link in lp.links:
                absu = urllib.parse.urldefrag(urllib.parse.urljoin(final, link.strip()))[0]
                if not absu.lower().startswith(("http://", "https://")) or absu in seen:
                    continue
                if p.get("stay") and not urllib.parse.urlparse(absu).path.startswith(base_path):
                    continue
                seen.add(absu)
                host = url_host(absu)
                if filters:
                    if not any(fnmatch.fnmatch(host, f) or fnmatch.fnmatch(absu.lower(), f) for f in filters):
                        continue
                elif host != base_host:
                    continue
                ext = url_ext(absu)
                if ext and (types == ["*"] or ext in types):
                    files.append(absu)
                elif (not ext or ext in ("html", "htm", "php", "asp", "aspx")) and depth < p.get("depth", 2):
                    todo.append((absu, depth + 1))
        p["found"] = len(files)
        for u in files:
            if self.stop_flag:
                break
            self._queue_file(u, base_host)
        p["status"] = "Done" if not self.stop_flag else "Stopped"

    def _queue_file(self, url, base_host):
        p = self.proj
        u = urllib.parse.urlparse(url)
        rel = urllib.parse.unquote(u.path).lstrip("/") or "index.html"
        dest = os.path.join(p["folder"], safe_name(u.hostname or base_host),
                            *[safe_name(x) for x in rel.split("/")[:-1]])
        name = safe_name(rel.split("/")[-1])
        final = os.path.join(dest, name)
        if p.get("sync") and os.path.exists(final):
            try:
                with http_open(url, {"Range": "bytes=0-0"}, timeout=15) as r:
                    cr = r.headers.get("Content-Range", "")
                    size = int(cr.rsplit("/", 1)[-1]) if "/" in cr and cr.rsplit("/", 1)[-1].isdigit() \
                        else int(r.headers.get("Content-Length", -1))
                if size == os.path.getsize(final):
                    return
            except Exception:
                pass
        t = Task(url, dest)
        t.fixed_name, t.overwrite = name, True
        t.auto_folder = t.auto_cat = False
        t.category = categorize(url, name)
        t.queue = p.get("queue", "")
        t.grab = p["id"]
        self.mgr.add_task(t, start=not t.queue)


# ------------------------------------------------------------------ manager (queues, scheduler, persistence)
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def new_queue(name):
    return {"name": name, "start": "", "stop": "", "days": list(range(7)), "parallel": 1,
            "shutdown": False, "exit": False, "active": False, "after": "none", "date": "", "folder": "",
            "open_after": "", "start_on_startup": False, "retries": 0}


class Manager:
    def __init__(self):
        self.tasks = {}
        self.queues = {"Main download queue": new_queue("Main download queue"),
                       "Synchronization queue": new_queue("Synchronization queue")}
        self.grabbers = {}
        self.events = queue.Queue()
        self.lock = threading.RLock()
        self.quota_blocked = False
        self.gthreads = {}
        self._last = {}

    # ---- persistence
    def load(self):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
            for td in d.get("tasks", []):
                t = (VideoTask if td.get("kind") == "video" else Task).from_dict(td)
                t.on_complete = self._done
                self.tasks[t.id] = t
            for q in d.get("queues", []):
                q["active"] = False
                self.queues[q["name"]] = q
            for g in d.get("grabbers", []):
                g["status"] = "Idle"
                self.grabbers[g["id"]] = g
        except (OSError, ValueError, KeyError):
            pass

    def save(self):
        try:
            os.makedirs(APP_DIR, exist_ok=True)
            tmp = STATE_FILE + ".tmp"
            with self.lock:
                data = {"tasks": [t.to_dict() for t in self.tasks.values()],
                        "queues": list(self.queues.values()), "grabbers": list(self.grabbers.values())}
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, STATE_FILE)
        except OSError:
            pass

    # ---- tasks
    def add_task(self, t, start=True):
        t.on_complete = self._done
        with self.lock:
            self.tasks[t.id] = t
        if start:
            lim = CFG["max_parallel"]
            if lim and sum(1 for x in self.tasks.values() if x.status in ("Downloading", "Pausing")) >= lim:
                t.status = "Queued"          # waits for a free place (Options > downloads at the same time)
            else:
                t.start()
        else:
            t.status = "Queued"
        return t

    def add_url(self, url, folder=None, category="Uncategorized", nconn=None, queue="", start=True,
                referer="", cookies="", user="", pwd="", description="", filename=None,
                overwrite=False, speed_limit_kb=0, expect_hash=""):
        url = url.strip()
        qf = self.queues.get(queue or "", {}).get("folder")
        if qf and not folder:
            folder = qf
        t = Task(url, folder, nconn)
        t.overwrite, t.speed_limit_kb, t.expect_hash = overwrite, max(0, int(speed_limit_kb or 0)), (expect_hash or "").strip()
        t.referer, t.cookies, t.user, t.pwd, t.description = referer, cookies, user, pwd, description
        t.fixed_name = safe_name(filename) if filename else None
        if category != "Auto":                       # "Auto" = classify by file type; default = no category
            t.category = category if category in CFG["categories"] else "Uncategorized"
            t.auto_cat = False
        if folder:
            t.folder, t.auto_folder = folder, False
        elif not t.auto_cat:
            t.folder = category_folder(t.category)
        t.queue = queue or ""
        if t.queue:
            t.status = "Queued"
            return self.add_task(t, start=False)
        return self.add_task(t, start=start)

    def remove(self, t, delete_files=False):
        t.stop_event.set()
        threading.Thread(target=self._cleanup, args=(t, delete_files), daemon=True).start()
        with self.lock:
            self.tasks.pop(t.id, None)

    @staticmethod
    def _cleanup(t, delete_files):
        t.join(10)
        if t.status != "Completed":
            for p in (t.part_path,):
                try:
                    if p and os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass
        elif delete_files and t.final_path:
            try:
                os.remove(t.final_path)
            except OSError:
                pass

    def _done(self, t):
        if CFG["av_enabled"] and CFG["av_command"] and t.final_path:
            args = CFG["av_args"].replace("{file}", t.final_path)
            try:
                subprocess.Popen(f'"{CFG["av_command"]}" {args}', shell=True)
            except Exception:
                pass
        if CFG["open_after"] and t.final_path:
            open_path(t.final_path)
        pa = getattr(t, "post_action", "")
        if t.final_path and pa == "open" and not CFG["open_after"]:
            open_path(t.final_path)
        elif t.final_path and pa == "folder":
            open_path(os.path.dirname(t.final_path))
        self.events.put(("done", t))

    # ---- queues
    def start_queue(self, name):
        q = self.queues.get(name)
        if not q:
            return
        for t in list(self.tasks.values()):
            if t.queue == name and t.status in ("Paused", "Error", "Queued"):
                t.status = "Queued"
        q["active"] = True
        play_sound("qstart")

    def stop_queue(self, name):
        q = self.queues.get(name)
        if q:
            q["active"] = False
        for t in list(self.tasks.values()):
            if t.queue == name:
                t.pause()
        play_sound("qstop")

    def tick(self):
        now = datetime.datetime.now()
        hm, today = now.strftime("%H:%M"), now.strftime("%Y-%m-%d")
        # quota
        if QUOTA.exceeded():
            self.quota_blocked = True
            for t in list(self.tasks.values()):
                if t.status == "Downloading":
                    t.quota_paused = True
                    t.pause()
        elif self.quota_blocked:
            for t in list(self.tasks.values()):
                if t.quota_paused and t.start():
                    t.quota_paused = False
            if not any(t.quota_paused for t in self.tasks.values()):
                self.quota_blocked = False
        # direct downloads waiting for a free place
        lim = CFG["max_parallel"]
        if lim and not QUOTA.exceeded():
            run = sum(1 for t in self.tasks.values() if t.status in ("Downloading", "Pausing"))
            for t in [t for t in self.tasks.values() if t.status == "Queued" and not t.queue]:
                if run >= lim:
                    break
                if t.start():
                    run += 1
        # queues
        for q in list(self.queues.values()):
            name = q["name"]
            if now.weekday() in q.get("days", range(7)) and (not q.get("date") or q["date"] == today):
                if q.get("start") == hm and self._last.get(("s", name)) != today + hm:
                    self._last[("s", name)] = today + hm
                    self.start_queue(name)
            if q.get("stop") == hm and self._last.get(("e", name)) != today + hm:
                self._last[("e", name)] = today + hm
                self.stop_queue(name)
            if not q.get("active") or QUOTA.exceeded():
                continue
            members = [t for t in self.tasks.values() if t.queue == name]
            running = [t for t in members if t.status in ("Downloading", "Pausing")]
            waiting = [t for t in members if t.status == "Queued"]
            for t in waiting[:max(0, q.get("parallel", 1) - len(running))]:
                t.start()
            if not running and not waiting:
                q["active"] = False
                act = q.get("after") or ("shutdown" if q.get("shutdown") else "exit" if q.get("exit") else "none")
                if act != "none":
                    self.events.put(("after", act))
                if q.get("open_after") and os.path.exists(q["open_after"]):
                    open_path(q["open_after"])
        # grabbers
        for g in list(self.grabbers.values()):
            due = False
            if g.get("schedule") == hm and self._last.get(("g", g["id"])) != today + hm:
                self._last[("g", g["id"])] = today + hm
                due = True
            iv = g.get("interval_h", 0)
            if iv and time.time() - g.get("last_run", 0) >= iv * 3600 and g.get("status") != "Running":
                due = True
            if due and g.get("status") != "Running":
                self.run_grabber(g)

    def run_grabber(self, proj):
        if proj.get("status") == "Running":
            return
        g = Grabber(self, proj)
        self.gthreads[proj["id"]] = g
        g.start()




# ====================================================================== video support (yt-dlp + FFmpeg + Deno)
NOWIN = 0x08000000 if IS_WIN else 0
QL = {144: "144p", 240: "240p", 360: "360p", 480: "480p", 720: "720p (HD)", 1080: "1080p (Full HD)",
      1440: "1440p (2K)", 2160: "2160p (4K)", 4320: "4320p (8K)"}


def _exe(n):
    return n + (".exe" if IS_WIN else "")


def tools_user():
    return os.path.join(APP_DIR, "tools")


def tools_bundled():
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "tools")


def tool_path(name):
    for d in (tools_user(), tools_bundled()):
        p = os.path.join(d, _exe(name))
        if os.path.exists(p):
            return p
    return shutil.which(name)


def ensure_tools():
    """Copy the bundled yt-dlp to a writable folder so it can update itself in place."""
    src, dst = os.path.join(tools_bundled(), _exe("yt-dlp")), os.path.join(tools_user(), _exe("yt-dlp"))
    try:
        if os.path.exists(src) and (not os.path.exists(dst) or os.path.getmtime(src) > os.path.getmtime(dst)):
            os.makedirs(tools_user(), exist_ok=True)
            shutil.copy2(src, dst)
    except OSError:
        pass


def run_tool(args, timeout=120):
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, creationflags=NOWIN)


def update_ytdlp_verified():
    """Update yt-dlp from GitHub, verifying its SHA-256 against the official SHA2-256SUMS first.
    The old copy is kept if anything fails, so a bad download can never break video downloads."""
    import tempfile, urllib.request
    yt = tool_path("yt-dlp")
    if not yt:
        return "yt-dlp was not found"
    base = "https://github.com/yt-dlp/yt-dlp/releases/latest/download/"
    try:
        req = urllib.request.Request(base + "SHA2-256SUMS", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as r:
            sums = r.read().decode("utf-8", "replace")
        want = None
        for line in sums.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].lstrip("*") == "yt-dlp.exe":
                want = parts[0].lower()
                break
        if not want:
            return "Could not find the official checksum — update cancelled, your version is unchanged"
        d = tempfile.mkdtemp(prefix="udm-ytdlp-")
        new = os.path.join(d, "yt-dlp.exe")
        req = urllib.request.Request(base + "yt-dlp.exe", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=300) as r, open(new, "wb") as f:
            shutil.copyfileobj(r, f)
        if file_hash(new, "sha256").lower() != want:
            return "Checksum mismatch — the downloaded file is not the official yt-dlp, update cancelled"
        dst = os.path.join(tools_user(), _exe("yt-dlp"))
        os.makedirs(tools_user(), exist_ok=True)
        bak = dst + ".bak"
        if os.path.exists(dst):
            try:
                os.replace(dst, bak)
            except OSError:
                pass
        try:
            shutil.copy2(new, dst)
        except OSError as e:
            if os.path.exists(bak):
                try:
                    os.replace(bak, dst)
                except OSError:
                    pass
            return f"Could not replace yt-dlp: {e}"
        try:
            os.remove(bak)
        except OSError:
            pass
        shutil.rmtree(d, ignore_errors=True)
        ver = ""
        try:
            ver = run_tool([dst, "--version"], 20).stdout.strip()
        except Exception:
            pass
        return f"yt-dlp updated to {ver}" if ver else "yt-dlp updated"
    except Exception as e:
        return f"Update failed ({e}) — your version is unchanged"


def ytdlp_common(url, referer="", cookies="", playlist=False, task=None):
    a = ["--no-warnings", "--yes-playlist" if playlist else "--no-playlist", "--socket-timeout", "30"]
    ff, dn = tool_path("ffmpeg"), tool_path("deno")
    if ff:
        a += ["--ffmpeg-location", os.path.dirname(ff)]
    if dn:
        a += ["--js-runtimes", "deno:" + dn]
    px = proxy_for(url, task)
    if px:
        if CFG["proxy_user"] and "@" not in px:
            u = urllib.parse.urlparse(px)
            px = f"{u.scheme}://{urllib.parse.quote(CFG['proxy_user'])}:{urllib.parse.quote(CFG['proxy_pass'])}@{u.netloc}"
        a += ["--proxy", px]
    if referer:
        a += ["--referer", referer]
    if cookies:
        a += ["--add-header", "Cookie:" + cookies]
    return a


_VJ_CACHE = {}


def _video_json(url, referer="", cookies="", _depth=0):
    """yt-dlp -J for one video (cached for 10 minutes: the page button and the dialog ask for the same thing)."""
    hit = _VJ_CACHE.get(url)
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    yt = tool_path("yt-dlp")
    if not yt:
        raise RuntimeError("yt-dlp was not found")
    p = run_tool([yt, "-J"] + ytdlp_common(url, referer, cookies) + [url], 150)
    if p.returncode != 0 or not p.stdout.strip():
        err = [l for l in p.stderr.splitlines() if l.startswith("ERROR")]
        raise RuntimeError(err[-1] if err else (p.stderr.strip()[-300:] or "Could not analyze this link"))
    info = json.loads(p.stdout)
    if info.get("_type") == "playlist":               # playlists are not supported yet: use the first video
        ents = [e for e in info.get("entries") or [] if e]
        if not ents:
            raise RuntimeError("Empty playlist")
        info = ents[0]
        nxt = info.get("webpage_url") or info.get("url")
        if not info.get("formats") and nxt and _depth < 1:
            return _video_json(nxt, referer, cookies, 1)
    if len(_VJ_CACHE) > 20:
        _VJ_CACHE.clear()
    _VJ_CACHE[url] = (time.time(), info)
    return info


def _codec_name(vc):
    vc = (vc or "").lower()
    if vc.startswith(("avc1", "h264")):
        return "H.264"
    if vc.startswith(("vp09", "vp9")):
        return "VP9"
    if vc.startswith("av01"):
        return "AV1"
    if vc.startswith(("hev1", "hvc1", "h265")):
        return "H.265"
    return vc.split(".")[0].upper() or "?"


def _res_badge(h):
    return "8K" if h >= 4320 else "4K" if h >= 2160 else "2K" if h >= 1440 else "Full HD" if h >= 1080 else "HD" if h >= 720 else "SD"


def video_formats(url, referer="", cookies=""):
    """Every real choice (resolution / fps / codec / container) with its size, for the button on web pages."""
    info = _video_json(url, referer, cookies)
    dur = info.get("duration") or 0
    fm = info.get("formats") or []

    def fsize(f):
        sz = f.get("filesize") or f.get("filesize_approx")
        if not sz and f.get("tbr") and dur:
            sz = int(f["tbr"] * 1000 / 8 * dur)
        return sz or 0
    audio = [f for f in fm if f.get("acodec") not in (None, "none") and f.get("vcodec") in (None, "none")]

    def best_audio(ext):
        pool = [f for f in audio if f.get("ext") == ext] or audio
        return max(pool, key=lambda f: f.get("abr") or f.get("tbr") or 0) if pool else None
    ba = {"mp4": best_audio("m4a"), "webm": best_audio("webm")}
    groups = {}
    for f in fm:
        h, ext = f.get("height"), f.get("ext")
        if not h or f.get("vcodec") in (None, "none") or ext not in ("mp4", "webm"):
            continue
        fps = f.get("fps") or 30
        key = (h, 60 if fps > 30 else 30, _codec_name(f.get("vcodec")), ext)
        if key not in groups or (f.get("tbr") or 0) > (groups[key].get("tbr") or 0):
            groups[key] = f
    rows = []
    for (h, fb, codec, ext), f in groups.items():
        muxed = f.get("acodec") not in (None, "none")
        sz = fsize(f) + (0 if muxed else fsize(ba[ext]) if ba.get(ext) else 0)
        fps = int(round(f.get("fps") or 0))
        rows.append({"fid": str(f.get("format_id")), "h": h, "fps": fps, "label": f"{h}p" + (str(fps) if fps > 30 else ""),
                     "badge": _res_badge(h), "ext": ext, "codec": codec, "tbr": int(f.get("tbr") or 0), "size": sz or None,
                     "muxed": muxed, "fb": fb})
    rows.sort(key=lambda r: (-r["h"], -r["fb"], -(r["size"] or 0)))
    for r in rows:                                         # how much smaller is AV1 than the same picture in H.264 / VP9
        if r["codec"] == "AV1" and r["size"]:
            base = [x for x in rows if x["h"] == r["h"] and x["fb"] == r["fb"] and x["codec"] != "AV1" and x["size"]]
            if base:
                ref = max(base, key=lambda x: x["size"])["size"]
                pct = round((1 - r["size"] / ref) * 100)
                if pct >= 10:
                    r["saving"] = pct
    h264 = [r for r in rows if r["codec"] == "H.264" and r["ext"] == "mp4" and r["h"] <= 1080]
    rec = (max(h264, key=lambda r: (r["h"], r["fb"])) if h264 else rows[0]) if rows else None
    if rec:
        rec["rec"] = True
    if audio:
        a = best_audio("m4a") or audio[0]
        rows.append({"fid": "mp3", "h": 0, "fps": 0, "label": "MP3", "badge": "Audio", "ext": "mp3", "codec": "MP3",
                     "tbr": int(a.get("abr") or a.get("tbr") or 0), "size": fsize(a) or None, "muxed": True, "fb": 0})
    if not rows:
        raise RuntimeError("No downloadable video formats were found")
    return {"title": info.get("title") or url, "thumb": info.get("thumbnail"), "duration": dur, "rows": rows,
            "rec": rec["fid"] if rec else rows[0]["fid"]}


def video_info(url, referer="", cookies="", _depth=0):
    info = _video_json(url, referer, cookies, _depth)
    dur = info.get("duration") or 0
    fm = info.get("formats") or []

    def fsize(f):
        s = f.get("filesize") or f.get("filesize_approx")
        if not s and f.get("tbr") and dur:
            s = int(f["tbr"] * 1000 / 8 * dur)
        return s
    audio = [f for f in fm if f.get("acodec") not in (None, "none") and f.get("vcodec") == "none"]
    asz = max([fsize(f) or 0 for f in audio] or [0])
    best = {}
    for f in fm:
        h = f.get("height")
        if h and f.get("vcodec") != "none" and ((f.get("tbr") or 0) >= (best.get(h, {}).get("tbr") or 0)):
            best[h] = f
    q = []
    for h in sorted(best):
        f = best[h]
        sz = fsize(f)
        if sz and f.get("acodec") in (None, "none") and f.get("vcodec") not in (None, "none"):
            sz += asz
        q.append({"h": h, "label": QL.get(h, f"{h}p"), "fps": f.get("fps"), "size": sz, "ext": f.get("ext"),
                  "codec": _codec_name(f.get("vcodec")), "badge": _res_badge(h)})
    rec = None
    for x in q:                                          # recommended: best H.264 MP4 up to 1080p
        if x.get("codec") == "H.264" and (x.get("ext") or "").lower() == "mp4" and x["h"] <= 1080:
            if rec is None or x["h"] > rec["h"]:
                rec = x
    if rec is None and q:
        rec = q[-1]
    if rec:
        rec["rec"] = True
    return {"title": info.get("title") or url, "thumb": info.get("thumbnail"), "duration": dur,
            "uploader": info.get("uploader") or info.get("channel"), "site": info.get("extractor_key"),
            "qualities": q, "audio_size": asz or None}


def video_playlist(url, referer="", cookies=""):
    yt = tool_path("yt-dlp")
    if not yt:
        raise RuntimeError("yt-dlp was not found")
    p = run_tool([yt, "-J", "--flat-playlist"] + ytdlp_common(url, referer, cookies, True) + [url], 300)
    if p.returncode != 0 or not p.stdout.strip():
        err = [l for l in p.stderr.splitlines() if l.startswith("ERROR")]
        raise RuntimeError(err[-1] if err else (p.stderr.strip()[-300:] or "Could not read this playlist"))
    info, ents = json.loads(p.stdout), []
    for e in info.get("entries") or []:
        if not e:
            continue
        u = e.get("url") or e.get("webpage_url") or ""
        if u and not u.startswith("http") and e.get("id"):
            u = "https://www.youtube.com/watch?v=" + e["id"]
        if u:
            ents.append({"title": e.get("title") or u, "url": u, "duration": e.get("duration")})
    if not ents:
        raise RuntimeError("No videos found in this playlist")
    return {"title": info.get("title") or "Playlist", "entries": ents[:500]}


class VideoTask(Task):
    """A download handled by yt-dlp (+FFmpeg merge). Pause = stop the process, resume = run it again."""
    VEXTRA = ("vheight", "vcont", "vtitle", "vsize", "vbase", "vcur", "vfid", "vstart", "vend", "vexact", "vsubs", "vthumb", "vfmt", "vmux", "vout")

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.kind = "video"
        self.vheight, self.vcont, self.vtitle, self.vsize = 0, "mp4", "", None
        self.vbase, self.vcur, self.vfid, self.proc = 0, 0, "", None
        self.vstart, self.vend, self.vexact, self.vsubs = "", "", False, ""
        self.vthumb = ""
        self.vfmt, self.vmux = "", False          # exact yt-dlp format id chosen on the page (and: has audio inside)
        self.vout = ""                            # exact output name chosen in the download dialog (without extension)
        self.resumable = True

    def to_dict(self):
        d = super().to_dict()
        d["kind"] = "video"
        d.update({k: getattr(self, k) for k in self.VEXTRA})
        return d

    @classmethod
    def from_dict(cls, d):
        t = super().from_dict(d)
        for k in cls.VEXTRA:
            if k in d:
                setattr(t, k, d[k])
        t.last_bytes = t.downloaded
        return t

    @property
    def downloaded(self):
        if self.status == "Completed" and self.size:
            return self.size
        return self.vbase + self.vcur

    def _cmd(self):
        yt = tool_path("yt-dlp")
        if not yt:
            raise RuntimeError("yt-dlp was not found")
        audio = self.vcont == "mp3"
        sec = bool(self.vstart or self.vend)
        tmpl = (self.vout.replace("%", "%%") + ".%(ext)s") if getattr(self, "vout", "") \
            else "%(title).150B" + ("" if audio else " [%(height)sp]") + (" (part)" if sec else "") + ".%(ext)s"
        c = [yt, "-q", "--progress", "--newline", "--windows-filenames", "--no-mtime", "--retries", "10",
             "--fragment-retries", "10", "--concurrent-fragments", str(max(1, min(16, CFG["connections"]))),
             "--progress-template", "download:UDMP|%(progress.downloaded_bytes)s|%(progress.total_bytes)s|"
             "%(progress.total_bytes_estimate)s|%(progress.speed)s|%(progress.eta)s|%(progress.status)s|%(info.format_id)s",
             "--print", "after_move:UDMF|%(filepath)s", "--no-simulate", "-o", os.path.join(self.folder, tmpl)]
        lim = self.speed_limit_kb or CFG["speed_limit_kb"]
        if lim > 0:
            c += ["--limit-rate", f"{lim}K"]
        c += ytdlp_common(self.url, self.referer, self.cookies, task=self)
        hf = f"[height<={self.vheight}]" if self.vheight else ""
        if self.vfmt and not audio:                         # one exact choice: resolution + fps + codec + container
            fid = re.sub(r"[^A-Za-z0-9_.-]", "", self.vfmt)
            if self.vmux:
                sel = f"{fid}/b"
            else:
                aud = "ba[ext=m4a]" if self.vcont == "mp4" else "ba[ext=webm]"
                sel = f"{fid}+{aud}/{fid}+ba/b"
            c += ["-f", sel, "--merge-output-format", "mp4/mkv" if self.vcont == "mp4" else "webm/mkv"]
        elif audio:
            c += ["-f", "ba/b", "-x", "--audio-format", "mp3", "--audio-quality", "0"]
        elif self.vcont == "webm":
            c += ["-f", f"bv*{hf}[ext=webm]+ba[ext=webm]/b{hf}[ext=webm]/bv*{hf}+ba/b{hf}", "--merge-output-format", "webm/mkv"]
        else:
            c += ["-f", f"bv*{hf}[ext=mp4]+ba[ext=m4a]/b{hf}[ext=mp4]/bv*{hf}+ba/b{hf}", "--merge-output-format", "mp4/mkv"]
        if sec:                                          # "download a part of a video"
            c += ["--download-sections", f"*{self.vstart or '0'}-{self.vend or 'inf'}"]
            if self.vexact:
                c += ["--force-keyframes-at-cuts"]       # exact cut: the picture is made again
        if self.vsubs and not audio:
            c += ["--write-subs", "--write-auto-subs", "--sub-langs", self.vsubs, "--embed-subs"]
        return c + [self.url]

    def _guard(self):
        p = self.proc
        while p.poll() is None:
            if self.stop_event.wait(0.3):
                try:
                    if IS_WIN:
                        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True, creationflags=NOWIN)
                    else:
                        p.terminate()
                    p.wait(5)
                except Exception:
                    pass
                return

    def _progress(self, p):
        def n(x):
            try:
                return float(x)
            except (ValueError, TypeError):
                return None
        dl, tot, est = n(p[1]), n(p[2]), n(p[3])
        fid = p[7] if len(p) > 7 else ""
        if self.vfid and fid != self.vfid:                  # next stream (audio after video, ...)
            self.vbase += self.vcur
            self.vcur = 0
        self.vfid = fid
        if dl is not None:
            self.vcur = int(dl)
        t = tot or est
        if t:
            guess = int(self.vbase + t)
            self.size = self.vsize if self.vsize and self.vsize >= self.vbase + self.vcur else guess

    def _find_output(self):
        best, bt = None, 0
        for f in os.listdir(self.folder):
            p = os.path.join(self.folder, f)
            if f.endswith((".part", ".ytdl", ".temp")) or not os.path.isfile(p):
                continue
            if os.path.getmtime(p) >= self.last_try - 2 and os.path.getmtime(p) > bt:
                best, bt = p, os.path.getmtime(p)
        return best

    def _run(self):
        try:
            self.last_try = time.time()
            os.makedirs(self.folder, exist_ok=True)
            self.vbase, self.vcur, self.vfid, self.nworkers = 0, 0, "", 1
            self.proc = subprocess.Popen(self._cmd(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                         encoding="utf-8", errors="replace", creationflags=NOWIN, cwd=self.folder)
            threading.Thread(target=self._guard, daemon=True).start()
            err = ""
            for line in self.proc.stdout:
                line = line.strip()
                if line.startswith("UDMP|"):
                    self._progress(line.split("|"))
                elif line.startswith("UDMF|"):
                    self.final_path = line[5:]
                elif line.startswith("ERROR"):
                    err = line
            rc = self.proc.wait()
            if self.stop_event.is_set():
                self.status = "Paused"
                return
            if rc != 0:
                self.status, self.error = "Error", (err or f"yt-dlp exited with code {rc}")[:200]
                return
            if not (self.final_path and os.path.exists(self.final_path)):
                self.final_path = self._find_output()
            if not self.final_path:
                raise RuntimeError("Finished, but the output file was not found")
            self.filename, self.size = os.path.basename(self.final_path), os.path.getsize(self.final_path)
            self.status, self.finished, self.queue = "Completed", time.time(), ""
            if self.on_complete:
                self.on_complete(self)
        except Exception as e:
            self.status, self.error = "Error", str(e)
            if CFG.get("proxy_fallback") and CFG["proxy_mode"] == "none":
                self.proxy_fallback = True        # a retry goes through the system proxy (IDM behaviour)
        finally:
            self.nworkers = 0
# ------------------------------------------------------------------ local server (browser integration / CLI)
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code=200, body=b"", ctype="application/json", cors=True):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-UDM-Token")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self, qs=None, body=None):
        tok = self.headers.get("X-UDM-Token") or (qs or {}).get("token", [""])[0] or (body or {}).get("token", "")
        return secrets.compare_digest(str(tok), CFG["token"])

    def do_OPTIONS(self):
        self._send(204)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        if u.path == "/ping":
            return self._send(200, b"UDM", "text/plain")
        if u.path == "/ext/pair":            # only answers requests that really come from a browser extension
            if self.headers.get("Origin", "").startswith(("chrome-extension://", "moz-extension://")):
                return self._send(200, json.dumps({"token": CFG["token"]}).encode())
            return self._send(403, b'{"ok":false}')
        if u.path == "/show":
            ensure_ui()
            return self._send(200, b"ok", "text/plain")
        if not self._authed(qs):
            return self._send(403, b'{"ok":false}')
        if u.path == "/ui":
            return self._send(200, UI_HTML.replace("__TOKEN__", CFG["token"]).replace("__ICON__", "data:image/png;base64," + ICON_B64).replace("__WOLF__", WOLF_B64).encode("utf-8"),
                              "text/html; charset=utf-8", False)
        if u.path == "/popup":
            return self._send(200, POPUP_HTML.replace("__TOKEN__", CFG["token"]).replace("__PID__", re.sub(r"\W", "", (qs.get("pid") or [""])[0]))
                              .replace("__ICON__", "data:image/png;base64," + ICON_B64).replace("__APP__", APP_NAME).encode("utf-8"),
                              "text/html; charset=utf-8", False)
        if u.path == "/api/state":
            G.last_poll = time.time()
            return self._send(200, json.dumps(ui_state()).encode(), cors=False)
        if u.path == "/rules":
            rules = {"enabled": CFG["capture_enabled"], "types": split_list(CFG["capture_types"]),
                     "excluded_types": split_list(CFG["excluded_types"]),
                     "excluded_sites": split_list(CFG["excluded_sites"]),
                     "exceptions": split_list(CFG["url_exceptions"]),
                     "large_mb": CFG.get("capture_large_mb", 5), "lang": CFG["language"]}
            return self._send(200, json.dumps(rules).encode())
        if u.path == "/add" and qs.get("url"):
            capture_incoming({"urls": [qs["url"][0]]})
            return self._send(200, b'{"ok":true}')
        self._send(404, b'{"ok":false}')

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(min(n, 5_000_000)).decode("utf-8") or "{}")
        except Exception:
            return self._send(400, b'{"ok":false}')
        if not self._authed(body=body):
            return self._send(403, b'{"ok":false}')
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/act":
            try:
                res = ui_act(body)
            except Exception as e:
                res = {"err": str(e)}
            return self._send(200, json.dumps(res).encode(), cors=False)
        if path == "/ext/hello":
            ext_hello(body, "http")
            return self._send(200, b'{"ok":true}')
        if path == "/video/detect":
            video_detect(body)
            return self._send(200, b'{"ok":true}')
        if path == "/video/formats" and body.get("url"):
            try:
                res = video_formats(body["url"], body.get("referer", ""), body.get("cookies", ""))
            except Exception as e:
                res = {"err": str(e)[:300]}
            return self._send(200, json.dumps(res).encode())
        if path == "/video/get" and body.get("url") and G.mgr:
            try:
                mp3 = body.get("ext") == "mp3"
                b = {"height": body.get("h") or 0, "cont": "mp3" if mp3 else body.get("ext") or "mp4",
                     "title": body.get("title", ""), "thumb": body.get("thumb", ""), "size": body.get("size"),
                     "referer": body.get("referer", ""), "cookies": body.get("cookies", ""),
                     "fid": body.get("fid", ""), "muxed": body.get("muxed")}
                if CFG.get("silent") or not CFG.get("popup_dialog", True):
                    G.mgr.add_task(new_video_task(body["url"], b), start=True)
                    G.events.append({"k": "info", "name": body.get("title") or body["url"], "msg": "Video download started"})
                else:                       # ask first: the small File Information window (like a plain file)
                    open_popup(body["url"], b["referer"], b["cookies"],
                               video={**b, "folder": "", "start": "", "end": "", "exact": False, "subs": ""})
                return self._send(200, b'{"ok":true}')
            except Exception as e:
                return self._send(200, json.dumps({"err": str(e)[:200]}).encode())
        if path == "/add" and body.get("url"):
            capture_incoming({"urls": [body["url"]], "referer": body.get("referer", ""), "cookies": body.get("cookies", ""),
                              "video": bool(body.get("video")), "title": body.get("title", "")})
        elif path == "/addmany" and body.get("urls"):
            capture_incoming({"urls": body["urls"], "referer": body.get("referer", ""), "cookies": body.get("cookies", "")})
        else:
            return self._send(404, b'{"ok":false}')
        self._send(200, b'{"ok":true}')


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def start_server():
    try:
        srv = Server(("127.0.0.1", CFG["server_port"]), Handler)
    except OSError:
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def send_to_running(urls):
    """Return True if another instance is running (and hand the URLs to it)."""
    base = f"http://127.0.0.1:{CFG['server_port']}"
    try:
        with urllib.request.urlopen(base + "/ping", timeout=1.5) as r:
            if r.read() != b"UDM":
                return False
        if urls:
            data = json.dumps({"urls": urls, "token": CFG["token"]}).encode()
            urllib.request.urlopen(urllib.request.Request(
                base + "/addmany", data, {"Content-Type": "application/json"}), timeout=3).read()
        else:
            urllib.request.urlopen(base + "/show", timeout=1.5).read()
        return True
    except Exception:
        return False


# ------------------------------------------------------------------ Windows integration
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def set_startup(enable):
    if not winreg:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            if enable:
                if getattr(sys, "frozen", False):
                    cmd = f'"{sys.executable}" --minimized'
                else:
                    exe = sys.executable.replace("python.exe", "pythonw.exe")
                    cmd = f'"{exe}" "{os.path.abspath(sys.argv[0])}" --minimized'
                winreg.SetValueEx(k, "UnlimitedDownloadManager", 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(k, "UnlimitedDownloadManager")
                except FileNotFoundError:
                    pass
        return True
    except OSError:
        return False




EXT_JS = r"""
// Unlimited Download Manager - browser integration (generated by UDM; do not edit)
const PORT = %PORT%, HOST = "com.udm.host", VER = "%VER%", HINT = "%HINT%";
let TOKEN = "%TOKEN%";
const BASE = "http://127.0.0.1:" + PORT;
const B = globalThis.browser || globalThis.chrome;
const ACT = B.action || B.browserAction;
let rules = {enabled: true, types: [], excluded_types: [], excluded_sites: [], exceptions: [], large_mb: 5};
const wc = (p) => new RegExp("^" + p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "i");

/* ---- transport: Native Messaging first, local HTTP as the fallback ---- */
let port = null, nmFailUntil = 0, seq = 0;
const pend = {};
function nmConnect() {
  if (port || Date.now() < nmFailUntil) return;
  try {
    port = B.runtime.connectNative(HOST);
    port.onMessage.addListener((m) => { const p = pend[m && m.id]; if (p) { delete pend[m.id]; p(m); } });
    port.onDisconnect.addListener(() => {
      port = null; nmFailUntil = Date.now() + 60000;
      for (const k in pend) { pend[k](null); delete pend[k]; }
    });
  } catch (e) { port = null; nmFailUntil = Date.now() + 60000; }
}
function nmCall(msg, ms) {
  return new Promise((res) => {
    nmConnect();
    if (!port) return res(null);
    const id = ++seq, t = setTimeout(() => { delete pend[id]; res(null); }, ms || 6000);
    pend[id] = (m) => { clearTimeout(t); res(m && m.ok ? m : null); };
    try { port.postMessage(Object.assign({}, msg, {id})); } catch (e) { clearTimeout(t); delete pend[id]; res(null); }
  });
}
async function ensureToken() {
  if (TOKEN) return TOKEN;
  try {   // build without an embedded token: ask UDM (it only answers requests that come from a browser extension)
    const r = await fetch(BASE + "/ext/pair");
    if (r.ok) TOKEN = (await r.json()).token || "";
  } catch (e) {}
  return TOKEN;
}
const PATH = {add: "/add", addmany: "/addmany", detect: "/video/detect", hello: "/ext/hello", formats: "/video/formats", get: "/video/get"};
async function call(type, payload, ms) {
  payload = payload || {};
  const r = await nmCall({type, payload}, ms);
  if (r) return {via: "native", data: r.data || {}};
  try {
    const tok = await ensureToken();
    if (type === "rules") { const x = await fetch(BASE + "/rules?token=" + tok); return x.ok ? {via: "http", data: await x.json()} : null; }
    if (type === "show") { await fetch(BASE + "/show"); return {via: "http", data: {}}; }
    payload.token = tok;
    const x = await fetch(BASE + PATH[type], {method: "POST", headers: {"Content-Type": "application/json", "X-UDM-Token": tok},
                                              body: JSON.stringify(payload)});
    return x.ok ? {via: "http", data: await x.json().catch(() => ({}))} : null;
  } catch (e) { return null; }
}
async function detectBrowser() {
  const ua = navigator.userAgent;
  if (/Firefox\//.test(ua)) return "firefox";
  if (/Edg\//.test(ua)) return "edge";
  try { if (navigator.brave && await navigator.brave.isBrave()) return "brave"; } catch (e) {}
  return HINT === "brave" ? "brave" : "chrome";
}
async function hello() {
  return call("hello", {browser: await detectBrowser(), hint: HINT, ext_id: B.runtime.id, version: VER, last_cap: lastCap});
}
async function cookieHeader(url) {
  try { return (await B.cookies.getAll({url})).map((c) => c.name + "=" + c.value).join("; "); } catch (e) { return ""; }
}

/* ---- keep the link alive and tell UDM we are here ---- */
B.alarms.create("udm-hello", {periodInMinutes: 0.5});
B.alarms.onAlarm.addListener((a) => { if (a.name === "udm-hello") { nmConnect(); hello(); } });
B.runtime.onStartup.addListener(() => hello());
B.runtime.onInstalled.addListener(() => { hello(); makeMenus(); });
hello();

/* ---- capture browser downloads ---- */
let lastCap = "";
function note(msg) { lastCap = new Date().toLocaleTimeString() + "  " + msg; hello(); }
let rulesOk = false;
async function loadRules() { const r = await call("rules"); if (r && r.data && r.data.types) { rules = r.data; rulesOk = true; } else rulesOk = false; }
const nameOf = (x) => ((x.filename || x.finalUrl || x.url || "").split(/[\\/]/).pop() || "").split("?")[0];
B.downloads.onCreated.addListener(async (item) => {
  if (item.byExtensionId) return;
  await loadRules();
  if (!rulesOk) return note("UDM did not answer, so the browser kept the download");
  if (!rules.enabled) return note("capture is switched off in UDM");
  let it = item;
  const url = it.finalUrl || it.url;
  if (!/^(https?|ftp):/i.test(url)) return;                 // blob: / data: / file: stay in the browser
  let host = ""; try { host = new URL(url).hostname; } catch (e) {}
  if (rules.excluded_sites.some((p) => wc(p).test(host)) || rules.exceptions.some((p) => wc(p).test(url))) return note("skipped (excluded site / URL): " + host);
  let ext = (nameOf(it).split(".").pop() || "").toLowerCase();
  if (!rules.types.includes(ext)) {                         // the real file name is often not known yet: look again
    await new Promise((r) => setTimeout(r, 600));
    try { const f = (await B.downloads.search({id: item.id}))[0]; if (f) it = f; } catch (e) {}
    ext = (nameOf(it).split(".").pop() || "").toLowerCase();
  }
  const bytes = it.totalBytes || it.fileSize || 0, bigMb = rules.large_mb || 0;
  const big = bigMb > 0 && bytes >= bigMb * 1048576 && !/^text\//i.test(it.mime || "");
  if (rules.excluded_types.includes(ext)) return note('skipped (excluded type "' + ext + '")');
  if (!rules.types.includes(ext) && !big) return note('skipped: type "' + ext + '" is not in the capture list' + (bigMb ? " and the file is smaller than " + bigMb + " MB" : ""));
  const r = await call("add", {url, referer: it.referrer || "", cookies: await cookieHeader(url)});
  if (r) { B.downloads.cancel(item.id); B.downloads.erase({id: item.id}); note("sent to UDM: " + nameOf(it)); }
  else note("UDM did not answer, so the browser kept: " + nameOf(it));
});

/* ---- "Download with UDM" buttons inside web pages (content.js) ---- */
B.runtime.onMessage.addListener((m, sender, reply) => {
  if (!m || !m.udm) return;
  (async () => {
    const tab = sender.tab || {};
    const page = (m.frame && /youtube\.com\/embed/i.test(m.page || "")) ? m.page : (tab.url || m.page || "");
    if (m.udm === "cfg") { await loadRules(); return reply({lang: rules.lang || ""}); }
    if (m.udm === "formats") {
      const r = await call("formats", {url: page, referer: page, cookies: await cookieHeader(page)}, 150000);
      return reply(r ? r.data : {err: "UDM did not answer"});
    }
    if (m.udm === "get") {
      const r = await call("get", Object.assign({}, m.row, {url: page, title: m.title || tab.title || "", thumb: m.thumb || "", referer: page, cookies: await cookieHeader(page)}), 30000);
      return reply({ok: !!r && !(r.data && r.data.err)});
    }
    if (m.udm === "video") {
      const url = m.direct ? m.url : page;
      const r = await call("add", {url, video: !m.direct, title: m.title || tab.title || "", referer: page, cookies: await cookieHeader(url)});
      return reply({ok: !!r});
    }
  })();
  return true;
});

/* ---- context menus ---- */
function makeMenus() {
  try {
    B.contextMenus.removeAll(() => {
      B.contextMenus.create({id: "udm-link", title: "Download with UDM", contexts: ["link", "video", "audio", "image"]});
      B.contextMenus.create({id: "udm-sel", title: "Download selected links with UDM", contexts: ["selection"]});
      B.contextMenus.create({id: "udm-all", title: "Download all links on page with UDM", contexts: ["page"]});
    });
  } catch (e) {}
}
const grabLinks = (onlySel) => {
  let links = [];
  if (onlySel) {
    const s = window.getSelection();
    for (let i = 0; i < s.rangeCount; i++) s.getRangeAt(i).cloneContents().querySelectorAll("a[href]").forEach((a) => links.push(a.href));
    (s.toString().match(/https?:\/\/[^\s"'<>]+/g) || []).forEach((u) => links.push(u));
  } else { document.querySelectorAll("a[href]").forEach((a) => links.push(a.href)); }
  return [...new Set(links.filter((l) => /^(https?|ftp):/i.test(l)))];
};
async function runGrab(tabId, onlySel) {
  if (B.scripting) { const r = await B.scripting.executeScript({target: {tabId}, func: grabLinks, args: [onlySel]}); return (r && r[0] && r[0].result) || []; }
  const r = await B.tabs.executeScript(tabId, {code: "(" + grabLinks.toString() + ")(" + (onlySel ? "true" : "false") + ")"});
  return (r && r[0]) || [];
}
B.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "udm-link") {
    const url = info.linkUrl || info.srcUrl;
    await call("add", {url, referer: tab.url, cookies: await cookieHeader(url), force: true});
  } else {
    const urls = await runGrab(tab.id, info.menuItemId === "udm-sel");
    if (urls.length) await call("addmany", {urls, referer: tab.url});
  }
});

/* ---- video detection (MP4 / HLS / DASH / site videos) ---- */
const vstore = {};
const SKIP = /\.(ts|m4s|aac|vtt|jpe?g|png|gif|webp|js|css|woff2?|svg)(\?|$)/i;
const PAGE_CDN = /(googlevideo\.com|fbcdn\.net|cdninstagram\.com|video\.twimg\.com|tiktokcdn)/i;
function classify(url, ct, len) {
  if (SKIP.test(url)) return null;
  if (/\.m3u8(\?|$)/i.test(url) || /mpegurl/i.test(ct)) return "hls";
  if (/\.mpd(\?|$)/i.test(url) || /dash\+xml/i.test(ct)) return "dash";
  if (/^video\//i.test(ct) || /\.(mp4|webm|mkv|mov|flv|m4v)(\?|$)/i.test(url)) return (len && len < 200000) ? null : "mp4";
  if (/^audio\//i.test(ct) && len > 200000) return "audio";
  return null;
}
B.webRequest.onHeadersReceived.addListener(async (d) => {
  if (d.tabId < 0 || d.statusCode >= 400) return;
  const h = (n) => (d.responseHeaders.find((x) => x.name.toLowerCase() === n) || {}).value || "";
  const ct = h("content-type"); let len = parseInt(h("content-length")) || 0;
  const cr = h("content-range").match(/\/(\d+)$/); if (cr) len = parseInt(cr[1]);
  let type = classify(d.url, ct, len); if (!type) return;
  if (PAGE_CDN.test(d.url)) type = "page";
  let tab; try { tab = await B.tabs.get(d.tabId); } catch (e) { return; }
  const s = vstore[d.tabId] || (vstore[d.tabId] = {page: tab.url, items: {}});
  if (s.page !== tab.url) { s.page = tab.url; s.items = {}; }
  const url = type === "page" ? tab.url : d.url;
  if (s.items[url] || Object.keys(s.items).length > 40) return;
  s.items[url] = {url, type, size: len || null, ct};
  try { ACT.setBadgeText({tabId: d.tabId, text: String(Object.keys(s.items).length)}); ACT.setBadgeBackgroundColor({color: "#7c3aed"}); } catch (e) {}
  clearTimeout(s.t); s.t = setTimeout(() => pushVideos(d.tabId), 600);
}, {urls: ["<all_urls>"]}, ["responseHeaders"]);
async function pushVideos(tabId) {
  const s = vstore[tabId]; if (!s) return;
  let title = ""; try { title = (await B.tabs.get(tabId)).title; } catch (e) {}
  await call("detect", {page: s.page, title, cookies: await cookieHeader(s.page), items: Object.values(s.items)});
}
B.tabs.onRemoved.addListener((id) => { delete vstore[id]; });
B.tabs.onUpdated.addListener((id, ch) => {
  if (ch.status === "loading" && ch.url) { delete vstore[id]; try { ACT.setBadgeText({tabId: id, text: ""}); } catch (e) {} }
});
ACT.onClicked.addListener(() => { call("show"); });
makeMenus();
"""

CONTENT_JS = r"""
// UDM - video download panel shown on top of videos (generated by UDM; do not edit)
(() => {
  if (window.__udmButtons) return; window.__udmButtons = true;
  const B = globalThis.browser || globalThis.chrome;
  const isYT = /(^|\.)youtube\.com$/i.test(location.hostname);
  const inFrame = window.top !== window;
  let AR = /^ar/i.test(navigator.language);
  const TX = {
    en: {dl: "Download video", all: "All", filter: "Filter:", av1: "Smallest AV1", rec: "Recommended", save: "Save", busy: "Analyzing the video…", retry: "Try again",
         sent: "Sent to UDM", noudm: "UDM did not answer. Is it running?", reload: "UDM was updated: reload this page", start: "Download started in UDM"},
    ar: {dl: "تحميل الفيديو", all: "الكل", filter: "فلتر:", av1: "أصغر حجم AV1", rec: "موصى به", save: "توفير", busy: "جارٍ تحليل الفيديو…", retry: "إعادة المحاولة",
         sent: "تم الإرسال إلى UDM", noudm: "UDM لا يرد. هل البرنامج يعمل؟", reload: "تم تحديث UDM: أعد تحميل الصفحة", start: "بدأ التحميل في UDM"}};
  const T = (k) => TX[AR ? "ar" : "en"][k];
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[c]));
  const ask = (msg, cb) => { try { B.runtime.sendMessage(msg, (r) => cb(B.runtime.lastError ? null : r)); } catch (e) { cb(undefined); } };
  const SVG = {
    dl: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v11M7.5 11 12 15.5 16.5 11M5 20h14"/></svg>',
    dl2: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v11M7.5 11 12 15.5 16.5 11M5 20h14"/></svg>',
    chev: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>',
    leaf: '<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M20 4C9 4 4 9 4 15c0 1.6.5 3 1.4 4C7 14 10 11 14 9c-3 3-5 6-6 10 1.2.7 2.6 1 4 1 6 0 8-5 8-16z"/></svg>'};
  const CSS = `
:host{all:initial}*{box-sizing:border-box;font-family:'Segoe UI',Tahoma,Arial,sans-serif}
.wrap{position:fixed;display:none;direction:ltr;color:#fff}.wrap.on{display:block}
.pill{display:inline-flex;align-items:center;gap:10px;height:42px;padding:0 8px 0 8px;border-radius:15px;background:linear-gradient(180deg,rgba(22,26,62,.96),rgba(10,13,34,.96));border:1px solid rgba(95,120,255,.42);box-shadow:0 6px 26px rgba(0,0,0,.6),0 0 20px rgba(60,90,255,.22);backdrop-filter:blur(8px)}
button{font:inherit;color:inherit;border:0;background:none;cursor:pointer;padding:0}
.chev{width:28px;height:28px;border-radius:9px;display:grid;place-items:center;color:#c8d2ff;transition:.15s}.chev:hover,.chev.on{background:rgba(255,255,255,.12)}.chev.on svg{transform:rotate(180deg)}
.chip{display:none;align-items:center;height:24px;padding:0 11px;border-radius:999px;background:rgba(40,70,170,.55);border:1px solid rgba(80,130,255,.7);color:#a9c8ff;font:700 12.5px 'Segoe UI',Arial,sans-serif;white-space:nowrap}.chip.on{display:inline-flex}
.chip.ld{opacity:.7;letter-spacing:2px}
.main{display:inline-flex;align-items:center;gap:11px;font-weight:700;font-size:15px;white-space:nowrap;padding:0 2px 0 4px;border-radius:11px}.main:hover .dlc{filter:brightness(1.15)}
.dlc{width:30px;height:30px;border-radius:50%;background:linear-gradient(180deg,#2d94ff,#1673ee);display:grid;place-items:center;box-shadow:0 0 14px rgba(40,140,255,.75);transition:.15s}
.panel{display:none;margin-top:9px;width:432px;max-width:calc(100vw - 16px);overflow-x:hidden;max-height:var(--ph,420px);overflow:auto;background:#0d0f16;border:1px solid #252a3a;border-radius:18px;padding:12px;box-shadow:0 18px 50px rgba(0,0,0,.7)}
.panel.on{display:block}.panel::-webkit-scrollbar{width:6px}.panel::-webkit-scrollbar-thumb{background:#2c3247;border-radius:6px}
.filters{display:flex;gap:6px;flex-wrap:wrap;align-items:center;padding:2px 2px 4px}.filters.rtl{direction:rtl}.fl{color:#8f96ad;font-size:12.5px;margin-inline-end:2px}
.f{padding:6px 11px;border-radius:999px;border:1px solid #373d52;background:#151822;color:#c9cfe0;font-size:12.5px;font-weight:600;display:inline-flex;align-items:center;gap:6px}
.f:hover{border-color:#6a728c}.f.on{background:#2b3040;border-color:#9aa1bb;color:#fff}.f.av{color:#35dcae;border-color:#1f7d66;background:#0d2824}.f.av.on{background:#12403a;border-color:#35dcae}
.row{display:flex;align-items:center;gap:10px;padding:13px 12px;margin-top:10px;border-radius:15px;background:#14161f;border:1px solid #232838}.row:hover{border-color:#3a4260}
.sz{flex:1 0 auto;font-weight:800;font-size:18px;letter-spacing:.2px;white-space:nowrap}.rc{display:block;color:#2dd4a7;font-size:11.5px;font-weight:600;margin-top:3px}.rtl .rc{direction:rtl}
.q{display:flex;flex-direction:column;align-items:flex-end;gap:7px}.l1{display:flex;align-items:center;gap:8px}
.bd{font-size:11px;font-weight:700;padding:3px 8px;border-radius:6px;background:#17306f;border:1px solid #2f5fd6;color:#a9c8ff;white-space:nowrap}.bd.sv{background:#0e3a2c;border-color:#1f8a66;color:#4ff0b8}
.res{font-weight:800;font-size:17px}.cd{font:600 11.5px Consolas,'Courier New',monospace;color:#98a0b8;white-space:nowrap}
.go{width:42px;height:42px;border-radius:13px;background:#191c27;border:1px solid #2c3246;display:grid;place-items:center;color:#fff;transition:.15s;flex:none}.go:hover{background:#1673ee;border-color:#58a6ff}
.msg{display:flex;align-items:center;gap:12px;padding:14px 6px;color:#c9cfe0;font-size:14px}.msg.err{color:#ff8da1}.retry{margin:0 6px 6px;padding:8px 16px;border-radius:11px;background:#1b1f2c;border:1px solid #333a52;font-size:13px;font-weight:600}
.spin{width:18px;height:18px;border-radius:50%;border:2.5px solid #3a4262;border-top-color:#58a6ff;animation:sp .8s linear infinite;flex:none}@keyframes sp{to{transform:rotate(360deg)}}
.toast{position:fixed;right:18px;bottom:22px;background:#0b1332;color:#fff;font:600 14px 'Segoe UI',Tahoma,Arial,sans-serif;padding:12px 18px;border-radius:13px;border:1px solid #2f6bff;box-shadow:0 8px 28px rgba(0,0,0,.6);display:none;direction:ltr}.toast.on{display:block}`;
  const host = document.createElement("div");
  host.id = "udm-overlay"; host.style.cssText = "all:initial;position:fixed;top:0;left:0;width:0;height:0;z-index:2147483647";
  const root = host.attachShadow({mode: "closed"});
  root.innerHTML = `<style>${CSS}</style><div class="wrap" id="wrap"><div class="pill" id="pill"><button class="chev" id="chev">${SVG.chev}</button><span class="chip" id="chip"></span><button class="main" id="main"><span id="txt"></span><span class="dlc">${SVG.dl}</span></button></div><div class="panel" id="panel"></div></div><div class="toast" id="toast"></div>`;
  (document.documentElement || document).appendChild(host);
  const $ = (id) => root.getElementById(id);
  const wrap = $("wrap"), panel = $("panel"), chip = $("chip"), chev = $("chev"), toastEl = $("toast");
  const cache = new Map();                 // page url -> {st: "loading" | "ok" | "err", data, err, after}
  let cur = null, isOpen = false, filter = "all", over = false, hideT = 0, toastT = 0;
  const say = (t) => { toastEl.textContent = t; toastEl.classList.add("on"); clearTimeout(toastT); toastT = setTimeout(() => toastEl.classList.remove("on"), 3200); };
  const fsize = (n) => !n ? "-" : n >= 1073741824 ? (n / 1073741824).toFixed(2) + " GB" : (n / 1048576).toFixed(1) + " MB";
  const recOf = (c) => c && c.data && (c.data.rows.find((r) => r.fid === c.data.rec) || c.data.rows[0]);
  function load(url) {
    let c = cache.get(url); if (c) return c;
    c = {st: "loading"}; cache.set(url, c);
    ask({udm: "formats", page: url, frame: inFrame}, (r) => {
      if (r === undefined) { c.st = "err"; c.err = T("reload"); }
      else if (!r) { c.st = "err"; c.err = T("noudm"); }
      else if (r.err) { c.st = "err"; c.err = r.err; }
      else { c.st = "ok"; c.data = r; }
      if (c.st === "err") setTimeout(() => { if (cache.get(url) === c) cache.delete(url); }, 8000);
      render(); const go = c.after; c.after = null; if (go && c.st === "ok") go(); else if (go) fallback();
    });
    return c;
  }
  function render() {
    $("txt").textContent = T("dl");
    const c = cache.get(location.href), r = recOf(c);
    chip.className = "chip" + (c && c.st === "loading" ? " on ld" : r ? " on" : "");
    chip.textContent = c && c.st === "loading" ? "•••" : r ? r.label : "";
    if (!isOpen) return;
    if (!c || c.st === "loading") { panel.innerHTML = `<div class="msg"><i class="spin"></i>${esc(T("busy"))}</div>`; return; }
    if (c.st === "err") { panel.innerHTML = `<div class="msg err">${esc(c.err)}</div><button class="retry" data-retry="1">${esc(T("retry"))}</button>`; return; }
    const rows = c.data.rows, av1 = rows.some((x) => x.codec === "AV1");
    const chips = [["all", `${T("all")} (${rows.length})`], ["mp4", "MP4"], ["webm", "WEBM"]].concat(av1 ? [["av1", T("av1")]] : []);
    const list = rows.filter((x) => filter === "all" || (filter === "av1" ? x.codec === "AV1" : x.ext === filter));
    panel.innerHTML = `<div class="filters ${AR ? "rtl" : ""}"><span class="fl">${esc(T("filter"))}</span>${chips.map(([k, l]) => `<button class="f ${filter === k ? "on" : ""} ${k === "av1" ? "av" : ""}" data-f="${k}">${k === "av1" ? SVG.leaf : ""}${esc(l)}</button>`).join("")}</div>` +
      list.map((x) => `<div class="row"><div class="sz">${fsize(x.size)}${x.rec ? `<span class="rc">${esc(T("rec"))}</span>` : ""}</div><div class="q"><div class="l1">${x.saving ? `<span class="bd sv" dir="${AR ? "rtl" : "ltr"}">${esc(T("save"))} ${x.saving}%</span>` : ""}<span class="bd">${esc(x.badge)}</span><span class="res">${esc(x.label)}</span></div><div class="cd">${esc(x.ext.toUpperCase())} • ${esc(x.codec)}${x.tbr ? " • " + x.tbr.toLocaleString("en-US") + " kbps" : ""}</div></div><button class="go" data-go="${esc(x.fid)}">${SVG.dl2}</button></div>`).join("");
  }
  function download(row, c) {
    ask({udm: "get", page: location.href, frame: inFrame, title: document.title, thumb: c.data.thumb, row}, (r) => { say(r === undefined ? T("reload") : r && r.ok ? T("start") : T("noudm")); });
    closePanel();
  }
  function fallback() {      // not a site yt-dlp understands: hand the page / the file link to UDM
    const v = cur, src = (v && (v.currentSrc || v.src)) || "";
    const direct = !isYT && /^https?:/i.test(src) && /\.(mp4|webm|mkv|mov|m4v)(\?|$)/i.test(src);
    ask({udm: "video", title: document.title, frame: inFrame, page: location.href, url: direct ? src : location.href, direct}, (r) => say(r === undefined ? T("reload") : r && r.ok ? T("sent") : T("noudm")));
  }
  function openPanel() { isOpen = true; chev.classList.add("on"); panel.classList.add("on"); load(location.href); fit(); render(); }
  function closePanel() { isOpen = false; chev.classList.remove("on"); panel.classList.remove("on"); }
  function fit() { const r = wrap.getBoundingClientRect(); panel.style.setProperty("--ph", Math.max(180, innerHeight - r.top - 70) + "px"); if (r.left + 440 > innerWidth) wrap.style.left = Math.max(8, innerWidth - 448) + "px"; }
  $("main").addEventListener("click", (e) => {
    e.preventDefault(); e.stopPropagation();
    const c = load(location.href);
    if (c.st === "ok") download(recOf(c), c);
    else if (c.st === "loading") { c.after = () => download(recOf(c), c); say(T("busy")); }
    else fallback();
  });
  chev.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); isOpen ? closePanel() : openPanel(); });
  panel.addEventListener("click", (e) => {
    const t = e.target.closest("button"); if (!t) return;
    const c = cache.get(location.href);
    if (t.dataset.f) { filter = t.dataset.f; render(); }
    else if (t.dataset.retry) { cache.delete(location.href); openPanel(); }
    else if (t.dataset.go && c && c.data) download(c.data.rows.find((x) => x.fid === t.dataset.go), c);
  });
  wrap.addEventListener("mouseenter", () => { over = true; clearTimeout(hideT); });
  wrap.addEventListener("mouseleave", () => { over = false; arm(400); });
  const arm = (ms) => { clearTimeout(hideT); hideT = setTimeout(() => { if (!over && !isOpen) wrap.classList.remove("on"); }, ms); };
  document.addEventListener("mousedown", (e) => { if (isOpen && !e.composedPath().includes(host)) closePanel(); }, true);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && isOpen) closePanel(); }, true);
  window.addEventListener("scroll", () => { if (!isOpen) wrap.classList.remove("on"); }, {passive: true, capture: true});
  const sizeOK = (v) => { const r = v.getBoundingClientRect(); return r.width >= 220 && r.height >= 120 && r.bottom > 0 && r.top < innerHeight; };
  function showFor(v, forceOpen) {
    cur = v; const r = v.getBoundingClientRect();
    if (!isOpen) { wrap.style.left = Math.max(8, r.left + 12) + "px"; wrap.style.top = Math.max(8, r.top + 12) + "px"; }
    wrap.classList.add("on"); render();
    if (isYT && /^\/(watch|shorts)/.test(location.pathname)) load(location.href);   // so the quality chip is ready
    if (forceOpen) openPanel(); else arm(2800);
  }
  let busy = false;
  document.addEventListener("mousemove", (e) => {
    if (busy || over) return; busy = true; setTimeout(() => { busy = false; }, 120);
    for (const v of document.getElementsByTagName("video")) {
      if (!sizeOK(v)) continue;
      const r = v.getBoundingClientRect();
      if (e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom) { if (!isOpen) showFor(v); return; }
    }
    if (!isOpen) arm(400);
  }, true);
  /* YouTube: a button in the row with Like / Share / Save opens the same panel */
  if (isYT && !inFrame) {
    const tick = () => {
      const old = document.querySelector(".udm-yt");
      if (!/^\/(watch|shorts)/.test(location.pathname)) { if (old) old.remove(); return; }
      if (old) return;
      const row = document.querySelector("#top-level-buttons-computed") || document.querySelector("ytd-watch-metadata #actions #menu") || document.querySelector("#actions");
      if (!row) return;
      const b = document.createElement("button"); b.className = "udm-yt"; b.title = T("dl");
      b.style.cssText = "all:initial;margin-inline-start:8px;height:36px;padding:0 14px;border-radius:18px;background:#1673ee;color:#fff;font:600 14px 'Segoe UI',Arial,sans-serif;display:inline-flex;align-items:center;gap:7px;cursor:pointer;box-sizing:border-box";
      b.innerHTML = SVG.dl + "<span>UDM</span>";
      b.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); const v = document.querySelector("video.html5-main-video") || document.querySelector("video"); if (v) { wrap.style.left = ""; showFor(v, true); } });
      row.appendChild(b);
    };
    setInterval(tick, 1200); tick();
  }
  try { B.runtime.sendMessage({udm: "cfg"}, (r) => { if (!B.runtime.lastError && r && r.lang) { AR = r.lang === "ar"; render(); } }); } catch (e) {}
})();
"""


# ====================================================================== browser integration (installed from inside UDM, no store)
EXT_VERSION = "1.5.0"
HOST_NAME = "com.udm.host"
EXT_PUBKEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx16FSZLkwo6Ru2hW/X3+uaeZoxojJzWekIRjNWI9SlH4wFiw7U98Ye2Zj7fxUCKRJ7HJbhjSgNMMMWNrST0ZWq5UKvj4aZIVUpCnwwfQdC+05W46uMtqOKh005v7umzm0uYyt3SEK02QYJ2skZeGTD22hDKkaACqWPU0AtVYKiiy5w79aROgjEqq4rooreJH8HBnlM4OVtqn5C159jNDUeoM632Oq+er2qXrD84Ief12gq20gOgLINnkrFvpBI9hifNVq25avAHMwMvSlG8bcVfHvjkVM8dgbBMFZRquPddqEFf3WDTBp7Hs4i/2/ZiaRd222NzO1cL5EakXQw/2+QIDAQAB"
EXT_ID_FIREFOX = "udm@unlimited.download.manager"


def chrome_ext_id(pub_b64):
    h = hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()[:32]
    return "".join(chr(ord("a") + int(c, 16)) for c in h)


EXT_ID_CHROMIUM = chrome_ext_id(EXT_PUBKEY)
BROWSERS = {
    "chrome": {"title": "Google Chrome", "family": "chromium", "exe": "chrome.exe", "url": "chrome://extensions",
               "nm": r"Software\Google\Chrome\NativeMessagingHosts",
               "paths": [("ProgramFiles", r"Google\Chrome\Application\chrome.exe"),
                         ("ProgramFiles(x86)", r"Google\Chrome\Application\chrome.exe"),
                         ("LocalAppData", r"Google\Chrome\Application\chrome.exe")]},
    "brave": {"title": "Brave", "family": "chromium", "exe": "brave.exe", "url": "brave://extensions",
              "nm": r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
              "paths": [("ProgramFiles", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                        ("ProgramFiles(x86)", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
                        ("LocalAppData", r"BraveSoftware\Brave-Browser\Application\brave.exe")]},
    "edge": {"title": "Microsoft Edge", "family": "chromium", "exe": "msedge.exe", "url": "edge://extensions",
             "nm": r"Software\Microsoft\Edge\NativeMessagingHosts",
             "paths": [("ProgramFiles(x86)", r"Microsoft\Edge\Application\msedge.exe"),
                       ("ProgramFiles", r"Microsoft\Edge\Application\msedge.exe")]},
    "firefox": {"title": "Mozilla Firefox", "family": "firefox", "exe": "firefox.exe",
                "url": "about:debugging#/runtime/this-firefox", "nm": r"Software\Mozilla\NativeMessagingHosts",
                "paths": [("ProgramFiles", r"Mozilla Firefox\firefox.exe"),
                          ("ProgramFiles(x86)", r"Mozilla Firefox\firefox.exe")]},
}
CHROME_NM_KEY = BROWSERS["chrome"]["nm"]


def find_browser_exe(key):
    b, cands = BROWSERS[key], []
    if winreg:
        for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(root, r"Software\Microsoft\Windows\CurrentVersion\App Paths" + "\\" + b["exe"]) as k:
                    cands.append(str(winreg.QueryValueEx(k, "")[0]).strip('"'))
            except OSError:
                pass
    for env, rel in b["paths"]:
        base = os.environ.get(env)
        if base:
            cands.append(os.path.join(base, rel))
    cands.append(shutil.which(b["exe"]) or "")
    return next((c for c in cands if c and os.path.exists(c)), None)


def ext_root():
    return os.path.join(APP_DIR, "extensions")


def ext_dir(browser):
    return os.path.join(ext_root(), browser)


def bundled_signed_xpi():
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "extension", "udm-firefox-signed.xpi")


PERMS = ["downloads", "contextMenus", "activeTab", "cookies", "storage", "webRequest", "tabs", "nativeMessaging", "alarms"]


def manifest_for(browser):
    base = {"name": "Unlimited Download Manager", "version": os.environ.get("UDM_EXT_VERSION", EXT_VERSION), "icons": {"128": "icon128.png"},
            "description": "Sends downloads, links and detected videos to Unlimited Download Manager."}
    if BROWSERS[browser]["family"] == "firefox":
        base["content_scripts"] = [{"matches": ["<all_urls>"], "js": ["content.js"], "run_at": "document_idle", "all_frames": True}]
        base.update({"manifest_version": 2, "permissions": PERMS + ["<all_urls>"],
                     "browser_specific_settings": {"gecko": {"id": EXT_ID_FIREFOX, "strict_min_version": "115.0"}},
                     "background": {"scripts": ["background.js"]},
                     "browser_action": {"default_title": "Unlimited Download Manager", "default_icon": {"128": "icon128.png"}}})
    else:
        base["content_scripts"] = [{"matches": ["<all_urls>"], "js": ["content.js"], "run_at": "document_idle", "all_frames": True}]
        base.update({"manifest_version": 3, "key": EXT_PUBKEY, "permissions": PERMS + ["scripting"],
                     "host_permissions": ["<all_urls>"], "background": {"service_worker": "background.js"},
                     "action": {"default_title": "Unlimited Download Manager", "default_icon": {"128": "icon128.png"}}})
    return base


def write_extension(dest, browser, embed_token=True):
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest_for(browser), f, indent=2)
    js = (EXT_JS.replace("%PORT%", str(CFG["server_port"])).replace("%TOKEN%", CFG["token"] if embed_token else "")
          .replace("%VER%", EXT_VERSION).replace("%HINT%", browser))
    with open(os.path.join(dest, "background.js"), "w", encoding="utf-8") as f:
        f.write(js)
    with open(os.path.join(dest, "content.js"), "w", encoding="utf-8") as f:
        f.write(CONTENT_JS)
    with open(os.path.join(dest, "icon128.png"), "wb") as f:
        f.write(base64.b64decode(ICON_B64))
    return dest


def _stamp():
    return f"{EXT_VERSION}|{CFG['server_port']}|{CFG['token']}"


def prepare_extension(browser):
    """Unpack the right extension for this browser into a fixed UDM folder."""
    d = ext_dir(browser)
    write_extension(d, browser)
    with open(os.path.join(d, ".stamp"), "w") as f:
        f.write(_stamp())
    info = {"folder": d, "xpi": None, "signed_xpi": None}
    if BROWSERS[browser]["family"] == "firefox":
        xpi = os.path.join(ext_root(), "udm-firefox.xpi")
        with zipfile.ZipFile(xpi, "w", zipfile.ZIP_DEFLATED) as z:
            for fn in ("manifest.json", "background.js", "icon128.png"):
                z.write(os.path.join(d, fn), fn)
        info["xpi"] = xpi
        sg = bundled_signed_xpi()
        if os.path.exists(sg):
            dst = os.path.join(ext_root(), "udm-firefox-signed.xpi")
            shutil.copy2(sg, dst)
            info["signed_xpi"] = dst
    return info


def refresh_extensions():
    """Keep already-prepared extension folders in sync after an update / token change."""
    for b in BROWSERS:
        sp = os.path.join(ext_dir(b), ".stamp")
        try:
            if os.path.exists(sp) and open(sp).read() != _stamp():
                prepare_extension(b)
        except OSError:
            pass


def export_extension(dest):
    return write_extension(dest, "chrome")


# ---- Native Messaging registration (HKCU: no administrator rights needed)
HOST_EXE_OVERRIDE = None


def native_host_exe():
    if HOST_EXE_OVERRIDE:
        return HOST_EXE_OVERRIDE
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(sys.executable), "host", "udm-host.exe")
    return None


def write_native_manifests():
    host = native_host_exe()
    if not host:
        return None
    d = os.path.join(APP_DIR, "native")
    os.makedirs(d, exist_ok=True)
    ids = sorted({EXT_ID_CHROMIUM} | set(CFG.get("ext_ids", [])))
    common = {"name": HOST_NAME, "description": "Unlimited Download Manager native host", "path": host, "type": "stdio"}
    paths = {"chromium": os.path.join(d, HOST_NAME + ".chromium.json"), "firefox": os.path.join(d, HOST_NAME + ".firefox.json")}
    with open(paths["chromium"], "w", encoding="utf-8") as f:
        json.dump(dict(common, allowed_origins=[f"chrome-extension://{i}/" for i in ids]), f, indent=2)
    with open(paths["firefox"], "w", encoding="utf-8") as f:
        json.dump(dict(common, allowed_extensions=[EXT_ID_FIREFOX]), f, indent=2)
    return paths


def _nm_subkeys(browser):
    keys = [BROWSERS[browser]["nm"]]
    if BROWSERS[browser]["family"] == "chromium" and browser != "chrome":
        keys.append(CHROME_NM_KEY)          # many Chromium browsers also read Chrome's location
    return [k + "\\" + HOST_NAME for k in keys]


def register_native(browsers=None, remove=False):
    """Create (or remove) the registry entries that let each browser find udm-host."""
    if not winreg:
        return {"ok": False, "err": "Native Messaging registration works on Windows only"}
    paths = None if remove else write_native_manifests()
    if not remove and not paths:
        return {"ok": False, "err": "udm-host.exe was not found next to UDM.exe"}
    done = []
    for b in browsers or list(BROWSERS):
        for sub in _nm_subkeys(b):
            try:
                if remove:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
                else:
                    winreg.SetValue(winreg.HKEY_CURRENT_USER, sub, winreg.REG_SZ, paths[BROWSERS[b]["family"]])
                done.append(sub)
            except OSError:
                pass
    return {"ok": True, "keys": done}


def native_registered(browser):
    if not winreg:
        return False
    paths = os.path.join(APP_DIR, "native")
    want = os.path.join(paths, HOST_NAME + (".firefox.json" if BROWSERS[browser]["family"] == "firefox" else ".chromium.json"))
    try:
        return winreg.QueryValue(winreg.HKEY_CURRENT_USER, BROWSERS[browser]["nm"] + "\\" + HOST_NAME) == want and os.path.exists(want)
    except OSError:
        return False


def startup_integration():
    """Run at every start: repair the registration (e.g. portable copy moved) and refresh extension files."""
    try:
        if getattr(sys, "frozen", False):
            CFG["app_exe"] = sys.executable
        register_native()
        refresh_extensions()
    except Exception:
        pass


# ---- state of the browser <-> UDM link
def ext_hello(b, via="http"):
    key = b.get("hint") or b.get("browser") or "chrome"
    if key not in BROWSERS:
        return
    rec = {"last": time.time(), "via": b.get("via") or via, "version": b.get("version", ""), "ext_id": b.get("ext_id", ""),
           "browser": b.get("browser", ""), "last_cap": b.get("last_cap", "")}
    G.ext[key] = rec
    seen = CFG.setdefault("ext_seen", {})
    if time.time() - seen.get(key, 0) > 1800:
        seen[key] = time.time()
        save_cfg()
    eid = rec["ext_id"]
    if BROWSERS[key]["family"] == "chromium" and re.match(r"^[a-p]{32}$", eid) and eid != EXT_ID_CHROMIUM \
            and eid not in CFG.get("ext_ids", []):
        CFG.setdefault("ext_ids", []).append(eid)          # self-heal: allow the ID this browser really gave the extension
        save_cfg()
        write_native_manifests()


def _profile_dirs(key):
    la, ap = os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", "")
    roots = {"chrome": [os.path.join(la, "Google", "Chrome", "User Data")],
             "brave": [os.path.join(la, "BraveSoftware", "Brave-Browser", "User Data")],
             "edge": [os.path.join(la, "Microsoft", "Edge", "User Data")],
             "firefox": [os.path.join(ap, "Mozilla", "Firefox", "Profiles")]}.get(key, [])
    out = []
    for r in roots:
        if r and os.path.isdir(r):
            out += [os.path.join(r, d) for d in sorted(os.listdir(r)) if d == "Default" or d.startswith("Profile ") or key == "firefox"]
    return out


def _ext_in_profile(key):
    """Look into the browser profile for the UDM extension (best effort, read-only)."""
    found, disabled = False, False
    me = os.path.normcase(os.path.abspath(ext_dir(key)))
    for pd in _profile_dirs(key):
        try:
            if BROWSERS[key]["family"] == "firefox":
                with open(os.path.join(pd, "extensions.json"), encoding="utf-8") as f:
                    for a in json.load(f).get("addons", []):
                        if a.get("id") == EXT_ID_FIREFOX:
                            found, disabled = True, not a.get("active", True)
                continue
            for fn in ("Secure Preferences", "Preferences"):
                fp = os.path.join(pd, fn)
                if not os.path.exists(fp):
                    continue
                with open(fp, encoding="utf-8") as f:
                    sett = (json.load(f).get("extensions") or {}).get("settings") or {}
                for eid, e in sett.items():
                    pth = os.path.normcase(os.path.abspath(e.get("path", ""))) if e.get("path") else ""
                    if eid == EXT_ID_CHROMIUM or pth == me:
                        found = True
                        disabled = bool(e.get("disable_reasons")) or e.get("state") == 0
        except (OSError, ValueError, AttributeError):
            continue
    return {"found": found, "disabled": disabled}


_EXT_DET = {}


def ext_in_profile(key):
    c = _EXT_DET.get(key)
    if c and time.time() - c[0] < 15:
        return c[1]
    try:
        det = _ext_in_profile(key)
    except Exception:
        det = {"found": False, "disabled": False}
    _EXT_DET[key] = (time.time(), det)
    return det


def ext_summary():
    now = time.time()
    names = [k for k, v in G.ext.items() if now - v.get("last", 0) < 90]
    return {"connected": len(names), "names": names, "total": len(BROWSERS), "seen": bool(CFG.get("ext_seen"))}


def ext_browser_info(key):
    b, rec = BROWSERS[key], G.ext.get(key) or {}
    exe = find_browser_exe(key)
    age = time.time() - rec["last"] if rec.get("last") else None
    d = ext_dir(key)
    det = ext_in_profile(key)
    seen = (CFG.get("ext_seen") or {}).get(key, 0)
    connected = age is not None and age < 90
    return {"id": key, "title": b["title"], "family": b["family"], "installed": bool(exe), "exe": exe, "url": b["url"],
            "prepared": os.path.exists(os.path.join(d, "manifest.json")), "folder": d,
            "host_registered": native_registered(key), "connected": connected, "age": age,
            "ext_installed": bool(connected or det["found"] or seen), "ext_disabled": det["disabled"] and not connected,
            "seen_at": rec.get("last") or seen or None, "win": IS_WIN,
            "via": rec.get("via"), "ext_version": rec.get("version"), "last_cap": rec.get("last_cap", ""),
            "signed_xpi": os.path.exists(os.path.join(ext_root(), "udm-firefox-signed.xpi")) or os.path.exists(bundled_signed_xpi())
            if b["family"] == "firefox" else False,
            "xpi": os.path.join(ext_root(), "udm-firefox.xpi") if b["family"] == "firefox" else None}


def ext_open(key, what):
    b, exe = BROWSERS[key], find_browser_exe(key)
    d = ext_dir(key)
    if what == "folder":
        open_path(d if os.path.isdir(d) else ext_root())
        return {"ok": True}
    if what == "launch":
        if not exe:
            return {"err": f"{b['title']} was not found on this computer."}
        subprocess.Popen([exe])
        return {"ok": True}
    if what in ("manage", "signed") and not exe:
        return {"err": f"{b['title']} was not found. Open this address in it yourself: {b['url']}"}
    if what == "manage":
        subprocess.Popen([exe, b["url"]])
    elif what == "signed":
        subprocess.Popen([exe, os.path.join(ext_root(), "udm-firefox-signed.xpi")])
    return {"ok": True}


# ====================================================================== web UI glue
import types
import webbrowser

G = types.SimpleNamespace(mgr=None, last_poll=0.0, started=time.time(), events=[], incoming=[], quit=False,
                          tray=None, proc=None, prev={}, last_clip="", server=None, notified=False, videos=[], ext={},
                          pending={}, last_popup=0.0, recent={}, win=None, win_closed=False, want_ui=False,
                          build_no=0, update=None, update_dl=None)
KINDS = {}


def push_incoming(p):
    G.incoming.append(p)
    ensure_ui()


def ui_alive():
    if G.proc is not None and G.proc.poll() is not None:      # our window was closed
        return False
    return time.time() - G.last_poll < 6


def find_browser():
    cands = []
    if IS_WIN:
        for env in ("ProgramFiles(x86)", "ProgramFiles", "LocalAppData"):
            b = os.environ.get(env)
            if b:
                cands += [os.path.join(b, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
                          os.path.join(b, "Google", "Chrome", "Application", "chrome.exe"),
                          os.path.join(b, "Microsoft", "Edge", "Application", "msedge.exe")]
    else:
        cands = [shutil.which(x) or "" for x in ("brave-browser", "brave", "google-chrome", "microsoft-edge", "chromium", "chromium-browser")]
    return next((c for c in cands if c and os.path.exists(c)), None)


def _on_win_closing(*args):
    """The user pressed X on the native window: hide it to the tray instead of quitting,
    so downloads keep running in the background."""
    if CFG.get("tray") and G.tray:
        try:
            G.win.hide()
        except Exception:
            pass
        try:
            G.tray.notify("Still running in the system tray.", APP_NAME)
        except Exception:
            pass
        return False                                   # veto the close: keep running in the background
    return True


def _on_win_closed():
    G.win_closed = True
    G.win = None
    if not (CFG.get("tray") and G.tray):
        quit_app()


def _try_native_window(url):
    """Open the UI in a real program window (pywebview, Edge WebView2). Returns True when the
    native window ran and has now closed for good; False when pywebview is not available, so
    the caller falls back to a browser window. Must run on the main thread."""
    try:
        import webview
    except ImportError:
        return False
    if threading.current_thread() is not threading.main_thread():
        return False
    try:
        if G.win is not None and not G.win_closed:
            return False
        G.win = webview.create_window(APP_NAME, url, width=1280, height=800, min_size=(960, 600))
        G.win.events.closing += _on_win_closing
        G.win.events.closed += _on_win_closed
        G.win_closed = False
        webview.start()                                # blocks until the window is really closed
        return True
    except Exception:
        G.win = None
        return False


def open_ui():
    """Show the main window. Returns True when a native program window was used and has
    now closed for good (so the caller should quit when the tray is off)."""
    url = f"http://127.0.0.1:{CFG['server_port']}/ui?token={CFG['token']}"
    if _try_native_window(url + "&native=1"):
        return True
    exe = find_browser()
    if exe:
        try:
            G.proc = subprocess.Popen([exe, f"--app={url}", "--window-size=1280,780", "--no-first-run",
                                       f"--user-data-dir={os.path.join(APP_DIR, 'profile')}"])
            return False
        except OSError:
            pass
    webbrowser.open(url)
    return False


def screen_size():
    if IS_WIN:
        try:
            import ctypes
            return ctypes.windll.user32.GetSystemMetrics(0), ctypes.windll.user32.GetSystemMetrics(1)
        except Exception:
            pass
    return 1920, 1080


def popup_alive():
    return time.time() - G.last_popup < 15


def open_popup(url, referer="", cookies="", video=None):
    """The small window of one download (file information, then live progress), like a classic download manager."""
    now = time.time()
    if now - G.recent.get(url, 0) < 4:                      # the browser may report the same click twice
        return
    G.recent[url] = now
    pid = uuid.uuid4().hex[:10]
    G.pending[pid] = {"url": url, "referer": referer, "cookies": cookies, "t": now, "video": video}
    for k in [k for k, v in G.pending.items() if now - v["t"] > 3600]:
        G.pending.pop(k, None)
    G.last_popup = now
    link = f"http://127.0.0.1:{CFG['server_port']}/popup?token={CFG['token']}&pid={pid}"
    exe, (sw, sh), (w, h) = find_browser(), screen_size(), (800, 660)
    if exe:
        try:
            subprocess.Popen([exe, f"--app={link}", f"--window-size={w},{h}", f"--window-position={max(0, (sw - w) // 2)},{max(0, (sh - h) // 2 - 20)}",
                              "--no-first-run", f"--user-data-dir={os.path.join(APP_DIR, 'profile')}"])
            return pid
        except OSError:
            pass
    webbrowser.open(link)
    return pid


def capture_incoming(p):
    """A link from the browser: one plain file link gets the small window, everything else the main window."""
    urls = p.get("urls") or []
    if len(urls) == 1 and not p.get("video") and not CFG["silent"] and CFG.get("popup_dialog", True) \
            and re.match(r"^(https?|ftp)://", urls[0], re.I):
        open_popup(urls[0], p.get("referer", ""), p.get("cookies", ""))
    else:
        push_incoming(p)


def ensure_ui(force=False):
    if G.win is not None and not G.win_closed:
        # native window is hidden in the tray: bring it back (plain Win32, safe from any thread)
        if IS_WIN:
            win_control("show")
        else:
            try:
                G.win.show()
            except Exception:
                pass
        return
    if not ui_alive():
        if threading.current_thread() is threading.main_thread():
            open_ui()
        else:
            G.want_ui = True                           # the main loop opens it


def win_control(what, prefix=None):
    """Minimize / maximize / close the UDM window (Windows). Returns False when the browser must do it."""
    if not IS_WIN:
        return {"ok": False}
    try:
        import ctypes
        from ctypes import wintypes
        u = ctypes.windll.user32
        proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        mypid = os.getpid()
        pid = wintypes.DWORD()
        own, other = [], []                            # our own program window first, browser window second

        def cb(h, _):
            n = u.GetWindowTextLengthW(h)
            # a window hidden to the tray is NOT visible: "show" must still find it,
            # otherwise reopening from the tray / desktop shortcut silently does nothing
            if n and (what == "show" or u.IsWindowVisible(h)):
                buf = ctypes.create_unicode_buffer(n + 1)
                u.GetWindowTextW(h, buf, n + 1)
                u.GetWindowThreadProcessId(h, ctypes.byref(pid))
                if pid.value == mypid:
                    own.append(h)                      # native pywebview window (same process)
                elif (buf.value.startswith(prefix) if prefix else buf.value == APP_NAME):
                    other.append(h)                    # browser --app window with the same title
            return True
        u.EnumWindows(proc(cb), 0)
        found = own or other
        if not found:
            return {"ok": False}
        h = found[0]
        if what == "min":
            u.ShowWindow(h, 6)
        elif what == "show":
            if u.IsWindowVisible(h):
                u.ShowWindow(h, 9)                         # restore a minimized window
            else:
                u.ShowWindow(h, 5)                         # show a window hidden to the tray
            try:
                u.SetForegroundWindow(h)                   # bring it to the front
            except Exception:
                pass
        elif what == "max":
            u.ShowWindow(h, 9 if u.IsZoomed(h) else 3)
        elif what == "close":
            u.PostMessageW(h, 0x0010, 0, 0)
        return {"ok": True}
    except Exception:
        return {"ok": False}


def ui_state():
    m = G.mgr
    rows = []
    for t in list(m.tasks.values()):
        rows.append({"id": t.id, "name": t.filename or urllib.parse.unquote(os.path.basename(urllib.parse.urlparse(t.url).path)) or t.url,
                     "url": t.url, "size": t.size, "done": t.live_bytes, "status": t.status, "err": (t.error or "")[:120],
                     "speed": t.speed, "cat": t.category, "queue": t.queue, "added": t.added, "fin": t.finished,
                     "res": t.resumable, "conn": t.nworkers, "ctarget": t.target, "desc": t.description, "folder": t.folder,
                     "nconn": t.nconn, "referer": t.referer, "cookies": t.cookies, "user": t.user, "pwd": t.pwd,
                     "speed_limit_kb": t.speed_limit_kb, "hash": t.hash_result,
                     "kind": getattr(t, "kind", "file"), "thumb": getattr(t, "vthumb", ""),
                     "vh": getattr(t, "vheight", 0), "vc": getattr(t, "vcont", "")})
    try:
        base = DEFAULT_DIR if os.path.exists(DEFAULT_DIR) else os.path.expanduser("~")
        du = shutil.disk_usage(base)
        disk = {"pct": round(du.used * 100 / du.total), "path": base, "free": du.free}
    except OSError:
        disk = None
    ev, inc = G.events[:], G.incoming[:]
    del G.events[:len(ev)]
    del G.incoming[:len(inc)]
    act = [t for t in m.tasks.values() if t.status == "Downloading"]
    queues = [dict(q, count=sum(1 for t in m.tasks.values() if t.queue == q["name"])) for q in m.queues.values()]
    return {"tasks": rows, "queues": queues, "cats": list(CFG["categories"]), "speed": sum(t.speed for t in act),
            "active": len(act), "disk": disk, "events": ev, "incoming": inc, "silent": CFG["silent"],
            "notify": CFG["notify"], "confirm": CFG["confirm_delete"], "confirm_stop": CFG["confirm_stop"],
            "show_complete": CFG["show_complete"], "connections": CFG["connections"],
            "theme": CFG["theme"], "language": CFG["language"], "vcount": len(G.videos),
            "palette": CFG["palette"], "text_size": CFG["text_size"], "limit": CFG["speed_limit_kb"], "limit_saved": CFG["limit_saved"],
            "ext": ext_summary(), "capture": CFG["capture_enabled"], "mode": CFG["speed_mode"], "ver": APP_VER,
            "conns": sum(t.nworkers for t in act), "upd": update_ui_state()}


def video_detect(b):
    page = b.get("page", "")
    for it in b.get("items", []):
        u = it.get("url")
        if not u or any(v["url"] == u for v in G.videos):
            continue
        G.videos.append({"id": uuid.uuid4().hex[:8], "url": u, "type": it.get("type", "mp4"), "size": it.get("size"),
                         "page": page, "title": b.get("title") or url_host(page), "referer": page,
                         "cookies": b.get("cookies", ""), "host": url_host(u), "ts": time.time()})
    del G.videos[:-150]


def list_write(tasks):
    out = []
    for t in tasks:
        out += ["<", t.url]
        for k, v in (("referer", t.referer), ("cookie", t.cookies), ("description", t.description)):
            if v:
                out.append(f"{k}: {v}")
        out.append(">")
    return "\r\n".join(out) + "\r\n"


def list_parse(text):
    items, cur = [], None
    is_url = lambda s: re.match(r"^(https?|ftp)://", s, re.I)
    for raw in text.splitlines():
        line = raw.strip()
        if line == "<":
            cur = {"url": ""}
        elif line == ">":
            if cur and cur["url"]:
                items.append(cur)
            cur = None
        elif cur is None:
            if is_url(line):
                items.append({"url": line})
        elif not cur["url"] and is_url(line):
            cur["url"] = line
        else:
            key, sep, val = line.partition(":")
            key = {"cookie": "cookies"}.get(key.strip().lower(), key.strip().lower())
            if sep and val.strip() and key in ("referer", "cookies", "description"):
                cur[key] = val.strip()
    return items


def _ts(s):
    s = (s or "").strip()
    return s if re.match(r"^[0-9]+(:[0-9]{1,2}){0,2}(\.[0-9]+)?$", s) else ""


def new_video_task(url, b, title=None):
    mp3 = b.get("cont") == "mp3"
    t = VideoTask(url, (b.get("folder") or "").strip() or category_folder("Musics" if mp3 else "Videos"), CFG["connections"])
    t.vheight, t.vcont, t.vtitle = int(b.get("height") or 0), b.get("cont") or "mp4", title if title is not None else (b.get("title") or "")
    t.size = t.vsize = b.get("size") or None
    t.referer, t.cookies = b.get("referer", ""), b.get("cookies", "")
    t.vthumb = b.get("thumb") if str(b.get("thumb") or "").startswith("http") else ""
    t.vfmt, t.vmux = re.sub(r"[^A-Za-z0-9_.-]", "", str(b.get("fid") or "")) if not mp3 else "", bool(b.get("muxed"))
    t.vstart, t.vend, t.vexact = _ts(b.get("start")), _ts(b.get("end")), bool(b.get("exact"))
    t.vsubs = re.sub(r"[^A-Za-z0-9,.*-]", "", b.get("subs") or "")
    t.speed_limit_kb = max(0, int(b.get("speed_limit_kb") or 0))
    t.category, t.auto_cat, t.auto_folder = ("Musics" if mp3 else "Videos"), False, False
    t.filename = safe_name(t.vtitle or "video") + ("." + ("mp3" if mp3 else t.vcont))
    return t


def cats_to_text():
    return "\n".join(f"{n} | {' '.join(c.get('exts', []))} | {c.get('folder', '')}" for n, c in CFG["categories"].items())


def apply_cats_text(txt):
    old, new = CFG["categories"], {}
    for line in txt.splitlines():
        p = [x.strip() for x in line.split("|")]
        if p and p[0]:
            new[p[0]] = {"exts": split_list(p[1]) if len(p) > 1 else [],
                         "sites": old.get(p[0], {}).get("sites", []), "folder": p[2] if len(p) > 2 else ""}
    new.setdefault("Uncategorized", {"exts": [], "sites": [], "folder": ""})
    CFG["categories"] = new


def ui_act(b):
    m, op = G.mgr, b.get("op")
    ts = [m.tasks[i] for i in b.get("ids", []) if i in m.tasks]
    if op == "add":
        urls = []
        for line in (b.get("urls") or "").splitlines():
            if re.match(r"^(https?|ftp)://", line.strip(), re.I):
                urls += expand_pattern(line.strip())
        dup = b.get("dup") or (CFG["dup_action"] if CFG["dup_action"] != "ask" else "")
        exist = {t.url: t for t in m.tasks.values()}
        dups = [u for u in urls if u in exist]
        if dups and not dup:
            return {"dups": dups}
        cat = b.get("category") or "Uncategorized"
        done = 0
        for u in urls:
            old = exist.get(u)
            if old and dup == "skip":
                continue
            args = dict(folder=(b.get("folder") or "").strip() or None, category=cat,
                        nconn=max(1, min(32, int(b.get("nconn") or CFG["connections"]))),
                        queue=b.get("queue", "") if not b.get("start") else "", start=bool(b.get("start")),
                        referer=b.get("referer", ""), cookies=b.get("cookies", ""), user=b.get("user", ""),
                        pwd=b.get("pwd", ""), description=b.get("description", ""),
                        speed_limit_kb=int(b.get("speed_limit_kb") or 0),
                        expect_hash=(b.get("expect_hash") or "") if len(urls) == 1 else "")
            if old and dup == "replace":
                args.update(overwrite=True, filename=old.filename, folder=old.folder)
                m.remove(old, False)
            m.add_url(u, **args)
            done += 1
        if b.get("folder") and cat != "Auto" and CFG["remember_dir"]:
            CFG["last_dir"][cat] = b["folder"]
            save_cfg()
        if b.get("folder") and cat != "Auto" and CFG.get("cat_folder_follow") and cat in CFG["categories"]:
            CFG["categories"][cat]["folder"] = b["folder"]
            save_cfg()
        return {"n": done}
    if op == "resume":
        for t in ts:
            t.start()
    elif op == "stop":
        for t in ts:
            t.pause()
            if t.status == "Queued":
                t.status = "Paused"
    elif op == "stopall":
        for t in list(m.tasks.values()):
            t.pause()
        for q in m.queues.values():
            q["active"] = False
    elif op == "delete":
        for t in ts:
            m.remove(t, bool(b.get("files")))
    elif op == "delcompleted":
        for t in [t for t in m.tasks.values() if t.status == "Completed"]:
            m.tasks.pop(t.id, None)
    elif op == "open" and ts:
        t = ts[0]
        if t.status == "Completed" and t.final_path and os.path.exists(t.final_path):
            open_path(t.final_path)
    elif op == "folder" and ts:
        open_path(os.path.dirname(ts[0].final_path) if ts[0].final_path else ts[0].folder)
    elif op == "moveq":
        for t in ts:
            if t.status != "Completed" and b.get("queue") in m.queues:
                t.queue = b["queue"]
                if t.status in ("Paused", "Error"):
                    t.status = "Queued"
    elif op == "props" and ts:
        t = ts[0]
        t.description, t.referer, t.cookies = b.get("description", ""), b.get("referer", ""), b.get("cookies", "")
        t.user, t.pwd = b.get("user", ""), b.get("pwd", "")
        t.speed_limit_kb = max(0, int(b.get("speed_limit_kb") or 0))
        t.nconn = max(1, min(32, int(b.get("nconn") or t.nconn)))
        name, folder = (b.get("name") or "").strip(), (b.get("folder") or "").strip()
        if (name and name != (t.filename or "")) or (folder and folder != t.folder):
            try:
                t.relocate(folder or None, name or None)
            except Exception as e:
                return {"err": str(e)}
    elif op == "zip" and ts:
        try:
            return {"rows": zip_listing(ts[0].real_url or ts[0].url, ts[0])}
        except Exception as e:
            return {"err": str(e)}
    elif op == "cfg_get":
        c = {k: v for k, v in CFG.items() if k not in ("token", "categories", "logins", "last_dir", "columns")}
        c["cats_text"] = cats_to_text()
        c["logins_text"] = "\n".join(f"{l['pattern']} | {l['user']} | {l['pass']}" for l in CFG["logins"])
        return c
    elif op == "cfg_set":
        for k, v in b["cfg"].items():
            if k == "cats_text":
                apply_cats_text(v)
            elif k == "logins_text":
                lg = []
                for line in v.splitlines():
                    p = [x.strip() for x in line.split("|")]
                    if len(p) >= 2 and p[0]:
                        lg.append({"pattern": p[0], "user": p[1], "pass": p[2] if len(p) > 2 else ""})
                CFG["logins"] = lg
            elif k in DEFAULT_CFG and k not in ("token", "categories", "logins", "last_dir", "columns"):
                d = DEFAULT_CFG[k]
                try:
                    CFG[k] = bool(v) if isinstance(d, bool) else int(float(v)) if isinstance(d, int) else str(v)
                except (ValueError, TypeError):
                    pass
        CFG["connections"] = max(1, min(32, CFG["connections"]))
        CFG["host_max_conn"] = max(0, min(64, CFG["host_max_conn"]))
        CFG["write_buffer_kb"] = max(64, min(16384, CFG["write_buffer_kb"]))
        if CFG["speed_mode"] not in ("auto", "manual"):
            CFG["speed_mode"] = "auto"
        save_cfg()
        set_startup(CFG["startup"])
    elif op == "qsave" and b.get("name") in m.queues:
        q = m.queues[b["name"]]
        for k in ("start", "stop"):
            v = (b.get(k) or "").strip()
            q[k] = f"{int(v.split(':')[0]):02d}:{v.split(':')[1]}" if re.match(r"^\d{1,2}:\d{2}$", v) else ""
        q["parallel"] = max(1, min(16, int(b.get("parallel") or 1)))
        q["days"], q["folder"] = b.get("days", list(range(7))), (b.get("folder") or "").strip()
        q["after"] = b.get("after") if b.get("after") in ("none", "exit", "sleep", "hibernate", "shutdown") else "none"
        q["shutdown"], q["exit"] = q["after"] == "shutdown", q["after"] == "exit"
        q["open_after"] = (b.get("open_after") or "").strip()
        q["start_on_startup"] = bool(b.get("start_on_startup"))
        q["retries"] = max(0, min(100, int(b.get("retries") or 0)))
        q["date"] = b.get("date", "").strip() if re.match(r"^\d{4}-\d{2}-\d{2}$", b.get("date", "").strip()) else ""
        m.save()
    elif op == "qnew" and b.get("name") and b["name"] not in m.queues:
        m.queues[b["name"]] = new_queue(b["name"])
    elif op == "qdel" and b.get("name") not in ("Main download queue", "Synchronization queue"):
        for t in m.tasks.values():
            if t.queue == b.get("name"):
                t.queue = ""
        m.queues.pop(b.get("name"), None)
    elif op == "qstart":
        m.start_queue(b.get("name"))
    elif op == "qstop":
        m.stop_queue(b.get("name"))
    elif op == "glist":
        return {"items": list(m.grabbers.values())}
    elif op == "gnew":
        gid = uuid.uuid4().hex[:6]
        m.grabbers[gid] = {"id": gid, "name": "New project", "url": "", "depth": 2, "types": "jpg png gif", "filters": "",
                           "folder": os.path.join(DEFAULT_DIR, "Grabber"), "queue": "", "schedule": "", "interval_h": 0,
                           "sync": False, "stay": False, "status": "Idle"}
    elif op == "gsave" and b.get("id") in m.grabbers:
        g = m.grabbers[b["id"]]
        for k in ("name", "url", "types", "filters", "folder", "queue", "schedule"):
            g[k] = str(b.get(k, "")).strip()
        for k in ("depth", "interval_h"):
            g[k] = max(0, int(b.get(k) or 0))
        g["sync"], g["stay"] = bool(b.get("sync")), bool(b.get("stay"))
        m.save()
    elif op == "grun" and b.get("id") in m.grabbers:
        g = m.grabbers[b["id"]]
        if re.match(r"^https?://", g["url"], re.I):
            m.run_grabber(g)
    elif op == "gstop":
        t = m.gthreads.get(b.get("id"))
        if t:
            t.stop_flag = True
    elif op == "gdel":
        m.grabbers.pop(b.get("id"), None)
    elif op == "ext":
        return {"path": export_extension(os.path.join(os.path.expanduser("~"), "Downloads", "UDM-Extension"))}
    elif op == "vinfo":
        try:
            return video_info(b["url"], b.get("referer", ""), b.get("cookies", ""))
        except Exception as e:
            return {"err": str(e)[:300]}
    elif op == "vpopup":
        # a video from the quality picker: ask first in the small download window (like a plain file),
        # unless the small window is switched off — then start at once, like before
        if not CFG.get("popup_dialog", True):
            m.add_task(new_video_task(b["url"], b), start=True)
            return {"ok": True, "started": True}
        v = {"height": int(b.get("height") or 0), "cont": (b.get("cont") or "mp4"), "title": b.get("title") or "",
             "size": b.get("size"), "thumb": b.get("thumb") or "", "folder": (b.get("folder") or "").strip(),
             "start": b.get("start") or "", "end": b.get("end") or "", "exact": bool(b.get("exact")),
             "subs": b.get("subs") or "", "fid": b.get("fid") or "", "muxed": bool(b.get("muxed"))}
        open_popup(b["url"].strip(), b.get("referer", ""), b.get("cookies", ""), video=v)
        return {"ok": True}
    elif op == "vdl":
        m.add_task(new_video_task(b["url"], b), start=True)
    elif op == "vplaylist":
        try:
            return video_playlist(b["url"], b.get("referer", ""), b.get("cookies", ""))
        except Exception as e:
            return {"err": str(e)[:300]}
    elif op == "vplaylist_dl":
        folder = (b.get("folder") or "").strip() or os.path.join(category_folder("Musics" if b.get("cont") == "mp3" else "Videos"), safe_name(b.get("title") or "Playlist"))
        qn = "Main download queue"
        titles = b.get("titles") or []
        for i, u in enumerate(b.get("urls", [])):
            if re.match(r"^https?://", u, re.I):
                t = new_video_task(u, dict(b, folder=folder), title=(titles[i] if i < len(titles) else ""))
                t.queue = qn
                m.add_task(t, start=False)
        m.start_queue(qn)
    elif op == "vlist":
        return {"items": G.videos[::-1]}
    elif op == "vclear":
        del G.videos[:]
    elif op == "vtools":
        yt, ver = tool_path("yt-dlp"), None
        if yt:
            try:
                ver = run_tool([yt, "--version"], 20).stdout.strip()
            except Exception:
                pass
        return {"ytdlp": ver, "ffmpeg": bool(tool_path("ffmpeg")), "deno": bool(tool_path("deno"))}
    elif op == "ytdlp_update":
        return {"out": update_ytdlp_verified()}
    elif op == "export":
        return {"text": list_write(ts or list(m.tasks.values()))}
    elif op == "import":
        n = 0
        for it in list_parse(b.get("text", "")):
            m.add_url(it["url"], queue=b.get("queue") or "Main download queue", start=False, referer=it.get("referer", ""),
                      cookies=it.get("cookies", ""), description=it.get("description", ""))
            n += 1
        return {"n": n}
    elif op == "newurl" and ts and re.match(r"^(https?|ftp)://", b.get("url", ""), re.I):
        t = ts[0]
        t.url, t.real_url = b["url"].strip(), None
        if t.status in ("Error", "Paused", "Queued"):
            t.start()
    elif op == "redo" and ts:
        t = ts[0]
        t.pause()
        t.join(10)
        t.segments, t.size, t.overwrite, t.fixed_name = [], None, True, t.filename
        t.final_path, t.part_file, t.status, t.error, t.finished, t.hash_result = None, None, "Paused", "", 0, ""
        t.start()
    elif op == "probe":
        try:
            t = Task(b["url"])
            t.referer, t.cookies = b.get("referer", ""), b.get("cookies", "")
            size, res, name, mt, real = t._probe()
            return {"size": size, "resume": res, "name": name, "mtime": mt, "url": real}
        except Exception as e:
            return {"err": str(e)[:200]}
    elif op == "hash" and ts:
        algo = b.get("algo") if b.get("algo") in ("md5", "sha1", "sha256") else "sha256"
        if ts[0].final_path and os.path.exists(ts[0].final_path):
            return {"hash": file_hash(ts[0].final_path, algo)}
        return {"err": "The file is not finished yet"}
    elif op == "ext_info":
        h = native_host_exe()
        return {"browsers": [ext_browser_info(k) for k in BROWSERS], "host": bool(h and os.path.exists(h)), "frozen": bool(getattr(sys, "frozen", False))}
    elif op == "ext_prepare" and b.get("browser") in BROWSERS:
        k = b["browser"]
        prepare_extension(k)
        reg = register_native([k])
        return dict(ext_browser_info(k), reg=reg)
    elif op == "ext_open" and b.get("browser") in BROWSERS:
        return ext_open(b["browser"], b.get("what", "manage"))
    elif op == "ext_check" and b.get("browser") in BROWSERS:
        k = b["browser"]
        info = ext_browser_info(k)
        info["others"] = [x for x, v in G.ext.items() if x != k and time.time() - v.get("last", 0) < 90]
        return info
    elif op == "popup_new" and re.match(r"^(https?|ftp)://", (b.get("url") or "").strip(), re.I):
        if not CFG.get("popup_dialog", True):
            m.add_url(b["url"].strip(), start=True, referer=b.get("referer", ""), cookies=b.get("cookies", ""))
            return {"ok": True, "started": True}
        open_popup(b["url"].strip(), b.get("referer", ""), b.get("cookies", ""))
        return {"ok": True}
    elif op == "popup_info":
        G.last_popup = time.time()
        pd = G.pending.get(b.get("pid"))
        if not pd:
            return {"err": "This download window is no longer valid."}
        return {"url": pd["url"], "host": url_host(pd["url"]), "ssl": ssl_state(pd["url"]), "lang": CFG["language"], "theme": CFG["theme"],
                "conns": CFG["connections"], "mode": CFG.get("speed_mode", "auto"), "show_progress": CFG["show_progress"],
                "task": pd.get("task"), "cats": [{"name": n, "folder": category_folder(n)} for n in CFG["categories"]],
                "default_dir": DEFAULT_DIR}
    elif op == "popup_probe":
        G.last_popup = time.time()
        pd = G.pending.get(b.get("pid"))
        if not pd:
            return {"err": "This download window is no longer valid."}
        v = pd.get("video")
        if v:                                       # a video: the name/size are already known, no probing
            cont = v.get("cont") or "mp4"
            ext = "mp3" if cont == "mp3" else cont
            name = safe_name(v.get("title") or "video") + "." + ext
            cat = "Musics" if cont == "mp3" else "Videos"
            folder = v.get("folder") or category_folder(cat)
            return {"name": name, "size": v.get("size"), "resume": True, "err": "", "host": url_host(pd["url"]),
                    "ssl": ssl_state(pd["url"]), "category": cat, "folder": folder, "path": os.path.join(folder, name)}
        t = Task(pd["url"], DEFAULT_DIR, None)
        t.referer, t.cookies = pd["referer"], pd["cookies"]
        guess = safe_name(urllib.parse.unquote(os.path.basename(urllib.parse.urlparse(pd["url"]).path)) or "download")
        try:
            size, res, name, mt, real = t._probe()
            name = safe_name(name or guess)
            err = ""
        except Exception as e:
            size, res, name, err = None, False, guess, str(e)[:300]
        cat = categorize(pd["url"], name)
        folder = category_folder(cat)
        return {"name": name, "size": size, "resume": res, "err": err, "host": url_host(pd["url"]), "ssl": ssl_state(pd["url"]),
                "category": cat, "folder": folder, "path": os.path.join(folder, name)}
    elif op == "popup_start":
        pd = G.pending.get(b.get("pid"))
        if not pd:
            return {"err": "This download window is no longer valid."}
        path = (b.get("path") or "").strip()
        folder, name = (os.path.dirname(path) or None), os.path.basename(path)
        cat = b.get("category") if b.get("category") in CFG["categories"] else "Uncategorized"
        n = b.get("nconn")
        if pd.get("video"):
            v = dict(pd["video"])
            v["folder"] = folder
            v["referer"], v["cookies"] = pd["referer"], pd["cookies"]
            t = new_video_task(pd["url"], v)
            t.nconn = max(1, min(32, int(n or CFG["connections"])))
            t.category = cat
            out = safe_name(os.path.splitext(name)[0][:150]) if name else ""
            t.vout = out
            if out:
                t.filename = out + "." + ("mp3" if t.vcont == "mp3" else t.vcont)
            t.post_action = b.get("after") if b.get("after") in ("open", "folder") else ""
            m.add_task(t, start=not b.get("later"))
            pd["task"] = t.id
            return {"id": t.id}
        t = m.add_url(pd["url"], folder=folder, category=cat, filename=name or None, nconn=max(1, min(32, int(n or CFG["connections"]))),
                      start=not b.get("later"), referer=pd["referer"], cookies=pd["cookies"])
        t.post_action = b.get("after") if b.get("after") in ("open", "folder") else ""
        pd["task"] = t.id
        return {"id": t.id}
    elif op == "popup_cancel":
        G.pending.pop(b.get("pid"), None)
    elif op == "popup_task":
        G.last_popup = time.time()
        t = m.tasks.get(b.get("id"))
        if not t:
            return {"gone": True}
        return {"status": t.status, "name": t.filename, "size": t.size, "done": t.live_bytes, "speed": t.speed, "conn": t.nworkers,
                "ctarget": t.target, "cap": t._conn_cap(), "hist": t.hist[-40:], "err": t.error, "path": t.final_path or "",
                "ssl": ssl_state(t.real_url or t.url), "resumable": t.resumable}
    elif op == "pick_folder":
        start = b.get("start") or DEFAULT_DIR
        try:
            if IS_WIN:
                ps = ("Add-Type -AssemblyName System.Windows.Forms; $f=New-Object System.Windows.Forms.FolderBrowserDialog; "
                      "$f.SelectedPath=$env:UDM_START; $f.Description='UDM'; if($f.ShowDialog() -eq 'OK'){[Console]::Out.Write($f.SelectedPath)}")
                r = subprocess.run(["powershell", "-NoProfile", "-STA", "-Command", ps], capture_output=True, text=True, timeout=300,
                                   creationflags=NOWIN, env=dict(os.environ, UDM_START=start))
            else:
                r = subprocess.run(["zenity", "--file-selection", "--directory", f"--filename={start}/"], capture_output=True, text=True, timeout=300)
            return {"path": r.stdout.strip()}
        except Exception as e:
            return {"err": str(e)[:100]}
    elif op == "ext_status":
        h = native_host_exe()
        return {"browsers": [ext_browser_info(k) for k in BROWSERS], "host": bool(h and os.path.exists(h)),
                "frozen": bool(getattr(sys, "frozen", False)), "capture": CFG["capture_enabled"], "win": IS_WIN,
                "summary": ext_summary()}
    elif op == "ext_repair" and b.get("browser") in BROWSERS:
        k = b["browser"]
        prepare_extension(k)
        reg = register_native([k])
        _EXT_DET.pop(k, None)
        return dict(ext_browser_info(k), reg=reg)
    elif op == "win":
        return win_control(b.get("what"), b.get("prefix"))
    elif op == "update_check":
        return check_for_updates()
    elif op == "update_download":
        if not (G.update and G.update.get("available")):
            return {"ok": False, "error": "no update"}
        if (G.update_dl or {}).get("state") == "downloading":
            return {"ok": True}
        threading.Thread(target=_download_update, daemon=True).start()
        return {"ok": True}
    elif op == "update_install":
        return _install_update()
    elif op == "cancel_shutdown":
        subprocess.Popen("shutdown /a", shell=True)
    elif op == "quit":
        threading.Thread(target=quit_app, daemon=True).start()
    return {"ok": True}


def clip_text():
    if not IS_WIN:
        return ""
    try:
        import ctypes
        u, k = ctypes.windll.user32, ctypes.windll.kernel32
        u.OpenClipboard.argtypes = [ctypes.c_void_p]
        u.GetClipboardData.argtypes = [ctypes.c_uint]
        u.GetClipboardData.restype = ctypes.c_void_p
        k.GlobalLock.argtypes = [ctypes.c_void_p]
        k.GlobalLock.restype = ctypes.c_void_p
        k.GlobalUnlock.argtypes = [ctypes.c_void_p]
        if not u.OpenClipboard(None):
            return ""
        try:
            h = u.GetClipboardData(13)          # CF_UNICODETEXT
            if not h:
                return ""
            p = k.GlobalLock(h)
            try:
                return ctypes.wstring_at(p)
            finally:
                k.GlobalUnlock(h)
        finally:
            u.CloseClipboard()
    except Exception:
        return ""


def clip_loop():
    G.last_clip = clip_text()
    while not G.quit:
        time.sleep(1)
        if not CFG["clipboard_monitor"]:
            continue
        txt = clip_text()
        if not txt or txt == G.last_clip:
            continue
        G.last_clip = txt
        urls = re.findall(r"(?:https?|ftp)://[^\s\"'<>]+", txt)
        if urls and (len(urls) > 1 or urls[0].lower().startswith("ftp") or should_capture(urls[0])):
            push_incoming({"urls": urls})


def engine_loop():
    n = 0
    while not G.quit:
        time.sleep(0.5)
        n += 1
        now, m = time.time(), G.mgr
        for t in list(m.tasks.values()):
            cur, dt = t.live_bytes, now - t.last_time
            if dt >= 0.5:
                inst = max(0, cur - t.last_bytes) / dt
                t.speed = inst if t.speed == 0 else 0.6 * t.speed + 0.4 * inst
                t.last_bytes, t.last_time = cur, now
            if t.status != "Downloading":
                t.speed = 0
            elif n % 2 == 0:
                t.hist.append(int(t.speed))
                del t.hist[:-60]
            prev = G.prev.get(t.id)
            if prev != t.status:
                if t.status == "Error" and prev is not None:
                    play_sound("error")
                    G.events.append({"k": "error", "name": t.filename or t.url, "msg": t.error})
                G.prev[t.id] = t.status
        if n % 2 == 0:
            m.tick()
        while True:
            try:
                kind, data = m.events.get_nowait()
            except queue.Empty:
                break
            if kind == "done":
                play_sound("done")
                G.events.append({"k": "done", "id": data.id, "name": data.filename})
            elif kind == "after":
                if data == "exit":
                    quit_app()
                elif IS_WIN and data == "shutdown":
                    subprocess.Popen("shutdown /s /t 60", shell=True)
                    G.events.append({"k": "shutdown"})
                elif IS_WIN and data == "hibernate":
                    subprocess.Popen("shutdown /h", shell=True)
                elif IS_WIN and data == "sleep":
                    subprocess.Popen("rundll32.exe powrprof.dll,SetSuspendState 0,1,0", shell=True)
        if n % 10 == 0:
            m.save()
        if n % 4 == 0 and G.tray:
            act = [t for t in m.tasks.values() if t.status == "Downloading"]
            try:
                G.tray.title = f"{APP_NAME}\n{len(act)} active · {human_size(sum(t.speed for t in act))}/s"
            except Exception:
                pass


# ------------------------------------------------------------------ self-update from GitHub releases
UPD_REPO = "ahmedmidopro/Unlimited-Download-Manager"
UPD_API = "https://api.github.com/repos/" + UPD_REPO + "/releases/latest"


def _build_number():
    """The build number stamped into the app at build time (build.txt next to the exe).
    0 means unknown (an older build without the stamp): any release counts as newer."""
    bases = []
    if getattr(sys, "frozen", False):
        bases.append(os.path.dirname(sys.executable))
    bases.append(getattr(sys, "_MEIPASS", ""))
    bases.append(os.path.dirname(os.path.abspath(__file__)))
    for base in bases:
        if not base:
            continue
        try:
            with open(os.path.join(base, "build.txt"), "r", encoding="utf-8") as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            continue
    return 0


def _github_latest_release():
    req = urllib.request.Request(UPD_API, headers={"User-Agent": APP_NAME, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode("utf-8"))


def check_for_updates():
    """Ask GitHub for the latest release and compare it with this build. Never raises."""
    try:
        rel = _github_latest_release()
    except Exception as e:
        return {"ok": False, "error": str(e)[:120]}
    tag = str(rel.get("tag_name") or "")
    m = re.match(r"build-(\d+)", tag)
    latest = int(m.group(1)) if m else 0
    setup_url, setup_size, portable_url = "", 0, ""
    for a in rel.get("assets") or []:
        if a.get("name") == "UDM-Setup.exe":
            setup_url = a.get("browser_download_url") or ""
            setup_size = a.get("size") or 0
        elif a.get("name") == "UDM-Portable.zip":
            portable_url = a.get("browser_download_url") or ""
    info = {"ok": True, "available": latest > G.build_no, "latest": latest, "current": G.build_no,
            "tag": tag, "notes": (rel.get("body") or "")[:600],
            "setup_url": setup_url, "setup_size": setup_size, "portable_url": portable_url}
    G.update = info
    CFG["last_update_check"] = time.time()
    save_cfg()
    return info


def _refresh_icon_cache_once():
    """Refresh the Windows icon cache once per build, so a new program icon shows on the
    desktop / taskbar by itself. The exe already carries the new icon; only Explorer's
    saved copy is stale. Runs in a background thread, never raises, never kills Explorer:
    ie4uinit clears the cache and SHChangeNotify tells Explorer to re-read the icons."""
    if not IS_WIN:
        return
    try:
        if G.build_no and CFG.get("icon_refresh_build") == G.build_no:
            return
    except Exception:
        return
    try:
        import subprocess
        sysdir = os.environ.get("SystemRoot", r"C:\Windows")
        ie = os.path.join(sysdir, "System32", "ie4uinit.exe")
        if os.path.exists(ie):
            for param in ("-ClearIconCache", "-show"):
                try:
                    subprocess.run([ie, param], timeout=25,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    break
                except Exception:
                    continue
        try:
            import ctypes
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
        except Exception:
            pass
        CFG["icon_refresh_build"] = G.build_no
        save_cfg()
    except Exception as e:
        _tray_log(f"icon cache refresh failed: {e!r}")


def _auto_update_check():
    """Check at startup and then once an hour while the program runs (at most every hour)."""
    while True:
        try:
            if CFG.get("auto_update_check", True) and time.time() - CFG.get("last_update_check", 0) >= 3600:
                check_for_updates()
        except Exception:
            pass
        time.sleep(3600)


def _download_update():
    """Download the new installer in the background; progress lands in G.update_dl."""
    info = G.update or {}
    if not info.get("setup_url"):
        return
    G.update_dl = {"state": "downloading", "pct": 0}
    try:
        tmp = os.path.join(tempfile.gettempdir(), "UDM-Setup.exe")
        req = urllib.request.Request(info["setup_url"], headers={"User-Agent": APP_NAME})
        with urllib.request.urlopen(req, timeout=30) as r, open(tmp, "wb") as f:
            total = int(r.headers.get("Content-Length") or info.get("setup_size") or 0)
            done = 0
            while True:
                chunk = r.read(1024 * 256)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if total:
                    G.update_dl["pct"] = round(done * 100 / total)
        G.update_dl = {"state": "ready", "path": tmp}
    except Exception as e:
        G.update_dl = {"state": "error", "error": str(e)[:120]}


def _is_installed_version():
    """True when running from an Inno Setup install (the uninstaller sits next to the exe)."""
    if not getattr(sys, "frozen", False):
        return False
    return os.path.exists(os.path.join(os.path.dirname(sys.executable), "unins000.exe"))


def _install_update():
    """Start the downloaded installer and quit: a helper waits for this process to exit,
    installs silently, then starts the new version. Returns a dict for the UI."""
    dl = G.update_dl or {}
    if dl.get("state") != "ready" or not os.path.exists(dl.get("path", "")):
        return {"ok": False, "error": "not downloaded"}
    if not IS_WIN or not _is_installed_version():
        return {"ok": False, "error": "portable"}   # portable copy: the user installs the new zip by hand
    bat = os.path.join(tempfile.gettempdir(), "udm-update.bat")
    try:
        with open(bat, "w", encoding="utf-8") as f:
            f.write("@echo off\r\n")
            f.write(":wait\r\n")
            f.write('tasklist /FI "IMAGENAME eq UDM.exe" 2>nul | find /I "UDM.exe" >nul\r\n')
            f.write("if %ERRORLEVEL%==0 (timeout /t 1 /nobreak >nul & goto wait)\r\n")
            f.write(f'"{dl["path"]}" /SILENT\r\n')
            f.write(f'start "" "{sys.executable}"\r\n')
            f.write('(goto) 2>nul & del "%~f0"\r\n')
        os.startfile(bat)
    except Exception as e:
        return {"ok": False, "error": str(e)[:120]}
    threading.Thread(target=lambda: (time.sleep(1.5), quit_app()), daemon=True).start()
    return {"ok": True}


def update_ui_state():
    u = dict(G.update or {})
    dl = G.update_dl or {}
    u["dl_state"] = dl.get("state", "idle")
    u["dl_pct"] = dl.get("pct", 0)
    u["dl_error"] = dl.get("error", "")
    u["current"] = G.build_no
    u["portable"] = not _is_installed_version()
    return u


def _tray_log(msg):
    """Save tray errors next to the settings file, so a missing tray icon can be diagnosed."""
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(os.path.join(APP_DIR, "udm_tray.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + str(msg) + "\n")
    except Exception:
        pass


def setup_tray():
    try:
        import pystray
        from PIL import Image
    except ImportError as e:
        _tray_log(f"pystray import failed: {e!r}")
        return False
    try:
        img = Image.open(io.BytesIO(base64.b64decode(ICON_B64)))
        def pause_all():
            for t in list(G.mgr.tasks.values()):
                t.pause()

        def resume_all():
            for t in list(G.mgr.tasks.values()):
                t.start()
        menu = pystray.Menu(pystray.MenuItem("Open Unlimited Download Manager", lambda: ensure_ui(), default=True),
                            pystray.MenuItem("Resume all", lambda: resume_all()),
                            pystray.MenuItem("Pause all", lambda: pause_all()),
                            pystray.Menu.SEPARATOR,
                            pystray.MenuItem("Exit", lambda: quit_app()))
        G.tray = pystray.Icon("udm", img, APP_NAME, menu)
        G.tray.run_detached()
        return True
    except Exception as e:
        _tray_log(f"tray setup failed: {e!r}")
        G.tray = None
        return False


def quit_app():
    G.quit = True
    m = G.mgr
    for t in list(m.tasks.values()):
        t.pause()
    for t in list(m.tasks.values()):
        t.join(3)
    m.save()
    save_cfg()
    try:
        if G.tray:
            G.tray.stop()
    except Exception:
        pass
    os._exit(0)


def main():
    ap = argparse.ArgumentParser(description=APP_NAME)
    ap.add_argument("urls", nargs="*")
    ap.add_argument("--minimized", action="store_true")
    ap.add_argument("--register-native", action="store_true", help="register the browser host (used by the installer)")
    ap.add_argument("--unregister-native", action="store_true")
    ap.add_argument("--write-extension", nargs=2, metavar=("DIR", "BROWSER"))
    ap.add_argument("--no-token", action="store_true")
    args = ap.parse_args()
    load_cfg()
    if args.register_native:
        if getattr(sys, "frozen", False):
            CFG["app_exe"] = sys.executable
            save_cfg()
        for k in BROWSERS:
            prepare_extension(k)
        register_native()
        return
    if args.unregister_native:
        register_native(remove=True)
        return
    if args.write_extension:
        write_extension(args.write_extension[0], args.write_extension[1], embed_token=not args.no_token)
        return
    ensure_tools()
    urls = [u for u in args.urls if re.match(r"^(https?|ftp)://", u, re.I)]
    if send_to_running(urls):
        return
    G.server = start_server()
    if not G.server:
        msg = f"Port {CFG['server_port']} is busy. Change 'server_port' in {CFG_FILE} and start again."
        if IS_WIN:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, msg, APP_NAME, 0x10)
        else:
            print(msg)
        return
    G.mgr = Manager()
    G.mgr.load()
    for q in G.mgr.queues.values():                  # queues set to start with the program (IDM scheduler)
        if q.get("start_on_startup") and any(t.queue == q["name"] and t.status in ("Paused", "Error", "Queued")
                                             for t in G.mgr.tasks.values()):
            G.mgr.start_queue(q["name"])
    G.build_no = _build_number()
    threading.Thread(target=startup_integration, daemon=True).start()
    threading.Thread(target=engine_loop, daemon=True).start()
    threading.Thread(target=clip_loop, daemon=True).start()
    threading.Thread(target=_auto_update_check, daemon=True).start()
    threading.Thread(target=_refresh_icon_cache_once, daemon=True).start()
    tray = CFG["tray"] and setup_tray()
    if CFG["tray"] and not tray and IS_WIN:
        # the tray icon is what keeps UDM alive after closing the window: if it could
        # not start, say so plainly instead of silently quitting on close
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, "تعذّر تشغيل أيقونة شريط المهام، لذلك إغلاق النافذة سيغلق البرنامج تماماً.\nتم حفظ السبب في ملف udm_tray.log بجانب ملف الإعدادات.", APP_NAME, 0x30)
        except Exception:
            pass
    if urls:
        G.incoming.append({"urls": urls})
    if not args.minimized or urls:
        if open_ui() and not tray:
            quit_app()
    while not G.quit:
        time.sleep(1)
        if G.want_ui:
            G.want_ui = False
            if open_ui() and not tray:
                quit_app()
        if tray:
            if G.last_poll and not ui_alive() and not G.notified:
                G.notified = True                       # window closed: keep running in the tray
                try:
                    G.tray.notify("Still running in the system tray.", APP_NAME)
                except Exception:
                    pass
            elif ui_alive():
                G.notified = False
            continue
        if popup_alive():
            continue
        waited = time.time() - G.started
        if G.last_poll == 0 and waited > 90:
            quit_app()
        if G.last_poll and time.time() - G.last_poll > 8:
            if (G.proc is not None and G.proc.poll() is not None) or time.time() - G.last_poll > 150:
                quit_app()



ICON_B64 = (
"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"
)


WOLF_B64 = (
"/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAUEBAQEAwUEBAQGBQUGCA0ICAcHCBALDAkNExAUExIQ"
"EhIUFx0ZFBYcFhISGiMaHB4fISEhFBkkJyQgJh0gISD/2wBDAQUGBggHCA8ICA8gFRIVICAgICAg"
"ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICD/wAARCAGAAQADASIA"
"AhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQA"
"AAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3"
"ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWm"
"p6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEA"
"AwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSEx"
"BhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElK"
"U1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3"
"uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD4+pcZ"
"pQKdt4zXdY52yLFOoIpKQxfpSUUYpgLSj0pKcAadhNgBg0+nRnY4bAOOeRkUpwTmqRm2IpNSqwPB"
"5qOlAxVq6JZLtyMinJGSCeMD35pI2xwamAwdw5HetEk9TJuxE6ZGR+NRheavBPl3KMqeKgxhsgc0"
"3DqKMrkYTnJp2OelSAZHTmnBD1wcetCRVyIJ6VIiHoamSPJqwsBNaKFyHIqCDnmpBA2RxWhHbFsc"
"VbjtPmXIreNBsxlVSMtYwjZI4q3C0I4EfzdiavyWJI3474P1pyWDcYSuhUZJnNKrBopJbPJKEOBk"
"cEnGKbcWpV1XbyBmtaJjE6h4wdvQ1NPEsnmTrGSOg461p7JWMXVaZzixZk24yMc0y4tvL5xwRkVs"
"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"
)


POPUP_HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>__APP__</title><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="__ICON__">
<style>
:root{--tx:#eef3ff;--mut:#97a6d0;--ln:rgba(130,160,255,.2);--card:rgba(22,30,70,.58);--inp:rgba(8,12,34,.72);--b1:#2d7bff;--b2:#1550e6;--ok:#34d399;--bad:#fb7185;--warn:#fbbf24}
*{box-sizing:border-box;margin:0;padding:0}html,body{height:100%}
body{font:14px 'Segoe UI',Tahoma,system-ui,sans-serif;color:var(--tx);overflow:hidden;user-select:none;
background:radial-gradient(520px 340px at 85% -5%,rgba(70,90,255,.34),transparent 65%),radial-gradient(520px 380px at -5% 105%,rgba(110,60,220,.28),transparent 65%),linear-gradient(160deg,#0a1233,#0a0e29 58%,#110b2b)}
button{font:inherit;color:inherit;border:0;cursor:pointer}input,select{font:inherit;color:var(--tx);outline:0}
.win{height:100%;display:flex;flex-direction:column;padding:14px 18px 16px;gap:12px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:2px 4px}
.brand{display:flex;align-items:center;gap:10px;font-size:17px;font-weight:600;direction:ltr}.brand svg{filter:drop-shadow(0 0 8px rgba(60,130,255,.9))}
.sec{display:flex;align-items:center;gap:8px;font-size:13px;color:#cfe0ff}.sec svg{flex:none}.sec.ok{color:#a8c8ff}.sec.warn{color:var(--warn)}.sec.bad{color:var(--bad)}
main{flex:1;min-height:0;display:flex;flex-direction:column;gap:10px;overflow:auto}main::-webkit-scrollbar{width:6px}main::-webkit-scrollbar-thumb{background:#33407a;border-radius:6px}
.card{background:var(--card);border:1px solid var(--ln);border-radius:16px;padding:16px 18px;backdrop-filter:blur(10px);box-shadow:inset 0 1px 0 rgba(255,255,255,.05)}
h4{font-size:14px;font-weight:500;color:#dfe8ff;margin-bottom:10px;direction:ltr;text-align:left}
.fico svg{width:100%;height:100%;display:block}.fi{display:flex;gap:18px;align-items:flex-start}.fico{flex:none;width:76px;height:86px}
.fcol{flex:1;min-width:0}.fcol label{display:block;font-size:14px;margin-bottom:8px;direction:ltr;text-align:left;color:#dfe8ff}
.in{width:100%;height:38px;border-radius:9px;border:1px solid var(--ln);background:var(--inp);padding:0 12px;direction:ltr;text-align:left;user-select:text}.in:focus{border-color:#5b8cff}
.meta{display:flex;flex-wrap:wrap;gap:6px 22px;margin-top:10px;font-size:13px;color:#c5d2f5;justify-content:space-between}.meta .ok{color:var(--ok);display:flex;align-items:center;gap:7px}.meta .ok i{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok)}.meta .no{color:var(--warn)}
.meta b{font-weight:500;color:#fff;direction:ltr;unicode-bidi:isolate}
.prow{display:flex;gap:10px;direction:ltr}.prow .in{flex:1}.ghost{unicode-bidi:plaintext;height:38px;padding:0 20px;border-radius:9px;background:rgba(70,90,170,.28);border:1px solid var(--ln);white-space:nowrap;transition:.15s}.ghost:hover{background:rgba(90,120,230,.4)}
.cats{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;justify-content:flex-start}.chip{display:inline-flex;align-items:center;gap:7px;height:32px;padding:0 14px;border-radius:16px;background:rgba(40,52,110,.55);border:1px solid var(--ln);font-size:13px;transition:.15s}
.chip:hover{border-color:#6b8cff}.chip.on{background:linear-gradient(90deg,#3a7bff,#7a4dff);border-color:transparent;box-shadow:0 0 14px rgba(90,100,255,.55);font-weight:600}
.qcards{display:flex;flex-direction:column;gap:8px;margin-top:6px}
.qcard{display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:14px;background:rgba(20,32,72,.6);border:1px solid var(--ln);cursor:pointer;transition:.15s}
.qcard:hover{border-color:#6b8cff}
.qcard.on{background:linear-gradient(90deg,rgba(58,123,255,.35),rgba(122,77,255,.35));border-color:#3a7bff;box-shadow:0 0 14px rgba(90,100,255,.35)}
.qcard.off{opacity:.45;pointer-events:none}
.qb{min-width:64px;text-align:center;padding:4px 8px;border-radius:8px;font-weight:800;font-size:13px}
.qb.k4{background:linear-gradient(90deg,#7a4dff,#3a7bff);color:#fff}
.qb.hd{background:#1d4ed8;color:#dbeafe}
.qb.sd{background:#334155;color:#cbd5e1}
.qt{font-weight:700;font-size:15px}
.qm{color:var(--mut);font-size:13px}
.qs{margin-inline-start:auto;font-weight:600;font-size:13px}
.qr{color:#fbbf24;font-size:12px;font-weight:700}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px 22px}.g2 label{display:flex;flex-direction:column;gap:7px;font-size:13px;color:#dfe8ff;unicode-bidi:plaintext}
select.in{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' fill='none' stroke='%23aab8e8' stroke-width='1.8'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;padding-right:32px}
select.in option{background:#0d1538}
footer .r{margin-left:auto}footer{display:flex;align-items:center;justify-content:space-between;gap:10px}footer .r{display:flex;gap:10px}
.btn{height:38px;padding:0 22px;border-radius:9px;background:rgba(60,78,150,.4);border:1px solid var(--ln);font-weight:500;transition:.15s;display:inline-flex;align-items:center;gap:9px;white-space:nowrap}.btn:hover{background:rgba(90,120,230,.45)}
.btn.pri{background:linear-gradient(180deg,#3b86ff,#1d5cf0);border-color:rgba(150,190,255,.6);box-shadow:0 0 18px rgba(50,110,255,.55);font-weight:600}.btn.pri:hover{filter:brightness(1.12)}.btn:disabled{opacity:.5;pointer-events:none}
.skl{height:14px;border-radius:7px;background:linear-gradient(90deg,rgba(120,150,255,.1),rgba(120,150,255,.25),rgba(120,150,255,.1));background-size:200% 100%;animation:sk 1.2s linear infinite}@keyframes sk{to{background-position:-200% 0}}
.errb{margin-top:10px;font-size:12.5px;color:var(--bad);direction:ltr;text-align:left;user-select:text;line-height:1.5}
/* progress view */
.top{display:flex;align-items:center;gap:18px}.top .nm{flex:1;min-width:0;font-size:24px;font-weight:500;direction:ltr;text-align:left;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.top .sz{display:flex;align-items:center;gap:8px;color:#dfe8ff;font-size:17px;direction:ltr}.top .sz i{width:9px;height:9px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok)}
.bar{position:relative;height:46px;border-radius:12px;background:rgba(5,8,24,.7);border:1px solid var(--ln);margin-top:16px;overflow:hidden;direction:ltr}
.bar>i{position:absolute;inset:0 auto 0 0;width:0;border-radius:12px;background:linear-gradient(90deg,#2d5bff,#1fa5ff 55%,#22d3a6);box-shadow:0 0 24px rgba(40,160,255,.6),inset 0 1px 0 rgba(255,255,255,.35);transition:width .5s cubic-bezier(.2,.7,.2,1)}
.bar>b{position:absolute;inset:0;display:grid;place-items:center;font-size:27px;font-weight:600;text-shadow:0 2px 8px rgba(0,0,0,.5)}
.bar.dim>i{filter:saturate(.3) brightness(.8);box-shadow:none}.bar.done>i{background:linear-gradient(90deg,#16a870,#34d399)}.bar.err>i{background:linear-gradient(90deg,#be3a55,#fb7185)}
.sub{margin-top:8px;font-size:13.5px;color:#cdd9f7;direction:ltr;text-align:left}.sub span{color:var(--mut)}
.stats{display:grid;grid-template-columns:1fr 1fr 1.25fr;grid-template-rows:1fr 1fr;gap:10px;min-height:150px;direction:ltr}
.tile{background:rgba(10,15,42,.55);border:1px solid var(--ln);border-radius:14px;padding:10px 16px;display:flex;flex-direction:column;gap:5px;justify-content:center}
.tile small{display:flex;align-items:center;gap:8px;font-size:14px;color:#dfe8ff}.tile small svg{color:#5fb0ff}.tile small .sp{margin-inline-start:auto;color:#ffd24d}
.tile b{white-space:nowrap;font-size:25px;font-weight:600;color:#6fe3c4;letter-spacing:.2px}.tile b em{font-style:normal;font-size:14px;font-weight:400;color:var(--mut)}
.tile.g{grid-column:3;grid-row:1/3;padding:14px 14px 10px;justify-content:flex-start}.tile.g small{justify-content:flex-end;font-size:15px;font-weight:500}
.tile.g svg.ch{flex:1;width:100%;min-height:0;margin-top:6px}
.note{font-size:13px;margin-top:10px;direction:ltr;text-align:left}.note.err{color:var(--bad);user-select:text}
.doneb{display:flex;align-items:center;gap:10px;color:var(--ok);font-size:18px;font-weight:600;margin-top:12px;direction:ltr}
</style></head><body><div class="win"><header><div class="brand"><svg width="22" height="22" viewBox="0 0 24 24" fill="#3f8cff"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg><span>__APP__</span></div><div class="sec ok" id="sec"></div></header><main id="view"></main><footer id="foot"></footer></div>
<script>
const T="__TOKEN__",PID="__PID__",APP="__APP__",$=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const api=async(op,b={})=>(await fetch('/api/act',{method:'POST',headers:{'X-UDM-Token':T,'Content-Type':'application/json'},body:JSON.stringify({op,...b})})).json();
const TX={en:{secure:'Secure and trusted link (HTTPS)',relaxed:'HTTPS – the website certificate chain is incomplete',insecure:'Not encrypted (HTTP)',src:'Source',size:'Size',resume:'Resume supported',nores:'Resume not supported',chg:'Change…',conn:'Connections',after:'After download',auto:'Auto (smart) ⚡',max:'connections (max speed ⚡)',cn:'connections',none:'Nothing',openf:'Open the file',openF:'Open the folder',cancel:'Cancel',later:'Download later',start:'Start download',reading:'Reading file information…',stats:'Download Statistics',speed:'Speed',dled:'Downloaded',left:'Time Left',active:'Active Connections',link:'Connection status',pause:'Pause',resumeb:'Resume',done:'Download complete',openb:'Open',closeb:'Close',retry:'Try again',paused:'Paused',queued:'Waiting…',nofo:'Could not read the file information (you can still try to download):',added:'Added to the list',gone:'This window is no longer valid.'},
ar:{secure:'الرابط آمن وموثوق (HTTPS)',relaxed:'HTTPS – سلسلة شهادة الموقع غير مكتملة',insecure:'غير مشفّر (HTTP)',src:'المصدر',size:'الحجم',resume:'يدعم الاستكمال',nores:'لا يدعم الاستكمال',chg:'تغيير…',conn:'تقسيم الاتصال (Connections)',after:'إجراء ما بعد التحميل',auto:'تلقائي ذكي ⚡',max:'اتصال (أقصى سرعة ⚡)',cn:'اتصال',none:'لا شيء',openf:'فتح الملف',openF:'فتح المجلد',cancel:'إلغاء',later:'التحميل لاحقاً',start:'بدء التحميل',reading:'جارٍ قراءة معلومات الملف…',stats:'Download Statistics',speed:'Speed',dled:'Downloaded',left:'Time Left: الوقت',active:'Active Connections',link:'حالة الاتصال',pause:'إيقاف مؤقت',resumeb:'استئناف',done:'اكتمل التحميل',openb:'فتح',closeb:'إغلاق',retry:'إعادة المحاولة',paused:'متوقف مؤقتاً',queued:'بانتظار الدور…',nofo:'تعذّرت قراءة معلومات الملف (يمكنك المحاولة على أي حال):',added:'تمت الإضافة إلى القائمة',gone:'هذه النافذة لم تعد صالحة.'}};
const CATAR={Compressed:'مضغوط',Programs:'برامج',Videos:'فيديو',Documents:'مستندات',Musics:'موسيقى',Images:'صور',APKs:'تطبيقات',Uncategorized:'عام',General:'عام'},CATI={Compressed:'📦',Programs:'🖥️',Videos:'🎬',Documents:'📄',Musics:'🎵',Images:'🖼️',APKs:'🤖',Games:'🎮',Uncategorized:'📁',General:'📁'};
let lang='en',L=k=>TX[lang][k]||TX.en[k]||k,I={},S={},tid=null,poll=0;
const fs=n=>n==null||isNaN(n)?'—':n>=1073741824?(n/1073741824).toFixed(2)+' GB':n>=1048576?(n/1048576).toFixed(n>=1.05e8?1:2)+' MB':n>=1024?(n/1024).toFixed(0)+' KB':n+' B';
const sp=n=>n>=1048576?(n/1048576).toFixed(1)+' MB/s':n>=1024?Math.round(n/1024)+' KB/s':Math.round(n)+' B/s';
const clk=s=>{s=Math.max(0,Math.round(s));const p=x=>String(x).padStart(2,'0');return s>=3600?`${p(s/3600|0)}:${p(s%3600/60|0)}:${p(s%60)}`:`${p(s/60|0)}:${p(s%60)}`};
const sep=p=>p.includes('\\')?'\\':'/',base=p=>p.split(/[\\/]/).pop(),dir=p=>{const i=Math.max(p.lastIndexOf('\\'),p.lastIndexOf('/'));return i<0?'':p.slice(0,i)},join=(d,n)=>d?(d.replace(/[\\/]+$/,'')+sep(d)+n):n;
const ext=n=>{const e=(n.split('.').pop()||'').toUpperCase();return e.length<=4&&n.includes('.')?e:'FILE'};
const ico=e=>`<svg viewBox="0 0 76 86" width="76" height="86"><defs><linearGradient id="fg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#4f8dff"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs><path d="M10 4h38l20 20v54a6 6 0 01-6 6H10a6 6 0 01-6-6V10a6 6 0 016-6z" fill="url(#fg)"/><path d="M48 4v14a6 6 0 006 6h14z" fill="#fff" opacity=".35"/><text x="38" y="66" text-anchor="middle" font-family="Segoe UI,Arial" font-weight="800" font-size="${e.length>3?17:21}" fill="#fff">${esc(e)}</text></svg>`;
const SH={ok:'<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>',warn:'<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M12 8v5M12 16v.5"/></svg>'};
function secure(s){const e=$('#sec');e.className='sec '+(s=='secure'?'ok':s=='relaxed'?'warn':'bad');e.innerHTML=`<span>${L(s=='secure'?'secure':s=='relaxed'?'relaxed':'insecure')}</span>${s=='secure'?SH.ok:SH.warn}`}
function closeWin(){window.close();setTimeout(()=>api('win',{what:'close',prefix:APP+' · '}),250)}
function setTitle(n){document.title=APP+' · '+(n||'')}
/* ---------- view 1: before the download ---------- */
function preView(){const cats=I.cats;$('#view').innerHTML=`<section class="card"><div class="fi"><div class="fico" id="fi">${ico('…')}</div><div class="fcol"><label>File Information</label><input class="in" id="nm" disabled><div class="meta" id="meta" dir="ltr"><div class="skl" style="width:60%"></div></div></div></div></section>
<section class="card"><h4>Save To Path &amp; Auto-Categorization</h4><div class="prow"><button class="ghost" id="chg">${L('chg')}</button><input class="in" id="path" spellcheck="false"></div><div class="cats" id="cats" style="direction:${lang=='ar'?'rtl':'ltr'}">${cats.map(c=>`<button class="chip" data-c="${esc(c.name)}">${CATI[c.name]||'📁'} ${esc(lang=='ar'?(CATAR[c.name]||c.name):c.name)}</button>`).join('')}</div></section>
<section class="card"><h4>Smart Acceleration Settings</h4><div class="g2" style="text-align:${lang=='ar'?'right':'left'}"><label>${L('conn')}<select class="in" id="cn"><option value="">${L('auto')}</option><option value="4">4 ${L('cn')}</option><option value="8">8 ${L('cn')}</option><option value="16">16 ${L('max')}</option><option value="32">32 ${L('cn')}</option></select></label><label>${L('after')}<select class="in" id="af"><option value="">${L('none')}</option><option value="open">${L('openf')}</option><option value="folder">${L('openF')}</option></select></label></div></section>`;
$('#foot').innerHTML=`<button class="btn" id="cx">${L('cancel')}</button><div class="r"><button class="btn" id="lt" disabled>${L('later')}</button><button class="btn pri" id="go" disabled>${L('start')} <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></button></div>`;
$('#cx').onclick=async()=>{await api('popup_cancel',{pid:PID});closeWin()};$('#chg').onclick=changeDir;
$('#path').oninput=e=>{S.path=e.target.value;$('#nm').value=base(S.path);setTitle(base(S.path))};
$('#cats').onclick=e=>{const b=e.target.closest('[data-c]');if(b)setCat(b.dataset.c,true)};$('#cn').onchange=e=>S.conn=e.target.value;$('#af').onchange=e=>S.after=e.target.value;
const dc=[4,8,16,32].includes(I.conns)?String(I.conns):'32';$('#cn').value=dc;S.conn=dc;
$('#nm').oninput=e=>{S.path=join(dir(S.path),e.target.value);$('#path').value=S.path};
$('#go').onclick=()=>begin(false);$('#lt').onclick=()=>begin(true)}
function setCat(c,move){S.cat=c;document.querySelectorAll('.chip').forEach(x=>x.classList.toggle('on',x.dataset.c==c));if(move){const f=I.cats.find(x=>x.name==c);if(f){S.path=join(f.folder,base(S.path));$('#path').value=S.path}}}
async function changeDir(){const r=await api('pick_folder',{start:dir(S.path)||I.default_dir});if(r.path){S.path=join(r.path,base(S.path));$('#path').value=S.path}else if(r.err){const v=prompt(L('chg'),dir(S.path));if(v){S.path=join(v,base(S.path));$('#path').value=S.path}}}
function fillInfo(r){S.path=r.path;S.cat=r.category;S.name=r.name;$('#nm').disabled=false;$('#nm').value=r.name;$('#path').value=r.path;$('#fi').innerHTML=ico(ext(r.name));setCat(r.category,false);secure(r.ssl);setTitle(r.name);
$('#meta').innerHTML=`<span>${L('size')}: <b>${fs(r.size)}</b></span><span>${L('src')}: <b>${esc(r.host)}</b></span><span class="${r.resume?'ok':'no'}">${L(r.resume?'resume':'nores')}${r.resume?'<i></i>':''}</span>`+(r.err?`<div class="errb" style="flex-basis:100%">${esc(L('nofo'))} ${esc(r.err)}</div>`:'');$('#go').disabled=$('#lt').disabled=false}
async function begin(later){const g=$('#go'),l=$('#lt');g.disabled=l.disabled=true;const r=await api('popup_start',{pid:PID,path:S.path,category:S.cat,nconn:S.conn||'',after:S.after||'',later});if(r.err){$('#meta').insertAdjacentHTML('beforeend',`<div class="errb" style="flex-basis:100%">${esc(r.err)}</div>`);return}
if(later){$('#view').innerHTML=`<section class="card"><div class="doneb">✔ ${L('added')}</div></section>`;setTimeout(closeWin,1200);return}
if(!I.show_progress){closeWin();return}tid=r.id;progView()}
/* ---------- view 2: live progress ---------- */
function progView(){S.name=S.name||base(S.path);$('#view').innerHTML=`<section class="card"><div class="top"><div class="fico" style="width:46px;height:52px" id="pfi">${ico(ext(S.name))}</div><div class="nm" id="pn">${esc(S.name)}</div><div class="sz"><i></i><span id="ps">${fs(S.size)}</span></div></div><div class="bar" id="bar"><i id="bf"></i><b id="bp">0%</b></div><div class="sub"><b id="pd">0 B</b> <span>/ <span id="pt">${fs(S.size)}</span></span></div><div id="msg"></div></section>
<section class="card" style="flex:1;display:flex;flex-direction:column"><h4>${L('stats')}</h4><div class="stats" style="flex:1"><div class="tile"><small><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg>${L('speed')}<span class="sp">⚡</span></small><b id="ssp">0 MB/s</b></div><div class="tile"><small><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 4v10M8 10l4 4 4-4M4 19h16"/></svg>${L('dled')}</small><b id="sdl">0 <em>/ ${fs(S.size)}</em></b></div>
<div class="tile g"><small>${L('link')}</small><svg class="ch" id="ch" viewBox="0 0 200 100" preserveAspectRatio="none"></svg></div><div class="tile"><small><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>${L('left')}</small><b id="stl">--:--</b></div><div class="tile"><small><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M8 7l3 9M16 7l-3 9"/></svg>${L('active')}</small><b id="sco">0/0</b></div></div></section>`;
$('#foot').innerHTML=`<button class="btn" id="cx">${L('cancel')}</button><div class="r" id="fr"><button class="btn pri" id="pz"><svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg><span>${L('pause')}</span></button></div>`;
$('#cx').onclick=async()=>{await api('delete',{ids:[tid],files:true});closeWin()};$('#pz').onclick=async()=>{const p=S.paused;await api(p?'resume':'stop',{ids:[tid]})};
clearInterval(poll);poll=setInterval(tick,500);tick()}
function chart(h){const e=$('#ch');if(!e)return;const v=h.length>1?h:[0,0],mx=Math.max(...v,1)*1.15,n=v.length,pts=v.map((y,i)=>[i*200/(n-1),96-y/mx*88]);
let d=`M${pts[0][0]},${pts[0][1]}`;for(let i=1;i<n;i++){const[x0,y0]=pts[i-1],[x1,y1]=pts[i],cx=(x0+x1)/2;d+=` C${cx},${y0} ${cx},${y1} ${x1},${y1}`}
e.innerHTML=`<defs><linearGradient id="cg" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#3b82f6"/><stop offset="1" stop-color="#2dd4bf"/></linearGradient><linearGradient id="cf" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2dd4bf" stop-opacity=".45"/><stop offset="1" stop-color="#3b82f6" stop-opacity="0"/></linearGradient></defs><path d="${d} L200,100 L0,100Z" fill="url(#cf)"/><path d="${d}" fill="none" stroke="url(#cg)" stroke-width="2.2" vector-effect="non-scaling-stroke"/>`}
async function tick(){const r=await api('popup_task',{id:tid});if(r.gone){clearInterval(poll);$('#msg').innerHTML=`<div class="note err">${L('gone')}</div>`;return}
S.size=r.size||S.size;S.paused=r.status=='Paused';if(r.name&&r.name!=S.name){S.name=r.name;$('#pn').textContent=r.name;$('#pfi').innerHTML=ico(ext(r.name));setTitle(r.name)}secure(r.ssl);
const pct=r.size?Math.min(100,r.done*100/r.size):0,bar=$('#bar');$('#bf').style.width=(r.status=='Completed'?100:pct)+'%';$('#bp').textContent=(r.status=='Completed'?100:Math.floor(pct))+'%';$('#ps').textContent=fs(r.size);$('#pt').textContent=fs(r.size);$('#pd').textContent=fs(r.done);
$('#ssp').textContent=sp(r.speed);$('#sdl').innerHTML=`${fs(r.done)} <em>/ ${fs(r.size)}</em>`;$('#stl').textContent=r.speed>0&&r.size?clk((r.size-r.done)/r.speed):'--:--';$('#sco').textContent=`${r.conn}/${r.cap}`;chart(r.hist);
bar.className='bar'+(r.status=='Completed'?' done':r.status=='Error'?' err':r.status=='Paused'||r.status=='Queued'?' dim':'');
const pz=$('#pz');if(pz&&r.status!='Completed'){pz.querySelector('span').textContent=L(S.paused||r.status=='Error'?(r.status=='Error'?'retry':'resumeb'):'pause');S.paused=S.paused||r.status=='Error'}
$('#msg').innerHTML=r.status=='Error'?`<div class="note err">⚠ ${esc(r.err)}</div>`:r.status=='Paused'?`<div class="note" style="color:var(--warn)">${L('paused')}</div>`:r.status=='Queued'?`<div class="note" style="color:var(--mut)">${L('queued')}</div>`:'';
if(r.status=='Completed'){clearInterval(poll);$('#msg').innerHTML=`<div class="doneb">✔ ${L('done')}</div>`;$('#cx').style.display='none';$('#fr').innerHTML=`<button class="btn" id="o2">${L('openF')}</button><button class="btn" id="o1">${L('openb')}</button><button class="btn pri" id="o3">${L('closeb')}</button>`;$('#o1').onclick=()=>api('open',{ids:[tid]});$('#o2').onclick=()=>api('folder',{ids:[tid]});$('#o3').onclick=closeWin}}
/* ---------- start ---------- */
(async()=>{I=await api('popup_info',{pid:PID});if(I.err){document.body.innerHTML='<p style="padding:30px">'+esc(I.err)+'</p>';return}
lang=I.lang=='ar'?'ar':'en';document.documentElement.lang=lang;document.documentElement.dir='ltr';secure(I.ssl);setTitle(I.host);
if(I.task){tid=I.task;progView();return}
preView();const r=await api('popup_probe',{pid:PID});if(r.err&&!r.name){$('#meta').innerHTML=`<div class="errb">${esc(r.err)}</div>`;return}S.size=r.size;fillInfo(r)})();
</script></body></html>

'''


UI_HTML = r'''<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><title>Unlimited Download Manager</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" type="image/png" href="__ICON__">
<style>
:root{--sw:clamp(236px,20vw,330px);--tx:#eef4ff;--mut:#8fa6d6;--line:#1c3f99;--b1:#1b8bff;--b2:#2f5bff;--ok:#22c55e;--warn:#f59e0b;--bad:#f43f5e;
--pn:rgba(6,20,58,.72);--pn2:rgba(10,30,84,.55);--bd:rgba(70,140,255,.5);--bd2:rgba(80,150,255,.32);--inp:rgba(3,12,38,.85);--hov:rgba(40,100,240,.2);--hov2:rgba(50,115,255,.32);
--gl:0 0 24px rgba(30,110,255,.38);--win:#01040d;--shade:#000a;--card:#071a48}
[data-theme=light]{--tx:#0f1e45;--mut:#566a9a;--line:#9ab6f0;--pn:rgba(255,255,255,.78);--pn2:rgba(232,240,255,.9);--bd:rgba(60,110,230,.45);--bd2:rgba(60,110,230,.28);--inp:rgba(255,255,255,.95);--hov:rgba(40,100,240,.1);--hov2:rgba(40,100,240,.18);--gl:0 4px 22px rgba(30,90,220,.18);--win:#dfe8fb;--shade:#0005;--card:#fff}
[data-pal=ocean]{--b1:#38bdf8;--b2:#2563eb}[data-pal=forest]{--b1:#4ade80;--b2:#15803d}[data-pal=purple]{--b1:#a78bfa;--b2:#6d28d9}[data-pal=rose]{--b1:#fb7185;--b2:#e11d48}
[data-pal=sunset]{--b1:#fb923c;--b2:#e11d48}[data-pal=teal]{--b1:#2dd4bf;--b2:#0f766e}[data-pal=neon]{--b1:#22d3ee;--b2:#e879f9}[data-pal=clay]{--b1:#d6a77a;--b2:#b45f4b}
*{box-sizing:border-box;margin:0;padding:0}html,body{height:100%}
body{background:var(--win);color:var(--tx);font:14px 'Segoe UI',system-ui,-apple-system,sans-serif;overflow:hidden;user-select:none}
html[dir=rtl] body{font-family:'Segoe UI',Tahoma,system-ui,sans-serif}
svg{flex:none}::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-thumb{background:rgba(70,130,255,.35);border-radius:6px}::-webkit-scrollbar-track{background:transparent}
button{font:inherit;color:inherit;border:0;cursor:pointer}
.app{position:fixed;inset:8px;border-radius:26px;border:1.5px solid var(--bd);display:grid;grid-template-columns:var(--sw) minmax(0,1fr);grid-template-rows:auto minmax(0,1fr);overflow:hidden;
box-shadow:0 0 0 1px rgba(20,60,160,.5) inset,0 0 46px rgba(20,90,255,.32),inset 0 0 70px rgba(20,80,255,.14);
background:radial-gradient(900px 480px at 78% -12%,rgba(30,110,255,.30),transparent 62%),radial-gradient(720px 560px at -4% 104%,rgba(20,70,200,.30),transparent 62%),radial-gradient(500px 360px at 104% 104%,rgba(20,80,255,.20),transparent 62%),linear-gradient(180deg,#041036,#030b26 58%,#020819)}
[data-theme=light] .app{background:radial-gradient(900px 480px at 78% -12%,rgba(80,140,255,.28),transparent 62%),radial-gradient(720px 560px at -4% 104%,rgba(110,160,255,.3),transparent 62%),linear-gradient(180deg,#f4f8ff,#e6eeff)}
/* header */
.hdr{grid-column:1/3;display:grid;grid-template-columns:var(--sw) minmax(0,1fr) auto;grid-template-rows:auto auto;padding:10px 22px 4px 0;row-gap:2px}
.brand{grid-row:1/3;grid-column:1;display:flex;align-items:center;gap:12px;padding-inline-start:26px;min-width:0}
.brand .logo{width:clamp(48px,4.6vw,76px);height:auto;filter:drop-shadow(0 0 10px rgba(40,130,255,.75))}
.bt{display:flex;flex-direction:column;line-height:1}.bt b{font-size:clamp(34px,3.7vw,58px);font-weight:900;letter-spacing:1px;background:linear-gradient(180deg,#fff 10%,#a9c3f5 90%);-webkit-background-clip:text;background-clip:text;color:transparent;filter:drop-shadow(0 0 9px rgba(45,110,255,.9));direction:ltr}
[data-theme=light] .bt b{background:linear-gradient(180deg,#1b3fa8,#2f6bff);-webkit-background-clip:text;background-clip:text}
.bt small{font-size:clamp(10px,.95vw,14px);margin-top:4px;color:var(--tx);white-space:nowrap;direction:ltr}
.tools{grid-column:2/4;grid-row:1;justify-self:end;display:flex;align-items:center;gap:6px;height:44px}
.ib{width:42px;height:42px;border-radius:12px;background:transparent;color:var(--tx);display:grid;place-items:center;position:relative;transition:.15s}.ib:hover{background:var(--hov)}
.ib .dot{position:absolute;top:6px;inset-inline-end:7px;min-width:16px;height:16px;border-radius:8px;background:var(--bad);color:#fff;font-size:10px;font-weight:700;display:grid;place-items:center;padding:0 4px}
.vsep{width:1px;height:24px;background:var(--bd2);margin:0 10px}
.wc{width:40px}.wc:last-child:hover{background:#e11d48;color:#fff}
.lg{font-weight:700;font-size:15px}
.urlrow{grid-column:2/4;grid-row:2;display:flex;gap:18px;align-items:center;padding-inline-start:6px}
.urlbar{flex:1;min-width:0;height:clamp(50px,6.4vh,64px);border-radius:18px;border:1.5px solid var(--bd);background:var(--inp);display:flex;align-items:center;gap:16px;padding:0 18px;color:var(--mut);box-shadow:0 0 22px rgba(30,100,255,.22),inset 0 0 18px rgba(30,100,255,.1);position:relative}
.urlbar:focus-within{border-color:#4a9cff;box-shadow:0 0 28px rgba(50,130,255,.5),inset 0 0 18px rgba(30,100,255,.14)}
.urlbar input{flex:1;min-width:0;background:none;border:0;outline:0;color:var(--tx);font-size:clamp(14px,1.15vw,17px);user-select:text;direction:ltr;text-align:start}
html[dir=rtl] .urlbar input{direction:ltr}
.urlbar input::placeholder{color:#a9bde6;opacity:.9}.urlbar .chev{background:none;color:var(--tx);width:32px;height:32px;border-radius:8px;display:grid;place-items:center}.urlbar .chev:hover{background:var(--hov)}
.dlbtn{height:clamp(50px,6.4vh,64px);padding:0 clamp(22px,2.6vw,42px);border-radius:16px;background:linear-gradient(180deg,#2a8cff,#0d56ff);color:#fff;font-weight:700;font-size:clamp(15px,1.45vw,22px);display:flex;align-items:center;gap:12px;box-shadow:0 0 30px rgba(30,110,255,.7),inset 0 1px 0 rgba(255,255,255,.4);border:1px solid rgba(140,190,255,.7);transition:.15s;white-space:nowrap}
.dlbtn:hover{filter:brightness(1.12);transform:translateY(-1px)}.dlbtn:active{transform:none}
/* sidebar */
aside{grid-column:1;grid-row:2;position:relative;padding:clamp(8px,1.6vh,18px) 16px 0 26px;display:flex;flex-direction:column;min-height:0;overflow:hidden}
.nv{display:flex;align-items:center;gap:16px;min-height:clamp(46px,6.6vh,62px);padding:0 18px;border-radius:18px;cursor:pointer;font-size:clamp(14px,1.2vw,18px);border:1px solid transparent;margin-bottom:clamp(4px,1vh,10px);position:relative;z-index:2;transition:background .15s}
.nv:hover{background:rgba(40,100,240,.16)}.nv svg{color:#dbe8ff}
.nv.on{background:linear-gradient(90deg,rgba(30,105,255,.62),rgba(22,64,180,.42));border-color:rgba(100,165,255,.75);box-shadow:0 0 26px rgba(30,110,255,.5),inset 0 0 20px rgba(60,140,255,.25)}
[data-theme=light] .nv svg{color:#27407f}[data-theme=light] .nv.on{background:linear-gradient(90deg,rgba(40,110,255,.3),rgba(40,110,255,.12))}
.nv .cnt{margin-inline-start:auto;min-width:36px;height:36px;border-radius:50%;background:linear-gradient(180deg,#2a8cff,#1450ee);display:grid;place-items:center;font-weight:600;font-size:15px;box-shadow:0 0 14px rgba(40,120,255,.6);color:#fff;padding:0 6px}
.nv .st{margin-inline-start:auto;display:flex;align-items:center;gap:8px;height:30px;padding:0 14px 0 12px;border-radius:15px;font-size:13px;font-weight:600;white-space:nowrap}
.nv .st i{width:8px;height:8px;border-radius:50%;display:block}
.st.ok{background:linear-gradient(180deg,rgba(34,197,94,.34),rgba(16,120,60,.45));border:1px solid #22c55e;color:#eafff2}.st.ok i{background:#22e06f;box-shadow:0 0 8px #22e06f}
.st.no{background:rgba(245,158,11,.16);border:1px solid rgba(245,158,11,.7);color:#ffe2a8}.st.no i{background:#f59e0b}
.st.off{background:rgba(120,140,190,.14);border:1px solid rgba(120,140,190,.5);color:var(--mut)}.st.off i{background:#8aa0d0}
.nv.bi-nv{flex-wrap:wrap;row-gap:0}.nv.bi-nv>span:first-of-type{line-height:1.15}
.art{position:absolute;inset:auto 0 0 0;height:46%;pointer-events:none;z-index:1;-webkit-mask-image:linear-gradient(180deg,transparent 0,#000 38%);mask-image:linear-gradient(180deg,transparent 0,#000 38%)}
.art svg,.art img{width:100%;height:100%;display:block;object-fit:cover;object-position:center top}
/* main */
.main{grid-column:2;grid-row:2;padding:clamp(8px,1.6vh,18px) 26px 26px 0;min-width:0;min-height:0;display:flex}
html[dir=rtl] .main{padding:clamp(8px,1.6vh,18px) 0 26px 26px}
.pn{flex:1;min-width:0;min-height:0;display:flex;flex-direction:column;border-radius:22px;border:1.5px solid var(--bd);background:linear-gradient(180deg,rgba(8,26,72,.78),rgba(5,16,48,.72));box-shadow:var(--gl),inset 0 0 40px rgba(30,100,255,.1);backdrop-filter:blur(6px)}
[data-theme=light] .pn{background:linear-gradient(180deg,rgba(255,255,255,.88),rgba(240,246,255,.82))}
.ph{display:flex;align-items:center;gap:14px;padding:clamp(12px,2.2vh,22px) 22px;border-bottom:1px solid var(--bd2);flex-wrap:wrap}
.ph h2{font-size:clamp(20px,2vw,30px);font-weight:700;display:flex;align-items:center;gap:14px;margin-inline-end:auto;white-space:nowrap}
.ph h2 svg{color:#2f93ff;filter:drop-shadow(0 0 8px rgba(40,130,255,.8))}.ph h2 small{font-size:14px;font-weight:400;color:var(--mut);margin-inline-start:6px}
.pill{height:clamp(38px,5.4vh,48px);padding:0 clamp(12px,1.3vw,20px);border-radius:14px;background:rgba(10,32,90,.6);border:1px solid var(--bd);display:flex;align-items:center;gap:10px;font-size:clamp(13px,1.1vw,16px);color:var(--tx);white-space:nowrap;transition:.15s}
[data-theme=light] .pill{background:rgba(255,255,255,.85)}
.pill:hover{background:var(--hov2);box-shadow:0 0 16px rgba(40,120,255,.4)}.pill svg{color:#3b9bff}.pill.pri{background:linear-gradient(180deg,#2a8cff,#0d56ff);color:#fff;border-color:rgba(140,190,255,.7)}.pill.pri svg{color:#fff}
.pill:disabled{opacity:.45;pointer-events:none}.pill.sm{height:34px;font-size:13px;padding:0 12px;border-radius:11px}
.sq{width:38px;padding:0;justify-content:center}
.cs{display:flex;align-items:center;gap:8px;height:clamp(38px,5.4vh,48px);padding:0 14px;border-radius:14px;border:1px solid var(--bd);background:var(--inp);min-width:180px}.cs input{background:none;border:0;outline:0;color:var(--tx);font-size:14px;width:100%;user-select:text}
.chips{display:flex;gap:8px;padding:12px 22px 0;flex-wrap:wrap;align-items:center}.chp{padding:7px 15px;border-radius:12px;background:rgba(10,32,90,.5);border:1px solid var(--bd2);cursor:pointer;font-size:13.5px;color:var(--mut)}.chp.on{background:linear-gradient(180deg,#2a8cff,#0d56ff);color:#fff;border-color:transparent}
.chips select{width:auto;padding:7px 12px;border-radius:12px}
.list{flex:1;min-height:0;overflow:auto;padding:clamp(8px,1.4vh,14px) 16px 16px}
.row{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:clamp(14px,1.6vw,24px);padding:clamp(10px,1.8vh,20px);border-radius:18px;border:1px solid transparent;margin-bottom:clamp(6px,1vh,10px);position:relative;transition:background .15s,border-color .15s;cursor:default}
.row+.row::before{content:'';position:absolute;top:-6px;inset-inline:18px;height:1px;background:var(--bd2);opacity:.6}
.row:hover{background:rgba(30,90,230,.1)}.row.on{background:rgba(30,100,255,.18);border-color:rgba(100,165,255,.6);box-shadow:0 0 20px rgba(30,110,255,.28)}
.th{width:clamp(110px,10.6vw,178px);aspect-ratio:178/138;border-radius:14px;overflow:hidden;border:1px solid rgba(110,170,255,.55);position:relative;display:grid;place-items:center;box-shadow:0 0 18px rgba(30,100,255,.28)}
.th img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}.th svg{position:relative;filter:drop-shadow(0 0 10px currentColor)}
.th.t-v{background:linear-gradient(135deg,#102766,#2b1b66);color:#5eb4ff}.th.t-m{background:radial-gradient(circle at 50% 60%,#2a1670,#070b2a 72%);color:#c06bff}.th.t-z{background:linear-gradient(135deg,#3a2a0a,#1a1204);color:#ffb347}
.th.t-p{background:linear-gradient(135deg,#0a3a5a,#081a38);color:#4de0ff}.th.t-d{background:linear-gradient(135deg,#143a7a,#0a1a44);color:#8fc0ff}.th.t-a{background:linear-gradient(135deg,#0c4a2a,#06201a);color:#4ade80}
.th.t-i{background:linear-gradient(135deg,#5a1a4a,#240a30);color:#ff7bd0}.th.t-u{background:linear-gradient(135deg,#102a66,#071a44);color:#4aa6ff}
.cm{min-width:0;display:flex;flex-direction:column;gap:clamp(5px,1vh,9px)}.cm>b{font-weight:600;font-size:clamp(16px,1.55vw,24px);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:.1px}
.cmeta{display:flex;align-items:center;gap:12px;font-size:clamp(13px,1.2vw,18px);color:#dbe7ff}[data-theme=light] .cmeta{color:#27407f}
.cmeta .pc{margin-inline-start:auto;font-size:clamp(16px,1.5vw,22px);font-weight:600;color:var(--tx)}
.bd{padding:2px 9px;border-radius:7px;font-weight:700;font-size:.82em;color:#fff;letter-spacing:.2px;line-height:1.5}
.bd.hd{background:#1d78ff;box-shadow:0 0 10px rgba(30,120,255,.7)}.bd.k4{background:#8b3dff;box-shadow:0 0 10px rgba(139,61,255,.7)}.bd.mp3{background:#1fd35a;color:#04210f;box-shadow:0 0 10px rgba(31,211,90,.6)}
.bd.sd{background:#5b6b95}.bd.ft{background:#2a4fb8;box-shadow:0 0 8px rgba(40,90,220,.6)}
.pbar{display:block;height:7px;border-radius:4px;background:rgba(120,150,220,.2);overflow:hidden}.pbar i{display:block;height:100%;border-radius:4px;transition:width .6s cubic-bezier(.2,.7,.2,1)}
.pb i{background:linear-gradient(90deg,#1a8cff,#27c0ff);box-shadow:0 0 12px #1a8cff}.pg i{background:linear-gradient(90deg,#19c45a,#37f08a);box-shadow:0 0 12px #22d36a}
.pm i{background:linear-gradient(90deg,#8b3dff,#ff3dc4);box-shadow:0 0 12px #c03dff}.pc2 i{background:linear-gradient(90deg,#14c8d8,#2f93ff);box-shadow:0 0 12px #14b8d8}
.pbar.dim i{filter:saturate(.35) brightness(.8);box-shadow:none}
.cst{display:flex;align-items:center;gap:clamp(14px,2vw,32px);font-size:clamp(12.5px,1.15vw,17px);color:#dbe7ff;flex-wrap:wrap}[data-theme=light] .cst{color:#27407f}
.cst span{display:flex;align-items:center;gap:9px;white-space:nowrap}.cst .mu{color:var(--mut)}.cst svg{opacity:.9}
.pb+.cst .sp svg,.cst .sp svg{color:var(--c,#2f9bff)}.pm+.cst .sp svg{color:#d04dff}.pg+.cst .sp svg{color:#2fe17a}
.err{color:#ff7a93}.okc{color:#43e08a}
.ca{display:flex;gap:12px;align-items:center}
.rb{width:clamp(40px,3.6vw,60px);height:clamp(40px,3.6vw,60px);border-radius:50%;background:rgba(8,26,76,.75);border:1.5px solid rgba(120,170,255,.5);color:var(--tx);display:grid;place-items:center;transition:.15s}
.rb:hover{background:var(--hov2);box-shadow:0 0 18px rgba(50,130,255,.55);border-color:#6fb0ff}.rb.x:hover{background:rgba(244,63,94,.28);border-color:#f43f5e;box-shadow:0 0 18px rgba(244,63,94,.5)}
[data-theme=light] .rb{background:#fff}
.empty{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;color:var(--mut);text-align:center;padding:30px}.empty svg{color:#2f93ff;filter:drop-shadow(0 0 16px rgba(40,130,255,.8));opacity:.9}.empty b{color:var(--tx);font-size:20px;font-weight:600}
/* browser integration page */
.bi-sum{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;padding:16px 22px 0}
.tile{border-radius:16px;border:1px solid var(--bd2);background:var(--pn2);padding:14px 16px;display:flex;align-items:center;gap:14px}.tile .ti{width:44px;height:44px;border-radius:13px;background:rgba(30,110,255,.2);display:grid;place-items:center;color:#4aa6ff}
.tile small{display:block;color:var(--mut);font-size:12.5px}.tile b{font-size:18px;font-weight:600}
.bgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,330px),1fr));gap:16px;padding:16px 22px 8px}
.bcard{border-radius:20px;border:1.5px solid var(--bd2);background:var(--pn2);padding:18px;display:flex;flex-direction:column;gap:14px;position:relative;transition:.2s}
.bcard.ok{border-color:rgba(34,197,94,.7);box-shadow:0 0 26px rgba(34,197,94,.18)}.bcard:hover{border-color:var(--bd)}
.bh{display:flex;align-items:center;gap:14px}.bh .bn{font-size:19px;font-weight:600}.bh small{color:var(--mut);display:block;font-size:12.5px;margin-top:2px}
.bic{width:54px;height:54px;border-radius:16px;display:grid;place-items:center;background:rgba(255,255,255,.06);border:1px solid var(--bd2)}
.bst{display:flex;flex-direction:column;gap:9px}.sr{display:flex;align-items:center;justify-content:space-between;gap:10px;font-size:14px}.sr>span:first-child{color:var(--mut)}
.pl{display:inline-flex;align-items:center;gap:7px;height:26px;padding:0 11px;border-radius:13px;font-size:12.5px;font-weight:600;white-space:nowrap}
.pl i{width:7px;height:7px;border-radius:50%;display:block}
.pl.g{background:rgba(34,197,94,.18);border:1px solid rgba(34,197,94,.7);color:#7ff0ae}.pl.g i{background:#22e06f;box-shadow:0 0 7px #22e06f}
.pl.r{background:rgba(244,63,94,.14);border:1px solid rgba(244,63,94,.6);color:#ff9bb0}.pl.r i{background:#f43f5e}
.pl.a{background:rgba(245,158,11,.14);border:1px solid rgba(245,158,11,.65);color:#ffd48a}.pl.a i{background:#f59e0b}
.pl.n{background:rgba(120,140,190,.14);border:1px solid rgba(120,140,190,.45);color:var(--mut)}.pl.n i{background:#8aa0d0}
.pl.b{background:rgba(40,130,255,.16);border:1px solid rgba(60,140,255,.6);color:#a9d0ff}.pl.b i{background:#3b9bff}
[data-theme=light] .pl.g{color:#0d7a3a}[data-theme=light] .pl.r{color:#b3123b}[data-theme=light] .pl.a{color:#935d00}[data-theme=light] .pl.b{color:#1651b8}
.bact{display:flex;gap:8px;flex-wrap:wrap;margin-top:auto}.bact .pill{flex:0 0 auto}.hint{font-size:12.5px;color:var(--mut);line-height:1.55}.hint.w{color:#ffd48a}
.how{margin:8px 22px 20px;padding:14px 18px;border-radius:16px;border:1px dashed var(--bd2);color:var(--mut);font-size:13px;line-height:1.7;display:flex;gap:12px}
.sw{position:relative;width:46px;height:26px;border-radius:13px;background:rgba(120,140,190,.35);cursor:pointer;flex:none;transition:.2s;border:1px solid var(--bd2)}.sw::after{content:'';position:absolute;top:2px;inset-inline-start:2px;width:20px;height:20px;border-radius:50%;background:#fff;transition:.2s}
.sw.on{background:linear-gradient(180deg,#2a8cff,#0d56ff)}.sw.on::after{inset-inline-start:22px}
/* dialogs, menus, forms (restyled for the new design) */
.ov{position:fixed;inset:0;background:var(--shade);display:grid;place-items:center;z-index:100;backdrop-filter:blur(3px)}
.dlg{background:linear-gradient(180deg,#0a1f58,#06143c);border:1.5px solid var(--bd);border-radius:22px;padding:24px;width:580px;max-width:94vw;max-height:90vh;display:flex;flex-direction:column;box-shadow:0 0 50px rgba(30,100,255,.4),0 30px 80px #000a}
[data-theme=light] .dlg{background:linear-gradient(180deg,#fff,#eef4ff)}
.dlg.wide{width:800px}.dlg h3{font-weight:600;font-size:20px;margin-bottom:16px}.bd2,.dlg .bdy{overflow:auto;flex:1}.dlg>.bd{overflow:auto;flex:1;background:none;box-shadow:none;padding:0;color:inherit;font-weight:400;font-size:inherit;letter-spacing:0}
.dlg .f{display:flex;gap:10px;justify-content:flex-end;margin-top:18px;flex-wrap:wrap}
.dlg button,.dd div,.ctx div{font-size:14px}
.dlg .f button,.dlg button{background:rgba(40,100,240,.22);border:1px solid var(--bd2);border-radius:12px;padding:10px 18px;color:var(--tx)}.dlg button:hover{background:var(--hov2)}
.dlg button.pri{background:linear-gradient(180deg,#2a8cff,#0d56ff);border-color:rgba(140,190,255,.7);color:#fff}
.fld{display:block;margin-bottom:10px}.fld span{display:block;color:var(--mut);font-size:13px;margin-bottom:4px}.chk{display:flex;gap:10px;align-items:center;margin:8px 0}.chk input{accent-color:#2a8cff;width:17px;height:17px}
input[type=text],input[type=number],input[type=password],select,textarea{width:100%;background:var(--inp);border:1px solid var(--bd2);border-radius:11px;color:var(--tx);padding:9px 12px;font:inherit;user-select:text;outline:0}
input:focus,select:focus,textarea:focus{border-color:#4a9cff}select option{background:#0a1f58;color:#fff}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}.tabs span{padding:7px 14px;border-radius:10px;cursor:pointer;color:var(--mut)}.tabs span.on{background:var(--hov2);color:var(--tx)}
.dd,.ctx{position:fixed;background:linear-gradient(180deg,#0b2262,#071742);border:1.5px solid var(--bd);border-radius:14px;padding:6px;min-width:230px;z-index:90;box-shadow:0 14px 40px #000a,0 0 24px rgba(30,100,255,.3)}
[data-theme=light] .dd,[data-theme=light] .ctx{background:#fff}
.dd div,.ctx div{padding:9px 12px;border-radius:9px;cursor:pointer;color:var(--tx);display:flex;align-items:center;gap:10px}.dd div:hover,.ctx div:hover{background:var(--hov2)}.dd hr{border:0;border-top:1px solid var(--bd2);margin:5px 4px}
.np{width:360px;max-height:420px;overflow:auto}.np .nh{display:flex;align-items:center;justify-content:space-between;padding:8px 10px 10px;font-weight:600}.np .ni{display:block!important;padding:10px 12px;border-radius:10px}.np .ni small{display:block;color:var(--mut);margin-top:2px;font-size:12px}
#toasts{position:fixed;inset-inline-end:26px;bottom:26px;display:flex;flex-direction:column;gap:10px;z-index:200}
.toast{background:linear-gradient(180deg,#0b2262,#071742);border:1px solid var(--bd);border-inline-start:3px solid #2f93ff;border-radius:14px;padding:12px 16px;max-width:380px;box-shadow:0 10px 30px #000a;color:#fff}[data-theme=light] .toast{background:#fff;color:#0f1e45}
.lr{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--bd2)}.lr span{flex:1}
[name=urls],[name=url],[name=folder],[name=cookies],[name=referer],[name=user_agent],[name=proxy_http],[name=proxy_https],[name=proxy_ftp],[name=av_command],[name=temp_dir],[name=pwd],[name=user],[name=server_limits],[name=cats_text],[name=logins_text],.path{direction:ltr;text-align:left}
.dz{position:fixed;inset:12px;border:3px dashed #3b9bff;border-radius:26px;background:rgba(40,120,255,.16);display:none;place-items:center;font-size:24px;z-index:300;pointer-events:none;color:#fff}.dz.on{display:grid}
.chip{display:inline-block;padding:7px 14px;margin:4px 6px 4px 0;border-radius:12px;background:var(--hov);cursor:pointer;font-size:14px}.chip.on{background:linear-gradient(180deg,#2a8cff,#0d56ff);color:#fff}.chip.off{opacity:.4;pointer-events:none}
.vthumb{width:170px;border-radius:12px;flex:none}.badge{font-size:11px;padding:2px 8px;border-radius:8px;background:var(--hov)}
.bcards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:6px 0 14px}.bc{background:var(--hov);border:2px solid transparent;border-radius:16px;padding:16px 8px;text-align:center;cursor:pointer}.bc:hover,.bc.on{border-color:#3b9bff}.bc b{display:block;margin:8px 0 4px;font-weight:500}.bc small{color:var(--mut)}
.bi{width:46px;height:46px;border-radius:50%;margin:auto;display:grid;place-items:center;color:#fff;font-weight:700;font-size:20px}
.stp{display:flex;gap:14px;padding:14px 0;border-bottom:1px solid var(--bd2)}.stp>i{flex:none;width:30px;height:30px;border-radius:50%;background:linear-gradient(180deg,#2a8cff,#0d56ff);color:#fff;display:grid;place-items:center;font-style:normal;font-weight:600}
.stp .tx{flex:1;min-width:0}.stp h5{font-weight:500;font-size:15px;margin-bottom:6px}.stp p{color:var(--mut);font-size:13.5px;line-height:1.6;margin-bottom:8px}.stp svg.mk{width:100%;max-width:420px;height:auto;border-radius:12px;background:var(--inp);border:1px solid var(--bd2)}
.okb{padding:14px;border-radius:14px;background:#10b98122;border:1px solid #10b981;margin-top:12px}.wnb{padding:14px;border-radius:14px;background:#f59e0b22;border:1px solid #f59e0b;margin-top:12px}
.pth{direction:ltr;text-align:left;user-select:text;background:var(--inp);border:1px solid var(--bd2);border-radius:10px;padding:8px 10px;font-family:Consolas,monospace;font-size:12.5px;word-break:break-all}
.abt{text-align:center;padding:6px 0}.abt .logo{width:86px;margin:0 auto 6px;display:block}.abt b{font-size:30px;font-weight:900;background:linear-gradient(180deg,#fff,#9db8f0);-webkit-background-clip:text;color:transparent}.abt p{color:var(--mut);line-height:1.8}
@media (max-height:640px){.nv{min-height:40px}}
@media (max-width:980px){.cst .mu,.cmeta span:not(.bd):not(.pc){display:none}.bcards{grid-template-columns:repeat(2,1fr)}}
.cr{width:38px;height:38px;border-radius:50%;background:conic-gradient(#ea4335 0 33.3%,#fbbc05 0 66.6%,#34a853 0);position:relative}.cr i{position:absolute;inset:25%;border-radius:50%;background:#4285f4;border:3px solid #fff}
.bl{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;color:#fff;font-weight:800;font-size:20px}

.nv.bi-nv{flex-wrap:nowrap;gap:12px}.nv.bi-nv>svg{flex:none}.nv.bi-nv>span:first-of-type{flex:1 1 auto;min-width:0;line-height:1.15}.nv .st{flex:none}
.urlbar input[type=text],.cs input[type=text]{background:none;border:0;padding:0;border-radius:0;width:100%}

.ph{flex-wrap:nowrap}.ph h2{min-width:0;overflow:hidden}.ph h2 span{overflow:hidden;text-overflow:ellipsis}.cs{min-width:0;flex:0 1 190px}.pill{flex:none}
.ph .cs input{min-width:0}
@media (max-width:1500px){
.nv.bi-nv{flex-wrap:wrap;row-gap:2px;padding-top:7px;padding-bottom:7px}.nv.bi-nv>span:first-of-type{flex:1 1 calc(100% - 50px)}.nv.bi-nv .st{margin-inline-start:46px;height:26px;font-size:12px}
.ph h2 small{display:none}.chips{padding-top:10px}}
@media (max-width:1180px){.pill{padding:0 11px}.pill svg{display:none}.pill.sq svg{display:block}}

</style></head><body>
<div class="app" id="app"><header class="hdr"><div class="brand"><svg class="logo" viewBox="0 0 100 100" width="64" height="64" aria-hidden="true"><defs>
<linearGradient id="lg1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#7fe3ff"/><stop offset=".55" stop-color="#2d8bff"/><stop offset="1" stop-color="#2a4fe0"/></linearGradient>
<linearGradient id="lg2" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#7fd9ff"/></linearGradient>
<filter id="lgl" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="2.4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
<g filter="url(#lgl)"><path d="M32 8H68V36H88L50 80 12 36H32Z" fill="none" stroke="url(#lg1)" stroke-width="6" stroke-linejoin="round"/>
<path d="M58 4 27 54H47L40 96 76 44H55Z" fill="url(#lg2)" stroke="#1b6dff" stroke-width="2" stroke-linejoin="round"/></g></svg><div class="bt"><b>UDM</b><small data-i="Unlimited Download Manager">Unlimited Download Manager</small></div></div>
<div class="tools"><button class="ib" data-a="gear" title="Settings"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z"/></svg></button>
<button class="ib" data-a="theme" id="thm" title="Theme"></button><button class="ib" data-a="lang" id="lng" title="Language"><span class="lg"></span></button>
<button class="ib" data-a="bell" id="bell" title="Notifications"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 17V11a6 6 0 1112 0v6l2 2H4z"/><path d="M10 21a2 2 0 004 0"/></svg><i class="dot" hidden></i></button><i class="vsep"></i>
<button class="ib wc" data-a="min"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/></svg></button><button class="ib wc" data-a="max"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="14" height="14" rx="1.5"/></svg></button><button class="ib wc" data-a="close"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg></button></div>
<div class="urlrow"><div class="urlbar"><svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 007 0l3-3a5 5 0 00-7-7l-1 1M14 11a5 5 0 00-7 0l-3 3a5 5 0 007 7l1-1"/></svg><input id="url" type="text" spellcheck="false" autocomplete="off"><button class="chev" data-a="chev"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg></button></div>
<button class="dlbtn" data-a="dl"><svg width="30" height="30" viewBox="0 0 24 24" fill="currentColor"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg><span data-i="Download">Download</span></button></div><div id="updbar" style="display:none;grid-column:1/4"></div></header>
<aside><nav id="nav"></nav><div class="art"><img class="wolf" src="data:image/jpeg;base64,__WOLF__" alt=""></div></aside><main class="main" id="main"></main></div><div id="toasts"></div><div class="dz" id="dz" data-i="Drop links or files here to download">Drop links or files here to download</div>
<script>
const T="__TOKEN__",$=(s,e=document)=>e.querySelector(s),$$=(s,e=document)=>[...e.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

const AR={'Unlimited Download Manager':'مدير التحميل غير المحدود','Tasks':'المهام','File':'ملف','Downloads':'التحميلات','View':'عرض','Help':'مساعدة','Search in the List':'ابحث في القائمة',
'Add URL / batch':'إضافة رابط / دفعة','Grabber…':'تنزيل المواقع…','Delete completed':'حذف المكتمل','Exit':'خروج','Options…':'الإعدادات…',
'Resume':'استكمال','Stop':'إيقاف','Stop all':'إيقاف الكل','Delete':'حذف','Start queue':'تشغيل القائمة','Stop queue':'إيقاف القائمة','Refresh':'تحديث','Quick start':'بدء سريع','About':'حول البرنامج',
'All Downloads':'كل التحميلات','Unfinished':'غير مكتملة','Finished':'مكتملة','Uncategorized':'بدون تصنيف','General':'عام','Musics':'الموسيقى','Compressed':'مضغوطات','Videos':'فيديو','Programs':'برامج','Documents':'مستندات','APKs':'تطبيقات أندرويد','Images':'صور',
'Name':'الاسم','Size':'الحجم','Status':'الحالة','Time Left':'الوقت المتبقي','Last Modification':'آخر تعديل','Complete':'مكتمل','Paused':'متوقف','Queued':'في الانتظار','Pausing…':'جاري الإيقاف…','Error':'خطأ',
'Music':'موسيقى','Archive':'أرشيف','Video':'فيديو','Program':'برنامج','Document':'مستند','App':'تطبيق','Image':'صورة','Today':'اليوم','Sec':'ث','Min':'د','Hr':'س',
'Select All':'تحديد الكل','Speed Test :':'اختبار السرعة :','Mbs':'ميجابت/ث','Disk Space':'مساحة القرص','Add Url':'إضافة رابط','Stop All':'إيقاف الكل','Options':'الإعدادات','Queues':'القوائم','Scheduler':'الجدولة','Share':'مشاركة',
'Open':'فتح','Open folder':'فتح المجلد','Properties':'خصائص','ZIP preview':'معاينة ZIP','Copy link':'نسخ الرابط','Move to queue…':'نقل إلى قائمة…','Cancel':'إلغاء','Download Later':'حمّل لاحقاً','Download Now':'حمّل الآن','Save':'حفظ','Close':'إغلاق','New':'جديد','New queue':'قائمة جديدة','Start':'تشغيل','Start Queue':'تشغيل القائمة','Stop Queue':'إيقاف القائمة','Save & Run':'حفظ وتشغيل',
'Add URL':'إضافة رابط','Links — one per line (pattern: file[01-10].zip)':'الروابط — رابط في كل سطر (نمط: file[01-10].zip)','Category (optional)':'التصنيف (اختياري)','Auto':'تلقائي حسب النوع','Save to (empty = automatic)':'مكان الحفظ (فارغ = تلقائي)','Connections':'الاتصالات','Description':'الوصف','Queue (for Download Later)':'القائمة (للتحميل لاحقاً)','Referer':'المرجع (Referer)','Cookies':'الكوكيز','Username':'اسم المستخدم','Password':'كلمة المرور',
'Language':'اللغة','Theme':'المظهر','dark':'داكن','light':'فاتح','none':'بدون','system':'النظام','manual':'يدوي','hour':'ساعة','day':'يوم','Mon':'الاثنين','Tue':'الثلاثاء','Wed':'الأربعاء','Thu':'الخميس','Fri':'الجمعة','Sat':'السبت','Sun':'الأحد',
'Connection':'الاتصال','Proxy':'البروكسي','Types & sites':'الأنواع والمواقع','Save to':'مكان الحفظ','Antivirus':'مضاد الفيروسات',
'Monitor clipboard for links':'مراقبة الحافظة للروابط','Capture downloads from the browser extension':'التقاط التحميلات من إضافة المتصفح','Silent mode (add without asking)':'الوضع الصامت (إضافة بدون سؤال)','Completion notification':'إشعار عند الانتهاء','Sounds':'الأصوات','Start with Windows':'التشغيل مع ويندوز','Keep running in tray when window closes':'الاستمرار في شريط المهام عند إغلاق النافذة','Ask before deleting':'السؤال قبل الحذف',
'Connections per download (1-32)':'عدد الاتصالات لكل تحميل (1-32)','Timeout (seconds)':'مهلة الاتصال (ثانية)','Retries after error':'عدد المحاولات بعد الخطأ','Speed limit KB/s (0 = unlimited)':'حد السرعة كيلوبايت/ث (0 = بلا حد)','Quota MB (0 = off)':'حصة التحميل ميجابايت (0 = معطلة)','Quota period':'فترة الحصة','FTP passive mode':'وضع FTP السلبي','Ignore modification-time changes on resume':'تجاهل تغيّر تاريخ التعديل عند الاستكمال','Per-server limits — one per line: *.site.com=4':'حدود لكل سيرفر — سطر لكل واحد: *.site.com=4',
'Mode':'الوضع','HTTP proxy host:port':'بروكسي HTTP (مضيف:منفذ)','HTTPS proxy host:port':'بروكسي HTTPS (مضيف:منفذ)','FTP proxy host:port':'بروكسي FTP (مضيف:منفذ)','No proxy for (;)':'بدون بروكسي لـ (;)','If a download fails, retry it using the system proxy':'إذا فشل تحميل، أعد المحاولة باستخدام بروكسي النظام',
'Captured file types':'أنواع الملفات الملتقطة','Excluded file types':'أنواع ملفات مستثناة','Excluded sites (wildcards)':'مواقع مستثناة (يدعم *)','URL exceptions (wildcards)':'روابط مستثناة (يدعم *)',
'Temporary folder (empty = next to file)':'المجلد المؤقت (فارغ = بجوار الملف)','Remember last folder per category':'تذكر آخر مجلد لكل تصنيف','Categories — one per line: Name | extensions | folder':'التصنيفات — سطر لكل تصنيف: الاسم | الامتدادات | المجلد','Logins — one per line: site | user | password (encrypted when saved)':'الحسابات — سطر لكل حساب: الموقع | المستخدم | كلمة المرور (تُشفّر عند الحفظ)',
'Scan files after download':'فحص الملفات بعد التحميل','Antivirus program':'برنامج مضاد الفيروسات','Arguments ({file} = downloaded file)':'المعاملات ({file} = الملف المحمّل)',
'Queue':'القائمة','Start time (HH:MM, empty = manual)':'وقت البدء (HH:MM، فارغ = يدوي)','Stop time (HH:MM)':'وقت الإيقاف (HH:MM)','Max parallel downloads':'أقصى عدد تحميلات متزامنة','Shut down computer when finished':'إغلاق الجهاز عند الانتهاء','Exit program when finished':'إغلاق البرنامج عند الانتهاء',
'Project':'المشروع','Start URL':'رابط البداية','Depth (levels)':'العمق (مستويات)','File types (ext list or *)':'أنواع الملفات (امتدادات أو *)','Website filters (wildcards)':'فلاتر المواقع (يدعم *)','Queue (empty = start now)':'القائمة (فارغ = ابدأ الآن)','Run daily at (HH:MM)':'تشغيل يومياً الساعة (HH:MM)','Repeat every N hours (0 = off)':'تكرار كل N ساعة (0 = معطل)','Synchronize: only new / changed files':'مزامنة: الملفات الجديدة أو المتغيرة فقط','Grabber — download websites':'تنزيل المواقع',
'File name':'اسم الملف','Main download queue':'قائمة التحميل الرئيسية','Synchronization queue':'قائمة المزامنة','Also delete the files from disk':'احذف الملفات من القرص أيضاً',
'Enter a valid link':'أدخل رابطاً صحيحاً','Saved':'تم الحفظ','Link(s) copied':'تم نسخ الرابط','Download complete':'اكتمل التحميل','New version available':'نسخة جديدة متاحة','Update now':'حدّث الآن','Install and restart':'ثبّت وأعد التشغيل','Later':'لاحقاً','Check for updates…':'التحقق من التحديثات…','Downloading update…':'جارٍ تنزيل التحديث…','Update downloaded':'تم تنزيل التحديث','You have the latest version':'لديك أحدث نسخة','Could not check for updates':'تعذّر التحقق من التحديثات','Update failed':'فشل التحديث','Installing update…':'جارٍ تثبيت التحديث…','Downloads will pause and resume after the restart':'ستتوقف التحميلات مؤقتاً ويمكن استئنافها بعد إعادة التشغيل','Extract the new portable version over the old folder':'فُكّ ضغط النسخة المحمولة الجديدة فوق المجلد القديم','Drop links or files here to download':'أفلت الروابط أو الملفات هنا للتحميل','No links found in the dropped item':'لا توجد روابط في العنصر الذي أفلتّه',
'QS':'انسخ أي رابط وستظهر نافذة الإضافة تلقائياً.<br>اسحب الروابط أو الملفات النصية وأفلتها داخل النافذة.<br>استخدم «حمّل لاحقاً» مع الجدولة للتحميل في وقت محدد.<br>القائمة الجانبية ← ربط المتصفح لتوصيل Chrome / Brave / Edge / Firefox.','EXT':'تم إنشاء الإضافة في:','EXT2':'Chrome/Edge ← الإضافات ← وضع المطوّر ← Load unpacked','ABOUT':'مدير التحميل المتكامل','ZIP Preview':'معاينة ZIP','Delete':'حذف','Queue name:':'اسم القائمة:','Video Downloader':'تحميل الفيديو','Video Downloader…':'تحميل الفيديو…','Analyze':'تحليل','Analyzing…':'جاري التحليل…','Detected in browser':'تم اكتشافه في المتصفح','Clear list':'مسح القائمة','No videos detected yet':'لم يتم اكتشاف فيديوهات بعد — شغّل فيديو في المتصفح (مع إضافة UDM)','Direct download':'تحميل مباشر','Quality':'الجودة','Format':'الصيغة','Audio only':'صوت فقط','Download':'تحميل','Estimated size':'الحجم التقديري','Best':'الأفضل','Update yt-dlp':'تحديث yt-dlp','Updating…':'جاري التحديث…','Video download started':'بدأ تحميل الفيديو','Video':'فيديو','Browser Integration':'ربط المتصفح','Browser Integration…':'ربط المتصفح…','Choose your browser':'اختر المتصفح','installed':'مثبّت','not found':'غير موجود','Open the extensions page':'افتح صفحة الإضافات','Open extension folder':'افتح مجلد الإضافة','Copy folder path':'نسخ مسار المجلد','Check Connection':'تحقق من الاتصال','Back':'رجوع','Waiting for the extension…':'بانتظار الإضافة…','Connected successfully':'تم الربط بنجاح','The extension is ready.':'الإضافة جاهزة.','Native host registered':'تم تسجيل الـ Host','Extension files prepared':'تم تجهيز ملفات الإضافة','Extension detected':'تم اكتشاف الإضافة','Connection type':'نوع الاتصال','Native Messaging':'Native Messaging','Local connection (fallback)':'اتصال محلي (احتياطي)','Install the signed add-on':'ثبّت الإضافة الموقّعة','Not connected yet':'لم يتم الاتصال بعد','Test link':'اختبار الرابط','Resume capability':'دعم الاستكمال','Duplicate download link':'الرابط موجود بالفعل في القائمة','Skip':'تخطَّ','Add it with a numbered file name':'أضفه باسم ملف مرقّم','Add it and replace the old download':'أضفه واستبدل التحميل القديم','Speed limit for this download KB/s (0 = none)':'حد السرعة لهذا التحميل كيلوبايت/ث (0 = بلا حد)','Checksum MD5 / SHA-1 / SHA-256 (optional)':'بصمة الملف MD5 / SHA-1 / SHA-256 (اختياري)','Import list…':'استيراد قائمة…','Export list…':'تصدير قائمة…','Export selected':'تصدير المحدد','Copy folder path':'نسخ مسار المجلد','Refresh download address…':'تحديث عنوان التحميل…','Or paste the new address here:':'الصق العنوان الجديد هنا:','Redownload':'إعادة التحميل','Check file (SHA-256)':'فحص الملف (SHA-256)','Limiter: On':'المحدِّد: يعمل','Limiter: Off':'المحدِّد: متوقف','Maximum download speed (KB/s)':'أقصى سرعة تحميل (كيلوبايت/ث)','Once on date (YYYY-MM-DD, empty = every selected day)':'مرة واحدة في تاريخ (YYYY-MM-DD، فارغ = كل الأيام المحددة)','Save all files of this queue to':'احفظ كل ملفات هذه القائمة في','When the queue is done':'عند انتهاء القائمة','Downloads at the same time (0 = no limit)':'تحميلات في نفس الوقت (0 = بلا حد)','If a duplicate link is added':'إذا أُضيف رابط مكرر','Give finished files the date from the server':'اعطِ الملفات المكتملة تاريخ السيرفر','Open each file when it has finished downloading':'افتح كل ملف عند اكتمال تحميله','Color palette':'لوحة الألوان','Text size (%)':'حجم النص (%)','Don\'t go to parent folders':'لا تصعد للمجلدات الأعلى','Download a playlist':'تحميل قائمة تشغيل','Getting the list…':'جاري جلب القائمة…','Check all':'تحديد الكل','Uncheck all':'إلغاء التحديد','Download checked':'حمّل المحدد','Subtitles too':'مع الترجمة','Exact cut':'قص دقيق','From':'من','To':'إلى','default':'افتراضي','ocean':'أزرق المحيط','forest':'أخضر الغابة','purple':'بنفسجي منتصف الليل','rose':'وردي','sunset':'غروب','teal':'فيروزي','neon':'نيون','clay':'طيني','ask':'اسألني','replace':'استبدل','number':'رقّمه','skip':'تخطَّ','exit':'إغلاق البرنامج','sleep':'سكون','hibernate':'إسبات','shutdown':'إيقاف التشغيل'};

const EN={QS:'Copy a link and the Add dialog appears automatically.<br>Drag &amp; drop links or text files into the window.<br>Use “Download Later” + Scheduler for timed downloads.<br>Browser Integration (left menu) to connect Chrome / Brave / Edge / Firefox.',EXT:'Extension created in:',EXT2:'Chrome/Edge → Extensions → Developer mode → Load unpacked',ABOUT:'Unlimited Download Manager'};
const DISP={exit:'Exit the program',sleep:'Sleep',hibernate:'Hibernate',shutdown:'Shut down',default:'Default',ocean:'Ocean blue',forest:'Forest green',purple:'Midnight purple',rose:'Rose',sunset:'Sunset',teal:'Teal night',neon:'Cyber neon',clay:'Soft clay',ask:'Ask me',replace:'Replace the old one',number:'Number the file',skip:'Skip it',high:'High speed',medium:'Medium',low:'Low speed',mobile:'Mobile',custom:'Custom',en:'English',ar:'العربية',dark:'Dark',light:'Light',none:'None',system:'System',manual:'Manual',hour:'Hour',day:'Day'};

let theme='dark',lang='en',pal='default',tsz=100;

const L=s=>(lang=='ar'&&AR[s])||DISP[s]||s,M=k=>lang=='ar'?AR[k]:EN[k];

const I={play:'<polygon points="6 4 20 12 6 20"/>',sq:'<rect x="5" y="5" width="14" height="14" rx="2"/>',clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',trash:'<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v5M14 11v5"/>',gear:'<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9L7 7M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1"/>',copy:'<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 012-2h9"/>',cal:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',share:'<path d="M4 12v7a1 1 0 001 1h14a1 1 0 001-1v-7M16 6l-4-4-4 4M12 2v14"/>',music:'<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',archive:'<rect x="3" y="3" width="18" height="5" rx="1"/><path d="M5 8v11a2 2 0 002 2h10a2 2 0 002-2V8M10 12h4"/>',video:'<rect x="2" y="6" width="14" height="12" rx="2"/><path d="M22 8l-6 4 6 4z"/>',win:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18"/>',doc:'<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M9 13h6M9 17h6"/>',apk:'<rect x="5" y="9" width="14" height="11" rx="2"/><path d="M7 9a5 5 0 0110 0M9 4l1.5 2M15 4l-1.5 2"/>',img:'<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/>',folder:'<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>',fin:'<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><path d="M9 14l2 2 4-4"/>',unf:'<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><path d="M12 10v6M9 14l3 3 3-3"/>',cloud:'<path d="M8 17l4 4 4-4M12 12v9"/><path d="M20.9 18.6A5 5 0 0018 9h-1.3A8 8 0 104 16.3"/>',link:'<path d="M10 13a5 5 0 007 0l3-3a5 5 0 00-7-7l-1 1M14 11a5 5 0 00-7 0l-3 3a5 5 0 007 7l1-1"/>',chev:'<path d="M6 9l6 6 6-6"/>',hdd:'<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/>',file:'<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/>'};

const ic=(n,s=20)=>`<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${I[n]||I.file}</svg>`;

const KIND={Musics:'Music',Compressed:'Archive',Videos:'Video',Programs:'Program',Documents:'Document',APKs:'App',Images:'Image'},CI={Musics:'music',Compressed:'archive',Videos:'video',Programs:'win',Documents:'doc',APKs:'apk',Images:'img'};

const fs=n=>n==null?'?':n<1024?n+' B':n<1048576?Math.round(n/1024)+' KB':n<1073741824?(n/1048576).toFixed(2)+' MB':(n/1073741824).toFixed(1)+' GB';
const ft=s=>{if(!isFinite(s)||s<=0)return'0 '+L('Sec');s=Math.round(s);const h=s/3600|0,m=s%3600/60|0,x=s%60;return h?`${h} ${L('Hr')} ${m} ${L('Min')}`:m?`${m} ${L('Min')} ${x} ${L('Sec')}`:`${x} ${L('Sec')}`};
const fd=t=>{if(!t)return'-';const d=new Date(t*1e3);return d.toDateString()==new Date().toDateString()?L('Today'):d.getFullYear()+'/'+String(d.getMonth()+1).padStart(2,'0')+'/'+String(d.getDate()).padStart(2,'0')};

async function api(op,b={}){const r=await fetch('/api/act',{method:'POST',headers:{'X-UDM-Token':T,'Content-Type':'application/json'},body:JSON.stringify({op,...b})});return r.json()}
function toast(m,ms=5000){const e=document.createElement('div');e.className='toast';e.innerHTML=m;$('#toasts').append(e);setTimeout(()=>e.remove(),ms);return e}
function modal(title,body,btns,wide){const o=document.createElement('div');o.className='ov';o.innerHTML=`<div class="dlg${wide?' wide':''}"><h3>${L(title)}</h3><div class="bd"></div><div class="f"></div></div>`;$('.bd',o).append(body);btns.forEach(b=>{const e=document.createElement('button');e.textContent=L(b.t);if(b.p)e.className='pri';e.onclick=async()=>{const r=await b.fn?.();if(r!==false)o.remove()};$('.f',o).append(e)});document.body.append(o);return o}
function form(fields,v0={}){const w=document.createElement('div');fields.forEach(([k,l,t,o])=>{const v=v0[k];let h;if(t=='chk')h=`<label class="chk"><input type="checkbox" name="${k}" ${v?'checked':''}><span>${L(l)}</span></label>`;else{let i;if(t=='area')i=`<textarea name="${k}" rows="${o||3}">${esc(v)}</textarea>`;else if(t=='sel')i=`<select name="${k}">${o.map(x=>`<option value="${esc(x)}" ${x==v?'selected':''}>${esc(L(x))}</option>`).join('')}</select>`;else i=`<input name="${k}" type="${t=='num'?'number':t=='pass'?'password':'text'}" value="${esc(v)}">`;h=`<label class="fld"><span>${L(l)}</span>${i}</label>`}w.insertAdjacentHTML('beforeend',h)});w.get=()=>{const r={};$$('[name]',w).forEach(e=>r[e.name]=e.type=='checkbox'?e.checked:e.type=='number'?+e.value:e.value);return r};return w}

/* ---------- dialogs ---------- */
function addDlg(pre={}){const f=form([['urls','Links — one per line (pattern: file[01-10].zip)','area',4],['category','Category (optional)','sel',['Uncategorized','Auto',...S.cats.filter(c=>c!='Uncategorized')]],['folder','Save to (empty = automatic)','text'],['nconn','Connections','num'],['description','Description','text'],['queue','Queue (for Download Later)','sel',S.queues.map(q=>q.name)],['referer','Referer','text'],['cookies','Cookies','text'],['user','Username','text'],['pwd','Password','pass'],['speed_limit_kb','Speed limit for this download KB/s (0 = none)','num'],['expect_hash','Checksum MD5 / SHA-1 / SHA-256 (optional)','text']],{urls:(pre.urls||[]).join('\n'),nconn:S.connections,referer:pre.referer||'',cookies:pre.cookies||'',category:'Uncategorized'});
const go=now=>async()=>{const v=f.get();if(!/(https?|ftp):\/\//i.test(v.urls)){toast(L('Enter a valid link'));return false}await addCall({...v,start:now,queue:now?'':v.queue})};
const o=modal('Add URL',f,[{t:'Cancel'},{t:'Test link',fn:async()=>{const u=($('[name=urls]',f).value.match(/(?:https?|ftp):\/\/\S+/)||[])[0];if(!u)return false;const r=await api('probe',{url:u,referer:$('[name=referer]',f).value,cookies:$('[name=cookies]',f).value});toast(r.err?esc(r.err):`${esc(r.name)}<br>${fs(r.size)} · ${L('Resume capability')}: ${r.resume?'✓':'✗'}`,9000);return false}},{t:'Download Later',fn:go(0)},{t:'Download Now',p:1,fn:go(1)}]),ta=$('[name=urls]',f),chk=()=>{const v=ta.value.trim();if(v&&!/\s/.test(v)&&isVid(v)){o.remove();videoDlg(v,pre)}};ta.addEventListener('paste',()=>setTimeout(chk,60));ta.addEventListener('change',chk)}
const OPT=[['General',[['language','Language','sel',['en','ar']],['theme','Theme','sel',['dark','light']],['palette','Color palette','sel',['default','ocean','forest','purple','rose','sunset','teal','neon','clay']],['text_size','Text size (%)','num'],['clipboard_monitor','Monitor clipboard for links','chk'],['capture_enabled','Capture downloads from the browser extension','chk'],['silent','Silent mode (add without asking)','chk'],['notify','Completion notification','chk'],['confirm_stop','Warn before stopping a download','chk'],['show_complete','Show a dialog when a download completes','chk'],['startup','Start with Windows','chk'],['tray','Keep running in tray when window closes','chk'],['confirm_delete','Ask before deleting','chk'],['dup_action','If a duplicate link is added','sel',['ask','replace','number','skip']],['server_date','Give finished files the date from the server','chk'],['open_after','Open each file when it has finished downloading','chk']]],
['Connection',[['conn_preset','Connection type','sel',['high','medium','low','mobile','custom']],['speed_mode','Speed mode','sel',['auto','manual']],['connections','Connections per download: maximum in Auto mode, fixed number in Manual (1-32)','num'],['host_max_conn','Max connections per website (0 = no limit)','num'],['write_buffer_kb','Disk write buffer per connection (KB)','num'],['keepalive','Reuse connections (Keep-Alive)','chk'],['max_parallel','Downloads at the same time (0 = no limit)','num'],['timeout','Timeout (seconds)','num'],['retries','Retries after error','num'],['speed_limit_kb','Speed limit KB/s (0 = unlimited)','num'],['quota_mb','Quota MB (0 = off)','num'],['quota_period','Quota period','sel',['hour','day']],['user_agent','User-Agent','text'],['ftp_passive','FTP passive mode','chk'],['ignore_mtime','Ignore modification-time changes on resume','chk'],['server_limits','Per-server limits — one per line: *.site.com=4','area']]],
['Proxy',[['proxy_mode','Mode','sel',['none','system','manual']],['proxy_http','HTTP proxy host:port','text'],['proxy_https','HTTPS proxy host:port','text'],['proxy_ftp','FTP proxy host:port','text'],['proxy_user','Username','text'],['proxy_pass','Password','pass'],['proxy_exclude','No proxy for (;)','text'],['proxy_fallback','If a download fails, retry it using the system proxy','chk']]],
['Types & sites',[['capture_types','Captured file types','area',3],['excluded_types','Excluded file types','area',2],['excluded_sites','Excluded sites (wildcards)','area',2],['url_exceptions','URL exceptions (wildcards)','area',2]]],
['Save to',[['temp_dir','Temporary folder (empty = next to file)','text'],['remember_dir','Remember last folder per category','chk'],['cat_folder_follow','Change the category folder when I pick a different folder','chk'],['cats_text','Categories — one per line: Name | extensions | folder','area',6],['logins_text','Logins — one per line: site | user | password (encrypted when saved)','area',3]]],
['Antivirus',[['av_enabled','Scan files after download','chk'],['av_command','Antivirus program','text'],['av_args','Arguments ({file} = downloaded file)','text']]],
['Sounds',[['sounds','Play sounds','chk'],['sound_done','Sound: download complete (file, empty = default beep)','text'],['sound_error','Sound: download failed','text'],['sound_qstart','Sound: queue started','text'],['sound_qstop','Sound: queue finished','text']]]];
async function optDlg(){const c=await api('cfg_get'),w=document.createElement('div'),tabs=document.createElement('div'),fm=OPT.map(([n,fl])=>form(fl,c));tabs.className='tabs';
const show=i=>{$$('span',tabs).forEach((s,j)=>s.className=i==j?'on':'');fm.forEach((f,j)=>f.style.display=i==j?'':'none')};OPT.forEach(([n],i)=>{const s=document.createElement('span');s.textContent=n;s.onclick=()=>show(i);tabs.append(s)});w.append(tabs,...fm);show(0);const ps=$('[name=conn_preset]',fm[1]),cn=$('[name=connections]',fm[1]);if(ps&&cn){const PM={high:32,medium:16,low:8,mobile:4};ps.onchange=()=>{if(PM[ps.value])cn.value=PM[ps.value]};cn.onchange=()=>{ps.value='custom'}}
modal('Options',w,[{t:'Cancel'},{t:'Save',p:1,fn:async()=>{const cfg=Object.assign({},...fm.map(f=>f.get()));await api('cfg_set',{cfg});toast(L('Saved'));poll()}}],1)}
function schedDlg(name){name=name||S.queues[0].name;const q=S.queues.find(x=>x.name==name),D=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],v={...q};D.forEach((d,i)=>v['d'+i]=q.days.includes(i));v.after=q.after||(q.shutdown?'shutdown':q.exit?'exit':'none');
const f=form([['name','Queue','sel',S.queues.map(x=>x.name)],['start','Start time (HH:MM, empty = manual)','text'],['stop','Stop time (HH:MM)','text'],['parallel','Max parallel downloads','num'],...D.map((d,i)=>['d'+i,d,'chk']),['date','Once on date (YYYY-MM-DD, empty = every selected day)','text'],['folder','Save all files of this queue to','text'],['after','When the queue is done','sel',['none','exit','sleep','hibernate','shutdown']],['open_after','Open this file when the queue is done','text'],['start_on_startup','Start this queue on program startup','chk'],['retries','Retries per file (0 = use the global setting)','num']],v);
$('select',f).onchange=e=>{$('.ov').remove();schedDlg(e.target.value)};
const save=async()=>{const x=f.get();x.days=D.map((d,i)=>x['d'+i]?i:-1).filter(i=>i>=0);await api('qsave',x);poll()};
modal('Scheduler',f,[{t:'Close'},{t:'Stop Queue',fn:async()=>{await api('qstop',{name});poll()}},{t:'Start Queue',fn:async()=>{await save();await api('qstart',{name});poll()}},{t:'Save',p:1,fn:save}])}
function queuesDlg(){const w=document.createElement('div');w.innerHTML=S.queues.map(q=>`<div class="lr"><span>${esc(q.name)} <small style="color:var(--mut)">(${q.count} items${q.active?' · running':''})</small></span><button data-q="start" data-n="${esc(q.name)}">Start</button><button data-q="stop" data-n="${esc(q.name)}">Stop</button>${['Main download queue','Synchronization queue'].includes(q.name)?'':`<button data-q="del" data-n="${esc(q.name)}">Delete</button>`}</div>`).join('');
const o=modal('Queues',w,[{t:'New queue',fn:()=>{const n=prompt('Queue name');if(n)api('qnew',{name:n}).then(poll)}},{t:'Close',p:1}]);w.onclick=async e=>{const b=e.target.closest('[data-q]');if(b){await api('q'+b.dataset.q,{name:b.dataset.n});await poll();o.remove();queuesDlg()}}}
async function grabDlg(id){const g=(await api('glist')).items,cur=g.find(x=>x.id==id)||g[0];
const f=form([['id','Project','sel',g.map(x=>x.id+' — '+x.name)],['name','Name','text'],['url','Start URL','text'],['depth','Depth (levels)','num'],['types','File types (ext list or *)','text'],['filters','Website filters (wildcards)','text'],['folder','Save to','text'],['queue','Queue (empty = start now)','text'],['schedule','Run daily at (HH:MM)','text'],['interval_h','Repeat every N hours (0 = off)','num'],['stay',"Don't go to parent folders",'chk'],['sync','Synchronize: only new / changed files','chk']],cur?{...cur,id:cur.id+' — '+cur.name}:{});
if(cur)$('select',f).onchange=e=>{$('.ov').remove();grabDlg(e.target.value.split(' — ')[0])};else $('select',f).parentElement.style.display='none';
const get=()=>{const v=f.get();v.id=cur?cur.id:'';return v};
modal('Grabber — download websites'+(cur?` (${cur.status||'Idle'}, found ${cur.found||0})`:''),f,[{t:'Close'},{t:'New',fn:async()=>{await api('gnew');grabDlg()}},{t:'Delete',fn:async()=>{if(cur)await api('gdel',{id:cur.id})}},{t:'Stop',fn:()=>api('gstop',{id:cur?.id})},{t:'Save & Run',p:1,fn:async()=>{await api('gsave',get());await api('grun',{id:get().id})}},{t:'Save',fn:async()=>{await api('gsave',get())}}],1)}
function propsDlg(t){const f=form([['name','File name','text'],['folder','Save to','text'],['description','Description','text'],['nconn','Connections','num'],['speed_limit_kb','Speed limit for this download KB/s (0 = none)','num'],['referer','Referer','text'],['cookies','Cookies','text'],['user','Username','text'],['pwd','Password','pass']],{speed_limit_kb:t.speed_limit_kb,name:t.name,folder:t.folder,description:t.desc,nconn:t.nconn,referer:t.referer,cookies:t.cookies,user:t.user,pwd:t.pwd});
const i=document.createElement('div');i.style.cssText='color:var(--mut);font-size:13px;margin-bottom:12px;user-select:text;word-break:break-all';i.innerHTML=`${esc(t.url)}<br>Size: ${fs(t.size)} · Resume supported: ${t.res?'Yes':'No / unknown'} · Connections now: ${t.conn}${t.hash?'<br>Checksum: '+esc(t.hash):''}`;const w=document.createElement('div');w.append(i,f);
modal('Properties',w,[{t:'Cancel'},{t:'Save',p:1,fn:async()=>{const r=await api('props',{id:t.id,...f.get()});if(r.err){toast(esc(r.err));return false}poll()}}])}
async function zipDlg(t){const r=await api('zip',{id:t.id}),w=document.createElement('div');w.innerHTML=r.err?esc(r.err):r.rows.map(x=>`<div class="lr"><span>${esc(x[0])}</span><small>${fs(x[1])}</small></div>`).join('');modal('ZIP Preview',w,[{t:'Close',p:1}],1)}

/* ---------- actions ---------- */
const BR={chrome:{n:'Google Chrome',c:'#e94235',l:'C'},brave:{n:'Brave',c:'#fb542b',l:'B'},edge:{n:'Microsoft Edge',c:'#0a7bd8',l:'E'},firefox:{n:'Mozilla Firefox',c:'#ff7139',l:'F'}};
const mk=(k,t)=>({url:`<rect x="14" y="14" width="392" height="30" rx="15" fill="#2a2d3a"/><text x="34" y="34" fill="#cbd5e1" font-size="13" font-family="Segoe UI">${t}</text><circle cx="396" cy="29" r="0"/>`,
toggle:`<rect x="14" y="14" width="392" height="26" rx="6" fill="#2a2d3a"/><text x="26" y="32" fill="#cbd5e1" font-size="12" font-family="Segoe UI">Extensions</text><text x="268" y="32" fill="#cbd5e1" font-size="12" font-family="Segoe UI">${t}</text><rect x="352" y="19" width="40" height="16" rx="8" fill="#8b5cf6"/><circle cx="384" cy="27" r="6" fill="#fff"/><rect x="262" y="12" width="140" height="30" rx="8" fill="none" stroke="#f59e0b" stroke-width="2.5"/>`,
load:`<rect x="14" y="12" width="392" height="62" rx="8" fill="#2a2d3a"/><rect x="26" y="24" width="122" height="30" rx="8" fill="#8b5cf6"/><text x="38" y="44" fill="#fff" font-size="12" font-family="Segoe UI">${t}</text><rect x="20" y="19" width="134" height="40" rx="10" fill="none" stroke="#f59e0b" stroke-width="2.5"/><rect x="170" y="24" width="90" height="30" rx="8" fill="#374151"/><rect x="272" y="24" width="90" height="30" rx="8" fill="#374151"/>`,
back:`<rect x="14" y="14" width="392" height="46" rx="10" fill="#10b9812e" stroke="#10b981"/><text x="30" y="43" fill="#10b981" font-size="14" font-family="Segoe UI">✔ ${t}</text>`}[k]);
const svg=(k,t,h=76)=>`<svg class="mk" viewBox="0 0 420 ${h}">${mk(k,t)}</svg>`;
async function browserDlg(pre){
 const w=document.createElement('div'),info=await api('ext_info');let cur=null,timer=null;
 const o=modal('Browser Integration',w,[{t:'Close',fn:()=>{clearInterval(timer)}}],1);
 const cards=()=>{w.innerHTML=`<p style="color:var(--mut);margin-bottom:10px">${L('Choose your browser')}</p><div class="bcards">${info.browsers.map(b=>`<div class="bc" data-b="${b.id}"><div class="bi" style="background:${BR[b.id].c}">${BR[b.id].l}</div><b>${BR[b.id].n}</b><small>${b.installed?'✓ '+L('installed'):L('not found')}${b.connected?' · 🟢':''}</small></div>`).join('')}</div>`};
 const stepHTML=(i,title,body)=>`<div class="stp"><i>${i}</i><div class="tx"><h5>${title}</h5>${body}</div></div>`;
 const wizard=async(k)=>{const r=await api('ext_prepare',{browser:k});cur=r;const fx=k=='firefox',nm=BR[k].n,en=lang!='ar';
  const btn=(id,t,p)=>`<button ${p?'class="pri"':''} id="${id}">${L(t)}</button>`;
  let steps='';
  if(!fx){
   steps+=stepHTML(1,L('Open the extensions page'),`<p>${en?`Click the button, or type this in the address bar:`:`اضغط الزر، أو اكتب هذا العنوان في شريط العنوان:`} <code>${esc(r.url)}</code></p>${svg('url',esc(r.url))}<div>${btn('bo','Open the extensions page',1)}</div>`);
   steps+=stepHTML(2,en?'Turn on Developer mode':'فعّل وضع المطوّر (Developer mode)',`<p>${en?'Use the switch at the top right of the page.':'استخدم المفتاح في أعلى يمين الصفحة.'}</p>${svg('toggle','Developer mode')}`);
   steps+=stepHTML(3,en?'Click “Load unpacked” and choose the UDM folder':'اضغط «Load unpacked» واختر مجلد UDM',`<p>${en?'In the folder window paste this path (use the Copy button) and press Select Folder:':'في نافذة اختيار المجلد الصق هذا المسار (زر النسخ) ثم اضغط Select Folder:'}</p><div class="pth">${esc(r.folder)}</div>${svg('load','Load unpacked')}<div style="margin-top:8px">${btn('bc2','Copy folder path')} ${btn('bf','Open extension folder')}</div>`);
   steps+=stepHTML(4,en?'Come back here':'ارجع هنا',`<p>${en?`If ${nm} says “Disable developer mode extensions”, keep it enabled (close the message).`:`لو ظهرت رسالة «Disable developer mode extensions» اتركها (أغلق الرسالة).`}</p>${svg('back',L('Connected successfully'))}`);
  }else{
   steps+=stepHTML(1,en?'Firefox needs a signed add-on':'فايرفوكس يشترط إضافة موقّعة',`<p>${en?'Firefox Release/Beta refuses unsigned add-ons permanently. UDM cannot bypass that. Pick the first method that applies to you:':'فايرفوكس (النسخة العادية) يرفض الإضافات غير الموقّعة بشكل دائم، وUDM مش بيقدر يتخطى ده. اختر أول طريقة تنطبق عليك:'}</p>`);
   steps+=stepHTML('A',en?'Signed add-on (permanent, one click)':'إضافة موقّعة (دائمة بضغطة واحدة)',r.signed_xpi?`<p>${en?'This UDM build includes a signed add-on. Firefox will ask you to confirm “Add”.':'نسخة UDM دي فيها إضافة موقّعة. فايرفوكس هيطلب منك تأكيد «Add».'}</p><div>${btn('bs','Install the signed add-on',1)}</div>`:`<p>${en?'Not included in this build (the build needs Mozilla signing keys). Use B or C.':'مش موجودة في النسخة دي (البناء يحتاج مفاتيح توقيع Mozilla). استخدم B أو C.'}</p>`);
   steps+=stepHTML('B',en?'Temporary add-on (any Firefox; lost when Firefox restarts)':'إضافة مؤقتة (أي فايرفوكس؛ بتختفي عند إعادة التشغيل)',`<p>${en?'Open the page, click “Load Temporary Add-on…”, then choose manifest.json from the UDM folder:':'افتح الصفحة، اضغط «Load Temporary Add-on…»، ثم اختر manifest.json من مجلد UDM:'}</p><div class="pth">${esc(r.folder)}</div><div style="margin-top:8px">${btn('bo','Open the extensions page',1)} ${btn('bc2','Copy folder path')} ${btn('bf','Open extension folder')}</div>`);
   steps+=stepHTML('C',en?'Permanent without signing: Firefox Developer Edition / Nightly / ESR':'دائمة بدون توقيع: Developer Edition أو Nightly أو ESR',`<p>${en?'In about:config set xpinstall.signatures.required to false, then in about:addons click the gear → “Install Add-on From File…” and choose:':'في about:config اجعل xpinstall.signatures.required = false، ثم في about:addons اضغط الترس ← «Install Add-on From File…» واختر:'}</p><div class="pth">${esc(r.xpi||'')}</div>`);
  }
  w.innerHTML=`<div style="display:flex;align-items:center;gap:10px"><button id="bb">← ${L('Back')}</button><b style="font-size:16px">${nm}</b></div>${steps}<div id="bres"><div style="padding:14px 0"><button class="pri" id="bk">${L('Check Connection')}</button> <span id="bst" style="color:var(--mut)"></span></div></div>`;};
 const check=async(k)=>{const st=$('#bst',w);let n=0;st.textContent='⏳ '+L('Waiting for the extension…');clearInterval(timer);
  const once=async()=>{n++;const r=await api('ext_check',{browser:k});if(r.connected){clearInterval(timer);const via=r.via=='native'?L('Native Messaging'):L('Local connection (fallback)');
    $('#bres',w).innerHTML=`<div class="okb"><b>✔ ${L('Connected successfully')} — ${BR[k].n}</b><br>${L('The extension is ready.')}<br><small>${L('Connection type')}: ${via} · v${esc(r.ext_version||'')}</small></div>`;return}
   const lines=[`${r.prepared?'✔':'✗'} ${L('Extension files prepared')}`,`${r.host_registered?'✔':'✗'} ${L('Native host registered')}`,`⏳ ${L('Extension detected')}`];
   st.innerHTML=lines.join(' · ')+(r.others&&r.others.length?`<br><span style="color:#f59e0b">${en2()?'A different browser answered: ':'ردّ متصفح آخر: '}${r.others.join(', ')}</span>`:'');
   if(n>=30){clearInterval(timer);st.innerHTML=`<span style="color:#f59e0b">${L('Not connected yet')} — ${lang=='ar'?'تأكد من اتباع الخطوات ثم اضغط التحقق مرة أخرى.':'make sure the steps are done, then check again.'}</span>`}};
  await once();if(!$('#bres .okb',w))timer=setInterval(once,2000)};
 const en2=()=>lang!='ar';
 w.addEventListener('click',async e=>{const g=s=>e.target.closest(s);let x;
  if(x=g('[data-b]')){await wizard(x.dataset.b)}
  else if(g('#bb')){clearInterval(timer);cards()}
  else if(g('#bo')){const r=await api('ext_open',{browser:cur.id,what:'manage'});if(r.err)toast(esc(r.err),12000)}
  else if(g('#bf'))api('ext_open',{browser:cur.id,what:'folder'});
  else if(g('#bs')){const r=await api('ext_open',{browser:cur.id,what:'signed'});if(r.err)toast(esc(r.err),12000)}
  else if(g('#bc2')){try{await navigator.clipboard.writeText(cur.folder);toast(L('Link(s) copied'))}catch(_){}}
  else if(g('#bk'))check(cur.id)});
 if(pre&&BR[pre])wizard(pre);else cards()}


async function addCall(p){const r=await api('add',p);if(r.dups){const d=document.createElement('div');d.style.cssText='user-select:text;word-break:break-all;max-height:140px;overflow:auto';d.innerHTML=r.dups.map(esc).join('<br>');modal('Duplicate download link',d,[{t:'Skip'},{t:'Add it with a numbered file name',fn:async()=>{await api('add',{...p,dup:'number'});poll()}},{t:'Add it and replace the old download',p:1,fn:async()=>{await api('add',{...p,dup:'replace'});poll()}}])}else poll()}
async function exportList(ids=[]){const r=await api('export',{ids});const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([r.text],{type:'text/plain'}));a.download='udm-list.ef2';a.click()}
function importList(){const i=document.createElement('input');i.type='file';i.accept='.ef2,.txt,.lst,.list';i.onchange=async()=>{const f=i.files[0];if(!f)return;const r=await api('import',{text:await f.text()});toast('✓ '+r.n);poll()};i.click()}
function renderLim(){const e=$('#lim');if(!e)return;e.textContent=S.limit?`⚡ ${L('Limiter: On')} (${S.limit} KB/s)`:L('Limiter: Off');e.style.color=S.limit?'var(--a1)':'var(--mut)'}
async function toggleLim(){if(S.limit){await api('cfg_set',{cfg:{limit_saved:S.limit,speed_limit_kb:0}})}else{const v=prompt(L('Maximum download speed (KB/s)'),S.limit_saved||500);if(!v)return;await api('cfg_set',{cfg:{speed_limit_kb:+v||0,limit_saved:+v||500}})}poll()}
function applyPal(p){pal=p;document.documentElement.dataset.pal=p}
function applyTS(n){tsz=n;document.body.style.zoom=n/100}


const isVid=u=>/(youtu\.be|youtube\.com|vimeo\.com|dailymotion\.com|facebook\.com\/.*(video|watch|reel)|fb\.watch|instagram\.com\/(reel|p|tv)|tiktok\.com|(twitter|x)\.com\/.*status|twitch\.tv|reddit\.com\/r\/.*comments|bilibili\.com|streamable\.com|rumble\.com|odysee\.com|rutube\.ru|(vk|ok)\.com\/.*video|\.m3u8|\.mpd)/i.test(u);
const hms=s=>{s=Math.round(s);const h=s/3600|0,m=s%3600/60|0,x=s%60,p=n=>String(n).padStart(2,'0');return h?`${h}:${p(m)}:${p(x)}`:`${m}:${p(x)}`};
async function videoDlg(u0='',ctx={}){
const w=document.createElement('div');
w.innerHTML=`<div style="display:flex;gap:8px"><input type="text" id="vu" style="flex:1;direction:ltr" placeholder="https://…  YouTube · video page · .m3u8 · .mpd"><button class="pri" id="va">${L('Analyze')}</button><button id="vpl">${L('Download a playlist')}</button></div><h4 style="margin:14px 0 4px;font-weight:500;color:var(--mut)">${L('Detected in browser')} <button id="vc" style="padding:3px 10px;font-size:12px">${L('Clear list')}</button></h4><div id="vd" style="max-height:170px;overflow:auto"></div><div id="vr"></div><div id="vt" style="margin-top:14px;color:var(--mut);font-size:13px"></div>`;
const o=modal('Video Downloader',w,[{t:'Close'}],1),V=s=>$(s,w);let cur=null,items=[],pick={h:0,c:'mp4',f:''};
const drawDet=async()=>{const r=await api('vlist');items=r.items;V('#vd').innerHTML=items.length?items.map(x=>`<div class="lr"><b class="badge">${x.type.toUpperCase()}</b><span title="${esc(x.url)}">${esc(x.title||x.host)} <small style="color:var(--mut)">${esc(x.host)}${x.size?' · '+fs(x.size):''}</small></span>${x.type=='mp4'?`<button data-d="${x.id}">${L('Direct download')}</button>`:''}<button data-an="${x.id}">${L('Analyze')}</button></div>`).join(''):`<div style="color:var(--mut);padding:8px 0">${L('No videos detected yet')}</div>`};
const drawRes=()=>{const r=cur,q=r.qualities.length?r.qualities:[{h:0,label:'Best',size:null}],mp3=pick.c=='mp3',sl=q.find(x=>x.h==pick.h),size=mp3?r.audio_size:sl&&sl.size;
V('#vr').innerHTML=`<div style="display:flex;gap:14px;margin-top:10px">${r.thumb?`<img class="vthumb" src="${esc(r.thumb)}" referrerpolicy="no-referrer">`:''}<div style="min-width:0"><b>${esc(r.title)}</b><div style="color:var(--mut);font-size:13px">${esc(r.uploader||'')} ${r.duration?'· '+hms(r.duration):''}</div></div></div><div style="margin-top:10px;color:var(--mut)">${L('Quality')}</div><div class="qcards">${q.map(x=>`<div class="qcard ${mp3?'off':''} ${x.h==pick.h&&!mp3?'on':''}" data-h="${x.h}"><span class="qb ${['8K','4K','2K'].includes(x.badge)?'k4':['Full HD','HD'].includes(x.badge)?'hd':'sd'}">${esc(x.badge||x.label)}</span><span class="qt">${esc(L(x.label))}${x.fps>30?' · '+x.fps+'fps':''}</span><span class="qm">${esc(x.codec||'')}${x.ext?' · '+esc(x.ext.toUpperCase()):''}</span><span class="qs">${x.size?fs(x.size):''}</span>${x.rec?`<span class="qr">★ ${L('Recommended')}</span>`:''}</div>`).join('')}</div><div style="margin-top:6px;color:var(--mut)">${L('Format')}</div><div>${['mp4','webm','mp3'].map(c=>`<span class="chip ${pick.c==c?'on':''}" data-c="${c}">${c=='mp3'?'MP3 ('+L('Audio only')+')':c.toUpperCase()}</span>`).join('')}</div><div style="display:flex;gap:10px;margin-top:6px"><label class="fld" style="flex:1"><span>${L('From')} (mm:ss)</span><input type="text" id="vs" value="${esc(pick.s||'')}"></label><label class="fld" style="flex:1"><span>${L('To')} (mm:ss)</span><input type="text" id="ve" value="${esc(pick.e||'')}"></label><label class="fld" style="flex:1"><span>${L('Subtitles too')} (en,ar)</span><input type="text" id="vsub" value="${esc(pick.sub||'')}"></label></div><label class="chk"><input type="checkbox" id="vx" ${pick.x?'checked':''}><span>${L('Exact cut')}</span></label><label class="fld" style="margin-top:8px"><span>${L('Save to (empty = automatic)')}</span><input type="text" id="vf" value="${esc(pick.f)}"></label><div style="display:flex;align-items:center;gap:12px"><button class="pri" id="vg">${L('Download')}</button><span style="color:var(--mut)">${size?L('Estimated size')+': '+fs(size):''}</span></div>`};
const analyze=async(url,referer='',cookies='')=>{url=(url||'').trim();if(!url)return;V('#vu').value=url;V('#vr').innerHTML=`<p style="padding:14px 0;color:var(--mut)">${L('Analyzing…')}</p>`;const r=await api('vinfo',{url,referer,cookies});if(r.err){V('#vr').innerHTML=`<p class="err" style="padding:10px 0;user-select:text">${esc(r.err)}</p>`;return}cur={...r,url,referer,cookies};pick={h:r.qualities.length?(r.qualities.find(q=>q.rec)||r.qualities[r.qualities.length-1]).h:0,c:'mp4',f:''};drawRes()};
const loadPl=async()=>{const url=V('#vu').value.trim();if(!url)return;V('#vr').innerHTML=`<p style="padding:14px 0;color:var(--mut)">${L('Getting the list…')}</p>`;const r=await api('vplaylist',{url});if(r.err){V('#vr').innerHTML=`<p class="err" style="padding:10px 0;user-select:text">${esc(r.err)}</p>`;return}
V('#vr').innerHTML=`<b>${esc(r.title)}</b> <small>(${r.entries.length})</small><div style="margin:8px 0"><button id="pla">${L('Check all')}</button> <button id="plu">${L('Uncheck all')}</button></div><div id="pll" style="max-height:200px;overflow:auto">${r.entries.map((e,i)=>`<label class="chk"><input type="checkbox" data-i="${i}" checked><span style="user-select:text">${esc(e.title)}${e.duration?' · '+hms(e.duration):''}</span></label>`).join('')}</div><div style="display:flex;gap:10px;margin-top:8px"><select id="plq">${[0,2160,1440,1080,720,480,360].map(h=>`<option value="${h}" ${h==1080?'selected':''}>${h?h+'p':L('Best')}</option>`).join('')}</select><select id="plc"><option>mp4</option><option>webm</option><option>mp3</option></select><input type="text" id="pls" placeholder="${L('Subtitles too')} (en,ar)"></div><button class="pri" id="pld" style="margin-top:10px">${L('Download checked')}</button>`;V('#vr')._pl=r};
const tools=async()=>{const t=await api('vtools');V('#vt').innerHTML=`yt-dlp ${esc(t.ytdlp||'✗')} · ffmpeg ${t.ffmpeg?'✓':'✗'} · deno ${t.deno?'✓':'✗'} <button id="vup" style="padding:3px 10px;font-size:12px;margin-inline-start:8px">${L('Update yt-dlp')}</button>`};
w.addEventListener('input',e=>{const k={vf:'f',vs:'s',ve:'e',vsub:'sub'}[e.target.id];if(k)pick[k]=e.target.value});w.addEventListener('change',e=>{if(e.target.id=='vx')pick.x=e.target.checked});
w.addEventListener('keydown',e=>{if(e.key=='Enter'&&e.target.id=='vu')analyze(e.target.value)});
w.addEventListener('click',async e=>{const g=s=>e.target.closest(s);let x;
if(g('#va'))analyze(V('#vu').value);else if(g('#vpl'))loadPl();else if(g('#pla')||g('#plu')){$$('#pll input',w).forEach(c=>c.checked=!!g('#pla'))}else if(g('#pld')){const r=V('#vr')._pl,sel=$$('#pll input:checked',w).map(c=>r.entries[+c.dataset.i]);if(sel.length){await api('vplaylist_dl',{urls:sel.map(e=>e.url),titles:sel.map(e=>e.title),title:r.title,height:+V('#plq').value,cont:V('#plc').value,subs:V('#pls').value});toast(L('Video download started'));poll();o.remove()}}else if(g('#vc')){await api('vclear');drawDet();poll()}
else if(x=g('[data-an]')){const it=items.find(i=>i.id==x.dataset.an);if(it)analyze(it.url,it.referer,it.cookies)}
else if(x=g('[data-d]')){const it=items.find(i=>i.id==x.dataset.d);if(it){const r=await api('popup_new',{url:it.url,referer:it.referer,cookies:it.cookies});if(r.started)toast(L('Video download started'));poll();o.remove()}}
else if(x=g('[data-h]')){pick.h=+x.dataset.h;drawRes()}else if(x=g('[data-c]')){pick.c=x.dataset.c;drawRes()}
else if(g('#vg')){const sl=cur.qualities.find(q=>q.h==pick.h);const r=await api('vpopup',{thumb:cur.thumb,url:cur.url,height:pick.h,cont:pick.c,folder:pick.f,start:pick.s,end:pick.e,exact:pick.x,subs:pick.sub,title:cur.title,size:pick.c=='mp3'?cur.audio_size:sl&&sl.size,referer:cur.referer,cookies:cur.cookies});if(r.started)toast(L('Video download started'));poll();o.remove()}
else if(g('#vup')){toast(L('Updating…'));const r=await api('ytdlp_update');toast(esc(r.out),9000);tools()}});
drawDet();tools();const iv=setInterval(()=>{if(!document.body.contains(w))clearInterval(iv);else drawDet()},3000);
if(u0)analyze(u0,ctx.referer||'',ctx.cookies||'')}


const A={resume:()=>api('resume',{ids:sel()}),stop:()=>{if(S.confirm_stop&&!confirm(L('Stop the selected downloads?')))return;api('stop',{ids:sel()})},stopall:()=>api('stopall'),
del:async()=>{const ids=sel();if(!ids.length)return;let files=false;if(S.confirm){const o=modal('Delete',Object.assign(document.createElement('div'),{innerHTML:`Remove ${ids.length} download(s) from the list?<label class="chk"><input type="checkbox" id="dfiles"><span>Also delete the files from disk</span></label>`}),[{t:'Cancel'},{t:'Delete',p:1,fn:async()=>{await api('delete',{ids,files:$('#dfiles').checked});st.sel.clear();poll()}}]);return}await api('delete',{ids,files});st.sel.clear();poll()},
share:()=>{const u=sel().map(i=>S.tasks.find(t=>t.id==i)?.url).filter(Boolean).join('\n');if(u){navigator.clipboard?.writeText(u);toast(L('Link(s) copied'))}}};

function ctxMenu(e,items){$$('.ctx,.dd').forEach(x=>x.remove());const m=document.createElement('div');m.className='ctx';items.forEach(([l,fn])=>{const d=document.createElement('div');d.textContent=L(l);d.onclick=()=>{m.remove();fn()};m.append(d)});m.style.left=Math.min(e.clientX,innerWidth-230)+'px';m.style.top=Math.min(e.clientY,innerHeight-items.length*38-20)+'px';document.body.append(m)}
document.addEventListener('mousedown',()=>pressed=1);document.addEventListener('mouseup',()=>setTimeout(()=>pressed=0,0));

/* ===================== NEW DESIGN LAYER ===================== */
Object.assign(AR,{'Last capture':'آخر التقاط','Download with UDM':'تحميل بواسطة UDM','Home':'الرئيسية','Completed':'المكتملة','Settings':'الإعدادات','Connection type':'نوع الاتصال','Warn before stopping a download':'حذّرني قبل إيقاف تحميل','Show a dialog when a download completes':'أظهر نافذة عند اكتمال تحميل','Change the category folder when I pick a different folder':'غيّر مجلد التصنيف عندما أختار مجلداً مختلفاً','Play sounds':'تشغيل الأصوات','Sound: download complete (file, empty = default beep)':'صوت: اكتمال التحميل (ملف، فارغ = الصوت الافتراضي)','Sound: download failed':'صوت: فشل التحميل','Sound: queue started':'صوت: بدء القائمة','Sound: queue finished':'صوت: انتهاء القائمة','high':'سرعة عالية','medium':'متوسطة','low':'بطيئة','mobile':'جوال','custom':'مخصص','Stop this download?':'إيقاف هذا التحميل؟','Stop the selected downloads?':'إيقاف التحميلات المحددة؟','Open this file when the queue is done':'افتح هذا الملف عند انتهاء القائمة','Start this queue on program startup':'شغّل هذه القائمة عند بدء البرنامج','Retries per file (0 = use the global setting)':'عدد المحاولات لكل ملف (0 = استخدم الإعداد العام)','Pause All':'إيقاف الكل','Resume All':'استئناف الكل','Clear List':'مسح القائمة','Recommended':'موصى به','remaining':'متبقي',
'Connected':'متصل','Disconnected':'غير متصل','Not set up':'غير مُعدّ','Installed':'مثبّتة','Not Installed':'غير مثبّتة','Disabled in browser':'معطّلة في المتصفح','Detected':'موجود','Not found':'غير موجود',
'Extension':'الإضافة','Browser':'المتصفح','Native host':'Native Host','Registered':'مسجّل','Not registered':'غير مسجّل','Last seen':'آخر اتصال','ago':'منذ','Install extension':'تثبيت الإضافة','Reconnect':'إعادة الاتصال',
'Test connection':'اختبار الاتصال','Setup guide':'دليل الإعداد','Manage':'إدارة','Open browser':'فتح المتصفح','Open folder':'فتح المجلد','Refresh':'تحديث','Capture downloads':'التقاط التحميلات',
'Capture downloads and videos from your browsers':'التقاط التحميلات والفيديوهات من متصفحاتك','Connected browsers':'متصفحات متصلة','On':'مفعّل','Off':'معطّل','Windows only':'ويندوز فقط','Local connection':'اتصال محلي',
'Paste your link here… (YouTube, TikTok, or any supported site)':'الصق الرابط هنا… (يوتيوب، تيك توك، أو أي موقع مدعوم)','Download':'تحميل','No downloads yet':'لا توجد تحميلات بعد','Paste a link above and press Download.':'الصق رابطاً بالأعلى واضغط تحميل.',
'Nothing here yet':'لا يوجد شيء هنا بعد','All':'الكل','Active':'نشطة','Failed':'فاشلة','Notifications':'الإشعارات','No notifications':'لا توجد إشعارات','Clear':'مسح','Advanced add (options)…':'إضافة متقدمة (خيارات)…',
'Paste from clipboard':'لصق من الحافظة','Import list…':'استيراد قائمة…','Export list…':'تصدير قائمة…','Tools':'أدوات','Speed mode':'وضع السرعة','Max connections per website (0 = no limit)':'أقصى اتصالات لكل موقع (0 = بلا حد)',
'Disk write buffer per connection (KB)':'مخزن الكتابة على القرص لكل اتصال (KB)','Reuse connections (Keep-Alive)':'إعادة استخدام الاتصالات (Keep-Alive)','auto':'تلقائي (ذكي)','manual':'يدوي (ثابت)',
'Connections per download: maximum in Auto mode, fixed number in Manual (1-32)':'اتصالات لكل تحميل: الحد الأقصى في الوضع التلقائي، أو عدد ثابت في اليدوي (1-32)',
'items will be removed from the list.':'عناصر ستُزال من القائمة.','Copy a link and the Add dialog appears automatically.':'','Auto':'تلقائي','Items':'العناصر','Engine':'المحرك','Paused ·':'متوقف ·',
'Waiting in queue':'في انتظار الدور','Connections':'الاتصالات','Open':'فتح','conn':'اتصال','Speed':'السرعة','Language':'اللغة','Theme':'المظهر','Unlimited Download Manager':'مدير التنزيل غير المحدود',
'Browser extension connected':'تم ربط إضافة المتصفح','Select the browser to connect':'اختر المتصفح للربط','Repaired — open the browser, it connects by itself':'تم الإصلاح — افتح المتصفح وسيتصل تلقائياً',
'The extension is not connected yet. Open the browser first.':'الإضافة غير متصلة بعد. افتح المتصفح أولاً.','About UDM':'عن UDM'});
Object.assign(I,{home:'<path d="M3 11l9-8 9 8"/><path d="M5 10v10h5v-6h4v6h5V10"/>',puzzle:'<path d="M10 4a2 2 0 114 0v1h4a1 1 0 011 1v4h-1a2 2 0 100 4h1v4a1 1 0 01-1 1h-4v-1a2 2 0 10-4 0v1H6a1 1 0 01-1-1v-4h1a2 2 0 100-4H5V6a1 1 0 011-1h4z"/>',
dl:'<path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2"/>',check:'<circle cx="12" cy="12" r="9"/><path d="M8 12.5l3 3 5-6"/>',info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.5"/>',
bell:'<path d="M6 17V11a6 6 0 1112 0v6l2 2H4z"/><path d="M10 21a2 2 0 004 0"/>',moon:'<path d="M20 14.5A8 8 0 019.5 4 8 8 0 1020 14.5z"/>',sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5"/>',
min:'<path d="M5 12h14"/>',max:'<rect x="5" y="5" width="14" height="14" rx="1.5"/>',x:'<path d="M6 6l12 12M18 6L6 18"/>',pause:'<path d="M9 5v14M15 5v14" stroke-width="3"/>',playo:'<path d="M7 4.5v15l13-7.5z"/>',
bolt:'<path d="M13 2L5 14h6l-1 8 8-12h-6z" fill="currentColor"/>',clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',tray:'<path d="M12 4v10M8 10l4 4 4-4"/><path d="M4 15v3a2 2 0 002 2h12a2 2 0 002-2v-3"/>',
fopen:'<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v1H7l-4 8z"/><path d="M3 18l4-8h15l-4 8z"/>',refresh:'<path d="M20 11a8 8 0 10-2.3 5.7"/><path d="M20 4v7h-7"/>',warn:'<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18v.5"/>',
more:'<circle cx="5" cy="12" r="1.6" fill="currentColor"/><circle cx="12" cy="12" r="1.6" fill="currentColor"/><circle cx="19" cy="12" r="1.6" fill="currentColor"/>',search:'<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
sl:'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z"/>',
plug:'<path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 01-12 0z"/><path d="M12 18v4"/>'});
const iso=x=>'\u2066'+x+'\u2069';
const sz=n=>iso(n==null||isNaN(n)?'?':n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':n<1073741824?(n/1048576).toFixed(1)+' MB':(n/1073741824).toFixed(2)+' GB');
const spd=n=>iso(n>=1073741824?(n/1073741824).toFixed(1)+' GB/s':n>=1048576?(n/1048576).toFixed(1)+' MB/s':n>=1024?Math.round(n/1024)+' KB/s':'0 KB/s');
const clk=s=>{s=Math.max(0,Math.round(s));const p=n=>String(n).padStart(2,'0');return iso(`${p(s/3600|0)}:${p(s%3600/60|0)}:${p(s%60)}`)};
let S={tasks:[],queues:[],cats:[],speed:0,disk:null,connections:8,ext:{connected:0,total:4,seen:false}},st={page:'home',f:'all',cat:'',q:'',sel:new Set(),last:null},pressed=0,BI=null,lastBI=0,NOTES=[],unread=0,lastNav='';
const rk={Downloading:0,Pausing:0,Queued:1,Paused:2,Error:3};
const sel=()=>[...st.sel].filter(i=>S.tasks.some(t=>t.id==i));
function vis(){const p=st.page;return S.tasks.filter(t=>{const c=t.status=='Completed';if(p=='completed'){if(!c)return 0}else if(c)return 0;
if(p=='downloads'){const a=['Downloading','Pausing'].includes(t.status);if(st.f=='active'&&!a)return 0;if(st.f=='paused'&&t.status!='Paused')return 0;if(st.f=='queued'&&t.status!='Queued')return 0;if(st.f=='error'&&t.status!='Error')return 0}
if(st.cat&&t.cat!=st.cat)return 0;return!st.q||(t.name+' '+t.url).toLowerCase().includes(st.q)}).sort((x,y)=>p=='completed'?(y.fin||0)-(x.fin||0):((rk[x.status]??1)-(rk[y.status]??1))||y.added-x.added)}
function badge(t){const ext=(t.name.split('.').pop()||'').toUpperCase().slice(0,4);
if(t.kind=='video'){if(t.vc=='mp3')return{t:'MP3',c:'mp3',bar:'pm',tile:'t-m',meta:'MP3'};const h=t.vh,b=h>=2160?['4K','k4']:h>=1440?['2K','k4']:(h>=720||!h)?['HD','hd']:['SD','sd'];return{t:b[0],c:b[1],bar:h>=2160?'pg':'pb',tile:'t-v',meta:(h?h+'p':L('Best'))+' • '+(t.vc||'mp4').toUpperCase()}}
const tile={Musics:'t-m',Videos:'t-v',Compressed:'t-z',Programs:'t-p',Documents:'t-d',APKs:'t-a',Images:'t-i'}[t.cat]||'t-u';
return{t:ext||'FILE',c:ext=='MP3'?'mp3':ext=='MP4'||ext=='MKV'?'hd':'ft',bar:t.cat=='Musics'?'pm':t.cat=='Videos'?'pb':'pc2',tile,meta:(ext?ext+' • ':'')+L(KIND[t.cat]||t.cat)}}
function cardHTML(t){const b=badge(t),c=t.status=='Completed',pct=t.size?Math.min(100,t.done*100/t.size):0,dl=t.status=='Downloading';
const th=`<div class="th ${b.tile}">${t.thumb?`<img src="${esc(t.thumb)}" referrerpolicy="no-referrer" onerror="this.remove()">`:''}${ic(t.vc=='mp3'?'music':t.kind=='video'?'video':CI[t.cat]||'file',46)}</div>`;
let stats,bar='';const sizeTxt=t.size?' • '+sz(t.size):'';
if(c)stats=`<span class="okc">${ic('check',20)}${L('Complete')}</span><span class="mu">${ic('clock',19)}${fd(t.fin)}</span><span>${ic('tray',19)}${sz(t.size)}</span>`;
else{bar=`<i class="pbar ${b.bar}${dl?'':' dim'}"><i style="width:${pct}%"></i></i>`;
if(t.status=='Error')stats=`<span class="err" title="${esc(t.err)}">${ic('warn',19)}${L('Error')}: ${esc(t.err||'')}</span>`;
else if(dl)stats=`<span class="sp">${ic('bolt',20)}<b data-f="spd">${spd(t.speed)}</b></span><span>${ic('clock',19)}<span data-f="eta">${t.size&&t.speed?clk((t.size-t.done)/t.speed):'--:--:--'}</span>&nbsp;${L('remaining')}</span><span>${ic('tray',19)}<span data-f="done">${sz(t.done)} / ${sz(t.size)}</span></span><span class="mu" data-f="conn">${t.conn?'⇅ '+t.conn+' '+L('conn'):''}</span>`;
else stats=`<span class="mu">${ic(t.status=='Queued'?'clock':'pause',19)}${t.status=='Queued'?L('Waiting in queue'):L(t.status=='Pausing'?'Pausing…':'Paused')}</span><span>${ic('tray',19)}${sz(t.done)} / ${sz(t.size)}</span>`}
const act=c?`<button class="rb" data-act="folder" title="${L('Open folder')}">${ic('fopen',24)}</button>`:dl||t.status=='Pausing'?`<button class="rb" data-act="stop" title="${L('Stop')}">${ic('pause',24)}</button>`:`<button class="rb" data-act="resume" title="${L('Resume')}">${ic('playo',24)}</button>`;
return`${th}<div class="cm"><b title="${esc(t.name)}">${esc(t.name)}</b><div class="cmeta"><span class="bd ${b.c}">${b.t}</span><span>${esc(b.meta)}${sizeTxt}</span>${c?'':`<span class="pc" data-f="pct">${Math.floor(pct)}%</span>`}</div>${bar}<div class="cst">${stats}</div></div><div class="ca">${act}<button class="rb x" data-act="del" title="${L('Delete')}">${ic('x',24)}</button></div>`}
const sigOf=t=>[t.name,t.status,!!t.size,st.sel.has(t.id),lang,t.err,t.thumb,t.cat,st.page,Math.round(t.speed/1e5)>0].join('|');
function patchRow(e,t){const f=k=>e.querySelector(`[data-f=${k}]`),pct=t.size?Math.min(100,t.done*100/t.size):0;f('pct')&&(f('pct').textContent=Math.floor(pct)+'%');const b=e.querySelector('.pbar>i');if(b)b.style.width=pct+'%';
f('spd')&&(f('spd').textContent=spd(t.speed));f('eta')&&(f('eta').textContent=t.size&&t.speed?clk((t.size-t.done)/t.speed):'--:--:--');f('done')&&(f('done').textContent=sz(t.done)+' / '+sz(t.size));f('conn')&&(f('conn').textContent=t.conn?'⇅ '+t.conn+' '+L('conn'):'')}
function mkRow(t){const e=document.createElement('div');e.className='row'+(st.sel.has(t.id)?' on':'');e.dataset.id=t.id;e.dataset.sig=sigOf(t);e.innerHTML=cardHTML(t);return e}
function emptyHTML(){return`<div class="empty">${ic('dl',74)}<b>${L(st.page=='completed'?'Nothing here yet':'No downloads yet')}</b><span>${st.page=='completed'?'':L('Paste a link above and press Download.')}</span></div>`}
function renderList(){const box=$('#list');if(!box||pressed)return;const v=vis();if(!v.length){if(box.dataset.ids!='-'){box.innerHTML=emptyHTML();box.dataset.ids='-'}return}
const ids=v.map(t=>t.id).join(),old=box.dataset.ids;if(ids!=old){box.dataset.ids=ids;box.innerHTML='';v.forEach(t=>box.append(mkRow(t)))}
else v.forEach((t,i)=>{const e=box.children[i],g=sigOf(t);if(e.dataset.sig!=g){e.replaceWith(mkRow(t))}else patchRow(e,t)})}
function menuAt(el,items,cls=''){$$('.ctx,.dd').forEach(x=>x.remove());const m=document.createElement('div');m.className='dd '+cls;items.forEach(it=>{if(it=='-'){m.append(document.createElement('hr'));return}const d=document.createElement('div');d.innerHTML=(it[2]?ic(it[2],18):'')+'<span>'+L(it[0])+'</span>';d.onclick=()=>{m.remove();it[1]()};m.append(d)});
document.body.append(m);const r=el.getBoundingClientRect(),w=m.offsetWidth;m.style.top=(r.bottom+6)+'px';const rtl=document.dir=='rtl'||document.documentElement.dir=='rtl';m.style.left=Math.max(8,Math.min(innerWidth-w-8,rtl?r.left:r.right-w))+'px';return m}
function toolsMenu(el){menuAt(el,[['Add URL / batch',()=>addDlg(),'link'],['Video Downloader…',()=>videoDlg(),'video'],'-',['Queues',queuesDlg,'copy'],['Scheduler',()=>schedDlg(),'cal'],['Grabber…',()=>grabDlg(),'cloud'],'-',['Import list…',importList,'tray'],['Export list…',()=>exportList(sel()),'share'],['Delete completed',()=>api('delcompleted').then(poll),'trash'],'-',[S.limit?'Limiter: On ('+S.limit+' KB/s)':'Limiter: Off',toggleLim,'bolt'],['Quick start',()=>toast(M('QS'),14000),'info'],['Check for updates…',()=>checkUpdates(),'refresh']])}
function clearList(){const v=vis();if(!v.length)return;const comp=st.page=='completed',d=document.createElement('div');d.innerHTML=`${v.length} ${L('items will be removed from the list.')}`+(comp?`<label class="chk"><input type="checkbox" id="dfiles"><span>${L('Also delete the files from disk')}</span></label>`:'');
modal('Clear List',d,[{t:'Cancel'},{t:'Clear List',p:1,fn:async()=>{await api('delete',{ids:v.map(t=>t.id),files:comp&&$('#dfiles').checked});st.sel.clear();poll()}}])}
/* ---- sidebar ---- */
function renderNav(){const e=S.ext||{},unf=S.tasks.filter(t=>t.status!='Completed').length,fin=S.tasks.length-unf,bi=e.connected?['ok','Connected']:e.seen?['no','Disconnected']:['off','Not set up'];
const nv=(p,i,l,x='',cl='')=>`<div class="nv ${cl} ${st.page==p?'on':''}" data-page="${p}">${ic(i,30)}<span>${L(l)}</span>${x}</div>`;
const h=nv('home','home','Home')+nv('browser','puzzle','Browser Integration',`<span class="st ${bi[0]}"><i></i>${L(bi[1])}</span>`,'bi-nv')+`<div class="nv" data-vid="1">${ic('video',30)}<span>${L('Video Downloader')}</span></div>`+nv('downloads','dl','Downloads',`<span class="cnt">${unf}</span>`)+nv('completed','check','Completed',`<span class="cnt">${fin}</span>`)+`<div class="nv" data-page="settings">${ic('sl',30)}<span>${L('Settings')}</span></div><div class="nv" data-page="about">${ic('info',30)}<span>${L('About')}</span></div>`;
const k=h+lang+theme;if(k!=lastNav){lastNav=k;$('#nav').innerHTML=h}}
/* ---- pages ---- */
function shell(){const p=st.page;if(p=='browser')return`<div class="pn"><div class="ph"><h2>${ic('puzzle',34)}<span>${L('Browser Integration')}</span><small>${L('Capture downloads and videos from your browsers')}</small></h2><label class="chk" style="margin:0;gap:12px;cursor:pointer" data-a="cap"><span>${L('Capture downloads')}</span><i class="sw" id="capsw"></i></label><button class="pill" data-a="birefresh">${ic('refresh',18)}${L('Refresh')}</button></div><div class="list" id="bibody"></div></div>`;
const comp=p=='completed',chips=p=='downloads'?`<div class="chips">${[['all','All'],['active','Active'],['paused','Paused'],['queued','Queued'],['error','Failed']].map(([k,l])=>`<span class="chp ${st.f==k?'on':''}" data-f2="${k}">${L(l)}</span>`).join('')}<select id="catsel" style="margin-inline-start:auto"><option value="">${L('Categories')}</option>${S.cats.map(c=>`<option value="${esc(c)}" ${st.cat==c?'selected':''}>${esc(L(c))}</option>`).join('')}</select></div>`:'';
return`<div class="pn"><div class="ph"><h2>${ic(comp?'check':'dl',36)}<span id="ptitle"></span><small id="pspd"></small></h2>${p!='home'?`<div class="cs">${ic('search',18)}<input id="q" placeholder="${L('Search')}" value="${esc(st.q)}"></div>`:''}${comp?'':`<button class="pill" data-a="pauseall">${ic('pause',20)}${L('Pause All')}</button><button class="pill" data-a="resumeall">${ic('playo',20)}${L('Resume All')}</button>`}<button class="pill" data-a="clear">${ic('trash',20)}${L('Clear List')}</button><button class="pill sq" data-a="more" data-menu title="${L('Tools')}">${ic('more',22)}</button></div>${chips}<div class="list" id="list"></div></div>`}
function renderMain(){const m=$('#main'),key=st.page+'|'+lang+'|'+(st.page=='downloads'?S.cats.join():'');if(m.dataset.key!=key){m.dataset.key=key;m.innerHTML=shell();if(st.page=='browser')renderBI()}
if(st.page!='browser'){const v=vis().length,t=$('#ptitle');if(t)t.textContent=L(st.page=='completed'?'Completed':'Downloads')+' ('+v+')';const sp=$('#pspd');if(sp)sp.textContent=S.speed>0?'· '+spd(S.speed)+(S.conns?' · '+S.conns+' '+L('conn'):''):'';renderList()}}
function go(p){if(p=='settings'){optDlg();return}if(p=='about'){aboutDlg();return}st.page=p;st.f='all';st.q='';st.cat='';st.sel.clear();$('#main').dataset.key='';lastNav='';render();if(p=='browser'){lastBI=0;loadBI()}}
function aboutDlg(){const w=document.createElement('div');w.className='abt';w.innerHTML=`${$('.brand .logo').outerHTML}<b>UDM</b><p>${L('Unlimited Download Manager')}<br>v${esc(S.ver||'')}<br>${L('Engine')}: ${L(S.mode||'auto')} · ${L('Connections')}: ${S.connections}</p>`;modal('About',w,[{t:'Close',p:1}])}
/* ---- browser integration page ---- */
const BRI={chrome:'<div class="cr"><i></i></div>',brave:'<div class="bl" style="background:#fb542b;clip-path:polygon(25% 0,75% 0,100% 30%,100% 70%,50% 100%,0 70%,0 30%)">B</div>',edge:'<div class="bl" style="background:linear-gradient(135deg,#35d4a0,#0a7bd8)">e</div>',firefox:'<div class="bl" style="background:linear-gradient(135deg,#ffb02e,#ff4a3d 60%,#9b3dff)">F</div>'};
async function loadBI(){try{BI=await api('ext_status');lastBI=Date.now();renderBI()}catch(e){}}
const pl=(c,t)=>`<span class="pl ${c}"><i></i>${L(t)}</span>`;
function biCard(b){const con=b.connected,ins=b.ext_installed,age=b.age==null?null:Math.round(b.age);
const rows=[[L('Browser'),b.installed?pl('b','Detected'):pl('n','Not found')],[L('Extension'),ins?(b.ext_disabled?pl('a','Disabled in browser'):pl('g','Installed')):pl('n','Not Installed')],[L('Connection'),con?pl('g','Connected'):pl('r','Disconnected')],
[L('Native host'),b.win?(b.host_registered?pl('g','Registered'):pl('n','Not registered')):pl('n','Windows only')]];
let hint='';if(!b.installed)hint=`<div class="hint w">${L('Browser not found on this computer.')}</div>`;else if(con)hint=`<div class="hint">${L(b.via=='native'?'Native Messaging':'Local connection')}${b.ext_version?' · v'+esc(b.ext_version):''} · ${L('Last seen')} ${age}s</div>`;
else if(ins)hint=`<div class="hint">${L('The extension is not connected yet. Open the browser first.')}</div>`;
const main=!ins?`<button class="pill pri" data-bi="setup|${b.id}">${ic('dl',18)}${L('Install extension')}</button>`:!con?`<button class="pill pri" data-bi="recon|${b.id}">${ic('refresh',18)}${L('Reconnect')}</button>`:`<button class="pill pri" data-bi="test|${b.id}">${ic('check',18)}${L('Test connection')}</button>`;
const lc=b.last_cap?`<div class="hint" style="direction:ltr;text-align:start">${L('Last capture')}: ${esc(b.last_cap)}</div>`:'';
return`<div class="bcard ${con?'ok':''}"><div class="bh"><div class="bic">${BRI[b.id]||''}</div><div><div class="bn">${esc(b.title)}</div><small>${esc(b.family=='firefox'?'Gecko':'Chromium')}</small></div><div style="margin-inline-start:auto">${con?pl('g','Connected'):pl('r','Disconnected')}</div></div><div class="bst">${rows.map(r=>`<div class="sr"><span>${r[0]}</span>${r[1]}</div>`).join('')}</div>${hint}${lc}<div class="bact">${main}${ins?`<button class="pill" data-bi="setup|${b.id}">${L('Setup guide')}</button>`:''}<button class="pill sm" data-bi="manage|${b.id}" ${b.installed?'':'disabled'}>${L('Manage')}</button><button class="pill sm" data-bi="launch|${b.id}" ${b.installed?'':'disabled'}>${L('Open browser')}</button>${b.prepared?`<button class="pill sm" data-bi="folder|${b.id}">${L('Open folder')}</button>`:''}</div></div>`}
function renderBI(){const body=$('#bibody');if(!body||!BI)return;const bs=BI.browsers,n=bs.filter(b=>b.connected).length,reg=bs.some(b=>b.host_registered);const sw=$('#capsw');if(sw)sw.className='sw'+(BI.capture?' on':'');
const html=`<div class="bi-sum"><div class="tile"><div class="ti">${ic('plug',24)}</div><div><small>${L('Connected browsers')}</small><b>${n} / ${bs.length}</b></div></div><div class="tile"><div class="ti">${ic('puzzle',24)}</div><div><small>${L('Native host')}</small><b>${BI.win?(reg?L('Registered'):L('Not registered')):L('Windows only')}</b></div></div><div class="tile"><div class="ti">${ic('dl',24)}</div><div><small>${L('Capture downloads')}</small><b>${BI.capture?L('On'):L('Off')}</b></div></div></div><div class="bgrid">${bs.map(biCard).join('')}</div><div class="how">${ic('info',22)}<div>${lang=='ar'?'تلتقط الإضافة التحميلات والفيديوهات من المتصفح وترسلها لـ UDM. تتصل أولاً عبر Native Messaging ثم تلجأ للاتصال المحلي. الإضافة تُحمَّل مرة واحدة (Load unpacked) لأن المتصفحات تمنع التثبيت الصامت.':'The extension captures downloads and videos in your browser and hands them to UDM. It connects through Native Messaging first, then the local port. It is loaded once (Load unpacked) because browsers block silent installs.'}</div></div>`;
if(body.dataset.h!=html){const y=body.scrollTop;body.dataset.h=html;body.innerHTML=html;body.scrollTop=y}}
async function biAct(k,id){if(k=='setup')return browserDlg(id);if(k=='manage'||k=='folder'||k=='launch'){const r=await api('ext_open',{browser:id,what:k});if(r.err)toast(esc(r.err),9000);return}
if(k=='recon'){await api('ext_repair',{browser:id});toast(L('Repaired — open the browser, it connects by itself'),8000);loadBI();return}
if(k=='test'){const r=await api('ext_check',{browser:id});toast(r.connected?'✔ '+L('Browser extension connected'):L('The extension is not connected yet. Open the browser first.'));loadBI()}}
/* ---- top bar ---- */
async function quickDl(){const i=$('#url'),u=i.value.trim();if(!/^(https?|ftp):\/\//i.test(u))return toast(L('Enter a valid link'));if(isVid(u)){videoDlg(u)}else{await api('popup_new',{url:u})}i.value='';poll()}
function winCtl(w){api('win',{what:w}).then(r=>{if(r&&r.ok)return;if(w=='max'){document.fullscreenElement?document.exitFullscreen():document.documentElement.requestFullscreen?.()}else if(w=='close')window.close()})}
/* ---- self-update: a banner under the top bar when a newer build is on GitHub ---- */
let updDismissed=0;
function updBar(){const b=$('#updbar');if(!b)return;const u=S.upd||{};if(!u.available||updDismissed==u.latest){if(b.dataset.k){b.dataset.k='';b.style.display='none';b.innerHTML=''}return}
 const key=u.latest+'|'+u.dl_state+'|'+u.dl_pct+'|'+(u.dl_error||'');if(key==b.dataset.k)return;b.dataset.k=key;b.style.display='block';
 const bar=inner=>{b.innerHTML=`<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:6px 0 4px;padding:10px 14px;border-radius:12px;background:linear-gradient(90deg,#0d56ff,#2a8cff);color:#fff;font-size:14px">${inner}</div>`};
 const notes=u.notes?esc(u.notes.split('\n').map(s=>s.trim()).filter(Boolean).slice(0,2).join(' — ').slice(0,200)):'';
 const later=()=>{updDismissed=u.latest;updBar()};
 if(u.dl_state=='downloading'){bar(`<b>${L('Downloading update…')}</b><span style="flex:1">${u.dl_pct}%</span>`);return}
 if(u.dl_state=='ready'){bar(`<b>✔ ${L('Update downloaded')}</b><span style="flex:1">${L('Downloads will pause and resume after the restart')}</span><button class="btn pri" id="upinst">${L('Install and restart')}</button><button class="btn" id="uplate">${L('Later')}</button>`);$('#upinst').onclick=installUpdate;$('#uplate').onclick=later;return}
 if(u.dl_state=='error'){bar(`<b>⚠ ${L('Update failed')}</b><span style="flex:1">${esc(u.dl_error||'')}</span><button class="btn pri" id="upretry">${L('Try again')}</button><button class="btn" id="uplate">${L('Later')}</button>`);$('#upretry').onclick=startUpdate;$('#uplate').onclick=later;return}
 bar(`<b>⬆ ${L('New version available')}: build ${u.latest}</b><span style="flex:1;opacity:.9">${notes}</span><button class="btn pri" id="upnow">${L('Update now')}</button><button class="btn" id="uplate">${L('Later')}</button>`);
 $('#upnow').onclick=startUpdate;$('#uplate').onclick=later}
async function startUpdate(){const u=S.upd||{};if(u.portable){if(u.portable_url)window.open(u.portable_url,'_blank');toast(L('Extract the new portable version over the old folder'));return}const r=await api('update_download');if(r&&r.ok)toast(L('Downloading update…'));else toast(L('Update failed'))}
async function installUpdate(){const r=await api('update_install');if(r&&r.ok)toast(L('Installing update…'));else if(r&&r.error=='portable'){const u=S.upd||{};if(u.portable_url)window.open(u.portable_url,'_blank')}else toast(L('Update failed'))}
async function checkUpdates(){const r=await api('update_check');if(r&&r.ok&&r.available){updDismissed=0;updBar()}else if(r&&r.ok)toast(L('You have the latest version'));else toast(L('Could not check for updates'))}
function bellMenu(el){unread=0;renderBell();const m=menuAt(el,[],'np');m.innerHTML=`<div class="nh"><span>${L('Notifications')}</span><button class="pill sm" id="nclr">${L('Clear')}</button></div>`+(NOTES.length?NOTES.slice(0,20).map(n=>`<div class="ni" ${n.id?`data-open="${n.id}"`:''}>${n.k=='done'?'<span class="okc">✔</span> ':'<span class="err">⚠</span> '}${esc(n.name)}<small>${esc(n.msg||'')} ${new Date(n.t).toLocaleTimeString()}</small></div>`).join(''):`<div class="ni" style="color:var(--mut)">${L('No notifications')}</div>`);
const r=el.getBoundingClientRect();m.style.left=Math.max(8,r.right-m.offsetWidth)+'px';$('#nclr',m)?.addEventListener('click',()=>{NOTES=[];m.remove()})}
function renderBell(){const d=$('#bell .dot');if(d){d.hidden=!unread;d.textContent=unread}}
function topAct(a,el,e){switch(a){case'dl':return quickDl();case'gear':return optDlg();case'theme':{const t=theme=='dark'?'light':'dark';applyTheme(t);api('cfg_set',{cfg:{theme:t}});return}
case'lang':{const l=lang=='ar'?'en':'ar';applyLang(l);api('cfg_set',{cfg:{language:l}});return}case'bell':return bellMenu(el);case'min':case'max':case'close':return winCtl(a);
case'chev':return menuAt($('.urlbar'),[['Advanced add (options)…',()=>addDlg({urls:[$('#url').value].filter(Boolean)}),'link'],['Video Downloader…',()=>videoDlg($('#url').value.trim()),'video'],['Paste from clipboard',async()=>{try{$('#url').value=(await navigator.clipboard.readText()).trim()}catch(_){}},'copy'],['Import list…',importList,'tray']]);
case'more':return toolsMenu(el);case'pauseall':return api('stopall').then(poll);case'resumeall':return api('resume',{ids:S.tasks.filter(t=>t.status!='Completed').map(t=>t.id)}).then(poll);case'clear':return clearList();
case'cap':{const on=!(BI?BI.capture:S.capture);if(BI)BI.capture=on;S.capture=on;api('cfg_set',{cfg:{capture_enabled:on}}).then(loadBI);renderBI();return}case'birefresh':return loadBI()}}
function rowAct(x){const id=x.closest('.row').dataset.id,k=x.dataset.act;if(k=='stop'){if(S.confirm_stop&&!confirm(L('Stop this download?')))return;api('stop',{ids:[id]}).then(poll)}else if(k=='resume')api('resume',{ids:[id]}).then(poll);else if(k=='folder')api('folder',{ids:[id]});else if(k=='del'){st.sel=new Set([id]);A.del()}}

document.addEventListener('mousedown',()=>pressed=1);document.addEventListener('mouseup',()=>setTimeout(()=>pressed=0,0));
document.addEventListener('click',e=>{pressed=0;const g=s=>e.target.closest(s);if(!g('.ctx')&&!g('.dd')&&!g('[data-menu]')&&!g('[data-a=chev]')&&!g('[data-a=bell]'))$$('.ctx,.dd').forEach(x=>x.remove());let x;
if(x=g('[data-a]')){e.preventDefault();topAct(x.dataset.a,x,e);return}
if(x=g('[data-bi]')){const[k,id]=x.dataset.bi.split('|');biAct(k,id);return}
if(x=g('[data-vid]')){videoDlg();return}
if(x=g('[data-page]')){go(x.dataset.page);return}
if(x=g('[data-open]')){api('open',{ids:[x.dataset.open]});return}
if(x=g('[data-f2]')){st.f=x.dataset.f2;$('#main').dataset.key='';render();return}
if(x=g('[data-act]')){rowAct(x);return}
if(x=g('.row')){const id=x.dataset.id;if(e.shiftKey&&st.last){const v=vis().map(t=>t.id),a=v.indexOf(st.last),b=v.indexOf(id);if(a>=0&&b>=0){st.sel.clear();v.slice(Math.min(a,b),Math.max(a,b)+1).forEach(i=>st.sel.add(i))}}else if(e.ctrlKey){st.sel.has(id)?st.sel.delete(id):st.sel.add(id);st.last=id}else{st.sel.has(id)&&st.sel.size==1?st.sel.clear():(st.sel.clear(),st.sel.add(id));st.last=id}$('#list').dataset.ids='';renderList()}});
document.addEventListener('input',e=>{if(e.target.id=='q'){st.q=e.target.value.toLowerCase();$('#list').dataset.ids='';renderMain()}});
document.addEventListener('change',e=>{if(e.target.id=='catsel'){st.cat=e.target.value;$('#list').dataset.ids='';renderMain()}});
document.addEventListener('dblclick',e=>{const r=e.target.closest('.row');if(r&&!e.target.closest('button'))api('open',{ids:[r.dataset.id]})});
document.addEventListener('contextmenu',e=>{const r=e.target.closest('.row');if(!r)return;e.preventDefault();if(!st.sel.has(r.dataset.id)){st.sel.clear();st.sel.add(r.dataset.id);$('#list').dataset.ids='';renderList()}const ids=sel(),t=S.tasks.find(x=>x.id==ids[0]);
ctxMenu(e,[['Open',()=>api('open',{ids})],['Open folder',()=>api('folder',{ids})],['Resume',A.resume],['Stop',A.stop],['Delete',A.del],['Move to queue…',()=>{const q=prompt(L('Queue name:')+'\n'+S.queues.map(q=>q.name).join('\n'));if(q)api('moveq',{ids,queue:q}).then(poll)}],['Copy link',A.share],['Copy folder path',()=>{navigator.clipboard?.writeText(t.folder);toast(L('Link(s) copied'))}],['Refresh download address…',()=>{const u=prompt(L('Or paste the new address here:'),t.url);if(u)api('newurl',{ids,url:u}).then(poll)}],['Redownload',()=>api('redo',{ids}).then(poll)],['Check file (SHA-256)',async()=>{const r=await api('hash',{ids,algo:'sha256'});toast(r.err?esc(r.err):'SHA-256<br><span style="user-select:text;word-break:break-all">'+r.hash+'</span>',20000)}],['Export selected',()=>exportList(ids)],['Properties',()=>propsDlg(t)],...(/\.zip$/i.test(t.name)?[['ZIP preview',()=>zipDlg(t)]]:[])])});
document.addEventListener('keydown',e=>{const inp=/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);if(e.key=='Escape')$$('.ov').pop()?.remove();else if(e.key=='Enter'&&document.activeElement.id=='url')quickDl();else if(e.key=='Delete'&&!inp)A.del();else if(e.ctrlKey&&e.key=='a'&&!inp){e.preventDefault();vis().forEach(t=>st.sel.add(t.id));$('#list').dataset.ids='';renderList()}else if(e.ctrlKey&&e.key=='n'){e.preventDefault();addDlg()}});
/* ---------- polling ---------- */
async function poll(){try{const s=await(await fetch('/api/state',{headers:{'X-UDM-Token':T}})).json();S=s;if(s.theme&&s.theme!=theme)applyTheme(s.theme);if(s.language&&s.language!=lang)applyLang(s.language);if(s.palette&&s.palette!=pal)applyPal(s.palette);if(s.text_size&&s.text_size!=tsz)applyTS(s.text_size);
st.sel.forEach(i=>{if(!S.tasks.some(t=>t.id==i))st.sel.delete(i)});render();updBar();
for(const ev of s.events){if(ev.k=='done'||ev.k=='error'){NOTES.unshift({k:ev.k,id:ev.id,name:ev.name,msg:ev.msg||L('Download complete'),t:Date.now()});unread++;renderBell()}
if(ev.k=='done'&&S.show_complete){const _d=document.createElement('div');_d.innerHTML='<b>'+esc(ev.name)+'</b>';modal('Download complete',_d,[{t:'Open',fn:()=>api('open',{ids:[ev.id]})},{t:'Open folder',fn:()=>api('folder',{ids:[ev.id]})},{t:'Close',p:1}])}else if(ev.k=='done'&&S.notify)toast(`✔ ${L('Download complete')}<br><b>${esc(ev.name)}</b><br><a href="#" style="color:#7fc0ff" onclick="api('open',{ids:['${ev.id}']});return false">${L('Open')}</a> · <a href="#" style="color:#7fc0ff" onclick="api('folder',{ids:['${ev.id}']});return false">${L('Open folder')}</a>`,9000);else if(ev.k=='error')toast('⚠ '+esc(ev.name)+'<br>'+esc(ev.msg),9000);else if(ev.k=='shutdown')toast('Queue finished — shutting down in 60 s. <a href="#" style="color:#7fc0ff" onclick="api(\'cancel_shutdown\');return false">Cancel</a>',60000)}
for(const p of s.incoming)onIncoming(p)}catch(e){}
if(st.page=='browser'&&Date.now()-lastBI>2500){lastBI=Date.now();loadBI()}}
function render(){renderNav();renderMain();renderBell()}
function applyTheme(t){theme=t;document.documentElement.dataset.theme=t;$('#thm').innerHTML=ic(t=='dark'?'sun':'moon',28)}
function applyLang(l){lang=l;const d=document.documentElement;d.lang=l;d.dir=l=='ar'?'rtl':'ltr';$$('[data-i]').forEach(e=>e.textContent=L(e.dataset.i));$('#url').placeholder=L('Paste your link here… (YouTube, TikTok, or any supported site)');$('#lng .lg').textContent=l=='ar'?'EN':'ع';lastNav='';$('#main').dataset.key='';render()}
function onIncoming(p){const one=p.urls.length==1&&(p.video||isVid(p.urls[0]));if(S.silent){if(one)api('vdl',{url:p.urls[0],height:0,cont:'mp4',referer:p.referer||'',cookies:p.cookies||''}).then(poll);else addCall({urls:p.urls.join('\n'),category:'Uncategorized',start:1,nconn:S.connections,referer:p.referer||'',cookies:p.cookies||''})}else if(!$('.ov')){if(one)videoDlg(p.urls[0],p);else addDlg(p)}}

/* drag & drop: links, selected text, or text-like files (.txt .url .html ...) */
let dc=0;const dz=$('#dz');
addEventListener('dragenter',e=>{e.preventDefault();dc++;dz.classList.add('on')});
addEventListener('dragleave',()=>{dc=Math.max(0,dc-1);if(!dc)dz.classList.remove('on')});
addEventListener('dragover',e=>e.preventDefault());
addEventListener('dragend',()=>pressed=0);
addEventListener('drop',async e=>{e.preventDefault();pressed=0;dc=0;dz.classList.remove('on');const dt=e.dataTransfer;let txt=(dt.getData('text/uri-list')||'')+'\n'+(dt.getData('text/plain')||'')+'\n'+(dt.getData('text/html')||'');
for(const f of dt.files){if(f.size<2e6&&/\.(txt|url|html?|csv|lst|list|m3u8?|json|md|xml|webloc)$/i.test(f.name))txt+='\n'+await f.text()}
const urls=[...new Set((txt.match(/(?:https?|ftp):\/\/[^\s"'<>\\]+/g)||[]).map(u=>u.replace(/[),.;]+$/,'')))];
if(!urls.length)return toast(L('No links found in the dropped item'));onIncoming({urls})});

/* in the native program window the OS title bar already has min/max/close: hide the
   in-page ones so there is only one X (in a browser tab they stay, there is no title bar).
   Detected from the ?native=1 flag on the URL: window.pywebview does not exist here
   (no js_api is passed to create_window), so checking it never hides anything. */
function hideNativeCtrls(){if(window.pywebview||new URLSearchParams(location.search).get('native')){$$('.wc').forEach(b=>b.style.display='none')}}
hideNativeCtrls();document.addEventListener('pywebviewready',hideNativeCtrls);

$('#thm').onclick=null;applyTheme(theme);applyLang(lang);poll();setInterval(poll,700);

</script></body></html>
'''


if __name__ == "__main__":
    main()

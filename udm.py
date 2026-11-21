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
    "connections": 32, "timeout": 30, "retries": 6, "queue_parallel": 1,
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
    "proxy_user": "", "proxy_pass": "", "proxy_exclude": "localhost;127.0.0.1",
    "clipboard_monitor": True,
    "capture_large_mb": 5,           # also capture any file bigger than this, whatever its type (0 = off)
    "capture_types": "zip rar 7z gz tar iso exe msi apk dmg deb pdf doc docx xls xlsx ppt pptx "
                     "mp3 wav flac aac m4a mp4 mkv avi mov wmv flv webm mpg mpeg",
    "excluded_types": "", "excluded_sites": "", "url_exceptions": "", "capture_enabled": True,
    "silent": False, "show_progress": True, "minimized_progress": False, "notify": True,
    "sounds": True, "sound_done": "", "sound_error": "", "confirm_delete": True,
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
    path = CFG.get("sound_done" if kind == "done" else "sound_error", "")
    try:
        if winsound:
            if path and os.path.exists(path):
                winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_ASYNC)
            else:
                winsound.MessageBeep(winsound.MB_OK if kind == "done" else winsound.MB_ICONHAND)
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


def proxy_for(url):
    mode = CFG["proxy_mode"]
    if mode == "none":
        return None
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if mode == "system":
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
    p = proxy_for(url)
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
        if proxy_for(url):                                   # proxies: classic path (no pooling)
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
                if stop.is_set():
                    return
                fails = 1 if ws.got else fails + 1                   # progress during the attempt resets the counter
                if fails > (2 if getattr(e, "fatal", False) else CFG["retries"]):
                    self.failed, self.error = True, str(e)
                    stop.set()
                    return
                throttled = isinstance(e, HttpFail) and e.status in (429, 503)
                self._penalize(host, throttled)
                wait = e.retry_after if throttled and e.retry_after else min(0.5 * 2 ** (fails - 1), 10)
                stop.wait(wait + random.random() * 0.5)

    def _block(self):
        return (8 << 20) if (CFG.get("keepalive", True) and not proxy_for(self.url)) else (1 << 60)

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
            "shutdown": False, "exit": False, "active": False, "after": "none", "date": "", "folder": ""}


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

    def stop_queue(self, name):
        q = self.queues.get(name)
        if q:
            q["active"] = False
        for t in list(self.tasks.values()):
            if t.queue == name:
                t.pause()

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


def ytdlp_common(url, referer="", cookies="", playlist=False):
    a = ["--no-warnings", "--yes-playlist" if playlist else "--no-playlist", "--socket-timeout", "30"]
    ff, dn = tool_path("ffmpeg"), tool_path("deno")
    if ff:
        a += ["--ffmpeg-location", os.path.dirname(ff)]
    if dn:
        a += ["--js-runtimes", "deno:" + dn]
    px = proxy_for(url)
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
    VEXTRA = ("vheight", "vcont", "vtitle", "vsize", "vbase", "vcur", "vfid", "vstart", "vend", "vexact", "vsubs", "vthumb", "vfmt", "vmux")

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.kind = "video"
        self.vheight, self.vcont, self.vtitle, self.vsize = 0, "mp4", "", None
        self.vbase, self.vcur, self.vfid, self.proc = 0, 0, "", None
        self.vstart, self.vend, self.vexact, self.vsubs = "", "", False, ""
        self.vthumb = ""
        self.vfmt, self.vmux = "", False          # exact yt-dlp format id chosen on the page (and: has audio inside)
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
        tmpl = "%(title).150B" + ("" if audio else " [%(height)sp]") + (" (part)" if sec else "") + ".%(ext)s"
        c = [yt, "-q", "--progress", "--newline", "--windows-filenames", "--no-mtime", "--retries", "10",
             "--fragment-retries", "10", "--concurrent-fragments", str(max(1, min(16, CFG["connections"]))),
             "--progress-template", "download:UDMP|%(progress.downloaded_bytes)s|%(progress.total_bytes)s|"
             "%(progress.total_bytes_estimate)s|%(progress.speed)s|%(progress.eta)s|%(progress.status)s|%(info.format_id)s",
             "--print", "after_move:UDMF|%(filepath)s", "--no-simulate", "-o", os.path.join(self.folder, tmpl)]
        lim = self.speed_limit_kb or CFG["speed_limit_kb"]
        if lim > 0:
            c += ["--limit-rate", f"{lim}K"]
        c += ytdlp_common(self.url, self.referer, self.cookies)
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
                G.mgr.add_task(new_video_task(body["url"], {"height": body.get("h") or 0, "cont": "mp3" if mp3 else body.get("ext") or "mp4",
                                                            "title": body.get("title", ""), "thumb": body.get("thumb", ""), "size": body.get("size"),
                                                            "referer": body.get("referer", ""), "cookies": body.get("cookies", ""),
                                                            "fid": body.get("fid", ""), "muxed": body.get("muxed")}), start=True)
                G.events.append({"k": "info", "name": body.get("title") or body["url"], "msg": "Video download started"})
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
                cands += [os.path.join(b, "Microsoft", "Edge", "Application", "msedge.exe"),
                          os.path.join(b, "Google", "Chrome", "Application", "chrome.exe")]
    else:
        cands = [shutil.which(x) or "" for x in ("microsoft-edge", "google-chrome", "chromium", "chromium-browser")]
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


def open_popup(url, referer="", cookies=""):
    """The small window of one download (file information, then live progress), like a classic download manager."""
    now = time.time()
    if now - G.recent.get(url, 0) < 4:                      # the browser may report the same click twice
        return
    G.recent[url] = now
    pid = uuid.uuid4().hex[:10]
    G.pending[pid] = {"url": url, "referer": referer, "cookies": cookies, "t": now}
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
            "notify": CFG["notify"], "confirm": CFG["confirm_delete"], "connections": CFG["connections"],
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


def _auto_update_check():
    """Check once at startup (at most every 6 hours) when the setting is on."""
    if not CFG.get("auto_update_check", True):
        return
    if time.time() - CFG.get("last_update_check", 0) < 6 * 3600:
        return
    try:
        check_for_updates()
    except Exception:
        pass


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
    G.build_no = _build_number()
    threading.Thread(target=startup_integration, daemon=True).start()
    threading.Thread(target=engine_loop, daemon=True).start()
    threading.Thread(target=clip_loop, daemon=True).start()
    threading.Thread(target=_auto_update_check, daemon=True).start()
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
'Mode':'الوضع','HTTP proxy host:port':'بروكسي HTTP (مضيف:منفذ)','HTTPS proxy host:port':'بروكسي HTTPS (مضيف:منفذ)','FTP proxy host:port':'بروكسي FTP (مضيف:منفذ)','No proxy for (;)':'بدون بروكسي لـ (;)',
'Captured file types':'أنواع الملفات الملتقطة','Excluded file types':'أنواع ملفات مستثناة','Excluded sites (wildcards)':'مواقع مستثناة (يدعم *)','URL exceptions (wildcards)':'روابط مستثناة (يدعم *)',
'Temporary folder (empty = next to file)':'المجلد المؤقت (فارغ = بجوار الملف)','Remember last folder per category':'تذكر آخر مجلد لكل تصنيف','Categories — one per line: Name | extensions | folder':'التصنيفات — سطر لكل تصنيف: الاسم | الامتدادات | المجلد','Logins — one per line: site | user | password (encrypted when saved)':'الحسابات — سطر لكل حساب: الموقع | المستخدم | كلمة المرور (تُشفّر عند الحفظ)',
'Scan files after download':'فحص الملفات بعد التحميل','Antivirus program':'برنامج مضاد الفيروسات','Arguments ({file} = downloaded file)':'المعاملات ({file} = الملف المحمّل)',
'Queue':'القائمة','Start time (HH:MM, empty = manual)':'وقت البدء (HH:MM، فارغ = يدوي)','Stop time (HH:MM)':'وقت الإيقاف (HH:MM)','Max parallel downloads':'أقصى عدد تحميلات متزامنة','Shut down computer when finished':'إغلاق الجهاز عند الانتهاء','Exit program when finished':'إغلاق البرنامج عند الانتهاء',
'Project':'المشروع','Start URL':'رابط البداية','Depth (levels)':'العمق (مستويات)','File types (ext list or *)':'أنواع الملفات (امتدادات أو *)','Website filters (wildcards)':'فلاتر المواقع (يدعم *)','Queue (empty = start now)':'القائمة (فارغ = ابدأ الآن)','Run daily at (HH:MM)':'تشغيل يومياً الساعة (HH:MM)','Repeat every N hours (0 = off)':'تكرار كل N ساعة (0 = معطل)','Synchronize: only new / changed files':'مزامنة: الملفات الجديدة أو المتغيرة فقط','Grabber — download websites':'تنزيل المواقع',
'File name':'اسم الملف','Main download queue':'قائمة التحميل الرئيسية','Synchronization queue':'قائمة المزامنة','Also delete the files from disk':'احذف الملفات من القرص أيضاً',
'Enter a valid link':'أدخل رابطاً صحيحاً','Saved':'تم الحفظ','Link(s) copied':'تم نسخ الرابط','Download complete':'اكتمل التحميل','New version available':'نسخة جديدة متاحة','Update now':'حدّث الآن','Install and restart':'ثبّت وأعد التشغيل','Later':'لاحقاً','Check for updates…':'التحقق من التحديثات…','Downloading update…':'جارٍ تنزيل التحديث…','Update downloaded':'تم تنزيل التحديث','You have the latest version':'لديك أحدث نسخة','Could not check for updates':'تعذّر التحقق من التحديثات','Update failed':'فشل التحديث','Installing update…':'جارٍ تثبيت التحديث…','Downloads will pause and resume after the restart':'ستتوقف التحميلات مؤقتاً ويمكن استئنافها بعد إعادة التشغيل','Extract the new portable version over the old folder':'فُكّ ضغط النسخة المحمولة الجديدة فوق المجلد القديم','Drop links or files here to download':'أفلت الروابط أو الملفات هنا للتحميل','No links found in the dropped item':'لا توجد روابط في العنصر الذي أفلتّه',
'QS':'انسخ أي رابط وستظهر نافذة الإضافة تلقائياً.<br>اسحب الروابط أو الملفات النصية وأفلتها داخل النافذة.<br>استخدم «حمّل لاحقاً» مع الجدولة للتحميل في وقت محدد.<br>القائمة الجانبية ← ربط المتصفح لتوصيل Chrome / Brave / Edge / Firefox.','EXT':'تم إنشاء الإضافة في:','EXT2':'Chrome/Edge ← الإضافات ← وضع المطوّر ← Load unpacked','ABOUT':'مدير التحميل المتكامل','ZIP Preview':'معاينة ZIP','Delete':'حذف','Queue name:':'اسم القائمة:','Video Downloader':'تحميل الفيديو','Video Downloader…':'تحميل الفيديو…','Analyze':'تحليل','Analyzing…':'جاري التحليل…','Detected in browser':'تم اكتشافه في المتصفح','Clear list':'مسح القائمة','No videos detected yet':'لم يتم اكتشاف فيديوهات بعد — شغّل فيديو في المتصفح (مع إضافة UDM)','Direct download':'تحميل مباشر','Quality':'الجودة','Format':'الصيغة','Audio only':'صوت فقط','Download':'تحميل','Estimated size':'الحجم التقديري','Best':'الأفضل','Update yt-dlp':'تحديث yt-dlp','Updating…':'جاري التحديث…','Video download started':'بدأ تحميل الفيديو','Video':'فيديو','Browser Integration':'ربط المتصفح','Browser Integration…':'ربط المتصفح…','Choose your browser':'اختر المتصفح','installed':'مثبّت','not found':'غير موجود','Open the extensions page':'افتح صفحة الإضافات','Open extension folder':'افتح مجلد الإضافة','Copy folder path':'نسخ مسار المجلد','Check Connection':'تحقق من الاتصال','Back':'رجوع','Waiting for the extension…':'بانتظار الإضافة…','Connected successfully':'تم الربط بنجاح','The extension is ready.':'الإضافة جاهزة.','Native host registered':'تم تسجيل الـ Host','Extension files prepared':'تم تجهيز ملفات الإضافة','Extension detected':'تم اكتشاف الإضافة','Connection type':'نوع الاتصال','Native Messaging':'Native Messaging','Local connection (fallback)':'اتصال محلي (احتياطي)','Install the signed add-on':'ثبّت الإضافة الموقّعة','Not connected yet':'لم يتم الاتصال بعد','Test link':'اختبار الرابط','Resume capability':'دعم الاستكمال','Duplicate download link':'الرابط موجود بالفعل في القائمة','Skip':'تخطَّ','Add it with a numbered file name':'أضفه باسم ملف مرقّم','Add it and replace the old download':'أضفه واستبدل التحميل القديم','Speed limit for this download KB/s (0 = none)':'حد السرعة لهذا التحميل كيلوبايت/ث (0 = بلا حد)','Checksum MD5 / SHA-1 / SHA-256 (optional)':'بصمة الملف MD5 / SHA-1 / SHA-256 (اختياري)','Import list…':'استيراد قائمة…','Export list…':'تصدير قائمة…','Export selected':'تصدير المحدد','Copy folder path':'نسخ مسار المجلد','Refresh download address…':'تحديث عنوان التحميل…','Or paste the new address here:':'الصق العنوان الجديد هنا:','Redownload':'إعادة التحميل','Check file (SHA-256)':'فحص الملف (SHA-256)','Limiter: On':'المحدِّد: يعمل','Limiter: Off':'المحدِّد: متوقف','Maximum download speed (KB/s)':'أقصى سرعة تحميل (كيلوبايت/ث)','Once on date (YYYY-MM-DD, empty = every selected day)':'مرة واحدة في تاريخ (YYYY-MM-DD، فارغ = كل الأيام المحددة)','Save all files of this queue to':'احفظ كل ملفات هذه القائمة في','When the queue is done':'عند انتهاء القائمة','Downloads at the same time (0 = no limit)':'تحميلات في نفس الوقت (0 = بلا حد)','If a duplicate link is added':'إذا أُضيف رابط مكرر','Give finished files the date from the server':'اعطِ الملفات المكتملة تاريخ السيرفر','Open each file when it has finished downloading':'افتح كل ملف عند اكتمال تحميله','Color palette':'لوحة الألوان','Text size (%)':'حجم النص (%)','Don\'t go to parent folders':'لا تصعد للمجلدات الأعلى','Download a playlist':'تحميل قائمة تشغيل','Getting the list…':'جاري جلب القائمة…','Check all':'تحديد الكل','Uncheck all':'إلغاء التحديد','Download checked':'حمّل المحدد','Subtitles too':'مع الترجمة','Exact cut':'قص دقيق','From':'من','To':'إلى','default':'افتراضي','ocean':'أزرق المحيط','forest':'أخضر الغابة','purple':'بنفسجي منتصف الليل','rose':'وردي','sunset':'غروب','teal':'فيروزي','neon':'نيون','clay':'طيني','ask':'اسألني','replace':'استبدل','number':'رقّمه','skip':'تخطَّ','exit':'إغلاق البرنامج','sleep':'سكون','hibernate':'إسبات','shutdown':'إيقاف التشغيل'};

const EN={QS:'Copy a link and the Add dialog appears automatically.<br>Drag &amp; drop links or text files into the window.<br>Use “Download Later” + Scheduler for timed downloads.<br>Browser Integration (left menu) to connect Chrome / Brave / Edge / Firefox.',EXT:'Extension created in:',EXT2:'Chrome/Edge → Extensions → Developer mode → Load unpacked',ABOUT:'Unlimited Download Manager'};
const DISP={exit:'Exit the program',sleep:'Sleep',hibernate:'Hibernate',shutdown:'Shut down',default:'Default',ocean:'Ocean blue',forest:'Forest green',purple:'Midnight purple',rose:'Rose',sunset:'Sunset',teal:'Teal night',neon:'Cyber neon',clay:'Soft clay',ask:'Ask me',replace:'Replace the old one',number:'Number the file',skip:'Skip it',en:'English',ar:'العربية',dark:'Dark',light:'Light',none:'None',system:'System',manual:'Manual',hour:'Hour',day:'Day'};

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
const OPT=[['General',[['language','Language','sel',['en','ar']],['theme','Theme','sel',['dark','light']],['palette','Color palette','sel',['default','ocean','forest','purple','rose','sunset','teal','neon','clay']],['text_size','Text size (%)','num'],['clipboard_monitor','Monitor clipboard for links','chk'],['capture_enabled','Capture downloads from the browser extension','chk'],['silent','Silent mode (add without asking)','chk'],['notify','Completion notification','chk'],['sounds','Sounds','chk'],['startup','Start with Windows','chk'],['tray','Keep running in tray when window closes','chk'],['confirm_delete','Ask before deleting','chk'],['dup_action','If a duplicate link is added','sel',['ask','replace','number','skip']],['server_date','Give finished files the date from the server','chk'],['open_after','Open each file when it has finished downloading','chk']]],
['Connection',[['speed_mode','Speed mode','sel',['auto','manual']],['connections','Connections per download: maximum in Auto mode, fixed number in Manual (1-32)','num'],['host_max_conn','Max connections per website (0 = no limit)','num'],['write_buffer_kb','Disk write buffer per connection (KB)','num'],['keepalive','Reuse connections (Keep-Alive)','chk'],['max_parallel','Downloads at the same time (0 = no limit)','num'],['timeout','Timeout (seconds)','num'],['retries','Retries after error','num'],['speed_limit_kb','Speed limit KB/s (0 = unlimited)','num'],['quota_mb','Quota MB (0 = off)','num'],['quota_period','Quota period','sel',['hour','day']],['user_agent','User-Agent','text'],['ftp_passive','FTP passive mode','chk'],['ignore_mtime','Ignore modification-time changes on resume','chk'],['server_limits','Per-server limits — one per line: *.site.com=4','area']]],
['Proxy',[['proxy_mode','Mode','sel',['none','system','manual']],['proxy_http','HTTP proxy host:port','text'],['proxy_https','HTTPS proxy host:port','text'],['proxy_ftp','FTP proxy host:port','text'],['proxy_user','Username','text'],['proxy_pass','Password','pass'],['proxy_exclude','No proxy for (;)','text']]],
['Types & sites',[['capture_types','Captured file types','area',3],['excluded_types','Excluded file types','area',2],['excluded_sites','Excluded sites (wildcards)','area',2],['url_exceptions','URL exceptions (wildcards)','area',2]]],
['Save to',[['temp_dir','Temporary folder (empty = next to file)','text'],['remember_dir','Remember last folder per category','chk'],['cats_text','Categories — one per line: Name | extensions | folder','area',6],['logins_text','Logins — one per line: site | user | password (encrypted when saved)','area',3]]],
['Antivirus',[['av_enabled','Scan files after download','chk'],['av_command','Antivirus program','text'],['av_args','Arguments ({file} = downloaded file)','text']]]];
async function optDlg(){const c=await api('cfg_get'),w=document.createElement('div'),tabs=document.createElement('div'),fm=OPT.map(([n,fl])=>form(fl,c));tabs.className='tabs';
const show=i=>{$$('span',tabs).forEach((s,j)=>s.className=i==j?'on':'');fm.forEach((f,j)=>f.style.display=i==j?'':'none')};OPT.forEach(([n],i)=>{const s=document.createElement('span');s.textContent=n;s.onclick=()=>show(i);tabs.append(s)});w.append(tabs,...fm);show(0);
modal('Options',w,[{t:'Cancel'},{t:'Save',p:1,fn:async()=>{const cfg=Object.assign({},...fm.map(f=>f.get()));await api('cfg_set',{cfg});toast(L('Saved'));poll()}}],1)}
function schedDlg(name){name=name||S.queues[0].name;const q=S.queues.find(x=>x.name==name),D=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],v={...q};D.forEach((d,i)=>v['d'+i]=q.days.includes(i));v.after=q.after||(q.shutdown?'shutdown':q.exit?'exit':'none');
const f=form([['name','Queue','sel',S.queues.map(x=>x.name)],['start','Start time (HH:MM, empty = manual)','text'],['stop','Stop time (HH:MM)','text'],['parallel','Max parallel downloads','num'],...D.map((d,i)=>['d'+i,d,'chk']),['date','Once on date (YYYY-MM-DD, empty = every selected day)','text'],['folder','Save all files of this queue to','text'],['after','When the queue is done','sel',['none','exit','sleep','hibernate','shutdown']]],v);
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
else if(x=g('[data-d]')){const it=items.find(i=>i.id==x.dataset.d);if(it){await api('add',{urls:it.url,category:'Videos',start:1,nconn:S.connections,referer:it.referer,cookies:it.cookies});toast(L('Video download started'));poll()}}
else if(x=g('[data-h]')){pick.h=+x.dataset.h;drawRes()}else if(x=g('[data-c]')){pick.c=x.dataset.c;drawRes()}
else if(g('#vg')){const sl=cur.qualities.find(q=>q.h==pick.h);await api('vdl',{thumb:cur.thumb,url:cur.url,height:pick.h,cont:pick.c,folder:pick.f,start:pick.s,end:pick.e,exact:pick.x,subs:pick.sub,title:cur.title,size:pick.c=='mp3'?cur.audio_size:sl&&sl.size,referer:cur.referer,cookies:cur.cookies});toast(L('Video download started'));poll();o.remove()}
else if(g('#vup')){toast(L('Updating…'));const r=await api('ytdlp_update');toast(esc(r.out),9000);tools()}});
drawDet();tools();const iv=setInterval(()=>{if(!document.body.contains(w))clearInterval(iv);else drawDet()},3000);
if(u0)analyze(u0,ctx.referer||'',ctx.cookies||'')}


const A={resume:()=>api('resume',{ids:sel()}),stop:()=>api('stop',{ids:sel()}),stopall:()=>api('stopall'),
del:async()=>{const ids=sel();if(!ids.length)return;let files=false;if(S.confirm){const o=modal('Delete',Object.assign(document.createElement('div'),{innerHTML:`Remove ${ids.length} download(s) from the list?<label class="chk"><input type="checkbox" id="dfiles"><span>Also delete the files from disk</span></label>`}),[{t:'Cancel'},{t:'Delete',p:1,fn:async()=>{await api('delete',{ids,files:$('#dfiles').checked});st.sel.clear();poll()}}]);return}await api('delete',{ids,files});st.sel.clear();poll()},
share:()=>{const u=sel().map(i=>S.tasks.find(t=>t.id==i)?.url).filter(Boolean).join('\n');if(u){navigator.clipboard?.writeText(u);toast(L('Link(s) copied'))}}};

function ctxMenu(e,items){$$('.ctx,.dd').forEach(x=>x.remove());const m=document.createElement('div');m.className='ctx';items.forEach(([l,fn])=>{const d=document.createElement('div');d.textContent=L(l);d.onclick=()=>{m.remove();fn()};m.append(d)});m.style.left=Math.min(e.clientX,innerWidth-230)+'px';m.style.top=Math.min(e.clientY,innerHeight-items.length*38-20)+'px';document.body.append(m)}
document.addEventListener('mousedown',()=>pressed=1);document.addEventListener('mouseup',()=>setTimeout(()=>pressed=0,0));

/* ===================== NEW DESIGN LAYER ===================== */
Object.assign(AR,{'Last capture':'آخر التقاط','Download with UDM':'تحميل بواسطة UDM','Home':'الرئيسية','Completed':'المكتملة','Settings':'الإعدادات','Pause All':'إيقاف الكل','Resume All':'استئناف الكل','Clear List':'مسح القائمة','Recommended':'موصى به','remaining':'متبقي',
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
function rowAct(x){const id=x.closest('.row').dataset.id,k=x.dataset.act;if(k=='stop')api('stop',{ids:[id]}).then(poll);else if(k=='resume')api('resume',{ids:[id]}).then(poll);else if(k=='folder')api('folder',{ids:[id]});else if(k=='del'){st.sel=new Set([id]);A.del()}}

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
if(ev.k=='done'&&S.notify)toast(`✔ ${L('Download complete')}<br><b>${esc(ev.name)}</b><br><a href="#" style="color:#7fc0ff" onclick="api('open',{ids:['${ev.id}']});return false">${L('Open')}</a> · <a href="#" style="color:#7fc0ff" onclick="api('folder',{ids:['${ev.id}']});return false">${L('Open folder')}</a>`,9000);else if(ev.k=='error')toast('⚠ '+esc(ev.name)+'<br>'+esc(ev.msg),9000);else if(ev.k=='shutdown')toast('Queue finished — shutting down in 60 s. <a href="#" style="color:#7fc0ff" onclick="api(\'cancel_shutdown\');return false">Cancel</a>',60000)}
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

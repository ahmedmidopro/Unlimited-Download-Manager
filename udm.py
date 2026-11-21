#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unlimited Download Manager (UDM)
A multi-connection download manager for Windows (64-bit) written in pure
Python 3.8+ (standard library only; optional: pystray + Pillow for tray icon).
"""
import os, re, sys, io, json, time, uuid, shutil, fnmatch, base64, secrets, threading, queue
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
                          pending={}, last_popup=0.0, recent={}, win=None, win_closed=False, want_ui=False)
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


def _on_win_closing():
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
    if _try_native_window(url):
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
        u, found = ctypes.windll.user32, []
        proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def cb(h, _):
            n = u.GetWindowTextLengthW(h)
            if n and u.IsWindowVisible(h):
                buf = ctypes.create_unicode_buffer(n + 1)
                u.GetWindowTextW(h, buf, n + 1)
                if (buf.value.startswith(prefix) if prefix else buf.value == APP_NAME):
                    found.append(h)
            return True
        u.EnumWindows(proc(cb), 0)
        if not found:
            return {"ok": False}
        h = found[0]
        if what == "min":
            u.ShowWindow(h, 6)
        elif what == "show":
            u.ShowWindow(h, 9)                         # restore a hidden / minimized window
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
            "conns": sum(t.nworkers for t in act)}


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


def setup_tray():
    try:
        import pystray
        from PIL import Image
    except ImportError:
        return False
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
    threading.Thread(target=startup_integration, daemon=True).start()
    threading.Thread(target=engine_loop, daemon=True).start()
    threading.Thread(target=clip_loop, daemon=True).start()
    tray = CFG["tray"] and setup_tray()
    if urls:
        G.incoming.append({"urls": urls})
    if not args.minimized or urls:
        if open_ui():
            quit_app()
    while not G.quit:
        time.sleep(1)
        if G.want_ui:
            G.want_ui = False
            if open_ui():
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
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAUEBAQEAwUEBAQGBQUGCA0ICAcHCBALDAkNExAUExIQEhIUFx0ZFBYcFhISGiMaHB4f"
    "ISEhFBkkJyQgJh0gISD/2wBDAQUGBggHCA8ICA8gFRIVICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICAgICD/wAARCAG4ANwDASIAAhEBAxEB/8QAHAAAAgIDAQEAAAAAAAAAAAAAAwQCBQABBgcI/8QAQBAAAgEDAwIFAgMHAgUE"
    "AQUAAQIDAAQRBRIhMUEGEyJRYXGBFDKRByNCobHB0RVSM2Lh8PEWJENTkiU1cqLC/8QAGgEAAgMBAQAAAAAAAAAAAAAAAwQBAgUA"
    "Bv/EADIRAAICAgECBAMIAgMBAQAAAAECABEDIRIEMRMiQVFhcbEFFDKBkaHR8CPhQsHxJEP/2gAMAwEAAhEDEQA/APkitdKJtqJF"
    "bNTPuZmsrMVlTOmVICsAorR7Y0cOp3Z9I6j61IFyCZpMUTGRUEHOaYVciiAQTGBx1Fawc00VwwZBsIHaoLEzsQq5IBOBXFZHKBAJ"
    "oqL71sL2oiofapAlS0xV5ogQ1JE9VHWM0dVgGeoDZxUCpzTpjI7UPYNxNECSgeL7OaPCuFkQAZI7mpxM8MvmKxU4IGBnrx3oyQbo"
    "Ny9uDmmcK+bU5n1Fk2tIpbcAeDg9ajfpGAzQqY4yfSmc0WXysL5aMHUes9uvX4od5ua2hOeefT7D3orV4bXJQ2wMqyMVE5PB7UXa"
    "SDUSMcVkVHQYFs9qh3orVBVLOFGASccnFBIhBI1lbbHGBg961VZMwVo1vmswO9SJ0lWYFSxWVaUkMVPyyE3FDj3rWfin21C6n02H"
    "TOGhjcuihRnc2Aeep6CuAHrIZmFVEAMUZCpidXkYY5VQMgn+3FYmELB4wxwVw2eD7/Wohea6qnE3JqM0eMDOKEg5o6LyKKogWMKE"
    "B69aj5R7DmmY13D5o6wnIbGQKLxuLF6iXkFNpJByM/Sjks0SRkKApJBCgHn3PerfU7g6hPHKba3gxEibYF2rwMZI9zjJ+aTWD4zV"
    "wkH4hIsxdIhuzTccGaNHAcj01Y29pnqKZTGYnlzASreDAzS4TGTV3PbbQcUoIWAOFBwM80U46MpjzWJXLbvJJsRSTzx3x1pu2kt4"
    "7ecT+YZmUeSVIChsjJbPUYz962scZ4YMCB1Hvn/FLmJnmJY5Aqt8diNA8tGLtAyqzk5HxUL4CVg+MAKAMdKYlyWKjqf5VC5j810j"
    "UiNBhck8Z9zVr/xssMDRBlX5WAG7GpxRWrRTmd3VwMptGefmpSKY5TGXBUHG4cg/NLP+c4bIHQjis9mC+kaG/WLNio/aiuq59JOP"
    "moYxyelKkRgGDIrNpxUz1reKrUtcgB6sVIoc8CpKPUKIcg4q4WVLQe09Kzae9FC1m013GV5SGyPyd28+Zn8uOMe+a0pZGVlJDA5B"
    "HGKntrYTNdU65DlmLMck8k1MKT0FTEQyOcZ7+1O6ddTadex3cCoZEzgSIHXkY6Hg1dV3uDZiB5e8U2Mp9SlSecEUxEma3hncsR1p"
    "qCJCQrenJ/N7URV3BM+oSBB0qzgg3Dkce1DtLaNo5GeUI6AFVxnfz/Krm0i3qqhRkew604i3M7LkAlcLNt+FQnvge1Mw2bbh6cgV"
    "fx6aZQGC1b2ehPKB6abTDMvN1oUbM5tbDMYITkVY2umSFC2013Nh4UnnTZHbvIx7KpJrrbL9nmsPCAulXHTvGRTP+NPxGpi5OtZ9"
    "YwT8p4jdae6dutV0tkQcbP8ApXtOr+BNTtFzc6dPEPdoyB+tcpd+HpI5G9BwPirEK4tTcJi64L5X0Z5w9vs4IJqN08I0yK1WzjSZ"
    "HZ2uATucEDCntgY/nXW3Gjum5inFUN3ZEE+2OaUdSJsYcyvRuc55I3rvcYcZO3kj61ue1kFuryYRWYoGJ4yBz/amZ4Sp6UKS3MkA"
    "O5fR1GeT/mhIdETSDdjcpJGJmMrje3X1DIJ+aUIIPtVhOu0nHakmXPWs/J3mjjMXZeKHtGDnPFMleMVHb6toJwfagcYcGosF5qZV"
    "FUbWJbvxxRWjIYr2qQiGOlWCHtOLQSRs30qbDmjhcL0oRUk9BRSnESoazI4qYH6VAGj7lY5VQox0BzVQJBMGUBNbC46D70QDNO2y"
    "WRtbj8SZROFHk7ANuc87vtnpU8YMvUWjQSsqouGxzk9TTlzHYrJELRpWXYvmbwAd+OcfGaVRMv2HzTEcRY/981YHVVKMRdxi1ZUK"
    "R3CboQwLAcEj600yQtPI1tGVjYnYrHJA+aDHAVIV1Knvkc1YWsXqHFMgkijFHYDYk7eBm2g54966PTbBnYYWh2dn5jDav2r0Lwzo"
    "Ml5cwwQx7pHOBnt9abx462Zg9Z1fEQ/h3wzc6jcRwW8DSyv0UD+dey6F+z3Q9JiS5124Esn/ANKnag+Cepqx0qytPD9l/p2mxia5"
    "I/8AcXI4A9xn2+Kp9S1O0h1CSOWV7icKcEtlIz2yO/0pd8r5fKhofuf4mYqqh55RyPsew/n6Tr/9W0e1jEWlQRRwgYAiUDP+aSl8"
    "QalGVa0s8gnh5Dwap9M1qyuoxFNahCnHmDH9hxTmo6hpunaejTOwWbKqUXLHHx7UoMSqeJWzGzmdxyDUPhqXkWrC6t43mCh26qFy"
    "KTvNG03WMxX2mwOSf+LH6Hx7g1xUeuQPOtq+oeRbsSFuG42HqBxXoemjfp0c8kgmzzvUDBP2quXF4PmXUthyfeTxfc8v8T/s4a2h"
    "kn00NcwLyylf3ifUdx8ivINS0f8ACzh2gV1Rs7Gzhvg19UXuuW9jGbtssmQoOOWP/ivOvF2m6TrelSeINGjA2vsuoVH5W7Njtmne"
    "nzu4rIPz/mK5VXA14m/L4e4nzVqFpl3cgBmOcY6VRzRlQQiliB27fNeg61pzJIx2/wDSuQuYfK3EE5IxRHWjNnps4dbnLzwkHkfN"
    "Juu2NvUvJHGOau5oiSWbqaRntx6SDnPUe1KMs2cb6lUVzRI4iWRmXamcbsdaOYsdqyOJtyBVLNu/KelDVdxjlYk9RtLS2vGjtro3"
    "MWARIF25OPb60sVCRgspGTwaLMqpOwDBgvfpmlHJaTk0wzAMSBU5L4gEyErEyAKcAUTAHVhmtGLJLNwBQiBmgkkGz6wmj2kAaIrA"
    "ChgVvHsRQRLmMJIoPNMo6GkVU0VDg1cMYJlEtIo1bnGRT0NuCQV4IqrhuZVgMAkIjZg5XsSMgH+Zp62u3jI9VXBERyK3pLloLi5l"
    "aaaRpZHOWZjkk03b2Z3cig2l+DgsimuitZLWQruUjP3pvGoMx82V01UsdHsdzqRXqmkNDpNishBWdhuLL1Ve2Pqef0rkvD9lHNKg"
    "jYYJArqHzPfbRtOMKMdAuMKP6U7xB1PKdTmLvOk1i/Gm+Hbe0sZJFllbzHDNkycc5P1I4rira5lN00khYuxy245zVleO5fNxIWkC"
    "7Vz3z7Umls4YFVKYyGVhz812NAoMh8pJA9pf6JLM8smY/wD26n1cE5+Kl4h//a4blZGks1kKpkEEN9/pQtPl1ZZ18qWOCJyA+9QF"
    "Udz/AGp/xPrMMsS2kYR4lXGVxj/rQiDzFQwI4Ekzj3YPZEgjAYZBq60jxk2maQbF52UxtmJh02+xp+DT2vdIvZtLhRwY1MTyxLvB"
    "xzz+vSvOjb3Co4lGXc4IblsCjKq5AQ3pAnIyEFTPZNI8U6J4q0ltKvjFBdvnlUI2N2Ydsc0xougzeH49Ta8VLyC4UDZHk71Gck15"
    "z4f0XVYpIbqK0ma2kJDOBlMDGQasrHXdXTUvJhvXFpKc+Sfygew9vtSeTp65LiOvaNDqgeLZV2Ox/n3lF448PjTdVmtkO6IgSRt/"
    "ynp9x0+1eVajZFWZscCvozxtp34nw/a6gsbF4QEdmHJB6Z+/9a8I1pG8xlx36UfGeeME9410znHkKDQnG3FvHsfBG4c9OtV6Wcty"
    "s7xRgrCu9xuA46feuhS3jklYTkom0kHHU9v51S3R8tVjji2SqSTICctnoMfH96E6V5iNT0GLJflU7lKzMr4jUbjxnHNK3DTQ3DiQ"
    "ESgncPY0zKrZyOKGbZpEL9T7mkzsUJrKQO8VZWb1MMFuaEybTz1pwwMq7nYZ7DNS2pjc4B469anjcLylfJJuAUDAFD20aVIw5K5x"
    "QyxzxQWJJswwGtQWKzgVMrzWitUIk3JJyM5xTLx+VEkbx7ZPz7s5ypAI/wC/ml4wARvzt7460RQcVIg2hUO3BGD/AGqxt/IaOV5n"
    "dZcAxhQME57+3FVyISasLdUCMGTcxxhs9KKgMWyVUtLUhgCWJYnniui09SzDk/pVFaOoTaVTBOc45FdLpzJvU8e+cVo4ccwOsagZ"
    "6X4QtzJdQoGAJPtV1bX8dlr34ho0lVDvCjhTnp0pTwLJCNUsy+CvmqGz7E4pnxBos+la9cWso2lDkZ43L2xTB48yh9p45+V+IPQ/"
    "+RubddgX8QXggFTztGev0rrNI0iwv4YZpJA/m+oyOwGD/iuX8M39jazSR6iC4kGAFHQdM09YahDBmNFUgg+ksc/QfFCyBjarqXxO"
    "oIZ9xnxDNZx2s1tG6vLGpZQvOevSlvC1zpEWlpBJbbJZGy4dd2STniiSW9nqSveQB41jyCeu5fiun0e20WTTImhZbvYN+Qo3KfpQ"
    "3YJjo3DYg75LFTo7Wzso7Fo44tgfpjt8Vz2o+AtInin1RzKHwQFjwATV/aXKAEeUSMcbh0NWcU6qArJyc7s+1Y3i5MbWpnpFwYM6"
    "gOBOO0JLew0lLK8laBEYjLcZzzVXf+FTBq5vbWRXgAMuSQAR14rr/E+mtqFqjWb7SGGVPc9qXtdGvb6zW0u7gHy1EZePjdjkY9sZ"
    "xR1z/wD6A1fcRPJ0pvwON12Mr9UlbUPDF4swwRErcjAJBGK8C1+x2ztuIHNfRPi9UsfD8zMcM6rHx9v8V4TqpeeQkRlgOevWtHoP"
    "PjJHa4j1bNi6gK3cCccmnB7bEZUuGyeOcVSa3pyTaiVhKgbRXUNbyNDMBnPUZGKrb21aG1SVpU3OgVeemK1DjUpxMvg6kjLYM4+9"
    "tLe2i8pioK9Rjkmqe4mQxhVVlYex4FP3yzzXDOyjn2pOe3mdXlOX8tRuIHCjoM1juRZ4jU9dgQgAsYkEZ/WQWVeTigysSCAFGeSK"
    "ce7aK0aG2mlVZVAmXoGwcj6joee9VDyZJzml2IAqaOMWbMgx96hWmatCRgMDH6UrcbhlXLYzRUXGWC5HQ0ANTts0cKM88BkV1ITJ"
    "IGemeOuKYU3FXsQcUSPJsdxGD/ERmoAYPSpDcVLKvA6mrHTNNXUHlDXcdvsjZxvz6iB0GO9WVC2gINn4gsx1FUAKMF2+nByTg+2B"
    "70eOQkAMc4GBn2pYRkPt684ptLdgMkg844Oasqk9oNyBHIXNdPpak24bPJPQda5+KzmVgjxsH49OOeeldDp5MKhEX1H55FbHS4GW"
    "2cUKmJ1hBXyz0bwtO0boS2054969s8VWieJvCNjf26o16OeeC5AO5Qe54PFeB6I8wfAQnAHqJwB9a9q8C69au6aVesjRtIHhduiS"
    "j2+tLdYhAGVO6/SeUw5FGZsGQ6f6+k83kRtwBBV1zvQjBBFWWmXMFpKgv43khxu9sg8CvVtW8L2U0011DbbZHI3ZHGQeo9uOK5Px"
    "jD/ptjaWlvZLI7AsZcelR3Xpz79aGnVLlpR6yMnRvhst6Sl0x9RtIlvBKEtXdkB4YP8Ab5pzSL/ydeEUDC2gmlG5VbhPjpzRtOeC"
    "50yIQWbLGvDoygnzDwSOx55xxT9p4A1C6vFupHAti4w0eMkd8n3FS7oAfENSuLHkdgMQup3cMZy7QosnoByDn9KZMbR26Ju3Sydw"
    "ckVc2OmxWOnxwxsSUUKCepHyaBcoEO8kJkgF/avNnMGahPbjo2xoGaLs3lIIwAdhxz1J96JautvN5xBChcsfahxKjuBGdvOSSCSf"
    "igavex6fpk08uPLgTc3bcewrq5Hh7zi3AHKfScF+0rWRM0Vmg3YJlcdMdh/evJRqqW9xkxhk/iRjww9qb8S61cXl9NdSklnbOQen"
    "xXLJcwyPvvXynIzjp7ZNeu6XD4aKgnkMjHO7Zn3c6CcafJay3xdYUX1IjHG/3Arjtb1e3uNQjeS1JtFx+5V8EqOMA0DVdVt5YgkV"
    "w/oU4THGc+9c1NfyIixswcNk7Tzt+OaZ6lgq1Geg6Bg3iN3+kUv7hRMyoMqeRjriqqeaMQ4VnEhJ3DtjjH8807dsrTFNwYjgbec/"
    "5qtlUDtWIzWTPZYuwi7XLLbyQhUO/HqIyRj2PakG604wUg5yKDuKE+W+CwKnjsaVbceTUVYdMCtbRRGG04NCLc9KAdQ4kx8kCpB6"
    "Eucc1IYz71eQRHrUI6SmSfywFzt59fPSp29xLbSF4JCjEFcjjgjBFJDIOCMYqwWxuhZLfNbyC1Z9gmKnYW64z747UwjHVQDgevrG"
    "LWJ5WErxsYlYB2A4GadRSkrxj07icBaQRgrskchePscYz9qsxcr5cbmMDnlh1Na2AKEmfmu5cW2kXcNnHqN0fLikyEdz1x1x/Kut"
    "0FNJttFl1K/ZZLiMjyrfoWB/iY+1cjdazJPbpa3UrSRJHsjBOPK5z96EbwwJAu5djxnOByQSetNv1QVRjTtMHNgy9QnFzW/T29p2"
    "cmviV96rEoY5Coc/rV9o+suZFLMd39K8ysZXCsgwVJ3Hium02ZVw5bYoxzmg43L7My+r6FFWlE+pvCHjKO7sI7XVHQSAbElk6P8A"
    "U+/z3rotQsNPv4il3bB8eoHj9a+YrLX3bbGrYUcAfFehaH48v9PiSBpRcQAY8uXnH0PUVkZ+g83iYNfCEwfaDogw9ULHv3/WdzDo"
    "VqYjaND5cG8OpV/zEd//ADXQ6aq2axxgBEXgBCcH61ytn4u0C7QJKkloxOT/ABAH4I/xV1aapojqQdYhK5yAQQRSeZMhFODGOly4"
    "kcHGRfzA+tTrVk3AyB/SKXkcSHaFGR0zzVQ/ijQrIbm1COX4QE5/lVBqX7S9OgkddPsi7jo8xwPrgdf1pHH0uZj5VP0m5m+0umRf"
    "PkHyG/pOvuJ7exgN1dzLBAo5Y9T9B3NeLeOPGMuqO1vADDZRH0R92Pu3zSeteLbzUbwXF1cmUdl6Ko9gO1cdrl2rZkjO5HFeg6To"
    "RiPN9n6TyvV/aL9W3hYxSfuf77Sg1LVHUmTywQ4K+rof+tcnd3czxl8nZ0J+frT99KpDM/rOSAmTx81zt1JxsUnYecZ70+z8dTW6"
    "XAABqZbJNe3JAG4ICxGQOAMmkL65aed5Wcs5P1J+ajM7RjcpKg9/ekJ5mc9eAMDtSmXL5eE3MePdzJLnEZGDvzkNnkUk1w+0jjr1"
    "rHY/ahbd7hQVBJ6k4FZjMbmiigQ8VwcbJfVFndt9zQVSWRJZo4yUiALt2XJwKCWYcZqJkkCGMOQhIJXPBI6f1NULQwX2mmIIodbN"
    "RJxQzCgSQ6ZqYYBeB6s8HNRA4re3v/WiCVMlvJOScn3qw/1a+fS00trqQ2aOZVh3HYHxjdjpnHeqzAx1+1SBwakORKsoPeOo5Bpq"
    "OTBAYn5qvRunPPtTghdLaO5LJsclQAwyMe47daaVye0WyKPWPecGnyvrUHjcOo+aso7NZJreNrgIZRuyfUEX5xz2qoRFO798qlV3"
    "DOfV8Uzb3jK6MMBkXbx/EO/9abSrp4jkQkeWWlnOTMUaREHJLMOtWLXspRAmDGnAIqk/d3RBAWFj0OeG/wAU9BaXyLvjXcoALEEE"
    "CnMSHagWPcRDIiE23edFaXqrCrmX94Tgrjt71fQajtjVvMGTxjPIri442CrNJ6EYZzjjrimoL1WcKxKqT6mAzx8CpcFO8y8uBX2J"
    "39vq7KRhulWNvrrBvz/zrgW1AyGSUybieMsMEj6VKG/YHg1W5nv0QbdTvbjWmJ/4nz1qrudXLSZDdRXMyag2evApV7sMwJbAHtXW"
    "JCdCPaXb6i25kZvpzRrEtqt0lgJY45JWCK0rhVB9yT0FchLeEPkdqxL1lw+T/mq8xHPuWrEZ1O3MF5LAxDFCRlTkHHzXN3gCyFtu"
    "0E8LnpV/JOZ1LJguAev0rl71yznNDyMAtza6VSdH0ily24gDsP1pB8kHA6Dmm36Vu0uxZ363b28Nztz+7mXcrZGORSZ8x801h5Rr"
    "cr2AEAZgrZyAN3IPvilCcZpmUgsTjAJ6UCaR5XLu25j3NJuKjSbkHcMq4QKQMEj+L5NCNbJrXbmhHcMJrIHbNQOCelTC7s46Co5q"
    "pl4QdKIORUBRFHIBOBTCwZmigYcDBoQPNMhGIJA496AF5NdkWqInAwkaNuGBRd24HOS+ck5qys9Ut7bQ7vTn0+CWWdlIuHU+ZFjs"
    "pzwDnmqon1HFR2qjAgsxNiowrkECQ5HxTKHY6urYGeDnpSqSIWXdGoAHI59VbBJAAUcc5oqtKMstUmWRu6tnOV6E1dBTaaXDepNG"
    "HlZkKK+WGMckduvWuahnePhTgA5+9NNcvIctyTWphz8QSO8z8uEkgekv7O6aS3khkj3CUj1/7SKbkSFU2KoDdciubimeJt2cZ6VY"
    "G5U2ihQTJ1LfFP4sqshDCzEMuCmtfWPF3QsEG7HB4zipwzkcZxVXucIChOSegozXLmFImRV2nOcYJz70mdbnHF6R6W5Oc5+lCW4O"
    "8E8jPfpSHmruBfJUdQKCbgrLuQ4weM0B29YRMMalnO7qDn2oK3TRudpxxjnmlmcE+onpxitLHLIcopJ+BQLMa4ACjLGG7KHBOR3p"
    "W82sdyUvvKnB6/1rZkDLiuJsUZypRsRd7qZbRrYECJzuIwMkj560rIjLOiz5jDAEkDPB74+lEmTB+tLOn7ln3qMHG3ufmgkmOKB6"
    "QMjDJA5qELxxXKyTQiaMHJjJIDD2yOastFn0y31SKXVrR7u0U+uJX2Fvv2qvu2ie6kaBdsZPpHsKE3blcMreYpXp3irDJOOKgRRM"
    "ZzWbaBUZE15hEZRQFB6n3oO2jqgY47UTyQOOtW4lpNgSO0ipAcGpggisGM0dYImSjx025LDA570BgQTRyQBUTggMBgirPRFSBNJC"
    "0qsynkDOPehg4PSpMSzEnqT9K2qg/mbGPigV7S0I87yiJWCgRrsGBjjJPPuealnLEgAZ7DtQFGWAqxube3s54vw11HdAxq5IU4Vi"
    "MlSD1x09quikgmCcgGoOEMXGBnHNPtbzywPfbFSEybDtwACecAUlBNJCxeJyjEEZBxwRgj9K2JTjAJxTC0BF3BJ1DZIbAzgdDTCM"
    "/l7sjBOOvNLB+RySCO4oisDgZx80dG3BMI7LeMbhJIwE2qqjaMdABmse5klfzJWLscck5pVXBGGH3ogXOKKxY+sCVAk2LEcVAqx7"
    "UxHGW4xXR2em6dpWjf8AqHxEXWyyUt7aM4lvHHZc9FHd+3QZNBYaswficTQ2Zz1vZTTsqKjMzHAAHJro/EtgdA0OLS7W7lttWZ1l"
    "u5IWwY8crDn46t84HarhPGdqLm0m0Wwt7SNOEENmu5MDlzMxJOTnHfoc9q4fxNc31/ZXUtnC7zufSq8sMnk0Nyoxk1K4DlfOvLQg"
    "b6S1uYbXUbKTfHcx7m4xtkBKuPpuBI+CKQZyORRtCign06bTktJYBaWzXHnSy5wwxuXAGMFicd+R91WPJFBR+aBj3miU4OVHaTL7"
    "1+aDK0Yt/LWEeZuyZCe3YAdu9ZvIOakMB1YxhwDkqc4b4qTuW7ROUmRl2oFwMHHegYOcYp8wk5IwM0CWPypGTIYg4yOQaoyk7MMj"
    "DsIrjBogX0g+9SVQRg8H5qXlnFUCwnKDXg5qfNbC84xUthNSNTr94IDFTKEcDn5qDt6sDn5o0S+jJ71ddmhKE0LgcENg03dQW0c6"
    "JZztcIyKSzJtwxHIx8HIz3oTx7WDYo2FMPAHTr7VYKdiVLdjD6ppUOnx2bx6hBdm4hErLCTmIkn0tkdfp71XxpE4cO4j2gkMQTuO"
    "OF/61InPBoJyDVGr2koCBRNyJOOFOR9KkGz3pm0s0uLhY7m5WzjdGcSSKSDgHA49yMUqRg1XiRLWCahw/HXmsD5OM4oNSTlse9Tc"
    "qRUOHPvmmEkKSI49WOdpHtQFj+QKkCwGORxiiKSDcCaMsZ7prq8kmeFISxyY412qvwB2qx02ya/voLSNlRpXCBnOAM+9UkeSdxOa"
    "srR5EkVkYqwOQQcEGnlyFu/eJZFoUJb2/iLwbpl/EsYk1SRCGL3Q/D25x8cuw+uzNc94t8V3/ii8i1K9dZldzb2oiiEarGp4VVXg"
    "DJ+tdR4w0i1svANp4juoIk1a+ucW8SLxJGAd8jKQQp3YxjGea4GCOG+0y2jaXF3BvJB4wWbIP9B9azMmTIWKE7jfS4sBAzqPhOjt"
    "JbzTtNt7K7QhFXja2QpPaktWv1jbyrUl1I4f3z3+/tVb/qGsXMTW0rLGqKXd2OAV6U9pFit5fxkSiQpIqtngDcOv07VJcuAiXJGI"
    "YycmSvylxfWj6JpNtpZyt1cRJdXh7ksNyJ9FUg/Vj7CuecktXpn7VtHks/E0WoxxkWd/bxSRMWB5CBWBHbBHSvO1QDJ6mjhAAAIt"
    "hzDIgye8EsJ4JaiMWJUHGAMDArRkCtjGaJcND5x8hiUODyMY45HU1egBCWSdyBxj5pQwu7s7t16VtpX8zC9BTMUrmJ41AAkAByOe"
    "Dn7UM02oVbXcQKMrc/rTdvMI45Y2hjk8xdoZhynIOR88Y+hNbaMEEEVGKI7uaoAQYUmxuQaHkkVodKemhMSq56Z6e/FJlQTnGKsy"
    "8TIV7FxHGOaKkjIMdR7VmCT8VJVGcUIaOoQn3m97ORnjHSm7cklgVBHfjtSwXcelWNpHmYw42uVI5NN4FJaAyGllbIRvYKOM8GsV"
    "YS6A78EerGOvbHx0opjId06kChKDmhGw1kQgOtTaxjaQ4OR79qjIgVBxye9WU7Wp062W2llaVd3mo6gAEnjaR1GMdaT3FgEfJUfy"
    "pk8CvGtwasTuLPCycFcHg1KMBDlu/tRChB9xWOvA4zSvGtwnK4xGxjxKAGIPGeRn6VrbuOaEjMo5U4pqFQ4BH6UQb1AN5dzI4zkV"
    "13hLw3fa/q8draQiQL65NzABUB5Y5I4H1qjsrOSadUVeWIAycfzNes+IvFOmfs28MWOiadbQXeq3MG68lt1QNGrcgOxRiR9x8Vck"
    "YxZmX1GTI5GPCLYzz/8Aa74ls9Z8QxaXoN+tzpWmRLaxKiFUXH5mGeSSe/xXml6qqIZYZ/LmBwMcZAOR/P8ApT+s5bVDeQl5xI3m"
    "lieXU/8AfHFUYiScgPLs9R9Ldqxs7GytT0nR4VxY1AOhGCb0TefcSO7KoGUbBA+neux8K6jcw39stnbw3PkgyIxTl17of+yP7cXs"
    "uLVyhYtHwVfPT6Ve6XcRW4/EktFIDuVo26N349iM/er9OxDyOrxh8ZBFz2Hxlcf6n+yjw3rN0UNzJLJHFsO4pGM+gseeD06+x5ry"
    "STIJO44r0fxSn+l/sw8LaRKq/iJTLe5DflVjgDHbPXj2z3rziT1L9K0t1MLolCpS9rP1ggGJ45xzW8HaXyAAcdea2FJT05BqJjYY"
    "yODXcTVzRhoEUv6u44zRPLZcgdexpy1uYbexubd7OGZ5goWRwd0WDnK89+nPaliysrkghyfTt4HzU0BB2STIAcDdRI49zYArI4Sx"
    "p5Y1hwXAz/t7mrIlmz2kM9aEjqCJ+6VWzhBnPbiq4KMf8MH5NMvvkkbe3JNRZQDipyNzYtOQcRUqQKkpwckZrQrZ60oI1CK/8JOB"
    "1BxRoXCyhskEc80sBW+Bjng0ZHKm5UgEVLOWDarSqCTxhh7H3pOZFPKjk9hV5pGqXENlcWEbRvFcKAwdAcgHOM9R9qrriMJK42Mh"
    "zyrdq0cuEMgyqe8WTIQeBiEa84NW1/o0lrFHcRzw3EbxLKxjb8mTjaQe+aVjtd4JDqpz0PFFMMiAeYG9uR0pUYmAupYuL7xMRmiq"
    "gRgSAT7UdYtx46Uwto78sCfrVwntBtlA7mKhXnkZ5DuLnJPuaudB8Pz6tq1vYWo3TTttUc/25qw0fwrf6kPPUR2toODdXLeXFn2B"
    "/iPwoJoXifxTb+FrCLSPC88zSOx/Hagkpj/Ej/6lVTkR++TlvYdKplyDEvI7MAhbO3hYzPToNT8D+DdNn0u0gg1jXER2a+MQYIEH"
    "rZAcnAPpDHG49PcfPF5q9zq8upPe3NxPcXExkzLIXyfc+5xx8VmmeIpJdZvFvH8pL+IQFum1cg4+M4qluYpEu2cZQhcjH8XvWVlz"
    "c1DDezc0ej6D7s7cjZNbkkmu7Ro15ljQdD7e38qcC2OpkBTsmC8DpkDr/mtIwljDL0IpSSFQ+9D5bxnhhS5BUa2JoWGO9GT8iS33"
    "p1MZyQf4l9/tVvpdibnU4dLjyrzzogXbu256Ee4PtVYJ3u4fJcFbiP1Kf93GGH8s/rXpP7J9Jju/Er6ldRCSPSYBdnL7d6jlee2D"
    "tOfjHeiYVBYV2ivWZjhws57gfv6R/wDaXcR/6vZ2EcbRtZ2kULqH3LuCgHHyCME/HxXAJDJKepAq41K+bVdWub24BMlxK0jfUnNZ"
    "HbbVDBSQenHWt/Hg5nfaZGE+DiCesWSAiMb2LbeFB7DrxUxZyyzKip6+ymug06z/ANShlmeJILeAcuex/vWX13aJbtFZR4CEAyN+"
    "Z/8AFbR6TAmPkza+sW+9sX4KN/SUTWZVSzyKMcYAzzQljEThmYDHQdSaLNLM45yqtzxwD/mliWICnoKwczY78gjyFiPMYz+IZiWU"
    "Kg+BQZHZ3Zskk9z1rFBYYx9qds9OuruTZb28kze0alsUDzNLWq7iCqT161Y2+h6tdwie00u8uIj0eKB2U/cCrqx8K3+0317p94mn"
    "wORNLFbtIAAMtyOBgdcnvXG3Pi7XJbub8Lqc626uViCyFQFzxgA4A+KFkdcemk4+WckYiNRTbWYGPmtg/FbI+eDVBGrkcVvHFTjj"
    "aSRY0GWY4A96d1GwOnXZs5d4uIvTOjADY4JyoIJyOnNXAlS26iSM6DCnA+KfF2ssAjuNzSLwr+w+aRA5opjCqjB1bcM4HVfrR8eV"
    "0sA6lHVT3jYhdozKgLKvUjtTEDSH0OzMrDGDzStvJIisqsQrfmHY1e6Tpk1+JJkUR28IBlmkO2OMH3b57DqewNNIwG+0TymhuPaN"
    "o0Esct7qNylnpltgz3L/AMP/ACqOrMeyj+lQuf2maFokrxeHPDMDPjCXWqL57n2bZkIP0Nc7468Qw3d9DpGks66Lpw2gLnE8v8bs"
    "e+SMD4AritQme5kExOWAz8YrO6rrDsJ2EY6ToBlAyZx39PadLrfi3X/ELpLqWoyzttONxwsa+yqOB9hjpVIRGdkRDyELuy3b2A/r"
    "96jDGZIN0jFi3QCjsrookbjtz1pTmW2ZqBVx+VBUrZLcvMSYygI4H2p5CJraKXq0YEb/AD1wf5Vhbcwk69qFaNi7lgHSWIk/GOf7"
    "UDStr1hSS4+UKnoTaKe1KxkksE1HCRq4Bx7n/rzVY8oEW/36U+Lt57FJLo7beJQiL/uI6/3otqQUMCQwIYSqRZHuI0i5ccqR1HsK"
    "9o0mxHhn9mN9qLBra+1R0gtmAwxjAUyY/wCVgQCv1rhvAuhyatrsNyIkxvC2ySnCO4OSWPZVHJPwB3rsvFuqLq93b2tnIXsLGPyo"
    "iQQJDklpNvbJPTsABTPR4dc5kfaWfnlXAvYbP8fr/wBzk0Gxg2ASOxohnZpUwNoHYGoyKUOD1piC2ldsRxkvwRxmtZXYaEC3GuRn"
    "QW9zYnw6to1j/wC5eUsZkcjjGACOnc0hbLbQ3yebbpPsYPscnawHJBx70SBHtVPmldxJzz3pS59N04SUPgkb1yAafy9RyUWJmIls"
    "wB0ZHVvwc+oSzafA8Ns53LG3O3Pb6UiwJOW9THuaaKsEPUj2p/Q9Dvde1VNPs1RXZS7SSttSNByWY+wrKybNzQUrjTZ0IzYafZ2P"
    "hpvEd9afjArybYHJVGSNMkkgg8sVUfQ1VXnjzXddgSCGSw0SxUkQWkMLQgj5IxuPbJNWficsqL4Qs5fxSWVqzPcqpVXWRwwwDzkg"
    "kfSvOtcvGutZvJn2oA5VQvRQOBj9KUy5jipk/v8A5Hel6Zc3nyiz6fAemviPzmWmqXbXH+m3mo3v+ltMZri1hmKq7d+OmT9DXU3H"
    "izwPaGO3tvB9qFSNQwkLSNu75Yn1fXj6Vwq2r2gY3IMTfm2E9MjI/lSUiK7lyzZbnpWWMrILoEn33NZ+lx5TskAexI+k6vZn8oJr"
    "ezPSraK2RZvNU4GPympNao+5o4Ru9j0rX8M1MrxhcpwpB47VLLE5bk08YokmUupK/wASg4/nS0gTcChbJyWBHQ57VHGpcNcgAAeR"
    "mphd1RAoiipE4xqzgkmuI4o1Lu7BVUdST0FXXiRxN4qtPB2nSMul6ODcX0kRzvlVcySH5H5F9vuaN4LtGm8S21ybVrmGzJuZVHTC"
    "DcM/UgD5zVJoskz+GfGmoht9zO8ULkEH0szM3zyQKjL/AMU/vvFQ3nZvav1Y1f5TkNVRWnjRPTE7blRTwAaHcxIIXZQRhcDJ7US7"
    "BeGJgQSijoehHY/NQlHmQge+M1msAS03ASAu4G0S5dNiyNGnuKajaQsbecHeB6T2OB0rV5ejTwtoigybAzH2J5qdlLNqeoW9jbWx"
    "nnuHCRov5tx4xQAVU8b3CHkRyI1FwXjUqRlAx5+QKlY4ee6hWLMsicP3ABG4fcV1E/gLxSsd7K+nNstslwDkvgLyo/i/MOnyOoot"
    "n4E8QWE7anexRW0MCscPKN0vpbIUDOSMZOcdvcUUY35ChFT1eHiTzH6znZLMXt/FaxqqM0gjXYOOTilbhoJL+R5WItY3KRRr1Kg8"
    "f+fmuj0G287xtawA8LOz5I/2gt/aqvxDpCadrktrAhSPYjoCcnBQHr96tmQ/iAnYsy8/DJ3VzvPDolg8BrehVjfUJXt1UDiOGPY2"
    "F9ss2SepwKVNu4bdyRVmGNt4X0KwQf8ACtfNI+Xdm/ptrUJcSICuM9fmvR9NjAxKDPLZch8R39yZXraCeYELk10Jitbe3j8pdjqo"
    "VwGyWPv8UN4lMSJBbmNhku+78/tx2xQ5LC5nZI4kJL/wjqxo1BdmKO/ikC6lbdnzJAq42jkYoTxMzFiSSe5rvI/Bdlpz2n+v6qIV"
    "mw7rbpvCIRnPmHCH7E9a4jxj4g03R9fFnoumxz2G0FWmuA0ze5JQlefpxSuTMijke0b6UHM3h4+9XCWdlcXCTGKLckKGWWQkBI0H"
    "VmY8AfWmdQ1TUPD3hu9i0i0lub/U4fJM8C+bHHCxzwygjJ2k9emKhL4i8Pav4HvbKz1GXSrM4FxDPgTXU3OyMEZBX8p6enknrVNr"
    "3iTU5x+B8Pxs9ilutjBBHGXCqgCBwB/E4ySSOc/FJ5upsHidfvHMHTO7/wCVex7Ht6HZhJdQ07VNNV4ZjaX2pyyXUqxnmKJPQic5"
    "wPSxx815vcOblkRIxnoACSW+pNdvD4d1/ToLd08NwRwiNml/GjDDsQxyCPcKvxXP32k6pb3D6jPawopViFgZcA4OPSOV+mM1m5ld"
    "lAI7fCb3T5MSk8WG/iJTyGS7lkuJ3JZ2zkjk0pPIwkCocBRiirJIYmc4CjpmhtG7kGNWIAxkDqe9IsbGppIKO56cI8UdGLIU6kci"
    "pCB/LL44raK0ciuV4PvXqwCDPGlgRKW4yJG2rjJ4oKpvKoqncT1Jq9vJsWQsMQSKXE28J61JGNu4jOPjpVb+GJ5Rs/FBK7jaZLXc"
    "XltZbdwk0ZQkZAPcVuKIsRTHlSfxgnsCe1dn4P8AD3m+bruoxIulWKmSRpAD5hH8Kg8E57ngZ5ycA8QoNjtB5c3BOTSLlPC37Nri"
    "4eXytQ1oeWgOQVtx1IH/ADHC57jOOM1wHhq6eTTNe02NtqyxrMxPT09OPuf5U3488T3fiHW5by9KK6+lIoj6Il6Ki/QdT3Oa5vw2"
    "90t3dSQg7PIKyNnheMD684H3pHJlvKojfS9MR07Pk7tv+P0iyBhEwOdrMT9ae0W1/GzsZcLbWsZnnY9kXt9+g+tLXHlo+2Ml8cD5"
    "PxV1c6Nd2Xgl5iShmmV51A6jooPwCf1PxS9G9bqO5HFAE1yNCcfctJd3k11Jw0zlse2e1dv+zOw2+J21iaPdb6bbSXDEj+MqVQf/"
    "AJEVyKwscZFeteG7E6X4RazYFLjUXSecEcpGo/dr9TksfqtD6XB4mUEwX2l1PDpyg9dfl6/tNrqWoJIrrezKyElSHPGev60bTA1x"
    "qtrFITIHcR4JJ4Ybf6VjWnqAVGx/uPemdPs5Y9VtJEXgSoef/wCQr0dHYnliycdanF+GkA8dIB/smx9TE3+aY8XwD/VdMcdZbRQf"
    "qrMv9AKJo6qn7SBDbr5g/EP6v+Xac/yo/jlRFeaYgx5gtTwDyMyNWZxBxH5zYL//AFp8V/mdRe6cN1upyBHawL+kS0okiWt5BMVi"
    "vFXDGNi2On5T0PHxV7dwzSMqSAo/kxqw9jsUVXQ6RMZ8bfTzhvc1tLpRXtPNLlBvmZC3kmckNgbuR8VK5t7iLw/q01s5N1JAbSHc"
    "fymXKs3/AOG/9aNcajY+G5orrVtOkvbcb/3SvsVyuBgt9SOB/KuJl/aHda1d3cMsdpYRS5EXloESIKvpzgZP5nOeSeBSmfqE5eE/"
    "rH+j6XNk/wA+IaG/nucK63LaXJcSTyHbIsL5YnI5wPnp+gpmXXdsEFna6dZ2kQOXEcQcyc9SX3HP3x8UxY6dqms2suk6Jp11qkiy"
    "s4/CwtIT0AJx04B/Wkb/AEbVLDXY9J1DTp7G9ZlURToUb1HAODXnWNDRnuBxJozvLiO61vwtI1touj+H/D6ttS7ulUyH/cEYje5J"
    "xnA4IxkdKur3VLXwxax6d4baGxsBCvmXV3cATXjgckqhZ1wTwvQe1cn46u9MfxBHpunRiO3sPKtg5PDiNcMwHyRn71w81w6lfMJJ"
    "Yljz70Uv4TG+8y8fS/elVn/Cd8f53s/P9LnQal4ku59VMrNNEwBUx+cXU8YyM81Rz6jLFerPbO8Y3BiCcnI681BVVmDk4CnP8qDI"
    "8X4tHePdH1K5xml3diLJ9ZqYsSL5VHpDrp9/fyu9rA7wu+7eRwueeTVsNF08DF3qxEvwQg+wPNSttZgstJhs9PwsxBaRpG4LE8Y9"
    "gAAMfU1UTSSyTNJcSoZWOWzk1asai+5Pf2kXkYkdhPXhCMYwcA9K2yZJGBtx0qE+qWVvnfKJH/2pzSsGswys3mwtGM4BHqH3r1hK"
    "jU8UqOfNUFJYtIS6kHHY0sY9pGEywPI96vTFHPGHRgVPRlNANou4AmhlPaGXNWjFYQ8swhEWNzYVDyRk8DNXf7QdXh8PaDZ+FrO4"
    "yIohc3KA/wDGcjKFj/tGfSvtyfzUrBaObuHdkoXVSSe2aovEPh3XvGHj7Wb2ONYLFrx0/ETHbGqoxXj3AwRge2KS6l3UAKNwvTpi"
    "yZQ+Q0q7/P0nnwjutRu47a3RpZXIUAdWP/nNdnfWsPhnQf8ASAyvfyETXhH/AMagt5cf1Jw30A966rTdBsPDmmtLZ5mvot8rXRGM"
    "enChR2xzz3J+BXDaPp8ut6uLF3kaNWMtxK5y0hz6mJ+TwPgUiMDYyCfxNNQ9UmeyDSJ+/wDqPeE/DTXcg1TUFKxf/Ch6v8/Aqy8c"
    "6rBFbR6DbsGkVhJdbeiED0R/XqSO3HzXbQWZkja3tSYJFQrGw42HHBH0ry7wvpBv/GVtYXybhCzyzI/O8oCxB98kYprNjOFBiT/l"
    "3MzsGdepyN1OU6TYHt8ZbeH/AA9DZRxanqkQmuWAeG2celB2Zx3PcL09/auqt0klaS5lLuM5ZsZyT7n9asn0/wA+cvL63Y5NKrrP"
    "hS2v30y+1qG1eJNxYAupP+3cON31IptMePp12amZk6jL1TEqCx+HoI67Q3NrD5MRjkXg8/mo9rbyxsrBSNp4Psas9K/9PXnh6TXr"
    "HVomsoFdpXuF8ooFGTjOQ3HQA5PtXGXP7XdNWxEOiadZefNFIzTagGZo2BAUKAQo67jkHpirP1WJB3uK4uj6rOxREqu9+kT/AAkX"
    "h79pqSwwhbRCszgEAJGyjf19smmfH9hbyaFFqFrNBdPaThGkgdXPlsDycc4yBj6153r/AIpu9dvZ7i5ng/EELHmCLbHtC4OMsef5"
    "UpaalcRAyTanNDCQFCpGH3gc9Dxjk9fespuqHFkUaM9Qn2dk548+RvMoo/H+7nr2n+LvD15YWAvtUaG/FuI5R5JZSyDaOfcqB79K"
    "d1zxbZeGYLe4SzXUGjb1MoYREkZXLjr1Bx7dxmvJrTxAjXYS9lt9RDACE3FqEaJhyuWQbiM/w554p/V/FXj3Ur+4sNQmv9QjjYPP"
    "aMjhCud20pjKr8Vf79k4VfwirfYmE5Q1a7kXX/X8S7uNUi1K/ttX/aFbzNoEZK21hC4ieRjwrbRhgmd7E8E9BVFLKPEt9Pp63ENl"
    "4WsZRJPOkaRJGmSTsHdjyFXnP604fCmu6to4vde1y10hriT8QLWcMzshON/AwoAzhc5PwDmjwvovh/SINIjtE11CxeWdYyASfZCO"
    "cdNxOeoGKEMZyG30D6n1jiumIccGyNUOw+Ptfxvf7Su0H9oeuafZJpGhaVakRytJbARfvIgeOq4LHH8R5+arXk1ZvEUmpeJElea3"
    "jMkak5/eE5UcfOTTEviODTZ5Z7JbNl/LBsQJJtz6g2FBGPY9aprS7n1O5jNwWdrq7QMWPBAxgf8A9jQjSlU5Wf2jioSWyBOIPr6y"
    "2V4ZPCckV0zee8LTXEgPLyO2UBz8Y/8AyrkopUnDB0G5R1xTc99LJLebufNmL4HQdcAfy/ShSLbwyW8cCncIj5rHuxP9qHkbmRXY"
    "a+cbxrwB+O/l/e0SEhEaqG5bqT2oe0yXAXmQn2HWtON5JHUtirVJ7ayXFtFuPQySdT78ClFXl3Oo2zcew3BpYQpYs9xKyvnARBzn"
    "5NVsitG+3dn2Ip95gYQS2cEkfJpHDOSx96jJx0FEjGW2TPQxH3PGOtKWkn4iN5OSBIwwfrVhqDi3s3kKvg9SvVfn4qn0FofLMZuA"
    "XdztjIO4/P8A4r0zmsqpPO4xyws86W0nuI900BCg8SIeVz71dW+oW0u1J/3EvcHofoaobd0ZdwyUcYyDTBQ+asgIITkE9MU+uxMz"
    "JjDGj3nWQ28kbhscf1qznuo77UCuBHuOVjX8q++Pvk/eqHSDpIlSRvF2n2+84EIEkuTjOCAMD6kireX8GPEsVl+KjS2mVfL1Avtj"
    "Dt/A4PMfwT6fmqF8anZmZkwZCTo6+H9v8pmr24ttAv5gvSFv6VzH7N7NZNO1G92bmadY846ALn//AFVn4t17SrXSLrw8l8Jr4gby"
    "ill2EHJ3dK43wt40/wDTMjW0Nm89tcSb2QqSzEcZHHcUllz4xnVr0I70/SdS/RZFVfMx1etCezPpjXCxvB+7dfYda848S2s3g79p"
    "lnq8kDrBPiZxtxlT6ZB/M/rVX4m8fa/qeq/iNHhv9HtwoEUaTMu7Bzubpk5+wrk28QapFeNcajd334nZ6fNlZt2e+Cf0oGfqlfVa"
    "94f7O+yM2LzZGBsEFfn8Z6f4k/aBo2lz/hdH8rUXkiJW5ik9CMenbnHU8j2ryG6tL1h5r2rBeSGJGQOuT3+aDcajPcMtxOBtJJUk"
    "ZZiPc1vzrmG1Kmd3aQEBdx4z7frSWXP4xPLtN/o+hTo0C4+573u5caX4nvrC0uBb/hobJuIo5rZJXOP9pYZBPc/NV2o6pBdwTpp2"
    "nJaGd/OuCpJHU4UZzheenvSs0NraxBpT50mMIM+kCkzOWiaKKNU3nnb36YFKs5UcTNBca3yWMW0kcVsjLChcjlpDn9BTltp17rup"
    "Q21okagjBkzsjQe7HoK6LTPDmm23h24XxBaPDqUhDQKZSGVMddoH14J549qOb6eCwg0qzgOmW5Bla4kHplYgb8dMjocfFMphYqFf"
    "t7ev+oi/VWT4Q3fc9vmPedjYweFIM28Ph2ymn06LAvYpWj2vtOXZ2IDHOTyP6Vyt3rmuaK6SW9xFJHNPvYwyrJJcORxuAOWHTjOM"
    "cVSyrqFsUtrXVUeOSXe3mLhnb6Z6fpS19Jq+iXYvVvQ07JjaHG5O2WAPB9u9NZGxhdqQR3qq/wBxLp+lIYkvyB9Df/fb9JvVJPEa"
    "/wD6nrMc3lvKS/nYQyse+M5J5yeOKrLWPU7mOWWytmcMw/8AjDbAPk9KGby61ANLeXJldFAG84CgHNSF2fwqRxs6qxbcNxweeKRJ"
    "RmsE1+81wGVeNC/gNReQ28Nu4RjJcHl3AG0Z7CnoZDFbWligUuR5uTxh2HHP0x+lU7RgDcOeMmi28zfiUY9VUqCfpil1yU3aodks"
    "SyvGt4jD+HTEUaqflj1JP3paOC5vmupLSIyEAyH4WphUmXypJ1jz1z3rqLHX4LTS4bZUzBGD5AdA7E56/HfAoxId9mhFmZ8a2i2Z"
    "y1rpN/HKZJrVovKw+JVwD8c0aRLSfbG0fkSt2UZ5+Kc1g3EvmyOwK4yFA24+cD3qmijaSMM0u1V555oRpTxUXCqWccmNfKFmhCEC"
    "HyyqjAxyc/OehpYbSMnj6UfCIxdSCG4OO1DZSGICkfSqkDvLidTql4kzyQSWLrcIcIyyYyPc0npkqxW8yuZllbdtKkbD75J6fbrQ"
    "LxFEzFZknUk42E4X9alZwyz7reOQjf1TdtUgdyTxxWozsct+sz1RVx8fSdP4fIk0qPDBmTORuyR9famdXv4rPS5JrO+hjuw3lvCG"
    "JkRSDk4xj+dJ6TrOnaJHB+KsE1BfUGiW4Iye2CvSuav5nu75kihJmuHLFFO45J4X7Dim8nUcMIQd6iKdOXzl20LuKQTy28iiF5Ul"
    "c8eXnJPYY71dwX2p6ZIL/ULOee6j9VvvfEUZ9yF798HA96rEiudP1VJ76GS3EYbYSOcgdvnmlZxFKdy3Qy4xjH5RWYCVXvv2mrSu"
    "fgY5eazdzk3czWovJ/WWWIh8k9cnqa0upTqJGDnOzDP0LfekmkE18ZHYEKoSMKOwobxyLKYNp2t6j9PmqHIw2DL8F7VL3RdUGjl7"
    "uUC6uQm0eZJkKP8AlGOvJ71T6jf3GoF5J38wrISru25sH+EfA/vS8ki7yqLnkc5PT4qxsNGN/BNdz3UVlaxjAdwW3Nx6Qo575z0o"
    "Zd3Hhr2kBMeNjmbuYmkjRpsjjMjkCNWAzyew+aPc6TqunrG+p2txY5AMQmiK7+MjGftV4PFOsaZFDZ6TdQwW0Z2wogUjI/iO7+I+"
    "9Lt4k1NFZtQuW1BnO8xXiiRFfP5sE4OO3XrVyq9iTr9PruVD5ibCivnv6UJzLlcHcxdz+gqz0BLNNTa9vAzQWcZn2KcF2HCDPb1E"
    "UZLuyv783N7axo0nG+KLCggdSi4yT8VF797iyt7CPJh3l5NoJIG7A+cAAce5NDVAPPdwrsWXhVTpby58M3Wlpq1/Dd/jLwYEC3Dl"
    "UG4gtnqTkE+1UGqQW11PEbfV5r+4mZUijkUsTk469vpiq+4MX4hlgLGBXYRhjnC54ocIxeM4PKRkjnGD0/vRny89FR/fWAw4PD2G"
    "P5/SNz6LfxM63VxGkkZwIw28kjjt0pSe2khgxLcq8meYl52/U9KlEz/io8H1ck/pUWAz06jFD4qQSB+8YBYVZ/aZt6SDHpGPtSy5"
    "jDbjkhSRz0ozOQGXPpKjFAkXY5UNmhOfUQq+xhY0H4Xk/mBNBhUmdQgLE8ADufais+Ywo44x/KmNJiZtSiYDhDnPse1RXIgCdZVS"
    "TL2107QoY2/1Qvd3cygqkUhTyfjp6if0FLXK6L/wo0ugEOAA/QY9sUisM13qBcHOxSWdjgAfWor5llLIxKiY+kc5C+9NchVBRXvU"
    "U4G7LG/nNSoGwLWSQqMHMj43e2AaW2ELlcgnqOgNHkuJppRLI58zsfYe1Gd4XmDqu0gd+hNC4KdiG5EaMV8tlVSwxnpWHJPWmn2s"
    "nOM+47UrxUMtSAbloVLsFDZBOQSMVJyPL8uFVUYy0mTkj6GlA0kbxnfuQDAPxRoGS689U6K/HHPSmuQJr1i/Ejcgy20SeYPNLken"
    "IAo9nepbfvVt2SRcndvOWOP+tBaIFSpGW7fFYI1WFnfEjHgA5/Wo8wNiSeJFGGn1WVnKGOKZCMqrLnYfikDMHZnEEYIG0YXAA/zU"
    "lVguBxg5z3rflNI6rGpZm4wOSxobM7dzLqEXsJGKSKBuQGYHgj6U3bWdzfLdPDMiQoFEk0h2qM9BxkknngUxGJ9Ls2mexjE7Nw8o"
    "5UewFAubyWeFYUI3yEySLGMAnHsOvH96LwCjzH8pTkWPl/WCk0eW2VJ3mgmtyTueGUHGOoweQftTWoS6Tei1tdJtpLVASzec29uQ"
    "M5bjOMewrWpWOoW9rDd3qxmGQEKsb58s/wC0gdDznFIvebkZViAQgDG3qBQ2CoSKr595KkuA138u3+4awsJ9VvzbW80SGJSWmnO1"
    "EA7nrV3a6LpNpO7XV0t5nC+cIv3AyR0BIJY9umKSR207SEhePm4ffIucHIHpXHt70rcanfm6jUsvnqcKegX/ALzVxwQecWYJvFyH"
    "yNQ/v9/mdXqz+HnCxQxwWkkx27YwuRj7bQfcg0rcas+kWn4fRdOFoDwWjX1OB3LdT9CaomhuY2kuvxavNMhVwF/oe3TrQEQ3SbUv"
    "ZY44gMmZgfV7Y9vmjtka6C0fygF6ZaHJuQHvcsG8QRTXSrqdnDKvl4ffECw+Ae31Fc9KYV1CVYgRbSPlcnnbnjmpTsXulMknmMp2"
    "7vce9RuI/wB3H8HBpF3Zu+6mjjxpj/Dq5jFFklYE+lcL85P+K1K5wgTgk9aIqbx6vUOgNCkGEVfvVTdXCCrqal9LIOq96hHG0jbY"
    "1LMegAzWOxc5ParS2u7iC2jt7dVh43O4HqbPz9MVQAM25LEqNQzaA8SE3N1FE7LlVGWxxnnHSteW1naOibXLHcWXkAYx1/WiwW1j"
    "BBHe30zzksxFsGwGA6kn59vikbi8MkvmQxCDtsQ+nH0o5AXYFRdWZjRNiEEhjt1VG2MTuJH8qWOZXwcEnklqMDuUE9cc/WoxR5kZ"
    "mxz84qSOVCWurg/wrs3oO5eppvyUAJxnFZH6Az5OAO1Cs7jzZJkZt3qypA4Iq4CqQPeVtmBPtMWB2ySOta/DnuKsFUk0YRjHSijC"
    "IM5DKh2wpYJlgM4HehadPIjMRnaz5ORjH1NbuCmTCxMbdVYjr9KWtHt0mLTB5H3+jnAH1pFmIcbjar5DOiQR3B9J2vzxWmtsEgc0"
    "u0kCNkTDI9qHJqkgUpCoH/M3Wny6AeaIhGP4Yy1tgnjA+ayBjCTLCRuwQGHPXiqeWWab/iSsw9iacs5mSHZGi9fVn+RoS5AW0KhD"
    "jPHZj6wfjJvNmZoYEH5uvPaiSTrEpS0t44c8bsDJPc5NEEyXMJSLKbOGQnkfWhlAAEwdh/MPema9R+sW9aP6QDTtJGquBcyjgM2S"
    "f8Cj2iR+qbUG2f8A1gNxx3PvQ0tpvOVV2J2ySBit33nkbPJCxAbR3yPf61AsDkRLEgniIrdQzrOpnbc0nKsWByKQbJleR23c9T3p"
    "swv5e/rx9xUBbBsM7BVxnjqaUZCToRlWobiods/uw2e/cViO5crnCuQTjvVgXYQFIwFTtgdaSET7+FqGQiqMuHuauoShjfBB6HI6"
    "YqTnfb59qLOTIpyeetYkYMZXb1XP86kps1I5aFwEaDy9wJDj9MVCQZbPxTBTYenBosFqbmQjcERVLu2PygVBQnyzuYGzE4I0/FR7"
    "xuUMCwx270/EEed5ZicE5Kr1x2Ap2W6ZIjHp8YijUbTtA9Xyfc/5quViBnHqJyWJ61cIE13lOZce0ntSe7wVby1wFXPQf+aBJFuk"
    "aRI9q56DtR4w3JHc801CpQMSKuEDakFuMAtsyKPM4J5x3qKxB3KgHrT5yxBOM+9TSNIgZH9K9yaP4Y9O0FzMrblW/Cv5AZmQ4IT8"
    "wNV1iZBeOJkkeUMSExgZ7kntTupgrMbqwnZGx68H0n5qmjljSXE+ZVD7iBzn+eOazszVkF/6j+FbQ/0zrolWSNXUgg9x0paS+jVt"
    "qjOOD+tJJfTz7iF8uLbtUZ7UPbk5Ap3xrA4xTwqPmit6szNhpY/LHIBOCaUiMgJaEk8/lHXHvR7uO13sySHeT0xwaXhLbzsm8o9P"
    "rWTk/HNFPwR+ONlTLg7z1Oc1vbU4oZVBaZtz9M54xUymacC67RUtvvAnaqFj2qUEzRESLghhg5HahXRMcBwCc9xU4MmEZRlAAxnv"
    "VAaehLV5bMeUlV86Essq9RnPH9xT0Op28mzzV8ts4PcfWqqKVkkG7lcYxWnCyHcow3tTQcjaxcoG006YpufcuNo7jvQGIWU5ySPY"
    "4qm/EXNqnlxuQjEMM89Ksre+iucKy7JNpLe3FMjKDrsYscRXfcTJAHztCpnihPbOYg+c47Zp8QAqrjowBB9600BwcdasUvZlQ9al"
    "ZsGAMdqgF9ZFPtbsCGx0oJh2tkdKGUhA8UdCMHA9qyNSGp3yM+rBqXkqvqIwKjwzdyfE9Ii0ZOBin95jsPwcZzvPqHv35/77ViKr"
    "N6WBNEjhG/J4q6p7esqzD1ibx+XCFUkjvUI41POM05NC8rAgEfFTjtSpxjmu8PehO8QVARRY6DFHCDKqeCxwPmhwSAve7jxAcj6Y"
    "/wA1Xz6g8hRosqyOWBP0A/zXFlUXJCMxlv5aIu52AHtVdcX29DvT9wchk65HTmkjcTuFDOTtGB+ua3GBKpZWznPQ0M5uWlhFxcdt"
    "K2eK1VHaK8yCc+WvHHtQklhjLxGMtEzggt1GK21tMbrZIjEk8DoTUEkjjkfMIY543dvjFYzHd1U1QNd7ljHc2qxhIQevCAc02Xij"
    "wrna2M4qvtri23bha+vovP8Aeg3c3mXLNkfY00MvFbuLnFyaqgi0YySisx6+woYJVi5XvwemDWgCWwOtFSZo1YBVbd/uGaRBvvGo"
    "3bz3si+na4ztOR+X5qwI2L6j0GSar7e9kZ1RLdd3RnA5Ip5pE/FOGZguzqvOK0MRBXvcSyA32qV108LJujnOSc7PY/2olqZTEMBn"
    "H+5jwPpS1xIDM+JfMUjhgoGfrUolttql7ll7lOvNLhvPcYK+SpYEc1rHcdanAfOjLBCi9Fz3qZTHJpyrFiJk0akUMkgaMerAziob"
    "SDxkH4oMMrfjZCp6YHHP/inWYPyww3vXIQ4nMCpmJeXUcccYkykbBlB7YpuDVJPMjEwGzfuYj2xilPL4z1rRjI7UYF17GCIVu4l1"
    "FqFvO23Yy9amZbfAZQzg/FUaqVII4NNxXLxRCPaCAODTC5ifxQDYh/xjskrnhFCL/OljGWHJJ+tFS6jZVBXngE/1ppYlc4QhvpRQ"
    "A/YwZ8sREJFNQPInBAcexrTOiy2yrz5rspA+M/3pDUNQEUskMR9SOvI9h1qpZcYu5cIzmpbx6nbGeeN0wYkDYxnsc/2pG+1dSqi3"
    "UcqjHB6HOSKo5LqVrmaVGKiXIIPPHtQg2OKVfq2I4iHXplB5RkTy7pznmb8365oYXBrSypuYEcjms35wcc0DkDD0YQFQMt3NCksw"
    "7PJbT7JO4B4oM7FYx7A1uaASkyxFt2NxK44+KEzctVCKK3dQDfjBCbgyuBnZndyaBG64dHAO8jLHqK2iyyyBWJOP9x6VEqiyMrZI"
    "HFJEk7jYFajMFrG8JZ50HGQCfy0oduTg1JVVnxv2A+9YSASFJxXGiBQnAGzuRAqQ2g+ocfFarAcVWWj9pMts5PlM2R6W7/4rbXDR"
    "FplxG5GBgZH0pON3U4TvRJGYQANg574o65CFoQBQctwLtIWLu3qYc/Ipi2WzdAJptjZ/29PvSnFHhWBx+8YhsjCjjI+tDXv/ADCs"
    "NS9h8sRRojlwTtDHvxULmVIW2SRuyMOWC5A+tKRyoJbURSFguMqTnb8U5fTXMPpjiDxsMcnB+2K0w9oT7fnM8pTge8qU8tbg5jea"
    "McggYI+1Wsf7yMOUKZ6A9apY3nSXzI/Sw429/wBO9Xtq0kq5kVs+5XaPt70DpiCaheoBAua5Ue1FjIf0t1pa/fyhEN2CXB6U0qhi"
    "CMgnkZp1T5ivtFGHlDe8l5WelSMWFye3NRe48qIqMFtpIP3oE16W3LGMAn+WMVdmQSiqxjBCKAxPBBYfSgPeSWl+GQkhVwQD17ik"
    "2eRlVSThRgVHbxknpS7ZSfw6hhjA7yLSzPt3OfQTtx2ycmonklick8k1LioTHbAx+KXb3MONmhNgZAI71vbzWWx3wjHQDFSmJiUM"
    "NuM4wxxmuA8tzjfLjF4jm7cEcEdqcCgDNVysqzM28ICO3q/SrGXItPM2kZxwariOjLZRsRa7UlCRFkdnzitfipbaNY5FVlI7EdPt"
    "QXWPyvzSbj2A9I/Ws2wKrq5GR7jmhliDY1CBRVGAeTcoAULjrjvUB15qbbUyu3n3JzQ6WPxjAmdT0rea0OTjOKmVUHGQa6dIit81"
    "oVLvUCdNoTvU8CpzOzNhhjHahjI6fSs71a9VK0LuaxWcdwT9KlUaiTGINgI2Bs++P70e5mYqAs+w9dmO/uPalVd9w5UDsPatyxuh"
    "Ds+4nvRgxC0IMqOVmQjaQSZiJL9jVxaXF1I8X4jCKp/O2ctmqQFl5UkH4pqGeUlczklOgzU4X4nvIyryEa1KRWucBn3BvylcY+hp"
    "iOSTYrZbOP4jk1X3EplKsXySeRtxj/NM2yFFLO6gEY/NTKuTkJHrAMvkAhsEjBOcVrCgc1Meouo6qcVCb93Ezd6KdC4AbNSIbnp3"
    "rRUnJNFCD0/83SoXX7u2b3PFQRqzLDZqZ5dLXJjIA3cjOR3FWEOHgVz125IqvupVcnZIeRyjL0+9UygBL95fHfL5TLSRFX1yEY4A"
    "PT7e9NXHnKn7uMSL3XHIpK13+avqkwvZRnr/AE+tTvpd12xXGF4yD/3mhq1Y9whW3iu50uCzL6uu0j+1MtNviKlmZs5yRtC/GKUJ"
    "LNuIGaJuIUmTLE0BWq4ZhdTUs0nkGPzsr1xjrUI/yHEm33FQdlMe0MTzwMcVAYx80Itu4QLqSbbnC5P1qNbJG3gc1rNUJkzK3jNa"
    "HWpjbjkE1I3OkazNa71qqyZPqM1vNQBOK2Dwam5UiSrDWA8Vo1acJJAC3P8AStyD1fn3dqh3rPepvVTvW5lSXqOmfeo1sZJAAqJ0"
    "MxBA9PPvnrTVksQkLSMowM+r+1J7ssV71JW2yAUdXAYNAspIqWVkd00gJzuOcVHUGwAgOMdRihW8hjnVskgckCt3b+bKeoAPAzxT"
    "XIeHUBx/yXJtOu2AggbT9a1qBJZQD6SOxpUg5z3okrGUqzckDGT1qhe1IMuFAIIhbacKyK5IUKQT0xQbhnY5eVXwcAjv80J+FrWf"
    "T80Mua4mWCi7kN5SQAZ5qbiIAbd2T/upZs7ic/epbyWXNLc4fjCAVpn2DAPPcVvNDkbJwQRViaGpA2dyBx2GKys7dKygwk3jHfmt"
    "VmKyunTK3uNarM106plZWVldOmYrKysrp0wcVvNZWVIkTdZ3rKypudMrdZWV06aHDA1Ik7iRWVlcO0rCwvj8zYx0pgHcAc5z71lZ"
    "TGNidQTj1gy/73aPepZyuRWVlSpJkMIFgQ2KEzkMwx2rKygvqEXcGSTn5rDxzWVlChZgJHPtWEg9CSe5NZWV06ZWu9ZWV06bzWqy"
    "srpM3Wqysrp0/9k="
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
.art svg,.art img{width:100%;height:100%;display:block;object-fit:cover;object-position:center bottom}
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
<button class="dlbtn" data-a="dl"><svg width="30" height="30" viewBox="0 0 24 24" fill="currentColor"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg><span data-i="Download">Download</span></button></div></header>
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
'Enter a valid link':'أدخل رابطاً صحيحاً','Saved':'تم الحفظ','Link(s) copied':'تم نسخ الرابط','Download complete':'اكتمل التحميل','Drop links or files here to download':'أفلت الروابط أو الملفات هنا للتحميل','No links found in the dropped item':'لا توجد روابط في العنصر الذي أفلتّه',
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
function toolsMenu(el){menuAt(el,[['Add URL / batch',()=>addDlg(),'link'],['Video Downloader…',()=>videoDlg(),'video'],'-',['Queues',queuesDlg,'copy'],['Scheduler',()=>schedDlg(),'cal'],['Grabber…',()=>grabDlg(),'cloud'],'-',['Import list…',importList,'tray'],['Export list…',()=>exportList(sel()),'share'],['Delete completed',()=>api('delcompleted').then(poll),'trash'],'-',[S.limit?'Limiter: On ('+S.limit+' KB/s)':'Limiter: Off',toggleLim,'bolt'],['Quick start',()=>toast(M('QS'),14000),'info']])}
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
st.sel.forEach(i=>{if(!S.tasks.some(t=>t.id==i))st.sel.delete(i)});render();
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

$('#thm').onclick=null;applyTheme(theme);applyLang(lang);poll();setInterval(poll,700);

</script></body></html>
'''


if __name__ == "__main__":
    main()

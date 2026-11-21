import http.server, socketserver, threading, time, os, hashlib, re, random

class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()
    def reset(self):
        self.conns = 0; self.requests = 0; self.bytes_sent = 0
        self.per_conn_bps = 0       # throttle per connection (0 = unlimited)
        self.total_bps = 0          # shared cap for whole server
        self.kill_every = 0         # kill the connection after N bytes of a response (failure injection)
        self.kill_count = 0
        self.max_conc = 0; self.conc = 0
        self.block_over = 0         # answer 429 when concurrent connections exceed this
        self.n429 = 0
        self.range_ok = True
        self.gate_t = time.time()
ST = State()
DATA = {}

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def setup(self):
        super().setup()
        with ST.lock: ST.conns += 1; ST.conc += 1; ST.max_conc = max(ST.max_conc, ST.conc)
        self.my_over = False
    def finish(self):
        with ST.lock: ST.conc -= 1
        try: super().finish()
        except Exception: pass
    def do_GET(self):
        with ST.lock: ST.requests += 1
        data = DATA.get(self.path.split('?')[0])
        if data is None:
            self.send_response(404); self.send_header("Content-Length","0"); self.end_headers(); return
        if ST.block_over and ST.conc > ST.block_over:
            with ST.lock: ST.n429 += 1
            self.send_response(429); self.send_header("Retry-After","1"); self.send_header("Content-Length","0"); self.end_headers(); return
        size = len(data); rng = self.headers.get("Range")
        m = re.match(r"bytes=(\d+)-(\d*)", rng or "") if ST.range_ok else None
        if m:
            a = int(m.group(1)); b = int(m.group(2)) if m.group(2) else size-1
            b = min(b, size-1)
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {a}-{b}/{size}")
        else:
            a, b = 0, size-1
            self.send_response(200)
        n = b - a + 1
        self.send_header("Content-Length", str(n)); self.send_header("Accept-Ranges", "bytes" if ST.range_ok else "none")
        self.send_header("Content-Type", "application/octet-stream"); self.end_headers()
        sent = 0; step = 32768; t0 = time.time()
        try:
            while sent < n:
                if ST.kill_every and sent > 0 and sent >= ST.kill_every and random.random() < 0.5:
                    with ST.lock: ST.kill_count += 1
                    self.close_connection = True
                    self.connection.close(); return
                k = min(step, n - sent)
                self.wfile.write(data[a+sent:a+sent+k]); sent += k
                with ST.lock: ST.bytes_sent += k
                if ST.per_conn_bps:
                    ahead = sent / ST.per_conn_bps - (time.time() - t0)
                    if ahead > 0: time.sleep(ahead)
                if ST.total_bps:
                    with ST.lock:
                        ST.gate_t = max(ST.gate_t, time.time()) + k / ST.total_bps
                        wait = ST.gate_t - time.time()
                    if wait > 0.05: time.sleep(wait - 0.05)
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 128

def start(port=0):
    srv = S(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

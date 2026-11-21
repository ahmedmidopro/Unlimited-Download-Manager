import os, sys, time, tempfile, hashlib, importlib.util, threading, json, random
HOME = tempfile.mkdtemp(prefix="udmhome_"); os.environ["HOME"] = HOME; os.environ["USERPROFILE"] = HOME
spec = importlib.util.spec_from_file_location("udm", os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","udm.py"))
udm = importlib.util.module_from_spec(spec); spec.loader.exec_module(udm)
udm.APP_DIR = os.path.join(HOME, ".udm"); udm.CFG_FILE = os.path.join(udm.APP_DIR, "config.json"); udm.STATE_FILE = os.path.join(udm.APP_DIR, "state.json")
udm.load_cfg()
import testsrv
srv = testsrv.start(); PORT = srv.server_address[1]
MB = 1 << 20
def mkdata(name, mb):
    d = os.urandom(mb * MB); testsrv.DATA["/" + name] = d; return hashlib.sha256(d).hexdigest()

def run(name, folder, nconn=None, wait=120, pause_at=None):
    t = udm.Task(f"http://127.0.0.1:{PORT}/{name}", folder, nconn)
    t.category = "Uncategorized"; t.auto_cat = False; t.auto_folder = False
    t.start(); t0 = time.time(); peak = 0; seen = set()
    while t.status in ("Downloading", "Pausing") and time.time() - t0 < wait:
        time.sleep(0.25); peak = max(peak, t.nworkers); seen.add(t.nworkers)
        if pause_at and t.downloaded >= pause_at: t.pause(); pause_at = None
    t.join(10)
    return t, time.time() - t0, peak

def check(t, h):
    if t.status != "Completed": return False, t.status + " " + t.error
    got = udm.file_hash(t.final_path, "sha256")
    return got == h, "hash ok" if got == h else "HASH MISMATCH"

results = []
def report(name, ok, info): print(("PASS " if ok else "FAIL ") + name + " - " + info); results.append(ok)

tmp = tempfile.mkdtemp(prefix="udmdl_")

# 1. correctness, unlimited server, auto mode
h = mkdata("a.bin", 64); testsrv.ST.reset()
t, el, peak = run("a.bin", tmp)
ok, info = check(t, h); report("1 correctness (64MB, auto)", ok, f"{info}, {el:.1f}s, peak conns {peak}, server conns {testsrv.ST.conns}, requests {testsrv.ST.requests}")

# 2. keep-alive: connections reused (requests >> connections)
report("2 keep-alive reuse", testsrv.ST.requests >= testsrv.ST.conns, f"requests={testsrv.ST.requests} connections={testsrv.ST.conns}")

# 3. adaptive: per-connection 3MB/s, total 60MB/s -> should climb to many connections and beat 1 conn
h = mkdata("b.bin", 120); testsrv.ST.reset(); testsrv.ST.per_conn_bps = 3 * MB; testsrv.ST.total_bps = 60 * MB
udm.CFG["speed_mode"] = "auto"; udm.CFG["connections"] = 16
t, el, peak = run("b.bin", tmp, nconn=16)
ok, info = check(t, h); sp = 120 / el
report("3 adaptive ramps up (per-conn throttled)", ok and peak >= 6 and sp > 18, f"{info}, {el:.1f}s = {sp:.1f} MB/s, peak conns {peak} (1 conn would be 3 MB/s)")

# 4. adaptive: saturated at 2 conns (total cap 10MB/s) -> should NOT keep opening connections
h = mkdata("c.bin", 60); testsrv.ST.reset(); testsrv.ST.per_conn_bps = 8 * MB; testsrv.ST.total_bps = 10 * MB
t, el, peak = run("c.bin", tmp, nconn=16)
ok, info = check(t, h)
report("4 adaptive stops when line is full", ok and testsrv.ST.max_conc <= 9, f"{info}, {el:.1f}s, server max concurrent={testsrv.ST.max_conc}, peak workers {peak}")

# 5. failures injected: connections killed mid-response -> still byte-perfect, retries only failed parts
h = mkdata("d.bin", 48); testsrv.ST.reset(); testsrv.ST.kill_every = 2 * MB
udm.CFG["retries"] = 20
t, el, peak = run("d.bin", tmp)
ok, info = check(t, h)
report("5 survives dropped connections", ok, f"{info}, kills={testsrv.ST.kill_count}, bytes sent {testsrv.ST.bytes_sent/MB:.0f}MB for 48MB file")
testsrv.ST.kill_every = 0

# 6. pause + resume: finished parts are not downloaded again
h = mkdata("e.bin", 80); testsrv.ST.reset(); testsrv.ST.per_conn_bps = 6 * MB
t, el, peak = run("e.bin", tmp, pause_at=30 * MB)
st1 = t.status; got1 = t.downloaded; sent1 = testsrv.ST.bytes_sent
t.start(); t0 = time.time()
while t.status in ("Downloading", "Pausing") and time.time() - t0 < 120: time.sleep(0.25)
t.join(10); ok, info = check(t, h)
extra = (testsrv.ST.bytes_sent - sent1) / MB
report("6 pause/resume without re-downloading", ok and st1 == "Paused" and extra <= (80 - got1 / MB) + 3, f"{info}, paused at {got1/MB:.0f}MB, resumed part sent {extra:.0f}MB (needed {80-got1/MB:.0f}MB)")

# 7. server that returns 429 when too many connections -> backs off, never breaks
h = mkdata("f.bin", 90); testsrv.ST.reset(); testsrv.ST.per_conn_bps = 3 * MB; testsrv.ST.block_over = 3
udm.CFG["retries"] = 8
t, el, peak = run("f.bin", tmp, nconn=16)
ok, info = check(t, h)
report("7 429 rate-limit handled", ok and testsrv.ST.n429 > 0, f"{info}, {el:.1f}s, 429 answers={testsrv.ST.n429}, max conc={testsrv.ST.max_conc}, learned limit={udm.HOSTS.learned}")
udm.HOSTS.learned.clear(); testsrv.ST.block_over = 0

# 8. no range support -> single stream, correct
h = mkdata("g.bin", 20); testsrv.ST.reset(); testsrv.ST.range_ok = False
t, el, peak = run("g.bin", tmp)
ok, info = check(t, h); report("8 server without Range", ok and peak <= 1, f"{info}, peak conns {peak}"); testsrv.ST.range_ok = True

# 9. manual mode uses exactly the fixed number
h = mkdata("h.bin", 64); testsrv.ST.reset(); testsrv.ST.per_conn_bps = 4 * MB
udm.CFG["speed_mode"] = "manual"
t, el, peak = run("h.bin", tmp, nconn=5)
ok, info = check(t, h); report("9 manual mode = fixed 5", ok and peak == 5, f"{info}, peak {peak}"); udm.CFG["speed_mode"] = "auto"

# 10. host safety cap
h = mkdata("i.bin", 60); testsrv.ST.reset(); testsrv.ST.per_conn_bps = 2 * MB; udm.CFG["host_max_conn"] = 4
t, el, peak = run("i.bin", tmp, nconn=16)
ok, info = check(t, h); report("10 per-site safety cap (4)", ok and testsrv.ST.max_conc <= 4, f"{info}, server max conc {testsrv.ST.max_conc}"); udm.CFG["host_max_conn"] = 16

# 11. missing file -> fails fast (fatal 404) not 6 retries
testsrv.ST.reset(); t0 = time.time()
t, el, peak = run("nothere.bin", tmp)
report("11 404 fails fast", t.status == "Error" and el < 8, f"status={t.status} err={t.error} in {el:.1f}s")

print("\nSUMMARY:", sum(results), "/", len(results), "passed")
os._exit(0 if all(results) else 1)

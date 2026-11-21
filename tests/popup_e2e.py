import os, sys, time, tempfile, importlib.util, json, threading, urllib.request, hashlib
HOME=tempfile.mkdtemp(); os.environ["HOME"]=HOME
spec=importlib.util.spec_from_file_location("udm","/home/claude/udm/UDM-Project/udm.py"); udm=importlib.util.module_from_spec(spec); spec.loader.exec_module(udm)
udm.APP_DIR=HOME+"/.udm"; udm.CFG_FILE=udm.APP_DIR+"/config.json"; udm.STATE_FILE=udm.APP_DIR+"/state.json"; udm.load_cfg()
udm.DEFAULT_DIR=HOME+"/Downloads"; udm.CFG["language"]=sys.argv[1] if len(sys.argv)>1 else "ar"
import testsrv
fsrv=testsrv.start(); FP=fsrv.server_address[1]; MB=1<<20
data=os.urandom(240*MB); testsrv.DATA["/Cyberpunk_2077_Patch_v2.1.zip"]=data; h=hashlib.sha256(data).hexdigest()
testsrv.ST.per_conn_bps=3*MB; testsrv.ST.total_bps=14*MB
PORT=7600+os.getpid()%300; udm.CFG["server_port"]=PORT; udm.start_server(); udm.G.mgr=udm.Manager()
threading.Thread(target=udm.engine_loop, daemon=True).start()
opened=[]; udm.webbrowser.open=lambda u: opened.append(u); udm.find_browser=lambda: None
def post(path, body):
    body["token"]=udm.CFG["token"]
    r=urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=json.dumps(body).encode(), headers={"Content-Type":"application/json","X-UDM-Token":udm.CFG["token"]})
    return json.loads(urllib.request.urlopen(r, timeout=30).read())
# the extension reports a click on a download link
print("POST /add ->", post("/add", {"url": f"http://127.0.0.1:{FP}/Cyberpunk_2077_Patch_v2.1.zip", "referer": "", "cookies": ""}))
print("popup window requested:", len(opened), "| main-window incoming queue:", len(udm.G.incoming))
post("/add", {"url": f"http://127.0.0.1:{FP}/Cyberpunk_2077_Patch_v2.1.zip"}); print("duplicate click within 4s ignored:", len(opened)==1)
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b=p.chromium.launch(); pg=b.new_page(viewport={"width":784,"height":620}); errs=[]; pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto(opened[0]); pg.wait_for_selector("#go:not([disabled])", timeout=15000); pg.wait_for_timeout(300)
    print("title:", pg.title(), "| name:", pg.input_value("#nm"), "| path:", pg.input_value("#path"))
    pg.screenshot(path="/home/claude/ui/pop_pre.png")
    pg.click('[data-c="Programs"]'); print("after choosing Programs:", pg.input_value("#path")); pg.click('[data-c="Compressed"]')
    pg.select_option("#cn", "16"); pg.click("#go"); pg.wait_for_selector("#bar", timeout=8000); pg.wait_for_timeout(5000)
    pg.screenshot(path="/home/claude/ui/pop_prog.png")
    print("live:", pg.inner_text("#bp"), "|", pg.inner_text("#ssp"), "|", pg.inner_text("#stl"), "|", pg.inner_text("#sco"))
    pg.click("#pz"); pg.wait_for_timeout(1400); print("after pause button ->", [t.status for t in udm.G.mgr.tasks.values()], "| button:", pg.inner_text("#pz"))
    pg.screenshot(path="/home/claude/ui/pop_pause.png"); pg.click("#pz"); pg.wait_for_timeout(500)
    t0=time.time()
    while time.time()-t0<60 and "Completed" not in [t.status for t in udm.G.mgr.tasks.values()]: time.sleep(.5)
    pg.wait_for_timeout(900); pg.screenshot(path="/home/claude/ui/pop_done.png")
    t=list(udm.G.mgr.tasks.values())[0]; print("final:", t.status, "| hash ok:", udm.file_hash(t.final_path,"sha256")==h, "| saved to:", t.final_path.replace(HOME,"~"))
    print("JS errors:", errs); b.close()
os._exit(0)

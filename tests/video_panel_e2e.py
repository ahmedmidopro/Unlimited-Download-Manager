import os, sys, tempfile, importlib.util, json, time, urllib.request
HOME=tempfile.mkdtemp(); os.environ["HOME"]=HOME
spec=importlib.util.spec_from_file_location("udm","/home/claude/udm/UDM-Project/udm.py"); udm=importlib.util.module_from_spec(spec); spec.loader.exec_module(udm)
udm.APP_DIR=HOME+"/.udm"; udm.CFG_FILE=udm.APP_DIR+"/config.json"; udm.STATE_FILE=udm.APP_DIR+"/state.json"; udm.load_cfg()
udm.tool_path=lambda n: "/home/claude/test/fake/yt-dlp" if n=="yt-dlp" else None
PORT=7100+os.getpid()%500; udm.CFG["server_port"]=PORT; srv=udm.start_server(); udm.G.mgr=udm.Manager()
udm.Task.start=lambda self: None; udm.VideoTask.start=lambda self: None      # do not really download in the test
def post(path, body):
    body["token"]=udm.CFG["token"]
    r=urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=json.dumps(body).encode(), headers={"Content-Type":"application/json","X-UDM-Token":udm.CFG["token"]})
    return json.loads(urllib.request.urlopen(r, timeout=30).read())
t0=time.time(); f=post("/video/formats",{"url":"https://www.youtube.com/watch?v=x","referer":"","cookies":""})
print("formats via HTTP:", len(f["rows"]), "rows, rec =", f["rec"], f"({time.time()-t0:.2f}s)")
row=[r for r in f["rows"] if r["codec"]=="AV1" and r["h"]==1080][0]
print("get ->", post("/video/get", dict(row, url="https://www.youtube.com/watch?v=x", title="GTA VI", thumb=f["thumb"], referer="", cookies="")))
t=list(udm.G.mgr.tasks.values())[0]; print("task:", t.kind, t.vfmt, t.vcont, t.vheight, "| file:", t.filename, "| thumb:", bool(t.vthumb))
print("bad yt-dlp ->", end=" "); udm.tool_path=lambda n: None; udm._VJ_CACHE.clear(); print(post("/video/formats",{"url":"https://www.youtube.com/watch?v=zzz"}))
# content script: clicking a row sends that exact row
from playwright.sync_api import sync_playwright
rows=json.load(open('/home/claude/test/fake/rows.json')); content=open('/home/claude/test/extout/chrome/content.js').read()
mock = """window.__msgs=[];globalThis.chrome={runtime:{lastError:null,sendMessage:(m,cb)=>{window.__msgs.push(m);setTimeout(()=>{ if(m.udm==='cfg') cb({lang:'en'}); else if(m.udm==='formats') cb(%s); else cb({ok:true}); },30)}}};""" % json.dumps(rows)
html='<html><body style="margin:0"><video style="position:absolute;top:60px;left:40px" width="860" height="480"></video></body></html>'
with sync_playwright() as p:
    b=p.chromium.launch(); pg=b.new_page(viewport={'width':1000,'height':640}); pg.route("https://www.youtube.com/**", lambda r: r.fulfill(body=html, content_type="text/html"))
    pg.goto("https://www.youtube.com/watch?v=abc"); pg.evaluate(mock+content); pg.wait_for_timeout(200)
    pg.mouse.move(300,200); pg.mouse.move(340,230); pg.wait_for_timeout(400)
    pg.mouse.click(64,96); pg.wait_for_timeout(300)          # open the list
    pg.screenshot(path='/home/claude/ui/p_en.png', clip={'x':0,'y':40,'width':520,'height':330})
    pg.mouse.click(448, 292); pg.wait_for_timeout(300)       # 3rd row: 1080p60 H.264 (recommended)
    g=[m for m in pg.evaluate("window.__msgs") if m['udm']=='get']; print("clicked row sent:", g and {k:g[0]['row'][k] for k in ('fid','label','codec','ext')})
    pg.mouse.move(340,230); pg.wait_for_timeout(300); pg.mouse.click(240,96); pg.wait_for_timeout(300)   # main button = recommended
    g=[m for m in pg.evaluate("window.__msgs") if m['udm']=='get']; print("main button sent:", {k:g[-1]['row'][k] for k in ('fid','label','codec')}, "| total get msgs:", len(g))
    b.close()
os._exit(0)

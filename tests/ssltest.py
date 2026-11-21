import os, sys, time, tempfile, hashlib, ssl, threading, importlib.util
HOME=tempfile.mkdtemp(); os.environ["HOME"]=HOME
spec=importlib.util.spec_from_file_location("udm","/home/claude/udm/UDM-Project/udm.py"); udm=importlib.util.module_from_spec(spec); spec.loader.exec_module(udm)
udm.APP_DIR=HOME+"/.udm"; udm.load_cfg()
import testsrv
srv=testsrv.S(("127.0.0.1",0),testsrv.H); ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("c.pem","k.pem")
srv.socket=ctx.wrap_socket(srv.socket, server_side=True); threading.Thread(target=srv.serve_forever,daemon=True).start()
PORT=srv.server_address[1]; MB=1<<20
d=os.urandom(24*MB); testsrv.DATA["/s.bin"]=d; h=hashlib.sha256(d).hexdigest(); tmp=tempfile.mkdtemp()
def run(**kw):
    t=udm.Task(f"https://127.0.0.1:{PORT}/s.bin", tmp); t.category="Uncategorized"; t.auto_cat=False; t.auto_folder=False
    for k,v in kw.items(): setattr(t,k,v)
    t.start(); t0=time.time()
    while t.status in ("Downloading","Pausing") and time.time()-t0<60: time.sleep(.2)
    t.join(5); return t
udm.CFG["ssl_fallback"]=False; udm.SSL_RELAXED.clear()
t=run(); print("1 fallback OFF ->", t.status, "|", t.error[:90])
udm.CFG["ssl_fallback"]=True; udm.SSL_RELAXED.clear()
t=run(); ok=t.status=="Completed" and udm.file_hash(t.final_path,"sha256")==h
print("2 fallback ON  ->", t.status, "| hash ok:", ok, "| state:", udm.ssl_state(t.url), "| relaxed hosts:", udm.SSL_RELAXED)
udm.SSL_RELAXED.clear(); t=run(user="me", pwd="secret")
print("3 with password never relaxed ->", t.status, "|", t.error[:70])
os._exit(0)

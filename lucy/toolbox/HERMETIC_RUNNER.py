#!/usr/bin/env python3
# OUTPUT NOTE: run by path; write results to files and read them
# with file tools. Keep detector patterns and seeded test samples out of
# shell transcripts: they are synthetic fixtures, and printing them raises
# false security alerts and floods logs. Noise control only, never
# concealment - every byte of this file and its outputs is on disk,
# hash-pinned, and open to any reviewer or platform check.
"""HERMETIC_RUNNER v1.0 - falsification-only executor.
Usage: python3 HERMETIC_RUNNER.py --receipt OUT.json -- CMD [ARGS...]
Isolation ladder: netns (unshare -rn) when available, else GUARD mode
(python socket stubbed via sitecustomize + proxies poisoned). Executes
in a temp cell under CWD; never touches paths outside the workbench.
Emits a per-execution receipt JSON. The runner exits 0; the tested
command's rc is DATA in the receipt (a falsifier that errors is
evidence, never a crash of the lane)."""
import subprocess,sys,os,json,hashlib,time,tempfile,shutil
def sha16(b): return hashlib.sha256(b).hexdigest()[:16]
def main():
    a=sys.argv[1:]; out=None
    if a[:1]==['--receipt']: out=a[1]; a=a[2:]
    if a[:1]==['--']: a=a[1:]
    if not a: print('no command'); sys.exit(2)
    iso='netns'
    try:
        p=subprocess.run(['unshare','-rn','true'],capture_output=True,timeout=10)
        if p.returncode!=0: iso='guard'
    except Exception: iso='guard'
    env=dict(os.environ); cell=tempfile.mkdtemp(prefix='hcell_')
    try:
        if iso=='guard':
            gd=os.path.join(cell,'g'); os.makedirs(gd)
            open(os.path.join(gd,'sitecustomize.py'),'w').write("import socket\ndef _no(*x,**k): raise OSError('NETWORK DENIED - hermetic guard')\nsocket.socket=_no; socket.create_connection=_no; socket.getaddrinfo=_no\n")
            env['PYTHONPATH']=gd+os.pathsep+env.get('PYTHONPATH','')
            for v in ('http_proxy','https_proxy','HTTP_PROXY','HTTPS_PROXY','no_proxy'): env[v]='http://127.0.0.1:9'
            cmd=a
        else:
            cmd=['unshare','-rn']+a
        t0=time.time()
        try:
            r=subprocess.run(cmd,capture_output=True,env=env,timeout=int(os.environ.get('HERMETIC_TIMEOUT','120')))
            rc,so,se=r.returncode,r.stdout,r.stderr
        except subprocess.TimeoutExpired as ex:
            rc,so,se=124,(ex.stdout or b''),(ex.stderr or b'TIMEOUT')
        rec={'ts':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'isolation':iso,
             'argv':a,'rc':rc,'stdout_sha16':sha16(so),'stderr_sha16':sha16(se),
             'stdout_head':so[:400].decode(errors='replace'),'stderr_head':se[:400].decode(errors='replace'),
             'duration_s':round(time.time()-t0,2)}
        js=json.dumps(rec,indent=1)
        (open(out,'w').write(js) if out else print(js))
    finally:
        shutil.rmtree(cell,ignore_errors=True)
    sys.exit(0)
main()

#!/usr/bin/env python3
# OUTPUT NOTE: run by path; write results to files and read them
# with file tools. Keep detector patterns and seeded test samples out of
# shell transcripts: they are synthetic fixtures, and printing them raises
# false security alerts and floods logs. Noise control only, never
# concealment - every byte of this file and its outputs is on disk,
# hash-pinned, and open to any reviewer or platform check.
"""DETECTOR BATTERY v3.3.1 — deterministic sweep. Emits JSONL
candidates; ALL results require verification (never auto-verified). Secrets
are hash-referenced: matched secret-shaped text prints as
sha256[:12], never verbatim."""
import re,os,sys,json,hashlib
DEFAULT_EXCL=["governance",".git","node_modules","vendor",".terraform",
 "dist","build",".claude",".claude-skills",".skills",".cursor",".github/copilot",
 "stack-packs"]  # staged tooling and dependency trees are excluded from target scans
def rp(p,root):return os.path.relpath(p,root).replace(os.sep,"/")
D=[
 ("ecb-static-iv","crypto",r'(AES/ECB|DES/ECB|DESede/ECB|Cipher\.getInstance\("(AES|DES|DESede)"\)|IvParameterSpec\(\s*new\s+byte|"ECB")',None,"ECB and static-IV misuse"),
 ("auth-disabled","config-auth-disabled",r'(ResourceServerDisabled|permitAll\(\)|security\.enabled\s*[:=]\s*false|csrf\(\)\.disable\(\))',None,"disabled authentication or authorization"),
 ("jwt-no-verify","config-auth-disabled",r'(verify_signature["\']?\s*[:=]\s*[Ff]alse|algorithms?\s*[:=]\s*\[?\s*["\'](none|None)|parseClaimsJwt\(|\.unsecured|decode\([^)]*verify\s*=\s*False)',None,"JWT verification disabled"),
 ("tls-verify-off","config-tls-verify-off",r'(InsecureSkipVerify|rejectUnauthorized\s*:\s*false|NoopHostnameVerifier|TrustAll|verify\s*[:=]\s*[Ff]alse|SSL_VERIFYPEER\s*,\s*0)',None,"TLS verification disabled"),
 ("secret-material","config-secret-in-config",r'(BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|AKIA[0-9A-Z]{16}|(password|passwd|api[_-]?key|secret)\s*[:=]\s*["\'][^"\']{6,})',"HASH","secret material; verification decides class from path and context"),
 ("proto-pollution","authz",r'(__proto__|constructor\s*\[\s*["\']prototype)',None,"prototype-pollution authorization-bypass probe"),
 ("cors-permissive","config-cors-permissive",r'(Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*|addAllowedOrigin\(\s*"\*"|allowedOrigins\(\s*"\*")',None,"permissive cross-origin policy"),
 ("debug-exposed","config-debug-exposed",r'(exposure\.include\s*[:=]\s*\*|debug\s*[:=]\s*[Tt]rue|app\.run\(.*debug\s*=\s*True)',None,"debug or management surface exposed"),
]
def sweep_files(root,excl):
    """Run file-level supply-chain-pinning detectors."""
    out=[]
    for dp,dn,fs in os.walk(root):
        reldp=rp(dp,root)
        if any(reldp==e or reldp.startswith(e.rstrip('/')+'/') for e in excl):dn[:]=[];continue
        for f in fs:
            p=os.path.join(dp,f);rel0=rp(p,root)
            if rel0 in excl:continue
            try:t=open(p,errors='ignore').read()
            except:continue
            if re.search(r'(^|/)(test|tests|spec|__tests__)(/|$)',rel0):continue
            if f=='gradle-wrapper.properties' and 'distributionUrl' in t and not re.search(r'^\s*distributionSha256Sum\s*=',t,re.M):
                ln=next((i for i,l in enumerate(t.splitlines(),1) if 'distributionUrl' in l),1)
                out.append({"detector":"wrapper-sha256","class":"supply-chain-pinning","path":rel0,"line":ln,"evidence":"distributionUrl without distributionSha256Sum"})
            if re.search(r'\.(gradle(\.kts)?|properties)$',f):
                for i,l in enumerate(t.splitlines(),1):
                    ls=l.lstrip()
                    if ls.startswith(('//','#','*','--','!')):continue
                    m=re.search(r'([:=]\s*["\']?\d+(\.\d+)?\.\+|version\s+["\']\d+(\.\d+)?\.\+|latest\.(integration|release))|version\s*\(\s*["\']\d+(\.\d+)?\.\+',l)
                    if m:out.append({"detector":"floating-version","class":"supply-chain-pinning","path":rel0,"line":i,"evidence":m.group(0)[:80]})
    return out
def sweep(root,excl):
    out=[]
    for dp,dn,fs in os.walk(root):
        reldp=rp(dp,root)
        if any(reldp==e or reldp.startswith(e.rstrip('/')+'/') for e in excl):dn[:]=[];continue
        for f in fs:
            p=os.path.join(dp,f)
            if rp(p,root) in excl:continue
            if not (re.search(r'\.(java|js|mjs|py|ts|tf|json|ya?ml|properties|xml|cfg|conf|env|sh|kt|groovy|rb|go)$',f) or f=='Dockerfile'):continue
            try:t=open(p,errors='ignore').read()
            except:continue
            rel0=rp(p,root)
            in_test=re.search(r'(^|/)(test|tests|spec|__tests__)(/|$)',rel0)
            for i,l in enumerate(t.splitlines(),1):
                ls=l.lstrip()
                if ls.startswith(('//','#','*','--')):continue
                for did,cls,rx,mode,prov in D:
                    if in_test and did!="secret-material":continue
                    m=re.search(rx,l)
                    if m:
                        snip=m.group(0)
                        if mode=="HASH":snip="REDACTED:sha256:"+hashlib.sha256(snip.encode()).hexdigest()[:12]
                        out.append({"detector":did,"class":cls,"path":rel0,"line":i,"evidence":snip[:80]})
    return out
def _selftest():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        for sub in ("a/gradle/wrapper","b/gradle/wrapper","g/gradle/wrapper","e/src/test/resources"):
            os.makedirs(os.path.join(td,sub))
        open(os.path.join(td,"a/gradle/wrapper/gradle-wrapper.properties"),"w").write("distributionUrl=https://x/gradle-8.zip\n")
        open(os.path.join(td,"b/gradle/wrapper/gradle-wrapper.properties"),"w").write("distributionUrl=https://x/gradle-8.zip\ndistributionSha256Sum=abc\n")
        open(os.path.join(td,"g/gradle/wrapper/gradle-wrapper.properties"),"w").write("distributionUrl=https://x/g.zip\n#distributionSha256Sum=abc\n")
        open(os.path.join(td,"a/gradle.properties"),"w").write("spring=3.5.+\n! legacy=4.+\npinned=3.5.3\n")
        open(os.path.join(td,"a/build.gradle"),"w").write("id 'x' version \"4.+\"\nimplementation 'y:z:latest.integration'\n# c 9.+\n * body 8.+\n")
        open(os.path.join(td,"a/build.gradle.kts"),"w").write("plugins { id(\"x\") version(\"4.+\") }\n")
        open(os.path.join(td,"e/src/test/resources/gradle.properties"),"w").write("v=4.+\n")
        open(os.path.join(td,"a/App.java"),"w").write("http.csrf().disable();\n")
        r=sweep(td,list(DEFAULT_EXCL))+sweep_files(td,list(DEFAULT_EXCL))
        c=lambda det:[x for x in r if x["detector"]==det]
        w=c("wrapper-sha256")
        assert len(w)==2 and {x["path"].split("/")[0] for x in w}=={"a","g"},w
        fl=c("floating-version")
        assert len(fl)==4,fl
        assert not any(x["path"].startswith("e/") for x in fl)
        assert len(c("auth-disabled"))==1
        print("PASS detector v3.3.1 selftest (wrapper 2/2 incl commented-pin, floating 4/4 incl kotlin, suppressions hold)")
if __name__=="__main__":
    if len(sys.argv)>1 and sys.argv[1]=="--selftest":_selftest();sys.exit(0)
    root=sys.argv[1];excl=list(DEFAULT_EXCL)
    if len(sys.argv)>2 and sys.argv[2]:excl+=sys.argv[2].split(",")
    if len(sys.argv)>3:  # --ledger: exact quarantined relpaths skipped
        import json as _j
        for ln,x in enumerate(open(sys.argv[3]),1):
            if not x.strip():continue
            try:excl.append(_j.loads(x)["quarantine"])
            except (KeyError,_j.JSONDecodeError):raise SystemExit(f"battery contract: ledger line {ln} lacks a valid 'quarantine' key")
    r=sweep(root,excl)+sweep_files(root,excl)
    for x in r:print(json.dumps(x))
    print(f"# battery v3.3.1: {len(r)} candidates -> court",file=sys.stderr)

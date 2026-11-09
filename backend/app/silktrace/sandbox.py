from __future__ import annotations
import json, os, shutil, subprocess, sys
from pathlib import Path

def inspect_isolated(path:Path, filename:str, timeout:float=15)->dict:
    worker=Path(__file__).with_name('parser_worker.py')
    source=path.resolve()
    command=[sys.executable,'-I',str(worker),str(source),str(filename)]
    bwrap=shutil.which('bwrap')
    isolation='resource-limited subprocess (network namespace unavailable)'
    if bwrap:
        command=[bwrap,'--die-with-parent','--new-session','--unshare-all','--cap-drop','ALL',
                 '--ro-bind','/','/','--dev','/dev','--proc','/proc','--tmpfs','/tmp',
                 '--chdir',str(source.parent),'--',*command]
        isolation='bubblewrap: read-only filesystem, isolated network namespace, no capabilities, plus process resource limits'
    env={'PATH':os.environ.get('PATH',''),'PYTHONIOENCODING':'utf-8','PYTHONDONTWRITEBYTECODE':'1'}
    if os.name=='nt':
        # Windows cannot start .cmd/.bat decoders (and some DLLs fail to load)
        # without these; they locate system binaries and carry no secrets.
        env.update({k:os.environ[k] for k in ('SYSTEMROOT','COMSPEC','PATHEXT') if k in os.environ})
    p=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,
                     cwd=str(source.parent),env=env,check=False)
    if p.returncode!=0: raise RuntimeError(f'isolated parser worker failed (exit {p.returncode}); stderr={p.stderr.decode("utf-8","replace")[:1000]}')
    if len(p.stdout)>16*1024*1024: raise RuntimeError('isolated parser output exceeded 16 MiB cap')
    result=json.loads(p.stdout.decode('utf-8'))
    result['_isolation']=isolation
    return result

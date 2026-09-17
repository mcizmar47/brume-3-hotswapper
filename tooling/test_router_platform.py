"""Local platform capability/startup checks. No router/network access."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SH=sys.argv[1] if len(sys.argv)>1 else 'sh'
if Path(SH).is_absolute(): os.environ['PATH']=str(Path(SH).parent)+os.pathsep+os.environ.get('PATH','')
source=(ROOT/'hotswapper-main.sh').read_text(encoding='utf-8')
def function(name):
    a=source.index('\n'+name+'() {')+1
    return source[a:source.index('\n}',a)+2]
prereq=(ROOT/'BrumeHotswapper.Installer/Services/RouterPrerequisites.cs').read_text(encoding='utf-8')
def constant(name):
    literal=re.search(r'const string '+name+r' = ("(?:\\.|[^"\\])*");',prereq).group(1)
    return json.loads(literal)
def run(code,expected=0):
    result=subprocess.run([SH,'-c',code],capture_output=True,text=True,timeout=15)
    assert result.returncode==expected,(result.returncode,result.stdout,result.stderr)
    return result.stdout
# Tests execute production prerequisite text with only external target facts stubbed.
# Fractional sleep and session utility are explicitly rejected.
stubs=r'''
command() { [ "$1" = -v ] || return 90; [ "$2" != setsid ] && [ "$2" != "$missing" ]; }
sleep() { case "$1" in *.*) return 1;; *) return 0;; esac; }
test() { case "$1" in -x) return 0;; *) [ "$@" ];; esac; }
id() { echo 0; }
'''
run(stubs+'\n'+constant('CapabilitiesCommand'))
run(stubs+'\nmissing=wg\n'+constant('CapabilitiesCommand'),1)
# The elapsed-time probe must reject a missing/no-op/whole-second implementation.
for elapsed,rc,expected in [(150,0,0),(0,0,1),(1000,0,1),(150,127,127)]:
    with tempfile.TemporaryDirectory(prefix='hotswapper-delay-') as d:
        script=f"cd '{Path(d).as_posix()}'\n"+f'''
awk() {{ if [ -f measured ]; then echo {elapsed}; else echo 0; fi; }}
busybox() {{ [ "$1 $2" = 'usleep 150000' ] || return 90; touch measured; return {rc}; }}
'''+constant('DelayCommand')
        run(script,expected)
production=[ROOT/n for n in ('hotswapper-main.sh','hotswapper-supervisor.sh','hotswapper-housekeeping.sh','firmware/install-gl-guard.sh')]
for path in production:
    text=path.read_text(encoding='utf-8')
    assert not re.search(r'\bsetsid\b|\bsleep\s+[0-9]+\.',text),path
# Run the real supervisor with paths redirected into an isolated host fixture.
# The daemon fixture uses production lock functions, with no VPN/network code.
with tempfile.TemporaryDirectory(prefix='hotswapper-startup-') as d:
    directory=Path(d); posix=directory.as_posix()
    pause=directory/'host_pause'
    pause.write_text("#!/bin/sh\nexec '"+Path(sys.executable).as_posix()+"' -c 'import time; time.sleep(.05)'\n",encoding='utf-8',newline='\n');pause.chmod(0o755)
    daemon=directory/'hotswapper-main.sh'
    daemon.write_text(f'''#!/bin/sh
PATH='{posix}':$PATH
RUNTIME_DIR='{posix}/runtime'
LOCK_DIR="$RUNTIME_DIR/lock"
SLOW_PID=''
'''+ '\n'.join(function(n) for n in ['stop_slow_command','release_lock','acquire_lock'])+'''
acquire_lock || exit 0
echo $$ >> "$RUNTIME_DIR/starts"
while :; do host_pause; done
''',encoding='utf-8',newline='\n');daemon.chmod(0o755)
    supervisor=directory/'supervisor.sh'
    supervisor.write_text((ROOT/'hotswapper-supervisor.sh').read_text(encoding='utf-8').replace('/root/hotswapper-main.sh',daemon.as_posix()).replace('/tmp/hotswapper',posix+'/runtime'),encoding='utf-8',newline='\n')
    run(f'''
cd '{posix}' || exit 90
PATH="$PWD:$PATH"; export PATH
# Launching shell exits; daemon must remain reachable after it is gone.
sh -c 'sh ./supervisor.sh' || exit 91
pid=''
trap '[ -z "$pid" ] || kill -TERM "$pid" 2>/dev/null' EXIT
n=0
while [ ! -s runtime/lock/pid ]; do n=$((n+1)); [ "$n" -lt 40 ] || exit 92; host_pause; done
pid=$(cat runtime/lock/pid)
kill -0 "$pid" || exit 93
kill -HUP "$pid" || exit 94
host_pause
kill -0 "$pid" || exit 95
sh ./supervisor.sh & a=$!
sh ./supervisor.sh & b=$!
wait "$a"; wait "$b"
host_pause
[ "$(cat runtime/lock/pid)" = "$pid" ] || exit 96
[ "$(wc -l < runtime/starts)" -eq 1 ] || exit 97
kill -TERM "$pid"
n=0
while [ -d runtime/lock ]; do n=$((n+1)); [ "$n" -lt 40 ] || exit 98; host_pause; done
pid=''
''')
print('PASS: 7 platform prerequisite/timing cases and real supervisor detachment, HUP, PID, duplicate-launch and shutdown checks (host shell)')

#!/usr/bin/env python3
"""Start / stop the local service without a shell or extra packages."""
from pathlib import Path
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'data'
URL = 'http://127.0.0.1:8766'

def alive():
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(URL + '/api/state', timeout=2) as r:
            d = json.load(r)
            return 'settings' in d and 'network' in d and 'scan' in d
    except Exception:
        return False

def main():
    DATA.mkdir(exist_ok=True)
    pidfile = DATA / 'server.pid'
    if '--stop' in sys.argv:
        if pidfile.exists():
            pid = int(pidfile.read_text())
            check = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'command='], capture_output=True, text=True)
            if str(ROOT / 'server.py') in check.stdout:
                os.kill(pid, signal.SIGTERM)
                print('Netwatch 已停止。')
            else:
                print('Netwatch 未运行。')
            pidfile.unlink(missing_ok=True)
        helper_path = str(ROOT / 'native/Netwatch Wi-Fi.app/Contents/MacOS/NetwatchWifi')
        listing = subprocess.run(['/bin/ps','-ax','-o','pid=,command='],capture_output=True,text=True)
        for line in listing.stdout.splitlines():
            parts=line.strip().split(None,1)
            if len(parts)==2 and parts[1].startswith(helper_path):
                try:os.kill(int(parts[0]),signal.SIGTERM)
                except ProcessLookupError:pass
        for name in ['wifi-state.json','wifi-command.json','wifi-result.json']:
            (DATA/name).unlink(missing_ok=True)
        return
    if not alive():
        with (DATA / 'server.log').open('ab') as log:
            process = subprocess.Popen([sys.executable, str(ROOT / 'server.py')], cwd=ROOT,
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        pidfile.write_text(str(process.pid))
        for _ in range(30):
            if alive(): break
            if process.poll() is not None: break
            time.sleep(.2)
        if not alive():
            raise SystemExit('启动失败，请查看 data/server.log。端口 8766 可能已被占用。')
    print('Netwatch 已运行：' + URL)
    if '--no-open' not in sys.argv:
        subprocess.run(['/usr/bin/open', URL], check=False)

if __name__ == '__main__':
    main()

"""Learn trusted Wi-Fi habits and switch through the signed native CoreWLAN companion."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time
from quality import metrics,quality_score

SEEDS=[]

class WifiError(Exception):pass

class WifiController:
    def __init__(self,root):
        self.root=Path(root);self.data=self.root/'data';self.lock=threading.Lock()
        self.data.mkdir(exist_ok=True);self.data.chmod(0o700)
    def state(self):
        try:
            state=json.loads((self.data/'wifi-state.json').read_text())
            if time.time()-state.get('ts',0)>=20 or not isinstance(state.get('pid'),int):return {}
            os.kill(state['pid'],0)
            return state
        except (OSError,ValueError):return {}
    def write(self,name,value):
        target=self.data/name;tmp=target.with_suffix('.tmp')
        tmp.write_text(json.dumps(value,ensure_ascii=False));tmp.chmod(0o600);tmp.replace(target)
    def start(self,authorize=False):
        app=self.root/'native/Netwatch Wi-Fi.app'
        if not app.exists():raise WifiError('Wi-Fi 辅助程序未构建，请运行 native/build.py。')
        if not self.state():
            subprocess.run(['/usr/bin/open','-g',str(app),'--args','--data',str(self.data)],check=True,timeout=8)
        for _ in range(20):
            if self.state():break
            time.sleep(.2)
        if not self.state():raise WifiError('Wi-Fi 辅助程序未启动，请重新点击允许 Wi-Fi 读取。')
        if authorize:
            if self.state().get('authorization') in (1,2):
                subprocess.run(['/usr/bin/open','x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices'],timeout=8)
            else:self.command('authorize')
    def command(self,action,ssid=None):
        with self.lock:
            self.start()
            request={'id':secrets.token_hex(12),'issued_at':time.time(),'action':action}
            if ssid:request['ssid']=ssid
            self.write('wifi-command.json',request)
            deadline=time.time()+40
            while time.time()<deadline:
                try:
                    result=json.loads((self.data/'wifi-result.json').read_text())
                    if result.get('id')==request['id']:
                        if not result.get('ok'):raise WifiError(result.get('error','Wi-Fi 操作未完成'))
                        return result
                except (OSError,ValueError):pass
                time.sleep(.25)
            raise WifiError('Wi-Fi 辅助程序未及时响应，已停止继续切换。')
    def connect(self,ssid,allowed):
        self.write('wifi-allowed.json',{'ssids':sorted(set(allowed))})
        self.command('connect',ssid)
        for _ in range(20):
            if self.state().get('ssid')==ssid:return
            time.sleep(.5)
        raise WifiError('尚未确认连接目标 Wi-Fi。')

class WifiManager:
    def __init__(self,monitor,root,probe,controller=None):
        self.monitor=monitor;self.store=monitor.store;self.probe=probe
        self.controller=controller or WifiController(root)
        self.lock=threading.RLock();self.busy=False;self.message='等待 Wi-Fi 识别';self.last_tick=0;self.last_ssid=None
        self.last_switch=0;self.bad=0;self.blocked_until=0
        self.last_missing=0
        with self.store.lock,self.store.db:
            self.store.db.executescript('''CREATE TABLE IF NOT EXISTS wifi_profiles
                (ssid TEXT PRIMARY KEY,trusted INTEGER,origin TEXT,seconds REAL DEFAULT 0,last_seen REAL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS wifi_history(id INTEGER PRIMARY KEY,ssid TEXT,ts REAL,payload TEXT);
                CREATE INDEX IF NOT EXISTS wifi_history_ssid ON wifi_history(ssid,ts);''')
            for name in SEEDS:
                self.store.db.execute('INSERT OR IGNORE INTO wifi_profiles VALUES (?,1,\'seed\',0,0)',(name,))
            previous=self.store.db.execute('SELECT ssid FROM wifi_profiles WHERE last_seen>0 ORDER BY last_seen DESC LIMIT 1').fetchone()
            if previous:self.last_ssid=previous[0]
    def profile(self,ssid,window=86400):
        with self.store.lock:
            rows=self.store.db.execute('SELECT payload FROM wifi_history WHERE ssid=? AND ts>? ORDER BY ts',(ssid,time.time()-window)).fetchall()
        values=[];attempts=failures=0
        for row in rows:
            p=json.loads(row[0]);values.extend(p.get('direct_readings',[]));attempts+=p.get('direct_attempts',0);failures+=p.get('direct_failures',0)
        stat=metrics(values,attempts,failures)
        return quality_score(stat),stat
    def view(self):
        native=self.controller.state();ssid=native.get('ssid')
        visible={x['ssid']:x.get('rssi') for x in native.get('visible',[])}
        with self.store.lock:
            rows=self.store.db.execute('SELECT ssid,trusted,origin,seconds,last_seen FROM wifi_profiles ORDER BY trusted DESC,seconds DESC').fetchall()
        profiles=[]
        for name,trusted,origin,seconds,last_seen in rows:
            score,stat=self.profile(name)
            profiles.append({'ssid':name,'trusted':bool(trusted),'origin':origin,'seconds':round(seconds),
                             'last_seen':last_seen,'quality':score,'metrics':stat,'visible':name in visible or name==ssid,
                             'rssi':visible.get(name),'current':name==ssid})
        return {'native_ready':bool(native),'authorization':native.get('authorization'),'authorized':native.get('authorization') in (3,4),'ssid':ssid,
                'rssi':native.get('rssi'),'profiles':profiles,'busy':self.busy,'message':self.message,
                'bad_count':self.bad,'last_switch':self.last_switch}
    def tick(self,sample):
        if self.busy:return
        native=self.controller.state();ssid=native.get('ssid');now=time.time()
        if not ssid:
            if native.get('authorization') in (3,4):self.on_network_unavailable()
            else:self.message='需要允许 Wi-Fi 读取权限，才能识别网络并学习连接习惯'
            return
        # Do not attribute a probe measured on one network to another one.
        if ssid!=sample.get('wifi_ssid'):return
        dt=min(60,max(0,now-self.last_tick)) if self.last_ssid==ssid else 0
        self.last_tick,self.last_ssid=now,ssid
        with self.store.lock,self.store.db:
            self.store.db.execute('INSERT OR IGNORE INTO wifi_profiles VALUES (?,0,\'observed\',0,?)',(ssid,now))
            self.store.db.execute('UPDATE wifi_profiles SET seconds=seconds+?,last_seen=? WHERE ssid=?',(dt,now,ssid))
            self.store.db.execute('INSERT INTO wifi_history(ssid,ts,payload) VALUES (?,?,?)',(ssid,now,json.dumps(sample)))
            self.store.db.execute('DELETE FROM wifi_history WHERE ts<?',(now-7*86400,))
            row=self.store.db.execute('SELECT trusted,seconds,origin FROM wifi_profiles WHERE ssid=?',(ssid,)).fetchone()
        cfg=self.monitor.cfg.copy();score,_=self.profile(ssid,900)
        if not row[0] and row[2]!='manual' and row[1]>=cfg['learn_minutes']*60 and score['ready'] and score['score']>=70:
            with self.store.lock,self.store.db:
                self.store.db.execute('UPDATE wifi_profiles SET trusted=1,origin=\'learned\' WHERE ssid=?',(ssid,))
            self.store.event('wifi','已根据长期连接习惯加入候选：'+ssid)
        value=score['score']
        self.bad=self.bad+1 if value is not None and value<cfg['wifi_score_threshold'] else 0
        self.message='当前网络学习中' if value is None else f'当前 Wi-Fi 评分 {value} 分'
        if not cfg['wifi_auto'] or self.bad<3 or now-self.last_switch<cfg['wifi_cooldown'] or now<self.blocked_until:return
        candidates=[p for p in self.view()['profiles'] if p['trusted'] and p['visible'] and not p['current']
                    and p['quality']['score'] is not None and p['quality']['samples']>=10
                    and p['quality']['score']>=max(cfg['wifi_score_threshold'],value+10)]
        if candidates:self.start_switch(max(candidates,key=lambda p:p['quality']['score'])['ssid'],automatic=True)
        else:self.message='当前评分偏低；暂无近期已验证、更稳定且可见的候选 Wi-Fi，继续观察'
    def on_network_unavailable(self):
        if self.busy:return
        now=time.time();cfg=self.monitor.cfg.copy();native=self.controller.state()
        if now-self.last_missing<max(10,cfg['interval']):return
        self.last_missing=now
        if native.get('authorization') not in (3,4):return
        self.bad+=1
        self.message='当前网络连接中断；正在检查已有质量记录的候选 Wi-Fi'
        if not cfg['wifi_auto'] or self.bad<3 or now-self.last_switch<cfg['wifi_cooldown'] or now<self.blocked_until:return
        candidates=[p for p in self.view()['profiles'] if p['trusted'] and p['visible'] and not p['current']
                    and p['quality']['score'] is not None and p['quality']['samples']>=10
                    and p['quality']['score']>=cfg['wifi_score_threshold']]
        if candidates:self.start_switch(max(candidates,key=lambda p:p['quality']['score'])['ssid'],automatic=True,recovery=True)
        else:self.message='连接中断，暂无可见且有足够良好记录的候选 Wi-Fi'
    def trust(self,ssid,trusted):
        if not isinstance(ssid,str) or type(trusted) is not bool:raise WifiError('候选设置无效')
        with self.store.lock,self.store.db:
            row=self.store.db.execute('SELECT ssid FROM wifi_profiles WHERE ssid=?',(ssid,)).fetchone()
            if not row:raise WifiError('只能修改已经观察到或预设的网络')
            self.store.db.execute('UPDATE wifi_profiles SET trusted=?,origin=\'manual\' WHERE ssid=?',(int(trusted),ssid))
    def start_switch(self,ssid,automatic=False,recovery=False):
        with self.lock:
            if self.busy:raise WifiError('已有 Wi-Fi 验证在进行中')
            state=self.view();native=self.controller.state()
            if not state['authorized']:raise WifiError('请先允许 Wi-Fi 读取权限')
            candidate=next((p for p in state['profiles'] if p['ssid']==ssid and p['trusted']),None)
            if not candidate:raise WifiError('该网络不在允许的候选列表中')
            if ssid==native.get('ssid'):raise WifiError('当前已经连接这个 Wi-Fi')
            if automatic and not candidate['visible']:raise WifiError('候选 Wi-Fi 当前不可见，请先开启热点或靠近路由器')
            self.busy=True;self.message='正在连接并验证：'+ssid
            thread=threading.Thread(target=self._switch,args=(ssid,native.get('ssid') or self.last_ssid,automatic,recovery),daemon=True);thread.start()
    def _switch(self,target,origin,automatic,recovery=False):
        switched=False
        try:
            with self.monitor.action_lock:
                cfg=self.monitor.cfg.copy()
                if automatic and not cfg['wifi_auto']:return
                old_score,_=self.profile(origin,900);old=old_score['score']
                if recovery:old=None
                allowed=[p['ssid'] for p in self.view()['profiles'] if p['trusted']]+([origin] if origin else [])
                switched=True;self.controller.connect(target,allowed)
                self.message='已连接，正在复测基础网络：'+target
                samples=[];values=[];failures=attempts=0
                for _ in range(3):
                    p=self.probe();samples.append(p);values.extend(p['readings']);attempts+=p['samples'];failures+=p['failures']
                    if self.controller.state().get('ssid')!=target:raise WifiError('验证期间网络被更改，终止验证')
                    time.sleep(1)
                verified=quality_score(metrics(values,attempts,failures))
                score=verified['score']
                with self.store.lock,self.store.db:
                    for p in samples:
                        payload={'direct_readings':p['readings'],'direct_attempts':p['samples'],'direct_failures':p['failures']}
                        self.store.db.execute('INSERT INTO wifi_history(ssid,ts,payload) VALUES (?,?,?)',(target,time.time(),json.dumps(payload)))
                if score is None or score<cfg['wifi_score_threshold'] or (old is not None and score<old+5):
                    raise WifiError('切换后的质量未达到阈值或未改善，尝试回到原 Wi-Fi')
                self.last_switch=time.time();self.bad=0
                self.message=f'已验证并保留 {target}，评分 {score} 分'
                self.store.event('wifi',('自动' if automatic else '手动')+'切换 Wi-Fi：'+(origin or '未连接')+' → '+target+f'，复测 {score} 分')
        except Exception as e:
            message=str(e) if isinstance(e,WifiError) else 'Wi-Fi 连接或验证未完成'
            if '未及时响应' in message:
                with self.monitor.lock:
                    self.monitor.cfg['wifi_auto']=False
                    self.store.save_settings(self.monitor.cfg)
                message+='；系统操作结果尚未确认，自动切 Wi-Fi 已暂停，请在 macOS 核对连接'
            elif switched:
                try:
                    # Respect a subsequent manual network selection instead of overriding it.
                    if not origin:message+='；没有可确认的原 Wi-Fi 可回退，请在 macOS 选择网络'
                    elif self.controller.state().get('ssid')==target:
                        self.controller.connect(origin,[origin,target]);message+='；已回到原 Wi-Fi'
                    elif self.controller.state().get('ssid')==origin:message+='；原 Wi-Fi 连接已保留'
                    else:message+='；检测到网络已被改动，保留当前连接'
                except Exception:message+='；自动回退未成功，请在 macOS 菜单选择原 Wi-Fi'
            self.message=message;self.blocked_until=time.time()+600;self.store.event('wifi',message)
        finally:
            self.busy=False;self.last_tick=0;self.monitor.wake.set()

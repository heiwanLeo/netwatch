import sys,time,tempfile,unittest,json,os
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from server import Store,Monitor
from quality import quality_score,metrics
from wifi import WifiManager,WifiError,WifiController

SEEDS = ["Test Wi-Fi A", "Test Wi-Fi B"]

class Native:
    def __init__(self):self.ssid=SEEDS[0];self.auth=3;self.calls=[]
    def state(self):return {'ssid':self.ssid,'authorization':self.auth,'visible':[{'ssid':SEEDS[1],'rssi':-50}]}
    def connect(self,ssid,allowed):
        if ssid not in allowed:raise WifiError('not allowed')
        self.calls.append(ssid);self.ssid=ssid

class WifiTest(unittest.TestCase):
    def setUp(self):
        self.seed_patch=patch('wifi.SEEDS', SEEDS);self.seed_patch.start()
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name)/'db')
        self.monitor=Monitor(self.store);self.native=Native()
        self.probe=lambda:{'readings':[30,40],'samples':2,'failures':0}
        self.wifi=WifiManager(self.monitor,self.tmp.name,self.probe,self.native)
    def tearDown(self):self.store.db.close();self.tmp.cleanup();self.seed_patch.stop()
    def sample(self,ssid=None):
        return {'wifi_ssid':ssid or self.native.ssid,'direct_readings':[20,30],'direct_attempts':2,'direct_failures':0}
    def test_no_identity_cannot_learn_or_switch(self):
        self.native.ssid=None;self.native.auth=0
        self.wifi.tick(self.sample('unverified'))
        self.assertEqual(len(self.wifi.view()['profiles']),2)
        with self.assertRaises(WifiError):self.wifi.start_switch(SEEDS[1])
    def test_long_good_connection_is_learned_but_not_all_saved_networks(self):
        self.native.ssid='常用网络'
        for _ in range(5):self.wifi.tick(self.sample())
        with self.store.lock,self.store.db:self.store.db.execute('UPDATE wifi_profiles SET seconds=1900 WHERE ssid=?',(self.native.ssid,))
        self.wifi.tick(self.sample())
        profile=next(p for p in self.wifi.view()['profiles'] if p['ssid']==self.native.ssid)
        self.assertTrue(profile['trusted']);self.assertEqual(profile['origin'],'learned')
    def test_manual_opt_out_is_not_automatically_readded(self):
        self.wifi.trust(SEEDS[0],False)
        with self.store.lock,self.store.db:self.store.db.execute('UPDATE wifi_profiles SET seconds=9000 WHERE ssid=?',(SEEDS[0],))
        for _ in range(6):self.wifi.tick(self.sample())
        self.assertFalse(next(p for p in self.wifi.view()['profiles'] if p['ssid']==SEEDS[0])['trusted'])
    def test_probe_from_other_wifi_is_not_attributed(self):
        self.wifi.tick(self.sample(SEEDS[1]))
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM wifi_history').fetchone()[0],0)
    def test_bad_post_switch_measurement_rolls_back(self):
        self.wifi.probe=lambda:{'readings':[],'samples':2,'failures':2}
        with patch('wifi.time.sleep'):self.wifi._switch(SEEDS[1],SEEDS[0],False)
        self.assertEqual(self.native.calls,[SEEDS[1],SEEDS[0]])
        self.assertEqual(self.native.ssid,SEEDS[0]);self.assertFalse(self.wifi.busy)
    def test_good_post_switch_is_kept(self):
        with patch('wifi.time.sleep'):self.wifi._switch(SEEDS[1],SEEDS[0],False)
        self.assertEqual(self.native.calls,[SEEDS[1]])
        self.assertGreater(self.wifi.last_switch,0)
        self.assertEqual(self.wifi.profile(SEEDS[1])[0]['samples'],6)
    def test_unknown_candidate_is_rejected(self):
        with self.assertRaises(WifiError):self.wifi.start_switch('陌生网络')
        self.assertEqual(self.native.calls,[])
    def test_dead_helper_status_is_not_treated_as_live(self):
        controller=WifiController(self.tmp.name)
        controller.write('wifi-state.json',{'ts':time.time(),'pid':99999999,'authorization':3})
        self.assertEqual(controller.state(),{})
    def test_live_helper_status_requires_a_pid(self):
        controller=WifiController(self.tmp.name)
        controller.write('wifi-state.json',{'ts':time.time(),'authorization':3})
        self.assertEqual(controller.state(),{})
        controller.write('wifi-state.json',{'ts':time.time(),'pid':os.getpid(),'authorization':3})
        self.assertEqual(controller.state()['authorization'],3)
    def test_automatic_switch_rejects_invisible_candidate(self):
        self.native.state=lambda:{'ssid':SEEDS[0],'authorization':3,'visible':[]}
        with self.assertRaises(WifiError):self.wifi.start_switch(SEEDS[1],automatic=True)
    def test_disconnected_wifi_recovers_only_after_repeated_checks_and_known_good_candidate(self):
        self.native.ssid=SEEDS[1]
        for _ in range(5):self.wifi.tick(self.sample())
        self.native.ssid=None;self.monitor.cfg['wifi_auto']=True
        with patch.object(self.wifi,'start_switch') as switch:
            for i in range(3):
                self.wifi.last_missing=0;self.wifi.on_network_unavailable()
                if i<2:switch.assert_not_called()
            switch.assert_called_once_with(SEEDS[1],automatic=True,recovery=True)
    def test_disconnected_wifi_does_not_choose_unmeasured_candidate(self):
        self.native.ssid=None;self.monitor.cfg['wifi_auto']=True
        with patch.object(self.wifi,'start_switch') as switch:
            for _ in range(4):self.wifi.last_missing=0;self.wifi.on_network_unavailable()
            switch.assert_not_called()
    def test_quality_requires_samples_and_penalizes_failures_and_jitter(self):
        self.assertIsNone(quality_score(metrics([30],1,0))['score'])
        stable=quality_score(metrics([30]*10,10,0))['score']
        unstable=quality_score(metrics([20,1500,30,1800,25],10,5))['score']
        self.assertGreater(stable,unstable)
        self.assertEqual(sum(p['weight'] for p in quality_score(metrics([],0,0))['parts']),100)

if __name__=='__main__':unittest.main()

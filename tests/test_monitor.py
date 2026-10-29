import copy
import http.client
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import Monitor, Store, UserError, should_switch, eligible_nodes, leaf_name, make_handler, tcp_direct, window_stats, aggregate, network_identity
from http.server import ThreadingHTTPServer


class FakeClash:
    def __init__(self):
        self.mode = 'global'
        self.data = {'GLOBAL': {'type': 'Selector', 'now': 'slow', 'all': ['slow','fast','dead','剩余流量：100 GB','DIRECT']},
                     'slow': {'type':'Vless'}, 'fast': {'type':'Vless'}, 'dead': {'type':'Vless'},
                     '剩余流量：100 GB': {'type':'Shadowsocks'}, 'DIRECT': {'type':'Direct'}}
        self.delays = {'fast':100, 'slow':1600, 'dead':None}
        self.writes = []
        self.change_mode_on_probe = False
    def proxies(self):
        return copy.deepcopy(self.data)
    def request(self, method, path, data=None, timeout=5):
        if path == '/configs': return {'mode': self.mode}
        if method == 'PUT':
            self.writes.append(data['name'])
            self.data['GLOBAL']['now'] = data['name']
        return {}
    def delay(self, name, url):
        if self.change_mode_on_probe: self.mode = 'direct'
        return {'delay':self.delays[name], 'checked_at':time.time(), 'error':None, 'url':url}


class MonitorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / 'db.sqlite3')
        self.clash = FakeClash()
        self.monitor = Monitor(self.store, self.clash)
        self.monitor.sync()
    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()
    def measure(self):
        for _ in range(5):
            self.store.sample({'ts':time.time(),'node':self.monitor.active,'group':'GLOBAL','vpn':2500,'direct':10,'probe_url':self.monitor.cfg['probe_url']})
        for name in self.monitor.nodes:
            self.monitor.nodes[name].update(self.clash.delay(name, self.monitor.cfg['probe_url']))
    def test_filter_metadata_and_direct(self):
        self.assertEqual(eligible_nodes(self.clash.data, 'GLOBAL'), ['slow','fast','dead'])
    def test_manual_switch_verifies_live_selection(self):
        self.assertTrue(self.monitor.switch('fast')['changed'])
        self.assertEqual(self.clash.data['GLOBAL']['now'], 'fast')
        self.assertEqual(self.monitor.active, 'fast')
        self.assertIn('slow → fast', self.store.events()[0]['message'])
    def test_failed_candidate_never_changes_route(self):
        with self.assertRaises(UserError): self.monitor.switch('dead')
        self.assertEqual(self.clash.writes, [])
    def test_foreign_node_never_changes_route(self):
        with self.assertRaises(UserError): self.monitor.switch('injected')
        self.assertEqual(self.clash.writes, [])
    def test_stale_results_cannot_select_fastest(self):
        self.measure()
        for n in self.monitor.nodes.values(): n['checked_at'] -= 181
        with self.assertRaises(UserError): self.monitor.switch()
        self.assertEqual(self.clash.writes, [])
    def test_same_node_does_not_write(self):
        self.assertFalse(self.monitor.switch('slow')['changed'])
        self.assertEqual(self.clash.writes, [])
    def test_mode_change_during_probe_cancels_switch(self):
        self.clash.change_mode_on_probe = True
        with self.assertRaises(UserError): self.monitor.switch('fast')
        self.assertEqual(self.clash.writes, [])
    def test_auto_requires_two_bad_samples(self):
        self.measure(); self.monitor.cfg['auto'] = True; self.monitor.bad_count = 1
        self.monitor.switch('fast', automatic=True)
        self.assertEqual(self.clash.writes, [])
        self.monitor.bad_count = 2
        self.monitor.switch('fast', automatic=True)
        self.assertEqual(self.clash.writes, ['fast'])
    def test_cooldown_blocks_auto_switch(self):
        self.measure(); self.monitor.cfg['auto'] = True; self.monitor.bad_count = 3
        self.monitor.last_switch = time.time()
        self.monitor.switch('fast', automatic=True)
        self.assertEqual(self.clash.writes, [])
    def test_external_node_change_resets_failure_counter(self):
        self.monitor.bad_count = 4
        self.clash.data['GLOBAL']['now'] = 'fast'
        self.monitor.sync()
        self.assertEqual(self.monitor.bad_count, 0)
    def test_settings_persist_and_invalid_values_rejected(self):
        self.monitor.update_settings({'threshold':900, 'auto':True})
        self.assertEqual(self.store.settings()['threshold'],900)
        with self.assertRaises(UserError): self.monitor.update_settings({'interval':0})
        with self.assertRaises(UserError): self.monitor.update_settings({'auto':'true'})
    def test_unknown_group_rejected(self):
        with self.assertRaises(UserError): self.monitor.update_settings({'group':'unknown'})
    def test_probe_change_during_scan_rejected(self):
        self.monitor.scan_state['running'] = True
        with self.assertRaises(UserError): self.monitor.update_settings({'probe_url':'https://www.gstatic.com/generate_204'})
    def test_scan_updates_all_nodes_and_excludes_metadata(self):
        self.monitor.start_scan()
        deadline=time.time()+3
        while self.monitor.scan_state['running'] and time.time()<deadline: time.sleep(.01)
        self.assertEqual(self.monitor.scan_state['done'],3)
        self.assertEqual(self.monitor.best()['name'],'fast')
    def test_history_roundtrip_and_switch_events(self):
        payload={'ts':time.time(),'vpn':None,'direct':8.2,'gateway':1.2,'node':'slow'}
        self.store.sample(payload)
        self.assertEqual(self.store.history(),[payload])
    def test_disabled_auto_never_changes_route(self):
        self.measure();self.monitor.bad_count=3
        self.monitor.switch('fast',automatic=True)
        self.assertEqual(self.clash.writes,[])


class PolicyTest(unittest.TestCase):
    def test_score_threshold_improvement_and_learning_guard(self):
        self.assertFalse(should_switch(60,65,2,500,300,65))
        self.assertFalse(should_switch(80,95,2,500,300,65))
        self.assertFalse(should_switch(50,60,2,500,300,65))
        self.assertFalse(should_switch(None,90,2,500,300,65))
        self.assertTrue(should_switch(50,80,2,500,300,65))
    def test_nested_leaf_and_cycle_terminate(self):
        self.assertEqual(leaf_name({'a':{'now':'b'},'b':{'type':'Vless'}},'a'),'b')
        self.assertEqual(leaf_name({'a':{'now':'b'},'b':{'now':'a'}},'a'),'a')
    def test_network_probe_requires_interface_binding(self):
        conn=MagicMock();conn.getsockopt.return_value=11;conn.getsockname.return_value=('192.168.1.2',53000)
        with patch('server.sys.platform','darwin'),patch('server.socket.socket',return_value=conn),patch('server.socket.if_nametoindex',return_value=11):
            result=tcp_direct('223.5.5.5','en0',samples=1)
        conn.setsockopt.assert_called_with(socket.IPPROTO_IP,25,11)
        conn.connect.assert_called_with(('223.5.5.5',443))
        self.assertTrue(result['bypass_tun'])
    def test_failed_binding_never_silently_uses_tun(self):
        conn=MagicMock();conn.getsockopt.return_value=0
        with patch('server.sys.platform','darwin'),patch('server.socket.socket',return_value=conn),patch('server.socket.if_nametoindex',return_value=11):
            with self.assertRaises(UserError): tcp_direct('223.5.5.5','en0',samples=1)
        conn.connect.assert_not_called()


class NetworkTest(unittest.TestCase):
    setUp = MonitorTest.setUp
    tearDown = MonitorTest.tearDown
    measure = MonitorTest.measure
    def identity(self, key, label):
        return {'id':key,'label':label,'interface':'en0','gateway':'192.168.0.1','gateway_mac':key,'ssid':None}
    def test_current_network_history_is_isolated(self):
        for key,delay in [('home',10),('office',300),('home',20)]:
            self.store.sample({'ts':time.time(),'network_id':key,'direct':delay,'vpn':100,'node':'slow','group':'GLOBAL'})
        self.monitor.set_network(self.identity('home','家里'))
        self.assertEqual([r['direct'] for r in self.monitor.view()['history']],[10,20])
        self.monitor.set_network(self.identity('office','公司'))
        self.assertEqual([r['direct'] for r in self.monitor.view()['history']],[300])
    def test_wifi_change_invalidates_old_node_measurements(self):
        self.monitor.set_network(self.identity('home','家里'));self.monitor.sync();self.measure()
        self.monitor.bad_count=3;generation=self.monitor.generation
        self.monitor.set_network(self.identity('office','公司'))
        self.assertIsNone(self.monitor.best())
        self.assertEqual(self.monitor.bad_count,0)
        self.assertGreater(self.monitor.generation,generation)
    def test_network_alias_persists_on_reconnect(self):
        identity=self.identity('home','自动识别')
        self.monitor.set_network(identity);self.monitor.rename_network('家里的 Wi-Fi')
        self.monitor.set_network(self.identity('office','公司'));self.monitor.set_network(identity)
        self.assertEqual(self.monitor.identity['label'],'家里的 Wi-Fi')
    def test_same_gateway_address_different_router_gets_different_id(self):
        def identify(mac):
            responses=[MagicMock(stdout=f'? (192.168.0.1) at {mac} on en0'),MagicMock(stdout='You are not associated with an AirPort network.')]
            with patch('server.subprocess.run',side_effect=responses):return network_identity('en0','192.168.0.1')
        self.assertNotEqual(identify('aa:bb:cc:dd:ee:01')['id'],identify('aa:bb:cc:dd:ee:02')['id'])


class StatisticsTest(unittest.TestCase):
    def test_timeouts_not_treated_as_zero_latency(self):
        s=aggregate([100,200,300],4,1)
        self.assertEqual(s['mean'],200)
        self.assertEqual(s['p95'],300)
        self.assertEqual(s['failure_rate'],25)
        self.assertEqual(s['successes'],3)
    def test_nodes_groups_urls_and_old_samples_do_not_mix(self):
        rows=[]
        for ts,node,group,url,delay in [(990,'fast','GLOBAL','https://www.google.com/generate_204',100),
            (995,'slow','GLOBAL','https://www.google.com/generate_204',900),
            (995,'fast','other','https://www.google.com/generate_204',800),
            (995,'fast','GLOBAL','https://www.gstatic.com/generate_204',700),
            (1,'fast','GLOBAL','https://www.google.com/generate_204',600)]:
            rows.append({'ts':ts,'node':node,'group':group,'probe_url':url,'vpn':delay,'direct':10})
        result=window_stats(rows,'fast','GLOBAL','https://www.google.com/generate_204',now=1000)
        self.assertEqual(result['vpn']['mean'],100)
        self.assertEqual(result['vpn']['attempts'],1)
    def test_no_data_is_not_zero_or_success(self):
        self.assertIsNone(aggregate([],0,0)['mean'])
        self.assertIsNone(aggregate([],0,0)['failure_rate'])
    def test_direct_uses_individual_tcp_attempts_and_excludes_core_downtime(self):
        rows=[{'ts':990,'direct':150,'direct_readings':[100,200],'direct_attempts':2,'direct_failures':0,
              'node':'fast','group':'GLOBAL','vpn':None,'vpn_checked':False},
              {'ts':995,'direct':None,'direct_readings':[],'direct_attempts':2,'direct_failures':2,
               'node':'fast','group':'GLOBAL','vpn':None,'vpn_checked':True}]
        s=window_stats(rows,'fast','GLOBAL','https://www.google.com/generate_204',now=1000)
        self.assertEqual(s['direct']['mean'],150)
        self.assertEqual(s['direct']['failure_rate'],50)
        self.assertEqual(s['vpn']['attempts'],1)
        self.assertEqual(s['vpn']['failure_rate'],100)


class HTTPTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name)/'test.sqlite3')
        self.monitor=Monitor(self.store,FakeClash());self.monitor.sync()
        self.server=ThreadingHTTPServer(('127.0.0.1',0),http.client.HTTPConnection)
        self.port=self.server.server_port
        self.server.RequestHandlerClass=make_handler(self.monitor,self.port)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.store.db.close();self.tmp.cleanup()
    def request(self,method,path,data=None,headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.port)
        c.request(method,path,body=json.dumps(data) if data is not None else None,headers=headers or {})
        r=c.getresponse();status=r.status;raw=r.read();c.close();return status,json.loads(raw)
    def test_missing_token_and_foreign_origin_block_mutation(self):
        status,state=self.request('GET','/api/state');self.assertEqual(status,200)
        status,_=self.request('POST','/api/switch',{'name':'fast'});self.assertEqual(status,403)
        status,_=self.request('POST','/api/switch',{'name':'fast'},{'X-Netwatch-Token':state['token'],'Origin':'https://untrusted.test'})
        self.assertEqual(status,403)
        self.assertEqual(self.monitor.clash.writes,[])
    def test_authenticated_switch_and_invalid_host(self):
        _,state=self.request('GET','/api/state')
        status,result=self.request('POST','/api/switch',{'name':'fast'},{'X-Netwatch-Token':state['token']})
        self.assertEqual(status,200);self.assertTrue(result['changed'])
        status,_=self.request('GET','/api/state',headers={'Host':'untrusted.test'})
        self.assertEqual(status,403)

if __name__ == '__main__': unittest.main()

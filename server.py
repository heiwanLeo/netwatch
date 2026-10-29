#!/usr/bin/env python3
"""Netwatch: local macOS network probes and Mihomo node selection. Standard library only."""
import argparse
import concurrent.futures
import copy
import http.client
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlencode, urlsplit
from quality import quality_score, node_estimate, should_switch
from wifi import WifiManager, WifiError

ROOT = Path(__file__).resolve().parent
DEFAULTS = {"auto": False, "threshold": 1000, "interval": 15, "cooldown": 300,
            "group": "", "probe_url": "https://www.google.com/generate_204",
            "vpn_score_threshold": 65, "wifi_auto": False, "wifi_score_threshold": 65,
            "wifi_cooldown": 600, "learn_minutes": 30}
URLS = {"https://www.google.com/generate_204", "https://www.gstatic.com/generate_204",
        "https://cp.cloudflare.com/generate_204"}
NON_NODES = {"Direct", "Reject", "RejectDrop", "Pass", "Compatible", "DNS", "Selector",
             "URLTest", "Fallback", "LoadBalance", "Relay"}
METADATA = re.compile(r"剩余|流量|到期|套餐|官网|公告|订阅|网址|使用前|www\.|traffic|expire|https?://", re.I)


class UserError(Exception):
    pass


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=5):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Clash:
    def __init__(self):
        self.path = None

    def discover(self):
        candidates = [f"/var/run/clash-verge-service/users/{os.getuid()}/verge-mihomo.sock"]
        try:
            result = subprocess.run(["/bin/ps", "-ax", "-o", "command="], capture_output=True,
                                    text=True, timeout=3)
            for line in result.stdout.splitlines():
                if "verge-mihomo" in line:
                    m = re.search(r"-ext-ctl-unix\s+(.+?\.sock)(?:\s|$)", line)
                    if m:
                        candidates.append(m.group(1))
        except (OSError, subprocess.TimeoutExpired):
            pass
        cfg = Path.home() / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml"
        try:
            m = re.search(r"^external-controller-unix:\s*(.+)$", cfg.read_text(), re.M)
            if m:
                candidates.append(m.group(1).strip("'\" "))
        except OSError:
            pass
        for path in dict.fromkeys(candidates):
            if Path(path).exists():
                self.path = path
                return
        raise UserError("未找到 Clash 内核，请启动 Clash Verge 并开启服务模式。")

    def request(self, method, path, data=None, timeout=5):
        if not self.path:
            self.discover()
        conn = UnixHTTP(self.path, timeout)
        try:
            conn.request(method, path, body=json.dumps(data) if data is not None else None,
                         headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read()
            if response.status >= 400:
                raise UserError(f"Clash 接口返回 {response.status}")
            return json.loads(raw) if raw else {}
        except (OSError, http.client.HTTPException) as e:
            self.path = None
            raise UserError("Clash 暂时无法连接，稍后会自动重试。") from e
        finally:
            conn.close()

    def proxies(self):
        return self.request("GET", "/proxies")["proxies"]

    def delay(self, name, url):
        start = time.time()
        try:
            data = self.request("GET", "/proxies/" + quote(name, safe="") + "/delay?" +
                                urlencode({"url": url, "timeout": 8000}), timeout=10)
            delay = data.get("delay")
            if not isinstance(delay, (int, float)) or delay <= 0:
                raise UserError("探测超时")
            return {"delay": delay, "checked_at": start, "error": None, "url": url}
        except (UserError, ValueError):
            return {"delay": None, "checked_at": start, "error": "超时或检测目标不可达", "url": url}


def leaf_name(proxies, name):
    seen = set()
    while name in proxies and name not in seen:
        seen.add(name)
        following = proxies[name].get("now")
        if not following:
            return name
        name = following
    return name


def eligible_nodes(proxies, group):
    return [name for name in proxies.get(group, {}).get("all", [])
            if name in proxies and proxies[name].get("type") not in NON_NODES and not METADATA.search(name)]


def aggregate(values, attempts, failures):
    values = sorted(v for v in values if isinstance(v, (int, float)) and math.isfinite(v))
    return {"mean": round(statistics.mean(values), 1) if values else None,
            "min": min(values) if values else None, "max": max(values) if values else None,
            "p95": values[max(0, math.ceil(len(values) * .95) - 1)] if values else None,
            "stddev": round(statistics.pstdev(values), 1) if values else None,
            "successes": len(values), "attempts": attempts, "failures": failures,
            "failure_rate": round(failures / attempts * 100, 1) if attempts else None}


def window_stats(history, active, group, url, now=None):
    cutoff = (now or time.time()) - 900
    rows = [r for r in history if r["ts"] >= cutoff]
    direct_values, attempts, failures = [], 0, 0
    for r in rows:
        direct_values.extend(r.get("direct_readings", [r["direct"]] if r.get("direct") is not None else []))
        attempts += r.get("direct_attempts", 1)
        failures += r.get("direct_failures", int(r.get("direct") is None))
    vpn = [r for r in rows if r.get("node") == active and r.get("group") == group
           and r.get("probe_url", DEFAULTS["probe_url"]) == url and r.get("vpn_checked", True)]
    return {"window": 900, "direct": aggregate(direct_values, attempts, failures),
            "vpn": aggregate([r["vpn"] for r in vpn if r.get("vpn") is not None],
                             len(vpn), sum(r.get("vpn") is None for r in vpn))}


def default_network():
    r = subprocess.run(["/sbin/route", "-n", "get", "default"], capture_output=True, text=True, timeout=3)
    gateway = re.search(r"gateway:\s*(\S+)", r.stdout)
    iface = re.search(r"interface:\s*(\S+)", r.stdout)
    if not gateway or not iface or not iface[1].startswith("en"):
        raise UserError("未发现可用于独立直连检测的物理网卡。")
    socket.inet_aton(gateway[1])
    return iface[1], gateway[1]


def network_identity(iface, gateway):
    arp = subprocess.run(["/usr/sbin/arp", "-n", gateway], capture_output=True, text=True, timeout=3)
    mac = re.search(r"\bat\s+([0-9a-f]+(?::[0-9a-f]+){5})\b", arp.stdout, re.I)
    wifi = subprocess.run(["/usr/sbin/networksetup", "-getairportnetwork", iface], capture_output=True,
                          text=True, timeout=3)
    match = re.search(r"Current Wi-Fi Network:\s*(.+)", wifi.stdout)
    ssid = match[1].strip() if match else None
    native = read_wifi_state()
    if native.get("interface") == iface and native.get("ssid"):
        ssid = native["ssid"]
    if ssid and ("redacted" in ssid.lower() or ssid.startswith("<")):
        ssid = None
    if not mac:
        raise UserError("暂时无法识别当前网关，请在网络连接稳定后重新检测。")
    gateway_mac = ":".join(part.zfill(2).lower() for part in mac[1].split(":"))
    key = hashlib.sha256(f"{iface}|{gateway}|{gateway_mac}|{ssid or ''}".encode()).hexdigest()[:16]
    return {"id": key, "ssid": ssid, "gateway_mac": gateway_mac, "gateway": gateway,
            "interface": iface, "label": ssid or "网络 · " + gateway_mac.replace(":", "")[-6:],
            "identified_by": "ssid+gateway" if ssid else "gateway"}


def read_wifi_state():
    try:
        state = json.loads((ROOT / "data/wifi-state.json").read_text())
        if time.time() - state.get("ts", 0) >= 20 or not isinstance(state.get("pid"), int):
            return {}
        os.kill(state['pid'], 0)
        return state
    except (OSError, ValueError):
        return {}


def probe_current_wifi():
    iface, gateway = default_network()
    return tcp_direct("223.5.5.5", iface)


def tcp_direct(ip, iface, samples=2):
    values, failures = [], 0
    source = None
    for _ in range(samples):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(2.5)
        try:
            if sys.platform != "darwin":
                raise UserError("独立直连检测目前仅支持 macOS。")
            index = socket.if_nametoindex(iface)
            # macOS IP_BOUND_IF (SDK netinet/in.h): enforce the physical interface, bypass TUN routes.
            conn.setsockopt(socket.IPPROTO_IP, 25, index)
            if conn.getsockopt(socket.IPPROTO_IP, 25) != index:
                raise UserError("无法确认直连网卡绑定，已停止此探测。")
            started = time.monotonic()
            conn.connect((ip, 443))
            values.append(round((time.monotonic() - started) * 1000, 1))
            source = conn.getsockname()[0]
        except OSError:
            failures += 1
        finally:
            conn.close()
    return {"target": ip, "delay": round(statistics.median(values), 1) if values else None,
            "jitter": round(max(values) - min(values), 1) if values else None,
            "failures": failures, "samples": samples, "interface": iface,
            "source": source, "readings": values, "method": "TCP 443 · IP_BOUND_IF", "bypass_tun": True}


def gateway_ping(ip, iface):
    r = subprocess.run(["/sbin/ping", "-n", "-b", iface, "-c", "3", "-i", "0.3", "-W", "1200", "-t", "5", ip],
                       capture_output=True, text=True, timeout=7)
    values = [float(x) for x in re.findall(r"time[=<]([\d.]+)\s*ms", r.stdout)]
    loss = re.search(r"([\d.]+)% packet loss", r.stdout)
    return {"target": ip, "delay": round(statistics.mean(values), 1) if values else None,
            "jitter": round(max(values) - min(values), 1) if values else None,
            "loss": float(loss[1]) if loss else 100, "interface": iface, "method": "ICMP"}


class Store:
    def __init__(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS samples (id INTEGER PRIMARY KEY, ts REAL, payload TEXT);
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts REAL, kind TEXT, message TEXT);
            CREATE TABLE IF NOT EXISTS networks (id TEXT PRIMARY KEY, label TEXT, metadata TEXT, last_seen REAL);""")
        if "network_id" not in {row[1] for row in self.db.execute("PRAGMA table_info(samples)")}:
            self.db.execute("ALTER TABLE samples ADD COLUMN network_id TEXT")
        self.db.execute("CREATE INDEX IF NOT EXISTS samples_network ON samples(network_id, id)")
        self.db.commit()

    def settings(self):
        with self.lock:
            row = self.db.execute("SELECT value FROM settings WHERE id=1").fetchone()
        return {**DEFAULTS, **(json.loads(row[0]) if row else {})}

    def save_settings(self, cfg):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO settings VALUES (1, ?)", (json.dumps(cfg),))

    def sample(self, payload):
        with self.lock, self.db:
            self.db.execute("INSERT INTO samples(ts,payload,network_id) VALUES (?,?,?)",
                            (payload["ts"], json.dumps(payload), payload.get("network_id")))
            self.db.execute("DELETE FROM samples WHERE ts < ?", (time.time() - 7 * 86400,))

    def history(self, network_id=None):
        with self.lock:
            if network_id is None:
                rows = self.db.execute("SELECT payload FROM samples ORDER BY id DESC LIMIT 240").fetchall()
            else:
                rows = self.db.execute("SELECT payload FROM samples WHERE network_id=? ORDER BY id DESC LIMIT 240",
                                       (network_id,)).fetchall()
        return [json.loads(row[0]) for row in reversed(rows)]

    def remember_network(self, identity):
        with self.lock, self.db:
            row = self.db.execute("SELECT label FROM networks WHERE id=?", (identity["id"],)).fetchone()
            label = row[0] if row else identity["label"]
            self.db.execute("INSERT OR REPLACE INTO networks VALUES (?,?,?,?)",
                            (identity["id"], label, json.dumps(identity), time.time()))
        return {**identity, "label": label}

    def rename_network(self, identity, label):
        with self.lock, self.db:
            self.db.execute("UPDATE networks SET label=? WHERE id=?", (label, identity["id"]))

    def networks(self):
        with self.lock:
            rows = self.db.execute("SELECT id,label,last_seen FROM networks ORDER BY last_seen DESC LIMIT 50").fetchall()
        return [dict(zip(("id", "label", "last_seen"), row)) for row in rows]

    def event(self, kind, message):
        with self.lock, self.db:
            self.db.execute("INSERT INTO events(ts,kind,message) VALUES (?,?,?)", (time.time(), kind, message))
            self.db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 200)")

    def events(self):
        with self.lock:
            rows = self.db.execute("SELECT ts,kind,message FROM events ORDER BY id DESC LIMIT 20").fetchall()
        return [dict(zip(("ts", "kind", "message"), row)) for row in rows]


class Monitor:
    def __init__(self, store, clash=None):
        self.store = store
        self.clash = clash or Clash()
        self.lock = threading.RLock()
        self.action_lock = threading.RLock()
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.cfg = store.settings()
        self.nodes = {}
        self.network = {}
        self.identity = None
        self.active = None
        self.groups = []
        self.mode = None
        self.error = None
        self.connected = False
        self.bad_count = 0
        self.last_switch = 0
        self.last_scan = 0
        self.last_sample = None
        self.scan_state = {"running": False, "done": 0, "total": 0, "finished_at": None}
        self.generation = 0
        self.wifi = None

    def sync(self):
        proxies = self.clash.proxies()
        mode = self.clash.request("GET", "/configs").get("mode")
        selectors = [n for n, v in proxies.items() if v.get("type") == "Selector"]
        with self.lock:
            group = self.cfg["group"]
            if group not in selectors:
                group = "GLOBAL" if mode == "global" else next((x for x in selectors if x != "GLOBAL"), "GLOBAL")
                self.cfg["group"] = group
                self.generation += 1
                self.store.save_settings(self.cfg)
            eligible = eligible_nodes(proxies, group)
            self.nodes = {name: {"name": name, "type": proxies[name].get("type"),
                                 **self.nodes.get(name, {"delay": None, "checked_at": None, "error": None})}
                          for name in eligible}
            new_active = leaf_name(proxies, group)
            if new_active != self.active:
                self.bad_count = 0
            self.active = new_active
            self.mode = mode
            self.groups = [{"name": name, "count": len(eligible_nodes(proxies, name))} for name in selectors]
            self.connected, self.error = True, None
        return proxies

    def view(self):
        with self.lock:
            state = copy.deepcopy({"settings": self.cfg, "network": self.network, "active": self.active,
                    "nodes": list(self.nodes.values()), "groups": self.groups, "mode": self.mode,
                    "connected": self.connected, "error": self.error, "scan": self.scan_state,
                    "bad_count": self.bad_count, "last_switch": self.last_switch,
                    "last_sample": self.last_sample, "identity": self.identity})
        state["history"] = self.store.history(state["identity"]["id"]) if state["identity"] else []
        state["known_networks"] = self.store.networks()
        state["statistics"] = window_stats(state["history"], state["active"], state["settings"]["group"],
                                            state["settings"]["probe_url"])
        state["quality"] = {"direct": quality_score(state["statistics"]["direct"]),
                            "vpn": quality_score(state["statistics"]["vpn"], "vpn")}
        state["wifi"] = self.wifi.view() if self.wifi else None
        state["events"] = self.store.events()
        return state

    def set_network(self, identity):
        identity = self.store.remember_network(identity)
        with self.lock:
            previous = self.identity
            if not previous or previous["id"] != identity["id"]:
                self.nodes = {}
                self.generation += 1
                self.bad_count = 0
                self.last_scan = 0
                self.network = {}
                self.last_sample = None
                self.identity = identity
                self.store.event("network", "当前网络：" + identity["label"] + "，统计已按网络分开")
            else:
                self.identity = identity

    def rename_network(self, label):
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 40:
            raise UserError("网络名称应为 1 到 40 个字。")
        with self.lock:
            if not self.identity:
                raise UserError("尚未识别当前网络，请稍后重试。")
            label = label.strip()
            self.store.rename_network(self.identity, label)
            self.identity["label"] = label

    def update_settings(self, change):
        allowed = set(DEFAULTS)
        if not isinstance(change, dict) or set(change) - allowed:
            raise UserError("设置字段无效。")
        with self.action_lock:
            with self.lock:
                cfg = {**self.cfg, **change}
                if type(cfg["auto"]) is not bool or type(cfg["wifi_auto"]) is not bool:
                    raise UserError("自动切换设置无效。")
                for key, low, high in [("threshold", 100, 10000), ("interval", 10, 120), ("cooldown", 60, 1800),
                                      ("vpn_score_threshold", 10, 95), ("wifi_score_threshold", 10, 95),
                                      ("wifi_cooldown", 120, 3600), ("learn_minutes", 10, 1440)]:
                    if type(cfg[key]) is not int or not low <= cfg[key] <= high:
                        raise UserError(f"{key} 数值超出范围。")
                if cfg["probe_url"] not in URLS:
                    raise UserError("检测地址无效。")
                if not isinstance(cfg["group"], str) or cfg["group"] not in [g["name"] for g in self.groups]:
                    raise UserError("请选择有效的节点组。")
                changed_path = any(cfg[k] != self.cfg[k] for k in ("group", "probe_url"))
                if changed_path and self.scan_state["running"]:
                    raise UserError("测速中，请完成后再更换节点组或检测地址。")
                if changed_path:
                    self.nodes = {}
                    self.generation += 1
                    self.bad_count = 0
                if cfg["auto"] != self.cfg["auto"]:
                    self.bad_count = 0
                if cfg["wifi_auto"] and self.wifi and not self.wifi.view()["authorized"]:
                    raise UserError("请先允许 Wi-Fi 读取权限，再开启自动切换 Wi-Fi。")
                self.cfg = cfg
                self.store.save_settings(cfg)
            self.store.event("setting", "监控设置已保存，自动切换" + ("已开启" if cfg["auto"] else "已关闭"))
        self.wake.set()

    def start_scan(self):
        with self.action_lock:
            with self.lock:
                if self.scan_state["running"]:
                    return False
            self.sync()
            with self.lock:
                names = list(self.nodes)
                if not names:
                    raise UserError("此节点组没有可直接选择的节点，请选择其他节点组。")
                self.scan_state = {"running": True, "done": 0, "total": len(names), "finished_at": None}
                generation, url = self.generation, self.cfg["probe_url"]
            threading.Thread(target=self._scan, args=(names, generation, url), daemon=True).start()
        return True

    def _scan(self, names, generation, url):
        try:
            # Four workers avoid overwhelming the local Wi-Fi or subscription servers.
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures = {pool.submit(self.clash.delay, name, url): name for name in names}
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    with self.lock:
                        if self.generation != generation:
                            for queued in futures:
                                queued.cancel()
                            break
                        if self.generation == generation and futures[future] in self.nodes:
                            node = self.nodes[futures[future]]
                            if result["checked_at"] >= (node.get("checked_at") or 0):
                                node.update(result)
                        self.scan_state["done"] += 1
        except Exception:
            self.store.event("error", "节点测速中断，请重试。")
        finally:
            with self.lock:
                self.scan_state["running"] = False
                self.scan_state["finished_at"] = time.time()
                outdated = self.generation != generation
                self.last_scan = 0 if outdated else time.time()
            self.store.event("scan", "网络已变化，旧测速结果已丢弃" if outdated else "节点测速完成")
            self.wake.set()

    def best(self):
        with self.lock:
            valid = [copy.deepcopy(n) for n in self.nodes.values() if n.get("delay") is not None
                     and n.get("checked_at") and time.time() - n["checked_at"] < 180
                     and n.get("url") == self.cfg["probe_url"]]
        return min(valid, key=lambda n: n["delay"]) if valid else None

    def switch(self, name=None, automatic=False):
        with self.action_lock:
            self.sync()
            with self.lock:
                if automatic and not self.cfg["auto"]:
                    return
                if self.mode == "direct":
                    raise UserError("Clash 当前为直连模式，节点切换不会生效；请在 Clash 中选择规则或全局模式。")
                group, url, current = self.cfg["group"], self.cfg["probe_url"], self.active
                network_id = self.identity["id"] if self.identity else None
                if self.mode == "global" and group != "GLOBAL":
                    raise UserError("全局模式请选 GLOBAL 组，其他节点组不会改变全局出口。")
                if self.mode == "rule" and group == "GLOBAL":
                    raise UserError("规则模式请选择实际使用的节点组。")
                if name is None:
                    best = self.best()
                    if not best:
                        raise UserError("没有近期可用的测速结果，请先测全部节点。")
                    name = best["name"]
                if name not in self.nodes:
                    raise UserError("节点不在当前可选择的节点组中。")
                if name == current:
                    return {"changed": False, "message": "当前已经使用此节点。"}
            # Recheck immediately before changing the route; never trust a stale table entry.
            measured = self.clash.delay(name, url)
            with self.lock:
                self.nodes[name].update(measured)
                if measured["delay"] is None:
                    raise UserError("候选节点复测失败，已保留当前节点。")
                if automatic:
                    current_score = self.current_vpn_score()["score"]
                    candidate_score = node_estimate(measured["delay"])["score"]
                    if not should_switch(current_score,candidate_score,self.bad_count,
                                         time.time()-self.last_switch,self.cfg['cooldown'],self.cfg['vpn_score_threshold']):
                        return
            # Guard against a mode / selected-node change made in Clash while the probe was running.
            live = self.clash.proxies()
            live_mode = self.clash.request("GET", "/configs").get("mode")
            if network_id:
                iface, gateway = default_network()
                if network_identity(iface, gateway)["id"] != network_id:
                    raise UserError("网络已变化，请等待重新检测后再切换节点。")
            if live_mode != self.mode or leaf_name(live, group) != current or name not in eligible_nodes(live, group):
                raise UserError("Clash 出口已变化，请刷新后重试。")
            self.clash.request("PUT", "/proxies/" + quote(group, safe=""), {"name": name})
            verified = self.clash.proxies()
            if verified.get(group, {}).get("now") != name:
                raise UserError("未能确认节点切换结果，请在 Clash 中检查。")
            with self.lock:
                self.active = name
                self.last_switch, self.bad_count = time.time(), 0
            self.store.event("switch", ("自动" if automatic else "手动") + f"切换：{current} → {name}")
            self.wake.set()
            return {"changed": True, "message": "已切换并确认：" + name}

    def current_vpn_score(self):
        history = self.store.history(self.identity["id"] if self.identity else None)
        stats = window_stats(history, self.active, self.cfg["group"], self.cfg["probe_url"])
        return quality_score(stats["vpn"], "vpn")

    def cycle(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            try:
                iface, gateway = default_network()
                identity = network_identity(iface, gateway)
                self.set_network(identity)
                gw_future = pool.submit(gateway_ping, gateway, iface)
                base_futures = [pool.submit(tcp_direct, ip, iface) for ip in ["223.5.5.5", "1.12.12.12"]]
                net = {"interface": iface, "gateway": gw_future.result(),
                       "direct": [f.result() for f in base_futures], "error": None}
                end_iface, end_gateway = default_network()
                if network_identity(end_iface, end_gateway)["id"] != identity["id"]:
                    self.wake.set()
                    return
            except (OSError, UserError, subprocess.TimeoutExpired) as e:
                net = {"error": str(e) if isinstance(e, UserError) else "基础网络探测暂时失败。"}
                with self.lock:
                    if self.identity:
                        self.generation += 1
                    self.identity = None
                    self.network = net
                    self.nodes = {}
                    self.bad_count = 0
                    self.last_sample = None
                if self.wifi:
                    self.wifi.on_network_unavailable()
                return
        vpn_checked = False
        active = None
        try:
            self.sync()
            with self.lock:
                active, generation, url, sampled_group = self.active, self.generation, self.cfg["probe_url"], self.cfg["group"]
            result = self.clash.delay(active, url) if active else {"delay": None}
            vpn_checked = bool(active)
            with self.lock:
                if generation == self.generation and active == self.active:
                    if active in self.nodes:
                        node = self.nodes[active]
                        if result.get("checked_at", 0) >= (node.get("checked_at") or 0):
                            node.update(result)
                else:
                    return
        except (UserError, KeyError):
            with self.lock:
                self.connected = False
                self.error = "未连接到 Clash，基础网络检测仍在运行。"
            result = {"delay": None}
        try:
            final_iface, final_gateway = default_network()
            if network_identity(final_iface, final_gateway)["id"] != identity["id"]:
                self.wake.set()
                return
        except (OSError, UserError, subprocess.TimeoutExpired):
            self.wake.set()
            return
        with self.lock:
            self.network = net
            self.last_sample = time.time()
            primary = next(iter(net.get("direct", [])), {})
            sample = {"ts": self.last_sample, "gateway": net.get("gateway", {}).get("delay"),
                      "direct": primary.get("delay"), "direct_readings": primary.get("readings", []),
                      "direct_attempts": primary.get("samples", 0), "direct_failures": primary.get("failures", 0),
                      "vpn": result["delay"], "vpn_checked": vpn_checked, "node": active,
                      "group": sampled_group if vpn_checked else self.cfg["group"],
                      "probe_url": url if vpn_checked else self.cfg["probe_url"],
                      "network_id": self.identity["id"] if self.identity else None,
                      "wifi_ssid": self.identity.get("ssid") if self.identity else None}
        self.store.sample(sample)
        score = self.current_vpn_score()["score"]
        with self.lock:
            self.bad_count = self.bad_count + 1 if score is not None and score < self.cfg["vpn_score_threshold"] else 0
            auto = self.cfg["auto"] and self.connected and self.bad_count >= 2 and self.mode != "direct"
        if self.wifi:
            self.wifi.tick(sample)
            auto = auto and not self.wifi.busy
        if auto:
            candidate = self.best()
            if not candidate or candidate["name"] == self.active:
                if time.time() - self.last_scan > 90:
                    self.start_scan()
            else:
                self.switch(candidate["name"], automatic=True)

    def run(self):
        while not self.stop.is_set():
            self.wake.clear()
            try:
                self.cycle()
            except Exception as e:
                with self.lock:
                    self.error = str(e) if isinstance(e, UserError) else "检测暂时中断，下一轮会自动重试。"
            with self.lock:
                interval = self.cfg["interval"]
            self.wake.wait(interval)


def make_handler(monitor, port):
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            if len(args) > 1 and str(args[1]).startswith("5"):
                super().log_message(fmt, *args)

        def respond(self, status, payload, content_type="application/json; charset=utf-8"):
            body = json.dumps(payload, ensure_ascii=False).encode() if isinstance(payload, (dict, list)) else payload
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def valid_host(self):
            return self.headers.get("Host") in {f"127.0.0.1:{port}", f"localhost:{port}"}

        def do_GET(self):
            if not self.valid_host():
                return self.respond(403, {"error": "仅允许本机访问。"})
            path = urlsplit(self.path).path
            if path == "/api/state":
                return self.respond(200, {**monitor.view(), "token": token})
            files = {"/": ("index.html", "text/html; charset=utf-8"),
                     "/app.js": ("app.js", "application/javascript; charset=utf-8"),
                     "/style.css": ("style.css", "text/css; charset=utf-8"),
                     "/favicon.svg": ("favicon.svg", "image/svg+xml")}
            if path not in files:
                return self.respond(404, {"error": "页面不存在。"})
            name, mime = files[path]
            self.respond(200, (ROOT / "static" / name).read_bytes(), mime)

        def do_POST(self):
            if not self.valid_host():
                return self.respond(403, {"error": "仅允许本机访问。"})
            if self.headers.get("Origin") not in {None, f"http://127.0.0.1:{port}", f"http://localhost:{port}"}:
                return self.respond(403, {"error": "请求来源无效。"})
            if not secrets.compare_digest(self.headers.get("X-Netwatch-Token", ""), token):
                return self.respond(403, {"error": "请刷新页面后重试。"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                if not 0 <= length <= 8192:
                    raise UserError("请求过大。")
                data = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(data, dict):
                    raise UserError("请求格式错误。")
                path = urlsplit(self.path).path
                if path == "/api/scan":
                    monitor.start_scan()
                    result = {"message": "测速已开始。"}
                elif path == "/api/switch":
                    name = data.get("name")
                    if name is not None and not isinstance(name, str):
                        raise UserError("节点名称无效。")
                    result = monitor.switch(name)
                elif path == "/api/settings":
                    monitor.update_settings(data)
                    result = {"message": "设置已保存。"}
                elif path == "/api/refresh":
                    monitor.wake.set()
                    result = {"message": "正在重新检测。"}
                elif path == "/api/network-name":
                    monitor.rename_network(data.get("label"))
                    result = {"message": "当前网络名称已保存。"}
                elif path.startswith("/api/wifi/"):
                    if not monitor.wifi:
                        raise UserError("Wi-Fi 模块尚未启动。")
                    action = path.rsplit("/", 1)[-1]
                    if action == "authorize":
                        monitor.wifi.controller.start(authorize=True)
                        result = {"message": "请在 macOS 提示中允许 Netwatch Wi-Fi 读取 Wi-Fi 信息。"}
                    elif action == "switch":
                        monitor.wifi.start_switch(data.get("ssid"))
                        result = {"message": "正在连接并验证 Wi-Fi，若质量变差会尝试回退。"}
                    elif action == "trust":
                        monitor.wifi.trust(data.get("ssid"), data.get("trusted"))
                        result = {"message": "候选网络设置已保存。"}
                    elif action == "scan":
                        monitor.wifi.controller.command("scan")
                        result = {"message": "已请求扫描附近 Wi-Fi。"}
                    else:
                        raise UserError("未知 Wi-Fi 操作。")
                else:
                    return self.respond(404, {"error": "接口不存在。"})
                self.respond(200, result or {"message": "当前无需切换。"})
            except (UserError, WifiError, ValueError, TypeError) as e:
                self.respond(400, {"error": str(e) if isinstance(e, (UserError, WifiError)) else "请求格式错误。"})
            except Exception:
                self.respond(503, {"error": "操作暂未完成，请稍后重试。"})

    return Handler


def main():
    parser = argparse.ArgumentParser(description="Netwatch 本机网络与 VPN 延迟监控")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    args = parser.parse_args()
    monitor = Monitor(Store(args.data_dir / "netwatch.sqlite3"))
    monitor.wifi = WifiManager(monitor, ROOT, probe_current_wifi)
    try:
        monitor.wifi.controller.start()
    except (OSError, WifiError, subprocess.SubprocessError):
        pass
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(monitor, args.port))
    server.daemon_threads = True
    threading.Thread(target=monitor.run, daemon=True).start()
    print(f"Netwatch 已启动：http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop.set()
        monitor.wake.set()
        server.server_close()


if __name__ == "__main__":
    main()

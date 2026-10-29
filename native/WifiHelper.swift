import Cocoa
import CoreWLAN
import CoreLocation

final class WifiHelper: NSObject, NSApplicationDelegate, CLLocationManagerDelegate {
    let location = CLLocationManager()
    let queue = DispatchQueue(label: "netwatch.wifi")
    var timer: Timer?
    var lastCommand = ""
    var visible: [[String: Any]] = []
    var lastScan: Double = 0
    var dataDir: URL {
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--data"), i + 1 < args.count {
            return URL(fileURLWithPath: args[i + 1], isDirectory: true)
        }
        return Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("data")
    }
    func write(_ name: String, _ value: [String: Any]) {
        if let data = try? JSONSerialization.data(withJSONObject: value) {
            try? data.write(to: dataDir.appendingPathComponent(name), options: .atomic)
        }
    }
    func read(_ name: String) -> [String: Any] {
        guard let data = try? Data(contentsOf: dataDir.appendingPathComponent(name)),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return obj
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        try? FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        location.delegate = self
        if CommandLine.arguments.contains("--authorize") { location.requestWhenInUseAuthorization() }
        tick()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { _ in self.tick() }
    }
    func application(_ application: NSApplication, open urls: [URL]) {
        if urls.contains(where: { $0.host == "authorize" }) { location.requestWhenInUseAuthorization() }
    }
    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) { tick() }
    func tick() {
        let auth = location.authorizationStatus.rawValue
        queue.async {
            let client = CWWiFiClient.shared()
            guard let iface = client.interface() else {
                self.write("wifi-state.json", ["ts": Date().timeIntervalSince1970, "pid": ProcessInfo.processInfo.processIdentifier, "authorization": auth, "error": "没有 Wi-Fi 网卡"])
                return
            }
            let command = self.read("wifi-command.json")
            let id = command["id"] as? String ?? ""
            if !id.isEmpty && id != self.lastCommand && (self.read("wifi-result.json")["id"] as? String) != id {
                self.lastCommand = id
                let issued = command["issued_at"] as? Double ?? 0
                let action = command["action"] as? String ?? ""
                if Date().timeIntervalSince1970 - issued > 60 {
                    self.write("wifi-result.json", ["id": id, "ok": false, "error": "命令已过期"])
                } else if action == "authorize" {
                    DispatchQueue.main.async { self.location.requestWhenInUseAuthorization() }
                    self.write("wifi-result.json", ["id": id, "ok": true])
                } else if action == "connect", let ssid = command["ssid"] as? String {
                    let allowed = self.read("wifi-allowed.json")["ssids"] as? [String] ?? []
                    if !allowed.contains(ssid) || !(auth == 3 || auth == 4) {
                        self.write("wifi-result.json", ["id": id, "ok": false, "error": "网络不在候选列表中，或 Wi-Fi 读取权限尚未允许"])
                    } else {
                        do {
                            let found = try iface.scanForNetworks(withName: ssid)
                            guard let network = found.max(by: { $0.rssiValue < $1.rssiValue }) else {
                                self.write("wifi-result.json", ["id": id, "ok": false, "error": "候选 Wi-Fi 当前不可见，请确认热点已开启"])
                                self.refresh(iface, auth: auth); return
                            }
                            var passphrase: NSString?
                            if let ssidData = ssid.data(using: .utf8) {
                                var status = CWKeychainFindWiFiPassword(.user, ssidData, &passphrase)
                                if status != 0 { status = CWKeychainFindWiFiPassword(.system, ssidData, &passphrase) }
                                // The passphrase stays in memory and is never written to files or logs.
                            }
                            try iface.associate(to: network, password: passphrase as String?)
                            passphrase = nil
                            self.write("wifi-result.json", ["id": id, "ok": iface.ssid() == ssid,
                                                             "error": iface.ssid() == ssid ? "" : "未确认连接到目标网络"])
                        } catch {
                            self.write("wifi-result.json", ["id": id, "ok": false,
                                                             "error": "系统未能连接该网络；请先在 macOS 中连接一次并保存密码。必要时允许系统钥匙串提示。"])
                        }
                    }
                } else if action == "scan" {
                    self.lastScan = 0
                    self.write("wifi-result.json", ["id": id, "ok": true])
                }
            }
            self.refresh(iface, auth: auth)
        }
    }
    func refresh(_ iface: CWInterface, auth: Int32) {
        let now = Date().timeIntervalSince1970
        if (auth == 3 || auth == 4) && now - lastScan > 60 {
            lastScan = now
            if let networks = try? iface.scanForNetworks(withSSID: nil) {
                var best: [String: Int] = [:]
                for n in networks { if let name = n.ssid { best[name] = max(best[name] ?? -110, n.rssiValue) } }
                visible = best.map { ["ssid": $0.key, "rssi": $0.value] }
            }
        }
        var state: [String: Any] = ["ts": now, "pid": ProcessInfo.processInfo.processIdentifier, "authorization": auth, "interface": iface.interfaceName ?? "en0",
                                    "rssi": iface.rssiValue(), "noise": iface.noiseMeasurement(),
                                    "tx_rate": iface.transmitRate(), "visible": visible, "scan_ts": lastScan]
        if let name = iface.ssid() { state["ssid"] = name }
        write("wifi-state.json", state)
    }
}
let app = NSApplication.shared
let helper = WifiHelper()
app.setActivationPolicy(.accessory)
app.delegate = helper
app.run()

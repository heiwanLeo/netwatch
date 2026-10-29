#!/usr/bin/env python3
from pathlib import Path
import plistlib, subprocess
root=Path(__file__).resolve().parent
app=root/'Netwatch Wi-Fi.app'
binary=app/'Contents/MacOS/NetwatchWifi'
binary.parent.mkdir(parents=True,exist_ok=True)
plist={'CFBundleIdentifier':'local.netwatch.wifi','CFBundleName':'Netwatch Wi-Fi','CFBundleDisplayName':'Netwatch Wi-Fi',
       'CFBundleExecutable':'NetwatchWifi','CFBundlePackageType':'APPL','CFBundleVersion':'1','LSUIElement':True,
       'NSLocationUsageDescription':'用于识别当前 Wi-Fi、比较网络质量并在你设定的候选网络之间切换。不会记录或上传地理位置。',
       'NSLocationWhenInUseUsageDescription':'读取 Wi-Fi 名称与信号，以便区分网络并执行你设置的自动切换。不会请求坐标。',
       'CFBundleURLTypes':[{'CFBundleURLName':'NetwatchWifi','CFBundleURLSchemes':['netwatch-wifi']}]}
with (app/'Contents/Info.plist').open('wb') as f:plistlib.dump(plist,f)
subprocess.run(['/usr/bin/swiftc',str(root/'WifiHelper.swift'),'-o',str(binary),'-framework','Cocoa','-framework','CoreWLAN','-framework','CoreLocation'],check=True)
subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(app)],check=True)
print('Wi-Fi helper built:',app)

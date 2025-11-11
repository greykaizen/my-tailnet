#!/bin/bash
# Boot Notification Script for Linux
# Sends system information to Telegram on boot

set -e

# Configuration (will be replaced by Ansible template)
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID}"

# Gather system information
HOSTNAME=$(hostname)
OS_TYPE="Linux"
OS_VERSION=$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
UPTIME=$(uptime -p)

# Get IP addresses
IP_ADDRESSES=$(ip -4 addr show | grep inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d'/' -f1 | tr '\n' ', ' | sed 's/,$//')

# Get Tailscale status
if command -v tailscale &> /dev/null; then
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "Not connected")
    TAILSCALE_STATUS=$(tailscale status --json 2>/dev/null | grep -o '"Self":{[^}]*}' | grep -o '"Online":[^,]*' | cut -d':' -f2 || echo "false")
    if [ "$TAILSCALE_STATUS" = "true" ]; then
        TAILSCALE_STATUS="✅ Online"
    else
        TAILSCALE_STATUS="❌ Offline"
    fi
else
    TAILSCALE_IP="Not installed"
    TAILSCALE_STATUS="❌ Not installed"
fi

# Get hardware information
CPU_COUNT=$(nproc)
RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}')

# Get current user
CURRENT_USER=$(whoami)

# Build notification message
MESSAGE="🖥️ *System Boot Notification*

*Hostname:* \`${HOSTNAME}\`
*OS:* ${OS_TYPE} - ${OS_VERSION}
*Uptime:* ${UPTIME}

*Network Information:*
• IP Addresses: ${IP_ADDRESSES}
• Tailscale IP: ${TAILSCALE_IP}
• Tailscale Status: ${TAILSCALE_STATUS}

*Hardware:*
• CPU Cores: ${CPU_COUNT}
• RAM: ${RAM_GB} GB
• Disk Usage: ${DISK_USAGE}

*Boot User:* ${CURRENT_USER}
*Timestamp:* $(date '+%Y-%m-%d %H:%M:%S %Z')"

# Send to Telegram
curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d text="${MESSAGE}" \
    -d parse_mode="Markdown" \
    > /dev/null 2>&1

exit 0

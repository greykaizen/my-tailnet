# Boot Notification Script for Windows
# Sends system information to Telegram on boot

# Configuration (will be replaced by Ansible)
$TelegramBotToken = "$TELEGRAM_BOT_TOKEN"
$TelegramChatId = "$TELEGRAM_CHAT_ID"

# Gather system information
$Hostname = $env:COMPUTERNAME
$OSType = "Windows"
$OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
$Uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$UptimeFormatted = "{0} days, {1} hours, {2} minutes" -f $Uptime.Days, $Uptime.Hours, $Uptime.Minutes

# Get IP addresses
$IPAddresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" }).IPAddress -join ", "

# Get Tailscale status
try {
    $TailscaleIP = & tailscale ip -4 2>$null
    $TailscaleStatus = & tailscale status --json 2>$null | ConvertFrom-Json
    if ($TailscaleStatus.Self.Online) {
        $TailscaleStatusText = "✅ Online"
    } else {
        $TailscaleStatusText = "❌ Offline"
    }
} catch {
    $TailscaleIP = "Not installed"
    $TailscaleStatusText = "❌ Not installed"
}

# Get hardware information
$CPUCount = (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors
$RAMBytes = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
$RAMGB = [math]::Round($RAMBytes / 1GB, 2)
$DiskC = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$DiskUsagePercent = [math]::Round((($DiskC.Size - $DiskC.FreeSpace) / $DiskC.Size) * 100, 1)

# Get current user
$CurrentUser = $env:USERNAME

# Get Windows version details
$WindowsBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
$WindowsVersion = (Get-CimInstance Win32_OperatingSystem).Version

# Build notification message
$Message = @"
🖥️ *System Boot Notification*

*Hostname:* ``$Hostname``
*OS:* $OSType - $OSVersion
*Build:* $WindowsBuild (Version $WindowsVersion)
*Uptime:* $UptimeFormatted

*Network Information:*
• IP Addresses: $IPAddresses
• Tailscale IP: $TailscaleIP
• Tailscale Status: $TailscaleStatusText

*Hardware:*
• CPU Cores: $CPUCount
• RAM: $RAMGB GB
• Disk C: Usage: $DiskUsagePercent%

*Boot User:* $CurrentUser
*Timestamp:* $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')
"@

# Send to Telegram
$TelegramApiUrl = "https://api.telegram.org/bot$TelegramBotToken/sendMessage"
$Body = @{
    chat_id = $TelegramChatId
    text = $Message
    parse_mode = "Markdown"
}

try {
    Invoke-RestMethod -Uri $TelegramApiUrl -Method Post -Body $Body -ErrorAction Stop | Out-Null
    Write-Host "Boot notification sent successfully"
} catch {
    Write-Error "Failed to send boot notification: $_"
    exit 1
}

exit 0

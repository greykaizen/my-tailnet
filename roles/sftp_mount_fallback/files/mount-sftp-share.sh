#!/bin/bash
# SFTP Mount Helper Script
# Usage: mount-sftp-share.sh <username>

set -e

# Configuration
SFTP_SERVER="lab-windows"
REMOTE_PATH="/TeamShare"
MOUNT_BASE="$HOME/TeamShare-sftp"

# Check arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 <username>"
    echo "Example: $0 alice"
    exit 1
fi

USERNAME="$1"

# Check if sshfs is installed
if ! command -v sshfs &> /dev/null; then
    echo "Error: sshfs is not installed"
    echo "Install with: sudo apt-get install sshfs (Debian/Ubuntu) or sudo yum install fuse-sshfs (RHEL/CentOS)"
    exit 1
fi

# Check if SSH key exists
SSH_KEY="$HOME/.ssh/id_ed25519"
if [ ! -f "$SSH_KEY" ]; then
    echo "Error: SSH key not found at $SSH_KEY"
    echo "Generate one with: ssh-keygen -t ed25519"
    exit 1
fi

# Create mount point
mkdir -p "$MOUNT_BASE"

# Check if already mounted
if mountpoint -q "$MOUNT_BASE" 2>/dev/null; then
    echo "SFTP share is already mounted at $MOUNT_BASE"
    exit 0
fi

# Mount via SFTP
echo "Mounting SFTP share for user $USERNAME..."
sshfs "${USERNAME}@${SFTP_SERVER}:${REMOTE_PATH}" "$MOUNT_BASE" \
    -o reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,follow_symlinks

if [ $? -eq 0 ]; then
    echo "Successfully mounted SFTP share at $MOUNT_BASE"
    echo "To unmount: umount-sftp-share.sh"
else
    echo "Failed to mount SFTP share"
    exit 1
fi

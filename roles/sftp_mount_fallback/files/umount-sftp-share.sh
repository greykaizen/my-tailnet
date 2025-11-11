#!/bin/bash
# SFTP Unmount Helper Script
# Usage: umount-sftp-share.sh

set -e

# Configuration
MOUNT_BASE="$HOME/TeamShare-sftp"

# Check if mounted
if ! mountpoint -q "$MOUNT_BASE" 2>/dev/null; then
    echo "SFTP share is not mounted at $MOUNT_BASE"
    exit 0
fi

# Unmount
echo "Unmounting SFTP share from $MOUNT_BASE..."
fusermount -u "$MOUNT_BASE"

if [ $? -eq 0 ]; then
    echo "Successfully unmounted SFTP share"
else
    echo "Failed to unmount SFTP share"
    exit 1
fi

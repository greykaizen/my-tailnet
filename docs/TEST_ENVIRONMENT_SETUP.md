# Test Environment Setup Guide

This guide explains how to set up a complete test environment for validating the Tailnet automation system before deploying to production.

## Overview

The test environment consists of:
- **Test Windows VM**: Windows 10/11 or Windows Server 2019+
- **Test Linux VM**: Ubuntu 20.04+ or similar
- **Test Tailscale Network**: Isolated tailnet for testing
- **Test Vault**: Sample user accounts and credentials

## Prerequisites

### Required Software

1. **Virtualization Platform** (choose one):
   - VirtualBox (free, cross-platform)
   - VMware Workstation/Fusion
   - Hyper-V (Windows)
   - KVM/QEMU (Linux)

2. **VM Images**:
   - Windows 10/11 or Windows Server 2019+ ISO
   - Ubuntu 20.04+ Server ISO

3. **Network Configuration**:
   - NAT or Bridged networking for internet access
   - Static IP addresses for consistent connectivity

## Step 1: Create Test VMs

### Windows Test VM

**Minimum Specifications**:
- 2 CPU cores
- 4 GB RAM
- 60 GB disk space
- Network adapter with internet access

**Installation Steps**:
1. Create new VM with Windows ISO
2. Install Windows with default settings
3. Set hostname to `test-windows`
4. Configure static IP: `192.168.1.100` (adjust for your network)
5. Enable Remote Desktop (optional, for troubleshooting)
6. Create Administrator account with password: `WindowsAdmin123!`

**Post-Installation**:
```powershell
# Run in PowerShell as Administrator

# Set static IP (adjust for your network)
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.1.100 -PrefixLength 24 -DefaultGateway 192.168.1.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8,8.8.4.4

# Enable WinRM for initial provisioning
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Install OpenSSH (required for Ansible)
winget install --id Microsoft.OpenSSH.Beta --silent --accept-package-agreements --accept-source-agreements

# Start SSH service
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# Create D: drive for shared folder (if not exists)
# Use Disk Management to create partition or use existing drive
```

### Linux Test VM

**Minimum Specifications**:
- 2 CPU cores
- 2 GB RAM
- 40 GB disk space
- Network adapter with internet access

**Installation Steps**:
1. Create new VM with Ubuntu Server ISO
2. Install Ubuntu with OpenSSH server selected
3. Set hostname to `test-linux`
4. Configure static IP: `192.168.1.101` (adjust for your network)
5. Create user account: `ubuntu` with sudo access

**Post-Installation**:
```bash
# Set static IP (adjust for your network)
sudo nano /etc/netplan/00-installer-config.yaml

# Add configuration:
network:
  ethernets:
    ens33:  # Adjust interface name
      addresses:
        - 192.168.1.101/24
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
  version: 2

# Apply network configuration
sudo netplan apply

# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-pip
```

## Step 2: Configure Test Tailscale Network

### Create Test Tailnet

1. Go to https://login.tailscale.com/
2. Create a new account or use existing (separate from production)
3. Navigate to Settings → Keys
4. Generate a new auth key:
   - Check "Reusable"
   - Check "Ephemeral" (optional, for testing)
   - Set expiration to 90 days
   - Copy the key (starts with `tskey-auth-`)

5. Update `vars/vault_test.yml` with the auth key:
```yaml
tailscale_authkey: "tskey-auth-YOUR-KEY-HERE"
```

### Configure Test Telegram Bot (Optional)

If testing boot notifications:

1. Create test Telegram bot:
   - Message @BotFather on Telegram
   - Send `/newbot` and follow prompts
   - Copy bot token

2. Get chat ID:
   - Create test group or use personal chat
   - Add bot to group
   - Send message to bot
   - Visit: `https://api.telegram.org/bot<TOKEN>/getUpdates`
   - Copy chat ID from response

3. Update `vars/vault_test.yml`:
```yaml
telegram_bot_token: "YOUR-BOT-TOKEN"
telegram_chat_id: "YOUR-CHAT-ID"
```

## Step 3: Configure Ansible Controller

### Install Ansible

```bash
# On Ubuntu/Debian
sudo apt update
sudo apt install -y ansible

# On macOS
brew install ansible

# Verify installation
ansible --version
```

### Configure SSH Access

```bash
# Generate test SSH key
ssh-keygen -t ed25519 -f ~/.ssh/ansible_test_key -N ""

# Copy public key to test VMs
ssh-copy-id -i ~/.ssh/ansible_test_key.pub ubuntu@192.168.1.101

# For Windows, manually copy public key (after OpenSSH is installed):
# Create directory: C:\Users\Administrator\.ssh\
# Copy content of ~/.ssh/ansible_test_key.pub to C:\Users\Administrator\.ssh\authorized_keys
```

### Encrypt Test Vault

```bash
# Encrypt the test vault file
ansible-vault encrypt vars/vault_test.yml

# When prompted, enter password: test123

# Create vault password file for convenience (DO NOT use in production)
echo "test123" > .vault_pass_test
chmod 600 .vault_pass_test

# Add to .gitignore
echo ".vault_pass_test" >> .gitignore
```

## Step 4: Validate Test Environment

### Test Connectivity

```bash
# Test SSH to Linux
ansible -i inventory/test/hosts.ini linux_group -m ping

# Test SSH to Windows
ansible -i inventory/test/hosts.ini windows_group -m ping

# Test all hosts
ansible -i inventory/test/hosts.ini all -m ping --ask-vault-pass
```

### Run Preflight Checks

```bash
# Run preflight validation
ansible-playbook playbooks/preflight-checks.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test
```

## Step 5: Test Deployment

### Initial Deployment

```bash
# Run full deployment to test environment
ansible-playbook playbooks/setup-all.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"
```

### Validate Deployment

```bash
# Run ACL validation
ansible-playbook playbooks/validate-acls.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test

# Test user accounts
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "Get-LocalUser" \
  --vault-password-file .vault_pass_test

ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "cat /etc/passwd | grep testuser" \
  --vault-password-file .vault_pass_test
```

## Test Scenarios

### Scenario 1: User Account Creation

**Objective**: Verify cross-platform user creation

**Steps**:
1. Run user creation playbooks
2. Verify users exist on both systems
3. Test password authentication
4. Verify UID consistency

**Validation**:
```bash
# Check Windows users
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "Get-LocalUser testuser1"

# Check Linux users
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "id testuser1"
```

### Scenario 2: File Sharing

**Objective**: Verify SMB share and mount functionality

**Steps**:
1. Create shared folder on Windows
2. Mount share on Linux
3. Test file creation and permissions
4. Verify SFTP fallback

**Validation**:
```bash
# Check SMB share on Windows
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "Get-SmbShare TeamShare"

# Check mount on Linux
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "mount | grep TeamShare"

# Test file operations
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "touch /mnt/TeamShare/test.txt && ls -la /mnt/TeamShare/test.txt"
```

### Scenario 3: Tailscale Integration

**Objective**: Verify Tailscale installation and SSH access

**Steps**:
1. Install Tailscale on both systems
2. Verify devices appear in tailnet
3. Test SSH over Tailscale
4. Verify network isolation

**Validation**:
```bash
# Check Tailscale status
ansible -i inventory/test/hosts.ini all \
  -m shell -a "tailscale status"

# Test SSH over Tailscale IP
ssh -i ~/.ssh/ansible_test_key testuser1@100.x.x.x
```

### Scenario 4: Idempotence Testing

**Objective**: Verify playbooks can be re-run safely

**Steps**:
1. Run full deployment
2. Capture system state
3. Re-run deployment
4. Verify no changes occurred

**Validation**:
```bash
# Run deployment twice
ansible-playbook playbooks/setup-all.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  --check --diff

# Should show no changes on second run
```

## Cleanup

### Remove Test Environment

```bash
# Remove Tailscale devices
tailscale logout  # On each test VM

# Delete VMs
# Use your virtualization platform's tools

# Clean up test files
rm -f .vault_pass_test
rm -rf inventory/test/
```

### Reset for New Test

```bash
# Decrypt and re-encrypt vault with new password
ansible-vault decrypt vars/vault_test.yml
ansible-vault encrypt vars/vault_test.yml

# Regenerate SSH keys
rm ~/.ssh/ansible_test_key*
ssh-keygen -t ed25519 -f ~/.ssh/ansible_test_key -N ""
```

## Troubleshooting

### Windows SSH Connection Issues

```powershell
# Check SSH service status
Get-Service sshd

# Check firewall rules
Get-NetFirewallRule -Name *ssh*

# Test SSH locally
ssh localhost

# Check SSH logs
Get-EventLog -LogName Application -Source sshd -Newest 20
```

### Linux Mount Issues

```bash
# Check CIFS utilities
dpkg -l | grep cifs-utils

# Test manual mount
sudo mount -t cifs //test-windows/TeamShare /mnt/TeamShare \
  -o username=smbmount,password=SmbMount123!,vers=3.0

# Check mount logs
sudo journalctl -u mnt-TeamShare.mount
```

### Ansible Connection Issues

```bash
# Increase verbosity
ansible -i inventory/test/hosts.ini all -m ping -vvv

# Test raw SSH
ssh -i ~/.ssh/ansible_test_key ansible_admin@192.168.1.100

# Check Ansible configuration
ansible-config dump --only-changed
```

## Best Practices

1. **Isolate Test Environment**: Use separate network/VLAN from production
2. **Snapshot VMs**: Take snapshots before major changes
3. **Document Changes**: Keep notes on test results and issues
4. **Test Incrementally**: Test each component before full deployment
5. **Validate Security**: Ensure test credentials never reach production
6. **Clean Up**: Remove test resources after validation

## Next Steps

After successful test environment validation:

1. Review test results and fix any issues
2. Update production inventory with actual host details
3. Create production vault with real credentials
4. Run preflight checks on production systems
5. Execute production deployment with monitoring
6. Validate production deployment with ACL checks

## References

- [Ansible Testing Strategies](https://docs.ansible.com/ansible/latest/reference_appendices/test_strategies.html)
- [Tailscale Testing](https://tailscale.com/kb/1019/subnets/)
- [Windows OpenSSH Setup](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)

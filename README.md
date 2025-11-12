# my-tailnet

Automated dual-boot lab PC setup with cross-platform user management, Tailscale remote access, and hybrid file sharing.

## Overview

Infrastructure as Code solution using Ansible to automate Windows/Linux dual-boot lab environments with:

- **Cross-platform user management** - Synchronized accounts across Windows and Linux
- **Tailscale VPN integration** - Secure mesh networking with SSH access
- **Hybrid file sharing** - SMB (primary) + SFTP (fallback) over Tailscale
- **Security hardening** - Individual user accounts, encrypted SMB 3.0, firewall restrictions
- **Boot notifications** - Telegram alerts when systems come online

## Quick Start

### Prerequisites

1. **Windows PC** - Dual-boot with Windows 10 (1809+) or Windows Server 2019+
2. **Linux PC** - Dual-boot with SSH access
3. **Tailscale account** - Auth key from https://login.tailscale.com/admin/settings/keys
4. **Telegram bot** (optional) - For boot notifications

### Initial Setup

1. **Bootstrap OpenSSH on Windows** (one-time, manual):
```powershell
# Run in PowerShell as Administrator
# Option 1: Install via winget (recommended - gets latest version)
winget install --id Microsoft.OpenSSH.Beta --silent --accept-package-agreements --accept-source-agreements

# Option 2: Fallback to Windows Optional Features if winget unavailable
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Start and enable SSH service
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# Configure firewall
New-NetFirewallRule -DisplayName "OpenSSH" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22
```

After manual bootstrap, verify SSH connectivity:
```bash
ansible-playbook playbooks/setup-openssh-bootstrap.yml -i inventory/hosts.ini
```

2. **Configure inventory and vault**:
```bash
# Copy example files
cp .vault_pass.example .vault_pass
# Edit .vault_pass with your vault password

# Edit inventory with your host IPs
vim inventory/hosts.ini

# Create/edit encrypted vault with user accounts
ansible-vault edit vars/vault.yml
```

3. **Run deployment**:
```bash
# Validate environment first
ansible-playbook playbooks/preflight-checks.yml -i inventory/hosts.ini --ask-vault-pass

# Deploy everything
ansible-playbook playbooks/setup-all.yml -i inventory/hosts.ini --ask-vault-pass

# Validate ACL idempotence
ansible-playbook playbooks/validate-acls.yml -i inventory/hosts.ini --ask-vault-pass
```

## Architecture

### User Account Model

- **Team members** (alice, bob, charlie) - Individual accounts with TeamShare group membership
- **ansible_admin** - Dedicated automation account (SSH key auth only)
- **smbmount** - Service account for Linux SMB mounting (restricted logon)
- **Guest** - Disabled globally

### File Sharing

**Primary: SMB/CIFS**
- Windows share: `\\lab-windows\TeamShare` → `D:\Shared`
- Linux mount: `/mnt/TeamShare` (production-grade fstab with `_netdev`)
- Security: SMB 3.0 only, encryption enforced, firewall restricted to Tailscale network

**Fallback: SFTP**
- Helper scripts for individual user access
- SSH key authentication
- Usage: `mount-sftp-share.sh alice`

### Security Features

- **SMB hardening**: Disabled SMB 1.0/2.0, enforced encryption, Tailscale-only firewall rules
- **Individual accounts**: All access auditable to specific users
- **Group-based permissions**: TeamShare group controls folder access
- **Vault encryption**: All secrets encrypted at rest with ansible-vault
- **SSH key management**: Runtime generation with automatic cleanup

## Project Structure

```
my-tailscale/
├── inventory/
│   ├── hosts.ini              # Production hosts (windows_group, linux_group)
│   ├── group_vars/            # OS-specific configuration
│   ├── host_vars/             # Machine-specific configuration
│   └── test/                  # Test environment inventory
│       ├── hosts.ini          # Test VMs with local network addresses
│       ├── group_vars/        # Test-specific group variables
│       ├── host_vars/         # Test-specific host variables
│       └── README.md          # Test inventory documentation
├── roles/
│   ├── windows_users/         # Windows user account management
│   ├── linux_users/           # Linux user account management
│   ├── openssh_setup_windows/ # OpenSSH installation/config
│   ├── ssh_key_management/    # SSH key generation, deployment, and cleanup
│   ├── tailscale_setup/       # Tailscale VPN setup (cross-platform)
│   ├── samba_share/           # SMB share creation (Windows)
│   ├── samba_mount/           # SMB mount setup (Linux)
│   ├── sftp_mount_fallback/   # SFTP fallback configuration
│   ├── boot_notify_linux/     # Linux boot notifications via Telegram
│   └── boot_notify_windows/   # Windows boot notifications via Telegram
├── playbooks/
│   ├── setup-openssh-bootstrap.yml # OpenSSH bootstrap verification
│   ├── preflight-checks.yml   # Pre-deployment validation
│   ├── setup-all.yml          # Master orchestration playbook
│   ├── setup-ssh-keys.yml     # SSH key generation and deployment
│   ├── transition-to-ssh.yml  # Transition from WinRM to SSH management
│   ├── validate-acls.yml      # ACL idempotence testing
│   ├── security-validation.yml # Comprehensive security audit
│   ├── boot-notifications.yml # Boot notification setup
│   └── *.yml                  # Individual component playbooks
└── vars/
    └── vault.yml              # Encrypted secrets and user definitions
```

## Common Commands

### Deployment
```bash
# Verify OpenSSH bootstrap (after manual Windows setup)
ansible-playbook playbooks/setup-openssh-bootstrap.yml -i inventory/hosts.ini

# Full deployment
ansible-playbook playbooks/setup-all.yml -i inventory/hosts.ini --ask-vault-pass

# Individual components
ansible-playbook playbooks/setup-windows-users.yml -i inventory/hosts.ini --ask-vault-pass
ansible-playbook playbooks/setup-linux-users.yml -i inventory/hosts.ini --ask-vault-pass
ansible-playbook playbooks/install-tailscale.yml -i inventory/hosts.ini --ask-vault-pass
ansible-playbook playbooks/setup-smb-share.yml -i inventory/hosts.ini --ask-vault-pass
ansible-playbook playbooks/mount-smb-linux.yml -i inventory/hosts.ini --ask-vault-pass
ansible-playbook playbooks/boot-notifications.yml -i inventory/hosts.ini --ask-vault-pass
```

### Security Hardening
```bash
# Generate and deploy SSH keys for ansible_admin (runtime generation with auto-cleanup)
ansible-playbook playbooks/setup-ssh-keys.yml -i inventory/hosts.ini --ask-vault-pass

# Transition from WinRM to SSH-based management
ansible-playbook playbooks/transition-to-ssh.yml -i inventory/hosts.ini --ask-vault-pass

# Run comprehensive security validation
ansible-playbook playbooks/security-validation.yml -i inventory/hosts.ini --ask-vault-pass
```

**SSH Key Management Features:**
- Runtime key generation (ed25519, secure by default)
- Automatic deployment to Windows and Linux hosts
- Platform-specific authorized_keys configuration
- SSH connectivity verification before cleanup
- Automatic cleanup of temporary private keys (security best practice)
- No permanent storage of private keys in vault

### Testing & Validation

**Production Environment:**
```bash
# Test connections
ansible all -i inventory/hosts.ini -u ansible_admin -m ping

# Verify mounts
ssh ansible_admin@lab-linux "mount | grep TeamShare"
ssh ansible_admin@lab-linux "ls -la /mnt/TeamShare"

# Test SMB access
smbclient -L //lab-windows -U alice
```

**Test Environment:**
```bash
# Run full test suite
./scripts/run-full-test-suite.sh

# Test with isolated VMs
ansible-playbook playbooks/test-full-deployment.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test

# Validate test deployment
ansible-playbook playbooks/test-validate-deployment.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test

# See docs/TESTING_GUIDE.md for comprehensive testing procedures
```

### Vault Management
```bash
# Edit encrypted vault
ansible-vault edit vars/vault.yml

# Encrypt new vault
ansible-vault encrypt vars/vault.yml

# View vault contents
ansible-vault view vars/vault.yml
```

## Configuration

### Vault Structure (vars/vault.yml)

```yaml
# Team members - add/remove users by editing this list
team_users:
  - username: alice
    password: "{{ vault_alice_password }}"
    uid: 1001
  - username: bob
    password: "{{ vault_bob_password }}"
    uid: 1002

# Service accounts
service_accounts:
  ansible_admin:
    username: ansible_admin
    password: "{{ vault_ansible_admin_password }}"
  smbmount:
    username: smbmount
    password: "{{ vault_smbmount_password }}"

# Tailscale auth key
tailscale_authkey: "{{ vault_tailscale_key }}"

# Telegram bot credentials (for boot notifications)
vault_telegram_bot_token: "your_bot_token_here"
vault_telegram_chat_id: "your_chat_id_here"
```

### Key Variables

**Windows (group_vars/windows_group.yml)**:
- `windows_shared_drive`: Drive letter for shared folder (default: "D")
- `windows_shared_path`: Full path to shared folder (e.g., "D:\\Shared")
- `smb_share_name`: SMB share name (default: "TeamShare")
- `windows_team_group`: Security group for folder access (default: "TeamShare")
- `telegram_notification_enabled`: Enable boot notifications (default: true)

**Linux (group_vars/linux_group.yml)**:
- `smb_mount_path`: Mount point for SMB share (default: "/mnt/TeamShare")
- `smb_users_group`: Group for SMB access (default: "smb-users", gid: 1100)
- `sftp_users_group`: Group for SFTP access (default: "sftp-users", gid: 1101)
- `telegram_notification_enabled`: Enable boot notifications (default: true)

**SMB Security (roles/samba_share/vars/main.yml)**:
- `smb_encryption_enabled`: Enforce SMB encryption (default: true)
- `smb_v1_disabled`: Disable SMB 1.0 (default: true)
- `smb_v2_disabled`: Disable SMB 2.0 (default: true)
- `tailscale_network`: Firewall restriction range (default: "100.0.0.0/8")

## Roles

### windows_users
Creates team member accounts, ansible_admin, TeamShare group, and smbmount service account. Sets up shared folder structure with NTFS ACLs.

### linux_users
Creates team member accounts with consistent UIDs, smb-users and sftp-users groups, and sudoers configuration for mount operations.

### openssh_setup_windows
Installs OpenSSH via winget (latest version) with automatic fallback to Windows Optional Features if winget is unavailable. Configures sshd with security settings, enables SFTP subsystem, and configures Windows firewall.

### tailscale_setup
Installs Tailscale on both platforms, authenticates with auth key, enables SSH access, and applies security hardening on Windows.

### samba_share
Creates SMB share on Windows with security hardening: disables SMB 1.0/2.0, enforces encryption, restricts firewall to Tailscale network.

### samba_mount
Mounts SMB share on Linux with production-grade options: `_netdev`, `x-systemd.automount`, waits for Tailscale service.

### sftp_mount_fallback
Deploys helper scripts for SFTP fallback access when SMB is unavailable.

### boot_notify_linux
Configures systemd service to send Telegram notifications on Linux boot with system information (hostname, IPs, Tailscale status, hardware specs).

### boot_notify_windows
Creates scheduled task to send Telegram notifications on Windows boot with system information (hostname, IPs, Tailscale status, hardware specs).

### ssh_key_management
Generates temporary SSH key pairs for ansible_admin account, deploys public keys to target hosts, verifies SSH connectivity, and automatically cleans up temporary private keys. Supports both Windows and Linux hosts with platform-specific authorized_keys configuration and proper file permissions.

## Security Best Practices

1. **Rotate Administrator password** after initial provisioning
2. **Use SSH keys** for ansible_admin (password auth disabled)
3. **Ephemeral SSH keys** - private keys generated at runtime and auto-deleted
4. **Keep vault encrypted** - never commit plaintext secrets
5. **Regular ACL validation** - run `validate-acls.yml` periodically
6. **Monitor boot notifications** - verify systems come online correctly
7. **Restrict SMB to Tailscale** - firewall rules prevent internet exposure
8. **Run security validation** - execute `security-validation.yml` monthly
9. **Transition to SSH mode** - switch from WinRM to SSH after initial provisioning
10. **No permanent private keys** - SSH keys are ephemeral and never stored in vault

### Dual-Mode Provisioning

The system uses a two-phase approach for Windows management:

**Phase 1: Initial Provisioning (WinRM)**
- One-time setup using Windows-specific modules
- Administrator account with password authentication
- Duration: 15-30 minutes

**Phase 2: Ongoing Management (SSH)**
- Long-term management with SSH key authentication
- ansible_admin account (no passwords)
- Better security posture and audit trail

See `docs/DUAL_MODE_PROVISIONING.md` for detailed transition guide.

## Boot Notifications

The infrastructure includes automated boot notifications via Telegram to monitor when systems come online.

### Setup

1. **Create a Telegram bot**:
   - Message @BotFather on Telegram
   - Send `/newbot` and follow prompts
   - Save the bot token

2. **Get your chat ID**:
   - Message your bot
   - Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
   - Find your chat ID in the response

3. **Add credentials to vault**:
```bash
ansible-vault edit vars/vault.yml
```

Add:
```yaml
vault_telegram_bot_token: "your_bot_token_here"
vault_telegram_chat_id: "your_chat_id_here"
```

4. **Deploy boot notifications**:
```bash
ansible-playbook playbooks/boot-notifications.yml -i inventory/hosts.ini --ask-vault-pass
```

### Notification Content

Boot notifications include:
- Hostname and OS information
- System uptime
- Local IP addresses
- Tailscale IP and connection status
- Hardware specs (CPU cores, RAM, disk usage)
- Current user and timestamp

### Testing

**Linux**: Run the script manually
```bash
sudo /usr/local/bin/boot-notify.sh
```

**Windows**: Trigger the scheduled task
```powershell
powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\boot-notify.ps1"
```

### Troubleshooting Boot Notifications

**No notification received**:
- Verify bot token and chat ID in vault
- Check network connectivity: `curl https://api.telegram.org`
- Linux: Check service status: `systemctl status boot-notify.service`
- Windows: Check scheduled task: `Get-ScheduledTask -TaskName "BootNotification"`

**Tailscale status shows offline**:
- Verify Tailscale is running: `tailscale status`
- Check service dependencies in systemd/scheduled task configuration

## Playbook Reference

### setup-openssh-bootstrap.yml
Verifies OpenSSH bootstrap completion on Windows. Run after manual OpenSSH installation to confirm SSH connectivity before proceeding with main deployment.

**Usage:**
```bash
ansible-playbook playbooks/setup-openssh-bootstrap.yml -i inventory/hosts.ini
```

**What it does:**
- Displays manual OpenSSH bootstrap instructions
- Tests SSH connectivity to Windows host (port 22)
- Provides clear status messages (✅ accessible or ❌ not accessible)
- Fails with helpful error if SSH is not ready
- Guides next steps after successful verification

**When to use:**
- After manually installing OpenSSH on Windows
- Before running preflight-checks.yml or setup-all.yml
- To troubleshoot SSH connectivity issues

## Troubleshooting

### OpenSSH not accessible on Windows
```bash
# Run bootstrap verification playbook
ansible-playbook playbooks/setup-openssh-bootstrap.yml -i inventory/hosts.ini

# If it fails, manually verify on Windows:
Get-Service sshd
Test-NetConnection -ComputerName localhost -Port 22

# Restart SSH service if needed
Restart-Service sshd
```

### SMB mount fails on Linux
```bash
# Check Tailscale connectivity
tailscale status

# Verify SMB share is accessible
smbclient -L //lab-windows -U smbmount

# Check mount options in /etc/fstab
grep TeamShare /etc/fstab

# Test manual mount
sudo mount -t cifs //lab-windows/TeamShare /mnt/TeamShare -o credentials=/etc/smbcredentials,vers=3.0
```

### SSH connection fails to Windows
```bash
# Verify OpenSSH service is running
ssh ansible_admin@lab-windows "Get-Service sshd"

# Check firewall rules
ssh ansible_admin@lab-windows "Get-NetFirewallRule -DisplayName 'OpenSSH*'"

# Test with verbose output
ssh -v ansible_admin@lab-windows
```

### Vault decryption fails
```bash
# Verify vault password file exists
cat .vault_pass

# Test vault decryption
ansible-vault view vars/vault.yml

# Re-encrypt if needed
ansible-vault rekey vars/vault.yml
```

## Testing

The project includes a comprehensive test environment for validating deployments before production:

- **Test Inventory**: `inventory/test/` - Isolated test VMs with local network addresses
- **Test Vault**: `vars/vault_test.yml` - Sample credentials for testing
- **Test Playbooks**: Automated validation and deployment testing
- **Test Scripts**: `scripts/run-full-test-suite.sh` - Complete test automation

See [Test Environment Setup Guide](docs/TEST_ENVIRONMENT_SETUP.md) and [Testing Guide](docs/TESTING_GUIDE.md) for detailed instructions.

## Documentation

- **README.md** (this file) - Quick start and reference
- **prd.md** - Comprehensive planning and implementation guide
- **docs/TEST_ENVIRONMENT_SETUP.md** - Test environment configuration
- **docs/TESTING_GUIDE.md** - Comprehensive testing procedures
- **docs/SECURITY_HARDENING.md** - Security best practices
- **docs/DUAL_MODE_PROVISIONING.md** - WinRM to SSH transition guide
- **.kiro/specs/tailnet-automation/** - Detailed requirements, design, and tasks

## License

Apache 2.0 - See LICENSE file for details

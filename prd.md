# Planning

## ✅ Production-Grade Enhancements

This plan incorporates 6 production-grade improvements:

1. ✅ **Hybrid SMB+SFTP** - SMB for GUI-based multi-user access (primary); SFTP for secure single-user access (fallback)
2. ✅ **OpenSSH instead of WinRM** - Cross-platform, reliable Windows management; simplifies deployment
3. ✅ **Vault-protected inventory** - User list stored in vault.yml instead of interactive prompts (better for automation/CI-CD)
4. ✅ **Robust fstab entries** - Proper `_netdev` flag and comma escaping for reliable boot behavior
5. ✅ **ACL idempotence testing** - Documentation and testing approach for Windows ACL consistency
6. ✅ **Per-user account model** - Maintains individual team accounts + guest isolation + shared folder structure

---

## Implementation Strategy

**Objective:** Automate dual-boot lab PC setup with scalable cross-platform user management, Tailscale remote access, hybrid SMB/SFTP file sharing, and Telegram boot notifications via Ansible playbooks.

**Architecture:**

- **Repository:** `my-tailscale` (branch: `compyle/ansible-tailnet-setup`)
- **Windows Management:** OpenSSH (not WinRM) for reliable cross-platform Ansible control
- **File Sharing:** SMB (primary, GUI-friendly) + SFTP (fallback, secure) over Tailscale
- **Secrets:** Ansible vault for user credentials, Tailscale auth keys, Telegram credentials
- **User Configuration:** Pre-defined user list in vault.yml (not interactive prompts) for automation/CI-CD
- **Variable Structure:** Separate host\_vars and group\_vars for OS-specific configuration
- **Consistency:** Vault-protected inventory enables repeatable, idempotent deployments

---

## Directory Structure

```
my-tailscale/
├── README.md
├── ansible.cfg
├── inventory/
│   ├── hosts.ini          # Hosts: windows_group, linux_group
│   ├── group_vars/
│   │   ├── windows_group.yml
│   │   └── linux_group.yml
│   └── host_vars/
│       ├── lab-windows.yml (or IP)
│       └── lab-linux.yml (or IP)
├── roles/
│   ├── windows_users/
│   │   ├── tasks/main.yml
│   │   └── vars/main.yml
│   ├── linux_users/
│   │   ├── tasks/main.yml
│   │   └── vars/main.yml
│   ├── openssh_setup_windows/
│   │   ├── tasks/main.yml
│   │   ├── templates/sshd_config.j2
│   │   └── vars/main.yml
│   ├── tailscale_setup/
│   │   ├── tasks/main.yml
│   │   ├── files/
│   │   └── vars/main.yml
│   ├── samba_share/
│   │   ├── tasks/main.yml
│   │   └── vars/main.yml
│   ├── samba_mount/
│   │   ├── tasks/main.yml
│   │   └── vars/main.yml
│   ├── sftp_mount_fallback/
│   │   ├── tasks/main.yml
│   │   └── vars/main.yml
│   ├── ssh_key_management/
│   │   ├── tasks/main.yml
│   │   └── vars/main.yml
│   ├── boot_notify_linux/
│   │   ├── tasks/main.yml
│   │   ├── files/boot_notify.sh
│   │   └── templates/telegram-notify.service.j2
│   └── boot_notify_windows/
│       ├── tasks/main.yml
│       ├── files/boot_notify.ps1
│       └── vars/main.yml
├── playbooks/
│   ├── setup-openssh-bootstrap.yml    # PREREQUISITE - Verify OpenSSH bootstrap completion
│   ├── preflight-checks.yml           # Validate Tailscale, vault, connectivity before main run
│   ├── setup-all.yml                  # Master orchestration (after OpenSSH bootstrap)
│   ├── setup-windows-users.yml
│   ├── setup-linux-users.yml
│   ├── install-tailscale.yml
│   ├── setup-smb-share.yml
│   ├── mount-smb-linux.yml
│   ├── setup-sftp-fallback.yml        # Optional: configure SFTP as fallback
│   ├── setup-ssh-keys.yml             # SSH key generation, deployment, and cleanup
│   ├── transition-to-ssh.yml          # Transition from WinRM to SSH management
│   ├── validate-acls.yml              # ACL idempotence validation test
│   ├── security-validation.yml        # Comprehensive security audit
│   └── boot-notifications.yml
└── vars/
    └── vault.yml              # Encrypted: passwords, tokens, chat IDs
```

---

## Variable Design

### Vault-Protected (vars/vault.yml)

```yaml
# Team members — add/remove users by editing this list
team_users:
  - username: alice
    password: "{{ vault_alice_password }}"
    uid: 1001
  - username: bob
    password: "{{ vault_bob_password }}"
    uid: 1002
  - username: charlie
    password: "{{ vault_charlie_password }}"
    uid: 1003

# PROVISIONING: Administrator account (WinRM connection, temporary)
# NOTE: Use only for initial provisioning. Rotate password after setup completes.
vault_admin_password: "{{ vault_administrator_password }}"

# PROVISIONING: ansible_admin SSH key (generated at runtime, NOT stored permanently)
# Key generation: 'ssh-keygen -t ed25519 -f /tmp/ansible_admin_key -N ""' (Ansible task)
# Public key deployed to C:\Users\ansible_admin\.ssh\authorized_keys during provisioning
# Private key used temporarily, then DELETED after SSH verification
# Vault contains: operator-generated public key only (optional), not private key
ansible_admin_ssh_key_path: "/tmp/lab-windows-admin-key"  # Temporary decrypted path (deleted after use)

# SMB MOUNT: smbmount account (credentials stored in /etc/smbcredentials on Linux)
# This account uses PASSWORD auth only (CIFS protocol requirement, no SSH)
smbmount_password: "{{ vault_smbmount_password }}"

# Tailscale auth key (generate from https://login.tailscale.com/admin/settings/keys)
tailscale_authkey: "{{ vault_tailscale_key }}"

# Telegram bot credentials (for boot notifications)
vault_telegram_bot_token: "your_bot_token_here"
vault_telegram_chat_id: "your_chat_id_here"
```

**User creation is vault-protected** — Playbooks reference `team_users` list from vault.yml:

- Add new users by editing `team_users` in vault
- Playbooks are repeatable and idempotent
- Suitable for automation, CI/CD, and Infrastructure-as-Code workflows
- No interactive prompts required
- All access via personal accounts for audit trail and traceability

**Account Model (Strict Isolation):**

- `team_users` (alice, bob, charlie): Individual accounts for team members
- Members of: "Power Users" group + "TeamShare" group
- Can access shared folder via TeamShare group membership
- All access auditable to specific user
- `Administrator`: Built-in account used ONLY for WinRM provisioning (setup phase)
- NOT used for ongoing access
- Credentials rotated after provisioning
- `ansible_admin`: Dedicated Ansible admin account
- Members of: "Administrators" group ONLY
- **NOT member of TeamShare group** (no shared folder access)
- SSH key authentication only (post-provisioning)
- Purpose: Ansible automation only, isolated from team access
- `smbmount`: Minimal service account for Linux SMB mount
- Members of: "TeamShare" group (for folder read/write)
- Interactive logon disabled (Local Group Policy)
- No GUI/RDP/console access
- Password stored in Linux `/etc/smbcredentials` (mode 600)
- Purpose: CIFS mount automation only
- Guest: Disabled globally (no access anywhere)

### Group Variables (inventory/group\_vars/)

**windows\_group.yml (PROVISIONING MODE - WinRM for module tasks):**

```yaml
# PROVISIONING: Use WinRM for ansible.windows.* modules (win_user, win_share, win_acl)
ansible_connection: winrm
ansible_port: 5985
ansible_user: Administrator
ansible_password: "{{ vault_admin_password }}"  # Administrator account password
ansible_winrm_scheme: http
ansible_winrm_transport: basic
ansible_winrm_server_cert_validation: ignore

# Windows SMB share config
windows_share_name: "TeamShare"
smb_share_path: "{{ windows_shared_path }}"
```

**windows\_group\_ssh.yml (ONGOING MODE - SSH for post-provisioning):**

```yaml
# POST-PROVISIONING: Use SSH for ongoing access (Ansible ad-hoc commands, updates)
ansible_connection: ssh
ansible_user: ansible_admin
ansible_private_key_file: "{{ ansible_admin_ssh_key_path }}"  # Path to decrypted SSH private key
ansible_port: 22
ansible_shell_type: cmd
ansible_pipelining: true
```

**linux\_group.yml:**

```yaml
ansible_connection: ssh
ansible_user: root
ansible_python_interpreter: /usr/bin/python3

# Linux SMB mount config
smb_mount_path: /mnt/TeamShare
smb_mount_src: "//{{ windows_host }}/{{ windows_share_name }}"
smb_mount_user: "smbmount"  # Minimal service account for mount
smb_mount_opts: "username={{ smb_mount_user }},password={{ smbmount_password }},uid=0,gid=1100,file_mode=0755,dir_mode=0755,_netdev"

# Windows host reference
windows_host: "lab-windows"  # Tailscale hostname
```

### Host Variables (inventory/host\_vars/)

**lab-windows.yml:**

```yaml
ansible_host: <windows-ip-or-tailscale-ip>
windows_hostname: "lab-pc-windows"
windows_shared_drive: "D"          # Change to real drive letter (D, E, etc.)
windows_shared_path: "{{ windows_shared_drive }}:\\Shared"
```

**lab-linux.yml:**

```yaml
ansible_host: <linux-ip-or-tailscale-ip>
linux_hostname: "lab-pc-linux"
sshfs_remote_path: "shared@lab-windows:/{{ windows_shared_drive|lower }}/Shared"  # Dynamically constructed SSHFS path
```

---

## Role Responsibilities

### Role: `windows_users`

**Create team member accounts and shared folder structure (from vault-protected user list):**

- For each user in `team_users` from vault.yml:
- Create account using `ansible.windows.win_user` module
- Add to "Power Users" group (grants permission to install software, modify system settings)
- Create home directory at `C:\Users\{username}` (auto-created by Windows)
- Enable password-based login
- Create `ansible_admin` account for Ansible OpenSSH management:
- Username: "ansible\_admin"
- Password: `vault_ansible_admin_password` from vault
- Add to Administrators group (for Ansible to manage system)
- Home directory: `C:\Users\ansible_admin`
- Enable password-based login
- Create shared group for folder permissions:
- Group name: "TeamShare"
- Add all team members to this group
- This group (not individual user) has access to shared folder
- Create `smbmount` service account for Linux SMB mount:
- Username: "smbmount"
- Password: `smbmount_password` from vault
- Add to "TeamShare" group (read-only access via group permissions)
- Home directory: `C:\Users\smbmount`
- **Restrict interactive logon**: Use `win_user` parameter `account_locked: no` but restrict logon rights via Local Group Policy (Settings → Local Group Policy Editor → Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment → Deny log on locally)
- No GUI/RDP access (service account for CIFS mount only)
- Used exclusively by Linux for mounting TeamShare SMB folder
- Ensure guest account exists but keep disabled (no access to shared folders)
- **Create shared folder structure** at `{{ windows_shared_path }}` (e.g., D:\\Shared):
- Create main directory: `{{ windows_shared_path }}`
- Create subdirectories: `Projects`, `Data`, `Archive`
- Set NTFS ACLs using `ansible.windows.win_acl` module:
    - "TeamShare" group: Modify permission (read/write/delete) on all folders
    - `NT AUTHORITY\Guest`: Deny Full on all folders
    - Inherit permissions to subfolders recursively
- Document: Test ACL idempotence on first run; verify inherited permissions apply correctly
- **CRITICAL: SMB Security Hardening (mandatory)**
- Disable SMB 1 & 2 (obsolete, insecure — ransomware target):

```powershell
    Set-SmbServerConfiguration -EncryptData $true -RejectUnencryptedAccess $true -EnableSMB1Protocol $false -EnableSMB2Protocol $false -Force
```

- Force SMB encryption (prevents MITM attacks)
- Allow SMB 3.0+ only (modern, secure)
- Configure firewall to restrict SMB to Tailscale network only:

```powershell
    New-NetFirewallRule -DisplayName "Tailscale-SMB-In" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress 100.0.0.0/8 -Action Allow
```

- This restricts port 445 inbound to Tailscale IP range (100.0.0.0/8)
- Prevents direct internet exposure of SMB
- **Rationale:** All access via personal accounts for audit trail/traceability; shared group enables permission management; hardened SMB prevents ransomware and MITM
- Playbook is idempotent; can be re-run to add users (existing users skipped)

### Role: `linux_users`

**Create team member accounts from vault-protected user list:**

- For each user in `team_users` from vault.yml:
- Create account using `ansible.builtin.user` module
- Use UID from vault (e.g., 1001, 1002, 1003)
- Add to `smb-users` group (for SMB share mount access)
- Add to `sftp-users` group (optional, for SFTP fallback access)
- Set default shell to `/bin/bash`
- Set password via hashed vault variables (use `password_hash('sha512', 'salt')` filter)
- Create home directory at `/home/{username}` with mode 0700
- Enable password-based login
- Create `smb-users` group (gid 1100) if not exists
- Create `sftp-users` group (gid 1101) if not exists
- Create sudoers entries via `/etc/sudoers.d/smb-users`:
- `/usr/bin/mount` (mount SMB shares without password)
- `/usr/bin/umount` (unmount SMB shares without password)
- `/usr/sbin/systemctl` (restart services)
- Playbook is idempotent; can be re-run to add users

### Role: `openssh_setup_windows`

**Install and configure OpenSSH on Windows for Ansible management + SFTP fallback:**

- Install OpenSSH with intelligent method selection:
  - **Primary method**: Install via winget (Microsoft.OpenSSH.Beta) for latest version
    - Checks if winget is available using `Get-Command winget`
    - Uses silent installation with automatic agreement acceptance
    - Handles "already installed" scenarios gracefully
  - **Fallback method**: Use `ansible.windows.win_optional_feature` if winget unavailable
    - Feature: `OpenSSH.Server~~~~0.0.1.0` (server component)
    - Available on Windows 10 (1809+) and Windows Server 2019+
  - Displays installation method used for transparency
- Configure sshd service:
    - Set StartMode to `Auto`
    - Ensure service is running
- Create/update `C:\ProgramData\ssh\sshd_config` with:
- Port 22
- `PasswordAuthentication no` (SSH keys only for security)
- `PubkeyAuthentication yes` (key-based authentication)
- `Subsystem sftp sftp-server.exe`
- `AllowUsers ansible_admin @TeamShare @Administrators` (Ansible admin + team members for SFTP + admins)
- `PermitEmptyPasswords no`
- `Protocol 2` (SSH protocol version 2 only)
- `MaxAuthTries 3` (limit authentication attempts)
- `ClientAliveInterval 300` and `ClientAliveCountMax 2` (connection keepalive)
- Configure Windows firewall to allow port 22:
- Use `community.windows.win_firewall_rule` to create inbound rule
- Rule: allow TCP port 22 from Tailscale network only (100.64.0.0/10)
- Restrict to domain, private, and public profiles
- Configure service failure recovery (automatic restart on failure)
- Verify SSH service is running and accessible via Tailscale IP
- Test: `ssh -l ansible_admin lab-windows` (Ansible management)
- Test: `ssh -l alice lab-windows` (Team member SFTP fallback)

### Role: `tailscale_setup`

- **Linux:**
- Install via `curl install.sh`
- Authenticate with authkey: `tailscale up --authkey={{ tailscale_authkey }} --ssh`
- Ensure `tailscaled.service` is enabled and started
- Verify service running post-install
- SSH is enabled for direct terminal access by team members over Tailnet
- **Windows:**
- Download + install Tailscale MSI
- Authenticate with authkey and enable SSH: `tailscale up --authkey={{ tailscale_authkey }}`; `tailscale set --ssh`
- Configure Tailscale service using `ansible.windows.win_service`:
    - `StartMode = Auto`
    - `StartType = AutomaticDelayedStart` (delay 2 minutes to allow network startup)
    - `FailureActions`: Restart on failure (actions: Restart, Restart, Restart with delays)
- Apply security hardening with ACLs:
    - Use `ansible.windows.win_acl` to remove "Users" group from `C:\Program Files\Tailscale`
    - Use `ansible.windows.win_service` to apply restrictive service DACL via `sc sdset Tailscale ...`
    - Result: Only SYSTEM and Administrators can modify Tailscale (prevents tampering)
- Verify service running post-install

### Role: `samba_share`

**Create and configure SMB share on Windows (primary file sharing method):**

- Create SMB share named `{{ windows_share_name }}` (e.g., "TeamShare") pointing to `{{ windows_shared_path }}`
- Use `ansible.windows.win_share` module to configure:
- Share name: `{{ windows_share_name }}`
- Path: `{{ windows_shared_path }}`
- Description: "Team shared project folder"
- State: present
- Set share permissions (SMB level) using `ansible.windows.win_share_permissions` (if available) or `net share` command:
- "TeamShare" group: Full permission (read/write/delete via group)
- Guest: Remove all permissions
- Verify share is accessible via network path: `\\lab-windows\{{ windows_share_name }}`
- Test: From Linux, verify `smbclient -L //lab-windows -U smbmount` works
- Verify team members can access via personal accounts (inherited from TeamShare group)

### Role: `samba_mount`

**Mount SMB share on Linux (primary access method with production options):**

- Install `cifs-utils` package on Linux
- Create mount point at `{{ smb_mount_path }}` (e.g., `/mnt/TeamShare`)
- Create credential file at `/etc/smbcredentials` with content:
- `username={{ smb_mount_user }}`
- `password={{ smbmount_password }}`
- File permissions: mode 600 (root only)
- Configure `/etc/fstab` entry with production-grade options:

```
  //{{ windows_host }}/{{ windows_share_name }} {{ smb_mount_path }} cifs credentials=/etc/smbcredentials,vers=3.0,uid=0,gid=1100,file_mode=0755,dir_mode=0755,_netdev,nounix,x-systemd.automount,x-systemd.after=tailscaled.service,x-systemd.after=network-online.target 0 0
```

- **vers=3.0**: Use SMB 3.0 (modern, encrypted, secure)
- **\_netdev**: Prevent boot hang if network unavailable
- **nounix**: Disable UNIX extensions (better compatibility with Windows)
- **x-systemd.automount**: Lazy mount (mount on first access, not at boot)
- **x-systemd.after=tailscaled.service**: Wait for Tailscale daemon to start before attempting mount
- **x-systemd.after=network-online.target**: Wait for network readiness
- **Distro-specific network readiness:**
    - Ubuntu/Debian (systemd-networkd): `systemctl enable systemd-networkd-wait-online.service`
    - Ubuntu/RHEL (NetworkManager): `systemctl enable NetworkManager-wait-online.service`
    - Verify: `systemctl is-active network-online.target` should show "active" before Tailscale mounts
- Mount immediately: `mount -a`
- Set mount point permissions: `chmod 0775 {{ smb_mount_path }}` and `chgrp smb-users {{ smb_mount_path }}`
- Verify: `mount | grep {{ smb_mount_path }}` shows CIFS mount with vers=3.0
- Test: Team members can read/write files at `{{ smb_mount_path }}`

### Role: `sftp_mount_fallback`

**Optional: Configure SFTP as fallback for secure single-user access:**

- Install `sshfs` and `fuse` packages on Linux
- Create helper scripts in `/usr/local/bin/`:
- `mount-sftp-share.sh`: Mount Windows shared folder via SFTP to user's home directory
- Script accepts username and creates `~/TeamShare-sftp` mount point
- Uses SSH key authentication (no passwords in script)
- Document for team members:
- "If SMB unavailable, run: `mount-sftp-share.sh alice`"
- Creates SFTP mount at `~/TeamShare-sftp`
- Unmount with: `fusermount -u ~/TeamShare-sftp`
- Optional: Set up automated SFTP mounts on login via PAM or systemd user service

### Role: `boot_notify_linux`

**Configure systemd service for boot notifications via Telegram:**

- Install `curl` package for Telegram API calls
- Deploy bash script to `/usr/local/bin/boot-notify.sh` with mode 0755
- Script gathers system information:
  - Hostname via `hostname`
  - OS version from `/etc/os-release`
  - System uptime via `uptime -p`
  - Local IP addresses via `ip -4 addr show`
  - Tailscale IP and status via `tailscale ip -4` and `tailscale status --json`
  - CPU count via `nproc`
  - RAM via `free -g`
  - Disk usage via `df -h /`
  - Current user via `whoami`
- Configure Telegram credentials in script:
  - `TELEGRAM_BOT_TOKEN` from `vault_telegram_bot_token`
  - `TELEGRAM_CHAT_ID` from `vault_telegram_chat_id`
- Create systemd service file at `/etc/systemd/system/boot-notify.service`:
  - Type: oneshot
  - After: network-online.target, tailscaled.service
  - ExecStart: `/usr/local/bin/boot-notify.sh`
  - User: root
- Enable service to run on boot (WantedBy: multi-user.target)
- Reload systemd daemon and enable service
- Message format: Markdown-formatted with hostname, OS, network info, hardware specs, timestamp
- Variables (from `roles/boot_notify_linux/vars/main.yml`):
  - `telegram_bot_token`: Bot token from vault
  - `telegram_chat_id`: Chat ID from vault
  - `service_name`: "boot-notify"
  - `service_description`: "Boot Notification Service via Telegram"
  - `script_path`: "/usr/local/bin/boot-notify.sh"

### Role: `boot_notify_windows`

**Configure scheduled task for boot notifications via Telegram:**

- Create `C:\Scripts` directory
- Deploy PowerShell script to `C:\Scripts\boot-notify.ps1`
- Script gathers system information:
  - Hostname via `$env:COMPUTERNAME`
  - OS version via `Get-CimInstance Win32_OperatingSystem`
  - System uptime calculation from LastBootUpTime
  - Local IP addresses via `Get-NetIPAddress -AddressFamily IPv4`
  - Tailscale IP and status via `tailscale ip -4` and `tailscale status --json`
  - CPU count via `Get-CimInstance Win32_Processor`
  - RAM via `Get-CimInstance Win32_ComputerSystem`
  - Disk usage via `Get-CimInstance Win32_LogicalDisk`
  - Current user via `$env:USERNAME`
  - Windows build and version details
- Configure Telegram credentials in script via string replacement:
  - Replace `$TELEGRAM_BOT_TOKEN` with `vault_telegram_bot_token`
  - Replace `$TELEGRAM_CHAT_ID` with `vault_telegram_chat_id`
- Create scheduled task using `community.windows.win_scheduled_task`:
  - Name: "BootNotification"
  - Trigger: On system boot with 2-minute delay (PT2M)
  - Action: Execute PowerShell with `-ExecutionPolicy Bypass`
  - Username: SYSTEM
  - Run level: highest
  - State: present and enabled
- Message format: Markdown-formatted with hostname, OS, network info, hardware specs, timestamp
- Variables (from `roles/boot_notify_windows/vars/main.yml`):
  - `telegram_bot_token`: Bot token from vault
  - `telegram_chat_id`: Chat ID from vault
  - `task_name`: "BootNotification"
  - `task_description`: "Send boot notification to Telegram"
  - `script_path`: "C:\\Scripts\\boot-notify.ps1"
  - `script_dir`: "C:\\Scripts"

### Role: `ssh_key_management`

**Runtime SSH key generation, deployment, and automatic cleanup (Requirements: 6.3, 6.4):**

- **Generate temporary SSH key pair** on Ansible control node:
  - Delegate to localhost
  - Key type: ed25519 (modern, secure, fast)
  - Location: `/tmp/ansible_admin_key` (temporary)
  - No passphrase (for automation)
  - Comment: "ansible_admin@tailnet-automation"
  - Creates only if not exists (idempotent)
  - Set restrictive permissions: mode 0600 on private key

- **Deploy public key to target hosts:**
  - **Windows:**
    - Create `.ssh` directory: `C:\Users\ansible_admin\.ssh`
    - Deploy public key to `authorized_keys` file
    - Set proper Windows ACLs:
      - Remove inheritance
      - Remove all existing rules
      - Grant SYSTEM and ansible_admin full control only
      - Prevents unauthorized access to authorized_keys
  - **Linux:**
    - Create `.ssh` directory: `/home/ansible_admin/.ssh` (mode 0700)
    - Deploy public key using `ansible.builtin.authorized_key` module
    - Proper ownership: ansible_admin:ansible_admin
    - Automatic permission handling by module

- **Verify SSH connectivity:**
  - Test SSH connection with new key from localhost
  - Command: `ssh -i /tmp/ansible_admin_key -o StrictHostKeyChecking=no ansible_admin@{{ ansible_host }}`
  - Fails if connection unsuccessful (prevents cleanup of working keys)
  - Platform-specific verification for Windows and Linux

- **Automatic cleanup (security best practice):**
  - Controlled by `ssh_key_auto_cleanup` variable (default: true)
  - Removes temporary private key: `/tmp/ansible_admin_key`
  - Removes temporary public key: `/tmp/ansible_admin_key.pub`
  - Only runs after successful verification
  - Can be disabled for troubleshooting: set `ssh_key_auto_cleanup: false`
  - Tagged with 'cleanup' for selective execution

- **Security features:**
  - Private keys never stored in vault (ephemeral generation)
  - Keys generated on-demand during deployment
  - Automatic cleanup prevents key exposure
  - No permanent storage of private keys
  - Can be regenerated at any time by re-running playbook
  - SSH key authentication enforced (no password fallback)

- **Variables (from `roles/ssh_key_management/vars/main.yml`):**
  - `ssh_key_auto_cleanup`: true (automatic cleanup enabled)
  - `ssh_key_type`: ed25519 (modern elliptic curve)
  - `ssh_key_temp_path`: /tmp/ansible_admin_key
  - `ssh_key_comment`: "ansible_admin@tailnet-automation"
  - `ssh_verify_timeout`: 10 seconds
  - `ssh_strict_host_checking`: false (for automation)

---

## Playbook Orchestration

### `setup-openssh-bootstrap.yml` (PREREQUISITE)

**Purpose:** Verifies OpenSSH bootstrap completion and SSH connectivity before main deployment.

**MUST RUN AFTER manual OpenSSH installation on Windows**

**Manual bootstrap step on Windows (PowerShell as Administrator):**

```powershell
  # Option 1: Install via winget (recommended - gets latest version)
  winget install --id Microsoft.OpenSSH.Beta --silent --accept-package-agreements --accept-source-agreements

  # Option 2: Fallback to Windows Optional Features if winget unavailable
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

  # Start SSH service
  Start-Service sshd
  Set-Service -Name sshd -StartupType Automatic

  # Allow SSH through firewall
  New-NetFirewallRule -DisplayName "OpenSSH" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22

  # Verify SSH is working
  ssh localhost "echo SSH is working"
```

**After manual bootstrap, run verification playbook:**

```bash
ansible-playbook playbooks/setup-openssh-bootstrap.yml -i inventory/hosts.ini
```

**What the playbook does:**
- Displays comprehensive OpenSSH bootstrap instructions
- Tests SSH connectivity to Windows host (port 22 reachability)
- Provides clear status messages:
  - ✅ SSH IS ACCESSIBLE - Ready to proceed with main deployment
  - ❌ SSH NOT ACCESSIBLE - Complete manual bootstrap steps first
- Fails with helpful error message if SSH is not ready
- Guides next steps (preflight-checks.yml, setup-all.yml)

**When to use:**
- After manually installing OpenSSH on Windows (one-time setup)
- Before running preflight-checks.yml or setup-all.yml
- To troubleshoot SSH connectivity issues
- To verify SSH service is running and accessible

**Note:** This playbook does NOT install OpenSSH (manual step required). It only verifies the installation was successful and SSH is accessible for Ansible automation.

### `setup-all.yml` (Master)

```yaml
- name: Full Lab PC Setup (Vault-Protected Users)
  hosts: all
  tasks:
    # Phase 1: User accounts
    - name: Setup Windows users and shared folders
      include_role:
        name: windows_users
      when: inventory_hostname in groups['windows_group']

    - name: Setup Linux users
      include_role:
        name: linux_users
      when: inventory_hostname in groups['linux_group']

    # Phase 2: Network services
    - name: Install Tailscale with SSH enabled
      include_role:
        name: tailscale_setup

    - name: Setup OpenSSH on Windows for Ansible
      include_role:
        name: openssh_setup_windows
      when: inventory_hostname in groups['windows_group']

    # Phase 3: File sharing (Windows)
    - name: Create and configure SMB share
      include_role:
        name: samba_share
      when: inventory_hostname in groups['windows_group']

    # Phase 4: File sharing (Linux)
    - name: Mount SMB share on Linux
      include_role:
        name: samba_mount
      when: inventory_hostname in groups['linux_group']

    # Phase 5: Boot notifications
    - name: Deploy boot notifications
      include_role:
        name: "{{ 'boot_notify_windows' if inventory_hostname in groups['windows_group'] else 'boot_notify_linux' }}"
```

### Individual Playbooks (for specific tasks or re-runs)

**`preflight-checks.yml`** (Run BEFORE setup-all.yml)

- Validates environment before main deployment:
- Verify Tailscale is running on both Windows and Linux
- Verify Tailscale IPs are reachable
- Test SSH connectivity to Windows (ansible\_admin account)
- Verify vault file exists and is readable
- Verify inventory files are valid
- Check disk space on Windows shared partition
- Test network connectivity to Windows SMB port 445
- Fails fast if any checks fail (prevents partial deployment)
- Run: `ansible-playbook playbooks/preflight-checks.yml -i inventory/hosts.ini --ask-vault-pass`

**`validate-acls.yml`** (Run AFTER setup-all.yml for verification)

- Tests ACL idempotence via icacls diff (production-grade):
- Task 1: Capture baseline ACLs: `icacls D:\Shared /T /C > /tmp/acl_baseline.txt`
- Task 2: Re-run windows\_users role ACL tasks
- Task 3: Capture post-apply ACLs: `icacls D:\Shared /T /C > /tmp/acl_after.txt`
- Task 4: Diff the two: `diff /tmp/acl_baseline.txt /tmp/acl_after.txt`
- Fail if diff non-empty (indicates ACL drift on re-run)
- Generate report artifact showing idempotence pass/fail
- Additional checks:
- Verify TeamShare group exists and has correct members
- Verify team members can access shared folder
- Verify guest account is denied access
- Run after first setup, and periodically to detect permission drift
- Run: `ansible-playbook playbooks/validate-acls.yml -i inventory/hosts.ini --ask-vault-pass`

**`setup-windows-users.yml`**

- Hosts: `windows_group`
- Role: `windows_users` (user creation + shared folder + ACLs from vault)

**`setup-linux-users.yml`**

- Hosts: `linux_group`
- Role: `linux_users` (user creation + group setup from vault)

**`install-tailscale.yml`**

- Hosts: `all`
- Role: `tailscale_setup` (includes service hardening on Windows)

**`setup-openssh-on-windows.yml`**

- Hosts: `windows_group`
- Role: `openssh_setup_windows` (installs/configures OpenSSH for Ansible management)

**`setup-smb-share.yml`**

- Hosts: `windows_group`
- Role: `samba_share` (creates SMB share on Windows)

**`mount-smb-linux.yml`**

- Hosts: `linux_group`
- Role: `samba_mount` (mounts SMB share with proper fstab and \_netdev)

**`setup-sftp-fallback.yml`**

- Hosts: `linux_group`
- Role: `sftp_mount_fallback` (optional SFTP helper scripts for fallback access)

**`boot-notifications.yml`**

- Hosts: `all`
- Role: `boot_notify_linux` or `boot_notify_windows` (conditional)

**`setup-ssh-keys.yml`**

- Hosts: `windows_group`, `linux_group`
- Role: `ssh_key_management`
- Purpose: Generate, deploy, and verify SSH keys for ansible_admin
- Features:
  - Runtime key generation (ed25519)
  - Cross-platform deployment (Windows + Linux)
  - SSH connectivity verification
  - Automatic cleanup of temporary keys
  - Security summary with next steps
- Run after initial provisioning to enable SSH key authentication
- Can be re-run to regenerate keys if needed

---

## Execution Workflow

1. **Windows Bootstrap (Manual, One-Time):**

- On Windows PC, open PowerShell as Administrator
- Run OpenSSH bootstrap manually:

```powershell
     # Option 1: Install via winget (recommended - gets latest version)
     winget install --id Microsoft.OpenSSH.Beta --silent --accept-package-agreements --accept-source-agreements

     # Option 2: Fallback to Windows Optional Features if winget unavailable
     # Requires Windows 10 (1809+) or Windows Server 2019+
     Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
     Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

     # Start and enable SSH service
     Start-Service sshd
     Set-Service -Name sshd -StartupType Automatic

     # Configure firewall
     New-NetFirewallRule -DisplayName "OpenSSH" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22

     # Verify SSH working
     ssh localhost "echo SSH is working"
```

- Verify bootstrap completion with Ansible:

```bash
     ansible-playbook playbooks/setup-openssh-bootstrap.yml -i inventory/hosts.ini
     # Should show: ✅ SSH IS ACCESSIBLE
```

2. **Prepare Vault and Inventory:**

- Create/edit `vars/vault.yml` with team user list and secrets (see Variable Design section)
- Update `inventory/hosts.ini` with Windows/Linux IPs or Tailscale IPs
- Populate `inventory/group_vars/windows_group.yml` and `inventory/group_vars/linux_group.yml`
- Populate `inventory/host_vars/lab-windows.yml` and `inventory/host_vars/lab-linux.yml`
- Set Windows shared drive letter in `host_vars/lab-windows.yml`: `windows_shared_drive: "D"`

3. **Encrypt Vault:**

```bash
   ansible-vault encrypt vars/vault.yml  # If plain text, encrypt it
```

**CRITICAL: Dual-Mode Provisioning/Ongoing Access Model**

The deployment uses TWO connection modes due to Windows module requirements:

**Phase 1: PROVISIONING (Initial setup - WinRM only)**

- Use `inventory/group_vars/windows_group.yml` (WinRM connection)
- Runs `setup-all.yml` to create users, shares, and ACLs
- Modules: `ansible.windows.win_user`, `win_share`, `win_acl` (require WinRM)
- Duration: \~15-30 minutes (one-time setup)
- Connection: WinRM on port 5985 (HTTP) via Administrator account

**Phase 2: ONGOING (Post-provisioning - SSH only)**

- Switch to `inventory/group_vars/windows_group_ssh.yml` (SSH connection)
- For subsequent updates, patches, and ad-hoc commands
- Modules: Standard Ansible + PowerShell over SSH
- Connection: SSH on port 22 via ansible\_admin account with SSH key
- Duration: Indefinite

**Transition Procedure:**

```bash
# Step 1: After setup-all.yml completes, backup WinRM config
cp inventory/group_vars/windows_group.yml inventory/group_vars/windows_group_winrm_backup.yml

# Step 2: Replace with SSH config
mv inventory/group_vars/windows_group_ssh.yml inventory/group_vars/windows_group.yml

# Step 3: Verify SSH connection works
ansible all -i inventory/hosts.ini -u ansible_admin -m setup -a "filter=ansible_os_family"

# Step 4: Now use ansible_admin SSH key for ongoing tasks
```

4. **Verify OpenSSH Bootstrap (Required):**

```bash
   # Confirm SSH connectivity to Windows before proceeding
   ansible-playbook playbooks/setup-openssh-bootstrap.yml -i inventory/hosts.ini

   # Expected output: ✅ SSH IS ACCESSIBLE
   # If failed: Complete manual OpenSSH bootstrap steps on Windows
```

5. **Run Preflight Checks (Optional but recommended):**

```bash
   # Validate environment before deployment
   ansible-playbook playbooks/preflight-checks.yml -i inventory/hosts.ini --ask-vault-pass

   # Will check:
   # - Tailscale connectivity on both systems
   # - SSH access to Windows
   # - Vault and inventory files
   # - Network prerequisites
   # - Exits with error if issues found (prevents failed partial deployment)
```

6. **Dry-Run (Optional for safety):**

```bash
   # Preview changes without making them
   ansible-playbook playbooks/setup-all.yml -i inventory/hosts.ini --ask-vault-pass --check

   # Will show what would be changed (test mode)
   # Review output for any unexpected changes
```

7. **Run Master Playbook (Single Command):**

```bash
   # After OpenSSH bootstrap, inventory configured, and preflight passed:
   ansible-playbook playbooks/setup-all.yml -i inventory/hosts.ini --ask-vault-pass

   # Playbook will:
   # - Generate ansible_admin SSH key at runtime (/tmp/ansible_admin_key)
   # - Deploy public key to Windows C:\Users\ansible_admin\.ssh\authorized_keys
   # - Create all users from team_users list in vault
   # - Setup shared folders on Windows with TeamShare group
   # - Configure Tailscale on both OSes
   # - Setup OpenSSH on Windows (hardened)
   # - Create and mount SMB share (with production mount options)
   # - Deploy boot notifications
   # - All in one coordinated run
```

8. **Post-Provisioning Security Hardening:**

```bash
   # Step 1: Generate and deploy SSH keys for ansible_admin
   ansible-playbook playbooks/setup-ssh-keys.yml -i inventory/hosts.ini --ask-vault-pass
   # This will:
   # - Generate ed25519 SSH key pair at runtime
   # - Deploy public key to all hosts (Windows + Linux)
   # - Verify SSH connectivity
   # - Automatically cleanup temporary private keys (security best practice)

   # Step 2: Verify SSH connection with ansible_admin works
   ansible all -i inventory/hosts.ini -m ping
   # Should succeed with SSH key authentication

   # Step 3: ROTATE Administrator password (security-critical!)
   # Generate new password OUTSIDE the repo (use secure password manager):
   # - Generate random 32-char password
   # - Store in secure location (1Password, LastPass, etc.) with backup codes
   # - Do NOT commit to any repo or CI system
   # - Only the operator knows the new password

   # Then remove from vault permanently:
   ansible-vault edit vars/vault.yml
   # Delete/null out: vault_admin_password
   # Leave file encrypted, commit to repo

   # Step 4: Verify dual-mode transition to SSH
   # (See Dual-Mode Provisioning section for transition procedure)
   ansible-playbook playbooks/transition-to-ssh.yml -i inventory/hosts.ini --ask-vault-pass

   # Step 5: Run ACL idempotence validation
   ansible-playbook playbooks/validate-acls.yml -i inventory/hosts.ini --ask-vault-pass

   # Step 6: Run comprehensive security validation
   ansible-playbook playbooks/security-validation.yml -i inventory/hosts.ini --ask-vault-pass
```

   **Optional: Run Individual Playbooks**
   For re-running specific tasks after initial setup:

```bash
   ansible-playbook playbooks/setup-windows-users.yml -i inventory/hosts.ini --ask-vault-pass
   ansible-playbook playbooks/setup-linux-users.yml -i inventory/hosts.ini --ask-vault-pass
   ansible-playbook playbooks/install-tailscale.yml -i inventory/hosts.ini --ask-vault-pass
   ansible-playbook playbooks/setup-openssh-on-windows.yml -i inventory/hosts.ini --ask-vault-pass
   ansible-playbook playbooks/setup-smb-share.yml -i inventory/hosts.ini --ask-vault-pass
   ansible-playbook playbooks/mount-smb-linux.yml -i inventory/hosts.ini --ask-vault-pass
   ansible-playbook playbooks/boot-notifications.yml -i inventory/hosts.ini --ask-vault-pass
```

5. **Verify Setup:**

- Windows: User accounts visible in Settings > Accounts, SSH working: `Test-NetConnection -ComputerName lab-windows -Port 22`
- Linux: `getent passwd` shows all created users
- Tailscale: `tailscale status` on both OSes shows SSH status
- SSHFS: `mount | grep /mnt/shared` on Linux shows active mount
- SSH Access: `ssh -p 22 username@lab-windows` (via Tailscale IP or hostname) from Linux
- Telegram: Boot notification received after reboot
- File Access: Team members can read/write files in `/mnt/shared` on Linux and via SFTP from any OS

---

## Key Implementation Notes

**Vault-Protected User List:**

- All user credentials stored in `vars/vault.yml` (encrypted)
- Add/remove users by editing `team_users` list in vault
- No interactive prompts — suitable for automation and CI/CD
- Playbooks are idempotent: re-running with same users is safe
- Implementation handles duplicate usernames gracefully (skip with message)
- To add users later: Edit vault, re-run playbook

**Configuration Variables (in host\_vars):**

- `windows_shared_drive`: Drive letter (e.g., "D", "E"). Set in `inventory/host_vars/lab-windows.yml`
- `windows_shared_path`: Derived as `{{ windows_shared_drive }}:\\Shared` (e.g., `D:\Shared`)
- All variables must be set before running playbooks

**Ansible OpenSSH Management (Windows):**

- Uses standard SSH instead of WinRM for ongoing management (more reliable, cross-platform)
- Set `ansible_connection: ssh`, `ansible_port: 22` in group\_vars (post-provisioning)
- Authenticate as `ansible_admin` user with SSH key
- **SSH key deployment (security-hardened runtime generation via ssh_key_management role):**
  - Key generated at runtime: `ssh-keygen -t ed25519 -f /tmp/ansible_admin_key -N ""`
  - Public key deployed to Windows `C:\Users\ansible_admin\.ssh\authorized_keys` during provisioning
  - Proper Windows ACLs applied (SYSTEM and ansible_admin only)
  - Private key used temporarily for verification, then AUTOMATICALLY DELETED
  - Vault does NOT store private key permanently (security best practice)
  - Cleanup controlled by `ssh_key_auto_cleanup` variable (default: true)
  - Can be regenerated at any time by re-running `setup-ssh-keys.yml`
- Configure Ansible: `ansible_private_key_file` points to temporary key path during provisioning only
- Set `ansible_shell_type: cmd` to use Windows CMD shell for Ansible commands
- Firewall rule allows port 22 inbound (configured by openssh\_setup\_windows role)
- Test connection: `ansible all -i inventory/hosts.ini -m ping`
- Benefits: 
  - Minimal credential exposure
  - Ephemeral private keys (never stored permanently)
  - Strong audit trail
  - Cross-platform consistency (same key management for Windows and Linux)
  - Automatic cleanup prevents key leakage

**Windows Shared Folder Setup (SMB):**

- Folder structure created by `windows_users` role:
- `{{ windows_shared_path }}\Projects`, `\Data`, `\Archive`
- NTFS ACLs configured with `ansible.windows.win_acl`:
- "TeamShare" group: Modify (read/write/delete)
- Team members inherit access via group membership
- Guest: Deny Full (no access)
- All team access is auditable (via personal accounts)
- **ACL Idempotence Testing (First Run):**
- ACL inheritance can cause issues if run multiple times
- Manually verify on first run: `icacls D:\Shared /T /C` to see permissions and group membership
- If ACLs revert, use `win_acl with state: present, propagation: No` to prevent reapply issues
- Document results in playbook logs for reference
- SMB share created via `ansible.windows.win_share` module
- Test (via service account): `smbclient -L //lab-windows -U smbmount%password`
- Test (via personal account): `smbclient -L //lab-windows -U alice%password` (should also work)

**SMB Mount on Linux (Production-Grade):**

- Use `cifs-utils` (not NFS) for Windows share compatibility
- Create credential file: `/etc/smbcredentials` with mode 600
- **fstab Entry (Critical for Boot Reliability):**

```
  //{{ windows_host }}/{{ windows_share_name }} {{ smb_mount_path }} cifs credentials=/etc/smbcredentials,uid=0,gid=1100,file_mode=0755,dir_mode=0755,_netdev 0 0
```

- **`_netdev`&#32;flag is essential**: Prevents boot hang if network unavailable at startup
- No comma escaping needed in fstab (use literal commas)
- `uid=0,gid=1100` ensures Linux root ownership and `smb-users` group access
- Credentials file prevents password exposure in plaintext
- Mount immediately after fstab edit: `mount -a`
- Verify persistent: reboot and check `mount | grep TeamShare`

**SFTP Fallback (Optional Safety):**

- If SMB temporarily unavailable, team members can use SFTP as fallback
- Helper script: `/usr/local/bin/mount-sftp-share.sh`
- Usage: `mount-sftp-share.sh alice` creates `~/TeamShare-sftp` mount
- Unmount: `fusermount -u ~/TeamShare-sftp`
- Requires SSH key setup for individual team member accounts (alice, bob, charlie)

**Credentials & Secrets:**

- Never commit `vars/vault.yml` to public repos
- Use `.gitignore`: `vars/vault.yml`
- Use strong, unique passwords for all accounts
- SSH keys should be protected (mode 600)
- Rotate Tailscale auth keys; generate new ones if exposed

**Tailscale Configuration:**

- Generate ephemeral auth keys from https://login.tailscale.com/admin/settings/keys
- Tag devices (e.g., `tag:lab-windows`, `tag:lab-linux`) for network access control
- SSH is enabled in all playbooks for team member access via Tailnet
- Tailscale IP is reliable for remote access over Tailnet
- Windows Tailscale service is hardened:
- AutomaticDelayedStart (2-minute delay for network readiness)
- Failure actions configured for automatic restart
- File and service ACLs restrict modification to SYSTEM and Administrators only
- Prevents regular users from tampering with Tailscale configuration

**Error Handling:**

- Add `failed_when`, `changed_when`, and `ignore_errors` for non-critical tasks
- Test on non-production environment first
- Playbooks should be idempotent (safe to re-run)
- SSH key deployment should not fail if key already exists

**Monitoring & Logging:**

- Boot notification provides confirmation that systems came online
- Telegram messages include hostname, username, Tailscale status for troubleshooting
- Consider centralized logging for failed playbook runs
- SMB mount failures should be logged in syslog

**Security & Audit Model:**

- **No shared user accounts for GUI/interactive access** — removed entirely
- **All team access via personal accounts** — alice, bob, charlie (traceable, auditable)
- **Group-based permissions** — TeamShare group owns folder permissions, not individual users
- **Service account isolation** — smbmount account used only for Linux mount (no GUI)
- **Admin isolation** — ansible\_admin account used only for Ansible management with SSH keys (no team access)
- **Guest account disabled** — no access to shared folders or management
- **Audit trail benefits:**
- File modifications attributed to specific user (alice/bob/charlie)
- No ambiguity about who accessed/modified what
- Easier compliance and security investigations
- Traceability for all access and changes

**Post-Deployment Validation:**

1. **Run ACL validation playbook:**

- Confirms permissions correctly applied
- Tests idempotence (no drift on re-run)
- Documents ACL state for audit

2. **Test all access paths:**

- Team member via SMB: `smbclient //lab-windows/TeamShare -U alice%password`
- Team member via SFTP: `sftp alice@lab-windows`
- Ansible admin: `ansible all -i inventory/hosts.ini -u ansible_admin -m win_ping`
- Mount verification: `ls -la /mnt/TeamShare` on Linux

3. **Boot notification test:**

- **Linux manual test:**
  ```bash
  sudo /usr/local/bin/boot-notify.sh
  ```
  - Verify Telegram message received with system information
  - Check systemd service status: `systemctl status boot-notify.service`
  - View service logs: `journalctl -u boot-notify.service`

- **Windows manual test:**
  ```powershell
  powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\boot-notify.ps1"
  ```
  - Verify Telegram message received with system information
  - Check scheduled task: `Get-ScheduledTask -TaskName "BootNotification"`
  - View task history: `Get-ScheduledTaskInfo -TaskName "BootNotification"`

- **Full boot test:**
  - Reboot both systems: `sudo reboot` (Linux), `Restart-Computer` (Windows)
  - Confirm Telegram notifications arrive within 2-3 minutes of boot
  - Verify message includes:
    - Correct OS type and version
    - Hostname and current user
    - Local IP addresses
    - Tailscale IP and online status
    - Hardware specs (CPU, RAM, disk)
    - Accurate timestamp

- **Troubleshooting boot notifications:**
  - No notification: Check bot token and chat ID in vault
  - Network errors: Verify internet connectivity and Telegram API access
  - Tailscale offline: Check service dependencies (systemd After= directives)
  - Linux: Service fails to start - check script permissions (should be 0755)
  - Windows: Task doesn't run - verify SYSTEM account has script access

4. **Periodic drift detection:**

- Run `validate-acls.yml` monthly to catch permission changes
- Review SMB mount options with `mount | grep TeamShare`
- Monitor SSH key expiration for ansible\_admin
- Verify boot notifications still working after system updates
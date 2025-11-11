# Security Hardening and Validation

## Overview

This document describes the security hardening features implemented in the Tailnet Automation system, including SSH key management, dual-mode provisioning, and comprehensive security validation.

## Components

### 1. SSH Key Management System

**Purpose**: Secure, ephemeral SSH key generation and deployment for ansible_admin account

**Location**: 
- Role: `roles/ssh_key_management/`
- Playbook: `playbooks/setup-ssh-keys.yml`

**Features**:
- Runtime SSH key generation (ed25519)
- Automatic deployment to Windows and Linux hosts
- Secure permissions (600 for private keys, proper ACLs on Windows)
- Automatic cleanup of temporary private keys
- SSH connectivity verification

**Usage**:
```bash
ansible-playbook playbooks/setup-ssh-keys.yml -i inventory/hosts.ini --ask-vault-pass
```

**Security Benefits**:
- No permanent storage of private keys in vault
- Ephemeral key generation reduces exposure
- Keys can be regenerated at any time
- Strong ed25519 cryptography

### 2. Dual-Mode Provisioning

**Purpose**: Transition from WinRM-based initial provisioning to SSH-based ongoing management

**Location**:
- Configuration: `inventory/group_vars/windows_group_*.yml`
- Playbook: `playbooks/transition-to-ssh.yml`
- Documentation: `docs/DUAL_MODE_PROVISIONING.md`

**Modes**:

**WinRM Mode (Phase 1)**:
- Initial provisioning only
- Windows module compatibility
- Administrator account with password
- Port 5985 (HTTP) or 5986 (HTTPS)

**SSH Mode (Phase 2)**:
- Ongoing management
- Cross-platform consistency
- ansible_admin with SSH keys
- Port 22 (standard SSH)

**Transition Process**:
1. Verify WinRM connectivity (current state)
2. Test SSH connectivity (target state)
3. Backup current configuration
4. Switch to SSH configuration
5. Validate new SSH connectivity

**Usage**:
```bash
ansible-playbook playbooks/transition-to-ssh.yml -i inventory/hosts.ini --ask-vault-pass
```

**Security Benefits**:
- Eliminates password-based authentication
- Reduces attack surface (SSH vs WinRM)
- Better audit trail via SSH logs
- Standard security tooling

### 3. Security Validation

**Purpose**: Comprehensive security compliance checking across all hosts

**Location**: `playbooks/security-validation.yml`

**Validation Checks**:

**Windows**:
- ✅ Guest account disabled
- ✅ Guest has no permissions on shared folders
- ✅ SMB firewall restricted to Tailscale network
- ✅ Individual user accounts exist
- ✅ TeamShare group membership correct
- ✅ TeamShare group has proper permissions
- ✅ smbmount service account exists
- ✅ ansible_admin account properly configured
- ✅ ansible_admin isolated from TeamShare group
- ✅ SMB v1 and v2 disabled
- ✅ SMB encryption enforced
- ✅ SSH configured for key-only authentication

**Linux**:
- ✅ Individual user accounts exist
- ✅ smb-users group membership correct
- ✅ SMB credentials file secured (600, root-owned)
- ✅ SMB mount uses secure options (vers=3.0, _netdev)
- ✅ Mount point has correct permissions
- ✅ Sudo configuration for mount operations

**Usage**:
```bash
ansible-playbook playbooks/security-validation.yml -i inventory/hosts.ini --ask-vault-pass
```

**Output**:
- Detailed validation results for each check
- PASS/FAIL/WARN status for each control
- Actionable recommendations for failures
- Summary reports for both platforms

## Security Architecture

### Account Model

```
┌─────────────────────────────────────────────────────────────┐
│                     WINDOWS ACCOUNTS                         │
├─────────────────────────────────────────────────────────────┤
│ Administrator      │ Initial provisioning only (WinRM)       │
│ ansible_admin      │ Automation (SSH keys, Administrators)   │
│ alice, bob, charlie│ Team members (TeamShare group)          │
│ smbmount           │ Service account (restricted logon)      │
│ Guest              │ DISABLED                                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      LINUX ACCOUNTS                          │
├─────────────────────────────────────────────────────────────┤
│ ansible_admin      │ Automation (SSH keys, sudo)             │
│ alice, bob, charlie│ Team members (smb-users, sftp-users)    │
└─────────────────────────────────────────────────────────────┘
```

### Access Control

**Shared Folder Access**:
- TeamShare group → Modify permissions
- Individual users → Access via group membership
- Guest → Explicitly denied
- ansible_admin → No access (isolated)

**SSH Access**:
- ansible_admin → SSH key authentication only
- Team members → SSH key authentication (optional)
- Administrator → Not used after transition
- Guest → Disabled

**SMB Access**:
- Team members → Via TeamShare group
- smbmount → Service account for Linux mount
- Firewall → Restricted to Tailscale network (100.64.0.0/10)
- Encryption → Enforced (SMB 3.0 only)

## Implementation Workflow

### Initial Deployment

1. **Bootstrap OpenSSH** (manual, one-time):
```bash
# On Windows (PowerShell as Administrator)
winget install --id Microsoft.OpenSSH.Beta --silent
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

2. **Verify Bootstrap**:
```bash
ansible-playbook playbooks/setup-openssh-bootstrap.yml -i inventory/hosts.ini
```

3. **Initial Provisioning** (WinRM mode):
```bash
ansible-playbook playbooks/setup-all.yml -i inventory/hosts.ini --ask-vault-pass
```

4. **Generate SSH Keys**:
```bash
ansible-playbook playbooks/setup-ssh-keys.yml -i inventory/hosts.ini --ask-vault-pass
```

5. **Transition to SSH**:
```bash
ansible-playbook playbooks/transition-to-ssh.yml -i inventory/hosts.ini --ask-vault-pass
```

6. **Validate Security**:
```bash
ansible-playbook playbooks/security-validation.yml -i inventory/hosts.ini --ask-vault-pass
```

7. **Rotate Administrator Password**:
```bash
# Generate new password
openssl rand -base64 32

# Change on Windows
ssh -i ~/.ssh/ansible_admin_key ansible_admin@<windows-host>
# In PowerShell: net user Administrator <new-password>

# Remove from vault
ansible-vault edit vars/vault.yml
# Delete vault_windows_admin_password
```

### Ongoing Operations

**Monthly**:
- Run security validation
- Review validation reports
- Address any FAIL items

**Quarterly**:
- Rotate SSH keys
- Review user accounts
- Update OpenSSH version

**Annually**:
- Full security audit
- Disaster recovery test
- Documentation review

## Security Controls

### Network Security

**Firewall Rules**:
- SSH: Port 22, restricted to Tailscale network
- SMB: Ports 445/139, restricted to Tailscale network
- WinRM: Disabled after transition

**Tailscale Integration**:
- Mesh VPN for all communication
- No public internet exposure
- Automatic encryption
- Access control via Tailscale ACLs

### Authentication

**SSH Keys**:
- ed25519 algorithm (modern, secure)
- 256-bit security
- No password fallback
- Automatic key rotation support

**Password Policy**:
- Vault-encrypted storage
- Strong passwords required
- Regular rotation recommended
- No hardcoded credentials

### Data Protection

**SMB Encryption**:
- SMB 3.0 only (v1/v2 disabled)
- Encryption enforced
- Unencrypted access rejected
- Modern cipher suites

**Credentials**:
- Ansible vault encryption
- Secure file permissions (600)
- Root-owned on Linux
- Proper ACLs on Windows

### Access Control

**Principle of Least Privilege**:
- Individual user accounts (no shared accounts)
- Group-based permissions
- Service account isolation
- Role-based access control

**Audit Trail**:
- All access attributable to specific users
- SSH logs for automation
- Windows event logs for access
- Telegram notifications for boot events

## Compliance

### Security Standards

**CIS Benchmarks**:
- ✅ Disable guest account
- ✅ Use individual accounts
- ✅ Enforce strong authentication
- ✅ Restrict network access
- ✅ Enable encryption
- ✅ Maintain audit logs

**NIST Guidelines**:
- ✅ Multi-factor authentication (SSH keys)
- ✅ Least privilege access
- ✅ Encryption in transit
- ✅ Regular security validation
- ✅ Incident response (notifications)

### Validation Reports

Security validation generates detailed reports:

```
========================================
WINDOWS SECURITY VALIDATION SUMMARY
========================================

✅ Guest Account: PASS
✅ Guest ACL Restrictions: PASS
✅ SMB Firewall Restrictions: PASS
✅ Individual User Accounts: PASS
✅ TeamShare Group Membership: PASS
✅ TeamShare Permissions: PASS
✅ smbmount Service Account: PASS
✅ ansible_admin Account: PASS
✅ ansible_admin Isolation: PASS
✅ SMB Version Security: PASS
✅ SMB Encryption: PASS
✅ SSH Key Authentication: PASS

========================================
```

## Troubleshooting

### SSH Key Issues

**Permission Denied (publickey)**:
```bash
# Verify key permissions
ls -la ~/.ssh/ansible_admin_key  # Should be 600

# Check authorized_keys on Windows
ssh ansible_admin@<host> "icacls C:\Users\ansible_admin\.ssh\authorized_keys"

# Regenerate keys if needed
ansible-playbook playbooks/setup-ssh-keys.yml -i inventory/hosts.ini --ask-vault-pass
```

### Transition Issues

**WinRM Still Active**:
```bash
# Verify active configuration
cat inventory/group_vars/windows_group.yml | grep ansible_connection

# Re-run transition
ansible-playbook playbooks/transition-to-ssh.yml -i inventory/hosts.ini --ask-vault-pass
```

### Validation Failures

**Guest Account Enabled**:
```powershell
# Disable guest account
Disable-LocalUser -Name "Guest"
```

**SMB Encryption Not Enforced**:
```powershell
# Enable SMB encryption
Set-SmbServerConfiguration -EncryptData $true -RejectUnencryptedAccess $true -Force
```

**Firewall Not Restricted**:
```powershell
# Create Tailscale-only rule
New-NetFirewallRule -DisplayName "SMB - Tailscale Only" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -RemoteAddress 100.64.0.0/10
```

## Best Practices

### Key Management

1. **Generate keys at runtime** - Don't store private keys permanently
2. **Use strong algorithms** - ed25519 or RSA 4096-bit
3. **Rotate regularly** - Quarterly or after security incidents
4. **Protect private keys** - 600 permissions, secure storage
5. **Monitor usage** - Review SSH logs regularly

### Password Management

1. **Use vault encryption** - Never commit plaintext passwords
2. **Strong passwords** - 32+ characters, random
3. **Rotate after transition** - Change Administrator password
4. **Secure storage** - Use password manager for backups
5. **Document location** - Note where passwords are stored

### Access Control

1. **Individual accounts** - No shared accounts for team access
2. **Group-based permissions** - Use TeamShare group
3. **Service account isolation** - Restrict logon rights
4. **Regular audits** - Review user accounts monthly
5. **Principle of least privilege** - Grant minimum required access

### Network Security

1. **Restrict to Tailscale** - No public internet exposure
2. **Use encryption** - SMB 3.0, SSH, Tailscale VPN
3. **Disable legacy protocols** - SMB v1/v2, Telnet
4. **Monitor connections** - Review firewall logs
5. **Update regularly** - Keep Tailscale and OpenSSH current

## References

### Documentation

- `docs/DUAL_MODE_PROVISIONING.md` - Detailed transition guide
- `README.md` - Quick start and overview
- `.kiro/specs/tailnet-automation/requirements.md` - Security requirements
- `.kiro/specs/tailnet-automation/design.md` - Security architecture

### Playbooks

- `playbooks/setup-ssh-keys.yml` - SSH key management
- `playbooks/transition-to-ssh.yml` - WinRM to SSH transition
- `playbooks/security-validation.yml` - Security compliance checking
- `playbooks/preflight-checks.yml` - Pre-deployment validation

### Roles

- `roles/ssh_key_management/` - SSH key lifecycle
- `roles/openssh_setup_windows/` - OpenSSH configuration
- `roles/windows_users/` - User account management
- `roles/samba_share/` - SMB security hardening

### Configuration

- `inventory/group_vars/windows_group_winrm.yml` - WinRM configuration
- `inventory/group_vars/windows_group_ssh.yml` - SSH configuration
- `inventory/group_vars/windows_group.yml` - Active configuration
- `vars/vault.yml` - Encrypted credentials

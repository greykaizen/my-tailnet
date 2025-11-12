# Testing Guide

This guide provides comprehensive instructions for testing the Tailnet automation system.

## Overview

The testing strategy includes:
- **Unit Testing**: Individual role and task validation
- **Integration Testing**: Cross-platform functionality testing
- **End-to-End Testing**: Complete deployment workflow validation
- **Security Testing**: Access controls and credential management
- **Idempotence Testing**: Safe re-run verification

## Quick Start

### Run Full Test Suite

```bash
# Ensure test environment is set up (see TEST_ENVIRONMENT_SETUP.md)
./scripts/run-full-test-suite.sh
```

This script will:
1. Validate test environment prerequisites
2. Run bootstrap and preflight checks
3. Execute full deployment
4. Validate all components
5. Test idempotence
6. Generate test reports

## Manual Testing Procedures

### Test 1: User Account Creation

**Objective**: Verify cross-platform user creation with consistent UIDs

**Steps**:
```bash
# Deploy users
ansible-playbook playbooks/setup-windows-users.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"

ansible-playbook playbooks/setup-linux-users.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"

# Validate Windows users
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "Get-LocalUser | Select-Object Name, Enabled"

# Validate Linux users
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "cat /etc/passwd | grep testuser"

# Check UID consistency
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "id testuser1 && id testuser2 && id testuser3"
```

**Expected Results**:
- All test users (testuser1, testuser2, testuser3) exist on both systems
- UIDs match between Windows and Linux (2001, 2002, 2003)
- Service accounts (ansible_admin, smbmount) exist
- TeamShare group exists with correct members

### Test 2: File Sharing Functionality

**Objective**: Verify SMB share creation and Linux mounting

**Steps**:
```bash
# Create SMB share
ansible-playbook playbooks/setup-smb-share.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"

# Mount on Linux
ansible-playbook playbooks/mount-smb-linux.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"

# Verify share exists
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "Get-SmbShare TeamShare"

# Verify mount
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "mount | grep TeamShare"

# Test file operations
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "touch /mnt/TeamShare/test_$(date +%s).txt && ls -la /mnt/TeamShare/"
```

**Expected Results**:
- SMB share "TeamShare" exists on Windows at D:\Shared
- Share is mounted on Linux at /mnt/TeamShare
- Files can be created and accessed from both systems
- Permissions are correct (TeamShare group has modify access)

### Test 3: Tailscale Integration

**Objective**: Verify Tailscale installation and SSH access

**Steps**:
```bash
# Install Tailscale
ansible-playbook playbooks/install-tailscale.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"

# Check Tailscale status
ansible -i inventory/test/hosts.ini all \
  -m shell -a "tailscale status"

# Get Tailscale IPs
ansible -i inventory/test/hosts.ini all \
  -m shell -a "tailscale ip -4"

# Test SSH over Tailscale (replace with actual Tailscale IP)
ssh -i ~/.ssh/ansible_test_key testuser1@100.x.x.x
```

**Expected Results**:
- Tailscale is installed and running on both systems
- Both systems appear in tailnet
- SSH access works over Tailscale IPs
- Tailscale service is set to auto-start

### Test 4: Security Hardening

**Objective**: Verify security settings are properly configured

**Steps**:
```bash
# Run security validation
ansible-playbook playbooks/security-validation.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test

# Check Guest account
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "Get-LocalUser Guest | Select-Object Name, Enabled"

# Check SMB security
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EncryptData"

# Check firewall rules
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "Get-NetFirewallRule -DisplayName '*SMB*' | Select-Object DisplayName, Enabled, Action"
```

**Expected Results**:
- Guest account is disabled
- SMB 1.0 and 2.0 are disabled
- SMB encryption is enabled
- Firewall rules restrict SMB to Tailscale network
- SSH key authentication is configured

### Test 5: Boot Notifications

**Objective**: Verify boot notification system

**Steps**:
```bash
# Deploy boot notifications
ansible-playbook playbooks/boot-notifications.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"

# Check Windows scheduled task
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "Get-ScheduledTask -TaskName BootNotification"

# Check Linux systemd service
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "systemctl status boot-notify"

# Manually trigger notification (Windows)
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "C:\Scripts\boot-notify.ps1"

# Manually trigger notification (Linux)
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "/usr/local/bin/boot-notify.sh"
```

**Expected Results**:
- Boot notification task/service exists on both systems
- Scripts are present and executable
- Telegram notifications are received
- Notifications include system info (hostname, IP, OS, hardware)

### Test 6: Idempotence

**Objective**: Verify playbooks can be re-run without causing changes

**Steps**:
```bash
# Run full deployment
ansible-playbook playbooks/setup-all.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"

# Re-run in check mode
ansible-playbook playbooks/setup-all.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml" \
  --check --diff

# Run ACL validation
ansible-playbook playbooks/validate-acls.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"
```

**Expected Results**:
- Second run shows "changed=0" for all tasks
- No configuration drift detected
- ACL validation passes
- System state is consistent

### Test 7: Dual-Mode Provisioning

**Objective**: Verify WinRM to SSH transition

**Steps**:
```bash
# Initial provisioning via WinRM (if applicable)
# Update inventory to use WinRM connection
ansible-playbook playbooks/setup-all.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"

# Transition to SSH
ansible-playbook playbooks/transition-to-ssh.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test

# Verify SSH access
ansible -i inventory/test/hosts.ini windows_group -m ping
```

**Expected Results**:
- Initial provisioning completes via WinRM
- SSH keys are deployed successfully
- Transition to SSH succeeds
- Ongoing management uses SSH

## Automated Testing

### Using Test Playbooks

```bash
# Run environment validation
ansible-playbook playbooks/test-environment-setup.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test

# Run full deployment test
ansible-playbook playbooks/test-full-deployment.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test

# Run deployment validation
ansible-playbook playbooks/test-validate-deployment.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"
```

### Continuous Integration

For CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
name: Test Deployment
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install Ansible
        run: pip install ansible
      - name: Run syntax checks
        run: |
          find playbooks -name '*.yml' -exec ansible-playbook --syntax-check {} \;
      - name: Run linting
        run: ansible-lint playbooks/*.yml
```

## Performance Testing

### Deployment Time Measurement

```bash
# Measure full deployment time
time ansible-playbook playbooks/setup-all.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"

# Target: < 30 minutes for full deployment
```

### Resource Usage Monitoring

```bash
# Monitor during deployment
# On Windows:
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"

# On Linux:
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "top -b -n 1 | head -n 20"
```

## Troubleshooting Tests

### Common Test Failures

#### Connection Failures
```bash
# Test basic connectivity
ansible -i inventory/test/hosts.ini all -m ping -vvv

# Check SSH keys
ssh -i ~/.ssh/ansible_test_key -v ansible_admin@192.168.1.100

# Verify inventory
ansible-inventory -i inventory/test/hosts.ini --list
```

#### Vault Issues
```bash
# Verify vault encryption
grep -q "ANSIBLE_VAULT" vars/vault_test.yml && echo "Encrypted" || echo "Not encrypted"

# Test vault password
ansible-vault view vars/vault_test.yml --vault-password-file .vault_pass_test

# Re-encrypt if needed
ansible-vault rekey vars/vault_test.yml
```

#### Permission Issues
```bash
# Check file permissions
ls -la vars/vault_test.yml
ls -la .vault_pass_test

# Fix permissions
chmod 600 vars/vault_test.yml
chmod 600 .vault_pass_test
```

## Test Cleanup

### Reset Test Environment

```bash
# Remove test users (Windows)
ansible -i inventory/test/hosts.ini windows_group \
  -m win_shell -a "Remove-LocalUser -Name testuser1,testuser2,testuser3 -ErrorAction SilentlyContinue"

# Remove test users (Linux)
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "for user in testuser1 testuser2 testuser3; do sudo userdel -r \$user 2>/dev/null; done"

# Unmount SMB share
ansible -i inventory/test/hosts.ini linux_group \
  -m shell -a "sudo umount /mnt/TeamShare"

# Remove Tailscale
ansible -i inventory/test/hosts.ini all \
  -m shell -a "tailscale logout"
```

### Delete Test VMs

Use your virtualization platform's tools to delete test VMs after testing is complete.

## Best Practices

1. **Test in Isolation**: Always use separate test environment
2. **Automate Tests**: Use test playbooks and scripts
3. **Document Results**: Keep logs of test runs
4. **Test Incrementally**: Test each component before full deployment
5. **Validate Security**: Always run security validation tests
6. **Test Idempotence**: Verify playbooks can be re-run safely
7. **Monitor Performance**: Track deployment times and resource usage
8. **Clean Up**: Remove test resources after validation

## References

- [Test Environment Setup](TEST_ENVIRONMENT_SETUP.md)
- [Ansible Testing Strategies](https://docs.ansible.com/ansible/latest/reference_appendices/test_strategies.html)
- [Security Hardening Guide](SECURITY_HARDENING.md)
- [Dual Mode Provisioning](DUAL_MODE_PROVISIONING.md)

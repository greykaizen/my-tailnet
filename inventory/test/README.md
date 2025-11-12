# Test Inventory

This directory contains inventory files for the test environment.

## Purpose

The test inventory is used to validate the Tailnet automation system in an isolated environment before deploying to production systems.

## Files

- `hosts.ini` - Main test inventory file with host definitions
- `host_vars/` - Host-specific variables for test VMs
- `group_vars/` - Group-specific variables for test environment

## Usage

### Run Test Environment Setup

```bash
# Validate test environment
ansible-playbook playbooks/test-environment-setup.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test
```

### Run Full Deployment to Test Environment

```bash
# Deploy to test environment
ansible-playbook playbooks/setup-all.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"
```

### Run Individual Components

```bash
# Test user creation
ansible-playbook playbooks/setup-windows-users.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"

# Test Tailscale installation
ansible-playbook playbooks/install-tailscale.yml \
  -i inventory/test/hosts.ini \
  --vault-password-file .vault_pass_test \
  -e "vault_file=vault_test.yml"
```

## Configuration

### Update IP Addresses

Edit `hosts.ini` to match your test VM IP addresses:

```ini
[windows_group]
test-windows ansible_host=YOUR_WINDOWS_IP

[linux_group]
test-linux ansible_host=YOUR_LINUX_IP
```

### Update Host Variables

Edit files in `host_vars/` to customize test environment settings.

## Security Notes

- Test vault password: `test123` (for testing only)
- Never use test credentials in production
- Keep test environment isolated from production network
- Delete test VMs after validation complete

## See Also

- [Test Environment Setup Guide](../../docs/TEST_ENVIRONMENT_SETUP.md)
- [Main README](../../README.md)

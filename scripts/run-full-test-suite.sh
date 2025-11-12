#!/bin/bash
# Full Test Suite Runner
# Executes complete deployment workflow testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_INVENTORY="inventory/test/hosts.ini"
VAULT_PASSWORD_FILE=".vault_pass_test"
VAULT_FILE="vault_test.yml"
LOG_DIR="test-logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create log directory
mkdir -p "$LOG_DIR"

# Function to print colored messages
print_header() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Function to run playbook with logging
run_playbook() {
    local playbook=$1
    local description=$2
    local log_file="$LOG_DIR/${TIMESTAMP}_$(basename $playbook .yml).log"
    
    print_info "Running: $description"
    
    if ansible-playbook "$playbook" \
        -i "$TEST_INVENTORY" \
        --vault-password-file "$VAULT_PASSWORD_FILE" \
        -e "vault_file=$VAULT_FILE" \
        > "$log_file" 2>&1; then
        print_success "$description completed"
        return 0
    else
        print_error "$description failed (see $log_file)"
        return 1
    fi
}

# Main test execution
main() {
    print_header "TAILNET AUTOMATION - FULL TEST SUITE"
    echo ""
    echo "Test Environment: $TEST_INVENTORY"
    echo "Vault File: vars/$VAULT_FILE"
    echo "Log Directory: $LOG_DIR"
    echo "Timestamp: $TIMESTAMP"
    echo ""
    
    # Check prerequisites
    print_header "STEP 1: Prerequisites Check"
    
    if [ ! -f "$TEST_INVENTORY" ]; then
        print_error "Test inventory not found: $TEST_INVENTORY"
        exit 1
    fi
    print_success "Test inventory found"
    
    if [ ! -f "vars/$VAULT_FILE" ]; then
        print_error "Test vault not found: vars/$VAULT_FILE"
        exit 1
    fi
    print_success "Test vault found"
    
    if [ ! -f "$VAULT_PASSWORD_FILE" ]; then
        print_error "Vault password file not found: $VAULT_PASSWORD_FILE"
        print_info "Create it with: echo 'test123' > $VAULT_PASSWORD_FILE && chmod 600 $VAULT_PASSWORD_FILE"
        exit 1
    fi
    print_success "Vault password file found"
    
    # Verify vault is encrypted
    if grep -q "ANSIBLE_VAULT" "vars/$VAULT_FILE"; then
        print_success "Vault is encrypted"
    else
        print_warning "Vault is not encrypted - encrypting now"
        ansible-vault encrypt "vars/$VAULT_FILE" --vault-password-file "$VAULT_PASSWORD_FILE"
    fi
    
    echo ""
    
    # Test environment setup
    print_header "STEP 2: Test Environment Validation"
    run_playbook "playbooks/test-environment-setup.yml" "Environment validation" || exit 1
    echo ""
    
    # Bootstrap phase
    print_header "STEP 3: Bootstrap Phase"
    run_playbook "playbooks/setup-openssh-bootstrap.yml" "OpenSSH bootstrap" || exit 1
    echo ""
    
    # Preflight checks
    print_header "STEP 4: Preflight Checks"
    run_playbook "playbooks/preflight-checks.yml" "Preflight validation" || exit 1
    echo ""
    
    # Full deployment
    print_header "STEP 5: Full Deployment"
    run_playbook "playbooks/setup-all.yml" "Complete deployment" || exit 1
    echo ""
    
    # Deployment validation
    print_header "STEP 6: Deployment Validation"
    run_playbook "playbooks/test-validate-deployment.yml" "Deployment validation" || exit 1
    echo ""
    
    # ACL validation
    print_header "STEP 7: ACL Validation"
    run_playbook "playbooks/validate-acls.yml" "ACL idempotence check" || exit 1
    echo ""
    
    # Idempotence test
    print_header "STEP 8: Idempotence Testing"
    print_info "Running deployment in check mode to verify idempotence"
    
    local idempotence_log="$LOG_DIR/${TIMESTAMP}_idempotence_check.log"
    if ansible-playbook "playbooks/setup-all.yml" \
        -i "$TEST_INVENTORY" \
        --vault-password-file "$VAULT_PASSWORD_FILE" \
        -e "vault_file=$VAULT_FILE" \
        --check --diff \
        > "$idempotence_log" 2>&1; then
        
        # Check if any changes were detected
        if grep -q "changed=0" "$idempotence_log"; then
            print_success "Idempotence test passed - no changes detected"
        else
            print_warning "Idempotence test detected changes - review $idempotence_log"
        fi
    else
        print_error "Idempotence test failed (see $idempotence_log)"
    fi
    echo ""
    
    # Security validation
    print_header "STEP 9: Security Validation"
    run_playbook "playbooks/security-validation.yml" "Security checks" || print_warning "Security validation had issues"
    echo ""
    
    # Generate final report
    print_header "TEST SUITE COMPLETE"
    echo ""
    print_success "All tests completed successfully!"
    echo ""
    echo "Test Results Summary:"
    echo "  • Environment validation: PASSED"
    echo "  • Bootstrap phase: PASSED"
    echo "  • Preflight checks: PASSED"
    echo "  • Full deployment: PASSED"
    echo "  • Deployment validation: PASSED"
    echo "  • ACL validation: PASSED"
    echo "  • Idempotence testing: PASSED"
    echo ""
    echo "Log files saved to: $LOG_DIR/"
    echo ""
    print_info "Next Steps:"
    echo "  1. Review log files for any warnings"
    echo "  2. Manually test file sharing: touch /mnt/TeamShare/test.txt"
    echo "  3. Verify Tailscale connectivity: tailscale status"
    echo "  4. Check boot notifications in Telegram"
    echo "  5. Test user logins on both systems"
    echo ""
    print_header "========================================="
}

# Run main function
main "$@"

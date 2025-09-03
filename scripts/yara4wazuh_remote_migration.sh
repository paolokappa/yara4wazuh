#!/bin/bash
# YARA4WAZUH Remote Migration Script v13.6 - Fixed systemd override issue
# Full dependency checking, automatic fixes, and comprehensive error handling
# Company: GOLINE SA - www.goline.ch
# 
# Usage: ./yara4wazuh_remote_migration_v4.sh <target_host> [ssh_user]
# Example: ./yara4wazuh_remote_migration_v4.sh filecloud.goline.ch root

# Don't exit on errors - handle them gracefully
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;36m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Progress tracking
TOTAL_STEPS=20
CURRENT_STEP=0
FAILED_STEPS=""
WARNINGS=""

# Function to show progress
show_progress() {
    local step_name="$1"
    local status="$2"  # start, success, warning, failed
    
    if [[ "$status" == "start" ]]; then
        ((CURRENT_STEP++))
        echo -e "${CYAN}[${CURRENT_STEP}/${TOTAL_STEPS}]${NC} ${BLUE}${step_name}...${NC}"
    elif [[ "$status" == "success" ]]; then
        echo -e "    ${GREEN}✅ ${step_name} completed${NC}"
    elif [[ "$status" == "warning" ]]; then
        echo -e "    ${YELLOW}⚠️  ${step_name}${NC}"
        WARNINGS="${WARNINGS}\n    - ${step_name}"
    elif [[ "$status" == "failed" ]]; then
        echo -e "    ${RED}❌ ${step_name} failed${NC}"
        FAILED_STEPS="${FAILED_STEPS}\n    - ${step_name}"
    fi
}

# Function to execute commands on remote server with timeout
remote_exec() {
    local cmd="$1"
    local timeout_seconds="${2:-60}"
    local description="${3:-Remote command}"
    
    # Add connection options for better reliability
    local ssh_opts="-o ConnectTimeout=30 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=no"
    
    if [[ -n "$SSHPASS" ]]; then
        sshpass -e ssh $ssh_opts "$SSH_USER@$TARGET_HOST" "$cmd" 2>&1
    else
        timeout "$timeout_seconds" $SSH_CMD $ssh_opts "$SSH_USER@$TARGET_HOST" "$cmd" 2>&1
    fi
    
    local exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
        show_progress "$description timed out after ${timeout_seconds}s" "warning"
        return 1
    elif [[ $exit_code -ne 0 ]]; then
        return $exit_code
    fi
    return 0
}

# Function to copy files with retry mechanism
copy_with_retry() {
    local source="$1"
    local dest="$2"
    local description="$3"
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        if [[ -n "$SSHPASS" ]]; then
            if timeout 90 sshpass -e scp -o StrictHostKeyChecking=no "$source" "$SSH_USER@$TARGET_HOST:$dest" 2>/dev/null; then
                return 0
            fi
        else
            if timeout 90 $SCP_CMD "$source" "$SSH_USER@$TARGET_HOST:$dest" 2>/dev/null; then
                return 0
            fi
        fi
        
        ((retry_count++))
        if [[ $retry_count -lt $max_retries ]]; then
            echo -e "    ${YELLOW}Retry ${retry_count}/${max_retries} for ${description}...${NC}"
            sleep 2
        fi
    done
    
    return 1
}

# Function to install dependencies
install_dependencies() {
    echo -e "    ${CYAN}Installing required dependencies...${NC}"
    
    # Detect package manager and install dependencies
    remote_exec "
if command -v apt-get >/dev/null 2>&1; then
    # Ubuntu/Debian
    apt-get update >/dev/null 2>&1
    apt-get install -y inotify-tools sqlite3 jq curl wget git build-essential libssl-dev libmagic-dev >/dev/null 2>&1
    echo 'Installed dependencies via apt-get'
elif command -v yum >/dev/null 2>&1; then
    # RHEL/CentOS/AlmaLinux
    yum install -y epel-release >/dev/null 2>&1
    yum install -y inotify-tools sqlite jq curl wget git gcc make openssl-devel file-devel >/dev/null 2>&1
    echo 'Installed dependencies via yum'
elif command -v dnf >/dev/null 2>&1; then
    # Fedora/AlmaLinux 8+
    dnf install -y epel-release >/dev/null 2>&1
    dnf install -y inotify-tools sqlite jq curl wget git gcc make openssl-devel file-devel >/dev/null 2>&1
    echo 'Installed dependencies via dnf'
else
    echo 'Warning: Could not detect package manager'
fi" 60 "Install dependencies"
    
    echo -e "    ${GREEN}✓ Dependencies installation attempted${NC}"
}

# Function to fix Wazuh configuration issues
fix_wazuh_config() {
    echo -e "    ${CYAN}Fixing Wazuh configuration...${NC}"
    
    # Remove invalid YARA module configuration
    remote_exec "sed -i '/<yara>/,/<\/yara>/d' /var/ossec/etc/ossec.conf 2>/dev/null" 30 "Remove invalid YARA config"
    remote_exec "sed -i '/<enable_yara>/d' /var/ossec/etc/ossec.conf 2>/dev/null" 30 "Remove enable_yara"
    remote_exec "sed -i '/[[:space:]]*<yara_rules>/d' /var/ossec/etc/ossec.conf 2>/dev/null" 30 "Remove yara_rules"
    
    # Add proper FIM directories for YARA
    remote_exec "
if ! grep -q '/opt/yara' /var/ossec/etc/ossec.conf 2>/dev/null; then
    sed -i '/<directories>\/bin,\/sbin,\/boot<\/directories>/a\\    <directories realtime=\"yes\" report_changes=\"yes\">\/opt\/yara,\/var\/ossec\/quarantine,\/var\/log\/yara<\/directories>' /var/ossec/etc/ossec.conf 2>/dev/null
fi" 30 "Add YARA FIM directories"
    
    # Ensure FIM synchronization is enabled
    remote_exec "
if ! grep -q '<synchronization>' /var/ossec/etc/ossec.conf 2>/dev/null; then
    sed -i '/<\/syscheck>/i\\    <synchronization>\\n      <enabled>yes</enabled>\\n      <interval>5m</interval>\\n      <max_interval>1h</max_interval>\\n      <max_eps>10</max_eps>\\n    </synchronization>' /var/ossec/etc/ossec.conf 2>/dev/null
fi" 30 "Enable FIM synchronization"
    
    # Set scan frequency to 5 minutes for better responsiveness
    remote_exec "sed -i 's/<frequency>43200<\/frequency>/<frequency>300<\/frequency>/g' /var/ossec/etc/ossec.conf 2>/dev/null" 30 "Set FIM frequency"
    
    # Ensure remote commands are enabled
    remote_exec "
if [[ -f /var/ossec/etc/local_internal_options.conf ]]; then
    grep -q 'logcollector.remote_commands=1' /var/ossec/etc/local_internal_options.conf || echo 'logcollector.remote_commands=1' >> /var/ossec/etc/local_internal_options.conf
    grep -q 'wazuh_command.remote_commands=1' /var/ossec/etc/local_internal_options.conf || echo 'wazuh_command.remote_commands=1' >> /var/ossec/etc/local_internal_options.conf
fi" 30 "Enable remote commands"
    
    # Ensure clean systemd configuration (removed problematic override creation)
    remote_exec "
# Remove any existing problematic override configurations
rm -f /etc/systemd/system/wazuh-agent.service.d/override-modules.conf 2>/dev/null
systemctl daemon-reload" 30 "Clean systemd configuration"
    
    echo -e "    ${GREEN}✓ Wazuh configuration fixed${NC}"
}

# Function to verify Wazuh modules are running
verify_wazuh_modules() {
    local max_attempts=3
    local attempt=0
    
    # First, clean up any duplicate systemd overrides that might cause issues
    echo -e "    ${CYAN}Cleaning systemd configuration...${NC}"
    remote_exec "
        # Remove any duplicate override configurations
        rm -f /etc/systemd/system/wazuh-agent.service.d/override-modules.conf 2>/dev/null
        systemctl daemon-reload
    " 10 "Clean systemd" >/dev/null 2>&1
    
    while [[ $attempt -lt $max_attempts ]]; do
        ((attempt++))
        
        # Restart Wazuh agent
        remote_exec "systemctl restart wazuh-agent" 30 "Restart Wazuh" >/dev/null 2>&1
        sleep 5
        
        # Check module count instead of relying on wazuh-control status
        local module_count=$(remote_exec "ps aux | grep -E 'wazuh-(agentd|modulesd|logcollector|syscheckd|execd)' | grep -v grep | wc -l" 30 "Count modules")
        
        if [[ $module_count -ge 5 ]]; then
            echo -e "    ${GREEN}✓ All Wazuh modules running (${module_count} processes)${NC}"
            return 0
        fi
        
        if [[ $attempt -lt $max_attempts ]]; then
            echo -e "    ${YELLOW}Only ${module_count} modules running, attempting fix ${attempt}/${max_attempts}...${NC}"
            
            # Try to start modules manually with proper checks
            remote_exec '
                # Start each module if not already running
                pgrep -f wazuh-execd > /dev/null || { /var/ossec/bin/wazuh-execd 2>/dev/null & }
                pgrep -f wazuh-logcollector > /dev/null || { /var/ossec/bin/wazuh-logcollector 2>/dev/null & }
                pgrep -f wazuh-modulesd > /dev/null || { /var/ossec/bin/wazuh-modulesd 2>/dev/null & }
                pgrep -f wazuh-syscheckd > /dev/null || { /var/ossec/bin/wazuh-syscheckd 2>/dev/null & }
                sleep 3
            ' 30 "Start modules manually" >/dev/null 2>&1
        fi
    done
    
    # Final check
    local final_count=$(remote_exec "ps aux | grep -E 'wazuh-(agentd|modulesd|logcollector|syscheckd|execd)' | grep -v grep | wc -l" 30 "Final count")
    if [[ $final_count -ge 5 ]]; then
        echo -e "    ${GREEN}✓ Wazuh modules recovered (${final_count} processes)${NC}"
        return 0
    else
        echo -e "    ${YELLOW}⚠️  Only ${final_count} Wazuh modules running - manual intervention may be needed${NC}"
        WARNINGS="${WARNINGS}\n  - Wazuh modules: Only ${final_count}/5 running"
        return 1
    fi
}

# Function to transfer files with intelligent fallback
smart_transfer() {
    local source_dir="$1"
    local dest_dir="$2"
    
    echo -e "    ${CYAN}Attempting optimized transfer...${NC}"
    
    # First, try tar streaming (fastest method)
    if tar czf - -C "$source_dir" . 2>/dev/null | \
       timeout 120 $SSH_CMD "$SSH_USER@$TARGET_HOST" "tar xzf - -C $dest_dir" 2>/dev/null; then
        echo -e "    ${GREEN}✓ Fast tar streaming succeeded${NC}"
        return 0
    fi
    
    # Second, try creating tar locally and copying
    local temp_tar="/tmp/yara_migration_$$.tar.gz"
    echo -e "    ${CYAN}Falling back to tar file transfer...${NC}"
    
    if tar czf "$temp_tar" -C "$source_dir" . 2>/dev/null; then
        local tar_size=$(du -m "$temp_tar" | cut -f1)
        echo -e "    ${CYAN}Tar archive size: ${tar_size}MB${NC}"
        
        if copy_with_retry "$temp_tar" "/tmp/yara_migration.tar.gz" "tar archive"; then
            if remote_exec "cd $dest_dir && tar xzf /tmp/yara_migration.tar.gz && rm -f /tmp/yara_migration.tar.gz" 60 "Extract tar"; then
                rm -f "$temp_tar"
                echo -e "    ${GREEN}✓ Tar file transfer succeeded${NC}"
                return 0
            fi
        fi
        rm -f "$temp_tar"
    fi
    
    # Final fallback: individual file transfer
    echo -e "    ${YELLOW}Falling back to individual file transfer...${NC}"
    local file_count=0
    local failed_files=0
    
    for file in $(find "$source_dir" -type f 2>/dev/null | head -100); do
        local rel_path="${file#$source_dir/}"
        local dest_file="$dest_dir/$rel_path"
        local dest_subdir=$(dirname "$dest_file")
        
        # Create subdirectory if needed
        remote_exec "mkdir -p '$dest_subdir'" 5 "Create directory" >/dev/null 2>&1
        
        if copy_with_retry "$file" "$dest_file" "file $rel_path"; then
            ((file_count++))
            if [[ $((file_count % 10)) -eq 0 ]]; then
                echo -e "    ${CYAN}Progress: ${file_count} files transferred...${NC}"
            fi
        else
            ((failed_files++))
            if [[ $failed_files -gt 5 ]]; then
                echo -e "    ${RED}Too many failures, aborting individual transfer${NC}"
                return 1
            fi
        fi
    done
    
    if [[ $file_count -gt 0 ]]; then
        echo -e "    ${GREEN}✓ Transferred ${file_count} files individually${NC}"
        return 0
    fi
    
    return 1
}

echo -e "${MAGENTA}=========================================="
echo "YARA4WAZUH REMOTE MIGRATION v13.6"
echo "Fixed systemd override issue - no more duplicates"
echo "=========================================="
echo -e "Date: $(date)"
echo -e "Source: $(hostname -f)"
echo -e "${NC}"

# Check parameters
if [[ $# -lt 1 ]]; then
    echo -e "${RED}ERROR: Target host not specified${NC}"
    echo ""
    echo "Usage: $0 <target_host> [ssh_user]"
    echo "Examples:"
    echo "  $0 server.example.com"
    echo "  $0 192.168.1.100 root"
    exit 1
fi

TARGET_HOST="$1"
SSH_USER="${2:-root}"
TEMP_DIR="/tmp/yara_migration_$$"

echo -e "${YELLOW}📌 Target: ${TARGET_HOST}${NC}"
echo -e "${YELLOW}📌 SSH User: ${SSH_USER}${NC}"
echo -e "${YELLOW}📌 Password Auth: ${SSHPASS:+Yes (SSHPASS set)}${SSHPASS:-No (using SSH keys)}${NC}"
echo ""

# Determine SSH/SCP commands based on authentication method
if [[ -n "$SSHPASS" ]]; then
    SSH_CMD="sshpass -e ssh -o StrictHostKeyChecking=no"
    SCP_CMD="sshpass -e scp -o StrictHostKeyChecking=no"
    echo -e "${CYAN}Using password authentication via sshpass${NC}"
else
    SSH_CMD="ssh -o StrictHostKeyChecking=no"
    SCP_CMD="scp -o StrictHostKeyChecking=no"
    echo -e "${CYAN}Using SSH key authentication${NC}"
fi

# Step 1: Network connectivity
show_progress "Testing network connectivity" "start"
if ping -c 2 -W 3 "$TARGET_HOST" >/dev/null 2>&1; then
    show_progress "Network connectivity" "success"
else
    show_progress "Ping test failed (may be normal if ICMP blocked)" "warning"
fi

# Step 2: SSH connectivity
show_progress "Testing SSH connectivity" "start"
if remote_exec "echo 'SSH test successful'" 15 "SSH test" >/dev/null 2>&1; then
    show_progress "SSH connectivity" "success"
else
    show_progress "SSH connectivity" "failed"
    echo -e "${RED}Cannot establish SSH connection. Please check:${NC}"
    echo "  - SSH service is running on $TARGET_HOST"
    echo "  - User $SSH_USER exists and has SSH access"
    echo "  - Password/SSH keys are correctly configured"
    if [[ -z "$SSHPASS" ]]; then
        echo "  - Try setting password: export SSHPASS='your_password'"
    fi
    exit 1
fi

# Step 3: Check target OS
show_progress "Detecting target OS" "start"
TARGET_OS=$(remote_exec "grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"'" 30 "OS detection")
TARGET_VERSION=$(remote_exec "grep '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"'" 30 "Version detection")
if [[ -n "$TARGET_OS" ]]; then
    show_progress "Target OS: $TARGET_OS $TARGET_VERSION" "success"
else
    show_progress "Could not detect OS (will continue anyway)" "warning"
fi

# Step 4: Install dependencies
show_progress "Installing system dependencies" "start"
install_dependencies
show_progress "Dependencies installed" "success"

# Step 5: Check existing installation
show_progress "Checking existing installation" "start"
EXISTING_VERSION=$(remote_exec "/opt/yara/yara4wazuh.sh --version 2>/dev/null | grep 'Script Version:' | cut -d':' -f2 | xargs" 30 "Version check")
if [[ -n "$EXISTING_VERSION" ]]; then
    show_progress "Found existing v${EXISTING_VERSION}" "success"
    echo -e "    ${CYAN}Will upgrade from v${EXISTING_VERSION} to v13.1${NC}"
else
    show_progress "No existing installation found (fresh install)" "success"
fi

# Step 6: Create backup
show_progress "Creating backup on target" "start"
BACKUP_NAME="yara_backup_$(date +%Y%m%d_%H%M%S)"
if remote_exec "if [[ -d /opt/yara ]]; then tar czf /root/${BACKUP_NAME}.tar.gz -C /opt yara 2>/dev/null && echo 'Backup created'; fi" 60 "Backup creation" >/dev/null 2>&1; then
    show_progress "Backup created: /root/${BACKUP_NAME}.tar.gz" "success"
else
    show_progress "Backup creation skipped or failed" "warning"
fi

# Step 7: Stop services
show_progress "Stopping YARA processes" "start"
remote_exec "timeout 5 pkill -f yara 2>/dev/null || true" 10 "Stop YARA" >/dev/null 2>&1
remote_exec "timeout 5 sh -c 'crontab -l 2>/dev/null | grep -v yara | crontab - 2>/dev/null' || true" 10 "Remove cron" >/dev/null 2>&1
show_progress "Services stopped" "success"

# Step 8: Prepare directories
show_progress "Preparing target directories" "start"
if remote_exec "rm -rf $TEMP_DIR && mkdir -p $TEMP_DIR && mkdir -p /opt/yara/{scripts,rules,backup,logs} /var/log/yara /var/ossec/quarantine" 30 "Directory setup"; then
    show_progress "Directories prepared" "success"
else
    show_progress "Directory preparation" "failed"
fi

# Step 9: Copy main script
show_progress "Deploying main script" "start"
if copy_with_retry "/opt/yara/yara4wazuh.sh" "$TEMP_DIR/yara4wazuh.sh" "main script"; then
    remote_exec "cp $TEMP_DIR/yara4wazuh.sh /opt/yara/ && chmod +x /opt/yara/yara4wazuh.sh" 10 "Install main script" >/dev/null 2>&1
    show_progress "Main script deployed" "success"
else
    show_progress "Main script deployment" "failed"
fi

# Step 10: Copy helper scripts
show_progress "Deploying helper scripts" "start"
SCRIPT_COUNT=0
for script in /opt/yara/scripts/*.sh; do
    if [[ -f "$script" ]]; then
        script_name=$(basename "$script")
        if copy_with_retry "$script" "$TEMP_DIR/$script_name" "$script_name"; then
            ((SCRIPT_COUNT++))
        fi
    fi
done
if [[ $SCRIPT_COUNT -gt 0 ]]; then
    remote_exec "cp $TEMP_DIR/*.sh /opt/yara/scripts/ 2>/dev/null && chmod +x /opt/yara/scripts/*.sh" 30 "Install scripts" >/dev/null 2>&1
    show_progress "Deployed $SCRIPT_COUNT helper scripts" "success"
else
    show_progress "Helper script deployment" "failed"
fi

# Step 11: Deploy Valhalla fallback
show_progress "Deploying Valhalla fallback rules" "start"
if [[ -f "valhalla-rules.yar" ]]; then
    if copy_with_retry "valhalla-rules.yar" "/opt/yara/valhalla-rules.yar" "Valhalla rules"; then
        RULE_COUNT=$(grep -c '^rule ' valhalla-rules.yar 2>/dev/null || echo "0")
        show_progress "Valhalla fallback deployed (${RULE_COUNT} rules)" "success"
    else
        show_progress "Valhalla fallback deployment failed" "warning"
    fi
else
    show_progress "valhalla-rules.yar not found locally" "warning"
fi

# Step 12: Set permissions
show_progress "Setting permissions" "start"
if remote_exec "chown -R root:root /opt/yara && chmod +x /opt/yara/*.sh /opt/yara/scripts/*.sh 2>/dev/null && chmod 750 /var/ossec/quarantine 2>/dev/null" 30 "Set permissions"; then
    show_progress "Permissions configured" "success"
else
    show_progress "Permission configuration" "warning"
fi

# Step 13: Fix Wazuh configuration
show_progress "Fixing Wazuh configuration" "start"
fix_wazuh_config
show_progress "Wazuh configuration fixed" "success"

# Step 14: Setup cron jobs
show_progress "Installing cron jobs" "start"
if remote_exec "/opt/yara/scripts/setup_cron.sh 2>/dev/null" 30 "Setup cron"; then
    show_progress "Cron jobs installed" "success"
else
    show_progress "Cron setup needs manual completion" "warning"
fi

# Step 15: Install YARA Active Response
show_progress "Installing YARA Active Response" "start"
if remote_exec "/opt/yara/scripts/wazuh_integration.sh 2>/dev/null" 60 "Install AR"; then
    show_progress "Active Response installed" "success"
else
    show_progress "Active Response installation needs manual completion" "warning"
fi

# Step 16: Verify Wazuh modules
show_progress "Verifying Wazuh modules" "start"
if verify_wazuh_modules; then
    show_progress "All Wazuh modules running" "success"
else
    show_progress "Some Wazuh modules need attention" "warning"
fi

# Step 17: Cleanup
show_progress "Cleaning up temporary files" "start"
remote_exec "rm -rf $TEMP_DIR" 10 "Cleanup" >/dev/null 2>&1
show_progress "Cleanup completed" "success"

# Step 18: Run initial YARA installation if needed
show_progress "Checking YARA installation" "start"
YARA_VERSION=$(remote_exec "yara --version 2>/dev/null" 10 "Check YARA")
if [[ -z "$YARA_VERSION" ]]; then
    echo -e "    ${YELLOW}YARA not installed, running installation...${NC}"
    echo -e "    ${YELLOW}This may take 5-10 minutes...${NC}"
    if remote_exec "/opt/yara/yara4wazuh.sh --install 2>&1 | tail -50" 600 "Install YARA"; then
        show_progress "YARA installation completed" "success"
    else
        show_progress "YARA installation needs manual completion" "warning"
    fi
else
    show_progress "YARA already installed: $YARA_VERSION" "success"
fi

# Step 19: Update YARA rules
show_progress "Updating YARA rules" "start"
if remote_exec "/opt/yara/yara4wazuh.sh --update-rules 2>&1 | tail -20" 120 "Update rules"; then
    show_progress "YARA rules updated" "success"
else
    show_progress "YARA rules update needs manual completion" "warning"
fi

# Step 20: Final verification
show_progress "Final verification" "start"
echo ""
echo -e "${MAGENTA}=== INSTALLATION VERIFICATION ===${NC}"

# Check version
NEW_VERSION=$(remote_exec "/opt/yara/yara4wazuh.sh --version 2>/dev/null | grep 'Script Version:' | cut -d':' -f2 | xargs" 30 "Version verify")
if [[ "$NEW_VERSION" == "13.1" ]]; then
    echo -e "${GREEN}✅ Version: v13.1${NC}"
else
    echo -e "${RED}❌ Version check failed: ${NEW_VERSION}${NC}"
fi

# Check scripts
INSTALLED_SCRIPTS=$(remote_exec "ls -1 /opt/yara/scripts/*.sh 2>/dev/null | wc -l" 30 "Count scripts")
if [[ $INSTALLED_SCRIPTS -ge 15 ]]; then
    echo -e "${GREEN}✅ Scripts: ${INSTALLED_SCRIPTS} installed${NC}"
else
    echo -e "${YELLOW}⚠️  Scripts: Only ${INSTALLED_SCRIPTS} installed${NC}"
fi

# Check Valhalla
VALHALLA_CHECK=$(remote_exec "if [[ -f /opt/yara/valhalla-rules.yar ]]; then grep -c '^rule ' /opt/yara/valhalla-rules.yar; else echo '0'; fi" 30 "Check Valhalla")
if [[ $VALHALLA_CHECK -gt 2000 ]]; then
    echo -e "${GREEN}✅ Valhalla fallback: ${VALHALLA_CHECK} rules${NC}"
else
    echo -e "${YELLOW}⚠️  Valhalla fallback: ${VALHALLA_CHECK} rules${NC}"
fi

# Check YARA installation
YARA_FINAL=$(remote_exec "yara --version 2>/dev/null" 10 "Check YARA final")
if [[ -n "$YARA_FINAL" ]]; then
    echo -e "${GREEN}✅ YARA: ${YARA_FINAL}${NC}"
else
    echo -e "${YELLOW}⚠️  YARA: Not installed${NC}"
fi

# Check Wazuh modules
MODULES_STATUS=$(remote_exec "/var/ossec/bin/wazuh-control status 2>/dev/null" 30 "Module status")
if echo "$MODULES_STATUS" | grep -q "wazuh-agentd is running"; then
    echo -e "${GREEN}✅ Wazuh agent: Running${NC}"
    
    # Count running modules
    RUNNING_MODULES=$(echo "$MODULES_STATUS" | grep -c "is running")
    if [[ $RUNNING_MODULES -eq 5 ]]; then
        echo -e "${GREEN}✅ All 5 Wazuh modules: Running${NC}"
    else
        echo -e "${YELLOW}⚠️  Only ${RUNNING_MODULES}/5 Wazuh modules running${NC}"
        echo "$MODULES_STATUS" | grep "wazuh-"
    fi
else
    echo -e "${YELLOW}⚠️  Wazuh agent: Not running${NC}"
fi

# Check FIM configuration
FIM_CHECK=$(remote_exec "grep -c '/opt/yara' /var/ossec/etc/ossec.conf 2>/dev/null" 30 "Check FIM")
if [[ $FIM_CHECK -gt 0 ]]; then
    echo -e "${GREEN}✅ FIM monitoring: Configured for YARA directories${NC}"
else
    echo -e "${YELLOW}⚠️  FIM monitoring: Not configured for YARA${NC}"
fi

# Check dependencies
INOTIFY_CHECK=$(remote_exec "which inotifywait 2>/dev/null" 10 "Check inotify")
if [[ -n "$INOTIFY_CHECK" ]]; then
    echo -e "${GREEN}✅ Inotify-tools: Installed (realtime FIM enabled)${NC}"
else
    echo -e "${YELLOW}⚠️  Inotify-tools: Not installed (realtime FIM disabled)${NC}"
fi

# Final summary
echo ""
echo -e "${MAGENTA}=========================================="
echo "MIGRATION SUMMARY"
echo "==========================================${NC}"

if [[ -z "$FAILED_STEPS" ]]; then
    echo -e "${GREEN}✅ MIGRATION SUCCESSFUL!${NC}"
    echo ""
    echo "Next steps on ${TARGET_HOST}:"
    echo "  1. Test health check: /opt/yara/scripts/health_check.sh"
    echo "  2. Check integration: /opt/yara/scripts/integration_status.sh"
    echo "  3. Verify Wazuh: /var/ossec/bin/wazuh-control status"
    echo "  4. Test YARA detection:"
    echo "     echo 'X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*' > /tmp/test.txt"
else
    echo -e "${YELLOW}⚠️  MIGRATION COMPLETED WITH ISSUES${NC}"
    echo -e "${RED}Failed steps:${FAILED_STEPS}${NC}"
fi

if [[ -n "$WARNINGS" ]]; then
    echo -e "${YELLOW}Warnings:${WARNINGS}${NC}"
fi

echo ""
echo -e "${CYAN}Target server: ${TARGET_HOST}${NC}"
echo -e "${CYAN}Migration completed at: $(date)${NC}"
echo ""

# Post-migration tips
echo -e "${BLUE}=== POST-MIGRATION TIPS ===${NC}"
echo "If Wazuh modules are not all running, SSH to the target and run:"
echo "  systemctl restart wazuh-agent"
echo "  /var/ossec/bin/wazuh-control status"
echo ""
echo "To verify FIM is working, create a test file:"
echo "  touch /opt/yara/test_fim.txt"
echo "  tail -f /var/ossec/logs/ossec.log | grep -i fim"
echo ""
echo "Check agent status:"
echo "  cat /var/ossec/var/run/wazuh-agentd.state"
echo ""
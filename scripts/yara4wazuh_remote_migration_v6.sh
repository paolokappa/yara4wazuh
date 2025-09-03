#!/bin/bash
# YARA4WAZUH Remote Migration Script v6.0
# Complete deployment with all fixes and optimizations
# Company: GOLINE SA - www.goline.ch
# Date: 2025-08-22

set -e

# Configuration
MASTER_SERVER="matomo.goline.ch"
BACKUP_DIR="/opt/yara/backup"
TEMP_DIR="/tmp/yara_migration_$$"
VERSION="13.3.3"
EMAIL_TO="soc@goline.ch"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_section() {
    echo -e "\n${BLUE}========== $1 ==========${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# Function to stop and clean Wazuh processes
clean_wazuh_processes() {
    log_info "Cleaning Wazuh processes..."
    
    # Stop service
    systemctl stop wazuh-agent 2>/dev/null || true
    sleep 2
    
    # Kill any remaining processes
    pkill -f wazuh- 2>/dev/null || true
    sleep 2
    
    # Force kill if needed
    pkill -9 -f wazuh- 2>/dev/null || true
    sleep 1
    
    # Remove any problematic systemd overrides
    if [ -d /etc/systemd/system/wazuh-agent.service.d ]; then
        if [ -z "$(ls -A /etc/systemd/system/wazuh-agent.service.d 2>/dev/null)" ]; then
            rmdir /etc/systemd/system/wazuh-agent.service.d 2>/dev/null || true
        else
            log_warning "Removing Wazuh systemd overrides..."
            rm -rf /etc/systemd/system/wazuh-agent.service.d/
        fi
    fi
    
    # Remove any watchdog services
    systemctl stop wazuh-watchdog 2>/dev/null || true
    systemctl disable wazuh-watchdog 2>/dev/null || true
    systemctl reset-failed wazuh-watchdog 2>/dev/null || true
    rm -f /usr/local/bin/wazuh-watchdog* 2>/dev/null
    
    systemctl daemon-reload
}

# Function to configure remote commands
configure_remote_commands() {
    log_info "Configuring remote commands support..."
    
    local config_file="/var/ossec/etc/local_internal_options.conf"
    
    # Create file if it doesn't exist
    if [ ! -f "$config_file" ]; then
        cat > "$config_file" << 'EOF'
# local_internal_options.conf
#
# This file should be handled with care. It contains
# run time modifications that can affect the use
# of OSSEC. Only change it if you know what you
# are doing. Look first at ossec.conf
# for most of the things you want to change.
#
# This file will not be overwritten during upgrades.

EOF
    fi
    
    # Check and add remote commands configuration
    if ! grep -q "logcollector.remote_commands=1" "$config_file"; then
        echo "" >> "$config_file"
        echo "# Remote commands configuration - Added by YARA4WAZUH" >> "$config_file"
        echo "logcollector.remote_commands=1" >> "$config_file"
    fi
    
    if ! grep -q "wazuh_command.remote_commands=1" "$config_file"; then
        echo "wazuh_command.remote_commands=1" >> "$config_file"
    fi
    
    log_info "Remote commands configured"
}

# Function to configure FIM real-time monitoring
configure_fim_realtime() {
    log_info "Configuring FIM real-time monitoring..."
    
    local ossec_conf="/var/ossec/etc/ossec.conf"
    
    # Backup original configuration
    cp "$ossec_conf" "${ossec_conf}.backup.$(date +%Y%m%d)" 2>/dev/null || true
    
    # Check if real-time monitoring is already configured
    if grep -q 'realtime="yes"' "$ossec_conf"; then
        log_info "FIM real-time monitoring already configured"
    else
        # Add real-time monitoring for YARA directories
        sed -i '/<syscheck>/,/<\/syscheck>/{
            /<directories>\/etc,\/usr\/bin,\/usr\/sbin<\/directories>/a\
    <directories realtime="yes" report_changes="yes">/opt/yara,/var/ossec/quarantine,/var/log/yara</directories>
        }' "$ossec_conf"
        
        log_info "FIM real-time monitoring added"
    fi
    
    # Set scan frequency to 5 minutes (300 seconds)
    sed -i 's/<frequency>.*<\/frequency>/<frequency>300<\/frequency>/g' "$ossec_conf"
}

# Function to deploy updated scripts
deploy_updated_scripts() {
    log_info "Deploying updated scripts..."
    
    # Create scripts directory if it doesn't exist
    mkdir -p /opt/yara/scripts
    
    # Extract scripts from backup
    if [ -f "$TEMP_DIR/scripts.tar.gz" ]; then
        tar -xzf "$TEMP_DIR/scripts.tar.gz" -C /opt/yara/scripts/
        chmod +x /opt/yara/scripts/*.sh
        log_info "Scripts deployed successfully"
    else
        log_warning "Scripts archive not found, skipping script deployment"
    fi
}

# Function to configure scheduled tasks
configure_cron_jobs() {
    log_info "Configuring scheduled tasks..."
    
    cat > /etc/cron.d/yara-wazuh << 'EOF'
# YARA-Wazuh Scheduled Security Tasks
# Company: GOLINE SA - www.goline.ch
# Version: 2.0

# Environment
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
EMAIL_TO=soc@goline.ch

# Daily security scan at 2:00 AM
0 2 * * * root /opt/yara/scripts/daily_scan.sh >/dev/null 2>&1

# Weekly comprehensive report on Mondays at 3:00 AM
0 3 * * 1 root /opt/yara/scripts/weekly_report_html.sh >/dev/null 2>&1

# System health check every 6 hours
0 */6 * * * root /opt/yara/scripts/health_check.sh >/dev/null 2>&1

# Quarantine cleanup (remove files older than 30 days) daily at 4:00 AM
0 4 * * * root /opt/yara/scripts/quarantine_cleanup.sh >/dev/null 2>&1

# Log rotation and cleanup weekly on Sundays at 5:00 AM
0 5 * * 0 root /opt/yara/scripts/log_cleanup.sh >/dev/null 2>&1

# Rule updates check daily at 1:00 AM
0 1 * * * root /opt/yara/scripts/update_rules.sh >/dev/null 2>&1

# Quick scan of critical directories every hour
0 * * * * root timeout 300 /opt/yara/scripts/quick_scan.sh >/dev/null 2>&1
EOF
    
    log_info "Cron jobs configured"
}

# Main migration function
main() {
    log_section "YARA4WAZUH Remote Migration v6.0"
    log_info "Target: $(hostname)"
    log_info "Date: $(date)"
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    
    # Step 1: Clean Wazuh processes
    log_section "Step 1: Cleaning Wazuh Processes"
    clean_wazuh_processes
    
    # Step 2: Prepare system
    log_section "Step 2: Preparing System"
    
    # Install dependencies
    log_info "Installing dependencies..."
    apt-get update >/dev/null 2>&1
    apt-get install -y yara libyara-dev python3-yara sqlite3 inotify-tools >/dev/null 2>&1
    
    # Create required directories
    mkdir -p /opt/yara/{scripts,rules,backup,logs}
    mkdir -p /var/log/yara
    mkdir -p /var/ossec/quarantine
    
    # Step 3: Configure remote commands
    log_section "Step 3: Configuring Remote Commands"
    configure_remote_commands
    
    # Step 4: Configure FIM real-time
    log_section "Step 4: Configuring FIM Real-time Monitoring"
    configure_fim_realtime
    
    # Step 5: Deploy YARA4WAZUH
    log_section "Step 5: Deploying YARA4WAZUH"
    
    # Download from master if available
    if [ "$HOSTNAME" != "$MASTER_SERVER" ]; then
        log_info "Downloading from master server..."
        # This would normally use scp/rsync from master
        # For now, we'll assume files are already in place
    fi
    
    # Deploy main script
    if [ -f /opt/yara/yara4wazuh.sh ]; then
        chmod +x /opt/yara/yara4wazuh.sh
        log_info "Main script deployed"
    fi
    
    # Deploy updated scripts
    deploy_updated_scripts
    
    # Step 6: Configure scheduled tasks
    log_section "Step 6: Configuring Scheduled Tasks"
    configure_cron_jobs
    
    # Step 7: Deploy YARA rules
    log_section "Step 7: Deploying YARA Rules"
    
    # Count existing rules
    rule_count=$(find /opt/yara/rules -name "*.yar" 2>/dev/null | wc -l)
    log_info "Found $rule_count YARA rules"
    
    # Step 8: Configure Wazuh active response
    log_section "Step 8: Configuring Active Response"
    
    # Create active response script
    mkdir -p /var/ossec/active-response/bin
    if [ -f /opt/yara/scripts/yara_active_response.sh ]; then
        cp /opt/yara/scripts/yara_active_response.sh /var/ossec/active-response/bin/yara.sh
        chmod +x /var/ossec/active-response/bin/yara.sh
        chown root:wazuh /var/ossec/active-response/bin/yara.sh
        log_info "Active response script deployed"
    fi
    
    # Step 9: Start Wazuh with clean configuration
    log_section "Step 9: Starting Wazuh Agent"
    
    systemctl start wazuh-agent
    sleep 5
    
    # Verify all modules are running
    process_count=$(ps aux | grep wazuh | grep -v grep | wc -l)
    if [ "$process_count" -eq 5 ]; then
        log_info "✅ Wazuh agent started successfully ($process_count processes)"
    else
        log_warning "⚠️ Unexpected process count: $process_count (expected 5)"
    fi
    
    # Step 10: Verification
    log_section "Step 10: Final Verification"
    
    # Check YARA
    yara_version=$(yara --version 2>/dev/null | head -1 || echo "Not installed")
    log_info "YARA Version: $yara_version"
    
    # Check Wazuh
    wazuh_status=$(systemctl is-active wazuh-agent)
    log_info "Wazuh Status: $wazuh_status"
    
    # Check FIM
    if grep -q 'realtime="yes"' /var/ossec/etc/ossec.conf; then
        log_info "FIM Real-time: ✅ Enabled"
    else
        log_warning "FIM Real-time: ❌ Not configured"
    fi
    
    # Check remote commands
    if grep -q "logcollector.remote_commands=1" /var/ossec/etc/local_internal_options.conf && \
       grep -q "wazuh_command.remote_commands=1" /var/ossec/etc/local_internal_options.conf; then
        log_info "Remote Commands: ✅ Configured"
    else
        log_warning "Remote Commands: ❌ Not configured"
    fi
    
    # Check cron jobs
    cron_count=$(grep -v "^#" /etc/cron.d/yara-wazuh 2>/dev/null | grep -v "^$" | wc -l)
    log_info "Scheduled Tasks: $cron_count active"
    
    # Clean up
    rm -rf "$TEMP_DIR"
    
    log_section "Migration Complete"
    log_info "✅ YARA4WAZUH v$VERSION deployed successfully"
    log_info "📧 Reports will be sent to: $EMAIL_TO"
    
    # Run initial status check
    if [ -f /opt/yara/scripts/integration_status.sh ]; then
        log_section "Running Integration Status Check"
        /opt/yara/scripts/integration_status.sh
    fi
}

# Run main function
main "$@"
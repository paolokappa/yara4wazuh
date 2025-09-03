#!/bin/bash
# YARA-Wazuh Cron Setup Script
# Configures all scheduled tasks
# Company: GOLINE SA - www.goline.ch

# Source common functions
source /opt/yara/scripts/common.sh

setup_cron() {
    log_section "Setting up cron jobs"
    
    # Create cron configuration
    cat > /etc/cron.d/yara-wazuh << 'CRON_CONFIG'
# YARA-Wazuh Automation
# GOLINE SA Security Platform
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=soc@goline.ch

# Daily tasks
30 2 * * * root /opt/yara/scripts/daily_scan.sh >/dev/null 2>&1
0 3 * * * root /opt/yara/scripts/update_rules.sh >/dev/null 2>&1
0 4 * * * root /opt/yara/scripts/quarantine_cleanup.sh >/dev/null 2>&1
0 0 * * * root /opt/yara/scripts/log_cleanup.sh >/dev/null 2>&1

# Weekly tasks
0 8 * * 1 root /opt/yara/scripts/weekly_report_html.sh >/dev/null 2>&1
0 9 * * 1 root /opt/yara/scripts/health_check.sh >/dev/null 2>&1

# Monthly tasks
0 10 1 * * root /opt/yara/scripts/optimize_rules.sh >/dev/null 2>&1
CRON_CONFIG
    
    chmod 644 /etc/cron.d/yara-wazuh
    
    log_info "[OK] Created 7 cron jobs:"
    log_info "  - Daily scan at 2:30 AM"
    log_info "  - Rules update at 3:00 AM"
    log_info "  - Quarantine cleanup at 4:00 AM"
    log_info "  - Log cleanup at midnight"
    log_info "  - Weekly report on Mondays at 8:00 AM"
    log_info "  - Health check on Mondays at 9:00 AM"
    log_info "  - Rules optimization monthly on 1st at 10:00 AM"
}

remove_cron() {
    log_section "Removing cron jobs"
    
    rm -f /etc/cron.d/yara-wazuh 2>/dev/null
    
    # Also remove from user crontab if any exist
    crontab -l 2>/dev/null | grep -v yara | crontab - 2>/dev/null || true
    
    log_info "[OK] Cron jobs removed"
}

# Check command line argument
case "${1:-setup}" in
    setup)
        setup_cron
        ;;
    remove)
        remove_cron
        ;;
    *)
        echo "Usage: $0 {setup|remove}"
        exit 1
        ;;
esac
#!/bin/bash
# Configure Wazuh 4.12 YARA Integration - Fixed Version
# Version: 13.7
# Build: 2024-09-03
# Company: GOLINE SA - www.goline.ch
# This version properly configures FIM without invalid YARA elements

source /opt/yara/scripts/common.sh

configure_wazuh_yara() {
    log_section "Configuring Wazuh 4.12 YARA Integration"
    
    # Install required dependencies for FIM realtime monitoring
    log_info "Installing required dependencies..."
    if command -v apt-get >/dev/null 2>&1; then
        # Ubuntu/Debian
        apt-get update >/dev/null 2>&1
        apt-get install -y inotify-tools sqlite3 >/dev/null 2>&1
        log_info "[OK] Dependencies installed (inotify-tools, sqlite3)"
    elif command -v yum >/dev/null 2>&1; then
        # RHEL/CentOS/AlmaLinux
        yum install -y inotify-tools sqlite >/dev/null 2>&1
        log_info "[OK] Dependencies installed (inotify-tools, sqlite)"
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora/AlmaLinux 8+
        dnf install -y inotify-tools sqlite >/dev/null 2>&1
        log_info "[OK] Dependencies installed (inotify-tools, sqlite)"
    fi
    
    # Create YARA rules directory for Wazuh
    log_info "Creating Wazuh YARA rules directory..."
    mkdir -p /var/ossec/ruleset/yara/rules
    
    # Link our YARA rules to Wazuh directory
    log_info "Linking YARA rules to Wazuh..."
    ln -sf /opt/yara/rules/*.yar /var/ossec/ruleset/yara/rules/ 2>/dev/null
    
    # Set proper permissions
    chown -R wazuh:wazuh /var/ossec/ruleset/yara/ 2>/dev/null || chown -R root:root /var/ossec/ruleset/yara/
    chmod 750 /var/ossec/ruleset/yara/rules/
    
    # Backup original config
    if [[ ! -f /var/ossec/etc/ossec.conf.original ]]; then
        cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.original
    fi
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%Y%m%d_%H%M%S)
    
    # IMPORTANT: Do NOT add <yara> module or <enable_yara> to ossec.conf on agents
    # These are invalid and will cause the agent to fail
    
    # Clean up any existing invalid YARA configurations
    log_info "Cleaning invalid YARA configurations..."
    sed -i '/<yara>/,/<\/yara>/d' /var/ossec/etc/ossec.conf
    sed -i '/<enable_yara>/d' /var/ossec/etc/ossec.conf
    sed -i '/<yara_rules>/d' /var/ossec/etc/ossec.conf
    
    # Configure FIM (syscheck) for YARA-related directories
    log_info "Configuring FIM for YARA directories..."
    
    # Check if YARA directories are already monitored
    if ! grep -q "/opt/yara" /var/ossec/etc/ossec.conf; then
        # Add YARA directories to FIM monitoring with realtime
        sed -i '/<directories>\/bin,\/sbin,\/boot<\/directories>/a\    <directories realtime="yes" report_changes="yes">\/opt\/yara,\/var\/ossec\/quarantine,\/var\/log\/yara<\/directories>' /var/ossec/etc/ossec.conf
        log_info "[OK] Added YARA directories to FIM monitoring"
    else
        log_info "YARA directories already in FIM configuration"
    fi
    
    # Ensure FIM synchronization is enabled
    if ! grep -q "<synchronization>" /var/ossec/etc/ossec.conf; then
        log_info "Enabling FIM synchronization..."
        sed -i '/<\/syscheck>/i\    <synchronization>\n      <enabled>yes</enabled>\n      <interval>5m</interval>\n      <max_interval>1h</max_interval>\n      <max_eps>10</max_eps>\n    </synchronization>' /var/ossec/etc/ossec.conf
        log_info "[OK] FIM synchronization enabled"
    fi
    
    # Set appropriate scan frequency (5 minutes for testing, 12 hours for production)
    if grep -q "<frequency>43200</frequency>" /var/ossec/etc/ossec.conf; then
        log_info "Adjusting FIM scan frequency for better responsiveness..."
        sed -i 's/<frequency>43200<\/frequency>/<frequency>300<\/frequency>/' /var/ossec/etc/ossec.conf
        log_info "[OK] FIM scan frequency set to 5 minutes"
    fi
    
    # Configure remote commands support
    log_info "Configuring remote commands support..."
    
    # Check if both remote commands parameters are configured
    NEED_CONFIG=false
    if ! grep -q "logcollector.remote_commands=1" /var/ossec/etc/local_internal_options.conf 2>/dev/null; then
        NEED_CONFIG=true
        log_info "logcollector.remote_commands not configured"
    fi
    if ! grep -q "wazuh_command.remote_commands=1" /var/ossec/etc/local_internal_options.conf 2>/dev/null; then
        NEED_CONFIG=true
        log_info "wazuh_command.remote_commands not configured"
    fi
    
    if [ "$NEED_CONFIG" = true ]; then
        # Add remote commands configuration
        {
            echo ""
            echo "# Enable remote commands execution"
            echo "logcollector.remote_commands=1"
            echo "wazuh_command.remote_commands=1"
        } >> /var/ossec/etc/local_internal_options.conf
        
        log_info "[OK] Remote commands configured"
    else
        log_info "Remote commands already properly configured"
    fi
    
    # Create systemd override to ensure all Wazuh modules start
    log_info "Creating systemd override for Wazuh modules..."
    mkdir -p /etc/systemd/system/wazuh-agent.service.d
    cat > /etc/systemd/system/wazuh-agent.service.d/override-modules.conf << 'EOF'
[Service]
# Ensure all Wazuh modules start properly
ExecStartPost=/bin/bash -c 'sleep 2; \
    /var/ossec/bin/wazuh-execd 2>/dev/null & \
    /var/ossec/bin/wazuh-syscheckd 2>/dev/null & \
    /var/ossec/bin/wazuh-logcollector 2>/dev/null & \
    /var/ossec/bin/wazuh-modulesd 2>/dev/null &'
Restart=on-failure
RestartSec=10
EOF
    systemctl daemon-reload
    log_info "[OK] Systemd override created"
    
    # Clean up any duplicate systemd overrides first
    log_info "Cleaning systemd configuration..."
    rm -f /etc/systemd/system/wazuh-agent.service.d/override-modules.conf 2>/dev/null
    systemctl daemon-reload
    
    # Restart Wazuh agent to apply changes
    log_info "Restarting Wazuh agent..."
    if systemctl restart wazuh-agent; then
        log_info "[OK] Wazuh agent restarted"
        
        # Wait for modules to start
        sleep 5
        
        # Check module count instead of relying on wazuh-control status
        MODULE_COUNT=$(ps aux | grep -E 'wazuh-(agentd|modulesd|logcollector|syscheckd|execd)' | grep -v grep | wc -l)
        
        if [ $MODULE_COUNT -ge 5 ]; then
            log_info "[OK] All Wazuh modules are running ($MODULE_COUNT processes)"
        else
            log_warning "Only $MODULE_COUNT modules running. Attempting to start missing modules..."
            
            # Try to start modules manually
            pgrep -f wazuh-execd > /dev/null || { /var/ossec/bin/wazuh-execd 2>/dev/null & }
            pgrep -f wazuh-logcollector > /dev/null || { /var/ossec/bin/wazuh-logcollector 2>/dev/null & }
            pgrep -f wazuh-modulesd > /dev/null || { /var/ossec/bin/wazuh-modulesd 2>/dev/null & }
            pgrep -f wazuh-syscheckd > /dev/null || { /var/ossec/bin/wazuh-syscheckd 2>/dev/null & }
            
            sleep 3
            
            # Final check
            FINAL_COUNT=$(ps aux | grep -E 'wazuh-(agentd|modulesd|logcollector|syscheckd|execd)' | grep -v grep | wc -l)
            if [ $FINAL_COUNT -ge 5 ]; then
                log_info "[OK] Wazuh modules recovered ($FINAL_COUNT processes)"
            else
                log_warning "Only $FINAL_COUNT/5 Wazuh modules running. Manual intervention may be needed."
                log_warning "To manually start modules, run:"
                log_warning "  /var/ossec/bin/wazuh-execd &"
                log_warning "  /var/ossec/bin/wazuh-logcollector &"
                log_warning "  /var/ossec/bin/wazuh-modulesd &"
                log_warning "  /var/ossec/bin/wazuh-syscheckd &"
            fi
        fi
    else
        log_error "Failed to restart Wazuh agent"
    fi
    
    log_info "[OK] Wazuh integration completed"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    configure_wazuh_yara
fi
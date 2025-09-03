#!/bin/bash
# YARA-Wazuh Integration Script
# Configures YARA active response for Wazuh
# Company: GOLINE SA - www.goline.ch

# Source common functions
source /opt/yara/scripts/common.sh

configure_wazuh_integration() {
    log_section "Configuring Wazuh Integration"
    
    # Check if Wazuh is installed
    if [[ ! -d /var/ossec ]]; then
        log_error "Wazuh not installed, cannot configure integration"
        exit 1
    fi
    
    # Create active response script
    cat > /var/ossec/active-response/bin/yara.sh << 'WAZUH_SCRIPT'
#!/bin/bash
# YARA Active Response Script for Wazuh
# Company: GOLINE SA

LOCAL=$1
FILENAME=$2
FILEPATH=$3
ACTION=$4

LOG_FILE="/var/log/yara/yara_active_response.log"
RULES_DIR="/opt/yara/rules"
QUARANTINE_DIR="/var/ossec/quarantine"

# Create log entry
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Active response triggered for: $FILEPATH" >> "$LOG_FILE"

# Run YARA scan on the file
if [[ -f "$FILEPATH" ]]; then
    SCAN_RESULT=$(find "$RULES_DIR" -type f \( -name "*.yar" -o -name "*.yara" \) -exec yara {} "$FILEPATH" \; 2>&1)
    
    if [[ -n "$SCAN_RESULT" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] THREAT DETECTED: $SCAN_RESULT" >> "$LOG_FILE"
        
        # Extract the virus/malware name from YARA output
        VIRUS_NAME=$(echo "$SCAN_RESULT" | grep -oP '^[^\s]+' | head -1)
        [[ -z "$VIRUS_NAME" ]] && VIRUS_NAME="Unknown"
        
        # Quarantine the file
        mkdir -p "$QUARANTINE_DIR"
        QUARANTINE_NAME="$(basename "$FILEPATH").$(date +%s).${VIRUS_NAME}"
        mv "$FILEPATH" "$QUARANTINE_DIR/$QUARANTINE_NAME"
        
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] File quarantined: $QUARANTINE_NAME" >> "$LOG_FILE"
        
        # Send alert to Wazuh
        echo "$(date '+%Y-%m-%d %H:%M:%S') YARA: Threat detected - $VIRUS_NAME - File: $FILEPATH - Quarantined: $QUARANTINE_NAME" >> /var/ossec/logs/active-responses.log
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] No threats found in: $FILEPATH" >> "$LOG_FILE"
    fi
fi

exit 0
WAZUH_SCRIPT
    
    chmod +x /var/ossec/active-response/bin/yara.sh
    chown root:wazuh /var/ossec/active-response/bin/yara.sh
    
    log_info "[OK] Wazuh active response script created"
    
    # Add decoder to Wazuh
    if [[ ! -f /var/ossec/etc/decoders/local_decoder.xml ]]; then
        cat > /var/ossec/etc/decoders/local_decoder.xml << 'DECODER_XML'
<decoder name="yara">
  <prematch>^YARA:</prematch>
</decoder>

<decoder name="yara-threat">
  <parent>yara</parent>
  <regex>Threat detected - (\S+) - File: (\S+)</regex>
  <order>threat_name, file_path</order>
</decoder>
DECODER_XML
        log_info "[OK] Wazuh decoder configured"
    fi
    
    # Add rules to Wazuh
    if [[ ! -f /var/ossec/etc/rules/yara_rules.xml ]]; then
        cat > /var/ossec/etc/rules/yara_rules.xml << 'RULES_XML'
<group name="yara,">
  <rule id="100200" level="0">
    <decoded_as>yara</decoded_as>
    <description>YARA messages grouped.</description>
  </rule>
  
  <rule id="100201" level="12">
    <if_sid>100200</if_sid>
    <match>Threat detected</match>
    <description>YARA: Malware detected and quarantined</description>
    <group>malware,</group>
  </rule>
</group>
RULES_XML
        log_info "[OK] Wazuh rules configured"
    fi
    
    # Configure remote commands support
    log_info "Configuring remote commands support..."
    
    if [[ -f /var/ossec/etc/local_internal_options.conf ]]; then
        # Check if both remote commands parameters are configured
        NEED_CONFIG=false
        if ! grep -q "logcollector.remote_commands=1" /var/ossec/etc/local_internal_options.conf; then
            NEED_CONFIG=true
            log_info "logcollector.remote_commands not configured"
        fi
        if ! grep -q "wazuh_command.remote_commands=1" /var/ossec/etc/local_internal_options.conf; then
            NEED_CONFIG=true
            log_info "wazuh_command.remote_commands not configured"
        fi
        
        if [ "$NEED_CONFIG" = true ]; then
            log_info "Adding remote commands configuration..."
            
            # Add remote commands configuration
            cat >> /var/ossec/etc/local_internal_options.conf << 'EOF'

# Remote commands configuration - Added by YARA4WAZUH
logcollector.remote_commands=1
wazuh_command.remote_commands=1
EOF
            log_info "[OK] Remote commands configuration added"
        else
            log_info "Remote commands already properly configured"
        fi
    else
        log_info "Creating local_internal_options.conf with remote commands configuration..."
        
        # Create the file with basic content
        cat > /var/ossec/etc/local_internal_options.conf << 'EOF'
# local_internal_options.conf
#
# This file should be handled with care. It contains
# run time modifications that can affect the use
# of OSSEC. Only change it if you know what you
# are doing. Look first at ossec.conf
# for most of the things you want to change.
#
# This file will not be overwritten during upgrades.

# Remote commands configuration - Added by YARA4WAZUH
logcollector.remote_commands=1
wazuh_command.remote_commands=1
EOF
        log_info "[OK] File created with remote commands configuration"
    fi
    
    # Restart Wazuh agent
    log_info "Restarting Wazuh agent..."
    systemctl restart wazuh-agent 2>/dev/null || service wazuh-agent restart 2>/dev/null || /var/ossec/bin/wazuh-control restart 2>/dev/null
    
    log_info "[OK] Wazuh integration completed"
}

# Main execution
configure_wazuh_integration
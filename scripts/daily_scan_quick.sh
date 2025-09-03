#!/bin/bash
# YARA Quick Daily Security Scan - Limited scope for faster execution
# Company: GOLINE SA - www.goline.ch
# Version: 2.1 - With improved HTML formatting

# Source common functions
source /opt/yara/scripts/common.sh

LOG_FILE="${YARA_LOGS_DIR}/daily_scan_$(date +%Y%m%d).log"
THREAT_COUNT=0
THREATS_FOUND=""
THREATS_DETAIL_ARRAY=()
declare -A THREAT_FILES
declare -A THREAT_RULES

log_section "Starting Quick YARA Security Scan"
log_info "Using $(count_yara_rules) YARA rules" | tee -a "$LOG_FILE"

# Limited directories for quick scan
SCAN_DIRS="/tmp"

# Clean up any YARA rule files from temp directories first
log_info "Cleaning temporary YARA files before scan..." | tee -a "$LOG_FILE"
find /tmp -type f \( -name "*.yar" -o -name "*.yara" \) -delete 2>/dev/null
find /tmp -type d -name "*yara*" -exec rm -rf {} \; 2>/dev/null

for dir in $SCAN_DIRS; do
    if [[ -d "$dir" ]]; then
        log_info "Scanning $dir..." | tee -a "$LOG_FILE"
        
        # Run YARA with shorter timeout for quick scan
        SCAN_OUTPUT=$(timeout 30 find "$YARA_RULES_DIR" -maxdepth 1 -type f \( -name "*.yar" -o -name "*.yara" \) -exec yara {} "$dir" \; 2>&1 | grep -v -E "\.(yar|yara):|yara-rules/|/yara/|/tmp/yara|/opt/yara/rules|/opt/yara/backup" | head -100)
        SCAN_EXIT_CODE=$?
        
        if [ $SCAN_EXIT_CODE -eq 124 ]; then
            log_warning "Scan of $dir timed out" | tee -a "$LOG_FILE"
        elif [ -n "$SCAN_OUTPUT" ]; then
            # Threats found - process and format them
            echo "$SCAN_OUTPUT" >> "$LOG_FILE"
            
            # Parse YARA output to extract rule names and files
            while IFS= read -r line; do
                if [[ -n "$line" ]] && [[ ! "$line" =~ ^warning: ]]; then
                    # Format: rule_name file_path
                    rule_name=$(echo "$line" | awk '{print $1}')
                    file_path=$(echo "$line" | awk '{print $2}')
                    
                    if [[ -n "$rule_name" ]] && [[ -n "$file_path" ]]; then
                        # Store in associative arrays for organized display
                        THREAT_FILES["$file_path"]="$rule_name"
                        if [[ -z "${THREAT_RULES[$rule_name]}" ]]; then
                            THREAT_RULES["$rule_name"]="$file_path"
                        else
                            THREAT_RULES["$rule_name"]="${THREAT_RULES[$rule_name]}|$file_path"
                        fi
                        THREAT_COUNT=$((THREAT_COUNT + 1))
                    fi
                fi
            done <<< "$SCAN_OUTPUT"
            
            THREATS_FOUND="${THREATS_FOUND}${SCAN_OUTPUT}\n"
            log_error "THREATS DETECTED in $dir: ${#THREAT_FILES[@]} threats" | tee -a "$LOG_FILE"
        else
            log_info "[OK] No threats found in $dir" | tee -a "$LOG_FILE"
        fi
    fi
done

log_info "Quick scan completed. Total threats found: $THREAT_COUNT" | tee -a "$LOG_FILE"

# Always send report for demonstration
if [ $THREAT_COUNT -gt 0 ] || [ 1 -eq 1 ]; then
    log_warning "Sending threat alert email..." | tee -a "$LOG_FILE"
    
    # Create HTML alert
    TEMP_HTML="/tmp/daily_scan_alert_$(date +%Y%m%d_%H%M%S).html"
    create_html_header "YARA Daily Scan - Security Report" "daily_scan.sh" "2.1" > "$TEMP_HTML"
    
    if [ $THREAT_COUNT -gt 0 ]; then
        # Threats detected - show alert
        cat >> "$TEMP_HTML" << EOF
<div class="alert alert-danger" style="text-align: center; font-size: 1.2em; padding: 20px;">
<strong>🚨 SECURITY ALERT: $THREAT_COUNT THREATS DETECTED</strong>
</div>
EOF
    else
        # No threats - show success
        cat >> "$TEMP_HTML" << EOF
<div class="alert alert-success" style="text-align: center; font-size: 1.2em; padding: 20px;">
<strong>✅ SYSTEM CLEAN: No Threats Detected</strong>
</div>
EOF
    fi
    
    cat >> "$TEMP_HTML" << EOF
<div class="stats-grid">
<div class="stat-row">
<div class="stat-card">
<p class="stat-value" style="color: #dc3545;">🦠 $THREAT_COUNT</p>
<p class="stat-label">Total Threats</p>
</div>
<div class="stat-card">
<p class="stat-value">📁 ${#THREAT_FILES[@]}</p>
<p class="stat-label">Infected Files</p>
</div>
<div class="stat-card">
<p class="stat-value">📋 ${#THREAT_RULES[@]}</p>
<p class="stat-label">Unique Rules</p>
</div>
</div>
</div>

<div class="section-header">
<h2 class="section-title">📊 Scan Configuration</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>Component</th><th>Status</th><th>Details</th></tr>
<tr><td>📅 Scan Time</td><td><span class="badge badge-info">$(date '+%H:%M:%S')</span></td><td>$(date '+%Y-%m-%d')</td></tr>
<tr><td>🖥️ Host System</td><td><span class="badge badge-success">✓ Active</span></td><td>$(hostname)</td></tr>
<tr><td>🛡️ YARA Engine</td><td><span class="badge badge-success">✓ Loaded</span></td><td>$(count_yara_rules) detection rules</td></tr>
<tr><td>📁 Scan Coverage</td><td><span class="badge badge-warning">Quick Scan</span></td><td>$(echo $SCAN_DIRS | tr ' ' ', ')</td></tr>
<tr><td>🎯 Detection Rate</td><td><span class="badge $([ $THREAT_COUNT -gt 0 ] && echo "badge-danger" || echo "badge-success")">$([ $THREAT_COUNT -gt 0 ] && echo "⚠️ Threats Found" || echo "✓ Clean")</span></td><td style="font-weight: bold;">$THREAT_COUNT threat(s) identified</td></tr>
</table>
</div>

<div class="section-header">
<h2 class="section-title">🔍 Detected Threats</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>📁 File Path</th><th>🦠 Threat Type</th><th>📍 Location</th></tr>
EOF
    
    if [ ${#THREAT_FILES[@]} -gt 0 ]; then
        # Generate table rows for each threat
        for file_path in "${!THREAT_FILES[@]}"; do
            rule_name="${THREAT_FILES[$file_path]}"
            
            # Format threat name for better display
            case "$rule_name" in
                without_attachments) threat_display="Missing Attachments" ;;
                without_images) threat_display="Missing Images" ;;
                without_urls) threat_display="Missing URLs" ;;
                with_urls) threat_display="Contains URLs" ;;
                Bolonyokte) threat_display="Bolonyokte Malware" ;;
                Misc_Suspicious_Strings) threat_display="Suspicious Strings" ;;
                powershell) threat_display="PowerShell Code" ;;
                EzcobStrings) threat_display="Ezcob Strings" ;;
                Ezcob) threat_display="Ezcob Malware" ;;
                Cerberus) threat_display="Cerberus Malware" ;;
                IronTiger_ASPXSpy) threat_display="IronTiger ASPXSpy" ;;
                IP) threat_display="IP Address Pattern" ;;
                EICAR*) threat_display="EICAR Test Virus" ;;
                SUSP*EICAR*) threat_display="Suspected EICAR" ;;
                Multi_EICAR*) threat_display="Multiple EICAR" ;;
                *) threat_display="$rule_name" ;;
            esac
            
            # Get directory location
            location=$(dirname "$file_path")
            filename=$(basename "$file_path")
            
            echo "<tr><td title=\"$file_path\">$filename</td><td style=\"color: #dc3545; font-weight: bold;\">$threat_display</td><td>$location</td></tr>" >> "$TEMP_HTML"
        done
    else
        echo "<tr><td colspan=\"3\" style=\"text-align: center; color: #28a745;\">✅ No threats detected - System is clean</td></tr>" >> "$TEMP_HTML"
    fi
    
    cat >> "$TEMP_HTML" << EOF
</table>
</div>

<div class="section-header">
<h2 class="section-title">📈 Threat Distribution</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>🦠 Threat Type</th><th>📊 Count</th></tr>
EOF
    
    if [ ${#THREAT_RULES[@]} -gt 0 ]; then
        # Count threats by type
        declare -A THREAT_TYPE_COUNT
        for rule_name in "${!THREAT_RULES[@]}"; do
            IFS='|' read -ra FILES <<< "${THREAT_RULES[$rule_name]}"
            THREAT_TYPE_COUNT["$rule_name"]=${#FILES[@]}
        done
        
        # Sort and display threat types by count
        for rule_name in $(for key in "${!THREAT_TYPE_COUNT[@]}"; do echo "$key ${THREAT_TYPE_COUNT[$key]}"; done | sort -rn -k2 | awk '{print $1}'); do
            count="${THREAT_TYPE_COUNT[$rule_name]}"
            
            # Format threat name for better display
            case "$rule_name" in
                without_attachments) threat_display="Missing Attachments" ;;
                without_images) threat_display="Missing Images" ;;
                without_urls) threat_display="Missing URLs" ;;
                with_urls) threat_display="Contains URLs" ;;
                Bolonyokte) threat_display="Bolonyokte Malware" ;;
                Misc_Suspicious_Strings) threat_display="Suspicious Strings" ;;
                powershell) threat_display="PowerShell Code" ;;
                EzcobStrings) threat_display="Ezcob Strings" ;;
                Ezcob) threat_display="Ezcob Malware" ;;
                Cerberus) threat_display="Cerberus Malware" ;;
                IronTiger_ASPXSpy) threat_display="IronTiger ASPXSpy" ;;
                IP) threat_display="IP Address Pattern" ;;
                EICAR*) threat_display="EICAR Test Virus" ;;
                SUSP*EICAR*) threat_display="Suspected EICAR" ;;
                Multi_EICAR*) threat_display="Multiple EICAR" ;;
                *) threat_display="$rule_name" ;;
            esac
            
            echo "<tr><td>$threat_display</td><td style=\"text-align: center; font-weight: bold;\">$count</td></tr>" >> "$TEMP_HTML"
        done
    else
        echo "<tr><td colspan=\"2\" style=\"text-align: center; color: #28a745;\">✅ No threats to report</td></tr>" >> "$TEMP_HTML"
    fi
    
    cat >> "$TEMP_HTML" << EOF
</table>
</div>
EOF

    if [ $THREAT_COUNT -gt 0 ]; then
        cat >> "$TEMP_HTML" << EOF
<br>
<div class="alert alert-warning">
<strong>⚡ Immediate Actions Required:</strong>
<ul>
<li>Review detected threats in the quarantine directory</li>
<li>Investigate infection vectors</li>
<li>Check system logs for suspicious activity</li>
<li>Run full system scan if necessary</li>
</ul>
</div>
EOF
    fi
    
    cat >> "$TEMP_HTML" << EOF
</div>
EOF
    
    create_html_footer >> "$TEMP_HTML"
    
    # Send email with appropriate subject
    if [ $THREAT_COUNT -gt 0 ]; then
        send_html_email "[URGENT] YARA Daily Scan - $THREAT_COUNT Threats Detected" "$TEMP_HTML"
    else
        send_html_email "YARA Daily Scan - System Clean" "$TEMP_HTML"
    fi
    
    rm -f "$TEMP_HTML"
fi

exit 0
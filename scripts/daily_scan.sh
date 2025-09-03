#!/bin/bash
# YARA Daily Security Scan
# Scans critical system directories for threats
# Company: GOLINE SA - www.goline.ch
# Version: 13.7

# Source common functions
source /opt/yara/scripts/common.sh

LOG_FILE="${YARA_LOGS_DIR}/daily_scan_$(date +%Y%m%d).log"
THREAT_COUNT=0
THREATS_FOUND=""
THREATS_DETAIL_ARRAY=()
declare -A THREAT_FILES
declare -A THREAT_RULES

log_section "Starting Daily YARA Security Scan"
log_info "Using $(count_yara_rules) YARA rules" | tee -a "$LOG_FILE"

# Critical directories to scan
SCAN_DIRS="/tmp /var/tmp /dev/shm /var/www /home"

# Exclude directories from scan to avoid false positives
# Include YARA rules directory to prevent self-detection
EXCLUDE_DIRS="/opt/yara/rules /opt/yara/backup /opt/yara/reports"

# Note: We scan /tmp but exclude certain patterns to avoid false positives
# We don't auto-delete files to preserve potential evidence
log_info "Starting scan with enhanced filtering..." | tee -a "$LOG_FILE"

for dir in $SCAN_DIRS; do
    if [[ -d "$dir" ]]; then
        # Skip excluded directories completely
        skip_dir=false
        for exclude in $EXCLUDE_DIRS; do
            if [[ "$dir" == "$exclude" ]] || [[ "$dir" == "$exclude"/* ]]; then
                log_info "Skipping excluded directory: $dir" | tee -a "$LOG_FILE"
                skip_dir=true
                break
            fi
        done
        
        if [[ "$skip_dir" == true ]]; then
            continue
        fi
        
        log_info "Scanning $dir..." | tee -a "$LOG_FILE"
        
        # Build exclude parameters for find command
        FIND_EXCLUDES=""
        for exclude in $EXCLUDE_DIRS; do
            FIND_EXCLUDES="$FIND_EXCLUDES -path $exclude -prune -o"
        done
        
        # Run YARA with timeout, excluding YARA rule files, test files and report directories
        # Build a comprehensive exclusion pattern that includes all YARA-related directories
        EXCLUDE_PATTERN="/opt/yara/|\.yar$|\.yara$|test.*\.(yar|sh|html)|all_test|full_yara_test|agentid_row\.txt"
        
        # Simplified scanning with proper exclusions
        SCAN_OUTPUT=$(timeout 300 find "$YARA_RULES_DIR" -maxdepth 1 -type f \( -name "*.yar" -o -name "*.yara" \) -exec yara {} "$dir" \; 2>&1 | grep -v -E "$EXCLUDE_PATTERN")
        SCAN_EXIT_CODE=$?
        
        if [ $SCAN_EXIT_CODE -eq 124 ]; then
            log_warning "Scan of $dir timed out after 5 minutes" | tee -a "$LOG_FILE"
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

log_info "Daily scan completed. Total threats found: $THREAT_COUNT" | tee -a "$LOG_FILE"

# Send email alert if threats were found
if [ $THREAT_COUNT -gt 0 ]; then
    log_warning "Sending threat alert email..." | tee -a "$LOG_FILE"
    
    # Create HTML alert
    TEMP_HTML="/tmp/daily_scan_alert_$(date +%Y%m%d_%H%M%S).html"
    create_html_header "YARA Daily Scan - THREAT ALERT" "daily_scan.sh" "2.0" > "$TEMP_HTML"
    
    cat >> "$TEMP_HTML" << EOF
<div class="alert alert-danger" style="text-align: center; font-size: 1.2em; padding: 20px;">
<strong>🚨 SECURITY ALERT: $THREAT_COUNT THREATS DETECTED</strong>
</div>

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
<tr><td>📁 Scan Coverage</td><td><span class="badge badge-info">Limited</span></td><td>$(echo $SCAN_DIRS | tr ' ' ', ')</td></tr>
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
            *) threat_display="$rule_name" ;;
        esac
        
        # Get directory location
        location=$(dirname "$file_path")
        filename=$(basename "$file_path")
        
        echo "<tr><td title=\"$file_path\">$filename</td><td style=\"color: #dc3545; font-weight: bold;\">$threat_display</td><td>$location</td></tr>" >> "$TEMP_HTML"
    done
    
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
            *) threat_display="$rule_name" ;;
        esac
        
        echo "<tr><td>$threat_display</td><td style=\"text-align: center; font-weight: bold;\">$count</td></tr>" >> "$TEMP_HTML"
    done
    
    cat >> "$TEMP_HTML" << EOF
</table>
</div>

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
</div>
EOF
    
    create_html_footer >> "$TEMP_HTML"
    send_html_email "[URGENT] YARA Daily Scan - $THREAT_COUNT Threats Detected" "$TEMP_HTML"
    rm -f "$TEMP_HTML"
    
    # Also quarantine detected files if active response is not handling them
    if command -v /var/ossec/active-response/bin/yara.sh >/dev/null 2>&1; then
        log_info "Active response will handle quarantine" | tee -a "$LOG_FILE"
    else
        log_warning "Consider enabling YARA active response for automatic quarantine" | tee -a "$LOG_FILE"
    fi
fi

# Rotate old logs (keep last 30 days)
find "$YARA_LOGS_DIR" -name "daily_scan_*.log" -mtime +30 -delete 2>/dev/null

exit 0
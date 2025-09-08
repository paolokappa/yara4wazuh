#!/bin/bash
# YARA Quick Daily Security Scan - Limited scope for faster execution
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

log_section "Starting Quick YARA Security Scan"

# Get and display rules summary
RULES_SUMMARY=$(get_rules_summary)
log_info "YARA Engine: $RULES_SUMMARY" | tee -a "$LOG_FILE"

# Limited directories for quick scan
SCAN_DIRS="/tmp"

# Clean up any YARA rule files from temp directories first
log_info "Cleaning temporary YARA files before scan..." | tee -a "$LOG_FILE"
find /tmp -type f \( -name "*.yar" -o -name "*.yara" \) -delete 2>/dev/null
find /tmp -type d -name "*yara*" -exec rm -rf {} \; 2>/dev/null

for dir in $SCAN_DIRS; do
    if [[ -d "$dir" ]]; then
        log_info "Scanning $dir..." | tee -a "$LOG_FILE"
        
        # Create a temporary file list excluding patterns that shouldn't be scanned
        TEMP_FILE_LIST="/tmp/yara_quick_scan_files_$$"
        
        # Build find command with proper exclusions
        FIND_CMD="find \"$dir\" -type f -maxdepth 3"
        
        # Add file pattern exclusions
        for pattern in $EXCLUDE_PATTERNS; do
            FIND_CMD="$FIND_CMD -not -name \"$pattern\""
        done
        
        # Add directory exclusions
        for exclude_dir in $EXCLUDE_DIRS; do
            FIND_CMD="$FIND_CMD -not -path \"$exclude_dir/*\""
        done
        
        # Limit to first 100 files for quick scan
        eval "$FIND_CMD" | head -100 > "$TEMP_FILE_LIST" 2>/dev/null
        
        # Run YARA only on filtered files with Linux-focused rules
        SCAN_OUTPUT=""
        if [ -s "$TEMP_FILE_LIST" ]; then
            # Use optimized rules for quick scan
            QUICK_RULES="/tmp/quick_linux_rules_$$.yar"
            
            # Check if optimized rules exist
            if [ ! -f "$YARA_RULES_DIR/optimized.yar" ]; then
                /opt/yara/scripts/optimize_rules.sh >/dev/null 2>&1
            fi
            
            # Use optimized rules
            cp "$YARA_RULES_DIR/optimized.yar" "$QUICK_RULES" 2>/dev/null
            
            if [ -s "$QUICK_RULES" ]; then
                RULE_COUNT=$(grep -c "^rule " "$QUICK_RULES" 2>/dev/null || echo "0")
                log_info "Quick scan with $RULE_COUNT Linux rules..." | tee -a "$LOG_FILE"
                
                while IFS= read -r file; do
                    if [ -f "$file" ]; then
                        FILE_SCAN=$(timeout 1 yara -w "$QUICK_RULES" "$file" 2>/dev/null)
                        if [ -n "$FILE_SCAN" ]; then
                            SCAN_OUTPUT="${SCAN_OUTPUT}${FILE_SCAN}\n"
                        fi
                    fi
                done < "$TEMP_FILE_LIST"
                
                rm -f "$QUICK_RULES"
            fi
        fi
        
        # Clean up temp file
        rm -f "$TEMP_FILE_LIST"
        
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
                    # Remove any trailing whitespace, newlines, or \n literal from file_path
                    file_path=$(echo "$line" | awk '{print $2}' | sed 's/\\n$//' | tr -d '\n' | tr -d '\r' | sed 's/[[:space:]]*$//')
                    
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
    
    # Create HTML alert in logs directory instead of /tmp
    TEMP_HTML="${YARA_LOGS_DIR}/daily_scan_alert_$(date +%Y%m%d_%H%M%S).html"
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
<tr><td>🛡️ YARA Engine</td><td><span class="badge badge-success">✓ Loaded</span></td><td><strong>$(count_yara_rules) total detection rules</strong></td></tr>
EOF

    # Add dynamic rule categories rows
    trojan=$(count_rules_by_pattern "Linux_Trojan")
    exploit=$(count_rules_by_pattern "Linux_Exploit")
    crypto=$(count_rules_by_pattern "Linux_Cryptominer")
    ransom=$(count_rules_by_pattern "Linux_Ransomware")
    rootkit=$(count_rules_by_pattern "Linux_Rootkit")
    backdoor=$(count_rules_by_pattern "Linux_Backdoor")
    webshell=$(count_rules_by_pattern "Linux_Webshell")
    hacktool=$(count_rules_by_pattern "Linux_Hacktool")
    mirai=$(count_rules_by_pattern "[Mm]irai")
    xz=$(count_rules_by_pattern "CVE.2024.3094\|XZ.*[Bb]ackdoor\|xz_util")
    pwnkit=$(count_rules_by_pattern "CVE.2021.4034\|PwnKit\|pkexec")
    ssh=$(count_rules_by_pattern "SSH\|ssh.*brute\|ssh.*backdoor")
    
    # Main malware categories
    [[ $trojan -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ Trojan</td><td><span class=\"badge badge-info\">Active</span></td><td><strong>$trojan</strong> rules - Linux trojan detection</td></tr>" >> "$TEMP_HTML"
    [[ $exploit -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ Exploit</td><td><span class=\"badge badge-info\">Active</span></td><td><strong>$exploit</strong> rules - Vulnerability exploits</td></tr>" >> "$TEMP_HTML"
    [[ $crypto -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ Cryptominer</td><td><span class=\"badge badge-info\">Active</span></td><td><strong>$crypto</strong> rules - Cryptocurrency miners</td></tr>" >> "$TEMP_HTML"
    [[ $ransom -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ Ransomware</td><td><span class=\"badge badge-info\">Active</span></td><td><strong>$ransom</strong> rules - Ransomware families</td></tr>" >> "$TEMP_HTML"
    [[ $rootkit -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ Rootkit</td><td><span class=\"badge badge-info\">Active</span></td><td><strong>$rootkit</strong> rules - Kernel/userspace rootkits</td></tr>" >> "$TEMP_HTML"
    [[ $backdoor -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ Backdoor</td><td><span class=\"badge badge-info\">Active</span></td><td><strong>$backdoor</strong> rules - Backdoor detection</td></tr>" >> "$TEMP_HTML"
    [[ $webshell -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ Webshell</td><td><span class=\"badge badge-info\">Active</span></td><td><strong>$webshell</strong> rules - Web shell detection</td></tr>" >> "$TEMP_HTML"
    [[ $hacktool -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ Hacktool</td><td><span class=\"badge badge-info\">Active</span></td><td><strong>$hacktool</strong> rules - Hacking tools</td></tr>" >> "$TEMP_HTML"
    
    # Critical threats
    [[ $xz -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ CVE-2024-3094</td><td><span class=\"badge badge-danger\">Critical</span></td><td><strong>$xz</strong> rules - XZ backdoor detection</td></tr>" >> "$TEMP_HTML"
    [[ $pwnkit -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ CVE-2021-4034</td><td><span class=\"badge badge-danger\">Critical</span></td><td><strong>$pwnkit</strong> rules - PwnKit exploit</td></tr>" >> "$TEMP_HTML"
    [[ $mirai -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ Mirai Botnet</td><td><span class=\"badge badge-warning\">High</span></td><td><strong>$mirai</strong> rules - IoT/DMZ botnet</td></tr>" >> "$TEMP_HTML"
    [[ $ssh -gt 0 ]] && echo "<tr><td>&nbsp;&nbsp;↳ SSH Attack</td><td><span class=\"badge badge-warning\">High</span></td><td><strong>$ssh</strong> rules - SSH bruteforce/backdoor</td></tr>" >> "$TEMP_HTML"
    
    # Feed sources
    echo "<tr><td>📚 Feed Sources</td><td><span class=\"badge badge-success\">✓ Active</span></td><td>$(get_feed_sources)</td></tr>" >> "$TEMP_HTML"
    
    cat >> "$TEMP_HTML" << EOF
<tr><td>📁 Scan Coverage</td><td><span class="badge badge-warning">Quick Scan</span></td><td>$(echo $SCAN_DIRS | tr ' ' ', ')</td></tr>
<tr><td>🎯 Detection Rate</td><td><span class="badge $([ $THREAT_COUNT -gt 0 ] && echo "badge-danger" || echo "badge-success")">$([ $THREAT_COUNT -gt 0 ] && echo "⚠️ Threats Found" || echo "✓ Clean")</span></td><td style="font-weight: bold;">$THREAT_COUNT threat(s) identified</td></tr>
</table>
</div>

<div class="section-header">
<h2 class="section-title">🔍 Detected Threats</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>📁 File Name</th><th>🦠 Threat Type</th><th>📍 Location</th><th>📝 Description</th></tr>
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
            
            # Get threat description
            threat_desc=$(get_threat_description "$rule_name")
            
            echo "<tr><td title=\"Full path: $file_path\">$filename</td><td style=\"color: #dc3545; font-weight: bold;\">$threat_display</td><td>$location</td><td style=\"font-size: 12px; color: #666;\">$threat_desc</td></tr>" >> "$TEMP_HTML"
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
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

# Note: We do NOT delete any files from /tmp as they could be malicious
# Files detected as threats will be quarantined, not deleted
log_info "Starting scan - suspicious files will be quarantined" | tee -a "$LOG_FILE"

# Critical directories to scan
SCAN_DIRS="/tmp /var/tmp /dev/shm /var/www /home"

# Exclude directories from scan to avoid false positives
# Include YARA rules directory to prevent self-detection
EXCLUDE_DIRS="/opt/yara/rules /opt/yara/backup /opt/yara/reports"

# File patterns to exclude from scanning (reports, temp files, etc.)
EXCLUDE_PATTERNS="daily_scan_alert_*.html yara_scan_*.html test_*.html *.yar *.yara agentid_row.txt"

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
        
        # Clean up old scan reports and temp files before scanning
        find "$dir" -name "daily_scan_alert_*.html" -mtime +1 -delete 2>/dev/null
        find "$dir" -name "yara_scan_*.html" -mtime +1 -delete 2>/dev/null
        
        # Create a temporary file list excluding patterns that shouldn't be scanned
        TEMP_FILE_LIST="/tmp/yara_scan_files_$$"
        
        # Build find command with proper exclusions BEFORE scanning
        FIND_CMD="find \"$dir\" -type f"
        
        # Add directory exclusions
        for exclude_dir in $EXCLUDE_DIRS; do
            FIND_CMD="$FIND_CMD -not -path \"$exclude_dir/*\""
        done
        
        # Add file pattern exclusions
        for pattern in $EXCLUDE_PATTERNS; do
            FIND_CMD="$FIND_CMD -not -name \"$pattern\""
        done
        
        # Execute find and save file list
        eval "$FIND_CMD" > "$TEMP_FILE_LIST" 2>/dev/null
        
        # Run YARA scan using yarac compiled rules for better performance
        SCAN_OUTPUT=""
        if [ -s "$TEMP_FILE_LIST" ]; then
            # Use only essential rules for daily scan (exclude noisy/slow rules)
            ESSENTIAL_RULES="/tmp/essential_rules_$$.yar"
            
            # Prepare LINUX-focused YARA rules for daily scan
            log_info "Preparing Linux-focused YARA rules for scan..." | tee -a "$LOG_FILE"
            
            # Include only Linux-relevant categories (no Windows-specific rules)
            cat "$YARA_RULES_DIR"/base_rules.yar \
                "$YARA_RULES_DIR"/000_common_rules.yar \
                "$YARA_RULES_DIR"/Multi_EICAR.yar \
                "$YARA_RULES_DIR"/Linux_*.yar \
                "$YARA_RULES_DIR"/APT_*.yar \
                "$YARA_RULES_DIR"/MALW_*.yar \
                "$YARA_RULES_DIR"/RANSOM_*.yar \
                "$YARA_RULES_DIR"/RAT_*.yar \
                "$YARA_RULES_DIR"/*[Bb]ackdoor*.yar \
                "$YARA_RULES_DIR"/*[Ee]xploit*.yar \
                "$YARA_RULES_DIR"/*[Ww]ebshell*.yar \
                "$YARA_RULES_DIR"/*[Mm]iner*.yar \
                "$YARA_RULES_DIR"/*[Cc]rypto*.yar 2>/dev/null | \
                grep -v "Windows\|Win32\|Win64\|PE\|MZ\|DOS" > "$ESSENTIAL_RULES" 2>/dev/null
            
            if [ -s "$ESSENTIAL_RULES" ]; then
                RULE_COUNT=$(grep -c "^rule " "$ESSENTIAL_RULES" 2>/dev/null || echo "0")
                log_info "Scanning with $RULE_COUNT essential rules..." | tee -a "$LOG_FILE"
                
                # Process files one by one with timeout to avoid hanging
                while IFS= read -r file; do
                    if [ -f "$file" ]; then
                        FILE_SCAN=$(timeout 2 yara -w "$ESSENTIAL_RULES" "$file" 2>/dev/null)
                        if [ -n "$FILE_SCAN" ]; then
                            SCAN_OUTPUT="${SCAN_OUTPUT}${FILE_SCAN}\n"
                        fi
                    fi
                done < "$TEMP_FILE_LIST"
            else
                log_warning "No YARA rules found in $YARA_RULES_DIR" | tee -a "$LOG_FILE"
            fi
            
            # Cleanup rules file
            rm -f "$ESSENTIAL_RULES"
        fi
        
        # Clean up temp file
        rm -f "$TEMP_FILE_LIST"
        
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

# Always send daily report (with or without threats)
# Check if there are files in quarantine
QUARANTINE_FILES=$(find "$QUARANTINE_DIR" -name "*.quarantine.*" -type f 2>/dev/null | wc -l)

# Send email report
if [ $THREAT_COUNT -gt 0 ] || [ $QUARANTINE_FILES -gt 0 ] || [ "${ALWAYS_SEND_REPORT:-yes}" = "yes" ]; then
    log_info "Preparing daily scan report..." | tee -a "$LOG_FILE"
    
    # Create HTML alert in logs directory instead of /tmp to avoid self-scanning
    TEMP_HTML="${YARA_LOGS_DIR}/daily_scan_alert_$(date +%Y%m%d_%H%M%S).html"
    
    # Set title based on threat status
    if [ $THREAT_COUNT -gt 0 ]; then
        REPORT_TITLE="YARA Daily Scan - 🚨 THREAT ALERT"
        EMAIL_SUBJECT="[URGENT] YARA Daily Scan - $THREAT_COUNT Threats Detected"
    elif [ $QUARANTINE_FILES -gt 0 ]; then
        REPORT_TITLE="YARA Daily Scan - ⚠️ Quarantine Active"
        EMAIL_SUBJECT="YARA Daily Scan - $QUARANTINE_FILES Files in Quarantine"
    else
        REPORT_TITLE="YARA Daily Scan - ✅ System Clean"
        EMAIL_SUBJECT="YARA Daily Scan - System Clean"
    fi
    
    create_html_header "$REPORT_TITLE" "daily_scan.sh" "2.0" > "$TEMP_HTML"
    
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

EOF
    
    # Add quarantine status section
    cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">🔒 Quarantine Status</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr>
<th>📅 Date</th>
<th>📁 Original File</th>
<th>🦠 Threat Type</th>
<th>📏 Size</th>
<th>🔑 SHA256</th>
<th>⏰ Quarantined</th>
</tr>
EOF
    
    # List all quarantined files with details
    QUARANTINE_COUNT=0
    if [ -d "$QUARANTINE_DIR" ]; then
        for qfile in $(find "$QUARANTINE_DIR" -name "*.quarantine.*" -type f 2>/dev/null | sort -r | head -20); do
            if [ -f "$qfile" ]; then
                QUARANTINE_COUNT=$((QUARANTINE_COUNT + 1))
                INFO_FILE="${qfile}.info"
                
                # Extract info from .info file if exists
                if [ -f "$INFO_FILE" ]; then
                    ORIG_PATH=$(grep "Original Path:" "$INFO_FILE" 2>/dev/null | cut -d: -f2- | xargs)
                    THREAT_RULE=$(grep "Detection Rule:" "$INFO_FILE" 2>/dev/null | cut -d: -f2- | xargs)
                    Q_TIME=$(grep "Quarantine Time:" "$INFO_FILE" 2>/dev/null | cut -d: -f2- | cut -c1-20)
                    SHA256=$(grep "SHA256:" "$INFO_FILE" 2>/dev/null | cut -d: -f2 | xargs | cut -c1-16)
                else
                    ORIG_PATH=$(basename "$qfile" | cut -d. -f1)
                    THREAT_RULE="Unknown"
                    Q_TIME=$(stat -c %y "$qfile" 2>/dev/null | cut -d. -f1)
                    SHA256=$(sha256sum "$qfile" 2>/dev/null | cut -c1-16)
                fi
                
                # Get file size
                FILE_SIZE=$(du -h "$qfile" 2>/dev/null | cut -f1)
                Q_DATE=$(echo "$qfile" | grep -oE "[0-9]{8}" | head -1)
                
                # Format date
                if [ -n "$Q_DATE" ]; then
                    FORMATTED_DATE="${Q_DATE:0:4}-${Q_DATE:4:2}-${Q_DATE:6:2}"
                else
                    FORMATTED_DATE=$(date +%Y-%m-%d)
                fi
                
                # Shorten original path for display
                SHORT_PATH=$(basename "$ORIG_PATH")
                
                echo "<tr>" >> "$TEMP_HTML"
                echo "<td>$FORMATTED_DATE</td>" >> "$TEMP_HTML"
                echo "<td title=\"$ORIG_PATH\">$SHORT_PATH</td>" >> "$TEMP_HTML"
                echo "<td style=\"color: #dc3545;\">$THREAT_RULE</td>" >> "$TEMP_HTML"
                echo "<td>$FILE_SIZE</td>" >> "$TEMP_HTML"
                echo "<td style=\"font-family: monospace; font-size: 0.9em;\">${SHA256}...</td>" >> "$TEMP_HTML"
                echo "<td>$Q_TIME</td>" >> "$TEMP_HTML"
                echo "</tr>" >> "$TEMP_HTML"
            fi
        done
    fi
    
    if [ $QUARANTINE_COUNT -eq 0 ]; then
        echo "<tr><td colspan=\"6\" style=\"text-align: center; color: #6c757d;\">No files currently in quarantine</td></tr>" >> "$TEMP_HTML"
    fi
    
    cat >> "$TEMP_HTML" << EOF
</table>
</div>

<div class="info-box" style="margin-top: 10px;">
<p><strong>📊 Quarantine Summary:</strong></p>
<ul style="list-style-type: none;">
<li>• Total files in quarantine: <strong>$(find "$QUARANTINE_DIR" -name "*.quarantine.*" -type f 2>/dev/null | wc -l)</strong></li>
<li>• Quarantine location: <code>$QUARANTINE_DIR</code></li>
<li>• Oldest quarantined file: <strong>$(find "$QUARANTINE_DIR" -name "*.quarantine.*" -type f -printf '%T+ %p\n' 2>/dev/null | sort | head -1 | cut -d' ' -f1)</strong></li>
<li>• Total quarantine size: <strong>$(du -sh "$QUARANTINE_DIR" 2>/dev/null | cut -f1)</strong></li>
</ul>
</div>

<br>
<div class="alert alert-warning">
<strong>⚡ Immediate Actions Required:</strong>
<ul>
<li>Review detected threats in the quarantine directory</li>
<li>Investigate infection vectors</li>
<li>Check system logs for suspicious activity</li>
<li>Run full system scan if necessary</li>
<li>Clean quarantine of confirmed false positives</li>
</ul>
</div>
</div>
EOF
    
    create_html_footer >> "$TEMP_HTML"
    send_html_email "$EMAIL_SUBJECT" "$TEMP_HTML"
    rm -f "$TEMP_HTML"
    
    # Quarantine detected threats
    QUARANTINE_DIR="/opt/yara/quarantine"
    mkdir -p "$QUARANTINE_DIR" 2>/dev/null
    chmod 700 "$QUARANTINE_DIR" 2>/dev/null
    
    log_warning "Quarantining detected threats..." | tee -a "$LOG_FILE"
    QUARANTINED_COUNT=0
    
    for file_path in "${!THREAT_FILES[@]}"; do
        if [ -f "$file_path" ]; then
            # Create quarantine subdirectory with date
            QUARANTINE_DATE_DIR="$QUARANTINE_DIR/$(date +%Y%m%d)"
            mkdir -p "$QUARANTINE_DATE_DIR" 2>/dev/null
            
            # Generate unique quarantine filename
            BASENAME=$(basename "$file_path")
            QUARANTINE_FILE="$QUARANTINE_DATE_DIR/${BASENAME}.quarantine.$(date +%H%M%S)_$$"
            
            # Move file to quarantine with restricted permissions
            if mv "$file_path" "$QUARANTINE_FILE" 2>/dev/null; then
                chmod 600 "$QUARANTINE_FILE" 2>/dev/null
                log_info "Quarantined: $file_path -> $QUARANTINE_FILE" | tee -a "$LOG_FILE"
                QUARANTINED_COUNT=$((QUARANTINED_COUNT + 1))
                
                # Create info file with threat details
                echo "Original Path: $file_path" > "${QUARANTINE_FILE}.info"
                echo "Detection Rule: ${THREAT_FILES[$file_path]}" >> "${QUARANTINE_FILE}.info"
                echo "Quarantine Time: $(date)" >> "${QUARANTINE_FILE}.info"
                echo "SHA256: $(sha256sum "$QUARANTINE_FILE" 2>/dev/null | awk '{print $1}')" >> "${QUARANTINE_FILE}.info"
            else
                log_error "Failed to quarantine: $file_path" | tee -a "$LOG_FILE"
            fi
        fi
    done
    
    log_info "Quarantined $QUARANTINED_COUNT of $THREAT_COUNT detected threats" | tee -a "$LOG_FILE"
    
    # Check if active response is available for additional actions
    if command -v /var/ossec/active-response/bin/yara.sh >/dev/null 2>&1; then
        log_info "Active response is available for additional security actions" | tee -a "$LOG_FILE"
    fi
fi

# Rotate old logs (keep last 30 days)
find "$YARA_LOGS_DIR" -name "daily_scan_*.log" -mtime +30 -delete 2>/dev/null

exit 0
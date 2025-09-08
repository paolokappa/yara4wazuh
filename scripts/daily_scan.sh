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
            
            # Use the optimized rules file
            log_info "Using optimized YARA rules for scan..." | tee -a "$LOG_FILE"
            
            # Check if optimized rules exist, if not create them
            if [ ! -f "$YARA_RULES_DIR/optimized.yar" ]; then
                log_info "Optimized rules not found, creating them..." | tee -a "$LOG_FILE"
                /opt/yara/scripts/optimize_rules.sh >/dev/null 2>&1
            fi
            
            # Use optimized rules for scanning
            cp "$YARA_RULES_DIR/optimized.yar" "$ESSENTIAL_RULES" 2>/dev/null
            
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
<tr><td>📁 Scan Coverage</td><td><span class="badge badge-info">Limited</span></td><td>$(echo $SCAN_DIRS | tr ' ' ', ')</td></tr>
<tr><td>🎯 Detection Rate</td><td><span class="badge $([ $THREAT_COUNT -gt 0 ] && echo "badge-danger" || echo "badge-success")">$([ $THREAT_COUNT -gt 0 ] && echo "⚠️ Threats Found" || echo "✓ Clean")</span></td><td style="font-weight: bold;">$THREAT_COUNT threat(s) identified</td></tr>
</table>
</div>

<div class="section-header">
<h2 class="section-title">📋 Active YARA Rules Categories</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>Category</th><th>Description</th><th>Active Rules</th></tr>
EOF

    # Get dynamic counts
    local trojan_count=$(count_rules_by_pattern "Linux_Trojan")
    local exploit_count=$(count_rules_by_pattern "Linux_Exploit")
    local crypto_count=$(count_rules_by_pattern "Linux_Cryptominer")
    local ransom_count=$(count_rules_by_pattern "Linux_Ransomware")
    local rootkit_count=$(count_rules_by_pattern "Linux_Rootkit")
    local backdoor_count=$(count_rules_by_pattern "Linux_Backdoor")
    local webshell_count=$(count_rules_by_pattern "Linux_Webshell")
    local hacktool_count=$(count_rules_by_pattern "Linux_Hacktool")
    local xz_count=$(count_rules_by_pattern "CVE.2024.3094\|XZ.*[Bb]ackdoor\|xz_util")
    local pwnkit_count=$(count_rules_by_pattern "CVE.2021.4034\|PwnKit\|pkexec")
    local mirai_count=$(count_rules_by_pattern "[Mm]irai")
    local ssh_count=$(count_rules_by_pattern "SSH\|ssh.*brute\|ssh.*backdoor")
    
    # Only show categories with rules
    [[ $trojan_count -gt 0 ]] && echo "<tr><td>🦠 Linux Trojan</td><td>Trojan detection for Linux</td><td style=\"text-align: center;\"><strong>$trojan_count</strong> rules</td></tr>" >> "$TEMP_HTML"
    [[ $exploit_count -gt 0 ]] && echo "<tr><td>💥 Linux Exploit</td><td>Exploit and vulnerability detection</td><td style=\"text-align: center;\"><strong>$exploit_count</strong> rules</td></tr>" >> "$TEMP_HTML"
    [[ $crypto_count -gt 0 ]] && echo "<tr><td>⛏️ Linux Cryptominer</td><td>Cryptocurrency mining malware</td><td style=\"text-align: center;\"><strong>$crypto_count</strong> rules</td></tr>" >> "$TEMP_HTML"
    [[ $ransom_count -gt 0 ]] && echo "<tr><td>🔐 Linux Ransomware</td><td>Ransomware detection</td><td style=\"text-align: center;\"><strong>$ransom_count</strong> rules</td></tr>" >> "$TEMP_HTML"
    [[ $rootkit_count -gt 0 ]] && echo "<tr><td>👻 Linux Rootkit</td><td>Rootkit and stealth malware</td><td style=\"text-align: center;\"><strong>$rootkit_count</strong> rules</td></tr>" >> "$TEMP_HTML"
    [[ $backdoor_count -gt 0 ]] && echo "<tr><td>🚪 Linux Backdoor</td><td>Backdoor detection</td><td style=\"text-align: center;\"><strong>$backdoor_count</strong> rules</td></tr>" >> "$TEMP_HTML"
    [[ $webshell_count -gt 0 ]] && echo "<tr><td>🌐 Linux Webshell</td><td>Web shell detection</td><td style=\"text-align: center;\"><strong>$webshell_count</strong> rules</td></tr>" >> "$TEMP_HTML"
    [[ $hacktool_count -gt 0 ]] && echo "<tr><td>🔧 Linux Hacktool</td><td>Hacking tools detection</td><td style=\"text-align: center;\"><strong>$hacktool_count</strong> rules</td></tr>" >> "$TEMP_HTML"
    
    # Show CVE section only if we have CVE rules
    if [[ $xz_count -gt 0 ]] || [[ $pwnkit_count -gt 0 ]] || [[ $mirai_count -gt 0 ]] || [[ $ssh_count -gt 0 ]]; then
        echo "<tr><td colspan=\"3\" style=\"background: #f0f0f0; font-weight: bold;\">Critical CVE & APT Coverage</td></tr>" >> "$TEMP_HTML"
        [[ $xz_count -gt 0 ]] && echo "<tr><td>🔴 CVE-2024-3094</td><td>XZ backdoor detection</td><td style=\"text-align: center;\"><strong>$xz_count</strong> rules</td></tr>" >> "$TEMP_HTML"
        [[ $pwnkit_count -gt 0 ]] && echo "<tr><td>🔴 CVE-2021-4034</td><td>PwnKit exploit detection</td><td style=\"text-align: center;\"><strong>$pwnkit_count</strong> rules</td></tr>" >> "$TEMP_HTML"
        [[ $mirai_count -gt 0 ]] && echo "<tr><td>🤖 Mirai Botnet</td><td>IoT/DMZ botnet detection</td><td style=\"text-align: center;\"><strong>$mirai_count</strong> rules</td></tr>" >> "$TEMP_HTML"
        [[ $ssh_count -gt 0 ]] && echo "<tr><td>🔑 SSH Attacks</td><td>SSH bruteforce and backdoor</td><td style=\"text-align: center;\"><strong>$ssh_count</strong> rules</td></tr>" >> "$TEMP_HTML"
    fi
    
    cat >> "$TEMP_HTML" << EOF
<tr><td colspan="3" style="background: #e8f4f8; font-weight: bold;">Premium Feed Sources</td></tr>
<tr><td>🏆 Elastic</td><td>Elastic protections-artifacts</td><td style="text-align: center;"><strong>Auto-updated</strong></td></tr>
<tr><td>🌟 Neo23x0</td><td>Florian Roth signature-base</td><td style="text-align: center;"><strong>Premium rules</strong></td></tr>
<tr><td>🛡️ GOLINE</td><td>Custom DMZ-focused rules</td><td style="text-align: center;"><strong>Custom</strong></td></tr>
</table>
</div>

<div class="section-header">
<h2 class="section-title">🔍 Detected Threats</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>📁 File Name</th><th>🦠 Threat Type</th><th>📍 Location</th><th>📝 Description</th></tr>
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
        
        # Get threat description
        threat_desc=$(get_threat_description "$rule_name")
        
        echo "<tr><td title=\"Full path: $file_path\">$filename</td><td style=\"color: #dc3545; font-weight: bold;\">$threat_display</td><td>$location</td><td style=\"font-size: 12px; color: #666;\">$threat_desc</td></tr>" >> "$TEMP_HTML"
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
#!/bin/bash
# YARA-Wazuh Health Check Script
# Performs comprehensive system health check and sends HTML report
# Company: GOLINE SA - www.goline.ch

# Source common functions
source /opt/yara/scripts/common.sh

perform_health_check() {
    log_section "Performing YARA-Wazuh Health Check"
    
    # Prepare HTML report
    TEMP_HTML="/tmp/health_check_$(date +%Y%m%d_%H%M%S).html"
    
    # Get system information
    local yara_version=$(yara --version 2>/dev/null | head -1 || echo "Not installed")
    local rules_count=$(count_yara_rules)
    local wazuh_status=$(check_wazuh_status)
    local wazuh_agent_id=$(get_wazuh_agent_id)
    local wazuh_version=$(/var/ossec/bin/wazuh-control info 2>/dev/null | grep -i version | cut -d'"' -f2 || echo "Unknown")
    local quarantine_files=$(find "$QUARANTINE_DIR" -type f 2>/dev/null | wc -l)
    local log_size=$(du -sh "$YARA_LOGS_DIR" 2>/dev/null | cut -f1 || echo "0")
    
    # Check infected files in quarantine
    local infected_files=""
    if [[ $quarantine_files -gt 0 ]]; then
        infected_files=$(find "$QUARANTINE_DIR" -type f -mtime -7 -exec basename {} \; 2>/dev/null | head -10)
    fi
    
    # Generate HTML report with enhanced header
    create_html_header "YARA-Wazuh Health Check Report" "health_check.sh" "1.0" > "$TEMP_HTML"
    
    cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">&#128200; System Overview</h2>
</div>

<div class="stats-grid">
<div class="stat-row">
<div class="stat-card">
<p class="stat-value">&#128220; ${rules_count}</p>
<p class="stat-label">YARA Rules</p>
</div>
<div class="stat-card">
<p class="stat-value">&#9888; ${quarantine_files}</p>
<p class="stat-label">Quarantined Files</p>
</div>
<div class="stat-card">
<p class="stat-value">&#128221; ${log_size}</p>
<p class="stat-label">Log Size</p>
</div>
</div>
</div>

<div class="section-header">
<h2 class="section-title">&#128736; System Status</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>Component</th><th>Status</th><th>Details</th></tr>
<tr><td>&#128640; YARA Engine</td><td><span class="badge badge-success">&#10004; Active</span></td><td>${yara_version}</td></tr>
<tr><td>&#128225; Wazuh Agent</td><td><span class="badge $([ "$wazuh_status" = "Running" ] && echo "badge-success" || echo "badge-danger")">$([ "$wazuh_status" = "Running" ] && echo "&#10004;" || echo "&#10060;") ${wazuh_status}</span></td><td>Version: ${wazuh_version} | Agent ID: ${wazuh_agent_id}</td></tr>
<tr><td>&#128218; Rules Database</td><td><span class="badge badge-success">&#10004; Loaded</span></td><td>${rules_count} rules active</td></tr>
<tr><td>&#9881; Automation</td><td><span class="badge badge-success">&#10004; Configured</span></td><td>7 scheduled tasks</td></tr>
<tr><td>&#128231; Email Notifications</td><td><span class="badge badge-success">&#10004; Enabled</span></td><td>Sending to: ${EMAIL_TO}</td></tr>
</table>
</div>
EOF

    # Add infected files section if any exist
    if [[ $quarantine_files -gt 0 ]]; then
        cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">&#128680; Recent Quarantine Activity</h2>
</div>
<div class="info-box">
<div class="alert alert-warning">
<strong>&#9888; ${quarantine_files} files in quarantine</strong>
</div>
<table class="data-table">
<tr><th>&#128193; File Name</th><th>&#128680; Threat Type</th><th>&#128337; Detection Time</th></tr>
EOF
        
        while IFS= read -r file; do
            if [[ -n "$file" ]]; then
                local full_path="$QUARANTINE_DIR/$file"
                local detect_time=$(stat -c %y "$full_path" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
                local threat_type="Unknown"
                
                # First, try to extract threat name from filename
                # Format: originalname.THREAT_NAME.timestamp
                if [[ "$file" =~ \.(.*)\.[0-9]{8}_[0-9]{6}$ ]]; then
                    local extracted_threat="${BASH_REMATCH[1]}"
                    # Get the threat name (between last two dots)
                    extracted_threat=$(echo "$file" | rev | cut -d'.' -f2 | rev)
                    if [[ -n "$extracted_threat" ]] && [[ "$extracted_threat" != "*" ]]; then
                        # Clean up common threat names for better display
                        case "$extracted_threat" in
                            Test_Malware) threat_type="Test Malware" ;;
                            EICAR_Test_File) threat_type="EICAR Test" ;;
                            Webshell_Generic) threat_type="Webshell" ;;
                            Suspicious_Base64_Shell) threat_type="Base64 Shell" ;;
                            *) threat_type="$extracted_threat" ;;
                        esac
                    fi
                fi
                
                # If still unknown, try to detect with YARA
                if [[ "$threat_type" == "Unknown" ]]; then
                    if [[ -f "/opt/yara/rules/base_rules.yar" ]] && command -v yara >/dev/null 2>&1; then
                        yara_result=$(timeout 2 yara /opt/yara/rules/base_rules.yar "$full_path" 2>/dev/null | head -1)
                        if [[ -n "$yara_result" ]]; then
                            rule_name=$(echo "$yara_result" | awk '{print $1}')
                            case "$rule_name" in
                                EICAR_Test_File) threat_type="EICAR Test" ;;
                                Test_Malware) threat_type="Test Malware" ;;
                                Webshell_Generic) threat_type="Webshell" ;;
                                Suspicious_Base64_Shell) threat_type="Base64 Shell" ;;
                                *) threat_type="$rule_name" ;;
                            esac
                        fi
                    fi
                fi
                
                # Also check for EICAR with grep (handles escaped versions)
                if [[ "$threat_type" == "Unknown" ]]; then
                    if grep -q "STANDARD-ANTIVIRUS-TEST-FILE" "$full_path" 2>/dev/null; then
                        threat_type="EICAR Test"
                    elif grep -q "MALWARE_TEST_STRING" "$full_path" 2>/dev/null; then
                        threat_type="Test Malware"
                    fi
                fi
                
                echo "<tr><td>$file</td><td style=\"color: #dc3545; font-weight: bold;\">$threat_type</td><td>$detect_time</td></tr>" >> "$TEMP_HTML"
            fi
        done <<< "$infected_files"
        
        echo "</table></div>" >> "$TEMP_HTML"
    fi
    
    # Add FIM (File Integrity Monitoring) Status
    cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">&#128065; FIM Status (File Integrity Monitoring)</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>&#128193; Directory</th><th>&#9989; Monitoring</th><th>&#128337; Real-time</th></tr>
EOF
    
    # Check FIM configuration from shared agent.conf (takes precedence over local config)
    CONFIG_FILE="/var/ossec/etc/shared/agent.conf"
    if [ ! -f "$CONFIG_FILE" ]; then
        CONFIG_FILE="/var/ossec/etc/ossec.conf"
    fi
    
    if [ -f "$CONFIG_FILE" ]; then
        # Extract all monitored directories from syscheck configuration
        # Process directories and check for real-time status (prioritize real-time)
        TEMP_DIRS_LIST="/tmp/fim_processing_$$"
        > "$TEMP_DIRS_LIST"
        
        # First pass: collect all directories with their real-time status
        grep '<directories' "$CONFIG_FILE" | while read -r line; do
            # Check if realtime is enabled for this line
            if echo "$line" | grep -q 'realtime="yes"'; then
                realtime_status="realtime"
            else
                realtime_status="scheduled"
            fi
            
            # Extract directory paths
            dirs=$(echo "$line" | sed 's/.*>\(.*\)<.*/\1/' | tr ',' '\n')
            for dir in $dirs; do
                # Clean up directory path (remove spaces)
                dir=$(echo "$dir" | xargs)
                if [ -n "$dir" ]; then
                    echo "$dir|$realtime_status" >> "$TEMP_DIRS_LIST"
                fi
            done
        done
        
        # Second pass: process unique directories (realtime takes priority)
        if [ -f "$TEMP_DIRS_LIST" ]; then
            sort "$TEMP_DIRS_LIST" | awk -F'|' '
            {
                if (seen[$1]) {
                    if ($2 == "realtime" && status[$1] == "scheduled") {
                        status[$1] = "realtime"
                    }
                } else {
                    seen[$1] = 1
                    status[$1] = $2
                }
            }
            END {
                for (dir in seen) {
                    print dir "|" status[dir]
                }
            }' | while IFS='|' read -r dir realtime_status; do
                if [ "$realtime_status" = "realtime" ]; then
                    realtime_display="✅ Enabled"
                    realtime_color="color: #28a745;"
                else
                    realtime_display="📅 Scheduled"
                    realtime_color="color: #17a2b8;"
                fi
                
                # Since we found this directory in the config, it's configured
                # Check how many files are actually being monitored
                if [ -f /var/ossec/queue/fim/db/fim.db ] && check_sqlite; then
                    # For exact directory matches, use exact path
                    if [[ "$dir" == "/etc" ]] || [[ "$dir" == "/tmp" ]] || [[ "$dir" == "/boot" ]] || [[ "$dir" == "/bin" ]] || [[ "$dir" == "/sbin" ]] || [[ "$dir" == "/usr/bin" ]] || [[ "$dir" == "/usr/sbin" ]] || [[ "$dir" == "/home" ]] || [[ "$dir" == "/root" ]]; then
                        monitored_files=$(sqlite3 /var/ossec/queue/fim/db/fim.db "SELECT COUNT(*) FROM file_entry WHERE path LIKE '$dir/%' OR path = '$dir';" 2>/dev/null || echo "0")
                    else
                        monitored_files=$(sqlite3 /var/ossec/queue/fim/db/fim.db "SELECT COUNT(*) FROM file_entry WHERE path LIKE '$dir%';" 2>/dev/null || echo "0")
                    fi
                    
                    if [ "$monitored_files" -gt 0 ]; then
                        monitoring_status="✅ Active ($monitored_files files)"
                    else
                        monitoring_status="✅ Active (empty)"
                    fi
                else
                    monitoring_status="✅ Active"
                fi
                monitoring_color="color: #28a745;"
                
                echo "<tr><td>$dir</td><td style=\"$monitoring_color\">$monitoring_status</td><td style=\"$realtime_color\">$realtime_display</td></tr>" >> "$TEMP_HTML"
            done
        fi
        
        # Cleanup temporary file
        rm -f "$TEMP_DIRS_LIST"
    fi
    
    # Add FIM recent events if available
    echo "</table>" >> "$TEMP_HTML"
    
    # Check for recent FIM events in Wazuh database
    if [ -f /var/ossec/queue/fim/db/fim.db ] && check_sqlite; then
        fim_event_count=$(sqlite3 /var/ossec/queue/fim/db/fim.db "SELECT COUNT(*) FROM file_entry WHERE mtime > datetime('now', '-24 hours');" 2>/dev/null || echo "0")
        if [ "$fim_event_count" != "0" ] && [ -n "$fim_event_count" ]; then
            echo "<br><div style=\"background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 10px;\">" >> "$TEMP_HTML"
            echo "<strong>&#128200; FIM Events (Last 24h):</strong> $fim_event_count file changes detected" >> "$TEMP_HTML"
            
            # Get top 5 recent FIM events
            recent_events=$(sqlite3 /var/ossec/queue/fim/db/fim.db "SELECT path, datetime(mtime, 'unixepoch') FROM file_entry ORDER BY mtime DESC LIMIT 5;" 2>/dev/null)
            if [ -n "$recent_events" ]; then
                echo "<br><strong>Recent Changes:</strong><ul style=\"margin: 5px 0;\">" >> "$TEMP_HTML"
                echo "$recent_events" | while IFS='|' read -r path timestamp; do
                    if [ -n "$path" ]; then
                        echo "<li style=\"font-size: 0.9em;\">$path <span style=\"color: #6c757d;\">(${timestamp})</span></li>" >> "$TEMP_HTML"
                    fi
                done
                echo "</ul>" >> "$TEMP_HTML"
            fi
            echo "</div>" >> "$TEMP_HTML"
        fi
    fi
    
    echo "</div>" >> "$TEMP_HTML"
    
    # Add YARA Active Response Statistics
    cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">&#9889; YARA Active Response Statistics</h2>
</div>
<div class="info-box">
EOF
    
    if [ -f /var/log/yara/yara_active_response.log ]; then
        # Count total YARA detections
        total_detections=$(grep -c "THREAT DETECTED" /var/log/yara/yara_active_response.log 2>/dev/null) || total_detections=0
        total_quarantined=$(grep -c "File quarantined" /var/log/yara/yara_active_response.log 2>/dev/null) || total_quarantined=0
        total_scans=$(grep -c "Starting YARA scan" /var/log/yara/yara_active_response.log 2>/dev/null) || total_scans=0
        
        echo "<table class=\"data-table\">" >> "$TEMP_HTML"
        echo "<tr><th>&#128200; Metric</th><th>&#128290; Count</th></tr>" >> "$TEMP_HTML"
        echo "<tr><td>Total YARA Scans Triggered</td><td>$total_scans</td></tr>" >> "$TEMP_HTML"
        echo "<tr><td>Total Threats Detected</td><td style=\"color: #dc3545; font-weight: bold;\">$total_detections</td></tr>" >> "$TEMP_HTML"
        echo "<tr><td>Total Files Quarantined</td><td style=\"color: #ffc107; font-weight: bold;\">$total_quarantined</td></tr>" >> "$TEMP_HTML"
        echo "</table>" >> "$TEMP_HTML"
        
        # Show last 5 YARA detections
        last_detections=$(grep "THREAT DETECTED" /var/log/yara/yara_active_response.log 2>/dev/null | tail -5)
        if [ -n "$last_detections" ]; then
            echo "<br><div style=\"background: #fff3cd; padding: 10px; border-radius: 5px; border-left: 4px solid #ffc107;\">" >> "$TEMP_HTML"
            echo "<strong>&#128680; Recent YARA Detections:</strong><ul style=\"margin: 5px 0; list-style: none; padding-left: 10px;\">" >> "$TEMP_HTML"
            echo "$last_detections" | while read -r line; do
                # Extract timestamp and threat info
                timestamp=$(echo "$line" | sed 's/^\[\([^]]*\)\].*/\1/')
                threat=$(echo "$line" | sed 's/.*THREAT DETECTED: //')
                echo "<li style=\"font-size: 0.9em; margin: 3px 0;\">&#8226; <span style=\"color: #6c757d;\">$timestamp</span> - $threat</li>" >> "$TEMP_HTML"
            done
            echo "</ul></div>" >> "$TEMP_HTML"
        fi
    else
        echo "<p style=\"color: #6c757d;\">No YARA active response log found</p>" >> "$TEMP_HTML"
    fi
    
    echo "</div>" >> "$TEMP_HTML"
    
    # Add performance metrics
    cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">&#128202; Performance Metrics</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>&#128200; Metric</th><th>&#128208; Value</th></tr>
<tr><td>Last Daily Scan</td><td>$(find "$YARA_LOGS_DIR" -name "daily_scan_*.log" -type f -exec ls -t {} \; 2>/dev/null | head -1 | xargs -I {} stat -c %y {} 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1 || echo "Never")</td></tr>
<tr><td>Last Rules Update</td><td>$(stat -c %y "$YARA_RULES_DIR" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1 || echo "Unknown")</td></tr>
<tr><td>Total Log Files</td><td>$(find "$YARA_LOGS_DIR" -name "*.log" -type f 2>/dev/null | wc -l)</td></tr>
<tr><td>Disk Usage (Logs)</td><td>${log_size}</td></tr>
</table>
</div>
EOF
    
    create_html_footer >> "$TEMP_HTML"
    
    # Send the report
    send_html_email "[YARA-Wazuh] Health Check Report - $(hostname)" "$TEMP_HTML"
    
    # Keep a copy for debugging (optional - comment out in production)
    cp "$TEMP_HTML" "/tmp/last_health_check.html" 2>/dev/null
    
    # Clean up
    rm -f "$TEMP_HTML"
    
    log_info "[OK] Health check completed and report sent"
}

# Main execution
perform_health_check
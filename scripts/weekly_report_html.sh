#!/bin/bash
# YARA-Wazuh Weekly Security Report - HTML Version
# v13.0 - Using common header/footer functions

# Source common functions
source /opt/yara/scripts/common.sh

generate_weekly_report() {
    log_section "Generating Weekly Security Report"
    
    # Configuration
    WEEK_START=$(date -d "7 days ago" "+%Y-%m-%d")
    WEEK_END=$(date "+%Y-%m-%d")
    WEEK_START_FORMATTED=$(date -d "7 days ago" "+%b %d")
    WEEK_END_FORMATTED=$(date "+%b %d, %Y")
    WEEK_LABEL="${WEEK_START_FORMATTED} - ${WEEK_END_FORMATTED}"
    
    # Get Wazuh Agent ID
    AGENT_ID=$(cat /var/ossec/etc/client.keys 2>/dev/null | head -1 | awk '{print $1}' || echo "Unknown")
    
    # Weekly metrics
    FILES_CHANGED_WEEK="0"
    if [[ -f /var/ossec/logs/ossec.log ]]; then
        for i in {0..6}; do
            CHECK_DATE=$(date -d "$i days ago" +%Y/%m/%d)
            DAILY_CHANGES=$(grep "$CHECK_DATE" /var/ossec/logs/ossec.log 2>/dev/null | grep -c "Integrity checksum changed\|New file added\|modified\|deleted" | tr -d '\n') || DAILY_CHANGES=0
            FILES_CHANGED_WEEK=$((FILES_CHANGED_WEEK + DAILY_CHANGES))
        done
    fi
    
    # YARA scans triggered this week
    YARA_SCANS_WEEK="0"
    if [[ -f "$YARA_LOGS_DIR/yara_active_response.log" ]]; then
        YARA_SCANS_WEEK=$(find "$YARA_LOGS_DIR" -name "*.log" -mtime -7 -exec grep -c "Starting YARA scan" {} \; 2>/dev/null | awk '{sum+=$1} END {print sum+0}') || YARA_SCANS_WEEK=0
    fi
    
    # Threat detections this week
    WEEKLY_DETECTIONS="0"
    if [[ -f "$YARA_LOGS_DIR/yara_active_response.log" ]]; then
        for i in {0..6}; do
            CHECK_DATE=$(date -d "$i days ago" +%Y-%m-%d)
            DAILY_THREATS=$(grep "$CHECK_DATE.*THREAT DETECTED" "$YARA_LOGS_DIR/yara_active_response.log" 2>/dev/null | wc -l | tr -d '\n' || echo "0")
            WEEKLY_DETECTIONS=$((WEEKLY_DETECTIONS + DAILY_THREATS))
        done
    fi
    
    # System metrics
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}' | cut -d'.' -f1 || echo "0")
    MEM_USAGE=$(free | grep Mem | awk '{printf "%.1f", ($3/$2) * 100.0}' || echo "0")
    DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//' || echo "0")
    
    # Quarantine count
    QUARANTINE_TOTAL=$(ls -1 "$QUARANTINE_DIR" 2>/dev/null | wc -l || echo "0")
    
    # Determine overall health
    HEALTH_STATUS="HEALTHY"
    HEALTH_SCORE=100
    [[ ${CPU_USAGE:-0} -gt 80 ]] && HEALTH_SCORE=$((HEALTH_SCORE - 20))
    [[ ${MEM_USAGE%.*} -gt 80 ]] && HEALTH_SCORE=$((HEALTH_SCORE - 20))
    [[ ${DISK_USAGE} -gt 80 ]] && HEALTH_SCORE=$((HEALTH_SCORE - 20))
    [[ ${WEEKLY_DETECTIONS} -gt 10 ]] && HEALTH_SCORE=$((HEALTH_SCORE - 10))
    
    if [[ $HEALTH_SCORE -ge 80 ]]; then
        HEALTH_STATUS="EXCELLENT"
        HEALTH_COLOR="#28a745"
    elif [[ $HEALTH_SCORE -ge 60 ]]; then
        HEALTH_STATUS="GOOD"
        HEALTH_COLOR="#17a2b8"
    else
        HEALTH_STATUS="WARNING"
        HEALTH_COLOR="#ffc107"
    fi
    
    # Create HTML report
    TEMP_HTML="/tmp/weekly_report_$(date +%Y%m%d_%H%M%S).html"
    create_html_header "Weekly Security Report" "weekly_report_html.sh" "13.1" > "$TEMP_HTML"
    
    cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">📊 Weekly Summary (${WEEK_LABEL})</h2>
</div>

<div class="stats-grid">
<div class="stat-row">
<div class="stat-card">
<p class="stat-value">📁 ${FILES_CHANGED_WEEK}</p>
<p class="stat-label">Files Changed</p>
</div>
<div class="stat-card">
<p class="stat-value">🔍 ${YARA_SCANS_WEEK}</p>
<p class="stat-label">YARA Scans</p>
</div>
<div class="stat-card">
<p class="stat-value">⚠️ ${WEEKLY_DETECTIONS}</p>
<p class="stat-label">Threats Detected</p>
</div>
</div>
</div>

<div class="section-header">
<h2 class="section-title">🛡️ System Status</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>Component</th><th>Status</th><th>Details</th></tr>
EOF

    # Get system information like health check
    local yara_version=$(yara --version 2>/dev/null | head -1 || echo "Not installed")
    local rules_count=$(count_yara_rules)
    local wazuh_status=$(check_wazuh_status)
    local wazuh_agent_id=$(get_wazuh_agent_id)
    local wazuh_version=$(/var/ossec/bin/wazuh-control info 2>/dev/null | grep -i version | cut -d'"' -f2 || echo "Unknown")
    
    cat >> "$TEMP_HTML" << EOF
<tr><td>🚀 YARA Engine</td><td><span class="badge badge-success">✅ Active</span></td><td>${yara_version}</td></tr>
<tr><td>🛡️ Wazuh Agent</td><td><span class="badge $([ "$wazuh_status" = "Running" ] && echo "badge-success" || echo "badge-danger")">$([ "$wazuh_status" = "Running" ] && echo "✅" || echo "❌") ${wazuh_status}</span></td><td>Version: ${wazuh_version} | Agent ID: ${wazuh_agent_id}</td></tr>
<tr><td>📚 Rules Database</td><td><span class="badge badge-success">✅ Loaded</span></td><td>${rules_count} rules active</td></tr>
<tr><td>📁 FIM Monitoring</td><td><span class="badge badge-success">✅ Active</span></td><td>${FILES_CHANGED_WEEK} changes this week</td></tr>
<tr><td>🔒 Quarantine System</td><td><span class="badge $([ ${QUARANTINE_TOTAL} -gt 0 ] && echo "badge-warning" || echo "badge-success")">$([ ${QUARANTINE_TOTAL} -gt 0 ] && echo "⚠️" || echo "✅") $([ ${QUARANTINE_TOTAL} -gt 0 ] && echo "Files Isolated" || echo "Clean")</span></td><td>${QUARANTINE_TOTAL} files in quarantine</td></tr>
<tr><td>📧 Email Notifications</td><td><span class="badge badge-success">✅ Enabled</span></td><td>Sending to: ${EMAIL_TO}</td></tr>
</table>
</div>

<div class="section-header">
<h2 class="section-title">💻 System Performance</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>📊 Metric</th><th>📈 Current Value</th><th>🎯 Status</th></tr>
<tr>
    <td>CPU Usage</td>
    <td>${CPU_USAGE}%</td>
    <td style="color: $([ ${CPU_USAGE} -gt 80 ] && echo '#dc3545' || echo '#28a745');">$([ ${CPU_USAGE} -gt 80 ] && echo '⚠️ High' || echo '✅ Normal')</td>
</tr>
<tr>
    <td>Memory Usage</td>
    <td>${MEM_USAGE}%</td>
    <td style="color: $([ ${MEM_USAGE%.*} -gt 80 ] && echo '#dc3545' || echo '#28a745');">$([ ${MEM_USAGE%.*} -gt 80 ] && echo '⚠️ High' || echo '✅ Normal')</td>
</tr>
<tr>
    <td>Disk Usage</td>
    <td>${DISK_USAGE}%</td>
    <td style="color: $([ ${DISK_USAGE} -gt 80 ] && echo '#dc3545' || echo '#28a745');">$([ ${DISK_USAGE} -gt 80 ] && echo '⚠️ High' || echo '✅ Normal')</td>
</tr>
<tr>
    <td>YARA Rules Active</td>
    <td>$(count_yara_rules)</td>
    <td style="color: #28a745;">✅ Loaded</td>
</tr>
</table>
</div>

<div class="section-header">
<h2 class="section-title">🛡️ Security Status</h2>
</div>
<div class="info-box">
EOF
    
    # Threat details
    if [[ "$WEEKLY_DETECTIONS" -gt 0 ]]; then
        echo "<div style='background: #fff3cd; padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107;'>" >> "$TEMP_HTML"
        echo "<strong>⚠️ Threats Detected This Week:</strong>" >> "$TEMP_HTML"
        echo "<ul style='margin: 10px 0;'>" >> "$TEMP_HTML"
        
        # Get recent threats
        grep "THREAT DETECTED" "$YARA_LOGS_DIR/yara_active_response.log" 2>/dev/null | tail -5 | while read -r line; do
            threat_info=$(echo "$line" | sed 's/.*THREAT DETECTED: //')
            echo "<li>$threat_info</li>" >> "$TEMP_HTML"
        done
        
        echo "</ul></div>" >> "$TEMP_HTML"
    else
        echo "<div style='background: #c6f7d5; padding: 15px; border-radius: 8px; border-left: 4px solid #48bb78;'>" >> "$TEMP_HTML"
        echo "<strong>✅ No Active Threats Detected This Week</strong>" >> "$TEMP_HTML"
        echo "<p style='margin: 5px 0 0 0; color: #22543d;'>All systems operating normally with no malware detections.</p>" >> "$TEMP_HTML"
        echo "</div>" >> "$TEMP_HTML"
    fi
    
    # Quarantine details - Enhanced with threat descriptions like health check
    if [[ ${QUARANTINE_TOTAL} -gt 0 ]]; then
        echo "<br><div class='alert alert-warning'>" >> "$TEMP_HTML"
        echo "<strong>⚠️ ${QUARANTINE_TOTAL} files in quarantine</strong>" >> "$TEMP_HTML"
        echo "</div>" >> "$TEMP_HTML"
        echo "<table class='data-table'>" >> "$TEMP_HTML"
        echo "<tr><th>📁 File Name</th><th>🚨 Threat Type</th><th>🕒 Detection Time</th></tr>" >> "$TEMP_HTML"
        
        # Get infected files with details like health check report
        if [[ ${QUARANTINE_TOTAL} -gt 0 ]]; then
            infected_files=$(find "$QUARANTINE_DIR" -type f -mtime -7 -exec basename {} \; 2>/dev/null | head -10)
            while IFS= read -r file; do
                if [[ -n "$file" ]]; then
                    local full_path="$QUARANTINE_DIR/$file"
                    local detect_time=$(stat -c %y "$full_path" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
                    local threat_type="Unknown"
                    
                    # Extract threat name from filename (same logic as health check)
                    if [[ "$file" =~ \.(.*)\.[0-9]{8}_[0-9]{6}$ ]]; then
                        local extracted_threat="${BASH_REMATCH[1]}"
                        extracted_threat=$(echo "$file" | rev | cut -d'.' -f2 | rev)
                        if [[ -n "$extracted_threat" ]] && [[ "$extracted_threat" != "*" ]]; then
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
                    
                    # Check for EICAR with grep
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
        fi
        
        echo "</table>" >> "$TEMP_HTML"
    fi
    
    echo "</div>" >> "$TEMP_HTML"
    
    # Add recommendations
    cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">📋 Recommendations</h2>
</div>
<div class="info-box">
<ul style="margin: 0; padding-left: 20px;">
EOF
    
    # Dynamic recommendations based on metrics
    if [[ ${CPU_USAGE} -gt 80 ]]; then
        echo "<li>⚠️ High CPU usage detected. Consider reviewing active processes and optimizing YARA scan schedules.</li>" >> "$TEMP_HTML"
    fi
    
    if [[ ${DISK_USAGE} -gt 80 ]]; then
        echo "<li>⚠️ Disk usage is high. Consider cleaning old logs or increasing disk space.</li>" >> "$TEMP_HTML"
    fi
    
    if [[ ${WEEKLY_DETECTIONS} -gt 0 ]]; then
        echo "<li>🔍 Review quarantined files and investigate infection vectors.</li>" >> "$TEMP_HTML"
    fi
    
    if [[ ${FILES_CHANGED_WEEK} -gt 100 ]]; then
        echo "<li>📁 High number of file changes detected. Review FIM alerts for unusual activity.</li>" >> "$TEMP_HTML"
    fi
    
    # Always show these
    echo "<li>✅ Continue monitoring system health and security events.</li>" >> "$TEMP_HTML"
    echo "<li>📊 Review detailed daily reports for trend analysis.</li>" >> "$TEMP_HTML"
    echo "</ul></div>" >> "$TEMP_HTML"
    
    # Add footer
    create_html_footer >> "$TEMP_HTML"
    
    # Send email
    send_html_email "[YARA-Wazuh] Weekly Report - ${WEEK_LABEL}" "$TEMP_HTML"
    
    # Keep a copy for debugging
    cp "$TEMP_HTML" "/tmp/last_weekly_report.html" 2>/dev/null
    
    # Clean up
    rm -f "$TEMP_HTML"
    
    log_info "[OK] Weekly report generated and sent"
}

# Main execution
generate_weekly_report
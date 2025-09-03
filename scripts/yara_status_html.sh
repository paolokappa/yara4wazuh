#!/bin/bash
# YARA-Wazuh Status Report - HTML Email Version
# v13.0 - Using common header/footer functions

# Source common functions
source /opt/yara/scripts/common.sh

generate_status_report() {
    log_section "Generating YARA-Wazuh Status Report"
    
    # Get Wazuh Agent ID and Version
    AGENT_ID=$(cat /var/ossec/etc/client.keys 2>/dev/null | head -1 | awk '{print $1}' || echo "Unknown")
    WAZUH_VERSION=$(/var/ossec/bin/wazuh-control info 2>/dev/null | grep -i version | cut -d'"' -f2 || echo "Unknown")
    AGENT_NAME=$(hostname)
    
    # System Uptime
    UPTIME=$(uptime -p 2>/dev/null | sed 's/up //' || uptime | awk -F'up' '{print $2}' | awk -F',' '{print $1}' | xargs || echo "N/A")
    
    # YARA Status
    if command -v yara >/dev/null 2>&1; then
        YARA_STATUS="OPERATIONAL"
        YARA_VERSION=$(yara --version 2>/dev/null || echo "Unknown")
        YARA_STATUS_COLOR="#48bb78"
    else
        YARA_STATUS="NOT INSTALLED"
        YARA_VERSION="N/A"
        YARA_STATUS_COLOR="#f56565"
    fi
    
    # Rules Status
    if [[ -d "$YARA_RULES_DIR" ]]; then
        RULES_STATUS="CONFIGURED"
        RULES_COUNT=$(count_yara_rules)
        RULES_FILES=$(find "$YARA_RULES_DIR" -type f \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null | wc -l || echo "0")
        RULES_STATUS_COLOR="#48bb78"
    else
        RULES_STATUS="NOT CONFIGURED"
        RULES_COUNT="0"
        RULES_FILES="0"
        RULES_STATUS_COLOR="#f56565"
    fi
    
    # Wazuh Status
    if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
        WAZUH_STATUS="ACTIVE"
        WAZUH_STATUS_COLOR="#48bb78"
    else
        WAZUH_STATUS="INACTIVE"
        WAZUH_STATUS_COLOR="#f56565"
    fi
    
    # FIM Status
    FIM_STATUS="DISABLED"
    FIM_STATUS_COLOR="#f56565"
    if [[ -f /var/ossec/etc/ossec.conf ]]; then
        if grep -q '<syscheck>.*<disabled>no</disabled>' /var/ossec/etc/ossec.conf 2>/dev/null || grep -q '<disabled>no</disabled>' /var/ossec/etc/ossec.conf 2>/dev/null; then
            FIM_STATUS="ENABLED"
            FIM_STATUS_COLOR="#48bb78"
        fi
    fi
    
    # Quarantine Stats
    QUARANTINE_COUNT=$(ls -1 "$QUARANTINE_DIR" 2>/dev/null | wc -l || echo "0")
    
    # Recent Activity
    RECENT_SCANS="0"
    RECENT_DETECTIONS="0"
    if [[ -f "$YARA_LOGS_DIR/yara_active_response.log" ]]; then
        RECENT_SCANS=$(grep -c "Starting YARA scan" "$YARA_LOGS_DIR/yara_active_response.log" 2>/dev/null) || RECENT_SCANS=0
        RECENT_DETECTIONS=$(grep -c "THREAT DETECTED" "$YARA_LOGS_DIR/yara_active_response.log" 2>/dev/null) || RECENT_DETECTIONS=0
    fi
    
    # System Resource Usage
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}' | cut -d'.' -f1 || echo "0")
    MEM_USAGE=$(free | grep Mem | awk '{printf "%.1f", ($3/$2) * 100.0}' || echo "0")
    DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//' || echo "0")
    
    # Create HTML report
    TEMP_HTML="/tmp/yara_status_$(date +%Y%m%d_%H%M%S).html"
    create_html_header "YARA-Wazuh Status Report" "yara_status_html.sh" "13.1" > "$TEMP_HTML"
    
    cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">🛡️ Security Components Status</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>Component</th><th>Status</th><th>Details</th></tr>
<tr>
    <td>🔍 YARA Engine</td>
    <td style="color: ${YARA_STATUS_COLOR}; font-weight: bold;">${YARA_STATUS}</td>
    <td>Version: ${YARA_VERSION}</td>
</tr>
<tr>
    <td>📚 YARA Rules</td>
    <td style="color: ${RULES_STATUS_COLOR}; font-weight: bold;">${RULES_STATUS}</td>
    <td>${RULES_COUNT} rules in ${RULES_FILES} files</td>
</tr>
<tr>
    <td>🛡️ Wazuh Agent</td>
    <td style="color: ${WAZUH_STATUS_COLOR}; font-weight: bold;">${WAZUH_STATUS}</td>
    <td>Version: ${WAZUH_VERSION} | Agent ID: ${AGENT_ID}</td>
</tr>
<tr>
    <td>👁️ FIM (File Integrity)</td>
    <td style="color: ${FIM_STATUS_COLOR}; font-weight: bold;">${FIM_STATUS}</td>
    <td>Syscheck monitoring</td>
</tr>
<tr>
    <td>🔒 Quarantine</td>
    <td style="color: #17a2b8; font-weight: bold;">${QUARANTINE_COUNT} FILES</td>
    <td>Isolated threats</td>
</tr>
</table>
</div>

<div class="section-header">
<h2 class="section-title">📊 System Information</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>Property</th><th>Value</th></tr>
<tr><td>🖥️ Hostname</td><td>${AGENT_NAME}</td></tr>
<tr><td>⏱️ Uptime</td><td>${UPTIME}</td></tr>
<tr><td>💻 CPU Usage</td><td>${CPU_USAGE}%</td></tr>
<tr><td>💾 Memory Usage</td><td>${MEM_USAGE}%</td></tr>
<tr><td>💿 Disk Usage</td><td>${DISK_USAGE}%</td></tr>
</table>
</div>

<div class="section-header">
<h2 class="section-title">⚡ Recent Activity</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>Metric</th><th>Count</th></tr>
<tr><td>🔍 Total YARA Scans</td><td>${RECENT_SCANS}</td></tr>
<tr><td>⚠️ Threats Detected</td><td style="color: $([ ${RECENT_DETECTIONS} -gt 0 ] && echo '#dc3545' || echo '#28a745'); font-weight: bold;">${RECENT_DETECTIONS}</td></tr>
<tr><td>🔒 Files Quarantined</td><td>${QUARANTINE_COUNT}</td></tr>
</table>
EOF
    
    # Add recent detections if any
    if [[ ${RECENT_DETECTIONS} -gt 0 ]] && [[ -f "$YARA_LOGS_DIR/yara_active_response.log" ]]; then
        echo "<br><div style='background: #fff3cd; padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107;'>" >> "$TEMP_HTML"
        echo "<strong>⚠️ Recent Threat Detections:</strong>" >> "$TEMP_HTML"
        echo "<ul style='margin: 10px 0; list-style: none; padding-left: 10px;'>" >> "$TEMP_HTML"
        
        grep "THREAT DETECTED" "$YARA_LOGS_DIR/yara_active_response.log" 2>/dev/null | tail -3 | while read -r line; do
            timestamp=$(echo "$line" | sed 's/^\[\([^]]*\)\].*/\1/')
            threat=$(echo "$line" | sed 's/.*THREAT DETECTED: //')
            echo "<li style='font-size: 0.9em; margin: 3px 0;'>• <span style='color: #6c757d;'>$timestamp</span> - $threat</li>" >> "$TEMP_HTML"
        done
        
        echo "</ul></div>" >> "$TEMP_HTML"
    fi
    
    echo "</div>" >> "$TEMP_HTML"
    
    # Add scheduled tasks status
    cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">⏰ Scheduled Tasks</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>Task</th><th>Schedule</th><th>Status</th></tr>
EOF
    
    if [[ -f /etc/cron.d/yara-wazuh ]]; then
        echo "<tr><td>Daily YARA Scan</td><td>02:30 AM</td><td style='color: #28a745;'>✅ Scheduled</td></tr>" >> "$TEMP_HTML"
        echo "<tr><td>Rules Update</td><td>03:00 AM</td><td style='color: #28a745;'>✅ Scheduled</td></tr>" >> "$TEMP_HTML"
        echo "<tr><td>Weekly Report</td><td>Monday 08:00 AM</td><td style='color: #28a745;'>✅ Scheduled</td></tr>" >> "$TEMP_HTML"
        echo "<tr><td>Health Check</td><td>Every 6 hours</td><td style='color: #28a745;'>✅ Scheduled</td></tr>" >> "$TEMP_HTML"
    else
        echo "<tr><td colspan='3' style='color: #dc3545;'>⚠️ No scheduled tasks configured</td></tr>" >> "$TEMP_HTML"
    fi
    
    echo "</table></div>" >> "$TEMP_HTML"
    
    # Overall health assessment
    HEALTH_SCORE=100
    [[ "$YARA_STATUS" != "OPERATIONAL" ]] && HEALTH_SCORE=$((HEALTH_SCORE - 30))
    [[ "$WAZUH_STATUS" != "ACTIVE" ]] && HEALTH_SCORE=$((HEALTH_SCORE - 30))
    [[ ${RULES_COUNT} -eq 0 ]] && HEALTH_SCORE=$((HEALTH_SCORE - 20))
    [[ ${CPU_USAGE} -gt 80 ]] && HEALTH_SCORE=$((HEALTH_SCORE - 10))
    [[ ${DISK_USAGE} -gt 80 ]] && HEALTH_SCORE=$((HEALTH_SCORE - 10))
    
    if [[ $HEALTH_SCORE -ge 80 ]]; then
        HEALTH_STATUS="EXCELLENT"
        HEALTH_COLOR="#28a745"
        HEALTH_ICON="✅"
    elif [[ $HEALTH_SCORE -ge 60 ]]; then
        HEALTH_STATUS="GOOD"
        HEALTH_COLOR="#17a2b8"
        HEALTH_ICON="👍"
    elif [[ $HEALTH_SCORE -ge 40 ]]; then
        HEALTH_STATUS="WARNING"
        HEALTH_COLOR="#ffc107"
        HEALTH_ICON="⚠️"
    else
        HEALTH_STATUS="CRITICAL"
        HEALTH_COLOR="#dc3545"
        HEALTH_ICON="❌"
    fi
    
    cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">📈 Overall Health Assessment</h2>
</div>
<div class="info-box">
    <div style="text-align: center; padding: 20px;">
        <div style="display: inline-block; background: ${HEALTH_COLOR}; color: white; padding: 15px 30px; border-radius: 30px; font-size: 24px; font-weight: bold;">
            ${HEALTH_ICON} System Health: ${HEALTH_STATUS} (${HEALTH_SCORE}%)
        </div>
    </div>
EOF
    
    # Add recommendations if needed
    if [[ $HEALTH_SCORE -lt 80 ]]; then
        echo "<br><strong>📋 Recommendations:</strong><ul style='margin: 10px 0;'>" >> "$TEMP_HTML"
        [[ "$YARA_STATUS" != "OPERATIONAL" ]] && echo "<li>🔧 Install or fix YARA engine</li>" >> "$TEMP_HTML"
        [[ "$WAZUH_STATUS" != "ACTIVE" ]] && echo "<li>🔧 Start Wazuh agent service</li>" >> "$TEMP_HTML"
        [[ ${RULES_COUNT} -eq 0 ]] && echo "<li>📥 Download YARA rules</li>" >> "$TEMP_HTML"
        [[ ${CPU_USAGE} -gt 80 ]] && echo "<li>⚠️ High CPU usage - review active processes</li>" >> "$TEMP_HTML"
        [[ ${DISK_USAGE} -gt 80 ]] && echo "<li>💾 Low disk space - clean up logs or expand storage</li>" >> "$TEMP_HTML"
        echo "</ul>" >> "$TEMP_HTML"
    fi
    
    echo "</div>" >> "$TEMP_HTML"
    
    # Add footer
    create_html_footer >> "$TEMP_HTML"
    
    # Send email
    send_html_email "[YARA-Wazuh] Status Report - ${AGENT_NAME}" "$TEMP_HTML"
    
    # Keep a copy for debugging
    cp "$TEMP_HTML" "/tmp/last_status_report.html" 2>/dev/null
    
    # Clean up
    rm -f "$TEMP_HTML"
    
    log_info "[OK] Status report generated and sent"
}

# Main execution
generate_status_report
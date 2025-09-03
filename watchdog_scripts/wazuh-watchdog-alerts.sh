#!/bin/bash
# Wazuh Watchdog Alert HTML Generation - GOLINE Style with Restart Counter

source /usr/local/bin/wazuh-watchdog-email.sh

# Function to get restart count from state file
get_restart_count() {
    local state_file="/var/run/wazuh-watchdog.state"
    local cron_state="/var/run/wazuh-watchdog-cron.state"
    local current_time=$(date +%s)
    local hour_ago=$((current_time - 3600))
    local count=0
    
    # Count from main watchdog state
    if [ -f "$state_file" ]; then
        while IFS=: read -r timestamp _; do
            if [ "$timestamp" -ge "$hour_ago" ]; then
                count=$((count + 1))
            fi
        done < "$state_file"
    fi
    
    # Also check cron state
    if [ -f "$cron_state" ]; then
        while read -r timestamp; do
            if [ "$timestamp" -ge "$hour_ago" ]; then
                count=$((count + 1))
            fi
        done < "$cron_state"
    fi
    
    echo $count
}

# Generate restart alert HTML
generate_restart_alert() {
    local issues="$1"
    local restart_count="${2:-$(get_restart_count)}"
    local status="$3"
    local output_file="/tmp/wazuh-restart-alert.html"
    local hostname=$(hostname -f)
    
    # Calculate restart status color
    local counter_color="#28a745"  # Green for 0-1
    local counter_badge="badge-success"
    if [ $restart_count -ge 2 ]; then
        counter_color="#dc3545"  # Red for limit
        counter_badge="badge-danger"
    elif [ $restart_count -ge 1 ]; then
        counter_color="#ffc107"  # Yellow for warning
        counter_badge="badge-warning"
    fi
    
    {
        if [ "$status" = "success" ]; then
            create_watchdog_html_header "Automatic Restart Successful" "AUTO-RESTART" "#28a745"
        else
            create_watchdog_html_header "Restart Failed - Manual Intervention Required" "CRITICAL" "#dc3545"
        fi
        
        # Restart Counter Section (PROMINENT)
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>🔄 Restart Counter (Last Hour)</h2>"
        echo "</div>"
        echo "<div class='info-box' style='text-align: center; padding: 30px;'>"
        echo "<div style='font-size: 48px; font-weight: bold; color: $counter_color;'>$restart_count / 2</div>"
        echo "<div style='margin-top: 10px;'>"
        echo "<span class='badge $counter_badge' style='font-size: 14px; padding: 8px 16px;'>"
        if [ $restart_count -eq 0 ]; then
            echo "No restarts in last hour"
        elif [ $restart_count -eq 1 ]; then
            echo "1 restart performed - 1 remaining"
        elif [ $restart_count -eq 2 ]; then
            echo "⚠️ LIMIT REACHED - No automatic restarts available"
        else
            echo "❌ LIMIT EXCEEDED - Manual intervention required"
        fi
        echo "</span>"
        echo "</div>"
        echo "</div>"
        
        # Status section
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>📊 Service Status</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        
        if [ "$status" = "success" ]; then
            echo "<div class='alert alert-success'>"
            echo "<strong>✅ Service Status: ACTIVE</strong><br>"
            echo "The Wazuh agent has been successfully restarted and is now operational."
        else
            echo "<div class='alert alert-danger'>"
            echo "<strong>❌ Service Status: FAILED</strong><br>"
            echo "The Wazuh agent could not be restarted. Manual intervention is required immediately."
        fi
        echo "</div>"
        
        # Service information table
        echo "<table class='data-table'>"
        echo "<tr><th>Metric</th><th>Value</th></tr>"
        echo "<tr><td>🛡️ Wazuh Service Status</td><td>$(systemctl is-active wazuh-agent 2>/dev/null || echo 'unknown')</td></tr>"
        
        local components=$(ps aux | grep -E 'wazuh-(agentd|execd|logcollector|modulesd|syscheckd)' | grep -v grep | wc -l)
        echo "<tr><td>📊 Running Components</td><td>$components / 5</td></tr>"
        
        local memory=$(ps aux | grep wazuh-agentd | grep -v grep | awk '{print $6/1024}' | head -1)
        echo "<tr><td>💾 Memory Usage</td><td>${memory:-0} MB</td></tr>"
        
        # Add restart history
        echo "<tr><td>⏰ Last Restart</td><td>$(date '+%H:%M:%S')</td></tr>"
        echo "<tr><td>📅 Date</td><td>$(date '+%Y-%m-%d')</td></tr>"
        echo "</table>"
        echo "</div>"
        
        # Issues detected section
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>📋 Issues Detected</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<div class='alert alert-warning'>"
        echo "<ul style='margin: 10px 0; padding-left: 20px;'>"
        echo "$issues" | while IFS= read -r issue; do
            [ ! -z "$issue" ] && echo "<li>$issue</li>"
        done
        echo "</ul>"
        echo "</div>"
        echo "</div>"
        
        # System metrics
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>📊 System Metrics</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<table class='data-table'>"
        echo "<tr><th>Metric</th><th>Value</th></tr>"
        echo "<tr><td>⚡ Load Average</td><td>$(uptime | awk -F'load average:' '{print $2}')</td></tr>"
        echo "<tr><td>💾 Memory Usage</td><td>$(free -h | grep Mem | awk '{print $3" / "$2}')</td></tr>"
        echo "<tr><td>💿 Disk Usage (/)</td><td>$(df -h / | tail -1 | awk '{print $5}')</td></tr>"
        echo "<tr><td>👤 Active Processes</td><td>$(ps aux | wc -l)</td></tr>"
        echo "</table>"
        echo "</div>"
        
        # Warning if approaching limit
        if [ $restart_count -eq 1 ]; then
            echo "<div class='section-header'>"
            echo "<h2 class='section-title'>⚠️ Warning</h2>"
            echo "</div>"
            echo "<div class='info-box'>"
            echo "<div class='alert alert-warning'>"
            echo "<strong>Approaching Restart Limit!</strong><br>"
            echo "This is restart #$restart_count of 2 allowed per hour.<br>"
            echo "Only 1 automatic restart remaining before manual intervention is required.<br>"
            echo "Please investigate the root cause to prevent service disruption."
            echo "</div>"
            echo "</div>"
        fi
        
        # Action required section for failures or limit reached
        if [ "$status" != "success" ] || [ $restart_count -ge 2 ]; then
            echo "<div class='section-header'>"
            echo "<h2 class='section-title'>⚠️ Action Required</h2>"
            echo "</div>"
            echo "<div class='info-box'>"
            echo "<div class='action-box'>"
            echo "<h3>Manual Intervention Steps:</h3>"
            echo "<ol>"
            echo "<li>Connect to server: <code>ssh root@$hostname</code></li>"
            echo "<li>Check service status: <code>systemctl status wazuh-agent</code></li>"
            echo "<li>Review logs: <code>journalctl -u wazuh-agent -n 50</code></li>"
            echo "<li>Check resources: <code>free -h && df -h</code></li>"
            echo "<li>Restart manually: <code>systemctl restart wazuh-agent</code></li>"
            echo "</ol>"
            echo "</div>"
            echo "</div>"
        fi
        
        # Recent logs
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>📜 Recent Log Entries</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<div class='log-box'>"
        tail -20 /var/log/wazuh-watchdog.log 2>/dev/null | sed 's/</\&lt;/g; s/>/\&gt;/g' || echo "No logs available"
        echo "</div>"
        echo "</div>"
        
        create_watchdog_html_footer
    } > "$output_file"
    
    echo "$output_file"
}

# Generate limit exceeded alert HTML
generate_limit_alert() {
    local restart_count="${1:-$(get_restart_count)}"
    local output_file="/tmp/wazuh-limit-alert.html"
    local hostname=$(hostname -f)
    
    {
        create_watchdog_html_header "Restart Limit Exceeded - Manual Intervention Required" "CRITICAL" "#dc3545"
        
        # Big restart counter
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>🔄 Restart Counter Status</h2>"
        echo "</div>"
        echo "<div class='info-box' style='text-align: center; padding: 30px; background: #fed7d7;'>"
        echo "<div style='font-size: 64px; font-weight: bold; color: #dc3545;'>"
        echo "⚠️ $restart_count / 2"
        echo "</div>"
        echo "<div style='margin-top: 10px; font-size: 18px; color: #742a2a;'>"
        echo "<strong>RESTART LIMIT EXCEEDED</strong>"
        echo "</div>"
        echo "<div style='margin-top: 10px;'>"
        echo "<span class='badge badge-danger' style='font-size: 14px; padding: 8px 16px;'>"
        echo "Automatic restarts disabled - Manual intervention required"
        echo "</span>"
        echo "</div>"
        echo "</div>"
        
        # Critical alert section
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>🚨 Critical Alert</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<div class='alert alert-danger'>"
        echo "<strong>Service Protection Activated</strong><br><br>"
        echo "The Wazuh agent has been restarted <strong>$restart_count times</strong> in the last hour.<br>"
        echo "To prevent system instability, automatic restarts have been disabled.<br><br>"
        echo "<strong>Next Steps:</strong>"
        echo "<ul style='margin: 10px 0; padding-left: 20px;'>"
        echo "<li>Investigate the root cause immediately</li>"
        echo "<li>Fix the underlying issue</li>"
        echo "<li>Manually restart the service when ready</li>"
        echo "<li>Monitor for stability after manual restart</li>"
        echo "</ul>"
        echo "</div>"
        echo "</div>"
        
        # Current status
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>📊 Current Status</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<table class='data-table'>"
        echo "<tr><th>Component</th><th>Status</th></tr>"
        echo "<tr><td>🛡️ Wazuh Agent Service</td><td style='color: #dc3545; font-weight: bold;'>$(systemctl is-active wazuh-agent)</td></tr>"
        echo "<tr><td>🔄 Automatic Restarts</td><td style='color: #dc3545; font-weight: bold;'>DISABLED</td></tr>"
        echo "<tr><td>⏰ Limit Reset In</td><td>$(( 60 - (($(date +%M) % 60)) )) minutes</td></tr>"
        echo "<tr><td>⚡ System Load</td><td>$(uptime | awk -F'load average:' '{print $2}')</td></tr>"
        echo "<tr><td>💾 Memory Available</td><td>$(free -h | grep Mem | awk '{print $7}')</td></tr>"
        echo "<tr><td>💿 Disk Space Free</td><td>$(df -h / | tail -1 | awk '{print $4}')</td></tr>"
        echo "</table>"
        echo "</div>"
        
        # Action required
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>⚠️ Immediate Action Required</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<div class='action-box'>"
        echo "<h3>Investigation Steps:</h3>"
        echo "<ol>"
        echo "<li>Connect to the server immediately:<br><code>ssh root@$hostname</code></li>"
        echo "<li>Check service status and errors:<br><code>systemctl status wazuh-agent -l</code></li>"
        echo "<li>Review system logs for errors:<br><code>journalctl -u wazuh-agent -n 100 --no-pager</code></li>"
        echo "<li>Check for resource exhaustion:<br><code>free -h && df -h && ps aux | head -20</code></li>"
        echo "<li>Check for fork bombs or runaway processes:<br><code>ps aux | grep wazuh | wc -l</code></li>"
        echo "<li>Kill any stuck processes:<br><code>pkill -9 -f wazuh</code></li>"
        echo "<li>Attempt manual restart:<br><code>systemctl restart wazuh-agent</code></li>"
        echo "<li>Monitor after restart:<br><code>watch -n 5 'systemctl status wazuh-agent'</code></li>"
        echo "</ol>"
        echo "</div>"
        echo "</div>"
        
        # Restart history
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>📅 Restart History (Last Hour)</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<div class='log-box'>"
        if [ -f /var/run/wazuh-watchdog.state ] || [ -f /var/run/wazuh-watchdog-cron.state ]; then
            echo "Restart timestamps:"
            echo "=================="
            cat /var/run/wazuh-watchdog.state 2>/dev/null | while IFS=: read -r ts _; do
                echo "• $(date -d @$ts '+%H:%M:%S') - Watchdog restart"
            done
            cat /var/run/wazuh-watchdog-cron.state 2>/dev/null | while read -r ts; do
                echo "• $(date -d @$ts '+%H:%M:%S') - Cron restart"
            done
        else
            echo "No restart history available"
        fi
        echo "</div>"
        echo "</div>"
        
        # Watchdog log
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>📜 Watchdog Log (Last 30 lines)</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<div class='log-box'>"
        tail -30 /var/log/wazuh-watchdog.log 2>/dev/null | sed 's/</\&lt;/g; s/>/\&gt;/g' || echo "No logs available"
        echo "</div>"
        echo "</div>"
        
        create_watchdog_html_footer
    } > "$output_file"
    
    echo "$output_file"
}

# Generate test email HTML
generate_test_email() {
    local output_file="/tmp/wazuh-test-alert.html"
    local hostname=$(hostname -f)
    local restart_count=$(get_restart_count)
    
    # Calculate restart status
    local counter_color="#28a745"  # Green for 0
    local counter_status="Healthy - No recent restarts"
    if [ $restart_count -ge 2 ]; then
        counter_color="#dc3545"  # Red for limit
        counter_status="Critical - Limit reached"
    elif [ $restart_count -eq 1 ]; then
        counter_color="#ffc107"  # Yellow for warning
        counter_status="Warning - 1 restart used"
    fi
    
    {
        create_watchdog_html_header "Watchdog System Test" "TEST" "#007bff"
        
        # Restart counter section
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>🔄 Current Restart Counter</h2>"
        echo "</div>"
        echo "<div class='info-box' style='text-align: center; padding: 30px;'>"
        echo "<div style='font-size: 48px; font-weight: bold; color: $counter_color;'>"
        echo "$restart_count / 2"
        echo "</div>"
        echo "<div style='margin-top: 10px;'>"
        echo "<span class='badge' style='background: ${counter_color}22; color: $counter_color; font-size: 14px; padding: 8px 16px;'>"
        echo "$counter_status"
        echo "</span>"
        echo "</div>"
        echo "</div>"
        
        # Test status
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>✅ Email Notification Test</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<div class='alert alert-success'>"
        echo "<strong>Test Successful!</strong><br>"
        echo "This is a test email from the Wazuh watchdog system on <strong>$hostname</strong>.<br>"
        echo "If you receive this email, the notification system is working correctly."
        echo "</div>"
        echo "</div>"
        
        # Configuration
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>⚙️ Current Configuration</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<table class='data-table'>"
        echo "<tr><th>Setting</th><th>Value</th></tr>"
        echo "<tr><td>📧 Alert Email</td><td>soc@goline.ch</td></tr>"
        echo "<tr><td>🔄 Max Restarts per Hour</td><td>2</td></tr>"
        echo "<tr><td>🔄 Current Restart Count</td><td style='color: $counter_color; font-weight: bold;'>$restart_count</td></tr>"
        echo "<tr><td>⏱️ Check Interval</td><td>5 minutes</td></tr>"
        echo "<tr><td>💾 Memory Limit Alert</td><td>3500 MB</td></tr>"
        echo "<tr><td>📊 Service TasksMax</td><td>32768</td></tr>"
        echo "<tr><td>💾 Service MemoryMax</td><td>4 GB</td></tr>"
        echo "</table>"
        echo "</div>"
        
        # Current Wazuh Status
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>📊 Current Wazuh Status</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<table class='data-table'>"
        echo "<tr><th>Component</th><th>Status</th></tr>"
        
        local service_status=$(systemctl is-active wazuh-agent)
        local status_color="#28a745"
        [[ "$service_status" != "active" ]] && status_color="#dc3545"
        
        echo "<tr><td>🛡️ Service Status</td><td style='color: $status_color; font-weight: bold;'>$service_status</td></tr>"
        echo "<tr><td>📊 Running Components</td><td>$(ps aux | grep -E 'wazuh-(agentd|execd|logcollector|modulesd|syscheckd)' | grep -v grep | wc -l) / 5</td></tr>"
        echo "<tr><td>🆔 Agent ID</td><td>$(grep -oE '^[0-9]+' /var/ossec/etc/client.keys 2>/dev/null || echo 'N/A')</td></tr>"
        
        local memory=$(ps aux | grep wazuh-agentd | grep -v grep | awk '{print $6/1024}' | head -1)
        echo "<tr><td>💾 Current Memory Usage</td><td>${memory:-0} MB</td></tr>"
        echo "</table>"
        echo "</div>"
        
        # Monitoring features
        echo "<div class='section-header'>"
        echo "<h2 class='section-title'>📋 Monitoring Features</h2>"
        echo "</div>"
        echo "<div class='info-box'>"
        echo "<table class='data-table'>"
        echo "<tr><th>Feature</th><th>Status</th></tr>"
        echo "<tr><td>🔄 Automatic service restart on failure</td><td><span class='badge badge-success'>ENABLED</span></td></tr>"
        echo "<tr><td>📧 Email alerts for critical events</td><td><span class='badge badge-success'>ENABLED</span></td></tr>"
        echo "<tr><td>🔢 Restart counter tracking</td><td><span class='badge badge-success'>ENABLED</span></td></tr>"
        echo "<tr><td>💾 Memory usage monitoring</td><td><span class='badge badge-success'>ENABLED</span></td></tr>"
        echo "<tr><td>🛡️ Fork bomb prevention</td><td><span class='badge badge-success'>ENABLED</span></td></tr>"
        echo "<tr><td>📊 Component health checks</td><td><span class='badge badge-success'>ENABLED</span></td></tr>"
        echo "<tr><td>🔄 Dual watchdog system (service + cron)</td><td><span class='badge badge-success'>ENABLED</span></td></tr>"
        echo "</table>"
        echo "</div>"
        
        create_watchdog_html_footer
    } > "$output_file"
    
    echo "$output_file"
}

# Export functions
export -f get_restart_count
export -f generate_restart_alert
export -f generate_limit_alert
export -f generate_test_email

#!/bin/bash
# Wazuh Agent Watchdog v2 - With HTML email alerts
# Monitors and restarts Wazuh components if they fail

LOG_FILE="/var/log/wazuh-watchdog.log"
STATE_FILE="/var/run/wazuh-watchdog.state"
MAX_MEMORY_MB=3500  # Max memory in MB before restart
CHECK_INTERVAL=300  # Check every 5 minutes
MAX_RESTARTS_PER_HOUR=2  # Max restarts allowed per hour
ALERT_EMAIL="soc@goline.ch"
HOSTNAME=$(hostname -f)

# Source HTML functions
source /usr/local/bin/wazuh-watchdog-alerts.sh 2>/dev/null
source /usr/local/bin/wazuh-watchdog-email.sh 2>/dev/null

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

send_alert_email() {
    local subject="$1"
    local message="$2"
    local alert_type="${3:-restart}"
    
    case "$alert_type" in
        limit)
            html_file=$(generate_limit_alert "$MAX_RESTARTS_PER_HOUR")
            ;;
        restart_success)
            html_file=$(generate_restart_alert "$message" "$restart_count" "success")
            ;;
        restart_failed)
            html_file=$(generate_restart_alert "$message" "$restart_count" "failed")
            ;;
        *)
            # For other cases, generate a simple restart alert
            html_file=$(generate_restart_alert "$message" "${restart_count:-0}" "unknown")
            ;;
    esac
    
    if [ -f "$html_file" ]; then
        send_watchdog_email "[WAZUH] $subject - $HOSTNAME" "$html_file" "$ALERT_EMAIL"
        rm -f "$html_file"
    fi
}

check_restart_limit() {
    local current_time=$(date +%s)
    local hour_ago=$((current_time - 3600))
    local restart_count=0
    
    if [ -f "$STATE_FILE" ]; then
        while IFS=: read -r timestamp count; do
            if [ "$timestamp" -ge "$hour_ago" ]; then
                restart_count=$((restart_count + 1))
            fi
        done < "$STATE_FILE"
        
        awk -v hour_ago="$hour_ago" '$1 >= hour_ago' "$STATE_FILE" > "${STATE_FILE}.tmp"
        mv "${STATE_FILE}.tmp" "$STATE_FILE"
    fi
    
    if [ $restart_count -ge $MAX_RESTARTS_PER_HOUR ]; then
        log_msg "WARNING: Restart limit reached ($restart_count restarts in last hour)"
        send_alert_email "Wazuh Agent Restart Limit Exceeded" "Limit exceeded" "limit"
        return 1
    fi
    
    echo "$current_time:1" >> "$STATE_FILE"
    return 0
}

check_memory() {
    local pid=$1
    [ -z "$pid" ] && return 1
    
    local mem_kb=$(ps -o rss= -p $pid 2>/dev/null | tr -d ' ')
    [ -z "$mem_kb" ] && return 1
    
    local mem_mb=$((mem_kb / 1024))
    
    if [ $mem_mb -gt $MAX_MEMORY_MB ]; then
        log_msg "WARNING: Process $pid using ${mem_mb}MB (limit: ${MAX_MEMORY_MB}MB)"
        return 1
    fi
    return 0
}

check_wazuh_health() {
    local restart_needed=0
    local issues=""
    
    if ! systemctl is-active --quiet wazuh-agent; then
        log_msg "ERROR: Wazuh agent service is not active"
        issues="Service not active"
        restart_needed=1
    fi
    
    local components=("wazuh-agentd" "wazuh-execd" "wazuh-logcollector" "wazuh-modulesd" "wazuh-syscheckd")
    
    for component in "${components[@]}"; do
        local pid=$(pgrep -f $component)
        
        if [ -z "$pid" ]; then
            log_msg "ERROR: $component is not running"
            issues="${issues}
$component not running"
            restart_needed=1
        else
            if ! check_memory $pid; then
                log_msg "ERROR: $component memory limit exceeded"
                issues="${issues}
$component memory exceeded"
                restart_needed=1
            fi
        fi
    done
    
    local proc_count=$(ps aux | grep -c wazuh)
    if [ $proc_count -gt 100 ]; then
        log_msg "ERROR: Too many Wazuh processes ($proc_count), possible fork issue"
        issues="${issues}
Too many processes: $proc_count"
        restart_needed=1
    fi
    
    if [ $restart_needed -eq 1 ]; then
        if check_restart_limit; then
            log_msg "Restarting Wazuh agent due to health check failure"
            
            pkill -f wazuh- 2>/dev/null
            sleep 2
            pkill -9 -f wazuh- 2>/dev/null
            sleep 1
            
            systemctl restart wazuh-agent
            sleep 10
            
            if systemctl is-active --quiet wazuh-agent; then
                log_msg "Wazuh agent restarted successfully"
                local running_components=$(ps aux | grep -E 'wazuh-(agentd|execd|logcollector|modulesd|syscheckd)' | grep -v grep | wc -l)
                log_msg "Running components after restart: $running_components"
                
                send_alert_email "Wazuh Agent Auto-Restarted" "$issues" "restart_success"
            else
                log_msg "ERROR: Failed to restart Wazuh agent"
                send_alert_email "Wazuh Agent Restart Failed" "$issues" "restart_failed"
            fi
        else
            log_msg "Skipping restart due to limit - manual intervention required"
        fi
    fi
}

# Main loop
log_msg "Wazuh watchdog started (v2 with HTML email alerts)"

while true; do
    check_wazuh_health
    sleep $CHECK_INTERVAL
done

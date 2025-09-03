#!/bin/bash
# Smart cron watchdog with HTML emails

STATE_FILE="/var/run/wazuh-watchdog-cron.state"
MAX_RESTARTS_PER_HOUR=2
ALERT_EMAIL="soc@goline.ch"
HOSTNAME=$(hostname -f)

# Source HTML functions
source /usr/local/bin/wazuh-watchdog-alerts.sh
source /usr/local/bin/wazuh-watchdog-email.sh

# Check if service is active
if systemctl is-active --quiet wazuh-agent; then
    exit 0  # Service is running, nothing to do
fi

# Service is down, check restart limit
current_time=$(date +%s)
hour_ago=$((current_time - 3600))
restart_count=0

if [ -f "$STATE_FILE" ]; then
    # Count recent restarts
    while read -r timestamp; do
        if [ "$timestamp" -ge "$hour_ago" ]; then
            restart_count=$((restart_count + 1))
        fi
    done < "$STATE_FILE"
    
    # Clean old entries
    awk -v hour_ago="$hour_ago" '$1 >= hour_ago' "$STATE_FILE" > "${STATE_FILE}.tmp"
    mv "${STATE_FILE}.tmp" "$STATE_FILE"
fi

if [ $restart_count -ge $MAX_RESTARTS_PER_HOUR ]; then
    # Send alert but don't restart
    echo "Wazuh agent down but restart limit reached ($restart_count/$MAX_RESTARTS_PER_HOUR)"
    
    # Check if we already sent an alert recently
    alert_file="/var/run/wazuh-alert-sent"
    if [ ! -f "$alert_file" ] || [ $(find "$alert_file" -mmin +60 2>/dev/null | wc -l) -gt 0 ]; then
        html_file=$(generate_limit_alert "$restart_count")
        send_watchdog_email "[CRITICAL] Wazuh Agent Down - Manual Intervention Required - $HOSTNAME" "$html_file" "$ALERT_EMAIL"
        rm -f "$html_file"
        touch "$alert_file"
        echo "Alert email sent to $ALERT_EMAIL"
    fi
    exit 1
fi

# Restart the service
echo "Restarting Wazuh agent (attempt $((restart_count + 1))/$MAX_RESTARTS_PER_HOUR)"
systemctl restart wazuh-agent

# Record restart
echo "$current_time" >> "$STATE_FILE"

# Check if restart was successful
sleep 5
if systemctl is-active --quiet wazuh-agent; then
    echo "Wazuh agent restarted successfully"
    issues="Service was down and required restart"
    html_file=$(generate_restart_alert "$issues" "$((restart_count + 1))" "success")
    send_watchdog_email "[AUTO-RESTART] Wazuh Agent Restarted - $HOSTNAME" "$html_file" "$ALERT_EMAIL"
    rm -f "$html_file"
else
    echo "Failed to restart Wazuh agent"
    issues="Service is down and automatic restart failed"
    html_file=$(generate_restart_alert "$issues" "$((restart_count + 1))" "failed")
    send_watchdog_email "[CRITICAL] Wazuh Agent Restart Failed - $HOSTNAME" "$html_file" "$ALERT_EMAIL"
    rm -f "$html_file"
fi

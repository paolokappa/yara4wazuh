#!/bin/bash
# Wazuh Watchdog HTML Email Functions - GOLINE Style

# Source common functions if available
[[ -f /opt/yara/scripts/common.sh ]] && source /opt/yara/scripts/common.sh

# Create HTML header (GOLINE style)
create_watchdog_html_header() {
    local report_title="${1:-Wazuh Agent Watchdog Alert}"
    local alert_type="${2:-INFO}"
    local alert_color="${3:-#003366}"
    
    # Get system information
    local hostname=$(hostname -f)
    local ip_address=$(hostname -I | awk '{print $1}')
    local current_date=$(date '+%B %d, %Y')
    local current_time=$(date '+%H:%M:%S %Z')
    local os_name=$(grep "^PRETTY_NAME" /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)
    
    cat << HTML
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${report_title} - GOLINE SA</title>
<style>
body { margin: 0; padding: 0; background: #f4f7fa; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
.email-container { max-width: 720px; margin: 0 auto; background: #ffffff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.header-table { background: ${alert_color}; }
.logo-cell { padding: 40px 30px 30px 30px; text-align: center; }
.company-name { font-size: 34px; font-weight: 700; color: #ffffff; margin: 0; letter-spacing: 1px; }
.subtitle { font-size: 16px; color: #b3d9ff; margin: 8px 0 0 0; font-weight: 300; }
.system-info { background: #f8f9fa; padding: 20px 30px; border-bottom: 1px solid #e0e0e0; }
.info-grid { display: table; width: 100%; }
.info-cell { display: table-cell; padding: 5px 10px; font-size: 13px; color: #4a5568; }
.info-label { font-weight: 600; color: #2d3748; }
.info-value { color: #4a5568; }
.emoji { font-size: 16px; margin-right: 5px; }
.section-header { background: #f8f9fa; padding: 15px 30px; border-left: 4px solid ${alert_color}; }
.section-title { font-size: 18px; font-weight: 600; color: #003366; margin: 0; }
.info-box { padding: 25px 30px; border: 1px solid #e9ecef; border-top: none; }
.data-table { width: 100%; border-collapse: collapse; margin: 15px 0; }
.data-table th { background: #003366; color: #ffffff; padding: 12px 15px; text-align: left; font-weight: 600; }
.data-table td { padding: 10px 15px; border: 1px solid #e0e0e0; }
.data-table tr:nth-child(even) { background-color: #f8f9fa; }
.data-table tr:hover { background-color: #e9ecef; }
.alert { padding: 16px; border-radius: 8px; margin: 20px 0; }
.alert-success { background-color: #c6f7d5; border-left: 4px solid #48bb78; color: #22543d; }
.alert-warning { background-color: #fed7aa; border-left: 4px solid #f59e0b; color: #92400e; }
.alert-danger { background-color: #fed7d7; border-left: 4px solid #fc8181; color: #742a2a; }
.alert-info { background-color: #bee3f8; border-left: 4px solid #4299e1; color: #2c5282; }
.footer-table { background: #003366; }
.footer-content { padding: 30px; text-align: center; }
.footer-text { color: #b3d9ff; font-size: 14px; line-height: 1.6; margin: 0; }
.footer-link { color: #66b3ff; text-decoration: none; }
.badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; }
.badge-success { background: #c6f7d5; color: #22543d; }
.badge-warning { background: #fed7aa; color: #92400e; }
.badge-danger { background: #fed7d7; color: #742a2a; }
.badge-info { background: #bee3f8; color: #2c5282; }
.metric-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #e9ecef; }
.metric-row:last-child { border-bottom: none; }
.metric-label { font-weight: 600; color: #495057; }
.metric-value { color: #212529; }
.log-box { background-color: #2d3436; color: #dfe6e9; padding: 15px; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 12px; margin: 20px 0; max-height: 300px; overflow-y: auto; }
.action-box { background: #fff3cd; padding: 20px; border-radius: 8px; border-left: 4px solid #ffc107; margin: 20px 0; }
.action-box h3 { color: #856404; margin-top: 0; }
code { background-color: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
</style>
</head>
<body>
<div class="email-container">
<table class="header-table" width="100%" cellpadding="0" cellspacing="0">
<tr><td class="logo-cell">
<h1 class="company-name">GOLINE SA</h1>
<p class="subtitle">Security Operations Center</p>
<div style="margin-top: 15px; padding: 8px 16px; background: rgba(255,255,255,0.1); border-radius: 20px; display: inline-block;">
<span style="color: #ffffff; font-size: 14px; font-weight: 600;">🛡️ Wazuh Agent Watchdog | ${alert_type}</span>
</div>
</td></tr>
</table>
<div class="system-info">
<table width="100%" cellpadding="0" cellspacing="0">
<tr>
<td width="50%">
<span class="emoji">💻</span><span class="info-label">Hostname:</span> <span class="info-value">${hostname}</span><br>
<span class="emoji">🌐</span><span class="info-label">IP Address:</span> <span class="info-value">${ip_address}</span><br>
<span class="emoji">📋</span><span class="info-label">Report:</span> <span class="info-value">${report_title}</span>
</td>
<td width="50%">
<span class="emoji">🔧</span><span class="info-label">Component:</span> <span class="info-value">Wazuh Watchdog v2.0</span><br>
<span class="emoji">💻</span><span class="info-label">OS:</span> <span class="info-value">${os_name}</span><br>
<span class="emoji">📅</span><span class="info-label">Generated:</span> <span class="info-value">${current_date} ${current_time}</span>
</td>
</tr>
</table>
</div>
HTML
}

# Create HTML footer (GOLINE style)
create_watchdog_html_footer() {
    cat << 'HTML'
<table class="footer-table" width="100%" cellpadding="0" cellspacing="0">
<tr><td class="footer-content">
<p class="footer-text">
<strong>GOLINE SA</strong><br>
Via Croce Campagna 2<br>
6855 Stabio, TI, Switzerland<br>
Phone: +41 91 2507650 | Email: soc@goline.ch<br>
<a href="https://www.goline.ch" class="footer-link">www.goline.ch</a>
</p>
</td></tr>
</table>
</div>
</body>
</html>
HTML
}

# Function to send HTML email
send_watchdog_email() {
    local subject="$1"
    local html_file="$2"
    local recipient="${3:-soc@goline.ch}"
    local hostname=$(hostname -f)
    
    # Create email with HTML content
    {
        echo "To: $recipient"
        echo "From: wazuh-watchdog@$hostname"
        echo "Subject: $subject"
        echo "MIME-Version: 1.0"
        echo "Content-Type: text/html; charset=UTF-8"
        echo ""
        cat "$html_file"
    } | sendmail -t
    
    echo "HTML email sent to $recipient"
}

# Export functions for use in other scripts
export -f create_watchdog_html_header
export -f create_watchdog_html_footer
export -f send_watchdog_email

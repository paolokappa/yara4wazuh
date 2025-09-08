#!/bin/bash
# YARA4WAZUH Common Functions and Variables
# Version: 13.7
# Build: 2024-09-03
# Company: GOLINE SA - www.goline.ch
# This file contains shared functions and variables used by all YARA4WAZUH scripts

# Directories (only set if not already defined)
[[ -z "$YARA_BASE_DIR" ]] && readonly YARA_BASE_DIR="/opt/yara"
[[ -z "$YARA_RULES_DIR" ]] && readonly YARA_RULES_DIR="${YARA_BASE_DIR}/rules"
[[ -z "$YARA_SCRIPTS_DIR" ]] && readonly YARA_SCRIPTS_DIR="${YARA_BASE_DIR}/scripts"
[[ -z "$YARA_LOGS_DIR" ]] && readonly YARA_LOGS_DIR="/var/log/yara"
[[ -z "$CONFIG_DIR" ]] && readonly CONFIG_DIR="/etc/yara4wazuh"
[[ -z "$QUARANTINE_DIR" ]] && readonly QUARANTINE_DIR="/var/ossec/quarantine"

# Colors (only set if not already defined)
[[ -z "$RED" ]] && readonly RED="\033[0;31m"
[[ -z "$GREEN" ]] && readonly GREEN="\033[0;32m"
[[ -z "$YELLOW" ]] && readonly YELLOW="\033[1;33m"
[[ -z "$BLUE" ]] && readonly BLUE="\033[1;36m"
[[ -z "$NC" ]] && readonly NC="\033[0m"

# Load local configuration if exists
if [[ -f "/opt/yara/config.local" ]]; then
    source /opt/yara/config.local
fi

# Email configuration (use environment vars or defaults)
EMAIL_TO="${EMAIL_TO:-security@example.com}"
EMAIL_FROM_DOMAIN="${EMAIL_FROM_DOMAIN:-example.com}"
EMAIL_FROM="$(hostname)@${EMAIL_FROM_DOMAIN}"

# Logging functions
log_info() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}[INFO]${NC} $*"
}

log_error() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}[ERROR]${NC} $*" >&2
}

log_warning() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}[WARNING]${NC} $*"
}

log_section() {
    echo ""
    echo -e "${BLUE}========== $* ==========${NC}"
}

# Get Wazuh agent ID
get_wazuh_agent_id() {
    if [[ -f /var/ossec/etc/client.keys ]]; then
        awk '{print $1}' /var/ossec/etc/client.keys 2>/dev/null || echo "Unknown"
    else
        echo "Not configured"
    fi
}

# Count YARA rules (returns ACTIVE/VALID rules only)
count_yara_rules() {
    # Return count of rules in optimized file if it exists
    if [[ -f /opt/yara/rules/optimized.yar ]]; then
        grep -c "^rule " /opt/yara/rules/optimized.yar 2>/dev/null || echo "0"
    elif [[ -d /opt/yara/rules ]]; then
        # Otherwise count files as before
        find /opt/yara/rules -maxdepth 1 -type f \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null | wc -l
    else
        echo "0"
    fi
}

# Count rules by category (dynamic)
count_rules_by_pattern() {
    local pattern=$1
    local file="${2:-/opt/yara/rules/optimized.yar}"
    
    if [[ -f "$file" ]]; then
        grep -c "$pattern" "$file" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Get rules summary for display (dynamic)
get_rules_summary() {
    local file="${1:-/opt/yara/rules/optimized.yar}"
    
    if [[ ! -f "$file" ]]; then
        echo "No rules loaded"
        return 1
    fi
    
    # Count major categories
    local total=$(grep -c "^rule " "$file" 2>/dev/null || echo "0")
    local trojan=$(count_rules_by_pattern "Linux_Trojan" "$file")
    local exploit=$(count_rules_by_pattern "Linux_Exploit" "$file") 
    local crypto=$(count_rules_by_pattern "Linux_Cryptominer" "$file")
    local ransom=$(count_rules_by_pattern "Linux_Ransomware" "$file")
    local mirai=$(count_rules_by_pattern "[Mm]irai" "$file")
    local xz=$(count_rules_by_pattern "CVE.2024.3094\|XZ.*[Bb]ackdoor\|xz_util" "$file")
    
    # Build summary string
    local summary="$total rules ("
    local first=true
    
    [[ $trojan -gt 0 ]] && { [[ $first == false ]] && summary+=", "; summary+="${trojan} Trojan"; first=false; }
    [[ $exploit -gt 0 ]] && { [[ $first == false ]] && summary+=", "; summary+="${exploit} Exploit"; first=false; }
    [[ $crypto -gt 0 ]] && { [[ $first == false ]] && summary+=", "; summary+="${crypto} Cryptominer"; first=false; }
    [[ $ransom -gt 0 ]] && { [[ $first == false ]] && summary+=", "; summary+="${ransom} Ransomware"; first=false; }
    [[ $mirai -gt 0 ]] && { [[ $first == false ]] && summary+=", "; summary+="${mirai} Mirai"; first=false; }
    [[ $xz -gt 0 ]] && { [[ $first == false ]] && summary+=", "; summary+="${xz} XZ-backdoor"; first=false; }
    
    summary+=")"
    echo "$summary"
}

# Get complete rules detail with all feeds (dynamic)
get_rules_detail() {
    local file="${1:-/opt/yara/rules/optimized.yar}"
    
    if [[ ! -f "$file" ]]; then
        echo "No rules loaded"
        return 1
    fi
    
    # Count all categories
    local total=$(grep -c "^rule " "$file" 2>/dev/null || echo "0")
    local trojan=$(count_rules_by_pattern "Linux_Trojan" "$file")
    local exploit=$(count_rules_by_pattern "Linux_Exploit" "$file") 
    local crypto=$(count_rules_by_pattern "Linux_Cryptominer" "$file")
    local ransom=$(count_rules_by_pattern "Linux_Ransomware" "$file")
    local rootkit=$(count_rules_by_pattern "Linux_Rootkit" "$file")
    local backdoor=$(count_rules_by_pattern "Linux_Backdoor" "$file")
    local webshell=$(count_rules_by_pattern "Linux_Webshell" "$file")
    local hacktool=$(count_rules_by_pattern "Linux_Hacktool" "$file")
    local virus=$(count_rules_by_pattern "Linux_Virus" "$file")
    
    # Count special threats
    local mirai=$(count_rules_by_pattern "[Mm]irai" "$file")
    local xz=$(count_rules_by_pattern "CVE.2024.3094\|XZ.*[Bb]ackdoor\|xz_util" "$file")
    local pwnkit=$(count_rules_by_pattern "CVE.2021.4034\|PwnKit\|pkexec" "$file")
    local ssh=$(count_rules_by_pattern "SSH\|ssh.*brute\|ssh.*backdoor" "$file")
    
    # Build detailed string with better formatting
    local detail="<strong>$total detection rules</strong><br>"
    detail+="<small>"
    detail+="<strong>Malware:</strong> "
    [[ $trojan -gt 0 ]] && detail+="Trojan:$trojan "
    [[ $exploit -gt 0 ]] && detail+="Exploit:$exploit "
    [[ $crypto -gt 0 ]] && detail+="Cryptominer:$crypto "
    [[ $ransom -gt 0 ]] && detail+="Ransomware:$ransom "
    [[ $rootkit -gt 0 ]] && detail+="Rootkit:$rootkit "
    [[ $backdoor -gt 0 ]] && detail+="Backdoor:$backdoor "
    [[ $webshell -gt 0 ]] && detail+="Webshell:$webshell "
    [[ $hacktool -gt 0 ]] && detail+="Hacktool:$hacktool "
    [[ $virus -gt 0 ]] && detail+="Virus:$virus "
    detail+="<br>"
    detail+="<strong>Critical CVE:</strong> "
    [[ $xz -gt 0 ]] && detail+="CVE-2024-3094(XZ):$xz "
    [[ $pwnkit -gt 0 ]] && detail+="CVE-2021-4034(PwnKit):$pwnkit "
    [[ $mirai -gt 0 ]] && detail+="Mirai:$mirai "
    [[ $ssh -gt 0 ]] && detail+="SSH-Attack:$ssh "
    detail+="<br>"
    detail+="<strong>Sources:</strong> Elastic, Neo23x0, GOLINE"
    detail+="</small>"
    
    echo "$detail"
}

# Get feed sources summary (dynamic)
get_feed_sources() {
    # Count different feed types
    local elastic_count=$(cd /opt/yara/rules && ls Linux_*.yar 2>/dev/null | wc -l)
    local apt_count=$(cd /opt/yara/rules && ls APT_*.yar 2>/dev/null | wc -l)
    local ransom_count=$(cd /opt/yara/rules && ls | grep -i ransom | wc -l)
    local trojan_count=$(cd /opt/yara/rules && ls | grep -i trojan | wc -l)
    local exploit_count=$(cd /opt/yara/rules && ls | grep -i exploit | wc -l)
    local backdoor_count=$(cd /opt/yara/rules && ls | grep -i backdoor | wc -l)
    local webshell_count=$(cd /opt/yara/rules && ls | grep -i webshell | wc -l)
    local malware_count=$(cd /opt/yara/rules && ls | grep -i malware | wc -l)
    local total_files=$(cd /opt/yara/rules && ls *.yar 2>/dev/null | wc -l)
    
    local sources=""
    [[ $elastic_count -gt 0 ]] && sources+="Elastic ($elastic_count), "
    [[ $apt_count -gt 0 ]] && sources+="APT ($apt_count), "
    [[ $ransom_count -gt 0 ]] && sources+="Ransomware ($ransom_count), "
    [[ $trojan_count -gt 0 ]] && sources+="Trojan ($trojan_count), "
    [[ $exploit_count -gt 0 ]] && sources+="Exploit ($exploit_count), "
    [[ $backdoor_count -gt 0 ]] && sources+="Backdoor ($backdoor_count), "
    [[ $webshell_count -gt 0 ]] && sources+="Webshell ($webshell_count), "
    [[ $malware_count -gt 0 ]] && sources+="Malware ($malware_count), "
    sources+="Total: $total_files files"
    
    echo "$sources"
}

# Get rule categories with counts (dynamic)
get_rule_categories() {
    local file="${1:-/opt/yara/rules/optimized.yar}"
    
    if [[ ! -f "$file" ]]; then
        echo "No rules file found"
        return 1
    fi
    
    # Count major categories
    local trojan_count=$(count_rules_by_pattern "Linux_Trojan" "$file")
    local exploit_count=$(count_rules_by_pattern "Linux_Exploit" "$file")
    local crypto_count=$(count_rules_by_pattern "Linux_Cryptominer" "$file")
    local ransom_count=$(count_rules_by_pattern "Linux_Ransomware" "$file")
    local rootkit_count=$(count_rules_by_pattern "Linux_Rootkit" "$file")
    local backdoor_count=$(count_rules_by_pattern "Linux_Backdoor" "$file")
    local webshell_count=$(count_rules_by_pattern "Linux_Webshell" "$file")
    local hacktool_count=$(count_rules_by_pattern "Linux_Hacktool" "$file")
    
    # Count CVE and special threats
    local xz_count=$(count_rules_by_pattern "CVE.2024.3094\|XZ.*[Bb]ackdoor\|xz_util" "$file")
    local pwnkit_count=$(count_rules_by_pattern "CVE.2021.4034\|PwnKit\|pkexec" "$file")
    local mirai_count=$(count_rules_by_pattern "[Mm]irai" "$file")
    local ssh_count=$(count_rules_by_pattern "SSH\|ssh.*brute\|ssh.*backdoor" "$file")
    
    # Output as associative array format
    echo "TROJAN:$trojan_count"
    echo "EXPLOIT:$exploit_count"
    echo "CRYPTOMINER:$crypto_count"
    echo "RANSOMWARE:$ransom_count"
    echo "ROOTKIT:$rootkit_count"
    echo "BACKDOOR:$backdoor_count"
    echo "WEBSHELL:$webshell_count"
    echo "HACKTOOL:$hacktool_count"
    echo "XZ_BACKDOOR:$xz_count"
    echo "PWNKIT:$pwnkit_count"
    echo "MIRAI:$mirai_count"
    echo "SSH_ATTACK:$ssh_count"
}

# Check if Wazuh agent is running
check_wazuh_status() {
    if systemctl is-active --quiet wazuh-agent 2>/dev/null || pgrep -f "ossec-agentd" >/dev/null 2>&1; then
        echo "Running"
    else
        echo "Not Running"
    fi
}

# Safe temporary file creation and cleanup
create_safe_temp_html() {
    # Create temp file in a directory excluded from YARA scans
    local temp_dir="/opt/yara/reports"
    mkdir -p "$temp_dir" 2>/dev/null
    chmod 700 "$temp_dir" 2>/dev/null
    
    local temp_file="${temp_dir}/report_$(date +%Y%m%d_%H%M%S)_$$.html"
    echo "$temp_file"
}

# Clean up temporary HTML files (CRITICAL for avoiding false positives)
cleanup_temp_html() {
    local file="$1"
    if [[ -f "$file" ]]; then
        # Overwrite with zeros before deletion for security
        dd if=/dev/zero of="$file" bs=1 count=$(stat -c%s "$file") 2>/dev/null
        rm -f "$file" 2>/dev/null
        
        # Verify deletion
        if [[ -f "$file" ]]; then
            log_error "CRITICAL: Failed to delete temp file: $file"
            # Force removal
            shred -vfz "$file" 2>/dev/null || rm -rf "$file"
        fi
    fi
}

# Send email with HTML content (auto-detect mail system)
send_html_email() {
    local subject="$1"
    local html_file="$2"
    local cleanup="${3:-yes}"  # Default to cleanup
    local result=0
    
    # Detect which mail system is available
    if command -v sendmail >/dev/null 2>&1; then
        # Use sendmail (works with postfix, sendmail, exim)
        sendmail -t << EOF
To: ${EMAIL_TO}
From: ${EMAIL_FROM}
Subject: ${subject}
Content-Type: text/html; charset=UTF-8
MIME-Version: 1.0

$(cat "${html_file}")
EOF
        result=$?
    elif command -v mail >/dev/null 2>&1; then
        # Use mail command with HTML support
        cat "${html_file}" | mail -a "Content-Type: text/html; charset=UTF-8" \
                                 -s "${subject}" \
                                 "${EMAIL_TO}" 2>/dev/null || \
        # Fallback to basic mail if -a not supported
        cat "${html_file}" | mail -s "${subject}" "${EMAIL_TO}"
        result=$?
    elif command -v ssmtp >/dev/null 2>&1; then
        # Use ssmtp
        {
            echo "To: ${EMAIL_TO}"
            echo "From: ${EMAIL_FROM}"
            echo "Subject: ${subject}"
            echo "Content-Type: text/html; charset=UTF-8"
            echo "MIME-Version: 1.0"
            echo ""
            cat "${html_file}"
        } | ssmtp "${EMAIL_TO}"
        result=$?
    elif command -v msmtp >/dev/null 2>&1; then
        # Use msmtp
        {
            echo "To: ${EMAIL_TO}"
            echo "From: ${EMAIL_FROM}"
            echo "Subject: ${subject}"
            echo "Content-Type: text/html; charset=UTF-8"
            echo "MIME-Version: 1.0"
            echo ""
            cat "${html_file}"
        } | msmtp "${EMAIL_TO}"
        result=$?
    else
        log_warning "No email system found (install postfix, sendmail, ssmtp, or msmtp)"
        result=1
    fi
    
    # CRITICAL: Always cleanup temp HTML files to avoid false positives
    if [[ "$cleanup" == "yes" ]] && [[ -f "$html_file" ]]; then
        cleanup_temp_html "$html_file"
    fi
    
    if [[ $result -eq 0 ]]; then
        log_info "Email sent successfully to ${EMAIL_TO}"
    else
        log_warning "Failed to send email to ${EMAIL_TO}"
    fi
    
    return $result
}

# Create enhanced HTML header for reports
create_html_header() {
    local report_title="${1:-YARA Security Report}"
    local script_name="${2:-$(basename $0)}"
    # Get version dynamically or use provided parameter
    local script_version="${3:-$(get_yara_version)}"
    
    # Project information
    local project_name="Yara4Wazuh"
    # Read version dynamically from VERSION file
    local version_file="/opt/yara/VERSION"
    if [[ -f "$version_file" ]]; then
        local project_version="v$(cat "$version_file" | tr -d '\n')"
    else
        local project_version="v13.8"  # Fallback version
    fi
    
    # Get system information
    local os_name=$(grep "^PRETTY_NAME" /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)
    local kernel_version=$(uname -r)
    local hostname=$(hostname -f)
    local ip_address=$(hostname -I | awk '{print $1}')
    local current_date=$(date '+%B %d, %Y')
    local current_time=$(date '+%H:%M:%S %Z')
    
    cat << EOF
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${report_title} - GOLINE SA</title>
<style>
body { margin: 0; padding: 0; background: #f4f7fa; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
.email-container { max-width: 720px; margin: 0 auto; background: #ffffff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.header-table { background: #003366; }
.logo-cell { padding: 40px 30px 30px 30px; text-align: center; }
.company-name { font-size: 34px; font-weight: 700; color: #ffffff; margin: 0; letter-spacing: 1px; }
.subtitle { font-size: 16px; color: #b3d9ff; margin: 8px 0 0 0; font-weight: 300; }
.system-info { background: #f8f9fa; padding: 20px 30px; border-bottom: 1px solid #e0e0e0; }
.info-grid { display: table; width: 100%; }
.info-row { display: table-row; }
.info-cell { display: table-cell; padding: 5px 10px; font-size: 13px; color: #4a5568; }
.info-label { font-weight: 600; color: #2d3748; }
.info-value { color: #4a5568; }
.emoji { font-size: 16px; margin-right: 5px; }
.section-header { background: #f8f9fa; padding: 15px 30px; border-left: 4px solid #003366; }
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
.footer-table { background: #003366; }
.footer-content { padding: 30px; text-align: center; }
.footer-text { color: #b3d9ff; font-size: 14px; line-height: 1.6; margin: 0; }
.footer-link { color: #66b3ff; text-decoration: none; }
.stats-grid { display: table; width: 100%; padding: 25px 30px; }
.stat-row { display: table-row; }
.stat-card { display: table-cell; background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #e0e0e0; }
.stat-card:not(:last-child) { border-right: none; }
.stat-value { font-size: 32px; font-weight: 700; color: #003366; margin: 0; }
.stat-label { font-size: 14px; color: #6b7280; margin: 5px 0 0 0; }
.badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; }
.badge-success { background: #c6f7d5; color: #22543d; }
.badge-warning { background: #fed7aa; color: #92400e; }
.badge-danger { background: #fed7d7; color: #742a2a; }
.badge-info { background: #bee3f8; color: #2c5282; }
</style>
</head>
<body>
<div class="email-container">
<table class="header-table" width="100%" cellpadding="0" cellspacing="0">
<tr><td class="logo-cell">
<h1 class="company-name">GOLINE SA</h1>
<p class="subtitle">Security Operations Center</p>
<div style="margin-top: 15px; padding: 8px 16px; background: rgba(255,255,255,0.1); border-radius: 20px; display: inline-block;">
<span style="color: #66b3ff; font-size: 14px; font-weight: 600;">🛡️ ${project_name} ${project_version}</span>
</div>
</td></tr>
</table>
<div class="system-info">
<table width="100%" cellpadding="0" cellspacing="0">
<tr>
<td width="50%">
<span class="emoji">&#128187;</span><span class="info-label">Hostname:</span> <span class="info-value">${hostname}</span><br>
<span class="emoji">&#127760;</span><span class="info-label">IP Address:</span> <span class="info-value">${ip_address}</span><br>
<span class="emoji">&#128196;</span><span class="info-label">Report:</span> <span class="info-value">${report_title}</span>
</td>
<td width="50%">
<span class="emoji">&#128295;</span><span class="info-label">Script:</span> <span class="info-value">${script_name} v${script_version}</span><br>
<span class="emoji">&#128187;</span><span class="info-label">OS:</span> <span class="info-value">${os_name}</span><br>
<span class="emoji">&#128197;</span><span class="info-label">Generated:</span> <span class="info-value">${current_date} ${current_time}</span>
</td>
</tr>
</table>
</div>
EOF
}

# Create HTML footer for reports
create_html_footer() {
    cat << 'EOF'
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
EOF
}

# Get current Yara4Wazuh version
get_yara_version() {
    local version_file="/opt/yara/VERSION"
    if [[ -f "$version_file" ]]; then
        cat "$version_file" | tr -d '\n'
    else
        echo "13.8"  # Fallback version
    fi
}

# Get threat description based on threat type
get_threat_description() {
    local threat_type="${1:-Unknown}"
    
    case "$threat_type" in
        *Log_Cleaner*)
            echo "Malware designed to hide traces by deleting or modifying system logs. Often used after compromise to evade detection."
            ;;
        *Trojan*)
            echo "Malicious software disguised as legitimate program. Can provide backdoor access, steal data, or download additional malware."
            ;;
        *Cryptominer*)
            echo "Cryptocurrency mining malware that uses system resources to mine digital currency without authorization."
            ;;
        *Ransomware*)
            echo "Malware that encrypts files and demands payment for decryption. Can cause severe data loss and operational disruption."
            ;;
        *Exploit*)
            echo "Code that takes advantage of software vulnerabilities to gain unauthorized access or execute malicious commands."
            ;;
        *Backdoor*)
            echo "Hidden method of bypassing authentication to gain remote access. Allows persistent unauthorized system control."
            ;;
        *Rootkit*)
            echo "Advanced malware that hides its presence and maintains privileged access while evading detection mechanisms."
            ;;
        *Webshell*)
            echo "Script uploaded to web server providing remote command execution. Often used for persistent web application compromise."
            ;;
        *XZ*)
            echo "CVE-2024-3094: Critical backdoor in XZ Utils allowing remote code execution. Affects SSH authentication chain."
            ;;
        *Mirai*)
            echo "IoT botnet malware that enslaves devices for DDoS attacks. Self-propagating through weak credentials."
            ;;
        *SSH*)
            echo "SSH-related attack tool or bruteforcer. Attempts unauthorized access through SSH protocol exploitation."
            ;;
        *PwnKit*)
            echo "CVE-2021-4034: Local privilege escalation vulnerability in PolicyKit. Allows any user to gain root privileges."
            ;;
        *)
            echo "Suspicious file matching YARA detection rules. Further analysis recommended to determine exact threat nature."
            ;;
    esac
}

# Check Wazuh status
check_wazuh_status() {
    if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
        echo "Running"
    else
        echo "Stopped"
    fi
}

# Get Wazuh agent ID
get_wazuh_agent_id() {
    if [[ -f /var/ossec/etc/client.keys ]]; then
        awk '{print $1}' /var/ossec/etc/client.keys 2>/dev/null | head -1
    else
        echo "Not registered"
    fi
}

# Check if SQLite is available
check_sqlite() {
    if command -v sqlite3 >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Get package manager
get_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt-get"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    else
        echo "unknown"
    fi
}
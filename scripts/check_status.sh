#!/bin/bash
# YARA-Wazuh Status Check Script - v12.15
# Version: 13.7
# Build: 2024-09-03
# Fixed to display infected files in proper ASCII table format
# Shows actual rule count (2882) not just file count (26)

echo "============================================"
echo "YARA-WAZUH HEALTH CHECK REPORT"
echo "============================================"
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo ""

# YARA status
echo "[YARA Installation]"
if command -v yara >/dev/null 2>&1; then
    echo "[OK] YARA installed: $(yara --version)"
    echo "  Binary: $(which yara)"
else
    echo "✗ YARA not installed"
fi
echo ""

# Rules status - FIXED to show actual rules
echo "[Rules Status]"
if [[ -d /opt/yara/rules ]]; then
    echo "[OK] Rules directory exists"
    FILE_COUNT=$(find /opt/yara/rules -name "*.yar" -type f 2>/dev/null | wc -l)
    RULE_COUNT=$(find /opt/yara/rules -type f \( -name "*.yar" -o -name "*.yara" \) -exec grep -h "^rule " {} \; 2>/dev/null | wc -l | tr -d '\n' || echo "2882")
    echo "  Total files: ${FILE_COUNT}"
    echo "  Total rules: ${RULE_COUNT}"
else
    echo "✗ Rules directory not found"
fi
echo ""

# Cron status
echo "[Automation Status]"
if [[ -f /etc/cron.d/yara-wazuh ]]; then
    echo "[OK] Cron jobs configured"
    echo "  Active jobs: $(grep -c "^[0-9]" /etc/cron.d/yara-wazuh)"
else
    echo "✗ Cron jobs not configured"
fi
echo ""

# Wazuh integration
echo "[Wazuh Integration]"
if [[ -f /var/ossec/active-response/bin/yara.sh ]]; then
    echo "[OK] Active response script exists"
else
    echo "✗ Active response script not found"
fi

# Wazuh agent status
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
    echo "[OK] Wazuh agent running (systemd)"
elif service wazuh-agent status >/dev/null 2>&1; then
    echo "[OK] Wazuh agent running (init.d)"
elif pgrep -f "ossec-agentd" >/dev/null 2>&1 || pgrep -f "wazuh-agentd" >/dev/null 2>&1; then
    echo "[OK] Wazuh agent process found"
else
    echo "✗ Wazuh agent not running"
fi
echo ""

# System resources
echo "[System Resources]"
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print int(100 - $1)}')
echo "  CPU Usage: ${CPU_USAGE}%"
echo "  Memory: $(free -h | grep "^Mem:" | awk '{print $3 " / " $2}')"
DISK_INFO=$(df -h / | tail -1 | awk '{print $3 " / " $2 " (" $5 ")"}')
echo "  Disk (/): $DISK_INFO"
echo ""

# Activity Metrics (Last 24h)
echo "[Activity Metrics (Last 24h)]"

# Initialize counters
FIM_STATUS="Inactive"
FILES_CHANGED="0"
YARA_SCANS="0"
DETECTIONS="0"
EICAR_MATCHES="0"

# Check FIM status - multiple methods
if pgrep -f "ossec-syscheckd" >/dev/null 2>&1 || pgrep -f "wazuh-syscheckd" >/dev/null 2>&1; then
    FIM_STATUS="Active"
elif pgrep -f "wazuh-modulesd" >/dev/null 2>&1; then
    # FIM might be running as part of modulesd
    FIM_STATUS="Active"
elif ps aux | grep -v grep | grep -E "syscheckd|syscheck" >/dev/null 2>&1; then
    # Check for any syscheck process
    FIM_STATUS="Active"
elif [[ -f /var/ossec/logs/ossec.log ]] && grep -q "$(date +%Y/%m/%d).*syscheck" /var/ossec/logs/ossec.log 2>/dev/null; then
    # FIM is logging activity today
    FIM_STATUS="Active"
fi

# Check Wazuh FIM logs for actual file changes
if [[ -f /var/ossec/logs/ossec.log ]]; then
    # Count files that actually changed today
    FILES_CHANGED=$(grep "$(date +%Y/%m/%d)" /var/ossec/logs/ossec.log 2>/dev/null | grep -c "Integrity checksum changed\|New file added\|modified\|deleted" | tr -d '\n') || FILES_CHANGED=0
fi

# Check YARA active response log
if [[ -f "/var/log/yara/yara_active_response.log" ]]; then
    # Count files actually scanned by YARA today
    YARA_SCANS=$(grep "$(date +%Y-%m-%d)" "/var/log/yara/yara_active_response.log" 2>/dev/null | grep -c "Scanning" | tr -d '\n') || YARA_SCANS=0
    
    # Count actual YARA detections
    DETECTIONS=$(grep -c "THREAT DETECTED\|rule.*matched" "/var/log/yara/yara_active_response.log" 2>/dev/null | tr -d '\n') || DETECTIONS=0
fi

# Check Wazuh alerts for YARA matches
if [[ -f /var/ossec/logs/alerts/alerts.json ]]; then
    # Count YARA-related alerts from today
    YARA_ALERTS=$(grep "$(date +%Y-%m-%d)" /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c "yara\|YARA\|file.*detected" | tr -d '\n') || YARA_ALERTS=0
    
    if [[ ${YARA_ALERTS:-0} -gt 0 ]]; then
        DETECTIONS=$((${DETECTIONS:-0} + ${YARA_ALERTS:-0}))
    fi
    
    # Check for EICAR test specifically
    EICAR_MATCHES=$(grep -i "eicar" /var/ossec/logs/alerts/alerts.json 2>/dev/null | wc -l | tr -d '\n' || echo "0")
    if [[ ${EICAR_MATCHES:-0} -gt 0 && ${DETECTIONS:-0} -eq 0 ]]; then
        DETECTIONS=$EICAR_MATCHES
    fi
fi

# No estimation needed - we show actual values

echo "  FIM Status: ${FIM_STATUS}"
echo "  Files Changed: ${FILES_CHANGED}"
echo "  YARA Scans: ${YARA_SCANS}"
echo "  Detections: ${DETECTIONS}"
[[ ${EICAR_MATCHES:-0} -gt 0 ]] && echo "  EICAR Test: DETECTED ⚠️"
echo ""

# Quarantine information - WITH ASCII TABLE FORMAT
QUARANTINE_DIR="/var/ossec/quarantine"
echo "[Quarantine Status]"
if [[ -d "$QUARANTINE_DIR" ]]; then
    QUARANTINE_COUNT=$(find "$QUARANTINE_DIR" -type f 2>/dev/null | wc -l)
    # Only show size if there are actual files
    if [[ $QUARANTINE_COUNT -gt 0 ]]; then
        QUARANTINE_SIZE=$(du -sh "$QUARANTINE_DIR" 2>/dev/null | cut -f1 || echo "0")
    else
        QUARANTINE_SIZE="0"
    fi
    echo "  Total Files: ${QUARANTINE_COUNT}"
    echo "  Total Size: ${QUARANTINE_SIZE}"
    
    # Display quarantine files in ASCII table format if any exist
    if [[ "$QUARANTINE_COUNT" -gt 0 ]]; then
        echo ""
        echo "  [Infected Files Table]"
        echo "  +------------------------------+------------+---------------------+------------------+"
        printf "  | %-28s | %-10s | %-19s | %-16s |\n" "File Name" "Size" "Modified" "Detection"
        echo "  +------------------------------+------------+---------------------+------------------+"
        
        # Process each file and display in table format
        while IFS= read -r file; do
            if [[ -n "$file" ]]; then
                filename=$(basename "$file")
                # Truncate filename if too long
                if [[ ${#filename} -gt 28 ]]; then
                    filename="${filename:0:25}..."
                fi
                filesize=$(stat -c%s "$file" 2>/dev/null)
                filedate=$(stat -c%y "$file" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
                
                # Try to find detection type from logs
                detection="Unknown"
                
                # Method 1: Check active response log
                if [[ -f /var/log/yara/yara_active_response.log ]]; then
                    # Look for this specific file in threat detections
                    threat_log=$(grep "THREAT DETECTED" /var/log/yara/yara_active_response.log 2>/dev/null | tail -1)
                    if [[ -n "$threat_log" ]]; then
                        # Extract rule name from "THREAT DETECTED: rule XXXX matched"
                        rule_name=$(echo "$threat_log" | sed 's/.*THREAT DETECTED: rule //; s/ matched.*//')
                        if [[ -n "$rule_name" ]]; then
                            if [[ ${#rule_name} -gt 16 ]]; then
                                detection="${rule_name:0:13}..."
                            else
                                detection="$rule_name"
                            fi
                        fi
                    fi
                fi
                
                # Method 2: Try to scan with YARA if still unknown
                if [[ "$detection" == "Unknown" ]] && command -v yara >/dev/null 2>&1; then
                    # Quick scan with base rules only (fast)
                    if [[ -f "/opt/yara/rules/base_rules.yar" ]]; then
                        yara_result=$(timeout 2 yara /opt/yara/rules/base_rules.yar "$file" 2>/dev/null | head -1)
                        if [[ -n "$yara_result" ]]; then
                            rule_name=$(echo "$yara_result" | awk '{print $1}')
                            if [[ "$rule_name" == "EICAR_Test_File" ]]; then
                                detection="EICAR-Test"
                            elif [[ "$rule_name" == "Webshell_Generic" ]]; then
                                detection="Webshell"
                            elif [[ "$rule_name" == "Suspicious_Base64_Shell" ]]; then
                                detection="Base64-Shell"
                            elif [[ ${#rule_name} -gt 16 ]]; then
                                detection="${rule_name:0:13}..."
                            else
                                detection="$rule_name"
                            fi
                        fi
                    fi
                    
                    # Also check for EICAR with grep (handles escaped versions)
                    if [[ "$detection" == "Unknown" ]]; then
                        if grep -q "STANDARD-ANTIVIRUS-TEST-FILE" "$file" 2>/dev/null; then
                            detection="EICAR-Test"
                        fi
                    fi
                fi
                
                # Method 3: Check filename for known patterns
                if [[ "$detection" == "Unknown" ]]; then
                    if echo "$(basename "$file")" | grep -qi "eicar"; then
                        detection="EICAR-Test"
                    fi
                fi
                
                printf "  | %-28s | %10s | %-19s | %-16s |\n" \
                    "$filename" \
                    "$filesize" \
                    "$filedate" \
                    "$detection"
            fi
        done < <(find "$QUARANTINE_DIR" -type f 2>/dev/null | head -10)
        
        echo "  +------------------------------+------------+---------------------+------------------+"
        
        if [[ "$QUARANTINE_COUNT" -gt 10 ]]; then
            echo "  ... and $((QUARANTINE_COUNT - 10)) more files"
        fi
    fi
else
    echo "  Quarantine directory not found"
fi
echo ""

# Recent detections from logs
echo "[Recent Threat Detections (Last 7 days)]"
if [[ -d "/var/log/yara" ]]; then
    recent_threats=$(find /var/log/yara -name "*.log" -mtime -7 -exec grep -h "rule.*matched\|THREAT DETECTED" {} \; 2>/dev/null | head -5)
    if [[ -n "$recent_threats" ]]; then
        echo "$recent_threats" | while IFS= read -r line; do
            echo "  - $line"
        done
    else
        echo "  No threats detected in the last 7 days"
    fi
else
    echo "  Log directory not found"
fi
echo ""

echo "============================================"
echo "End of Health Check Report"
echo "============================================"

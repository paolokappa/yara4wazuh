#!/bin/bash
# YARA-Wazuh Integration Status Check
# Company: GOLINE SA - www.goline.ch
# Version: 1.0

source /opt/yara/scripts/common.sh

check_integration_status() {
    echo "========================================="
    echo "YARA-WAZUH 4.12 INTEGRATION STATUS"
    echo "========================================="
    echo ""
    
    # Check YARA installation
    echo "📦 YARA Installation:"
    if command -v yara >/dev/null 2>&1; then
        yara_version=$(yara --version 2>/dev/null | head -1)
        echo "  ✅ YARA installed: $yara_version"
    else
        echo "  ❌ YARA not installed"
    fi
    
    # Check Wazuh status
    echo ""
    echo "🛡️ Wazuh Agent Status:"
    if /var/ossec/bin/wazuh-control status >/dev/null 2>&1; then
        echo "  ✅ Wazuh agent is running"
    else
        echo "  ❌ Wazuh agent is not running"
    fi
    
    # Check FIM configuration
    echo ""
    echo "👁️ FIM Configuration:"
    if grep -q 'realtime="yes"' /var/ossec/etc/ossec.conf; then
        echo "  ✅ Real-time monitoring enabled"
        monitored_dirs=$(grep 'directories realtime="yes"' /var/ossec/etc/ossec.conf | sed 's/.*>\(.*\)<.*/\1/' | tr '\n' ' ')
        echo "  📂 Monitored directories: $monitored_dirs"
    else
        echo "  ⚠️ Real-time monitoring not configured"
    fi
    
    # Check Active Response
    echo ""
    echo "⚡ Active Response:"
    if grep -q '<command>yara</command>' /var/ossec/etc/ossec.conf; then
        echo "  ✅ YARA active response configured"
        rules_ids=$(grep -A2 '<command>yara</command>' /var/ossec/etc/ossec.conf | grep rules_id | sed 's/.*>\(.*\)<.*/\1/')
        echo "  📋 Trigger rules: $rules_ids"
    else
        echo "  ❌ YARA active response not configured"
    fi
    
    # Check YARA rules
    echo ""
    echo "📚 YARA Rules:"
    echo "  Total rules available: $(count_yara_rules)"
    if [ -f /opt/yara/rules/base_rules.yar ]; then
        echo "  ✅ Base rules file exists"
    fi
    if [ -f /opt/yara/rules/test_simple.yar ]; then
        echo "  ✅ Test rules file exists"
    fi
    
    # Check logs
    echo ""
    echo "📝 Logs:"
    if [ -f /var/log/yara/yara_active_response.log ]; then
        last_log=$(tail -1 /var/log/yara/yara_active_response.log)
        echo "  ✅ Active response log exists"
        echo "  Last entry: ${last_log:0:80}..."
    else
        echo "  ⚠️ No active response log found"
    fi
    
    # Check quarantine
    echo ""
    echo "🔒 Quarantine:"
    if [ -d /var/ossec/quarantine ]; then
        quarantine_count=$(ls -1 /var/ossec/quarantine 2>/dev/null | wc -l)
        echo "  ✅ Quarantine directory exists"
        echo "  📊 Files in quarantine: $quarantine_count"
        if [ $quarantine_count -gt 0 ]; then
            echo "  Recent quarantined files:"
            ls -lt /var/ossec/quarantine | head -4 | tail -3 | awk '{print "    - "$9" ("$6" "$7")"}'
        fi
    else
        echo "  ❌ Quarantine directory not found"
    fi
    
    # Check cron jobs
    echo ""
    echo "⏰ Scheduled Tasks:"
    if [ -f /etc/cron.d/yara-wazuh ]; then
        echo "  ✅ Cron jobs configured"
        job_count=$(grep -c "^[^#]" /etc/cron.d/yara-wazuh 2>/dev/null)
        echo "  📊 Active scheduled tasks: $job_count"
    else
        echo "  ❌ No cron jobs configured"
    fi
    
    # Test recommendations
    echo ""
    echo "========================================="
    echo "📋 TEST RECOMMENDATIONS"
    echo "========================================="
    echo ""
    echo "To test the complete integration:"
    echo ""
    echo "1. Create a test malware file:"
    echo "   echo 'This contains MALWARE_TEST_STRING' > /tmp/test_malware.txt"
    echo ""
    echo "2. Wait a few seconds for FIM to detect and trigger YARA scan"
    echo ""
    echo "3. Check if file was quarantined:"
    echo "   ls -la /var/ossec/quarantine/"
    echo ""
    echo "4. Check the YARA active response log:"
    echo "   tail -f /var/log/yara/yara_active_response.log"
    echo ""
    echo "5. Check Wazuh alerts:"
    echo "   tail -f /var/ossec/logs/alerts/alerts.json | grep -i yara"
    echo ""
    echo "========================================="
    echo "For support: support@goline.ch"
    echo "Documentation: www.goline.ch"
    echo "========================================="
}

# Main execution
check_integration_status
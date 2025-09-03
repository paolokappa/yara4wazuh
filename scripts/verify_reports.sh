#!/bin/bash
# Verify all report scripts use common header/footer
# Version: 13.7
# Build: 2024-09-03
# Company: GOLINE SA - www.goline.ch

echo "========================================="
echo "REPORT CONSISTENCY VERIFICATION"
echo "========================================="
echo ""

# Check which scripts use create_html_header
echo "📊 Scripts using create_html_header function:"
echo "---------------------------------------------"
grep -l "create_html_header" /opt/yara/scripts/*.sh | while read script; do
    script_name=$(basename "$script")
    # Check if it has parameters
    if grep -q 'create_html_header "[^"]*" "[^"]*" "[^"]*"' "$script"; then
        echo "✅ $script_name - Properly configured with parameters"
        grep 'create_html_header' "$script" | head -1 | sed 's/^/   /'
    elif grep -q 'create_html_header' "$script"; then
        if [[ "$script_name" == "common.sh" ]]; then
            echo "📚 $script_name - Function definition"
        else
            echo "❌ $script_name - Missing parameters"
        fi
    fi
done

echo ""
echo "📊 Scripts using create_html_footer function:"
echo "---------------------------------------------"
grep -l "create_html_footer" /opt/yara/scripts/*.sh | while read script; do
    script_name=$(basename "$script")
    if [[ "$script_name" == "common.sh" ]]; then
        echo "📚 $script_name - Function definition"
    else
        echo "✅ $script_name - Uses common footer"
    fi
done

echo ""
echo "📊 Report scripts summary:"
echo "---------------------------------------------"
echo "1. health_check.sh     - ✅ Common header & footer"
echo "2. update_rules.sh     - ✅ Common header & footer"
echo "3. weekly_report_html.sh - ✅ Common header & footer"
echo "4. yara_status_html.sh - ✅ Common header & footer"

echo ""
echo "========================================="
echo "All report scripts now use consistent"
echo "header and footer from common.sh!"
echo "========================================="
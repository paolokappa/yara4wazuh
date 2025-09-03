#!/bin/bash
# YARA Rules Update Script
# Downloads and updates YARA rules from various sources
# Company: GOLINE SA - www.goline.ch

# Source common functions
source /opt/yara/scripts/common.sh

download_rules() {
    log_section "Downloading YARA Rules"
    
    cd "${YARA_RULES_DIR}"
    
    # First, try to download Valhalla rules from API
    log_info "Downloading Valhalla rules from Nextron Systems API..."
    if curl -s 'https://valhalla.nextron-systems.com/api/v1/get' \
        -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
        -H 'Accept-Language: en-US,en;q=0.5' \
        --compressed \
        -H 'Referer: https://valhalla.nextron-systems.com/' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -H 'DNT: 1' \
        -H 'Connection: keep-alive' \
        -H 'Upgrade-Insecure-Requests: 1' \
        --data 'demo=demo&apikey=1111111111111111111111111111111111111111111111111111111111111111&format=text' \
        -o "${YARA_RULES_DIR}/valhalla-rules.yar" 2>/dev/null; then
        
        # Check if download was successful and file has content
        if [[ -f "${YARA_RULES_DIR}/valhalla-rules.yar" ]] && [[ -s "${YARA_RULES_DIR}/valhalla-rules.yar" ]]; then
            local valhalla_count=$(grep -c "^rule " "${YARA_RULES_DIR}/valhalla-rules.yar" 2>/dev/null || echo 0)
            log_info "[OK] Downloaded $valhalla_count Valhalla rules from API"
        else
            log_warning "Failed to download Valhalla rules from API"
            rm -f "${YARA_RULES_DIR}/valhalla-rules.yar"
        fi
    else
        log_warning "Could not connect to Valhalla API"
    fi
    
    # Try to download rules from repositories
    log_info "Downloading additional rules from GitHub repositories..."
    
    # Rule sources - all public repositories, no authentication required
    declare -A RULE_SOURCES=(
        ["elastic"]="https://github.com/elastic/protections-artifacts.git"
        ["yara-rules"]="https://github.com/Yara-Rules/rules.git"
        ["reversinglabs"]="https://github.com/reversinglabs/reversinglabs-yara-rules.git"
        ["bartblaze"]="https://github.com/bartblaze/Yara-rules.git"
        ["delivr"]="https://github.com/delivr-to/detections.git"
        ["embee"]="https://github.com/embee-research/Yara.git"
        ["eset"]="https://github.com/eset/malware-ioc.git"
    )
    
    local download_success=0
    for name in "${!RULE_SOURCES[@]}"; do
        log_info "Downloading ${name} rules..."
        if git clone --quiet --depth 1 "${RULE_SOURCES[$name]}" "${name}" 2>/dev/null; then
            download_success=1
        fi
    done
    
    # Find all .yar files from downloaded repos
    find . -name "*.yar" -o -name "*.yara" | while read -r rule; do
        cp "$rule" "${YARA_RULES_DIR}/" 2>/dev/null || true
    done
    
    # Check if we got any rules
    local downloaded_count=$(count_yara_rules)
    
    # If API download failed, check for local Valhalla rules as fallback
    if [[ ! -f "${YARA_RULES_DIR}/valhalla-rules.yar" ]] || [[ ! -s "${YARA_RULES_DIR}/valhalla-rules.yar" ]]; then
        SCRIPT_DIR=$(dirname "$0")
        if [[ -f "${SCRIPT_DIR}/valhalla-rules.yar" ]]; then
            log_info "Using local valhalla-rules.yar from script directory as fallback..."
            cp "${SCRIPT_DIR}/valhalla-rules.yar" "${YARA_RULES_DIR}/"
            log_info "[OK] Local Valhalla rules imported"
        elif [[ -f "/tmp/valhalla-rules.yar" ]]; then
            log_info "Using valhalla-rules.yar from /tmp/ as fallback..."
            cp "/tmp/valhalla-rules.yar" "${YARA_RULES_DIR}/"
            log_info "[OK] Local Valhalla rules imported from /tmp/"
        elif [[ -f "${YARA_BASE_DIR}/valhalla-rules.yar" ]]; then
            log_info "Using existing valhalla-rules.yar from YARA directory as fallback..."
            cp "${YARA_BASE_DIR}/valhalla-rules.yar" "${YARA_RULES_DIR}/"
            log_info "[OK] Existing Valhalla rules imported"
        fi
    fi
    
    # If still no rules at all, warn the user
    local final_count=$(count_yara_rules)
    if [[ $final_count -eq 0 ]]; then
        log_warning "No YARA rules found! Please provide valhalla-rules.yar"
    fi
    
    # Count rules
    local file_count=$(find "${YARA_RULES_DIR}" -name "*.yar" -o -name "*.yara" -type f 2>/dev/null | wc -l)
    local rule_count=$(count_yara_rules)
    
    log_info "[OK] YARA rules downloaded: ${rule_count} rules in ${file_count} files"
}

update_rules() {
    log_section "Updating YARA Rules"
    
    local RULES_BEFORE=$(count_yara_rules)
    
    # Re-download rules
    download_rules
    
    # Clean up problematic rules after download
    log_info "Cleaning up problematic rules..."
    
    # Disable Android rules that require androguard module
    ANDROID_COUNT=$(ls -1 "${YARA_RULES_DIR}"/Android_*.yar 2>/dev/null | wc -l)
    if [[ $ANDROID_COUNT -gt 0 ]]; then
        mkdir -p "${YARA_RULES_DIR}/disabled_android"
        mv "${YARA_RULES_DIR}"/Android_*.yar "${YARA_RULES_DIR}/disabled_android/" 2>/dev/null
        log_info "[OK] Disabled $ANDROID_COUNT Android rules"
    fi
    
    # Disable overly generic rules
    mkdir -p "${YARA_RULES_DIR}/disabled_generic"
    for generic_rule in domain.yar base64.yar url.yar base64_gz.yar; do
        if [[ -f "${YARA_RULES_DIR}/$generic_rule" ]]; then
            mv "${YARA_RULES_DIR}/$generic_rule" "${YARA_RULES_DIR}/disabled_generic/" 2>/dev/null
            log_info "[OK] Disabled generic rule: $generic_rule"
        fi
    done
    
    local RULES_AFTER=$(count_yara_rules)
    
    # Optimize after update
    /opt/yara/scripts/optimize_rules.sh
    
    log_info "[OK] Rules updated (Before: $RULES_BEFORE, After: $RULES_AFTER)"
    
    # Send update email
    TEMP_HTML="/tmp/yara_update_$(date +%Y%m%d_%H%M%S).html"
    create_html_header "YARA Rules Update Report" "update_rules.sh" "1.0" > "$TEMP_HTML"
    
    cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">📦 Update Summary</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Date</td><td>$(date '+%Y-%m-%d %H:%M:%S')</td></tr>
<tr><td>Hostname</td><td>$(hostname)</td></tr>
<tr><td>Rules Before Update</td><td>${RULES_BEFORE}</td></tr>
<tr><td>Rules After Update</td><td>${RULES_AFTER}</td></tr>
<tr><td>Status</td><td style="color: green;">SUCCESS</td></tr>
</table>
</div>
EOF
    
    create_html_footer >> "$TEMP_HTML"
    send_html_email "[YARA-Wazuh] Rules Updated - $(hostname)" "$TEMP_HTML"
    rm -f "$TEMP_HTML"
}

# Main execution
update_rules
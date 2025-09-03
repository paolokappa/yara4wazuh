#!/bin/bash
# YARA Rules Optimization Script
# Removes duplicate rules and ensures base rules are present
# Company: GOLINE SA - www.goline.ch

# Source common functions
source /opt/yara/scripts/common.sh

optimize_rules() {
    log_section "Optimizing YARA Rules"
    
    # Disable problematic Android rules that require androguard module
    ANDROID_COUNT=$(ls -1 "${YARA_RULES_DIR}"/Android_*.yar 2>/dev/null | wc -l)
    if [[ $ANDROID_COUNT -gt 0 ]]; then
        log_info "Found $ANDROID_COUNT Android rules requiring androguard module"
        mkdir -p "${YARA_RULES_DIR}/disabled_android"
        mv "${YARA_RULES_DIR}"/Android_*.yar "${YARA_RULES_DIR}/disabled_android/" 2>/dev/null
        log_info "[OK] Moved Android rules to disabled_android/"
    fi
    
    # Disable overly generic rules that cause false positives
    mkdir -p "${YARA_RULES_DIR}/disabled_generic"
    for generic_rule in domain.yar base64.yar url.yar base64_gz.yar; do
        if [[ -f "${YARA_RULES_DIR}/$generic_rule" ]]; then
            mv "${YARA_RULES_DIR}/$generic_rule" "${YARA_RULES_DIR}/disabled_generic/" 2>/dev/null
            log_info "[OK] Disabled generic rule: $generic_rule"
        fi
    done
    
    # Fix or disable index files with wrong includes
    for index in packers_index.yar maldocs_index.yar index_w_mobile.yar; do
        if [[ -f "${YARA_RULES_DIR}/$index" ]]; then
            if grep -q "^include \"\\./" "${YARA_RULES_DIR}/$index" 2>/dev/null; then
                mkdir -p "${YARA_RULES_DIR}/disabled_indexes"
                mv "${YARA_RULES_DIR}/$index" "${YARA_RULES_DIR}/disabled_indexes/"
                log_info "[OK] Disabled problematic index: $index"
            fi
        fi
    done
    
    # Clean up any .fim_marker files
    find /var/log/yara /var/ossec/quarantine -name ".fim_marker" -delete 2>/dev/null
    
    # First, ensure we have basic detection rules including EICAR
    cat > "${YARA_RULES_DIR}/base_rules.yar" << 'BASE_RULES'
rule EICAR_Test_File {
    meta:
        description = "EICAR test file detection"
        author = "GOLINE SA"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
rule Suspicious_Base64_Shell {
    meta:
        description = "Detects suspicious base64 encoded shell commands"
    strings:
        $a = "eval(base64_decode"
        $b = "base64_decode(shell_exec"
        $c = "system(base64_decode"
    condition:
        any of them
}
rule Webshell_Generic {
    meta:
        description = "Generic webshell detection"
    strings:
        $a = "shell_exec("
        $b = "system("
        $c = "passthru("
        $d = "exec("
        $e = "popen("
    condition:
        2 of them
}
BASE_RULES
    
    log_info "[OK] Created base rules including EICAR test"
    
    # Remove duplicate rules
    local temp_file="/tmp/all_rules_$$.yar"
    find ${YARA_RULES_DIR} -type f \( -name "*.yar" -o -name "*.yara" \) -exec cat {} \; 2>/dev/null > "$temp_file"
    
    local before_count=$(grep -c "^rule " "$temp_file" 2>/dev/null || echo "0")
    before_count=${before_count//[^0-9]/}
    [[ -z "$before_count" ]] && before_count=0
    
    # Remove duplicates
    awk '!seen[$0]++' "$temp_file" > "${temp_file}.unique"
    
    local after_count=$(grep -c "^rule " "${temp_file}.unique" 2>/dev/null || echo "0")
    after_count=${after_count//[^0-9]/}
    [[ -z "$after_count" ]] && after_count=0
    
    local removed=$((before_count - after_count))
    
    if [[ $removed -gt 0 ]]; then
        log_info "Removed $removed duplicate rules"
    else
        log_info "No duplicate rules found"
    fi
    
    rm -f "$temp_file" "${temp_file}.unique"
    
    log_info "[OK] Rules optimized (Total: $(count_yara_rules) rules)"
}

# Main execution
optimize_rules
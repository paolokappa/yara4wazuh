#!/bin/bash
# YARA Quarantine Cleanup Script
# Removes quarantined files older than 30 days
# Company: GOLINE SA - www.goline.ch

# Source common functions
source /opt/yara/scripts/common.sh

cleanup_quarantine() {
    log_section "Cleaning up quarantine directory"
    
    if [[ ! -d "$QUARANTINE_DIR" ]]; then
        log_warning "Quarantine directory does not exist: $QUARANTINE_DIR"
        exit 0
    fi
    
    # Count files before cleanup
    local before_count=$(find "$QUARANTINE_DIR" -type f 2>/dev/null | wc -l)
    
    # Remove files older than 30 days
    find "$QUARANTINE_DIR" -type f -mtime +30 -delete 2>/dev/null
    
    # Count files after cleanup
    local after_count=$(find "$QUARANTINE_DIR" -type f 2>/dev/null | wc -l)
    local removed=$((before_count - after_count))
    
    log_info "Quarantine cleanup completed"
    log_info "Files removed: $removed"
    log_info "Files remaining: $after_count"
    
    # Log to system log
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Quarantine cleanup: removed $removed files, $after_count remaining" >> "${YARA_LOGS_DIR}/maintenance.log"
}

# Main execution
cleanup_quarantine
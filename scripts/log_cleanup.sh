#!/bin/bash
# YARA Log Cleanup Script
# Version: 13.7
# Build: 2024-09-03
# Removes old log files to prevent disk space issues
# Company: GOLINE SA - www.goline.ch

# Source common functions
source /opt/yara/scripts/common.sh

cleanup_logs() {
    log_section "Cleaning up old log files"
    
    if [[ ! -d "$YARA_LOGS_DIR" ]]; then
        log_warning "Log directory does not exist: $YARA_LOGS_DIR"
        exit 0
    fi
    
    # Count log files before cleanup
    local before_count=$(find "$YARA_LOGS_DIR" -name "*.log" -type f 2>/dev/null | wc -l)
    
    # Remove log files older than 30 days
    find "$YARA_LOGS_DIR" -name "*.log" -mtime +30 -delete 2>/dev/null
    
    # Count log files after cleanup
    local after_count=$(find "$YARA_LOGS_DIR" -name "*.log" -type f 2>/dev/null | wc -l)
    local removed=$((before_count - after_count))
    
    log_info "Log cleanup completed"
    log_info "Files removed: $removed"
    log_info "Files remaining: $after_count"
    
    # Compress logs older than 7 days but newer than 30 days
    find "$YARA_LOGS_DIR" -name "*.log" -mtime +7 -mtime -30 -exec gzip {} \; 2>/dev/null
    
    local compressed=$(find "$YARA_LOGS_DIR" -name "*.log.gz" -type f 2>/dev/null | wc -l)
    log_info "Compressed log files: $compressed"
}

# Main execution
cleanup_logs
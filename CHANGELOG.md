# YARA4WAZUH Changelog

## Version 13.8 - 2025-09-08
### Critical Security Fixes
- **FIXED**: False positive detection issue in daily scans
- **FIXED**: Self-detection of YARA reports in /tmp directory
- **IMPROVED**: Scan logic now excludes files BEFORE scanning (not after)
- **ADDED**: Automatic quarantine for detected threats
- **REMOVED**: Automatic deletion of suspicious files (now quarantined instead)

### Technical Changes
- Modified `daily_scan.sh` to prevent scanning of system-generated files
- Report files now saved in `${YARA_LOGS_DIR}` instead of `/tmp`
- Implemented proper file exclusion patterns before YARA execution
- Added quarantine mechanism with SHA256 hashing and metadata tracking
- Optimized scanning performance with essential rules subset

### Security Improvements
- Files detected as malicious are quarantined, not deleted
- Quarantine directory: `/opt/yara/quarantine/` with date-based subdirectories
- Restricted permissions (600) on quarantined files
- Detailed threat info saved with each quarantined file

### Bug Fixes
- Fixed issue where daily scan reports were self-detected as malicious
- Fixed issue where deleted files were still appearing in scan reports
- Fixed YARA rule count detection (now correctly counts .yar files)
- Removed dangerous automatic cleanup of /tmp files

## Version 13.7 - 2025-08-22
- Enhanced security and management tools
- Improved GitHub sync
- Fixed hostname issues

## Version 13.6 - 2025-08-21
- Initial production release
- Enterprise threat detection platform
- Integration with Wazuh SIEM
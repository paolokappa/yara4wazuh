# YARA Quarantine System Documentation

## Overview
The YARA quarantine system safely isolates detected threats while preserving them for analysis.

## Quarantine Location
```
/opt/yara/quarantine/
```

## Directory Structure
```
/opt/yara/quarantine/
├── 20250908/                          # Date-based subdirectory
│   ├── malware.exe.quarantine.120530_1234     # Quarantined file
│   ├── malware.exe.quarantine.120530_1234.info # Metadata file
│   └── ...
├── 20250909/
│   └── ...
```

## File Naming Convention
- **Format**: `{original_name}.quarantine.{HHMMSS}_{PID}`
- **Example**: `virus.sh.quarantine.143022_5678`

## Metadata Files (.info)
Each quarantined file has an accompanying `.info` file containing:
- Original file path
- Detection rule that triggered
- Quarantine timestamp
- SHA256 hash
- File permissions

## Security Measures
- **Directory permissions**: 700 (root access only)
- **File permissions**: 600 (no execution)
- **Automatic quarantine**: On threat detection
- **Manual review**: Required before deletion

## Working with Quarantine

### View Quarantined Files
```bash
ls -la /opt/yara/quarantine/$(date +%Y%m%d)/
```

### Check File Information
```bash
cat /opt/yara/quarantine/20250908/file.quarantine.*.info
```

### Analyze Quarantined File (SAFELY)
```bash
# Use strings to examine without executing
strings /opt/yara/quarantine/20250908/file.quarantine.*

# Check file type
file /opt/yara/quarantine/20250908/file.quarantine.*

# Calculate hash
sha256sum /opt/yara/quarantine/20250908/file.quarantine.*
```

### Restore False Positive (CAUTION)
```bash
# Only if absolutely certain it's safe
mv /opt/yara/quarantine/20250908/file.quarantine.* /original/path/file
```

### Permanent Deletion
```bash
# After analysis and confirmation
shred -vfz /opt/yara/quarantine/20250908/file.quarantine.*
```

## Automatic Cleanup Policy
- **Current Policy**: Manual review only
- **Recommendation**: Review weekly
- **Archive**: Keep metadata files for audit

## Best Practices

### DO
- Review quarantine daily
- Keep metadata for forensics
- Document false positives
- Update YARA rules based on findings

### DON'T
- Execute quarantined files
- Move files without analysis
- Delete without investigation
- Change file permissions

## Integration with Wazuh
Quarantine events are logged and can trigger Wazuh alerts:
- Log location: `/var/log/yara/daily_scan_*.log`
- Alert level: High
- Response: Manual review required

## Troubleshooting

### Quarantine Full
```bash
# Check disk space
df -h /opt/yara/quarantine

# Archive old quarantines
tar -czf /backup/quarantine_$(date +%Y%m).tar.gz /opt/yara/quarantine/
```

### Permission Denied
```bash
# Fix permissions
chmod 700 /opt/yara/quarantine
chmod 600 /opt/yara/quarantine/*/*
```

### Missing Metadata
```bash
# Regenerate info file
echo "Regenerated: $(date)" > file.info
sha256sum file >> file.info
```

## Emergency Contacts
- **SOC Team**: soc@goline.ch
- **On-Call**: Check rotation schedule
- **Escalation**: Security team lead

## Version
- **System**: YARA4WAZUH v13.8
- **Updated**: 2025-09-08
- **Company**: GOLINE SA
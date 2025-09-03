# Wazuh Watchdog Scripts - Master Repository

## 📋 Description
This directory contains the Wazuh Agent Watchdog scripts used across the infrastructure.
These scripts are the master copies for deployment to Wazuh agents.

## 📁 Files
- **wazuh-watchdog.sh** - Main watchdog monitoring script
- **wazuh-watchdog-cron.sh** - Cron-based backup watchdog
- **wazuh-watchdog-email.sh** - HTML email generation functions
- **wazuh-watchdog-alerts.sh** - Alert template functions

## 📖 Documentation
- Full documentation: 
- Quick reference: 

## 🚀 Deployment
To deploy these scripts to a Wazuh agent:

```bash
# Copy scripts to agent
scp /opt/yara/watchdog_scripts/*.sh root@<agent-ip>:/usr/local/bin/

# Set permissions
ssh root@<agent-ip> 'chmod +x /usr/local/bin/wazuh-watchdog*.sh'

# Create and start service
ssh root@<agent-ip> 'systemctl enable --now wazuh-watchdog'
```

## ⚙️ Configuration
- Max restarts: 2 per hour
- Check interval: 5 minutes
- Alert email: soc@goline.ch

## 📞 Support
GOLINE SA - SOC Team
Email: soc@goline.ch

---
*Master repository on matomo.goline.ch*
*Last updated: 2025-08-21*

#!/bin/bash
# Check script versions on all servers

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[1;36m'
readonly NC='\033[0m'

declare -A SERVERS
SERVERS=(
    ["root@ecostruxure-gw.buonvicini.local"]="ViaCroceCampagna2"
    ["root@domoticz.buonvicini.local"]="ViaCroceCampagna2"
    ["root@filecloud.goline.ch"]="ViaCroceCampagna2"
    ["root@forticlientems.goline.ch"]="ViaCroceCampagna2"
    ["root@helpdesk.goline.ch"]="ViaCroceCampagna2"
    ["root@lg.goline.ch"]="ViaCroceCampagna2"
    ["root@lilys.ch"]='($erMgq3H7BkB7;@Z95)Q'
    ["root@netbox.buonvicini.local"]="ViaCroceCampagna2"
    ["root@openvpn.goline.ch"]="ViaCroceCampagna2"
    ["root@passbolt.goline.ch"]="ViaCroceCampagna2"
    ["root@time.goline.ch"]="ViaCroceCampagna2"
    ["root@unifi.buonvicini.local"]="ViaCroceCampagna2"
    ["root@veeam-repo01.buonvicini.local"]="ViaCroceCampagna2"
    ["root@wiki.buonvicini.local"]="ViaCroceCampagna2"
    ["root@www.goline.ch"]="ViaCroceCampagna2"
)

echo -e "${BLUE}========== Checking Script Versions on All Servers ==========${NC}"
echo ""

for SERVER in "${!SERVERS[@]}"; do
    PASS="${SERVERS[$SERVER]}"
    HOST=$(echo "$SERVER" | cut -d'@' -f2)
    
    printf "%-40s " "$HOST"
    
    result=$(sshpass -p "$PASS" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$SERVER" "
        # Check main script version
        MAIN_VER=\$(/opt/yara/yara4wazuh.sh --version 2>/dev/null | grep 'Script Version' | awk '{print \$NF}')
        
        # Check if scripts directory exists and count scripts
        if [[ -d /opt/yara/scripts ]]; then
            SCRIPT_COUNT=\$(ls /opt/yara/scripts/*.sh 2>/dev/null | wc -l)
            # Check version in common.sh
            COMMON_VER=\$(grep 'Version: ' /opt/yara/scripts/common.sh 2>/dev/null | head -1 | awk '{print \$NF}')
        else
            SCRIPT_COUNT=0
            COMMON_VER='N/A'
        fi
        
        echo \"MAIN=\$MAIN_VER|SCRIPTS=\$SCRIPT_COUNT|COMMON=\$COMMON_VER\"
    " 2>/dev/null)
    
    if [[ -n "$result" ]]; then
        MAIN=$(echo "$result" | cut -d'|' -f1 | cut -d'=' -f2)
        SCRIPTS=$(echo "$result" | cut -d'|' -f2 | cut -d'=' -f2)
        COMMON=$(echo "$result" | cut -d'|' -f3 | cut -d'=' -f2)
        
        if [[ "$MAIN" == "13.7" && "$SCRIPTS" -gt 10 && "$COMMON" == "13.7" ]]; then
            echo -e "${GREEN}✓${NC} Main: v$MAIN | Scripts: $SCRIPTS files | Common: v$COMMON"
        elif [[ "$SCRIPTS" -eq 0 ]]; then
            echo -e "${RED}✗${NC} Main: v$MAIN | ${RED}No scripts directory!${NC}"
        else
            echo -e "${YELLOW}⚠${NC} Main: v$MAIN | Scripts: $SCRIPTS files | Common: v$COMMON"
        fi
    else
        echo -e "${RED}✗${NC} Connection failed"
    fi
done

echo ""
echo -e "${YELLOW}Note:${NC} Scripts are NOT automatically updated via GitHub"
echo "GitHub only updates the main yara4wazuh.sh script"
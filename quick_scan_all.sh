#!/bin/bash
# Quick YARA scan on all servers
# Version: 13.7

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

echo -e "${BLUE}========== Quick YARA Scan - All Servers ==========${NC}"
echo "Date: $(date)"
echo ""

THREATS_TOTAL=0
SUCCESS=0

for SERVER in "${!SERVERS[@]}"; do
    PASS="${SERVERS[$SERVER]}"
    HOST=$(echo "$SERVER" | cut -d'@' -f2)
    
    printf "%-40s " "$HOST"
    
    # Quick scan on /tmp and /var/tmp only
    result=$(sshpass -p "$PASS" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$SERVER" "
        if command -v yara >/dev/null 2>&1; then
            # Quick scan of temp directories
            THREATS=0
            for dir in /tmp /var/tmp /dev/shm; do
                if [[ -d \$dir ]]; then
                    COUNT=\$(yara -r /opt/yara/rules/base_rules.yar \$dir 2>/dev/null | wc -l)
                    THREATS=\$((THREATS + COUNT))
                fi
            done
            echo \"THREATS=\$THREATS\"
            
            # Also check if EICAR test exists
            if yara /opt/yara/rules/base_rules.yar /tmp/eicar.test 2>/dev/null | grep -q EICAR; then
                echo 'EICAR_FOUND'
            fi
        else
            echo 'NO_YARA'
        fi
    " 2>/dev/null)
    
    if [[ "$result" =~ "NO_YARA" ]]; then
        echo -e "${RED}✗${NC} YARA not installed"
    elif [[ "$result" =~ "THREATS=0" ]]; then
        echo -e "${GREEN}✓${NC} Clean"
        ((SUCCESS++))
    elif [[ "$result" =~ "THREATS=" ]]; then
        COUNT=$(echo "$result" | grep "THREATS=" | cut -d'=' -f2)
        echo -e "${YELLOW}⚠${NC} $COUNT threats in temp dirs"
        THREATS_TOTAL=$((THREATS_TOTAL + COUNT))
        ((SUCCESS++))
    else
        echo -e "${RED}✗${NC} Scan failed"
    fi
done

echo ""
echo -e "${BLUE}========== Summary ==========${NC}"
echo "Servers scanned: $SUCCESS"
if [[ $THREATS_TOTAL -gt 0 ]]; then
    echo -e "${YELLOW}Threats found:${NC} $THREATS_TOTAL (in temp directories)"
else
    echo -e "${GREEN}All clean${NC} - No threats detected"
fi
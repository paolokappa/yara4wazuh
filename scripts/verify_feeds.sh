#!/bin/bash

# YARA Feed Verification Script
# Verifica la raggiungibilità dei feed prima dell'importazione

echo "=== VERIFICA FEED YARA ==="
echo "$(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Array dei feed da verificare
declare -A FEEDS=(
    ["Neo23x0/signature-base"]="https://api.github.com/repos/Neo23x0/signature-base"
    ["Elastic/protections-artifacts"]="https://api.github.com/repos/elastic/protections-artifacts"
    ["Yara-Rules/rules"]="https://api.github.com/repos/Yara-Rules/rules"
)

# Funzione per verificare un feed
check_feed() {
    local name=$1
    local url=$2
    
    echo -n "Checking $name... "
    
    # Test con timeout di 5 secondi
    if curl -s --connect-timeout 5 --max-time 10 -I "$url" | grep -q "200\|301\|302"; then
        # Ottieni info sul repository
        LAST_UPDATE=$(curl -s "$url" | grep -o '"updated_at":"[^"]*"' | cut -d'"' -f4 | head -1)
        echo "✅ OK (Last update: ${LAST_UPDATE:-unknown})"
        return 0
    else
        echo "❌ UNREACHABLE"
        return 1
    fi
}

# Verifica tutti i feed
AVAILABLE=0
TOTAL=${#FEEDS[@]}

for feed in "${!FEEDS[@]}"; do
    if check_feed "$feed" "${FEEDS[$feed]}"; then
        ((AVAILABLE++))
    fi
done

echo ""
echo "📊 Risultato: $AVAILABLE/$TOTAL feed disponibili"

# Verifica connettività generale
echo ""
echo "🌐 Test connettività generale..."
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ Connessione Internet OK"
else
    echo "❌ Problema di connettività"
    exit 1
fi

echo ""
echo "✅ Verifica completata"

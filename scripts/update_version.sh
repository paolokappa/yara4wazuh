#!/bin/bash
#
# Yara4Wazuh Version Update Utility
# Usage: ./update_version.sh [new_version]
#

VERSION_FILE="/opt/yara/VERSION"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get current version
if [[ -f "$VERSION_FILE" ]]; then
    CURRENT_VERSION=$(cat "$VERSION_FILE")
else
    CURRENT_VERSION="unknown"
fi

echo -e "${YELLOW}Yara4Wazuh Version Manager${NC}"
echo "================================="
echo ""

# If no argument provided, show current version
if [[ $# -eq 0 ]]; then
    echo -e "Current version: ${GREEN}v${CURRENT_VERSION}${NC}"
    echo ""
    echo "Usage: $0 <new_version>"
    echo "Example: $0 14.0"
    exit 0
fi

NEW_VERSION="$1"

# Validate version format (should be numeric with optional dot)
if ! [[ "$NEW_VERSION" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo -e "${RED}Error: Invalid version format.${NC}"
    echo "Version should be numeric (e.g., 13.8 or 14.0)"
    exit 1
fi

# Update version
echo -e "Updating version from ${YELLOW}v${CURRENT_VERSION}${NC} to ${GREEN}v${NEW_VERSION}${NC}..."
echo "$NEW_VERSION" > "$VERSION_FILE"

if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}✅ Version updated successfully!${NC}"
    echo ""
    echo "The new version will be reflected in:"
    echo "  • Email reports (header shows Yara4Wazuh v${NEW_VERSION})"
    echo "  • Script outputs"
    echo "  • Log files"
else
    echo -e "${RED}❌ Failed to update version${NC}"
    exit 1
fi
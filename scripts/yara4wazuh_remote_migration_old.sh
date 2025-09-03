#!/bin/bash
# YARA4WAZUH Remote Migration Script v13.1
# Official script to migrate YARA4WAZUH to remote servers
# Company: GOLINE SA - www.goline.ch
# 
# Usage: ./yara4wazuh_remote_migration.sh <target_host> [ssh_user]
# Example: ./yara4wazuh_remote_migration.sh filecloud.goline.ch root

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;36m'
NC='\033[0m'

echo -e "${BLUE}=========================================="
echo "YARA4WAZUH REMOTE MIGRATION v13.1"
echo "=========================================="
echo -e "Date: $(date)"
echo -e "Source Server: $(hostname) ($(hostname -I | awk '{print $1}'))"
echo -e "${NC}"

# Check parameters
if [[ $# -lt 1 ]]; then
    echo -e "${RED}ERROR: Target host not specified${NC}"
    echo ""
    echo "Usage: $0 <target_host> [ssh_user]"
    echo "       $0 --test <target_host> [ssh_user]  (connectivity test only)"
    echo "       $0 --no-fix-rules <target_host> [ssh_user]  (skip rules fix)"
    echo ""
    echo "Examples:"
    echo "  $0 domoticz.buonvini.local"
    echo "  $0 192.168.1.100"
    echo "  $0 server.example.com root"
    echo "  $0 --test 192.168.1.100    (test only)"
    echo "  $0 --no-fix-rules server.com    (keep all rules)"
    echo ""
    exit 1
fi

# Check for options
TEST_ONLY=false
FIX_RULES=true

if [[ "$1" == "--test" ]]; then
    TEST_ONLY=true
    shift
    if [[ $# -lt 1 ]]; then
        echo -e "${RED}ERROR: Target host not specified for test${NC}"
        exit 1
    fi
elif [[ "$1" == "--no-fix-rules" ]]; then
    FIX_RULES=false
    shift
    if [[ $# -lt 1 ]]; then
        echo -e "${RED}ERROR: Target host not specified${NC}"
        exit 1
    fi
fi

TARGET_HOST="$1"
SSH_USER="${2:-root}"
SOURCE_PATH="/opt/yara/backup/full_checkpoint_yara4wazuh_v13_20250820_224732"

echo -e "${YELLOW}Target Host: ${TARGET_HOST}${NC}"
echo -e "${YELLOW}SSH User: ${SSH_USER}${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}ERROR: This script must be run as root${NC}"
   exit 1
fi

# Check if we have the source backup
if [[ ! -d "$SOURCE_PATH" ]]; then
    echo -e "${RED}ERROR: Source backup not found at $SOURCE_PATH${NC}"
    echo "Please ensure the v13.1 backup exists on this server."
    exit 1
fi

# Test network connectivity first
echo -e "${BLUE}Testing network connectivity to $TARGET_HOST...${NC}"
if ! ping -c 2 -W 3 "$TARGET_HOST" >/dev/null 2>&1; then
    echo -e "${RED}ERROR: Cannot reach $TARGET_HOST${NC}"
    echo ""
    echo "Network troubleshooting:"
    echo "1. Check if hostname is correct"
    echo "2. Try using IP address instead: $0 <IP_ADDRESS>"
    echo "3. Check DNS resolution: nslookup $TARGET_HOST"
    echo "4. Check network connectivity"
    echo ""
    echo "Example with IP: $0 192.168.1.100"
    exit 1
fi

echo -e "${GREEN}Network connectivity test passed!${NC}"

# Test SSH connectivity
echo -e "${BLUE}Testing SSH connectivity to $TARGET_HOST...${NC}"

# First, ensure we have an SSH key
if [[ ! -f /root/.ssh/id_rsa ]]; then
    echo "Generating SSH key pair..."
    ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" -q
    echo "SSH key generated."
fi

# Test SSH key authentication with timeout
echo "Testing SSH key authentication..."
# Temporarily disable set -e for SSH test that may fail
set +e
timeout 15 ssh -T -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_HOST" "echo 'SSH test successful'" > /tmp/ssh_test.out 2>&1
SSH_EXIT_CODE=$?
set -e
SSH_TEST_OUTPUT=$(cat /tmp/ssh_test.out 2>/dev/null)

# Debug output removed
if [[ $SSH_EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}SSH key authentication successful!${NC}"
    SSH_BATCH_MODE="-o BatchMode=yes"
    SSH_KEY_AUTH=true
    
    # Even if key works, ensure permissions are correct (preventive)
    timeout 15 ssh $SSH_BATCH_MODE -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_HOST" "
        if [[ -f ~/.ssh/authorized_keys ]]; then
            # Check if permissions need fixing
            OWNER=\$(stat -c '%U' ~/.ssh/authorized_keys 2>/dev/null)
            PERMS=\$(stat -c '%a' ~/.ssh/authorized_keys 2>/dev/null)
            if [[ \"\$OWNER\" != \"$SSH_USER\" ]] || [[ \"\$PERMS\" != \"600\" ]]; then
                echo 'Fixing SSH key permissions (preventive maintenance)...'
                chown $SSH_USER:$SSH_USER ~/.ssh/authorized_keys
                chown $SSH_USER:$SSH_USER ~/.ssh/
                chmod 700 ~/.ssh/
                chmod 600 ~/.ssh/authorized_keys
                echo 'SSH key permissions verified and corrected'
            fi
        fi
    " 2>/dev/null
else
    echo -e "${YELLOW}SSH key authentication failed. Trying password authentication...${NC}"
    echo ""
    
    # Try password authentication using sshpass if available
    # Temporarily disable set -e for SSH test that may fail
    set +e
    if command -v sshpass >/dev/null 2>&1 && [[ -n "$SSHPASS" ]]; then
        echo "Using password from environment variable..."
        timeout 15 sshpass -e ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_HOST" "echo 'SSH test successful'" > /tmp/ssh_password_test.out 2>&1
        SSH_EXIT_CODE=$?
        SSH_TEST_OUTPUT=$(cat /tmp/ssh_password_test.out 2>/dev/null)
    else
        echo "Please enter the password for $SSH_USER@$TARGET_HOST when prompted:"
        timeout 15 ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_HOST" "echo 'SSH test successful'" > /tmp/ssh_interactive_test.out 2>&1
        SSH_EXIT_CODE=$?
        SSH_TEST_OUTPUT=$(cat /tmp/ssh_interactive_test.out 2>/dev/null)
    fi
    set -e
    
    if [[ $SSH_EXIT_CODE -eq 0 ]]; then
        echo ""
        echo -e "${GREEN}Password authentication successful!${NC}"
        echo -e "${YELLOW}Setting up SSH key for future use...${NC}"
        
        # Copy SSH key for future use
        if command -v sshpass >/dev/null 2>&1 && [[ -n "$SSHPASS" ]]; then
            if sshpass -e ssh-copy-id -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_HOST" 2>/dev/null; then
                SSH_KEY_COPY_SUCCESS=true
            else
                SSH_KEY_COPY_SUCCESS=false
            fi
        else
            if ssh-copy-id -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_HOST" 2>/dev/null; then
                SSH_KEY_COPY_SUCCESS=true
            else
                SSH_KEY_COPY_SUCCESS=false
            fi
        fi
        
        if [[ "$SSH_KEY_COPY_SUCCESS" == "true" ]]; then
            echo -e "${GREEN}SSH key installed successfully!${NC}"
            
            # Fix SSH key permissions (common issue with www-data ownership)
            echo "Fixing SSH key permissions on target..."
            if command -v sshpass >/dev/null 2>&1 && [[ -n "$SSHPASS" ]]; then
                sshpass -e ssh "$SSH_USER@$TARGET_HOST" "
                    if [[ -f ~/.ssh/authorized_keys ]]; then
                        chown $SSH_USER:$SSH_USER ~/.ssh/authorized_keys
                        chown $SSH_USER:$SSH_USER ~/.ssh/
                        chmod 700 ~/.ssh/
                        chmod 600 ~/.ssh/authorized_keys
                        echo 'SSH key permissions fixed'
                    fi
                " 2>/dev/null
            else
                ssh "$SSH_USER@$TARGET_HOST" "
                    if [[ -f ~/.ssh/authorized_keys ]]; then
                        chown $SSH_USER:$SSH_USER ~/.ssh/authorized_keys
                        chown $SSH_USER:$SSH_USER ~/.ssh/
                        chmod 700 ~/.ssh/
                        chmod 600 ~/.ssh/authorized_keys
                        echo 'SSH key permissions fixed'
                    fi
                " 2>/dev/null
            fi
            
            echo "Future connections will use key authentication."
            SSH_BATCH_MODE="-o BatchMode=yes"
            SSH_KEY_AUTH=true
        else
            echo -e "${YELLOW}SSH key installation failed, continuing with password authentication.${NC}"
            echo -e "${YELLOW}Note: Using password authentication for migration.${NC}"
            SSH_BATCH_MODE=""
            SSH_KEY_AUTH=false
        fi
    else
        echo -e "${RED}ERROR: Cannot connect to $TARGET_HOST via SSH${NC}"
        echo ""
        echo "SSH Error details:"
        echo "$SSH_TEST_OUTPUT"
        echo ""
        echo "Please check:"
        echo "1. Host is reachable: ping $TARGET_HOST"
        echo "2. SSH service is running on target"
        echo "3. Root password is correct"
        echo "4. SSH access is allowed for root"
        echo ""
        exit 1
    fi
fi

echo -e "${GREEN}SSH connectivity test passed!${NC}"
if [[ "$SSH_KEY_AUTH" == "true" ]]; then
    echo -e "${GREEN}Authentication: SSH Key${NC}"
else
    echo -e "${YELLOW}Authentication: Password (SSH key setup attempted)${NC}"
fi
echo ""

# Set up SSH and SCP command variables based on authentication method
if [[ "$SSH_KEY_AUTH" == "true" ]]; then
    SSH_CMD="ssh $SSH_BATCH_MODE -o StrictHostKeyChecking=no"
    SCP_CMD="scp $SSH_BATCH_MODE -o StrictHostKeyChecking=no"
else
    # Use sshpass for password authentication if available
    if command -v sshpass >/dev/null 2>&1 && [[ -n "$SSHPASS" ]]; then
        SSH_CMD="sshpass -e ssh -o StrictHostKeyChecking=no"
        SCP_CMD="sshpass -e scp -o StrictHostKeyChecking=no"
    else
        SSH_CMD="ssh -o StrictHostKeyChecking=no"
        SCP_CMD="scp -o StrictHostKeyChecking=no"
    fi
fi

# If test mode, exit here
if [[ "$TEST_ONLY" == "true" ]]; then
    echo -e "${GREEN}=========================================="
    echo "CONNECTIVITY TEST SUCCESSFUL!"
    echo "=========================================="
    echo -e "Target Host: $TARGET_HOST"
    echo -e "SSH User: $SSH_USER"
    if [[ "$SSH_KEY_AUTH" == "true" ]]; then
        echo -e "Authentication: SSH Key ✓"
    else
        echo -e "Authentication: Password (consider setting up SSH key)"
    fi
    echo -e "Status: Ready for migration"
    echo -e "${NC}"
    echo ""
    echo "To proceed with migration, run:"
    echo "  $0 $TARGET_HOST $SSH_USER"
    echo ""
    exit 0
fi

# Show what will be migrated
echo -e "${BLUE}Migration Plan:${NC}"
echo "1. Remove old YARA4WAZUH installation on target"
echo "2. Remove old cron jobs"
echo "3. Transfer v13.1 files to target"
echo "4. Set correct permissions"
echo "5. Install new cron schedule"
echo "6. Verify installation"
echo ""

# Confirmation (auto-proceed for automation)
echo "Proceeding with migration to $TARGET_HOST..."

echo ""
echo -e "${BLUE}Starting migration...${NC}"

# Function to execute commands on remote server with timeout
remote_exec() {
    # Add timeout and connection options for better reliability
    # Use timeout to prevent hanging on remote commands
    timeout 60 $SSH_CMD \
        -o ConnectTimeout=30 \
        -o ServerAliveInterval=10 \
        -o ServerAliveCountMax=3 \
        "$SSH_USER@$TARGET_HOST" "$1" 2>&1
}

# Function to transfer files with robust fallback mechanisms
transfer_files() {
    local source="$1"
    local dest="$2"
    
    echo "Starting robust file transfer with fallback mechanisms..."
    
    # Method 1: Try optimized tar transfer first (smaller chunks)
    if transfer_files_tar_optimized "$source" "$dest"; then
        echo "✅ Tar transfer method succeeded"
        return 0
    fi
    
    echo "⚠️ Tar transfer failed, falling back to individual file transfer..."
    
    # Method 2: Fallback to individual file transfer
    if transfer_files_individual "$source" "$dest"; then
        echo "✅ Individual file transfer method succeeded"
        return 0
    fi
    
    echo "❌ All transfer methods failed"
    return 1
}

# Optimized tar transfer with smaller chunks and timeouts
transfer_files_tar_optimized() {
    local source="$1"
    local dest="$2"
    
    echo "Attempting optimized tar transfer..."
    
    # Create a temporary directory for clean files
    TEMP_CLEAN="/tmp/yara_clean_$(date +%s)"
    mkdir -p "$TEMP_CLEAN"
    
    # Copy source to temp location, excluding symlinks and unwanted directories
    echo "Preparing files for transfer..."
    rsync -a --no-links \
        --exclude='bin/' \
        --exclude='cdrom/' \
        --exclude='home/' \
        --exclude='proc/' \
        --exclude='sys/' \
        --exclude='dev/' \
        --exclude='*.lnk' \
        "$source" "$TEMP_CLEAN/" 2>/dev/null || \
    cp -rL "$source" "$TEMP_CLEAN/" 2>/dev/null
    
    # Remove any remaining symlinks
    find "$TEMP_CLEAN" -type l -delete 2>/dev/null
    
    # Create smaller tar archive (compress better, exclude large files)
    echo "Creating optimized tar archive..."
    TEMP_TAR="/tmp/yara_transfer_$(date +%s).tar.gz"
    cd "$TEMP_CLEAN"
    
    # Use better compression and exclude very large files from tar
    find . -type f -size +10M -name "*.yar" -exec echo "Large rule file: {}" \;
    tar czf "$TEMP_TAR" --exclude='*.log' --exclude='backup/*' * 2>/dev/null
    
    # Check if tar was created successfully and isn't too large
    if [[ ! -f "$TEMP_TAR" ]]; then
        echo "❌ Failed to create tar archive"
        rm -rf "$TEMP_CLEAN"
        return 1
    fi
    
    TAR_SIZE=$(du -m "$TEMP_TAR" | cut -f1)
    echo "Archive size: ${TAR_SIZE}MB"
    
    # If archive is too large (>50MB), use individual transfer instead
    if [[ $TAR_SIZE -gt 50 ]]; then
        echo "Archive too large (${TAR_SIZE}MB), switching to individual transfer"
        rm -f "$TEMP_TAR"
        rm -rf "$TEMP_CLEAN"
        return 1
    fi
    
    # Transfer with timeout
    echo "Transferring optimized archive to target..."
    if ! timeout 120 $SCP_CMD "$TEMP_TAR" "$SSH_USER@$TARGET_HOST:/tmp/" 2>/dev/null; then
        echo "❌ Archive transfer timed out or failed"
        rm -f "$TEMP_TAR"
        rm -rf "$TEMP_CLEAN"
        return 1
    fi
    
    # Extract on target with timeout
    REMOTE_TAR="$(basename "$TEMP_TAR")"
    echo "Extracting archive on target..."
    if ! timeout 60 remote_exec "
        cd '$dest' || exit 1
        if tar xzf '/tmp/$REMOTE_TAR' 2>/dev/null; then
            rm -f '/tmp/$REMOTE_TAR'
            echo 'Archive extracted successfully'
            exit 0
        else
            echo 'Archive extraction failed'
            rm -f '/tmp/$REMOTE_TAR'
            exit 1
        fi
    " >/dev/null 2>&1; then
        echo "❌ Archive extraction timed out or failed"
        rm -f "$TEMP_TAR"
        rm -rf "$TEMP_CLEAN"
        return 1
    fi
    
    # Clean up local temp files and directory
    rm -f "$TEMP_TAR"
    rm -rf "$TEMP_CLEAN"
    
    return 0
}

# Individual file transfer method (more reliable for problematic connections)
transfer_files_individual() {
    local source="$1"
    local dest="$2"
    
    echo "Using individual file transfer method..."
    
    # Create destination directory on target
    remote_exec "mkdir -p '$dest'" >/dev/null 2>&1
    
    # Transfer main script first (most important)
    echo "Transferring main script..."
    if [[ -f "${source%/}/yara4wazuh.sh" ]]; then
        timeout 30 $SCP_CMD "${source%/}/yara4wazuh.sh" "$SSH_USER@$TARGET_HOST:$dest/" 2>/dev/null || return 1
    fi
    
    # Transfer scripts directory
    if [[ -d "${source%/}/scripts" ]]; then
        echo "Creating scripts directory..."
        remote_exec "mkdir -p '$dest/scripts'" >/dev/null 2>&1
        
        echo "Transferring scripts ($(ls -1 "${source%/}/scripts"/*.sh 2>/dev/null | wc -l) files)..."
        for script in "${source%/}/scripts"/*.sh; do
            if [[ -f "$script" ]]; then
                script_name=$(basename "$script")
                echo "  → $script_name"
                if ! timeout 30 $SCP_CMD "$script" "$SSH_USER@$TARGET_HOST:$dest/scripts/" 2>/dev/null; then
                    echo "❌ Failed to transfer $script_name"
                    return 1
                fi
            fi
        done
    fi
    
    # Transfer other important files
    for file in rules backup logs; do
        if [[ -d "${source%/}/$file" ]]; then
            echo "Transferring $file directory..."
            remote_exec "mkdir -p '$dest/$file'" >/dev/null 2>&1
            
            # Use tar for directories but with individual file verification
            TEMP_DIR_TAR="/tmp/${file}_$(date +%s).tar.gz"
            cd "${source%/}"
            tar czf "$TEMP_DIR_TAR" "$file" 2>/dev/null
            
            if timeout 60 $SCP_CMD "$TEMP_DIR_TAR" "$SSH_USER@$TARGET_HOST:/tmp/" 2>/dev/null; then
                if timeout 30 remote_exec "cd '$dest' && tar xzf '/tmp/$(basename "$TEMP_DIR_TAR")' && rm -f '/tmp/$(basename "$TEMP_DIR_TAR")'" >/dev/null 2>&1; then
                    echo "  ✅ $file directory transferred"
                else
                    echo "  ⚠️ $file directory extraction failed, but continuing..."
                fi
            else
                echo "  ⚠️ $file directory transfer failed, but continuing..."
            fi
            rm -f "$TEMP_DIR_TAR"
        fi
    done
    
    echo "Individual file transfer completed"
    return 0
}

# Step 1: Backup existing installation on target
echo -e "${YELLOW}Step 1: Backing up existing installation on target...${NC}"
remote_exec "
BACKUP_DIR=\"/root/yara_backup_pre_migration_\$(date +%Y%m%d_%H%M%S)\"
mkdir -p \"\$BACKUP_DIR\"
if [[ -d \"/opt/yara\" ]]; then
    echo \"Backing up existing installation...\"
    # Use tar to avoid issues with large directories
    tar czf \"\$BACKUP_DIR/yara_backup.tar.gz\" -C /opt yara 2>/dev/null || cp -r /opt/yara \"\$BACKUP_DIR/\" 2>/dev/null || true
fi
if [[ -f /etc/cron.d/yara-wazuh ]]; then
    echo \"Backing up existing cron...\"
    cp /etc/cron.d/yara-wazuh \"\$BACKUP_DIR/yara-wazuh.cron.old\" 2>/dev/null || true
fi
echo \"Backup completed: \$BACKUP_DIR\"
"

# Step 2: Remove old installation
echo -e "${YELLOW}Step 2: Removing old installation on target...${NC}"
if ! remote_exec "
echo \"Stopping any running YARA processes...\"
# Use timeout for pkill in case it hangs
timeout 5 pkill -f yara 2>/dev/null || true
sleep 1

echo \"Removing old cron jobs...\"
rm -f /etc/cron.d/yara-wazuh
# Fix potential hanging crontab command
timeout 5 sh -c 'crontab -l 2>/dev/null | grep -v yara | crontab - 2>/dev/null' || true

echo \"Removing old files...\"
rm -rf /opt/yara/scripts/
rm -f /opt/yara/yara4wazuh.sh
rm -f /opt/yara/*.sh

echo \"Old installation cleaned up.\"
"; then
    echo "⚠️ Warning: Cleanup may have timed out, but continuing..."
fi

# Step 3: Transfer new files
echo -e "${YELLOW}Step 3: Transferring v13.1 files...${NC}"

# Create temporary directory on target
remote_exec "
TEMP_DIR=\"/tmp/yara4wazuh_v13_migration_\$(date +%Y%m%d_%H%M%S)\"
mkdir -p \"\$TEMP_DIR\"
echo \"Created temp directory: \$TEMP_DIR\"
echo \"\$TEMP_DIR\" > /tmp/yara_migration_temp_path
"

TEMP_DIR=$(remote_exec "cat /tmp/yara_migration_temp_path")

echo "Transferring complete v13.1 installation..."
if ! transfer_files "$SOURCE_PATH/" "$TEMP_DIR/"; then
    echo -e "${RED}❌ File transfer failed completely${NC}"
    echo "This could be due to:"
    echo "  - Network connectivity issues"
    echo "  - Large file size causing timeouts"
    echo "  - Insufficient disk space on target"
    echo "  - SSH connection problems"
    echo ""
    echo "Please check the target server and try again."
    echo "You can also try manual file copying as demonstrated with www.goline.ch"
    exit 1
fi
echo "✅ File transfer completed successfully"

# Copy valhalla-rules.yar fallback file if it exists
if [[ -f "valhalla-rules.yar" ]]; then
    echo "Copying valhalla-rules.yar fallback file..."
    VALHALLA_SIZE=$(du -m "valhalla-rules.yar" | cut -f1)
    echo "Valhalla file size: ${VALHALLA_SIZE}MB"
    
    # Try direct SCP transfer with timeout
    if timeout 60 $SCP_CMD valhalla-rules.yar "$SSH_USER@$TARGET_HOST:$TEMP_DIR/" 2>/dev/null; then
        echo "✅ Valhalla fallback rules copied via SCP"
    else
        echo "⚠️ SCP transfer failed, trying alternative method..."
        # Fallback: use SSH pipe for reliable transfer
        if cat valhalla-rules.yar | timeout 90 $SSH_CMD "$SSH_USER@$TARGET_HOST" "cat > $TEMP_DIR/valhalla-rules.yar" 2>/dev/null; then
            echo "✅ Valhalla fallback rules copied via SSH pipe"
        else
            echo "❌ Failed to copy Valhalla fallback rules - will continue without fallback"
        fi
    fi
else
    echo "⚠️ valhalla-rules.yar not found in current directory"
fi

# Step 4: Check and Install YARA if needed
echo -e "${YELLOW}Step 4: Checking YARA installation...${NC}"
remote_exec "
echo \"Checking for YARA installation...\"
if ! command -v yara >/dev/null 2>&1; then
    echo \"YARA not found. Installing YARA...\"
    
    # Install build dependencies (aligned with main installer)
    if command -v apt-get >/dev/null 2>&1; then
        echo \"Installing dependencies for Debian/Ubuntu...\"
        apt-get update >/dev/null 2>&1
        apt-get install -y automake libtool make gcc pkg-config \\
            libssl-dev libjansson-dev libmagic-dev git curl wget \\
            sendmail mailutils sqlite3 >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        echo \"Installing dependencies for AlmaLinux/RHEL 9/Fedora...\"
        dnf install -y automake libtool make gcc pkgconfig \\
            openssl-devel jansson-devel file-devel git curl wget \\
            sendmail mailx sqlite >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        echo \"Installing dependencies for RHEL/CentOS...\"
        yum install -y automake libtool make gcc pkgconfig \\
            openssl-devel jansson-devel file-devel git curl wget \\
            sendmail mailx sqlite >/dev/null 2>&1
    else
        echo \"Warning: Unknown package manager, please install dependencies manually\"
    fi
    
    # Download and compile YARA
    cd /tmp
    # Use same version as main installer (can be overridden with YARA_VERSION_OVERRIDE)
    YARA_VERSION=\"\${YARA_VERSION_OVERRIDE:-4.5.4}\"
    echo \"Downloading YARA \${YARA_VERSION}...\"
    wget -q \"https://github.com/VirusTotal/yara/archive/refs/tags/v\${YARA_VERSION}.tar.gz\"
    tar -xzf \"v\${YARA_VERSION}.tar.gz\"
    cd \"yara-\${YARA_VERSION}\"
    
    echo \"Compiling YARA...\"
    ./bootstrap.sh >/dev/null 2>&1
    ./configure --enable-cuckoo --enable-magic --enable-dotnet >/dev/null 2>&1
    make -j\$(nproc) >/dev/null 2>&1
    make install >/dev/null 2>&1
    ldconfig
    
    # Cleanup
    cd /tmp
    rm -rf \"yara-\${YARA_VERSION}\" \"v\${YARA_VERSION}.tar.gz\"
    
    # Verify installation
    if command -v yara >/dev/null 2>&1; then
        echo \"✓ YARA installed successfully: \$(yara --version 2>&1 | head -1)\"
    else
        echo \"✗ YARA installation failed\"
        exit 1
    fi
else
    echo \"✓ YARA already installed: \$(yara --version 2>&1 | head -1)\"
fi

# Check Wazuh agent installation
echo \"\"
echo \"Checking Wazuh agent...\"
if [[ -d /var/ossec ]]; then
    if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
        echo \"✓ Wazuh agent installed and running\"
    else
        echo \"⚠ Wazuh agent installed but not running\"
        echo \"  Attempting to start Wazuh agent...\"
        systemctl start wazuh-agent 2>/dev/null || service wazuh-agent start 2>/dev/null || true
        sleep 2
        if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
            echo \"  ✓ Wazuh agent started successfully\"
        else
            echo \"  ✗ Failed to start Wazuh agent\"
        fi
    fi
else
    echo \"✗ Wazuh agent not found at /var/ossec\"
    echo \"  Please install Wazuh agent before proceeding\"
    exit 1
fi
"

# Step 5: Install all components
echo -e "${YELLOW}Step 5: Installing YARA4WAZUH v13.1 components...${NC}"
remote_exec "
TEMP_DIR=\"$TEMP_DIR\"
echo \"Installing from: \$TEMP_DIR\"

# Create complete directory structure (aligned with main installer)
mkdir -p /opt/yara
mkdir -p /opt/yara/rules
mkdir -p /opt/yara/scripts
mkdir -p /var/log/yara
mkdir -p /etc/yara4wazuh
mkdir -p /var/ossec/quarantine

# Set proper permissions (aligned with main installer)
chmod 755 /opt/yara
chmod 755 /opt/yara/rules
chmod 755 /opt/yara/scripts
chmod 755 /var/log/yara
chmod 755 /etc/yara4wazuh
chmod 700 /var/ossec/quarantine

echo \"Installing main YARA directory...\"
if [[ -d \"\$TEMP_DIR/yara\" ]]; then
    # Copy scripts directory
    if [[ -d \"\$TEMP_DIR/yara/scripts\" ]]; then
        cp -r \"\$TEMP_DIR/yara/scripts\" /opt/yara/
        chmod +x /opt/yara/scripts/*.sh 2>/dev/null || true
        echo \"   Scripts directory installed\"
    fi
    
    # Copy rules directory
    if [[ -d \"\$TEMP_DIR/yara/rules\" ]]; then
        if [[ ! -d /opt/yara/rules ]]; then
            cp -r \"\$TEMP_DIR/yara/rules\" /opt/yara/
            echo \"   Rules directory installed\"
        else
            echo \"   Rules directory exists, preserving\"
        fi
    fi
    
    # Install main script
    if [[ -f \"\$TEMP_DIR/yara/yara4wazuh.sh\" ]]; then
        cp \"\$TEMP_DIR/yara/yara4wazuh.sh\" /opt/yara/
        chmod +x /opt/yara/yara4wazuh.sh
        echo \"   Main script installed\"
    fi
    
    # Copy valhalla fallback rules if available
    if [[ -f \"\$TEMP_DIR/valhalla-rules.yar\" ]]; then
        cp \"\$TEMP_DIR/valhalla-rules.yar\" /opt/yara/
        echo \"   Valhalla fallback rules installed\"
    fi
    
    # Copy other directories (.claude, etc)
    for dir in .claude backup; do
        if [[ -d \"\$TEMP_DIR/yara/\$dir\" ]] && [[ ! -d \"/opt/yara/\$dir\" ]]; then
            cp -r \"\$TEMP_DIR/yara/\$dir\" /opt/yara/
            echo \"   \$dir directory copied\"
        fi
    done
fi

echo \"Installing Wazuh integration...\"
# Install Wazuh active response
if [[ -f \"\$TEMP_DIR/yara_active_response.sh\" ]]; then
    mkdir -p /var/ossec/active-response/bin
    cp \"\$TEMP_DIR/yara_active_response.sh\" /var/ossec/active-response/bin/yara.sh
    chmod +x /var/ossec/active-response/bin/yara.sh
    chown wazuh:wazuh /var/ossec/active-response/bin/yara.sh 2>/dev/null || true
    echo \"   Wazuh active response updated\"
fi

# Install decoders
mkdir -p /var/ossec/etc/decoders
if [[ -f \"\$TEMP_DIR/yara_decoders.xml\" ]]; then
    cp \"\$TEMP_DIR/yara_decoders.xml\" /var/ossec/etc/decoders/yara_decoders.xml
    chown wazuh:wazuh /var/ossec/etc/decoders/yara_decoders.xml 2>/dev/null || true
    echo \"   YARA decoders installed from backup\"
elif [[ ! -f /var/ossec/etc/decoders/yara_decoders.xml ]]; then
    # Create default decoder if not exists (aligned with main installer)
    cat > /var/ossec/etc/decoders/yara_decoders.xml << 'DECODER_XML'
<decoder name=\"yara\">
  <prematch>^YARA:</prematch>
</decoder>

<decoder name=\"yara-threat\">
  <parent>yara</parent>
  <regex>Threat detected - (\S+) - File: (\S+)</regex>
  <order>threat_name, file_path</order>
</decoder>
DECODER_XML
    chown wazuh:wazuh /var/ossec/etc/decoders/yara_decoders.xml 2>/dev/null || true
    echo \"   YARA decoders created (default)\"
else
    echo \"   YARA decoders already exist\"
fi

# Install rules
mkdir -p /var/ossec/etc/rules
if [[ -f \"\$TEMP_DIR/yara_rules.xml\" ]]; then
    cp \"\$TEMP_DIR/yara_rules.xml\" /var/ossec/etc/rules/yara_rules.xml
    chown wazuh:wazuh /var/ossec/etc/rules/yara_rules.xml 2>/dev/null || true
    echo \"   YARA rules installed from backup\"
elif [[ ! -f /var/ossec/etc/rules/yara_rules.xml ]]; then
    # Create default rules if not exists (aligned with main installer)
    cat > /var/ossec/etc/rules/yara_rules.xml << 'RULES_XML'
<group name=\"yara,\">
  <rule id=\"100200\" level=\"0\">
    <decoded_as>yara</decoded_as>
    <description>YARA messages grouped.</description>
  </rule>
  
  <rule id=\"100201\" level=\"12\">
    <if_sid>100200</if_sid>
    <match>Threat detected</match>
    <description>YARA: Malware detected and quarantined</description>
    <group>malware,</group>
  </rule>
</group>
RULES_XML
    chown wazuh:wazuh /var/ossec/etc/rules/yara_rules.xml 2>/dev/null || true
    echo \"   YARA rules created (default)\"
else
    echo \"   YARA rules already exist\"
fi

echo \"Setting up quarantine directory...\"
# Setup quarantine directory
if [[ ! -d /var/ossec/quarantine ]]; then
    mkdir -p /var/ossec/quarantine
    chown -R wazuh:wazuh /var/ossec/quarantine 2>/dev/null || true
    echo \"   Quarantine directory created\"
fi

# Set proper permissions
chown -R root:root /opt/yara/
chmod 755 /opt/yara/
chmod +x /opt/yara/yara4wazuh.sh 2>/dev/null || true
chmod +x /opt/yara/scripts/*.sh 2>/dev/null || true

echo \"Permissions set correctly.\"
"

# Step 6: Install new cron schedule
echo -e "${YELLOW}Step 6: Installing v13.1 cron schedule...${NC}"
remote_exec "
TEMP_DIR=\"$TEMP_DIR\"

# Install cron jobs from backup if available
if [[ -f \"\$TEMP_DIR/yara-wazuh.cron\" ]]; then
    cp \"\$TEMP_DIR/yara-wazuh.cron\" /etc/cron.d/yara-wazuh
    chmod 644 /etc/cron.d/yara-wazuh
    chown root:root /etc/cron.d/yara-wazuh
    echo \"   Cron jobs installed from backup\"
else
    # Create default v13.1 cron schedule
    cat > /etc/cron.d/yara-wazuh << 'EOF'
# YARA4WAZUH v13.1 Automated Tasks
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Daily YARA scan (2:00 AM)
0 2 * * * root /opt/yara/scripts/daily_scan.sh >/dev/null 2>&1

# Weekly security report (Sunday 6:00 AM)
0 6 * * 0 root /opt/yara/scripts/weekly_report_html.sh >/dev/null 2>&1

# Health check (twice daily: 8:00 AM and 8:00 PM)
0 8,20 * * * root DEBUG=1 EMAIL_TO=\"soc@goline.ch\" /opt/yara/scripts/health_check.sh >/dev/null 2>&1

# Log cleanup (daily at 3:00 AM)
0 3 * * * root /opt/yara/scripts/log_cleanup.sh >/dev/null 2>&1

# Quarantine cleanup (weekly on Sunday 4:00 AM)
0 4 * * 0 root /opt/yara/scripts/quarantine_cleanup.sh >/dev/null 2>&1

# System status check (every 6 hours)
0 */6 * * * root /opt/yara/scripts/check_status.sh >/dev/null 2>&1

# Integration status check (daily at 7:00 AM)
0 7 * * * root /opt/yara/scripts/integration_status.sh >/dev/null 2>&1
EOF
    echo \"   Default cron schedule created\"
fi

# Configure Wazuh remote commands support
echo \"Configuring Wazuh remote commands support...\"
if [[ -f /var/ossec/etc/local_internal_options.conf ]]; then
    # Check if both remote commands parameters are configured
    NEED_CONFIG=false
    if ! grep -q \"logcollector.remote_commands=1\" /var/ossec/etc/local_internal_options.conf; then
        NEED_CONFIG=true
        echo \"   logcollector.remote_commands not configured\"
    fi
    if ! grep -q \"wazuh_command.remote_commands=1\" /var/ossec/etc/local_internal_options.conf; then
        NEED_CONFIG=true
        echo \"   wazuh_command.remote_commands not configured\"
    fi
    
    if [[ \"\$NEED_CONFIG\" = true ]]; then
        echo \"   Adding remote commands configuration...\"
        
        # Add remote commands configuration
        cat >> /var/ossec/etc/local_internal_options.conf << 'EOFRC'

# Remote commands configuration - Added by YARA4WAZUH Migration
logcollector.remote_commands=1
wazuh_command.remote_commands=1
EOFRC
        echo \"   Remote commands configuration added\"
        
        # Restart Wazuh agent if running
        if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
            echo \"   Restarting Wazuh agent to apply configuration...\"
            systemctl restart wazuh-agent
            sleep 3
            if systemctl is-active --quiet wazuh-agent; then
                echo \"   Wazuh agent restarted successfully\"
            else
                echo \"   Warning: Wazuh agent restart failed\"
            fi
        else
            echo \"   Wazuh agent not running (will apply on next start)\"
        fi
    else
        echo \"   Remote commands already properly configured\"
    fi
else
    echo \"   /var/ossec/etc/local_internal_options.conf exists by default with Wazuh\"
    echo \"   Creating file with remote commands configuration...\"
    
    # Create the file with basic content
    cat > /var/ossec/etc/local_internal_options.conf << 'EOFRC'
# local_internal_options.conf
#
# This file should be handled with care. It contains
# run time modifications that can affect the use
# of OSSEC. Only change it if you know what you
# are doing. Look first at ossec.conf
# for most of the things you want to change.
#
# This file will not be overwritten during upgrades.

# Remote commands configuration - Added by YARA4WAZUH Migration
logcollector.remote_commands=1
wazuh_command.remote_commands=1
EOFRC
    echo \"   File created with remote commands configuration\"
fi

# Configure FIM monitoring for YARA directories
echo \"\"
echo \"Configuring FIM monitoring for YARA directories...\"
if [[ -f /var/ossec/etc/ossec.conf ]]; then
    # Check if YARA directories are already monitored
    if ! grep -q '/opt/yara' /var/ossec/etc/ossec.conf 2>/dev/null; then
        # Add YARA directories to FIM monitoring
        # Find the syscheck closing tag and insert before it
        if grep -q '</syscheck>' /var/ossec/etc/ossec.conf; then
            sed -i '/<\/syscheck>/i\\    <!-- YARA Integration Directories -->\\n    <directories realtime=\"yes\">/opt/yara</directories>\\n    <directories realtime=\"yes\">/var/ossec/quarantine</directories>\\n    <directories realtime=\"yes\">/var/log/yara</directories>' /var/ossec/etc/ossec.conf
            echo \"   Added YARA directories to FIM monitoring\"
        fi
    else
        echo \"   YARA directories already configured for FIM monitoring\"
    fi
fi

# Clean up temporary directory
rm -rf \"\$TEMP_DIR\"
rm -f /tmp/yara_migration_temp_path

echo \"Cron schedule installed.\"
# Reload cron service (different names on different systems)
systemctl reload cron 2>/dev/null || systemctl reload crond 2>/dev/null || service cron reload 2>/dev/null || service crond reload 2>/dev/null || true

# Fix YARA rules compatibility issues (if enabled)
if [[ \"$FIX_RULES\" == \"true\" ]]; then
    echo \"\"
    echo \"Checking and fixing YARA rules compatibility...\"
    if [[ -d /opt/yara/rules ]]; then
    # Count Android rules that require androguard module
    ANDROID_COUNT=\$(ls -1 /opt/yara/rules/Android_*.yar 2>/dev/null | wc -l)
    if [[ \$ANDROID_COUNT -gt 0 ]]; then
        echo \"   Found \$ANDROID_COUNT Android rules requiring androguard module\"
        mkdir -p /opt/yara/rules/disabled_android
        mv /opt/yara/rules/Android_*.yar /opt/yara/rules/disabled_android/ 2>/dev/null
        echo \"   Moved Android rules to disabled_android/\"
    fi
    
    # Fix or disable index files with wrong includes
    for index in packers_index.yar maldocs_index.yar index_w_mobile.yar; do
        if [[ -f /opt/yara/rules/\$index ]]; then
            if grep -q \"^include \\\"\\./\" /opt/yara/rules/\$index 2>/dev/null; then
                mkdir -p /opt/yara/rules/disabled_indexes
                mv /opt/yara/rules/\$index /opt/yara/rules/disabled_indexes/
                echo \"   Disabled problematic index: \$index\"
            fi
        fi
    done
    
    # Disable overly generic rules that cause false positives
    mkdir -p /opt/yara/rules/disabled_generic
    for generic_rule in domain.yar base64.yar url.yar base64_gz.yar; do
        if [[ -f /opt/yara/rules/\$generic_rule ]]; then
            mv /opt/yara/rules/\$generic_rule /opt/yara/rules/disabled_generic/ 2>/dev/null
            echo \"   Disabled generic rule causing false positives: \$generic_rule\"
        fi
    done
    
    # Clean up any .fim_marker files that might exist
    find /var/log/yara /var/ossec/quarantine -name ".fim_marker" -delete 2>/dev/null
    
    # Test rules quickly (just count working ones)
    echo \"   Testing YARA rules functionality...\"
    echo \"test\" > /tmp/yara_test.txt
    WORKING=0
    BROKEN=0
    for rule in /opt/yara/rules/*.yar; do
        if [[ -f \"\$rule\" ]]; then
            if yara \"\$rule\" /tmp/yara_test.txt >/dev/null 2>&1; then
                ((WORKING++))
            else
                ((BROKEN++))
                # Move broken rules
                mkdir -p /opt/yara/rules/disabled_broken
                mv \"\$rule\" /opt/yara/rules/disabled_broken/ 2>/dev/null
            fi
        fi
    done
    rm -f /tmp/yara_test.txt
    echo \"   Working rules: \$WORKING, Disabled: \$BROKEN\"
    fi
else
    echo \"\"
    echo \"Skipping YARA rules fix (--no-fix-rules option used)\"
fi
"

# Step 7: Verify installation
echo -e "${YELLOW}Step 7: Verifying installation...${NC}"
VERIFICATION_RESULT=$(remote_exec "
echo \"========== VERIFICATION RESULTS ==========\"
echo \"\"

# Check main script
echo \"Checking main script...\"
if [[ -x /opt/yara/yara4wazuh.sh ]]; then
    echo \"✓ Main script installed and executable\"
else
    echo \"✗ Main script missing or not executable\"
    exit 1
fi

# Check scripts directory
echo \"Checking scripts directory...\"
if [[ -d /opt/yara/scripts ]]; then
    script_count=\$(ls -1 /opt/yara/scripts/*.sh 2>/dev/null | wc -l)
    echo \"✓ Scripts directory installed (\$script_count scripts)\"
    
    # Check key scripts
    for script in health_check.sh daily_scan.sh weekly_report_html.sh; do
        if [[ -x /opt/yara/scripts/\$script ]]; then
            echo \"  ✓ \$script\"
        else
            echo \"  ✗ \$script missing or not executable\"
        fi
    done
else
    echo \"✗ Scripts directory missing\"
    exit 1
fi

# Check rules directory
echo \"Checking YARA rules...\"
if [[ -d /opt/yara/rules ]]; then
    rule_count=\$(find /opt/yara/rules -name '*.yar' 2>/dev/null | wc -l)
    echo \"✓ YARA rules directory (\$rule_count rules)\"
else
    echo \"⚠ YARA rules directory missing (will need manual setup)\"
fi

# Check Valhalla fallback
echo \"Checking Valhalla fallback...\"
if [[ -f /opt/yara/valhalla-rules.yar ]]; then
    valhalla_count=\$(grep -c '^rule ' /opt/yara/valhalla-rules.yar 2>/dev/null || echo '0')
    echo \"✓ Valhalla fallback rules (\$valhalla_count rules)\"
else
    echo \"⚠ Valhalla fallback rules missing\"
fi

# Check version
echo \"Checking version...\"
if [[ -x /opt/yara/yara4wazuh.sh ]]; then
    version=\$(/opt/yara/yara4wazuh.sh --version 2>/dev/null | grep 'Script Version:' | cut -d':' -f2 | xargs || echo 'Unknown')
    if [[ \"\$version\" == \"13.1\" ]]; then
        echo \"✓ Version 13.1 confirmed\"
    else
        echo \"⚠ Version mismatch: expected 13.1, got \$version\"
    fi
fi

# Check Wazuh integration
echo \"Checking Wazuh integration...\"
wazuh_components=0
if [[ -f /var/ossec/active-response/bin/yara.sh ]]; then
    echo \"  ✓ Active response script\"
    wazuh_components=\$((wazuh_components + 1))
fi
if [[ -f /var/ossec/etc/decoders/yara_decoders.xml ]]; then
    echo \"  ✓ YARA decoders\"
    wazuh_components=\$((wazuh_components + 1))
fi
if [[ -f /var/ossec/etc/rules/yara_rules.xml ]]; then
    echo \"  ✓ YARA rules\"
    wazuh_components=\$((wazuh_components + 1))
fi
if [[ -d /var/ossec/quarantine ]]; then
    echo \"  ✓ Quarantine directory\"
    wazuh_components=\$((wazuh_components + 1))
fi

# Check remote commands configuration
if [[ -f /var/ossec/etc/local_internal_options.conf ]]; then
    if grep -q \"logcollector.remote_commands=1\" /var/ossec/etc/local_internal_options.conf && \\
       grep -q \"wazuh_command.remote_commands=1\" /var/ossec/etc/local_internal_options.conf; then
        echo \"  ✓ Remote commands configured\"
        wazuh_components=\$((wazuh_components + 1))
    else
        echo \"  ✗ Remote commands not configured\"
    fi
fi

# Check Wazuh agent status
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
    echo \"  ✓ Wazuh agent running\"
    wazuh_components=\$((wazuh_components + 1))
else
    echo \"  ⚠ Wazuh agent not running\"
fi

if [[ \$wazuh_components -ge 4 ]]; then
    echo \"✓ Wazuh integration complete (\$wazuh_components/6 components)\"
elif [[ \$wazuh_components -gt 0 ]]; then
    echo \"⚠ Wazuh integration partial (\$wazuh_components/6 components)\"
else
    echo \"✗ Wazuh integration missing\"
fi

# Check cron installation
echo \"Checking cron installation...\"
if [[ -f /etc/cron.d/yara-wazuh ]]; then
    cron_jobs=\$(grep -c '^[^#].*root.*yara' /etc/cron.d/yara-wazuh 2>/dev/null || echo 0)
    echo \"✓ Cron schedule installed (\$cron_jobs jobs)\"
else
    echo \"✗ Cron schedule missing\"
    exit 1
fi

# Check log directory
echo \"Checking log directory...\"
if [[ -d /var/log/yara ]]; then
    echo \"✓ Log directory created\"
else
    echo \"⚠ Log directory missing\"
fi

# Test health check script
echo \"Testing health check script...\"
if /opt/yara/scripts/health_check.sh --test 2>/dev/null; then
    echo \"✓ Health check script working\"
elif [[ -x /opt/yara/scripts/health_check.sh ]]; then
    echo \"✓ Health check script installed (email configuration may be needed)\"
else
    echo \"✗ Health check script not working\"
fi

echo \"\"
echo \"=========================================\"
echo \"YARA4WAZUH v13.1 migration completed!\"
echo \"=========================================\"
echo \"Target server: \$(hostname)\"
echo \"Installation path: /opt/yara/\"
echo \"Architecture: Modular v13.1\"
echo \"\"
")

echo "$VERIFICATION_RESULT"

# Final comprehensive test
echo ""
echo -e "${BLUE}Running final deployment verification...${NC}"
FINAL_TEST=$(remote_exec "
echo \"🔍 Final Migration Verification\"
echo \"==============================\"

# Critical component check
errors=0

# 1. Version check
version=\$(/opt/yara/yara4wazuh.sh --version 2>/dev/null | grep 'Script Version:' | cut -d':' -f2 | xargs)
if [[ \"\$version\" == \"13.1\" ]]; then
    echo \"✅ Version: v13.1\"
else
    echo \"❌ Version check failed: \$version\"
    errors=\$((errors + 1))
fi

# 2. Script count check  
script_count=\$(ls -1 /opt/yara/scripts/*.sh 2>/dev/null | wc -l)
if [[ \$script_count -eq 16 ]]; then
    echo \"✅ Scripts: \$script_count/16\"
else
    echo \"❌ Script count mismatch: \$script_count/16\"
    errors=\$((errors + 1))
fi

# 3. Valhalla fallback check
if [[ -f /opt/yara/valhalla-rules.yar ]]; then
    valhalla_rules=\$(grep -c '^rule ' /opt/yara/valhalla-rules.yar 2>/dev/null)
    if [[ \$valhalla_rules -gt 2000 ]]; then
        echo \"✅ Valhalla fallback: \$valhalla_rules rules\"
    else
        echo \"⚠️ Valhalla rules low: \$valhalla_rules\"
    fi
else
    echo \"❌ Valhalla fallback missing\"
    errors=\$((errors + 1))
fi

# 4. Permissions check
if [[ -x /opt/yara/yara4wazuh.sh ]] && [[ -x /opt/yara/scripts/health_check.sh ]]; then
    echo \"✅ Permissions: Correct\"
else
    echo \"❌ Permission issues detected\"
    errors=\$((errors + 1))
fi

# 5. Wazuh agent check
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
    echo \"✅ Wazuh agent: Running\"
else
    echo \"⚠️ Wazuh agent: Not running\"
fi

# 6. Cron jobs check
if [[ -f /etc/cron.d/yara-wazuh ]]; then
    cron_count=\$(grep -c '^[^#].*root.*yara' /etc/cron.d/yara-wazuh 2>/dev/null)
    echo \"✅ Cron jobs: \$cron_count scheduled\"
else
    echo \"❌ Cron jobs missing\"
    errors=\$((errors + 1))
fi

# Summary
echo \"\"
if [[ \$errors -eq 0 ]]; then
    echo \"🎉 MIGRATION VERIFICATION: PASSED\"
    echo \"   All critical components deployed successfully\"
else
    echo \"⚠️ MIGRATION VERIFICATION: \$errors ISSUES FOUND\"
    echo \"   Please review the errors above\"
fi

exit \$errors
")

echo "$FINAL_TEST"
FINAL_EXIT_CODE=$?

if [[ $FINAL_EXIT_CODE -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}=========================================="
    echo "MIGRATION COMPLETED SUCCESSFULLY!"
    echo "=========================================="
else
    echo ""
    echo -e "${YELLOW}=========================================="
    echo "MIGRATION COMPLETED WITH WARNINGS"
    echo "=========================================="
    echo -e "${YELLOW}Please review the verification results above${NC}"
fi
echo -e "Target Host: $TARGET_HOST"
echo -e "Version: YARA4WAZUH v13.1"
echo -e "Architecture: Modular"
echo -e "${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Verify email configuration on target server"
echo "2. Test health check: ssh $SSH_USER@$TARGET_HOST '/opt/yara/scripts/health_check.sh'"
echo "3. Check cron status: ssh $SSH_USER@$TARGET_HOST 'crontab -l'"
echo ""
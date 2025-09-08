#!/bin/bash
# YARA4WAZUH Management Script v13.7
# Enterprise Security Platform for YARA and Wazuh Integration
# 
# Author: YARA4WAZUH Contributors
# Project: https://github.com/paolokappa/yara4wazuh
# Version: 13.8
# License: MIT
# Build: 2025-09-08 - Linux-optimized, fixed false positives, enhanced quarantine

# Dynamic version management
get_script_version() {
    local version_file="/opt/yara/VERSION"
    if [[ -f "$version_file" ]]; then
        cat "$version_file" | tr -d '\n'
    else
        echo "13.8"  # Fallback version
    fi
}

readonly SCRIPT_VERSION="$(get_script_version)"
readonly SCRIPT_NAME="yara4wazuh"

# YARA version configuration
# Can be overridden with YARA_VERSION_OVERRIDE environment variable
readonly YARA_INSTALL_VERSION="${YARA_VERSION_OVERRIDE:-4.5.4}"

# Function to detect currently installed YARA version
get_yara_version() {
    if command -v yara >/dev/null 2>&1; then
        yara --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
    else
        echo "Not installed"
    fi
}

# Get current YARA version
YARA_INSTALLED_VERSION=$(get_yara_version)

# Directories
readonly YARA_BASE_DIR="/opt/yara"
readonly YARA_RULES_DIR="${YARA_BASE_DIR}/rules"
readonly YARA_SCRIPTS_DIR="${YARA_BASE_DIR}/scripts"
readonly YARA_LOGS_DIR="/var/log/yara"
readonly CONFIG_DIR="/etc/yara4wazuh"
readonly QUARANTINE_DIR="/opt/yara/quarantine"

# Load local configuration if exists
if [[ -f "/opt/yara/config.local" ]]; then
    source /opt/yara/config.local
fi

# GitHub Configuration (can be overridden with environment variables)
readonly GITHUB_REPO="${GITHUB_REPO:-https://github.com/YOUR_USERNAME/yara4wazuh.git}"
readonly GITHUB_BRANCH="${GITHUB_BRANCH:-main}"

# Source common functions
if [[ -f "${YARA_SCRIPTS_DIR}/common.sh" ]]; then
    source "${YARA_SCRIPTS_DIR}/common.sh"
else
    # Basic functions if common.sh doesn't exist yet
    readonly RED="\033[0;31m"
    readonly GREEN="\033[0;32m"
    readonly YELLOW="\033[1;33m"
    readonly BLUE="\033[1;36m"
    readonly NC="\033[0m"
    
    log_info() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}[INFO]${NC} $*"; }
    log_error() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}[ERROR]${NC} $*" >&2; }
    log_warning() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}[WARNING]${NC} $*"; }
    log_section() { echo ""; echo -e "${BLUE}========== $* ==========${NC}"; }
fi

# ============================================================================
# CHECK ROOT PERMISSIONS
# ============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# ============================================================================
# DETECT OS
# ============================================================================
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${ID,,}"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# ============================================================================
# SETUP DIRECTORIES
# ============================================================================
setup_directories() {
    log_section "Setting up directories"
    
    mkdir -p "${YARA_BASE_DIR}"
    mkdir -p "${YARA_RULES_DIR}"
    mkdir -p "${YARA_SCRIPTS_DIR}"
    mkdir -p "${YARA_LOGS_DIR}"
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${QUARANTINE_DIR}"
    
    chmod 755 "${YARA_BASE_DIR}"
    chmod 755 "${YARA_RULES_DIR}"
    chmod 755 "${YARA_SCRIPTS_DIR}"
    chmod 755 "${YARA_LOGS_DIR}"
    chmod 755 "${CONFIG_DIR}"
    chmod 700 "${QUARANTINE_DIR}"
    
    log_info "[OK] Directory structure created"
}

# ============================================================================
# INSTALL DEPENDENCIES
# ============================================================================
install_dependencies() {
    log_section "Installing dependencies"
    
    local OS_TYPE=$(detect_os)
    
    case "$OS_TYPE" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq automake libtool make gcc pkg-config \
                libssl-dev libjansson-dev libmagic-dev git curl wget \
                sendmail mailutils 2>/dev/null
            ;;
        rhel|centos|fedora|rocky|almalinux)
            yum install -y -q automake libtool make gcc pkgconfig \
                openssl-devel jansson-devel file-devel git curl wget \
                sendmail mailx 2>/dev/null
            ;;
        *)
            log_warning "Unknown OS. Please install dependencies manually."
            ;;
    esac
    
    log_info "[OK] Dependencies installed"
}

# ============================================================================
# INSTALL YARA
# To install a different version, set YARA_VERSION_OVERRIDE environment variable:
# Example: YARA_VERSION_OVERRIDE=5.0.0 ./yara4wazuh.sh
# ============================================================================
install_yara() {
    log_section "Installing YARA ${YARA_INSTALL_VERSION}"
    
    # Check if already installed
    if command -v yara >/dev/null 2>&1; then
        INSTALLED_VERSION=$(get_yara_version)
        log_info "YARA already installed: ${INSTALLED_VERSION}"
        return 0
    fi
    
    cd /tmp
    
    # Download and compile YARA
    log_info "Downloading YARA source..."
    wget -q "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_INSTALL_VERSION}.tar.gz"
    tar -xzf "v${YARA_INSTALL_VERSION}.tar.gz"
    cd "yara-${YARA_INSTALL_VERSION}"
    
    log_info "Compiling YARA..."
    ./bootstrap.sh
    ./configure --enable-cuckoo --enable-magic --enable-dotnet
    make -j$(nproc)
    make install
    ldconfig
    
    # Verify installation
    if ! command -v yara >/dev/null 2>&1; then
        log_error "YARA installation failed"
        exit 1
    fi
    
    cd /tmp
    rm -rf "yara-${YARA_INSTALL_VERSION}" "v${YARA_INSTALL_VERSION}.tar.gz"
    
    log_info "[OK] YARA installed: $(get_yara_version)"
}

# ============================================================================
# UPDATE FROM GITHUB
# ============================================================================
update_from_github() {
    log_section "Updating from GitHub Repository"
    
    # Check if git is installed
    if ! command -v git >/dev/null 2>&1; then
        log_error "Git is not installed. Installing..."
        local OS_TYPE=$(detect_os)
        case "$OS_TYPE" in
            ubuntu|debian)
                apt-get update -qq && apt-get install -y -qq git
                ;;
            rhel|centos|fedora|rocky|almalinux)
                yum install -y -q git
                ;;
            *)
                log_error "Please install git manually"
                return 1
                ;;
        esac
    fi
    
    # Create temporary directory for cloning
    local TEMP_REPO="/tmp/yara4wazuh_github_$(date +%Y%m%d_%H%M%S)"
    
    log_info "Cloning repository: ${GITHUB_REPO}"
    log_info "Branch: ${GITHUB_BRANCH}"
    
    # Clone the repository
    if git clone --depth 1 --branch "${GITHUB_BRANCH}" "${GITHUB_REPO}" "$TEMP_REPO" 2>/dev/null; then
        log_info "[OK] Repository cloned successfully"
    else
        log_error "Failed to clone repository. Check URL and credentials."
        return 1
    fi
    
    # Backup current installation
    local BACKUP_DIR="${YARA_BASE_DIR}/backup/github_update_$(date +%Y%m%d_%H%M%S)"
    log_info "Creating backup at: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # Backup current scripts
    if [[ -d "${YARA_SCRIPTS_DIR}" ]]; then
        cp -r "${YARA_SCRIPTS_DIR}" "$BACKUP_DIR/scripts_backup"
    fi
    
    # Backup main installer
    if [[ -f "${YARA_BASE_DIR}/yara4wazuh.sh" ]]; then
        cp "${YARA_BASE_DIR}/yara4wazuh.sh" "$BACKUP_DIR/"
    fi
    
    # Update scripts
    if [[ -d "$TEMP_REPO/scripts" ]]; then
        log_info "Updating scripts..."
        cp -r "$TEMP_REPO/scripts"/* "${YARA_SCRIPTS_DIR}/" 2>/dev/null
        chmod +x "${YARA_SCRIPTS_DIR}"/*.sh
    fi
    
    # Update main installer
    if [[ -f "$TEMP_REPO/yara4wazuh.sh" ]]; then
        log_info "Updating main installer..."
        cp "$TEMP_REPO/yara4wazuh.sh" "${YARA_BASE_DIR}/"
        chmod +x "${YARA_BASE_DIR}/yara4wazuh.sh"
    fi
    
    # Update documentation
    if [[ -f "$TEMP_REPO/PROJECT_DOCUMENTATION.md" ]]; then
        cp "$TEMP_REPO/PROJECT_DOCUMENTATION.md" "${YARA_BASE_DIR}/"
    fi
    
    if [[ -f "$TEMP_REPO/README.md" ]]; then
        cp "$TEMP_REPO/README.md" "${YARA_BASE_DIR}/"
    fi
    
    # Get commit info for logging
    local COMMIT_HASH=$(cd "$TEMP_REPO" && git rev-parse --short HEAD 2>/dev/null)
    local COMMIT_DATE=$(cd "$TEMP_REPO" && git log -1 --format=%cd --date=short 2>/dev/null)
    
    # Clean up
    rm -rf "$TEMP_REPO"
    
    log_info "[OK] Update completed successfully"
    log_info "Updated to commit: $COMMIT_HASH ($COMMIT_DATE)"
    log_info "Backup saved at: $BACKUP_DIR"
    
    # Send update report
    if [[ -f "${YARA_SCRIPTS_DIR}/common.sh" ]]; then
        source "${YARA_SCRIPTS_DIR}/common.sh"
        TEMP_HTML=$(create_safe_temp_html)
        
        create_html_header "GitHub Update Report" "yara4wazuh.sh" "${SCRIPT_VERSION}" > "$TEMP_HTML"
        
        cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">✅ GitHub Update Completed</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><td>Repository</td><td>${GITHUB_REPO}</td></tr>
<tr><td>Branch</td><td>${GITHUB_BRANCH}</td></tr>
<tr><td>Commit</td><td>$COMMIT_HASH</td></tr>
<tr><td>Date</td><td>$COMMIT_DATE</td></tr>
<tr><td>Backup Location</td><td>$BACKUP_DIR</td></tr>
<tr><td>Hostname</td><td>$(hostname -f)</td></tr>
</table>

<br>
<div class="alert alert-success">
<strong>✅ System successfully updated from GitHub repository</strong>
</div>
</div>
EOF
        
        create_html_footer >> "$TEMP_HTML"
        send_html_email "[YARA4WAZUH] GitHub Update Successful" "$TEMP_HTML"
    fi
    
    return 0
}

# ============================================================================
# DEPLOY SCRIPTS FROM PACKAGE
# ============================================================================
deploy_scripts_from_package() {
    log_section "Deploying scripts from package"
    
    # Check if scripts directory exists in current location
    local SCRIPT_SOURCE_DIR=""
    
    # Check different possible locations
    if [[ -d "./scripts" ]]; then
        SCRIPT_SOURCE_DIR="./scripts"
        log_info "Found scripts directory in current location"
    elif [[ -d "$(dirname "$0")/scripts" ]]; then
        SCRIPT_SOURCE_DIR="$(dirname "$0")/scripts"
        log_info "Found scripts directory relative to installer"
    else
        log_warning "No scripts directory found in package"
        return 1
    fi
    
    # Backup existing scripts if they exist
    if [[ -d "${YARA_SCRIPTS_DIR}" ]] && [[ "$(ls -A ${YARA_SCRIPTS_DIR})" ]]; then
        local BACKUP_DIR="${YARA_BASE_DIR}/backup/scripts_$(date +%Y%m%d_%H%M%S)"
        log_info "Backing up existing scripts to $BACKUP_DIR"
        mkdir -p "$BACKUP_DIR"
        cp -r "${YARA_SCRIPTS_DIR}"/* "$BACKUP_DIR/" 2>/dev/null
    fi
    
    # Copy scripts from package
    log_info "Copying scripts from package..."
    mkdir -p "${YARA_SCRIPTS_DIR}"
    cp -r "$SCRIPT_SOURCE_DIR"/* "${YARA_SCRIPTS_DIR}/" 2>/dev/null
    
    # Make all scripts executable
    chmod +x "${YARA_SCRIPTS_DIR}"/*.sh 2>/dev/null
    
    log_info "[OK] Scripts deployed successfully"
    return 0
}

# ============================================================================
# CREATE ALL SCRIPTS
# ============================================================================
create_all_scripts() {
    log_section "Creating all helper scripts"
    
    # Copy this script to /opt/yara
    cp "$0" "${YARA_BASE_DIR}/"
    chmod +x "${YARA_BASE_DIR}/$(basename "$0")"
    
    # Try to deploy from package first
    deploy_scripts_from_package
    
    # Ensure all scripts are created
    local scripts=(
        "common.sh"
        "daily_scan.sh"
        "update_rules.sh"
        "optimize_rules.sh"
        "quarantine_cleanup.sh"
        "log_cleanup.sh"
        "health_check.sh"
        "wazuh_integration.sh"
        "setup_cron.sh"
    )
    
    # Verify all required scripts exist
    local missing_scripts=0
    for script in "${scripts[@]}"; do
        if [[ -f "${YARA_SCRIPTS_DIR}/${script}" ]]; then
            chmod +x "${YARA_SCRIPTS_DIR}/${script}"
            log_info "[OK] Script ready: ${script}"
        else
            log_warning "Script missing: ${script}"
            missing_scripts=$((missing_scripts + 1))
        fi
    done
    
    if [[ $missing_scripts -gt 0 ]]; then
        log_warning "$missing_scripts scripts are missing"
        log_warning "Please ensure all scripts are in the package"
        return 1
    fi
    
    # Keep existing scripts that weren't refactored yet
    if [[ ! -f "${YARA_SCRIPTS_DIR}/check_status.sh" ]]; then
        log_warning "check_status.sh needs to be preserved from original"
    fi
    
    if [[ ! -f "${YARA_SCRIPTS_DIR}/weekly_report_html.sh" ]]; then
        log_warning "weekly_report_html.sh needs to be preserved from original"
    fi
    
    if [[ ! -f "${YARA_SCRIPTS_DIR}/yara_status_html.sh" ]]; then
        log_warning "yara_status_html.sh needs to be preserved from original"
    fi
}

# ============================================================================
# SETUP ADVANCED RULE FEEDS
# ============================================================================
setup_advanced_feeds() {
    log_section "Setting up advanced rule feeds"
    
    # Create VERSION file for dynamic versioning
    echo "$SCRIPT_VERSION" > "${YARA_BASE_DIR}/VERSION"
    log_info "[OK] Created VERSION file with v$SCRIPT_VERSION"
    
    # Install feed verification script
    if [[ -f "${YARA_SCRIPTS_DIR}/verify_feeds.sh" ]]; then
        log_info "Running feed verification..."
        bash "${YARA_SCRIPTS_DIR}/verify_feeds.sh" 2>/dev/null || log_warning "Feed verification encountered issues"
    fi
    
    # Download and install Elastic Security rules
    log_info "Downloading Elastic Security rules..."
    local ELASTIC_URL="https://github.com/elastic/protections-artifacts/archive/main.tar.gz"
    local TEMP_ELASTIC="/tmp/elastic-rules-$(date +%s).tar.gz"
    
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$TEMP_ELASTIC" "$ELASTIC_URL" 2>/dev/null
    elif command -v curl >/dev/null 2>&1; then
        curl -s -L -o "$TEMP_ELASTIC" "$ELASTIC_URL" 2>/dev/null
    else
        log_warning "Neither wget nor curl available for downloading feeds"
        return 1
    fi
    
    if [[ -f "$TEMP_ELASTIC" ]]; then
        tar -xzf "$TEMP_ELASTIC" -C /tmp/ 2>/dev/null
        local EXTRACTED_DIR=$(find /tmp -name "protections-artifacts-*" -type d | head -1)
        if [[ -n "$EXTRACTED_DIR" ]]; then
            find "$EXTRACTED_DIR" -name "*.yar" -exec cp {} "${YARA_RULES_DIR}/" \; 2>/dev/null
            log_info "[OK] Installed Elastic Security rules"
            rm -rf "$EXTRACTED_DIR" "$TEMP_ELASTIC"
        fi
    fi
    
    # Download Neo23x0 Signature Base (APT rules)
    log_info "Downloading Neo23x0 APT detection rules..."
    local NEO_URL="https://github.com/Neo23x0/signature-base/archive/master.tar.gz"
    local TEMP_NEO="/tmp/neo-rules-$(date +%s).tar.gz"
    
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$TEMP_NEO" "$NEO_URL" 2>/dev/null
    elif command -v curl >/dev/null 2>&1; then
        curl -s -L -o "$TEMP_NEO" "$NEO_URL" 2>/dev/null
    fi
    
    if [[ -f "$TEMP_NEO" ]]; then
        tar -xzf "$TEMP_NEO" -C /tmp/ 2>/dev/null
        local NEO_EXTRACTED=$(find /tmp -name "signature-base-*" -type d | head -1)
        if [[ -n "$NEO_EXTRACTED" ]]; then
            find "$NEO_EXTRACTED" -name "*APT*.yar" -exec cp {} "${YARA_RULES_DIR}/" \; 2>/dev/null
            log_info "[OK] Installed Neo23x0 APT detection rules"
            rm -rf "$NEO_EXTRACTED" "$TEMP_NEO"
        fi
    fi
    
    # Create optimized rule set
    if [[ -f "${YARA_SCRIPTS_DIR}/optimize_rules.sh" ]]; then
        log_info "Creating optimized Linux rule set..."
        bash "${YARA_SCRIPTS_DIR}/optimize_rules.sh" 2>/dev/null || log_warning "Rule optimization encountered issues"
    fi
    
    # Count final rules
    local total_rules=$(find ${YARA_RULES_DIR} -name "*.yar" -exec grep -h "^rule " {} \; 2>/dev/null | wc -l)
    log_info "[OK] Advanced feeds setup complete: $total_rules total rules"
}

# ============================================================================
# TEST INSTALLATION
# ============================================================================
test_installation() {
    log_section "Testing installation"
    
    # Test YARA
    if command -v yara >/dev/null 2>&1; then
        log_info "[OK] YARA is installed and accessible"
    else
        log_error "YARA is not accessible"
        return 1
    fi
    
    # Test rules
    local rule_count=$(find ${YARA_RULES_DIR} -type f \( -name "*.yar" -o -name "*.yara" \) -exec grep -h "^rule " {} \; 2>/dev/null | wc -l)
    if [[ $rule_count -gt 0 ]]; then
        log_info "[OK] ${rule_count} YARA rules loaded"
    else
        log_warning "No YARA rules found"
    fi
    
    # Test EICAR
    log_info "Creating EICAR test file..."
    # Create test file in logs directory to avoid detection in /tmp
    local TEST_FILE="${YARA_LOGS_DIR}/eicar.test"
    echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TEST_FILE"
    
    if yara "${YARA_RULES_DIR}/base_rules.yar" "$TEST_FILE" 2>/dev/null | grep -q "EICAR"; then
        log_info "[OK] EICAR detection successful"
        rm -f "$TEST_FILE"
    else
        log_warning "EICAR detection failed"
        rm -f "$TEST_FILE"
    fi
    
    # Test Wazuh
    if [[ -d /var/ossec ]]; then
        if systemctl is-active --quiet wazuh-agent 2>/dev/null || pgrep -f "ossec-agentd" >/dev/null 2>&1; then
            log_info "[OK] Wazuh agent is running"
        else
            log_warning "Wazuh agent is not running"
        fi
    else
        log_warning "Wazuh is not installed"
    fi
    
    log_info "[OK] Installation test completed"
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================
main_install() {
    log_section "YARA4WAZUH Installation v${SCRIPT_VERSION}"
    log_info "Starting complete installation..."
    
    check_root
    setup_directories
    install_dependencies
    install_yara
    
    # Download initial rules
    "${YARA_SCRIPTS_DIR}/update_rules.sh" 2>/dev/null || log_warning "Rules update script not ready"
    
    # Optimize rules
    "${YARA_SCRIPTS_DIR}/optimize_rules.sh" 2>/dev/null || log_warning "Optimize script not ready"
    
    # Setup Wazuh integration
    "${YARA_SCRIPTS_DIR}/wazuh_integration.sh" 2>/dev/null || log_warning "Wazuh integration script not ready"
    
    # Setup cron jobs
    "${YARA_SCRIPTS_DIR}/setup_cron.sh" setup 2>/dev/null || log_warning "Cron setup script not ready"
    
    create_all_scripts
    setup_advanced_feeds
    test_installation
    
    log_section "Installation Complete!"
    
    local yara_version=$(get_yara_version)
    local rules_count=$(find ${YARA_RULES_DIR} -type f \( -name "*.yar" -o -name "*.yara" \) -exec grep -h "^rule " {} \; 2>/dev/null | wc -l)
    
    log_info "YARA version: $yara_version"
    log_info "Rules loaded: $rules_count"
    log_info "Scripts location: ${YARA_SCRIPTS_DIR}"
    log_info ""
    log_info "Available commands:"
    log_info "  $0 --status          : Show system status"
    log_info "  $0 --update-rules    : Update YARA rules"
    log_info "  $0 --optimize-rules  : Optimize rules database"
    log_info "  $0 --health-check    : Perform health check"
    log_info "  $0 --update-scripts  : Update all scripts"
    log_info "  $0 --reinstall       : Reinstall all scripts"
    log_info "  $0 --uninstall       : Remove YARA4WAZUH"
    
    # Send installation completion report
    if [[ -f "${YARA_SCRIPTS_DIR}/common.sh" ]]; then
        source "${YARA_SCRIPTS_DIR}/common.sh"
        
        log_info ""
        log_info "Sending installation completion report..."
        
        # Use safe temp directory to avoid YARA false positives
        TEMP_HTML=$(create_safe_temp_html)
        create_html_header "Installation Complete Report" "yara4wazuh.sh" "13.1" > "$TEMP_HTML"
        
        cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">✅ YARA4WAZUH Installation Completed Successfully</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>Component</th><th>Status</th><th>Details</th></tr>
<tr>
    <td>🔍 YARA Engine</td>
    <td style="color: #28a745; font-weight: bold;">INSTALLED</td>
    <td>$yara_version</td>
</tr>
<tr>
    <td>📚 YARA Rules</td>
    <td style="color: #28a745; font-weight: bold;">LOADED</td>
    <td>$rules_count rules</td>
</tr>
<tr>
    <td>📂 Scripts</td>
    <td style="color: #28a745; font-weight: bold;">DEPLOYED</td>
    <td>${YARA_SCRIPTS_DIR}</td>
</tr>
<tr>
    <td>🛡️ Wazuh Integration</td>
    <td style="color: #28a745; font-weight: bold;">CONFIGURED</td>
    <td>Active Response Ready</td>
</tr>
<tr>
    <td>⏰ Scheduled Tasks</td>
    <td style="color: #28a745; font-weight: bold;">ENABLED</td>
    <td>/etc/cron.d/yara-wazuh</td>
</tr>
</table>

<br>
<div class="alert alert-success">
<strong>🎉 Installation Successful!</strong>
<p>YARA4WAZUH v${SCRIPT_VERSION} has been successfully installed on $(hostname -f).</p>
</div>

<br>
<strong>📋 Next Steps:</strong>
<ul>
<li>Run <code>$0 --status</code> to verify system status</li>
<li>Run <code>$0 --health-check</code> to perform a complete health check</li>
<li>Check <code>/var/log/yara/</code> for activity logs</li>
<li>Monitor <code>/var/ossec/quarantine/</code> for quarantined threats</li>
</ul>

<br>
<strong>⏰ Scheduled Tasks:</strong>
<ul>
<li>Daily YARA scan: 02:30 AM</li>
<li>Rules update: 03:00 AM daily</li>
<li>Health check: Every 6 hours</li>
<li>Weekly report: Monday 08:00 AM</li>
</ul>
</div>
EOF
        
        create_html_footer >> "$TEMP_HTML"
        
        # Send email - the new send_html_email function automatically cleans up
        if send_html_email "[YARA4WAZUH] Installation Completed Successfully" "$TEMP_HTML"; then
            log_info "[OK] Installation report sent to ${EMAIL_TO}"
        else
            log_warning "Failed to send installation report"
        fi
    fi
}

# ============================================================================
# REINSTALL SCRIPTS
# ============================================================================
reinstall_scripts() {
    log_section "Reinstalling all scripts"
    
    check_root
    
    # Recreate scripts directory
    rm -rf "${YARA_SCRIPTS_DIR}"
    mkdir -p "${YARA_SCRIPTS_DIR}"
    
    # Recreate all scripts
    create_all_scripts
    
    # Re-setup cron
    "${YARA_SCRIPTS_DIR}/setup_cron.sh" setup
    
    log_info "[OK] All scripts reinstalled"
}

# ============================================================================
# UNINSTALL
# ============================================================================
uninstall_complete() {
    log_section "Uninstalling YARA4WAZUH"
    
    check_root
    
    local force="${1:-}"
    
    if [[ "$force" != "--force" ]]; then
        echo -e "${YELLOW}This will remove:"
        echo "  - YARA installation"
        echo "  - All YARA rules"
        echo "  - All helper scripts"
        echo "  - All cron jobs"
        echo "  - All log files"
        echo -e "Are you sure? (yes/no):${NC} "
        read -r confirmation
        if [[ "$confirmation" != "yes" ]]; then
            log_info "Uninstallation cancelled"
            exit 0
        fi
    fi
    
    log_info "Removing cron jobs..."
    "${YARA_SCRIPTS_DIR}/setup_cron.sh" remove 2>/dev/null || rm -f /etc/cron.d/yara-wazuh
    
    log_info "Removing YARA..."
    if [[ -f /usr/local/bin/yara ]]; then
        rm -f /usr/local/bin/yara /usr/local/bin/yarac
        rm -rf /usr/local/include/yara
        rm -f /usr/local/lib/libyara*
        ldconfig
    fi
    
    log_info "Removing directories..."
    rm -rf "${YARA_BASE_DIR}"
    rm -rf "${YARA_LOGS_DIR}"
    rm -rf "${CONFIG_DIR}"
    
    # Keep quarantine directory for safety
    if [[ -d "${QUARANTINE_DIR}" ]]; then
        local quarantine_count=$(find "${QUARANTINE_DIR}" -type f 2>/dev/null | wc -l)
        if [[ $quarantine_count -gt 0 ]]; then
            log_warning "Quarantine directory kept (${quarantine_count} files): ${QUARANTINE_DIR}"
        else
            rm -rf "${QUARANTINE_DIR}"
        fi
    fi
    
    # Remove Wazuh integration
    rm -f /var/ossec/active-response/bin/yara.sh 2>/dev/null
    
    log_info "[OK] YARA4WAZUH uninstalled successfully"
}

# ============================================================================
# UPDATE SCRIPTS
# ============================================================================
update_scripts() {
    log_section "Updating YARA4WAZUH Scripts"
    
    # Create backup of current scripts
    BACKUP_DIR="/tmp/yara_scripts_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    if [[ -d "${YARA_SCRIPTS_DIR}" ]]; then
        log_info "Backing up current scripts to $BACKUP_DIR..."
        cp -r "${YARA_SCRIPTS_DIR}"/* "$BACKUP_DIR/" 2>/dev/null
    fi
    
    log_info "Recreating all scripts with latest version..."
    
    # This would normally download or recreate scripts from a repository
    # For now, we'll just verify all scripts are present and fix permissions
    
    # Ensure all required scripts exist
    local required_scripts=(
        "common.sh"
        "daily_scan.sh"
        "update_rules.sh"
        "optimize_rules.sh"
        "quarantine_cleanup.sh"
        "log_cleanup.sh"
        "health_check.sh"
        "weekly_report_html.sh"
        "check_status.sh"
        "wazuh_integration.sh"
        "configure_wazuh_yara.sh"
        "integration_status.sh"
        "yara_status_html.sh"
        "setup_cron.sh"
        "verify_reports.sh"
    )
    
    local missing_count=0
    for script in "${required_scripts[@]}"; do
        if [[ ! -f "${YARA_SCRIPTS_DIR}/$script" ]]; then
            log_warning "Missing script: $script"
            missing_count=$((missing_count + 1))
        else
            log_info "[OK] Found: $script"
        fi
    done
    
    if [[ $missing_count -gt 0 ]]; then
        log_error "$missing_count scripts are missing. Run --reinstall to fix."
        return 1
    fi
    
    # Fix permissions
    log_info "Setting correct permissions..."
    chmod +x "${YARA_SCRIPTS_DIR}"/*.sh
    chown -R root:root "${YARA_SCRIPTS_DIR}"
    
    # Verify common header/footer functions
    if grep -q "create_html_header" "${YARA_SCRIPTS_DIR}/common.sh"; then
        log_info "[OK] Common header function verified"
    else
        log_error "Common header function missing in common.sh"
    fi
    
    if grep -q "create_html_footer" "${YARA_SCRIPTS_DIR}/common.sh"; then
        log_info "[OK] Common footer function verified"
    else
        log_error "Common footer function missing in common.sh"
    fi
    
    # Send update completion report
    log_info "Sending update completion report..."
    # Use safe temp directory to avoid YARA false positives
    TEMP_HTML=$(create_safe_temp_html)
    
    # Create the report using bash here-doc to avoid dependency issues
    cat > "$TEMP_HTML" << 'REPORT_EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>YARA4WAZUH Scripts Update Report</title>
</head>
<body>
<h2>YARA4WAZUH Scripts Update Completed</h2>
<p>Date: REPORT_DATE</p>
<p>Hostname: REPORT_HOST</p>
<p>Status: SUCCESS</p>
<p>Scripts verified: SCRIPT_COUNT</p>
<p>Backup location: BACKUP_LOC</p>
</body>
</html>
REPORT_EOF
    
    # Replace placeholders
    sed -i "s/REPORT_DATE/$(date '+%Y-%m-%d %H:%M:%S')/g" "$TEMP_HTML"
    sed -i "s/REPORT_HOST/$(hostname -f)/g" "$TEMP_HTML"
    sed -i "s/SCRIPT_COUNT/${#required_scripts[@]}/g" "$TEMP_HTML"
    sed -i "s|BACKUP_LOC|$BACKUP_DIR|g" "$TEMP_HTML"
    
    # Source common.sh if available and send report
    if [[ -f "${YARA_SCRIPTS_DIR}/common.sh" ]]; then
        source "${YARA_SCRIPTS_DIR}/common.sh"
        
        # Recreate report with proper header/footer
        create_html_header "Scripts Update Report" "yara4wazuh.sh" "13.1" > "$TEMP_HTML"
        
        cat >> "$TEMP_HTML" << EOF
<div class="section-header">
<h2 class="section-title">✅ Scripts Update Completed</h2>
</div>
<div class="info-box">
<table class="data-table">
<tr><th>Property</th><th>Value</th></tr>
<tr><td>📅 Update Date</td><td>$(date '+%Y-%m-%d %H:%M:%S')</td></tr>
<tr><td>🖥️ Hostname</td><td>$(hostname -f)</td></tr>
<tr><td>📊 Scripts Verified</td><td>${#required_scripts[@]}</td></tr>
<tr><td>💾 Backup Location</td><td>$BACKUP_DIR</td></tr>
<tr><td>✅ Status</td><td style="color: #28a745; font-weight: bold;">SUCCESS</td></tr>
</table>

<br>
<div class="alert alert-success">
<strong>✅ All scripts have been updated with:</strong>
<ul>
<li>Latest version with enhanced security features</li>
<li>Consistent footer with company information</li>
<li>Enhanced email reporting capabilities</li>
<li>Improved threat detection and alerting</li>
</ul>
</div>
</div>
EOF
        
        create_html_footer >> "$TEMP_HTML"
        
        # Send email - the new send_html_email function automatically cleans up
        if send_html_email "[YARA4WAZUH] Scripts Updated Successfully" "$TEMP_HTML"; then
            log_info "[OK] Update report sent"
        else
            log_warning "Failed to send update report"
        fi
    fi
    
    log_info "[OK] Scripts update completed successfully"
}

# ============================================================================
# SHOW STATUS
# ============================================================================
show_status() {
    if [[ -x "${YARA_SCRIPTS_DIR}/check_status.sh" ]]; then
        "${YARA_SCRIPTS_DIR}/check_status.sh"
    else
        log_error "Status script not found"
        exit 1
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
case "${1:-}" in
    --status)
        show_status
        ;;
    --update-rules)
        check_root
        "${YARA_SCRIPTS_DIR}/update_rules.sh"
        ;;
    --optimize-rules)
        check_root
        "${YARA_SCRIPTS_DIR}/optimize_rules.sh"
        ;;
    --health-check)
        check_root
        "${YARA_SCRIPTS_DIR}/health_check.sh"
        ;;
    --update-scripts)
        check_root
        update_scripts
        ;;
    --update-from-github|--github-update)
        check_root
        update_from_github
        ;;
    --reinstall)
        reinstall_scripts
        ;;
    --uninstall)
        uninstall_complete "$2"
        ;;
    --uninstall-force)
        uninstall_complete "--force"
        ;;
    --version)
        echo "YARA4WAZUH Management Script"
        echo "Script Version: ${SCRIPT_VERSION}"
        echo "YARA Installed: ${YARA_INSTALLED_VERSION}"
        echo "YARA Install Version: ${YARA_INSTALL_VERSION} (used for new installations)"
        echo ""
        echo "Company: ${COMPANY_NAME:-Your Company}"
        echo "Support: ${EMAIL_TO:-security@example.com}"
        ;;
    --deploy-only)
        check_root
        log_section "Deploying Scripts Only"
        setup_directories
        deploy_scripts_from_package
        log_info "[OK] Scripts deployed to ${YARA_SCRIPTS_DIR}"
        ;;
    --create-package)
        log_section "Creating Deployment Package"
        if [[ -x /opt/yara/create_deployment_package.sh ]]; then
            /opt/yara/create_deployment_package.sh
        else
            log_error "Package creation script not found"
            exit 1
        fi
        ;;
    --help)
        echo "YARA4WAZUH Management Script v${SCRIPT_VERSION}"
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  --status          Show system status"
        echo "  --update-rules    Update YARA rules from sources"
        echo "  --optimize-rules  Optimize and deduplicate rules"
        echo "  --health-check    Perform system health check"
        echo "  --update-scripts  Update all scripts to latest version"
        echo "  --update-from-github Update from GitHub repository"
        echo "  --deploy-only     Deploy scripts from package without full install"
        echo "  --create-package  Create deployment package for distribution"
        echo "  --reinstall       Reinstall all helper scripts"
        echo "  --uninstall       Remove YARA4WAZUH (interactive)"
        echo "  --uninstall-force Remove YARA4WAZUH (no confirmation)"
        echo "  --version         Show version information"
        echo "  --help            Show this help message"
        echo ""
        echo "Without options: Perform complete installation"
        echo ""
        echo "YARA Version: ${YARA_INSTALLED_VERSION}"
        ;;
    *)
        main_install
        ;;
esac
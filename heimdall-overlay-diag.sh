#!/bin/bash
#
# heimdall-overlay-diag.sh
#
# Compares work host configuration against known-good heimdall-01 baseline.
# Self-contained - no network calls, no external data. All baseline values
# embedded below. Run as your admin user (uses sudo).
#
# Output: PASS / FAIL / WARN per check with the actual value seen.
#
# Author: pair-debugged with Claude, 2026-05
#

set -u

# Color codes (degrade gracefully if no tty)
if [[ -t 1 ]]; then
    GREEN=$'\033[0;32m'
    RED=$'\033[0;31m'
    YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    GREEN="" RED="" YELLOW="" BLUE="" BOLD="" RESET=""
fi

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
FAILURES=()

pass() {
    echo "  ${GREEN}[PASS]${RESET} $1"
    ((PASS_COUNT++))
}

fail() {
    echo "  ${RED}[FAIL]${RESET} $1"
    ((FAIL_COUNT++))
    FAILURES+=("$1")
}

warn() {
    echo "  ${YELLOW}[WARN]${RESET} $1"
    ((WARN_COUNT++))
}

info() {
    echo "  ${BLUE}[INFO]${RESET} $1"
}

section() {
    echo
    echo "${BOLD}=== $1 ===${RESET}"
}

# Require sudo upfront so we don't get prompted mid-run
sudo -v || { echo "Need sudo. Exiting."; exit 1; }

echo "${BOLD}Heimdall Overlay Diagnostic — Work vs Home Lab Delta${RESET}"
echo "Baseline: heimdall-01.rh.corp.ritcsusa.com (working)"
echo "Host:     $(hostname -f)"
echo "Date:     $(date)"
echo

# =============================================================================
section "1. Kernel & Boot"
# =============================================================================

KERNEL=$(uname -r)
info "Running kernel: $KERNEL"
if [[ "$KERNEL" =~ ^5\.14\.0-611 ]]; then
    pass "Kernel in expected RHEL 9.7 series (5.14.0-611.x)"
else
    warn "Kernel branch differs from home (home: 5.14.0-611.49.1.el9_7)"
fi

CMDLINE=$(cat /proc/cmdline)
if grep -q "fips=1" /proc/cmdline; then
    pass "FIPS mode enabled in cmdline"
else
    fail "FIPS NOT enabled — home lab has fips=1, work should match"
fi

# =============================================================================
section "2. Overlay Module Parameters"
# =============================================================================

REDIRECT_DIR=$(cat /sys/module/overlay/parameters/redirect_dir 2>/dev/null || echo "MISSING")
METACOPY=$(cat /sys/module/overlay/parameters/metacopy 2>/dev/null || echo "MISSING")

info "redirect_dir = $REDIRECT_DIR    (home: N)"
info "metacopy     = $METACOPY    (home: N - controlled via mountopt instead)"

if [[ "$REDIRECT_DIR" == "Y" ]]; then
    fail "redirect_dir=Y — likely cause of 'failed to get redirect (-13)'"
    info "  Fix: echo 'options overlay redirect_dir=off' | sudo tee /etc/modprobe.d/overlay.conf"
    info "       then reboot"
elif [[ "$REDIRECT_DIR" == "N" ]]; then
    pass "redirect_dir=N (matches home)"
else
    warn "Could not read redirect_dir parameter"
fi

if ls /etc/modprobe.d/ 2>/dev/null | grep -qi overlay; then
    info "Overlay modprobe config present:"
    ls /etc/modprobe.d/ | grep -i overlay | sed 's/^/    /'
    cat /etc/modprobe.d/overlay.conf 2>/dev/null | sed 's/^/    /'
else
    info "No /etc/modprobe.d/overlay.conf (matches home — none needed if metacopy mountopt is set)"
fi

# =============================================================================
section "3. Container Storage Configuration"
# =============================================================================

STORAGE_CONF="/etc/containers/storage.conf"
if [[ -f "$STORAGE_CONF" ]]; then
    pass "$STORAGE_CONF exists"
else
    fail "$STORAGE_CONF MISSING"
fi

# Critical check: mountopt with metacopy=on
MOUNTOPT_LINE=$(grep -E '^\s*mountopt\s*=' "$STORAGE_CONF" 2>/dev/null | head -1)
info "mountopt line: ${MOUNTOPT_LINE:-<not set>}"
info "Home baseline: mountopt = \"nodev,metacopy=on\""

if echo "$MOUNTOPT_LINE" | grep -q "metacopy=on"; then
    pass "metacopy=on present in storage.conf mountopt"
else
    fail "metacopy=on MISSING from mountopt — likely root cause of overlay redirect errors"
    info "  Fix: add to [storage.options.overlay]:  mountopt = \"nodev,metacopy=on\""
fi

# Driver should be overlay, not vfs or fuse-overlayfs
DRIVER=$(grep -E '^\s*driver\s*=' "$STORAGE_CONF" 2>/dev/null | head -1 | awk -F'"' '{print $2}')
info "Configured driver: ${DRIVER:-<not set>}"
if [[ "$DRIVER" == "overlay" ]]; then
    pass "Storage driver = overlay (matches home)"
else
    warn "Driver is '$DRIVER' — home uses 'overlay'"
fi

# Check svc_heimdall doesn't have a conflicting per-user override
USER_STORAGE_CONF="/home/svc_heimdall/.config/containers/storage.conf"
if sudo test -f "$USER_STORAGE_CONF"; then
    warn "svc_heimdall has a per-user storage.conf — could override system config"
    info "  Contents:"
    sudo cat "$USER_STORAGE_CONF" | sed 's/^/    /'
else
    pass "No per-user storage.conf override for svc_heimdall (matches home)"
fi

# =============================================================================
section "4. Filesystem Backing"
# =============================================================================

FTYPE=$(sudo xfs_info /home 2>/dev/null | grep -oP 'ftype=\K[01]')
if [[ "$FTYPE" == "1" ]]; then
    pass "XFS ftype=1 on /home (overlay-compatible)"
elif [[ "$FTYPE" == "0" ]]; then
    fail "XFS ftype=0 on /home — overlay WILL break. Filesystem must be reformatted."
else
    info "/home is not XFS or xfs_info unavailable. Checking filesystem type:"
    df -T /home | tail -1 | sed 's/^/    /'
fi

# =============================================================================
section "5. SELinux State & Policy"
# =============================================================================

SELINUX_MODE=$(getenforce)
info "SELinux mode: $SELINUX_MODE  (home: Enforcing)"
if [[ "$SELINUX_MODE" == "Enforcing" ]]; then
    pass "SELinux Enforcing (matches home)"
else
    warn "SELinux not enforcing — home is Enforcing"
fi

# Compare key package versions
HOME_SELINUX_POLICY="38.1.65-1.el9_7.1"
HOME_CONTAINER_SELINUX="2.240.0-4.el9_7"
HOME_PODMAN="5.6.0-14.el9_7"

ACTUAL_POLICY=$(rpm -q --qf '%{VERSION}-%{RELEASE}' selinux-policy 2>/dev/null)
ACTUAL_CSEL=$(rpm -q --qf '%{VERSION}-%{RELEASE}' container-selinux 2>/dev/null)
ACTUAL_PODMAN=$(rpm -q --qf '%{VERSION}-%{RELEASE}' podman 2>/dev/null)

info "selinux-policy:    $ACTUAL_POLICY    (home: $HOME_SELINUX_POLICY)"
info "container-selinux: $ACTUAL_CSEL    (home: $HOME_CONTAINER_SELINUX)"
info "podman:            $ACTUAL_PODMAN    (home: $HOME_PODMAN)"

[[ "$ACTUAL_POLICY" == "$HOME_SELINUX_POLICY" ]] && pass "selinux-policy matches" || warn "selinux-policy differs"
[[ "$ACTUAL_CSEL" == "$HOME_CONTAINER_SELINUX" ]] && pass "container-selinux matches" || warn "container-selinux differs"
[[ "$ACTUAL_PODMAN" == "$HOME_PODMAN" ]] && pass "podman matches" || warn "podman differs"

# =============================================================================
section "6. SELinux File Context Rules (the relabel-resistance check)"
# =============================================================================

EXPECTED_FCONTEXT_PATHS=(
    "/home/svc_heimdall/.local/share"
    "/home/svc_heimdall/.local/share/heimdall_app_certs"
    "/home/svc_heimdall/.local/share/heimdall_env"
    "/home/svc_heimdall/.local/share/heimdall_gateway/gateway.yaml"
    "/home/svc_heimdall/.local/share/heimdall_nginx_certs"
    "/home/svc_heimdall/.local/share/heimdall_nginx_conf"
    "/home/svc_heimdall/.local/share/heimdall_pg_certs"
    "/home/svc_heimdall/.local/share/heimdall_pgdata"
)

FCONTEXT_OUTPUT=$(sudo semanage fcontext -l 2>/dev/null | grep -iE 'heimdall|svc_heimdall')

if [[ -z "$FCONTEXT_OUTPUT" ]]; then
    fail "NO semanage fcontext rules for Heimdall paths — relabel will strip container_file_t"
    info "  This is almost certainly the post-patch failure cause."
    info "  Fix: replay rules from home (see end of this report)"
else
    info "Existing fcontext rules:"
    echo "$FCONTEXT_OUTPUT" | sed 's/^/    /'

    MISSING=0
    for path in "${EXPECTED_FCONTEXT_PATHS[@]}"; do
        if ! echo "$FCONTEXT_OUTPUT" | grep -qF "$path"; then
            warn "Missing fcontext rule for: $path"
            ((MISSING++))
        fi
    done

    if [[ $MISSING -eq 0 ]]; then
        pass "All 8 expected fcontext rules present"
    else
        fail "$MISSING of 8 expected fcontext rules missing"
    fi
fi

# =============================================================================
section "7. Current Labels on Bind Mount Paths"
# =============================================================================

if sudo test -d /home/svc_heimdall/.local/share; then
    info "Current labels under /home/svc_heimdall/.local/share/:"
    sudo ls -laZ /home/svc_heimdall/.local/share/ 2>/dev/null | sed 's/^/    /' | head -20

    BAD_LABELS=$(sudo find /home/svc_heimdall/.local/share -maxdepth 2 \
        \( -name 'heimdall_*' -o -path '*/heimdall_*' \) -printf '%p %Z\n' 2>/dev/null | \
        grep -v container_file_t || true)

    if [[ -z "$BAD_LABELS" ]]; then
        pass "All heimdall_* paths labeled container_file_t"
    else
        fail "Some heimdall_* paths have wrong SELinux label:"
        echo "$BAD_LABELS" | sed 's/^/    /'
        info "  Fix: sudo restorecon -RFv /home/svc_heimdall/.local/share"
    fi
else
    warn "/home/svc_heimdall/.local/share does not exist (or unreadable even via sudo)"
fi

# =============================================================================
section "8. Recent SELinux Denials"
# =============================================================================

AVC_OUTPUT=$(sudo ausearch -m AVC -ts today 2>/dev/null | \
    grep -iE 'overlay|svc_heimdall|heimdall' | tail -10)

if [[ -z "$AVC_OUTPUT" ]]; then
    pass "No recent AVC denials related to overlay/heimdall today"
else
    fail "Recent SELinux AVC denials found:"
    echo "$AVC_OUTPUT" | sed 's/^/    /'
fi

# =============================================================================
section "9. svc_heimdall Runtime State"
# =============================================================================

LINGER_STATE=$(sudo loginctl show-user svc_heimdall 2>/dev/null | grep -E '^Linger=' | cut -d= -f2)
USER_STATE=$(sudo loginctl show-user svc_heimdall 2>/dev/null | grep -E '^State=' | cut -d= -f2)

info "Linger=$LINGER_STATE  State=$USER_STATE  (home: yes / lingering)"
[[ "$LINGER_STATE" == "yes" ]] && pass "Linger enabled" || fail "Linger NOT enabled — fix: sudo loginctl enable-linger svc_heimdall"
[[ "$USER_STATE" == "lingering" || "$USER_STATE" == "active" ]] && pass "User manager state OK" || warn "User state: $USER_STATE"

USER_SVC_ACTIVE=$(sudo systemctl is-active user@1001.service 2>/dev/null)
info "user@1001.service: $USER_SVC_ACTIVE"
[[ "$USER_SVC_ACTIVE" == "active" ]] && pass "user@1001.service active" || fail "user@1001.service not active"

# =============================================================================
section "10. Failed Quadlet Units"
# =============================================================================

FAILED_UNITS=$(sudo machinectl shell svc_heimdall@ /bin/bash -c \
    'systemctl --user list-units --type=service --state=failed --no-legend --no-pager' 2>/dev/null | \
    grep -v '^$' || true)

if [[ -z "$FAILED_UNITS" ]]; then
    pass "No failed user services for svc_heimdall"
else
    fail "Failed services under svc_heimdall:"
    echo "$FAILED_UNITS" | sed 's/^/    /'
fi

# =============================================================================
section "11. Podman Storage State"
# =============================================================================

GRAPH_DRIVER=$(sudo -i -u svc_heimdall podman info --format '{{.Store.GraphDriverName}}' 2>/dev/null)
NATIVE_DIFF=$(sudo -i -u svc_heimdall podman info 2>/dev/null | grep -A 8 graphStatus | grep 'Native Overlay Diff' | awk '{print $NF}' | tr -d '"')
DTYPE=$(sudo -i -u svc_heimdall podman info 2>/dev/null | grep -A 8 graphStatus | grep 'Supports d_type' | awk '{print $NF}' | tr -d '"')

info "Graph driver:        $GRAPH_DRIVER         (home: overlay)"
info "Native Overlay Diff: $NATIVE_DIFF         (home: true)"
info "Supports d_type:     $DTYPE         (home: true)"

[[ "$GRAPH_DRIVER" == "overlay" ]] && pass "Native overlay driver (matches home)" || fail "Wrong graph driver: $GRAPH_DRIVER"
[[ "$NATIVE_DIFF" == "true" ]] && pass "Native overlay diff supported" || warn "Native overlay diff = $NATIVE_DIFF"
[[ "$DTYPE" == "true" ]] && pass "d_type supported" || fail "d_type=$DTYPE — overlay won't work"

# =============================================================================
# SUMMARY
# =============================================================================
echo
echo "${BOLD}=== SUMMARY ===${RESET}"
echo "  ${GREEN}PASS: $PASS_COUNT${RESET}    ${YELLOW}WARN: $WARN_COUNT${RESET}    ${RED}FAIL: $FAIL_COUNT${RESET}"
echo

if [[ $FAIL_COUNT -gt 0 ]]; then
    echo "${RED}${BOLD}Failures requiring attention:${RESET}"
    for f in "${FAILURES[@]}"; do
        echo "  - $f"
    done
    echo
fi

# =============================================================================
# REMEDIATION SNIPPETS (only printed if relevant failures detected)
# =============================================================================

if [[ $FAIL_COUNT -gt 0 ]]; then
    echo "${BOLD}=== Remediation reference (do not run blindly) ===${RESET}"
    echo
    echo "# If metacopy=on missing from storage.conf:"
    echo "sudo cp /etc/containers/storage.conf /etc/containers/storage.conf.bak.\$(date +%F)"
    echo "# Then add under [storage.options.overlay]:"
    echo '#   mountopt = "nodev,metacopy=on"'
    echo
    echo "# If fcontext rules missing — replay home baseline:"
    cat <<'EOF'
for p in \
  '/home/svc_heimdall/\.local/share(/.*)?' \
  '/home/svc_heimdall/\.local/share/heimdall_app_certs(/.*)?' \
  '/home/svc_heimdall/\.local/share/heimdall_env(/.*)?' \
  '/home/svc_heimdall/\.local/share/heimdall_gateway/gateway.yaml' \
  '/home/svc_heimdall/\.local/share/heimdall_nginx_certs(/.*)?' \
  '/home/svc_heimdall/\.local/share/heimdall_nginx_conf(/.*)?' \
  '/home/svc_heimdall/\.local/share/heimdall_pg_certs(/.*)?' \
  '/home/svc_heimdall/\.local/share/heimdall_pgdata(/.*)?' ; do
    sudo semanage fcontext -a -t container_file_t "$p" 2>/dev/null || \
    sudo semanage fcontext -m -t container_file_t "$p"
done
sudo restorecon -RFv /home/svc_heimdall/.local/share
EOF
    echo
    echo "# If redirect_dir=Y in kernel module:"
    echo "echo 'options overlay redirect_dir=off metacopy=on' | sudo tee /etc/modprobe.d/overlay.conf"
    echo "# then reboot"
    echo
fi

exit $FAIL_COUNT

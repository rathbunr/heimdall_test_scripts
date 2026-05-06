#!/bin/bash
#
# heimdall-forensics-v3.sh
#
# Read-only forensic capture with hypothesis ranking. No system state changes.
# v3 changes:
#   - REMOVED destructive bind-mount test (was using :Z on live pgdata, breaking
#     MCS labels for the running container). All probes are now read-only.
#   - Postgres binary path detected from image instead of hardcoded.
#   - Quadlet error detection tightened (no longer matches Restart=on-failure).
#   - AVC summary logic corrected.
#   - Container exec tests use tempdir or no mounts only.
#
# Usage:
#   sudo ./heimdall-forensics-v3.sh
#

OUT="$HOME/heimdall-forensics-$(date +%F-%H%M).log"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT
exec > >(tee "$OUT") 2>&1

declare -A FINDINGS
add_finding() { FINDINGS["$1"]="$2"; }

section() { echo; echo "=== $1 ==="; }
sub() { echo "--- $1 ---"; }

echo "=== Heimdall Forensics v3 (read-only) - $(date) ==="
echo "Host: $(hostname -f)"
echo "Output: $OUT"
echo "NOTE: This script makes no system changes. All probes are read-only."
echo

sudo -v

as_svc() {
    sudo -i -u svc_heimdall \
        env XDG_RUNTIME_DIR=/run/user/1001 \
            DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus \
        "$@"
}

# ============================================================================
section "1. AVC denials today"
# ============================================================================
AVC_OUT=$(sudo ausearch -m AVC,USER_AVC,SELINUX_ERR -ts today 2>/dev/null)
if [[ -z "$AVC_OUT" ]]; then
    echo "No AVC denials today."
    add_finding "selinux_avcs_present" "no"
    add_finding "selinux_heimdall_denials" "no"
else
    echo "$AVC_OUT" | head -40
    add_finding "selinux_avcs_present" "yes"

    HEIMDALL_AVC=$(echo "$AVC_OUT" | grep -iE 'heimdall|svc_heim|/home/svc' || true)
    if [[ -n "$HEIMDALL_AVC" ]]; then
        add_finding "selinux_heimdall_denials" "yes"
    else
        add_finding "selinux_heimdall_denials" "no"
    fi

    sub "Deduped summary"
    echo "$AVC_OUT" | grep -oE 'comm="[^"]+"|tcontext=[^ ]+|tclass=[^ ]+|denied  \{ [^}]+ \}' | \
        sort | uniq -c | sort -rn | head -20
fi

# ============================================================================
section "2. Container state"
# ============================================================================
PS_OUT=$(as_svc podman ps -a 2>/dev/null)
echo "$PS_OUT"

RUNNING=$(echo "$PS_OUT" | grep -c "Up " 2>/dev/null | head -1)
EXIT126=$(echo "$PS_OUT" | grep -c "Exited (126)" 2>/dev/null | head -1)
EXIT125=$(echo "$PS_OUT" | grep -c "Exited (125)" 2>/dev/null | head -1)
EXIT1=$(echo "$PS_OUT" | grep -c "Exited (1)" 2>/dev/null | head -1)
RESTARTING=$(echo "$PS_OUT" | grep -ciE "(restarting|created)" 2>/dev/null | head -1)

# Force to integers in case grep -c returned something weird
RUNNING=${RUNNING//[^0-9]/}; RUNNING=${RUNNING:-0}
EXIT126=${EXIT126//[^0-9]/}; EXIT126=${EXIT126:-0}
EXIT125=${EXIT125//[^0-9]/}; EXIT125=${EXIT125:-0}
EXIT1=${EXIT1//[^0-9]/}; EXIT1=${EXIT1:-0}
RESTARTING=${RESTARTING//[^0-9]/}; RESTARTING=${RESTARTING:-0}

add_finding "containers_running" "$RUNNING"
add_finding "containers_exit126" "$EXIT126"
add_finding "containers_exit125" "$EXIT125"
add_finding "containers_exit1" "$EXIT1"
add_finding "containers_restarting" "$RESTARTING"

echo
echo "Running: $RUNNING | Exit126: $EXIT126 | Exit125: $EXIT125 | Exit1: $EXIT1 | Restarting/Created: $RESTARTING"

# ============================================================================
section "3. Container logs (read-only, last 30 lines per container)"
# ============================================================================
for c in database server nginx gateway heimdall-pod-infra; do
    sub "$c"
    LOG=$(as_svc podman logs --tail 30 "$c" 2>&1 || true)
    if [[ -z "$LOG" ]]; then
        echo "(no log output)"
        add_finding "container_${c}_logs" "empty"
    else
        # For database, focus on the most recent log entries (errors near the end)
        if [[ "$c" == "database" ]]; then
            echo "$LOG" | tail -15
        else
            echo "$LOG" | tail -10
        fi

        if echo "$LOG" | grep -qiE 'permission denied|EACCES'; then
            add_finding "container_${c}_perm_denied" "yes"
        fi
        if echo "$LOG" | grep -qiE 'no such file|not found'; then
            add_finding "container_${c}_missing_file" "yes"
        fi
        if echo "$LOG" | grep -qiE 'incompatible|wrong version|version mismatch'; then
            add_finding "container_${c}_version_mismatch" "yes"
        fi
        if echo "$LOG" | grep -qiE 'address already in use|bind: '; then
            add_finding "container_${c}_port_collision" "yes"
        fi
    fi
done

# ============================================================================
section "4. crun/conmon journal (last 2 hours)"
# ============================================================================
CRUN=$(sudo journalctl _UID=1001 --since "2 hours ago" --no-pager 2>/dev/null | \
    grep -iE 'crun|conmon|oci|exec|fork|spawn|EACCES|EPERM|error|fail' | \
    grep -viE 'Started lib|nwarn.*cgroups' | tail -30)
echo "${CRUN:-(no crun/conmon errors of interest)}"

if echo "$CRUN" | grep -qiE 'exec.*permission denied|exec.*EACCES'; then
    add_finding "crun_exec_denied" "yes"
fi
if echo "$CRUN" | grep -qiE 'executable file.*not found|ENOENT'; then
    add_finding "crun_exec_missing" "yes"
fi
if echo "$CRUN" | grep -qiE 'mount.*EACCES|mount.*permission'; then
    add_finding "crun_mount_denied" "yes"
fi
if echo "$CRUN" | grep -qiE 'OCI runtime.*not found'; then
    add_finding "crun_runtime_error" "yes"
fi

# ============================================================================
section "5. Image probes (READ-ONLY, no live bind mounts)"
# ============================================================================
PG_IMAGE="registry1.dso.mil/ironbank/opensource/postgres/postgresql:17"

sub "Probe 1: image exec (no mounts at all)"
P1=$(as_svc podman run --rm --entrypoint=/bin/sh "$PG_IMAGE" \
    -c 'echo IMAGE_OK; id postgres' 2>&1)
P1_RC=$?
echo "$P1"
echo "exit: $P1_RC"
if [[ $P1_RC -eq 0 ]] && echo "$P1" | grep -q IMAGE_OK; then
    add_finding "probe_bare_exec" "ok"
else
    add_finding "probe_bare_exec" "fail"
fi

sub "Probe 2: discover postgres binary path inside image"
PG_BIN=$(as_svc podman run --rm --entrypoint=/bin/sh "$PG_IMAGE" \
    -c 'command -v postgres || which postgres || find / -name postgres -type f -executable 2>/dev/null | head -1' \
    2>&1 | grep -E '^/' | head -1)
echo "Postgres binary: ${PG_BIN:-NOT FOUND}"
add_finding "postgres_binary_path" "${PG_BIN:-not_found}"

sub "Probe 3: postgres binary version (using discovered path)"
if [[ -n "$PG_BIN" ]]; then
    P3=$(as_svc podman run --rm --entrypoint="$PG_BIN" "$PG_IMAGE" --version 2>&1)
    P3_RC=$?
    echo "$P3"
    echo "exit: $P3_RC"
    if [[ $P3_RC -eq 0 ]]; then
        add_finding "probe_postgres_runs" "ok"
    else
        add_finding "probe_postgres_runs" "fail"
    fi
else
    echo "(skipped - postgres binary path not discovered)"
    add_finding "probe_postgres_runs" "skipped"
fi

sub "Probe 4: image has expected entrypoint and required files"
P4=$(as_svc podman run --rm --entrypoint=/bin/sh "$PG_IMAGE" -c '
    echo "Entrypoint candidate(s):"
    ls -la /docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh /entrypoint.sh 2>/dev/null
    echo
    echo "Postgres user:"
    id postgres
    echo
    echo "Available shells:"
    ls -la /bin/sh /bin/bash 2>/dev/null
' 2>&1)
echo "$P4"
if echo "$P4" | grep -qE 'docker-entrypoint\.sh|entrypoint\.sh'; then
    add_finding "image_entrypoint_present" "yes"
else
    add_finding "image_entrypoint_present" "no"
fi

# ============================================================================
section "6. Bind mount inspection (READ-ONLY)"
# ============================================================================
sub "Top-level paths under .local/share"
sudo ls -laZ /home/svc_heimdall/.local/share/ 2>/dev/null

sub "pgdata directory (top-level only)"
sudo ls -laZ /home/svc_heimdall/.local/share/heimdall_pgdata/ 2>/dev/null

sub "pgdata/pgdata contents (postgres data root, top-level only)"
sudo ls -laZ /home/svc_heimdall/.local/share/heimdall_pgdata/pgdata/ 2>/dev/null | head -20

sub "PG_VERSION file (postgres reads this on startup)"
PG_VER_PATHS=(
    "/home/svc_heimdall/.local/share/heimdall_pgdata/PG_VERSION"
    "/home/svc_heimdall/.local/share/heimdall_pgdata/pgdata/PG_VERSION"
)
for p in "${PG_VER_PATHS[@]}"; do
    if sudo test -f "$p"; then
        VER=$(sudo cat "$p" 2>/dev/null)
        echo "Found at: $p"
        echo "Version: $VER"
        add_finding "pgdata_version" "$VER"
        add_finding "pgdata_version_path" "$p"
        break
    fi
done
[[ -z "${FINDINGS[pgdata_version]:-}" ]] && {
    echo "(PG_VERSION not found in any expected location)"
    add_finding "pgdata_version" "missing"
}

# ============================================================================
section "7. Namespace and UID mapping"
# ============================================================================
sub "/etc/subuid"
grep svc_heimdall /etc/subuid /etc/subgid

sub "uid_map inside namespace"
as_svc podman unshare cat /proc/self/uid_map 2>/dev/null

sub "In-container postgres UID expectation"
IB_UID_LINE=$(as_svc podman run --rm --entrypoint=/bin/sh "$PG_IMAGE" \
    -c 'id postgres' 2>&1)
echo "$IB_UID_LINE"
IB_UID=$(echo "$IB_UID_LINE" | grep -oE 'uid=[0-9]+' | head -1 | cut -d= -f2)
add_finding "image_postgres_uid" "$IB_UID"

SUBUID_START=$(grep ^svc_heimdall: /etc/subuid | cut -d: -f2)
if [[ -n "$IB_UID" && -n "$SUBUID_START" ]]; then
    EXPECTED=$((SUBUID_START + IB_UID - 1))
    echo "Expected pgdata host UID: $EXPECTED (= subuid_start $SUBUID_START + container_uid $IB_UID - 1)"
    ACTUAL=$(sudo stat -c '%u' /home/svc_heimdall/.local/share/heimdall_pgdata 2>/dev/null)
    echo "Actual pgdata host UID:   $ACTUAL"
    add_finding "pgdata_expected_uid" "$EXPECTED"
    add_finding "pgdata_actual_uid" "$ACTUAL"
    if [[ "$EXPECTED" == "$ACTUAL" ]]; then
        add_finding "pgdata_uid_match" "yes"
    else
        add_finding "pgdata_uid_match" "no"
    fi
fi

# ============================================================================
section "8. Filesystem mount options (noexec check)"
# ============================================================================
HOMEMNT=$(findmnt -n -o OPTIONS /home 2>/dev/null || findmnt -n -o OPTIONS /)
echo "Mount options for /home: $HOMEMNT"
if echo "$HOMEMNT" | grep -q noexec; then
    add_finding "noexec_mount" "yes"
else
    add_finding "noexec_mount" "no"
fi

# ============================================================================
section "9. Overlay module state"
# ============================================================================
echo "redirect_dir = $(cat /sys/module/overlay/parameters/redirect_dir 2>/dev/null)"
echo "metacopy     = $(cat /sys/module/overlay/parameters/metacopy 2>/dev/null)"
echo
sub "storage.conf mountopt"
grep -E '^\s*mountopt' /etc/containers/storage.conf 2>/dev/null

# ============================================================================
section "10. Recent kernel overlay messages"
# ============================================================================
sudo dmesg -T | grep -i overlay | tail -20

# ============================================================================
section "11. Quadlet generation"
# ============================================================================
QUADLET=$(as_svc /usr/libexec/podman/quadlet -dryrun -user 2>&1)
echo "$QUADLET" | head -30
echo "..."

# Tighter error detection - exclude legitimate Restart=on-failure lines
QUADLET_ERRORS=$(echo "$QUADLET" | grep -iE 'error|fail|invalid|warning' | \
    grep -viE 'Restart=on-failure|RestartSec' | head -5)
if [[ -n "$QUADLET_ERRORS" ]]; then
    sub "Possible issues in generator output"
    echo "$QUADLET_ERRORS"
    add_finding "quadlet_errors" "yes"
else
    add_finding "quadlet_errors" "no"
fi

# ============================================================================
section "12. Active security agents"
# ============================================================================
ps -ef | grep -iE 'cb[a-z]*daemon|cbsensor|carbon|trellix|nessus|tenable|crowdstrike|sentinel|wazuh|osquery' | grep -v grep | head -10

OOT_MODULES=$(sudo lsmod | awk 'NR>1 {print $1}' | while read m; do
    p=$(modinfo -F filename "$m" 2>/dev/null)
    [[ -n "$p" ]] && rpm -qf "$p" 2>/dev/null > /dev/null || echo "$m"
done | grep -v '^$')
if [[ -n "$OOT_MODULES" ]]; then
    sub "Out-of-tree kernel modules (not from any RPM)"
    echo "$OOT_MODULES"
    add_finding "out_of_tree_modules" "yes"
else
    add_finding "out_of_tree_modules" "no"
fi

# ============================================================================
# HYPOTHESIS ENGINE
# ============================================================================
echo
echo "================================================================"
echo "                   HYPOTHESIS ANALYSIS"
echo "================================================================"
echo

declare -a HYPOTHESES

# Critical: image won't exec at all
if [[ "${FINDINGS[probe_bare_exec]:-}" == "fail" ]]; then
    HYPOTHESES+=("CRITICAL|Image cannot exec even with no bind mounts. The image storage itself is broken or filesystem prevents execution.|Run 'sudo dmesg -T | tail -30' for kernel-level block; 'findmnt /home' to confirm mount options; consider 'podman pull --force <image>' to refresh image.")
fi

# Critical: noexec mount
if [[ "${FINDINGS[noexec_mount]:-}" == "yes" ]]; then
    HYPOTHESES+=("CRITICAL|Filesystem holding /home is mounted noexec. Containers cannot exec ANY binary regardless of other config.|Fix needs STIG deviation or relocating container storage. Talk to gold image team. This is the root cause and nothing else matters until it's fixed.")
fi

# High: UID mismatch
if [[ "${FINDINGS[pgdata_uid_match]:-}" == "no" ]]; then
    EXP=${FINDINGS[pgdata_expected_uid]:-?}
    ACT=${FINDINGS[pgdata_actual_uid]:-?}
    UID=${FINDINGS[image_postgres_uid]:-1001}
    HYPOTHESES+=("HIGH|UID mismatch on pgdata. Expected host UID $EXP but actual is $ACT. Container cannot access its data dir even though dir exists.|Fix: stop containers, then run 'sudo -i -u svc_heimdall env XDG_RUNTIME_DIR=/run/user/1001 podman unshare chown -R $UID:$UID /home/svc_heimdall/.local/share/heimdall_pgdata', then start containers.")
fi

# High: SELinux denials specifically targeting Heimdall paths
if [[ "${FINDINGS[selinux_heimdall_denials]:-}" == "yes" ]]; then
    HYPOTHESES+=("HIGH|SELinux is denying operations on Heimdall paths. See section 1 for the deduped summary showing what's denied.|If tcontext is not container_file_t, run 'sudo restorecon -RFv /home/svc_heimdall/.local/share'. If it IS container_file_t, this is a deeper container-selinux policy issue.")
fi

# High: crun couldn't find the entrypoint executable
if [[ "${FINDINGS[crun_exec_missing]:-}" == "yes" ]]; then
    HYPOTHESES+=("HIGH|crun reports the container entrypoint executable is not found. Image may be corrupt OR quadlet config has wrong entrypoint path.|Compare 'podman inspect <container> --format {{.Config.Entrypoint}}' against the actual binaries in the image (see section 5 probe 2 for the discovered path).")
fi

# High: crun-level exec denied
if [[ "${FINDINGS[crun_exec_denied]:-}" == "yes" ]]; then
    HYPOTHESES+=("HIGH|crun reports exec permission denied. OCI runtime cannot execute the entrypoint. No SELinux denial means it's not labels.|Check kernel taint, mount options, and whether out-of-tree security modules (section 12) might be blocking exec.")
fi

# High: postgres data version mismatch
if [[ "${FINDINGS[container_database_version_mismatch]:-}" == "yes" ]]; then
    HYPOTHESES+=("HIGH|Postgres version mismatch in container logs. The pgdata directory was initialized by a different postgres major version than the current image expects.|PG_VERSION on disk says: ${FINDINGS[pgdata_version]:-unknown}. Image is postgres 17. If they don't match, you need pg_upgrade or restore from a matching backup.")
fi

# Medium: app-level perm denied (file-level inside the bind mount)
if [[ "${FINDINGS[container_database_perm_denied]:-}" == "yes" ]]; then
    HYPOTHESES+=("MEDIUM|Database container's logs show permission denied at the application layer. Individual file perms inside pgdata may be wrong even if the directory ownership is right.|Check perms on specific files within pgdata (especially postmaster.pid, pg_filenode.map, global/). May indicate MCS label drift between container instances or partial chown.")
fi

# Medium: containers exited 126 but probes pass
if [[ "${FINDINGS[probe_bare_exec]:-}" == "ok" && \
      "${FINDINGS[containers_exit126]:-0}" -gt 0 ]]; then
    HYPOTHESES+=("MEDIUM|Image probe succeeds but quadlet-managed container exits 126. The difference is in what quadlet adds: bind mounts, env vars, security_opt, capabilities, or pod network namespace.|Compare 'podman inspect <container>' output against the .container quadlet file. Look for security_opt, AddCapability, ReadOnly, or Volume directives that change behavior.")
fi

# Medium: out-of-tree kernel modules present
if [[ "${FINDINGS[out_of_tree_modules]:-}" == "yes" && \
      "${FINDINGS[selinux_heimdall_denials]:-}" == "no" && \
      "${FINDINGS[containers_exit126]:-0}" -gt 0 ]]; then
    HYPOTHESES+=("MEDIUM|Out-of-tree kernel modules are loaded (likely EDR/CB) AND containers fail with no SELinux denials logged. Pattern fits a kernel-level security agent denying operations without using AVC.|Check section 12 for which modules. Investigate vendor logs (varies: /var/log/cb/, /var/opt/carbonblack/, journalctl). Coordinate with corp security team for exclusions if applicable.")
fi

# Indeterminate
if [[ ${#HYPOTHESES[@]} -eq 0 ]]; then
    if [[ "${FINDINGS[containers_running]:-0}" -ge 4 ]]; then
        HYPOTHESES+=("HEALTHY|System appears to be running normally. No failure indicators detected.|If you ran this expecting a problem, the symptoms may have resolved. Re-run if the issue recurs.")
    else
        HYPOTHESES+=("INDETERMINATE|None of the rule patterns matched the evidence. Unusual.|Manual review of section 4 (crun journal) and section 10 (kernel overlay) may surface clues the rule engine missed.")
    fi
fi

i=1
for h in "${HYPOTHESES[@]}"; do
    SEV=$(echo "$h" | cut -d'|' -f1)
    DESC=$(echo "$h" | cut -d'|' -f2)
    ACTION=$(echo "$h" | cut -d'|' -f3)
    echo "[$i] [$SEV]"
    echo "    $DESC"
    echo "    Action: $ACTION"
    echo
    ((i++))
done

# ============================================================================
echo "================================================================"
echo "                       QUICK FACTS"
echo "================================================================"
printf "  %-32s %s\n" "Containers running:"          "${FINDINGS[containers_running]:-?}"
printf "  %-32s %s\n" "Containers exit 126:"         "${FINDINGS[containers_exit126]:-0}"
printf "  %-32s %s\n" "AVC denials today:"           "${FINDINGS[selinux_avcs_present]:-?}"
printf "  %-32s %s\n" "  ...heimdall-related:"       "${FINDINGS[selinux_heimdall_denials]:-?}"
printf "  %-32s %s\n" "Image probe (bare exec):"     "${FINDINGS[probe_bare_exec]:-?}"
printf "  %-32s %s\n" "Postgres binary in image:"    "${FINDINGS[postgres_binary_path]:-?}"
printf "  %-32s %s\n" "Postgres binary runs:"        "${FINDINGS[probe_postgres_runs]:-?}"
printf "  %-32s %s\n" "pgdata UID match:"            "${FINDINGS[pgdata_uid_match]:-?}"
printf "  %-32s %s -> %s\n" "  expected -> actual:" \
    "${FINDINGS[pgdata_expected_uid]:-?}" "${FINDINGS[pgdata_actual_uid]:-?}"
printf "  %-32s %s\n" "PG_VERSION on disk:"          "${FINDINGS[pgdata_version]:-?}"
printf "  %-32s %s\n" "noexec on /home:"             "${FINDINGS[noexec_mount]:-?}"
printf "  %-32s %s\n" "Quadlet generator errors:"    "${FINDINGS[quadlet_errors]:-?}"
printf "  %-32s %s\n" "Out-of-tree modules:"         "${FINDINGS[out_of_tree_modules]:-?}"
echo
echo "Full log saved to: $OUT"

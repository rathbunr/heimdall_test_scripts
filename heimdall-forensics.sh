#!/bin/bash
#
# heimdall-forensics.sh
#
# Single-shot evidence capture for "what stripped my SELinux labels?"
# Run on the work host. Captures everything to a single timestamped file.
# No system state changes - read-only.
#
# Usage:
#   chmod +x heimdall-forensics.sh
#   ./heimdall-forensics.sh
#
# Output: ~/heimdall-forensics-YYYY-MM-DD-HHMM.log
#

OUT="$HOME/heimdall-forensics-$(date +%F-%H%M).log"
exec > >(tee "$OUT") 2>&1

echo "=== Heimdall Forensics Capture - $(date) ==="
echo "Host: $(hostname -f)"
echo "Output: $OUT"
echo

sudo -v

section() { echo; echo "=== $1 ==="; }

section "1. AVC denials today (full)"
sudo ausearch -m AVC,USER_AVC,SELINUX_ERR -ts today 2>/dev/null

section "2. AVC summary - who/what/where"
sudo ausearch -m AVC -ts today --raw 2>/dev/null | \
    grep -oE 'comm="[^"]+"|tcontext=[^ ]+|tclass=[^ ]+|name="[^"]+"' | sort | uniq -c | sort -rn

section "3. AVC timeline - first and last denial today"
sudo ausearch -m AVC -ts today 2>/dev/null | grep -E '^time->' | head -1
sudo ausearch -m AVC -ts today 2>/dev/null | grep -E '^time->' | tail -1

section "4. Current fcontext rules vs on-disk labels"
echo "--- semanage rules ---"
sudo semanage fcontext -l -C 2>/dev/null | grep -i heimdall
echo "--- on-disk ---"
sudo ls -laZ /home/svc_heimdall/.local/share/ 2>/dev/null

section "5. Subuid/namespace state"
grep svc_heimdall /etc/subuid /etc/subgid
sudo -i -u svc_heimdall env XDG_RUNTIME_DIR=/run/user/1001 podman unshare cat /proc/self/uid_map 2>/dev/null

section "6. Container state and recent failures"
sudo -i -u svc_heimdall env XDG_RUNTIME_DIR=/run/user/1001 podman ps -a 2>/dev/null
echo "--- recent crun/conmon errors ---"
sudo journalctl _UID=1001 --since today --no-pager 2>/dev/null | grep -iE 'crun|conmon|oci|exec|denied|EACCES' | tail -30

section "7. What ran today that could touch labels"
echo "--- dnf/rpm transactions today ---"
sudo grep "$(date '+%Y-%m-%d')" /var/log/dnf.log /var/log/dnf.rpm.log 2>/dev/null | head -40
echo "--- restorecon/setfiles/relabel mentions in messages today ---"
sudo grep "$(date '+%b %_d')" /var/log/messages 2>/dev/null | grep -iE 'restorecon|setfiles|relabel|matchpath|fcontext' | head -20
echo "--- /.autorelabel present? ---"
ls -la /.autorelabel 2>/dev/null && echo "WARNING: autorelabel pending" || echo "no autorelabel pending"
echo "--- last full relabel timestamp ---"
sudo ls -la /etc/selinux/.policy.sha256 /etc/selinux/targeted/contexts/files/file_contexts 2>/dev/null

section "8. Third-party kernel modules (potential EDR/FIM)"
sudo lsmod | awk 'NR>1 {print $1}' | while read m; do
    p=$(modinfo -F filename "$m" 2>/dev/null)
    [[ -n "$p" ]] && rpm -qf "$p" 2>/dev/null > /dev/null || echo "$m :: $p"
done | grep -v '^$'

section "9. Security agents and their recent activity"
echo "--- agent-flavored processes ---"
ps -ef | grep -iE 'cb[a-z]*daemon|cbsensor|carbonblack|trellix|mcafee|nessus|tenable|crowdstrike|sentinel|splunk|wazuh|osquery' | grep -v grep
echo "--- agent log directories ---"
sudo ls -la /var/log/cb /var/opt/carbonblack /var/log/trellix /var/log/nessusagent 2>/dev/null
echo "--- recent agent log activity (last 100 lines, redacted to filenames+sizes) ---"
sudo find /var/log /var/opt -newer /tmp -type f 2>/dev/null | grep -iE 'cb|carbon|trellix|nessus|crowd|sentinel|splunk' | head -10

section "10. Kernel taint and recent dmesg"
echo "Tainted: $(cat /proc/sys/kernel/tainted)"
sudo dmesg -T | tail -50

section "11. Audit watches currently in effect"
sudo auditctl -l 2>/dev/null | grep -iE 'home|svc_heimdall|container'

section "12. Linger and user manager state"
sudo loginctl show-user svc_heimdall 2>/dev/null | grep -E 'Linger|State'
sudo systemctl is-active user@1001.service
ls -la /var/lib/systemd/linger/svc_heimdall 2>/dev/null

section "13. Cron and timer activity that ran today"
sudo grep "$(date '+%b %_d')" /var/log/cron 2>/dev/null | grep -iE 'restorecon|relabel|selinux|hardening|stig|scap' | head -20
sudo systemctl list-timers --no-pager 2>/dev/null | head -20

echo
echo "=== Capture complete ==="
echo "Output saved to: $OUT"
echo
echo "Suggested next step - install an audit watch so future drift is caught live:"
echo "  echo '-w /home/svc_heimdall/.local/share -p wa -k heimdall_label_changes' | sudo tee /etc/audit/rules.d/heimdall.rules"
echo "  sudo augenrules --load"

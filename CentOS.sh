#!/bin/bash

echo "[+] Ensure mounting of cramfs filesystems is disabled"
modprobe -n -v cramfs
lsmod | grep cramfs
echo ""

echo "[+] Ensure mounting of freevxfs filesystems is disabled"
modprobe -n -v freevxfs
lsmod | grep freevxfs
echo ""

echo "[+] Ensure mounting of jffs2 filesystems is disabled"
modprobe -n -v jffs2
lsmod | grep jffs2
echo ""

echo "[+] Ensure mounting of hfs filesystems is disabled"
modprobe -n -v hfs
lsmod | grep hfs
echo ""

echo "[+] Ensure mounting of hfsplus filesystems is disabled"
modprobe -n -v hfsplus
lsmod | grep hfsplus
echo ""

echo "[+] Ensure mounting of squashfs filesystems is disabled"
modprobe -n -v squashfs
lsmod | grep squashfs
echo ""

echo "[+] Ensure mounting of udf filesystems is disabled"
modprobe -n -v udf
lsmod | grep udf
echo ""

echo "[+] Ensure mounting of FAT filesystems is disabled"
modprobe -n -v vfat
lsmod | grep vfat
echo ""

echo "[+] Ensure separate partition exists for /tmp"
mount | grep /tmp
echo ""

echo "[+] Ensure nodev option set on /tmp partition"
mount | grep /tmp
echo ""

echo "[+] Ensure nosuid option set on /tmp partition"
mount | grep /tmp
echo ""

echo "[+] Ensure noexec option set on /tmp partition"
mount | grep /tmp
echo ""

echo "[+] Ensure separate partition exists for /var"
mount | grep /var
echo ""

echo "[+] Ensure separate partition exists for /var/tmp"
mount | grep /var/tmp
echo ""

echo "[+] Ensure nodev option set on /var/tmp partition"
mount | grep /var/tmp
echo ""

echo "[+] Ensure nosuid option set on /var/tmp partition"
mount | grep /var/tmp
echo ""

echo "[+] Ensure noexec option set on /var/tmp partition"
mount | grep /var/tmp
echo ""

echo "[+] Ensure separate partition exists for /var/log"
mount | grep /var/log
echo ""

echo "[+] Ensure separate partition exists for /var/log/audit"
mount | grep /var/log/audit
echo ""

echo "[+] Ensure separate partition exists for /home"
mount | grep /home
echo ""

echo "[+] Ensure nodev option set on /home partition"
mount | grep /home
echo ""

echo "[+] Ensure nodev option set on /dev/shm partition"
mount | grep /dev/shm
echo ""

echo "[+] Ensure nosuid option set on /dev/shm partition"
mount | grep /dev/shm
echo ""

echo "[+] Ensure noexec option set on /dev/shm partition"
mount | grep /dev/shm
echo ""

echo "[+] Ensure sticky bit is set on all world-writable directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
echo ""

echo "[+] Disable Automounting"
chkconfig --list autofs
echo ""

echo "[+] Ensure gpgcheck is globally activated"
grep ^gpgcheck /etc/yum.conf
echo ""

echo "[+] verify that all instances of gpgcheck returned are set to '1'"
grep ^gpgcheck /etc/yum.repos.d/*
echo ""

echo "[+] Ensure AIDE is installed"
rpm -q aide
echo ""

echo "[+] Ensure filesystem integrity is regularly checked"
crontab -u root -l | grep aide
echo ""

echo "[+] Ensure permissions on bootloader config are configured"
stat /boot/grub/grub.conf
echo ""

echo "[+] Ensure bootloader password is set"
grep "^password" /boot/grub/grub.conf
echo ""

echo "[+] Ensure authentication required for single user mode"
grep ^SINGLE /etc/sysconfig/init
echo ""

echo "[+] Ensure interactive boot is not enabled"
grep "^PROMPT=" /etc/sysconfig/init
echo ""

echo "[+] Ensure core dumps are restricted"
grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*
sysctl fs.suid_dumpable
grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure address space layout randomization (ASLR) is enabled"
sysctl kernel.randomize_va_space
grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure prelink is disabled"
rpm -q prelink
echo ""

echo "[+] Ensure SELinux is not disabled in bootloader configuration"
grep "^\s*kernel" /boot/grub/grub.conf
echo ""

echo "[+] Ensure the SELinux state is enforcing"
grep SELINUX=enforcing /etc/selinux/config
sestatus
echo ""

echo "[+] Ensure SELinux policy is configured"
grep SELINUXTYPE=targeted /etc/selinux/config
sestatus
echo ""

echo "[+] Ensure SETroubleshoot is not installed"
rpm -q setroubleshoot
echo ""

echo "[+] Ensure the MCS Translation Service (mcstrans) is not installed"
rpm -q mcstrans
echo ""

echo "[+] Ensure no unconfined daemons exist"
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'
echo ""

echo "[+] Ensure SELinux is installed"
rpm -q libselinux
echo ""

echo "[+] Ensure message of the day is configured properly"
cat /etc/motd
egrep '(\\v|\\r|\\m|\\s)' /etc/motd
echo ""

echo "[+] Ensure permissions on /etc/issue are configured"
stat /etc/issue
echo ""

echo "[+] Ensure GDM login banner is configured"
cat /etc/dconf/profile/gdm
cat /etc/dconf/db/gdm.d/01-banner-message 
echo ""

echo "[+] Ensure chargen services are not enabled"
chkconfig --list
echo ""

echo "[+] Ensure daytime services are not enabled"
chkconfig --list
echo ""

echo "[+] Ensure discard services are not enabled"
chkconfig --list
echo ""

echo "[+] Ensure echo services are not enabled"
chkconfig --list
echo ""

echo "[+] Ensure time services are not enabled"
chkconfig --list
echo ""

echo "[+] Ensure rsh server is not enabled"
chkconfig --list
echo ""

echo "[+] Ensure talk server is not enabled"
chkconfig --list
echo ""

echo "[+] Ensure telnet server is not enabled"
chkconfig --list
echo ""

echo "[+] Ensure tftp server is not enabled"
chkconfig --list
echo ""

echo "[+] Ensure rsync service is not enabled"
chkconfig --list
echo ""

echo "[+] Ensure xinetd is not enabled"
chkconfig --list xinetd
echo ""

echo "[+] Ensure ntp is configured"
grep "^restrict" /etc/ntp.conf
echo ""

echo "[+] Verify remote server is configured properly"
grep "^(server|pool)" /etc/ntp.conf
echo ""

echo "[+] Verify that ' -u ntp:ntp ' is included in OPTIONS"
grep "^OPTIONS" /etc/sysconfig/ntpd
echo ""

echo "[+] Ensure chrony is configured"
grep "^(server|pool)" /etc/chrony.conf
grep ^OPTIONS /etc/sysconfig/chronyd
echo ""

echo "[+] Ensure X Window System is not installed"
rpm -qa xorg-x11*
echo ""

echo "[+] Ensure Avahi Server is not enabled"
chkconfig --list avahi-daemon
echo ""

echo "[+] Ensure CUPS is not enabled"
chkconfig --list cups
echo ""

echo "[+] Ensure DHCP Server is not enabled"
chkconfig --list dhcpd
echo ""

echo "[+] Ensure LDAP server is not enabled"
chkconfig --list slapd
echo ""

echo "[+] Ensure NFS and RPC are not enabled"
chkconfig --list nfs
echo ""

echo "[+] Verify all runlevels are listed as "off" or rpcbind is not available"
chkconfig --list rpcbind
echo ""

echo "[+] Ensure DNS Server is not enabled"
chkconfig --list named
echo ""

echo "[+] Ensure FTP Server is not enabled"
chkconfig --list vsftpd
echo ""

echo "[+] Ensure HTTP server is not enabled"
chkconfig --list httpd
echo ""

echo "[+] Ensure IMAP and POP3 server is not enabled"
chkconfig --list dovecot
echo ""

echo "[+] Ensure Samba is not enabled"
chkconfig --list smb
echo ""

echo "[+] Ensure HTTP Proxy Server is not enabled"
chkconfig --list squid
echo ""

echo "[+] Ensure SNMP Server is not enabled"
chkconfig --list snmpd
echo ""

echo "[+] Ensure mail transfer agent is configured for local-only mode"
netstat -an | grep LIST | grep ":25[[:space:]]"
echo ""

echo "[+] Ensure NIS Server is not enabled"
chkconfig --list ypserv
echo ""

echo "[+] Ensure NIS Client is not installed"
rpm -q ypbind
echo ""

echo "[+] Ensure rsh client is not installed"
rpm -q rsh
echo ""

echo "[+] Ensure talk client is not installed"
rpm -q talk
echo ""

echo "[+] Ensure telnet client is not installed"
rpm -q telnet
echo ""

echo "[+] Ensure LDAP client is not installed"
rpm -q openldap-clients
echo ""

echo "[+] Ensure IP forwarding is disabled"
sysctl net.ipv4.ip_forward
grep "net\.ipv4\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure packet redirect sending is disabled"
sysctl net.ipv4.conf.all.send_redirects
sysctl net.ipv4.conf.default.send_redirects
grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure source routed packets are not accepted"
sysctl net.ipv4.conf.all.accept_source_route
sysctl net.ipv4.conf.default.accept_source_route
grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure ICMP redirects are not accepted"
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.conf.default.accept_redirects
grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure secure ICMP redirects are not accepted"
sysctl net.ipv4.conf.all.secure_redirects
sysctl net.ipv4.conf.default.secure_redirects
grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure suspicious packets are logged"
sysctl net.ipv4.conf.all.log_martians
sysctl net.ipv4.conf.default.log_martians
grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure broadcast ICMP requests are ignored"
sysctl net.ipv4.icmp_echo_ignore_broadcasts
grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure bogus ICMP responses are ignored"
sysctl net.ipv4.icmp_ignore_bogus_error_responses
grep "net\.ipv4\.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure Reverse Path Filtering is enabled"
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.default.rp_filter
grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure TCP SYN Cookies is enabled"
sysctl net.ipv4.tcp_syncookies
grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*
echo ""

echo "[+] Ensure TCP Wrappers is installed"
rpm -q tcp_wrappers
echo ""

echo "[+] Verify libwrap.so is installed"
rpm -q tcp_wrappers-libs
echo ""

echo "[+] Ensure /etc/hosts.allow is configured"
cat /etc/hosts.allow
echo ""

echo "[+] Ensure /etc/hosts.deny is configured"
cat /etc/hosts.deny
echo ""

echo "[+] Ensure permissions on /etc/hosts.allow are configured"
stat /etc/hosts.allow
echo ""

echo "[+] Ensure permissions on /etc/hosts.deny are configured"
stat /etc/hosts.deny
echo ""

echo "[+] Ensure iptables is installed"
rpm -q iptables
echo ""

echo "[+] Ensure default deny firewall policy"
iptables -L
echo ""

echo "[+] Ensure loopback traffic is configured"
iptables -L INPUT -v -n
iptables -L OUTPUT -v -n
echo ""

echo "[+] Ensure firewall rules exist for all open ports"
netstat -ln
echo ""

echo "[+] determine firewall rules"
iptables -L INPUT -v -n
echo ""

echo "[+] Ensure system is disabled when audit logs are full"
grep space_left_action /etc/audit/auditd.conf
grep action_mail_acct /etc/audit/auditd.conf
grep admin_space_left_action /etc/audit/auditd.conf
echo ""

echo "[+] Ensure audit logs are not automatically deleted"
grep max_log_file_action /etc/audit/auditd.conf
echo ""

echo "[+] Ensure auditd service is enabled"
chkconfig --list auditd
echo ""

echo "[+] Ensure auditing for processes that start prior to auditd is enabled"
grep "^\s*kernel" /boot/grub/grub.conf
echo ""

echo "[+] Ensure events that modify date and time information are collected"
grep time-change /etc/audit/audit.rules
auditctl -l | grep time-change
grep time-change /etc/audit/audit.rules
auditctl -l | grep time-change
echo ""

echo "[+] Ensure events that modify user/group information are collected"
grep identity /etc/audit/audit.rules
auditctl -l | grep identity
echo ""

echo "[+] Ensure events that modify the system's network environment are collected"
grep system-locale /etc/audit/audit.rules
auditctl -l | grep system-locale
grep system-locale /etc/audit/audit.rules
auditctl -l | grep system-locale
echo ""

echo "[+] Ensure events that modify the system's Mandatory Access Controls are collected"
grep MAC-policy /etc/audit/audit.rules
echo ""

echo "[+] Ensure login and logout events are collected"
grep logins /etc/audit/audit.rules
echo ""

echo "[+] Ensure session initiation information is collected"
grep session /etc/audit/audit.rules
auditctl -l | grep session
echo ""

echo "[+] Ensure discretionary access control permission modification events are collected"
grep perm_mod /etc/audit/audit.rules
auditctl -l | grep perm_mod
grep perm_mod /etc/audit/audit.rules
auditctl -l | grep perm_mod
echo ""

echo "[+] Ensure unsuccessful unauthorized file access attempts are collected"
grep access /etc/audit/audit.rules
auditctl -l | grep access
grep access /etc/audit/audit.rules
auditctl -l | grep access
echo ""

echo "[+] Ensure use of privileged commands is collected"
find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \ "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 \ -k privileged" }'
echo ""

echo "[+] Ensure successful file system mounts are collected"
grep mounts /etc/audit/audit.rules
auditctl -l | grep mounts
grep mounts /etc/audit/audit.rules
auditctl -l | grep mounts
echo ""

echo "[+] Ensure file deletion events by users are collected"
grep delete /etc/audit/audit.rules
auditctl -l | grep delete
grep delete /etc/audit/audit.rules
auditctl -l | grep delete
echo ""

echo "[+] Ensure changes to system administration scope (sudoers) is collected"
grep scope /etc/audit/audit.rules
auditctl -l | grep scope
echo ""

echo "[+] Ensure system administrator actions (sudolog) are collected"
grep actions /etc/audit/audit.rules
auditctl -l | grep actions
echo ""

echo "[+] Ensure kernel module loading and unloading is collected"
grep modules /etc/audit/audit.rules
auditctl -l | grep modules
grep modules /etc/audit/audit.rules
auditctl -l | grep modules
echo ""

echo "[+] Ensure the audit configuration is immutable"
grep "^\s*[^#]" /etc/audit/audit.rules | tail -1 -e 2
echo ""

echo "[+] Ensure rsyslog Service is enabled"
chkconfig --list rsyslog
echo ""

echo "[+] Ensure rsyslog default file permissions configured"
grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo ""

echo "[+] Ensure rsyslog is configured to send logs to a remote log host"
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo ""

echo "[+] Ensure syslog-ng service is enabled"
chkconfig --list syslog-ng
echo ""

echo "[+] Ensure syslog-ng default file permissions configured"
grep ^options /etc/syslog-ng/syslog-ng.conf 
echo ""

echo "[+] Ensure rsyslog or syslog-ng is installed"
rpm -q rsyslog
rpm -q syslog-ng
echo ""

echo "[+] Ensure permissions on all logfiles are configured"
find /var/log -type f -ls
echo ""

echo "[+] Ensure cron daemon is enabled"
chkconfig --list crond
echo ""

echo "[+] Ensure permissions on /etc/crontab are configured"
stat /etc/crontab
echo ""

echo "[+] Ensure permissions on /etc/cron.hourly are configured"
stat /etc/cron.hourly
echo ""

echo "[+] Ensure permissions on /etc/cron.daily are configured"
stat /etc/cron.daily
echo ""

echo "[+] Ensure permissions on /etc/cron.weekly are configured"
stat /etc/cron.weekly
echo ""

echo "[+] Ensure permissions on /etc/cron.monthly are configured"
stat /etc/cron.monthly
echo ""

echo "[+] Ensure permissions on /etc/cron.d are configured"
stat /etc/cron.d
echo ""

echo "[+] Ensure at/cron is restricted to authorized users"
stat /etc/cron.deny
stat /etc/at.deny
echo ""

echo "[+] Verify Uid and Gid are both 0/root and Access does not grant permissions to group or other for both /etc/cron.allow and /etc/at.allow"
stat /etc/cron.allow
stat /etc/at.allow
echo ""

echo "[+] Ensure permissions on /etc/ssh/sshd_config are configured"
stat /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH Protocol is set to 2"
grep "^Protocol" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH LogLevel is set to INFO"
grep "^LogLevel" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH X11 forwarding is disabled"
grep "^X11Forwarding" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH MaxAuthTries is set to 4 or less"
grep "^MaxAuthTries" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH IgnoreRhosts is enabled"
grep "^IgnoreRhosts" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH HostbasedAuthentication is disabled"
grep "^HostbasedAuthentication" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH root login is disabled"
grep "^PermitRootLogin" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH PermitEmptyPasswords is disabled"
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH PermitUserEnvironment is disabled"
grep PermitUserEnvironment /etc/ssh/sshd_config
echo ""

echo "[+] Ensure only approved MAC algorithms are used"
grep "MACs" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH Idle Timeout Interval is configured"
grep "^ClientAliveInterval" /etc/ssh/sshd_config
grep "^ClientAliveCountMax" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH LoginGraceTime is set to one minute or less"
grep "^LoginGraceTime" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH access is limited"
grep "^AllowUsers" /etc/ssh/sshd_config
grep "^AllowGroups" /etc/ssh/sshd_config
grep "^DenyUsers" /etc/ssh/sshd_config
grep "^DenyGroups" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure SSH warning banner is configured"
grep "^Banner" /etc/ssh/sshd_config
echo ""


echo "[+] Ensure SSH warning banner is configured"
grep "^Banner" /etc/ssh/sshd_config
echo ""

echo "[+] Ensure password creation requirements are configured"
grep pam_cracklib.so /etc/pam.d/password-auth
grep pam_cracklib.so /etc/pam.d/system-auth
echo ""


echo "[+] Ensure lockout for failed password attempts is configured"
cat /etc/pam.d/password-auth
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
cat /etc/pam.d/system-auth
echo ""

echo "[+] Ensure password reuse is limited"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth
echo ""

echo "[+] Ensure password hashing algorithm is SHA-512"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth
echo ""

echo "[+] Ensure password expiration is 365 days or less"
grep PASS_MAX_DAYS /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
for OUTPUT in $(awk -F: '{ print $1}' /etc/passwd)
do
        echo "-------- $OUTPUT --------";
		chage --list $OUTPUT
done

echo ""

echo "[+] Ensure minimum days between password changes is 7 or more"
grep PASS_MIN_DAYS /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 /etc/passwd
for OUTPUT in $(awk -F: '{ print $1}' /etc/passwd)
do
        echo "-------- $OUTPUT --------";
		chage --list $OUTPUT
done
echo ""

echo "[+] Ensure password expiration warning days is 7 or more"
grep PASS_WARN_AGE /etc/login.defs
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 /etc/passwd
for OUTPUT in $(awk -F: '{ print $1}' /etc/passwd)
do
        echo "-------- $OUTPUT --------";
		chage --list $OUTPUT
done
echo ""

echo "[+] Ensure inactive password lock is 30 days or less"
useradd -D | grep INACTIVE
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 /etc/passwd
for OUTPUT in $(awk -F: '{ print $1}' /etc/passwd)
do
        echo "-------- $OUTPUT --------";
		chage --list $OUTPUT
done
echo ""

echo "[+] Ensure all users last password change date is in the past"
cat /etc/shadow | cut -d: -f1 /etc/passwd
for OUTPUT in $(awk -F: '{ print $1}' /etc/passwd)
do
        echo "-------- $OUTPUT --------";
		chage --list $OUTPUT
done
echo ""

echo "[+] Ensure system accounts are non-login"
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false") {print}'
echo ""

echo "[+] Ensure default group for the root account is GID 0"
grep "^root:" /etc/passwd | cut -f4 -d:
echo ""

echo "[+] Ensure default user umask is 027 or more restrictive"
grep "umask" /etc/bashrc
grep "umask" /etc/profile /etc/profile.d/*.sh
echo ""

echo "[+] Ensure default user shell timeout is 900 seconds or less"
grep "^TMOUT" /etc/bashrc
grep "^TMOUT" /etc/profile
echo ""

echo "[+] Ensure access to the su command is restricted"
grep pam_wheel.so /etc/pam.d/su
echo ""

echo "[+] Verify users in wheel group match site policy"
grep wheel /etc/group
echo ""

echo "[+] Ensure permissions on /etc/passwd are configured"
stat /etc/passwd
echo ""

echo "[+] Ensure permissions on /etc/shadow are configured"
stat /etc/shadow
echo ""

echo "[+] Ensure permissions on /etc/group are configured"
stat /etc/group
echo ""

echo "[+] Ensure permissions on /etc/gshadow are configured"
stat /etc/gshadow
echo ""

echo "[+] Ensure permissions on /etc/passwd- are configured"
stat /etc/passwd-
echo ""

echo "[+] Ensure permissions on /etc/shadow- are configured"
stat /etc/shadow-
echo ""

echo "[+] Ensure permissions on /etc/group- are configured"
stat /etc/group-
echo ""

echo "[+] Ensure permissions on /etc/gshadow- are configured"
stat /etc/gshadow-
echo ""

echo "[+] Ensure no world writable files exist"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002
echo ""

echo "[+] Manually for individual partitions"
#find <partition> -xdev -type f -perm -0002
echo ""

echo "[+] Ensure no unowned files or directories exist"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser
echo ""

echo "[+] Manually for individual partitions"
#find <partition> -xdev -nouser
echo ""

echo "[+] Ensure no ungrouped files or directories exist"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup
#find <partition> -xdev -nogroup
echo ""

echo "[+] Ensure password fields are not empty"
cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'
echo ""

echo "[+] Ensure no legacy "+" entries exist in /etc/passwd"
grep '^\+:' /etc/passwd
echo ""

echo "[+] Ensure no legacy "+" entries exist in /etc/shadow"
grep '^\+:' /etc/shadow
echo ""

echo "[+] Ensure no legacy "+" entries exist in /etc/group"
grep '^\+:' /etc/group
echo ""

echo "[+] Ensure root is the only UID 0 account"
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'
echo ""

echo "[+] Ensure root PATH Integrity"
if [ "`echo $PATH | grep ::`" != "" ]; then
	echo "Empty Directory in PATH (::)"
fi
if [ "`echo $PATH | grep :$`"]; then
	echo "Trailing : in PATH"
fi
p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
	if [ "$1" = "." ]; then
		echo "PATH contains ."
		shift
		continue
	fi
	if [ -d $1 ]; then
		dirperm=`ls -ldH $1 | cut -f1 -d" "`
		if [ `echo $dirperm | cut -c6` != "-" ]; then
			echo "Group Write permission set on directory $1"
		fi
		if [ `echo $dirperm | cut -c9` != "-" ]; then
			echo "Other Write permission set on directory $1"
		fi
		dirown=`ls -ldH $1 | awk '{print $3}'`
		if [ "$dirown" != "root" ] ; then
			echo "$1 is not owned by root"
		fi
		else
		echo "$1 is not a directory"
	fi
	shift
done
echo ""

echo "[+] Ensure all users' home directories exist"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then
echo "The home directory ($dir) of user $user does not exist."
fi
done
echo ""

echo "[+] Ensure users' home directories permissions are 750 or more restrictive"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then
echo "The home directory ($dir) of user $user does not exist."
else
dirperm=`ls -ld $dir | cut -f1 -d" "`
if [ `echo $dirperm | cut -c6` != "-" ]; then
echo "Group Write permission set on the home directory ($dir) of user $user"
fi
if [ `echo $dirperm | cut -c8` != "-" ]; then
echo "Other Read permission set on the home directory ($dir) of user $user"
fi
if [ `echo $dirperm | cut -c9` != "-" ]; then
echo "Other Write permission set on the home directory ($dir) of user $user"
fi
if [ `echo $dirperm | cut -c10` != "-" ]; then
echo "Other Execute permission set on the home directory ($dir) of user $user"
fi
fi
done
echo ""

echo "[+] Ensure users own their home directories"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then
echo "The home directory ($dir) of user $user does not exist."
else
owner=$(stat -L -c "%U" "$dir")
if [ "$owner" != "$user" ]; then
echo "The home directory ($dir) of user $user is owned by $owner."
fi
fi
done
echo ""

echo "[+] Ensure users' dot files are not group or world writable"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then
	echo "The home directory ($dir) of user $user does not exist."
else
	for file in $dir/.[A-Za-z0-9]*; do
		if [ ! -h "$file" -a -f "$file" ]; then
			fileperm=`ls -ld $file | cut -f1 -d" "`
			if [ `echo $fileperm | cut -c6` != "-" ]; then 
				echo "Group Write permission set on file $file"
			fi
		if [ `echo $fileperm | cut -c9` != "-" ];then
			echo "Other Write permission set on file $file"
		fi
fi
done
fi
done
echo ""

echo "[+] Ensure no users have .forward files"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then
echo "The home directory ($dir) of user $user does not exist."
else
if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
echo ".forward file $dir/.forward exists"
fi
fi
done
echo ""

echo "[+] Ensure no users have .netrc files"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then
echo "The home directory ($dir) of user $user does not exist."
else
if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
echo ".netrc file $dir/.netrc exists"
fi
fi
done
echo ""

echo "[+] Ensure user's .netrc Files are not group or world accessible"

cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then
echo "The home directory ($dir) of user $user does not exist."
else
for file in $dir/.netrc; do
if [ ! -h "$file" -a -f "$file" ]; then
fileperm=`ls -ld $file | cut -f1 -d" "`
if [ `echo $fileperm | cut -c5` != "-" ]; then
echo "Group Read set on $file"
fi
if [ `echo $fileperm | cut -c6` != "-" ]; then
echo "Group Write set on $file"
fi
if [ `echo $fileperm | cut -c7` != "-" ]; then
echo "Group Execute set on $file"
fi
if [ `echo $fileperm | cut -c8` != "-" ]; then
echo "Other Read set on $file"
fi
if [ `echo $fileperm | cut -c9` != "-" ]; then
echo "Other Write set on $file"
fi
if [ `echo $fileperm | cut -c10` != "-" ]; then
echo "Other Execute set on $file"
fi
fi
done
fi
done
echo ""

echo "[+] Ensure no users have .rhosts files"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then
echo "The home directory ($dir) of user $user does not exist."
else
for file in $dir/.rhosts; do
if [ ! -h "$file" -a -f "$file" ]; then
echo ".rhosts file in $dir"
fi
done
fi
done
echo ""

echo "[+] Ensure all groups in /etc/passwd exist in /etc/group"
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
grep -q -P "^.*?:[^:]*:$i:" /etc/group
if [ $? -ne 0 ]; then
echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
fi
done
echo ""

echo "[+] Ensure no duplicate UIDs exist"
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
echo "Duplicate UID ($2): ${users}"
fi
done
echo ""

echo "[+] Ensure no duplicate GIDs exist"
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
echo "Duplicate GID ($2): ${groups}"
fi
done
echo ""

echo "[+] Ensure no duplicate user names exist"
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
echo "Duplicate User Name ($2): ${uids}"
fi
done
echo ""

echo "[+] Ensure no duplicate group names exist"
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
echo "Duplicate Group Name ($2): ${gids}"
fi
done
echo ""

csv_file="Results.csv"


echo "Stay idle for 5 minutes and a notification such as 'AUDIT COMPLETED' will appear."

#------------------------------------------------------------------------------------------------------------------------------


a="1.Ensure vulnerable file systems are removed if no dependencies exist"

b="Filesystem kernel modules are pieces of code that can be dynamically loaded into the
Linux kernel to extend its filesystem capabilities, or so-called base kernel, of an
operating system. Filesystem kernel modules are typically used to add support for new
hardware (as device drivers), or for adding system calls.

Rationale:

While loadable filesystem kernel modules are a convenient method of modifying the
running kernel, this can be abused by attackers on a compromised system to prevent
detection of their processes or files, allowing them to maintain control over the system.
Many rootkits make use of loadable filesystem kernel modules in this way.
Removing support for unneeded filesystem types reduces the local attack surface of the
system. If those filesystem type is not needed, disable it."

c="The following filesystem kernel modules must 
be removed if no dependencies exist:

cramfs
freevxfs
hfs
hfsplus
jffs2
squashfs
udf
usb-storage
afs
ceph
cifs 
exfat
ext 
fat 
fscache 
fuse 
gfs2 
nfs_common 
nfsd 
smbfs_common"

check="cramfs|freevxfs|hfs|hfsplus|jffs2|squashfs|udf|usb-storage|overlayfs|afs|ceph|cifs|exfat|ext|fat|fscache|fuse|gfs2|nfs_common|nfsd|smbfs_common"

d=$( cat /proc/filesystems )

echo "$d" | grep -E -q "$check" && e="FAIL" || e="PASS"

f="Unloading, disabling or denylisting filesystem modules that are in use on the
system maybe FATAL. It is extremely important to thoroughly review the filesystems
returned by the audit before following the remediation procedure.


Unload the relevant filesystem modules from the kernel using,

sudo modprobe -r (Name of the filesystem)
"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------------------

a="2.Ensure /tmp directory is a separate partition with mount options"

b="
The /tmp directory is a world-writable directory used for temporary storage by all users
and some applications

The nodev mount option specifies that the filesystem cannot contain special devices.
The nosuid mount option specifies that the filesystem cannot contain setuid files.
The noexec mount option specifies that the filesystem cannot contain executable binaries.

Rationale:

Making /tmp its own file system allows an administrator to set additional mount options
such as the noexec option on the mount, making /tmp useless for an attacker to install
executable code. 
It would also prevent an attacker from establishing a hard link to a
system setuid program and wait for it to be updated. Once the program was updated,
the hard link would be broken, and the attacker would have his own copy of the
program. If the program happened to have a security vulnerability, the attacker could
continue to exploit the known flaw.
This can be accomplished by either mounting tmpfs to /tmp, or creating a separate
partition for /tmp.
"

c="/tmp tmpfs tmpfs rw,nosuid,nodev,noexec"

check=( "/tmp" "nodev" "nosuid" "noexec"  )

d=$(findmnt /tmp)

e="PASS"

for opt in "${check[@]}"; do
    echo "$d" | grep -q "$opt" || e="FAIL"
done

f="
*To mount the directory with the nodev, nosuid, and noexec options,
execute the following command.
sudo mount -t tmpfs -o nodev,nosuid,noexec tmpfs /tmp

*Remount to apply the changes without rebooting,
sudo mount -o remount /tmp

*You can check that the /tmp directory is mounted with the correct options by running:
mount | grep /tmp
"
echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.Ensure /dev/shm directory is a separate partition with mount options"

b="
The /dev/shm directory is a world-writable directory that can function as shared
memory that facilitates inter process communication (IPC).
Making /dev/shm its own file system allows an administrator to set additional mount
options such as the noexec option on the mount, making /dev/shm useless for an
attacker to install executable code. 
It would also prevent an attacker from establishing a hard link to a system setuid 
program and wait for it to be updated. Once the program was updated, the hard link 
would be broken and the attacker would have his own copy of the program. If the 
program happened to have a security vulnerability, the attacker could continue to 
exploit the known flaw.
This can be accomplished by mounting tmpfs to /dev/shm."

c="
/dev/shm tmpfs tmpfs rw,nosuid,nodev,noexec,"

check=("nodev" "nosuid" "noexec")

d=$(findmnt /dev/shm )

e="PASS"

for opt in "${check[@]}"; do
    echo "$d" | grep -q "$opt" || e="FAIL"
done

f="
*To mount the directory with the nodev, nosuid, and noexec options,
execute the following command.
sudo mount -t tmpfs -o nodev,nosuid,noexec tmpfs /dev/shm

*Remount to apply the changes without rebooting,
sudo mount -o remount /dev/shm

*You can check that the /tmp directory is mounted with the correct options by running:
mount | grep /dev/shm
"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="4.Ensure /home directory is a separate partition with mount options"

b="
The /home directory is used to support disk storage needs of local users.
THe home directories can be mounted anywhere and are not necessarily
restricted to /home, nor restricted to a single location, nor is the 
name restricted in any way.
Finding user home directories can be done by looking in /etc/passwd, looking over the
mounted file systems with mount or querying the relevant database with getent.

Rationale:

Configuring /home as its own file system allows an administrator to set additional mount
options such as noexec/nosuid/nodev. These options limit an attacker's ability to
create exploits on the system. In the case of /home options such as
usrquota/grpquota may be considered to limit the impact that users can have on each
other with regards to disk resource exhaustion. Other options allow for specific
behavior. See man mount for exact details regarding filesystem-independent and
filesystem-specific options.
As /home contains user data, care should be taken to ensure the security and integrity
of the data and mount poin"

c="/home /dev/sdb ext4 rw,nosuid,nodev,noexec"

check=( "/home" "nodev" "nosuid" "noexec" )

d=$(findmnt /home)

e="PASS"

for opt in "${check[@]}"; do
    echo "$d" | grep -q "$opt" || e="FAIL"
done

f="
*To mount the directory with the nodev, nosuid, and noexec options,
execute the following command.
sudo mount -t tmpfs -o nodev,nosuid,noexec tmpfs /home

*Remount to apply the changes without rebooting,
sudo mount -o remount /home

*You can check that the /tmp directory is mounted with the correct options by running:
mount | grep /home
"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.Ensure /var directory is a separate partition with mount options"

b="
The /var directory is used by daemons and other system services to temporarily store
dynamic data. Some directories created by these processes may be world-writable.

Rationale:

Configuring /var as its own file system allows an administrator to set additional mount
options such as noexec/nosuid/nodev. These options limit an attacker's ability to
create exploits on the system. Other options allow for specific behavior. See man mount
for exact details regarding filesystem-independent and filesystem-specific options.

An example of exploiting /var may be an attacker establishing a hard-link to a system
setuid program and waiting for it to be updated. Once the program is updated, the
hard-link can be broken and the attacker would have their own copy of the program. If
the program happened to have a security vulnerability, the attacker could continue to
exploit the known flaw."

c="/var /dev/sdb ext4 rw,nosuid,nodev,noexec"

check=( "/var" "nodev" "nosuid" "noexec" )

d=$(findmnt /var )

e="PASS"

for opt in "${check[@]}"; do
    echo "$d" | grep -q "$opt" || e="FAIL"
done

f="
*To mount the directory with the nodev, nosuid, and noexec options,
execute the following command.
sudo mount -t tmpfs -o nodev,nosuid,noexec tmpfs /var

*Remount to apply the changes without rebooting,
sudo mount -o remount /var

*You can check that the /tmp directory is mounted with the correct options by running:
mount | grep /var
"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="6.Ensure /vartmp directory is a separate partition with mount options"

b="
The /var/tmp directory is a world-writable directory used for temporary storage by all
users and some applications. Temporary files residing in /var/tmp are to be preserved
between reboots.

Rationale:

The default installation only creates a single / partition. Since the /var/tmp directory is
world-writable, there is a risk of resource exhaustion. In addition, other operations on
the system could fill up the disk unrelated to /var/tmp and cause potential disruption to
daemons as the disk is full.
Configuring /var/tmp as its own file system allows an administrator to set additional
mount options such as noexec/nosuid/nodev. These options limit an attacker's ability
to create exploits on the system."

c="/var/tmp /dev/sdb ext4 rw,nosuid,nodev,noexec"

check=( "/vartmp" "nodev" "nosuid" "noexec"  )

d=$(findmnt /vartmp )

e="PASS"

for opt in "${check[@]}"; do
    echo "$d" | grep -q "$opt" || e="FAIL"
done

f="
*To mount the directory with the nodev, nosuid, and noexec options,
execute the following command.
sudo mount -t tmpfs -o nodev,nosuid,noexec tmpfs /var/tmp

*Remount to apply the changes without rebooting,
sudo mount -o remount /var/tmp

*You can check that the /tmp directory is mounted with the correct options by running:
mount | grep /var/tmp
"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="7.Ensure /var/log directory is a separate partition with mount options"

b="
The /var/log directory is used by system services to store log data.

Rationale:

The default installation only creates a single / partition. Since the /var/log directory
contains log files which can grow quite large, there is a risk of resource exhaustion. It
will essentially have the whole disk available to fill up and impact the system as a whole.

Configuring /var/log as its own file system allows an administrator to set additional
mount options such as noexec/nosuid/nodev. These options limit an attackers ability
to create exploits on the system. Other options allow for specific behavior.

As /var/log contains log files,should ensure the security of the data and mount point."

c="/var/log /dev/sdb ext4 rw,nosuid,nodev,noexec"

check=( "/var/log" "nodev" "nosuid" "noexec"  )

d=$(findmnt /var/log )

e="PASS"

for opt in "${check[@]}"; do
    echo "$d" | grep -q "$opt" || e="FAIL"
done

f="
*To mount the directory with the nodev, nosuid, and noexec options,
execute the following command.
sudo mount -t tmpfs -o nodev,nosuid,noexec tmpfs /var/log

*Remount to apply the changes without rebooting,
sudo mount -o remount /var/log

*You can check that the /tmp directory is mounted with the correct options by running:
mount | grep /var/log
"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="8.Ensure /var/log/audit directory is a separate partition with mount options"

b="
The auditing daemon, auditd, stores log data in the /var/log/audit directory.

Rationale:

The default installation only creates a single / partition. Since the /var/log/audit
directory contains the audit.log file which can grow quite large, there is a risk of
resource exhaustion. It will essentially have the whole disk available to fill up and impact
the system as a whole. In addition, other operations on the system could fill up the disk
unrelated to /var/log/audit and cause auditd to trigger its space_left_action as
the disk is full. See man auditd.conf for details.

Configuring /var/log/audit as its own file system allows an administrator to set
additional mount options such as noexec/nosuid/nodev. These options limit an
attacker's ability to create exploits on the system. Other options allow for specific
behavior. See man mount for exact details regarding filesystem-independent and
filesystem-specific options.

As /var/log/audit contains audit logs, care should be taken to ensure the security
and integrity of the data and mount point.
"

c="/var/log/audit /dev/sdb ext4 rw,nosuid,nodev,noexec"

check=( "/var/log/audit" "nodev" "nosuid" "noexec"  )

d=$(findmnt /var/log/audit 2>&1 )

e="PASS"

for opt in "${check[@]}"; do
    echo "$d" | grep -q "$opt" || e="FAIL"
done

f="
*To mount the directory with the nodev, nosuid, and noexec options,
execute the following command.
sudo mount -t tmpfs -o nodev,nosuid,noexec tmpfs /var/log/audit

*Remount to apply the changes without rebooting,
sudo mount -o remount /var/log/audit

*You can check that the /tmp directory is mounted with the correct options by running:
mount | grep /var/log/audit
"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.3.1.1 Ensure AppArmor is installed "

b="
AppArmor provides a Mandatory Access Control (MAC) system that greatly augments
the default Discretionary Access Control (DAC) model. Under AppArmor MAC rules are
applied by file paths instead of by security contexts as in other MAC systems. As such it
does not require support in the filesystem and can be applied to network mounted
filesystems for example.
AppArmor security policies define what system resources applications can access and what
privileges they can do so with. This automatically limits the damage that the software
can do to files accessible by the calling user. The user does not need to take any action
to gain this benefit. For an action to occur, both the traditional DAC permissions must 
be satisfied as well as the AppArmor MAC rules.

The action will not be allowed if either one of these models does not permit the action.
In this way,AppArmor rules can only make a system's permissions more restrictive and secure.

Rationale:

Without a Mandatory Access Control system installed only the default Discretionary
Access Control system will be available.
"

c="
apparmor is installed
apparmor-utils is installed"

d1=$(dpkg-query -s apparmor &>/dev/null && echo "apparmor is installed" || echo "apparmor is not installed" 2>&1)

d2=$(dpkg-query -s apparmor-utils &>/dev/null && echo "apparmor-utils is installed" || echo "apparmor-utils is not installed" 2>&1)

d="$d1, 
$d2"

[ "$d1" == "apparmor is installed" ] && [ "$d2" == "apparmor-utils is installed" ] && e="PASS" || e="FAIL"

f="
Configure AppArmor using,

#apt install apparmor apparmor-utils"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.3.1.2 Ensure AppArmor is enabled in the bootloader configuration "

b="
Configure AppArmor to be enabled at boot time and verify that it has not been
overwritten by the bootloader boot parameters.

Note: This recommendation is designed around the grub bootloader, if LILO or another
bootloader is in use in your environment enact equivalent settings.

Rationale:
AppArmor must be enabled at boot time in your bootloader configuration to ensure that
the controls it provides are not overridden."

c="AppArmor is enabled in the bootloader configuration"

check=$(grep "^\s*linux" /boot/grub/grub.cfg | grep -v -e "apparmor=1" -e "security=apparmor" 2>&1)

[ -z "$check" ] && { d="AppArmor is enabled in the bootloader configuration"; e="PASS"; } || { d="AppArmor is not enabled in the bootloader configuration"; e="FAIL"; }

f="
Edit /etc/default/grub and add the apparmor=1 and security=apparmor
parameters to the GRUB_CMDLINE_LINUX= line

GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"

Run the following command to update the grub2 configuration:
# update-grub"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file
sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.3.1.3 Ensure all AppArmor Profiles are in enforce or complain mode"

b="AppArmor profiles define what resources applications are able to access.

Rationale:
Security configuration requirements vary from site to site. Some sites may mandate a
policy that is stricter than the default policy, which is perfectly acceptable. 
This is intended to ensure that any policies that exist on the system are activated"

c="
(no. of) profiles are loaded.
(no. of) profiles are in enforce mode.
(no. of) profiles are in complain mode.
(no. of) processes have profiles defined."

d=$(apparmor_status | grep profiles 2>&1)

[ -n "$d" ] &&
   [[ "$d" == *" profiles are loaded"* ]] &&
   [[ "$d" == *" profiles are in enforce mode"* ]] &&
   [[ "$d" == *" profiles are in complain mode"* ]] &&
   [[ "$d" == *" processes have profiles defined"* ]] && e="PASS" || e="FAIL"

f="
Run the following command to set all profiles to enforce mode:
# aa-enforce /etc/apparmor.d/*
- OR -
Run the following command to set all profiles to complain mode:
# aa-complain /etc/apparmor.d/*

Note: Any unconfined processes may need to have a profile created or activated for
them and then be restarted"

echo "\"$a\",\"$d\",\"$e\"" >> $csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.3.1.4 Ensure all AppArmor Profiles are enforcing"

b="AppArmor profiles define what resources applications are able to access.

Rationale:
Security configuration requirements vary from site to site. Some sites may mandate a
policy that is stricter than the default policy, which is perfectly acceptable. 
This is intended to ensure that any policies that exist on the system are activated"

c="
(no. of) processes have profiles defined.
(no. of) processes are in enforce mode.
(no. of) processes are in complain mode.
(no. of) processes are unconfined but have a profile defined.."

d=$(apparmor_status | grep processes 2>&1)

[ -n "$d" ] &&
   [[ "$d" == *" processes have profiles defined"* ]] &&
   [[ "$d" == *" processes are in enforce mode"* ]] &&
   [[ "$d" == *" processes are in complain mode"* ]] &&
   [[ "$d" == *" processes are unconfined but have a profile defined"* ]] && e="PASS" || e="FAIL"

f="
Run the following command to set all profiles to enforce mode:
# aa-enforce /etc/apparmor.d/*

Note: Any unconfined processes may need to have a profile created or activated for
them and then be restarted"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.4.1 Ensure bootloader password is set"

b="
Setting the boot loader password will require that anyone rebooting the system must
enter a password before being able to set command line boot parameters.

Rationale:

Requiring a boot password upon execution of the boot loader will prevent an
unauthorized user from entering boot parameters or changing the boot partition.
This prevents users from weakening security(e.g. turning off AppArmor at boot time)"

c="set superusers=(usernames)
password_pbkdf2 (usernames) grub.pbkdf2.sha512"

d1=$(grep "^set superusers" /boot/grub/grub.cfg 2>&1)

d2=$(awk -F. '/^\s*password/ {print $1"."$2"."$3}' /boot/grub/grub.cfg 2>&1)

d="$d1, $d2"

[[ "$d1" == *set\ superusers=* && "$d2" == *password* ]] && e="PASS" || e="FAIL"

f="
Create an encrypted password with grub-mkpasswd-pbkdf2:
# grub-mkpasswd-pbkdf2 --iteration-count=600000 --salt=64
Enter password: <password>
Reenter password: <password>
PBKDF2 hash of your password is <encrypted-password>

Add the following into a custom /etc/grub.d configuration file:
cat <<EOF
exec tail -n +2 $ 0
set superusers="username"
password_pbkdf2 <username> <encrypted-password>
EOF

The superuser/user information and password should not be contained in the
/etc/grub.d/00_header file as this file could be overwritten in a package update.

If there is a requirement to be able to boot/reboot without entering the password, edit
/etc/grub.d/10_linux and add --unrestricted to the line CLASS=

Run the following command to update the grub2 configuration:
# update-grub "

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.4.2 Ensure access to bootloader config is configured"

b="
The grub configuration file contains information on boot settings and passwords for
unlocking boot options.

Rationale:

Setting the permissions to read and write for root only prevents non-root users from
seeing the boot parameters or changing them. 
Non-root users who read the boot parameters may be able to identify weaknesses in 
security upon boot and be able to exploit them."

c="Access: ( (≤0600)/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)"

d=$(stat -Lc 'Access: (%#a/%A) Uid: (%u/%U) Gid: (%g/%G)' /boot/grub/grub.cfg 2>&1)

access=$(echo "$d" | grep -oP '(?<=Access: \()[0-9]{4}')
uid=$(echo "$d" | grep -oP '(?<=Uid: \()[0-9]+')
gid=$(echo "$d" | grep -oP '(?<=Gid: \()[0-9]+')

[[ "$uid" == "0" && "$gid" == "0" && "$access" -le "0600" ]] && e="PASS" || e="FAIL"

f="
Run the following commands to set permissions on your grub configuration:

# chown root:root /boot/grub/grub.cfg
# chmod u-x,go-rwx /boot/grub/grub.cfg"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.5.1 Ensure address space layout randomization is enabled"

b="
Address space layout randomization (ASLR) is an exploit mitigation technique which
randomly arranges the address space of key data areas of a process.

Rationale:

Randomly placing virtual memory regions will make it difficult to write memory page
exploits as the memory placement will be consistently shifting"

c="kernel.randomize_va_space = 2"

d=$(sysctl kernel.randomize_va_space 2>&1)

[[ "$d" == "kernel.randomize_va_space = 2" ]] && e="PASS" || e="FAIL"

f="
Set the following parameter in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
kernel.randomize_va_space = 2

Run the following command to set the active kernel parameter:
# sysctl -w kernel.randomize_va_space=2

Note: If these settings appear in a canonically later file, or later in the same file, these
settings will be overwritten"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.5.2 Ensure ptrace_scope is restricted"

b="
The ptrace() system call provides a means by which one process (the "tracer") may
observe and control the execution of another process (the "tracee"), and examine and
change the tracee's memory and registers.

The sysctl settings (writable only with CAP_SYS_PTRACE) are:
0 - classic ptrace permissions: a process can PTRACE_ATTACH to any other
process running under the same uid, as long as it is dumpable (i.e. did not
transition uids, start privileged, or have called prctl(PR_SET_DUMPABLE...)
already). Similarly, PTRACE_TRACEME is unchanged.

1 - restricted ptrace: a process must have a predefined relationship with the
inferior it wants to call PTRACE_ATTACH on. By default, this relationship is that
of only its descendants when the above classic criteria is also met. To change
the relationship, an inferior can call prctl(PR_SET_PTRACER, debugger, ...) to
declare an allowed debugger PID to call PTRACE_ATTACH on the inferior.
Using PTRACE_TRACEME is unchanged.

2 - admin-only attach: only processes with CAP_SYS_PTRACE may use ptrace
with PTRACE_ATTACH, or through children calling PTRACE_TRACEME.

3 - no attach: no processes may use ptrace with PTRACE_ATTACH nor via
PTRACE_TRACEME. Once set, this sysctl value cannot be changed.

Rationale:

If one application is compromised, it would be possible for an attacker to attach to other
running processes (e.g. Bash, Firefox, SSH sessions, GPG agent, etc) to extract
additional credentials and continue to expand the scope of their attack.

Enabling restricted mode will limit the ability of a compromised process to
PTRACE_ATTACH on other processes running under the same user. With restricted
mode, ptrace will continue to work with root user"

c="kernel.yama.ptrace_scope is set to a value of: 1 or 2 or 3"

d=$(sysctl kernel.yama.ptrace_scope)

echo "$d" | grep -q -E '1|2|3' && e="PASS" || e="FAIL"

f="
Set the kernel.yama.ptrace_scope parameter in /etc/sysctl.conf or a file in
/etc/sysctl.d/ ending in .conf to a value of 1, 2, or 3:
kernel.yama.ptrace_scope = 1 or 2 or 3

Run the following command to set the active kernel parameter:
# sysctl -w kernel.yama.ptrace_scope= 1 or 2 or 3

Note:

*If a value of 2 or 3 is preferred, or required by local site policy, replace the 1 with
the desired value of 2 or 3 in the example above

*If this setting appears in a canonically later file, or later in the same file, the
setting will be overwritten.
"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.5.3 Ensure core dumps are restricted "

b="
A core dump is the memory of an executable program. It is generally used to determine
why a program aborted. It can also be used to glean confidential information from a core
file. The system provides the ability to set a soft limit for core dumps, but this can be
overridden by the user.

Rationale:

Setting a hard limit on core dumps prevents users from overriding the soft variable. If
core dumps are required, consider setting limits for user groups (see limits.conf(5)). 
In addition, setting the fs.suid_dumpable variable to 0 will prevent setuid programs
from dumping core."

c="hard core 0
fs.suid_dumpable = 0"

d1=$(grep -Ps -- '^\h*\*\h+hard\h+core\h+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>&1)

d2=$(sysctl fs.suid_dumpable)

d="$d1
$d2"

[[ "$d1" == "* hard core 0" ]] && [[ "$d2" == "fs.suid_dumpable = 0" ]] && e="PASS" || e="FAIL"

f="
Add the following line to /etc/security/limits.conf or a
/etc/security/limits.d/* file:    * hard core 0
Set the following parameter in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending
in .conf:     fs.suid_dumpable = 0

Run the following command to set the active kernel parameter:
# sysctl -w fs.suid_dumpable=0

Note: If these settings appear in a canonically later file, or later in the same file, these
settings will be overwritten

-IF- systemd-coredump is installed:
edit /etc/systemd/coredump.conf and add/modify the following lines:
Storage=none
ProcessSizeMax=0

Run the command:
systemctl daemon-reload"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.5.4 Ensure prelink is not installed "

#no output 

b="Prelink is a program that modifies ELF shared libraries and ELF dynamically linked
binaries in such a way that the time needed for the dynamic linker to perform relocations
at startup significantly decreases.

Rationale:

The prelinking feature can interfere with the operation of AIDE, because it changes
binaries. Prelinking can also increase the vulnerability of the system if a malicious user
is able to compromise a common library such as libc."

c="Prelink is not installed"

check=$(dpkg -l | grep prelink 2>&1)

[ -z "$check" ] && { d="Prelink is not installed"; e="PASS"; } || { d="Prelink is installed"; e="FAIL"; }

f="
Run the following command to restore binaries to normal:
# prelink -ua

Uninstall prelink using the appropriate package manager or manual installation:
# apt purge prelink"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.5.5 Ensure Automatic Error Reporting is disabled "

#no output

b="
The Apport Error Reporting Service automatically generates crash reports for debugging.

Rationale:

Apport collects potentially sensitive data, such as core dumps, stack traces, and log
files. They can contain passwords, credit card numbers, serial numbers, and other
private material."

c="enabled=0"

d=$( dpkg-query -s apport &> /dev/null && grep -Psi -- '^\h*enabled\h*=\h*[^0]\b' /etc/default/apport )

[ "$d" == "enabled=0" ] && e="PASS" || e="FAIL"

f="
Edit /etc/default/apport and add or edit the enabled parameter to equal 0:
enabled=0

Run the following commands to stop and mask the apport service
# systemctl stop apport.service
# systemctl mask apport.service
- OR -
Run the following command to remove the apport package:
# apt purge apport"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.6.1 Ensure message of the day is configured properly"

#no output 

b="The contents of the /etc/motd file are displayed to users after login and 
function as a message of the day for authenticated users.

Rationale:

Warning messages inform users who are attempting to login to the system of their legal
status regarding the system and must include the name of the organization that owns
the system and any monitoring policies that are in place. Displaying OS and patch level
information in login banners also has the side effect of providing detailed system
information to attackers attempting to target specific exploits of a system."

c="Message of the day is configured"

check=$(grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd)

[ -z "$check" ] && { d="Message of the day is configured"; e="PASS"; } || { d="Message of the day is not configured"; e="FAIL"; }

f="
Edit the /etc/motd file with the appropriate contents according to your site policy,
remove any instances of \m , \r , \s , \v or references to the OS platform
- OR -
- IF - the motd is not used, this file can be removed.

Run the following command to remove the motd file:
# rm /etc/motd"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.6.2 Ensure local login warning banner is configured properly"

#no output 

b="The contents of the /etc/issue file are displayed to users prior 
to login for local terminals."

c="Local login warning banner is configured"

check=$( grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue )

[ -z "$check" ] && { d="Local login warning banner is configured"; e="PASS"; } || { d="Local login warning banner is not configured"; e="FAIL"; }

f="
Edit the /etc/issue file with the appropriate contents according to your site policy,
remove any instances of \m , \r , \s , \v or references to the OS platform
Example:
# echo "Message" > /etc/issue"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.6.3 Ensure remote login warning banner is configured properly"

#no output 

b="The contents of the /etc/issue.net file are displayed to users prior 
to login for remote connections from configured services."

c="Remote login warning banner is configured"

check=$( grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net 2>&1)

[ -z "$check" ] && { d="Remote login warning banner is configured"; e="PASS"; } || { d="Remote login warning banner is not configured"; e="FAIL"; }

f="
Edit the /etc/issue.net file with the appropriate contents according to your site policy,
remove any instances of \m , \r , \s , \v or references to the OS platform

Example:
# echo "Message" >/etc/issue.net"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.6.4 Ensure access to /etc/motd is configured "

#no output 

b="
The contents of the /etc/motd file are displayed to users after login and
function as a message of the day for authenticated users.

Rationale:
If the /etc/motd file does not have the correct access configured, it could be
modified by unauthorized users with incorrect or misleading information."

c="Access to /etc/motd is configured"

check=$( [ -e /etc/motd ] && stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: { %g/ %G)' /etc/motd 2>&1)

[ -z "$check" ] || [[ ! "$check" == *"Access"* ]] && { d="Access to /etc/motd is configured"; e="PASS"; } || { d="Access to /etc/motd is not configured"; e="FAIL"; }

f='Run the following commands to set mode, owner, and group on /etc/motd:
# chown root:root $(readlink -e /etc/motd)
# chmod u-x,go-wx $(readlink -e /etc/motd)'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.6.5 Ensure access to /etc/issue is configured "

b='
The contents of the /etc/issue file are displayed to users prior to login for local terminals.

Rationale:
- IF - the /etc/issue file does not have the correct access configured, it could be
modified by unauthorized users with incorrect or misleading information.'

c='Access: ( '≤0644'/-rw-r--r--) Uid: ( 0/ root) Gid: { 0/ root)'

d=$(stat -Lc 'Access: (%#a/%A) Uid: (%u/%U) Gid: (%g/%G)' /etc/issue 2>&1)

access=$(echo "$d" | grep -oP '(?<=Access: \()[0-9]{4}')
uid=$(echo "$d" | grep -oP '(?<=Uid: \()[0-9]+')
gid=$(echo "$d" | grep -oP '(?<=Gid: \()[0-9]+')

[[ "$uid" == "0" && "$gid" == "0" && $((8#$access)) -ge 0644 ]] && e="PASS" || e="FAIL"

f='
Run the following commands to set mode, owner, and group on /etc/issue:
# chown root:root $(readlink -e /etc/issue)
# chmod u-x,go-wx $(readlink -e /etc/issue)'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.6.6 Ensure access to /etc/issue.net is configured "

b='
The contents of the /etc/issue.net file are displayed to users prior to login for remote
connections from configured services.

Rationale:
- IF - the /etc/issue.net file does not have the correct access configured, it could be
modified by unauthorized users with incorrect or misleading information.'

c='Access: ("≤0644"/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)'

d=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: { %g/ %G)' /etc/issue.net 2>&1) 

access=$(echo "$d" | grep -oP 'Access: \(\K[0-9]+')
uid=$(echo "$d" | grep -oP 'Uid: \( \K[0-9]+')
gid=$(echo "$d" | grep -oP 'Gid: { \K[0-9]+')

[ "$access" -le 644 ] && [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ] && e="PASS" || e="FAIL"

f='
Run the following commands to set mode, owner, and group on /etc/issue.net:
# chown root:root $(readlink -e /etc/issue.net)
# chmod u-x,go-wx $(readlink -e /etc/issue.net)'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.7.1 Ensure GDM is removed "

b='
The GNOME Display Manager (GDM) is a program that manages graphical display
servers and handles graphical user logins.

Rationale:
If a Graphical User Interface (GUI) is not required, it should be removed 
to reduce the attack surface of the system.'

c='gdm3 unknown ok not-installed not-installed'

d=$( dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' gdm3 2>&1 )

[ "$d" == *"not-installed"* ] && e="PASS" || e="FAIL"

f='
Run the following commands to uninstall gdm3 and remove unused dependencies:
# apt purge gdm3
# apt autoremove gdm3

Note: 
Removing the GNOME Display manager will remove the Graphical User Interface (GUI)
from the system'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.7.2 Ensure GDM login banner is configured "

b='
GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.

Rationale:
Warning messages inform users who are attempting to login to the system of their legal
status regarding the system and must include the name of the organization that owns
the system and any monitoring policies that are in place.'

c='true
(banner message)'

d1=$(gsettings get org.gnome.login-screen banner-message-enable)

d2=$(gsettings get org.gnome.login-screen banner-message-text)

d="$d1
$d2"

[[ "$d1" == "false" && "$d2" == "''" ]] && e="FAIL" || e="PASS"

f='
- IF - A user profile is already created run the following commands to set and enable the
text banner message on the login screen:

# gsettings set org.gnome.login-screen banner-message-text 'message'
# gsettings set org.gnome.login-screen banner-message-enable true '

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.7.3 Ensure GDM disable-user-list option is enabled "

b='
GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.
The disable-user-list option controls if a list of users is displayed on the login screen

Rationale:
Displaying the user list eliminates half of the Userid/Password equation that an
unauthorized person would need to log on.'

c='true'

d=$(gsettings get org.gnome.login-screen disable-user-list)

[[ "$d" == "false" ]] && e="FAIL" || e="PASS"

f='
- IF - A user profile exists run the following command to enable the disable-user-list:

# gsettings set org.gnome.login-screen disable-user-list true'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.7.4 Ensure GDM screen locks when the user is idle"

b='GNOME Desktop Manager can make the screen lock automatically whenever the user
is idle for some amount of time.

Rationale:
Setting a lock-out value reduces the window of opportunity for unauthorized user access
to another session of a user that has been left unattended.'

c='
lock-delay=uint32 {n} - should be 5 seconds or less and follow local site policy
idle-delay=uint32 {n} - Should be 900 seconds (15 minutes) or less, not 0
(disabled) and follow local site policy'

d1=$(gsettings get org.gnome.desktop.screensaver lock-delay | awk '{print $2}' )

d2=$(gsettings get org.gnome.desktop.session idle-delay | awk '{print $2}' )

d="lock-delay=uint32: $d1 seconds
idle-delay=uint32: $d2 seconds"

[[ "$d1" -le 5 && "$d1" -ne 0 ]] &&  [[ "$d2" -le 900 && "$d2" -ne 0 ]] && e="PASS" || e="FAIL"

f='
- IF - A user profile is already created run the following commands to enable screen
locks when the user is idle:

# gsettings set org.gnome.desktop.screensaver lock-delay ( ≤ 5 seconds)
# gsettings set org.gnome.desktop.session idle-delay ( ≤ 900 seconds)'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.7.5 Ensure GDM screen locks cannot be overridden"

b="GNOME Desktop Manager can lock down specific settings by using the lockdown mode
in dconf to prevent users from changing specific settings.

To lock down a dconf key or subpath, create a locks subdirectory in the keyfile directory.
The files inside this directory contain a list of keys or subpaths to lock. Just as with the
keyfiles, you may add any number of files to this directory.

Rationale:
Setting a lock-out value reduces the window of opportunity for unauthorized user access
to another user's session that has been left unattended.

Without locking down the system settings, user settings take precedence over the
system settings."

c='false
true'

d1=$(gsettings get org.gnome.desktop.lockdown disable-lock-screen)

d2=$( gsettings get org.gnome.desktop.screensaver lock-enabled  )

d="$d1
$d2"

[[ "$d1" == "false" && "$d2" == "true" ]] && e="PASS" || e="FAIL"

f='
To prevent the user from overriding these settings, create the file
/etc/dconf/db/local.d/locks/00-screensaver with the following content:

# Lock desktop screensaver settings
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-delay'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="1.7.6 Ensure GDM automatic mounting of removable media is disabled  "

b='
By default GNOME automatically mounts removable media when inserted as a
convenience to the user.

Rationale:

With automounting enabled anyone with physical access could attach a USB drive
or disc and have its contents available in system even if they lacked 
permissions to mount it themselves.'

c='false
false'

d1=$(gsettings get org.gnome.desktop.media-handling automount 2>&1)

d2=$(gsettings get org.gnome.desktop.media-handling automount-open 2>&1)

d="$d1
$d2"

[[ "$d1" == "false" && "$d2" == "false" ]] && e="PASS" || e="FAIL"

f='
- IF - A user profile exists run the following commands to ensure automatic 
mounting is disabled:

# gsettings set org.gnome.desktop.media-handling automount false
# gsettings set org.gnome.desktop.media-handling automount-open false '

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.7.7 Ensure GDM disabling automatic mounting of removable media is not overridden "

b='
By default GNOME automatically mounts removable media when inserted as a
convenience to the user.
By using the lockdown mode, you can prevent users from changing specific settings. 
To lock down a dconf key or subpath, create a locks subdirectory in keyfile directory. 

The files inside this directory contain a list of keys or subpaths to lock. Just as
with the keyfiles, you may add any number of files to this directory.

Rationale:
With automounting enabled anyone with physical access could attach a USB drive or
disc and have its contents available in system even if they lacked permissions to mount
it themselves.'

c='false'

d=$( gsettings get org.gnome.desktop.media-handling automount 2>&1)

[ "$d" == "false" ] && e="PASS" || e="FAIL"

f='
Execute the follwing command,

gsettings set org.gnome.desktop.media-handling automount false'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="1.7.8 Ensure GDM autorun-never is enabled "

b='
The autorun-never setting allows the GNOME Desktop Display Manager to disable autorun through GDM.

Rationale:

Malware on removable media may taking advantage of Autorun features when the media is inserted 
into a system and execute.'

c='true'

d=$(gsettings get org.gnome.desktop.media-handling autorun-never)

[[ "$d" == "false" ]] && e="FAIL" || e="PASS"

f='
- IF - A user profile exists run the following command to set autorun-never to true for
GDM users:
# gsettings set org.gnome.desktop.media-handling autorun-never true '

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="1.7.9 Ensure GDM autorun-never is not overridden"

b='
The setting allows the GNOME Desktop Display Manager to disable autorun through GDM.
By using the lockdown mode in dconf, you can prevent users from changing specific settings.

To lock down a dconf key or subpath, create a locks subdirectory in the keyfile directory.
The files inside this directory contain a list of keys or subpaths to lock. Just as with the
keyfiles, you may add any number of files to this directory.

Rationale:
Malware on removable media may taking advantage of Autorun features when the
media is inserted into a system and execute.'

c='true'

d=$(gsettings get org.gnome.desktop.media-handling autorun-never 2>&1)

[[ "$d" == "false" ]] && e="FAIL" || e="PASS"

f='
1. To prevent the user from overriding these settings, create the file
/etc/dconf/db/local.d/locks/00-media-autorun with the following content:
[org/gnome/desktop/media-handling]
autorun-never=true

2. Update the systems databases:
# dconf update'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="1.7.10 Ensure XDMCP is disabled "

#no output 

b='X Display Manager Control Protocol (XDMCP) is designed to provide authenticated
access to display management services for remote displays.

Rationale:

XDMCP is inherently insecure.
* XDMCP is not a ciphered protocol. This may allow an attacker to capture
keystrokes entered by a user
* XDMCP is vulnerable to man-in-the-middle attacks. This may allow an attacker to
steal the credentials of legitimate users by impersonating the XDMCP server.'

c='XDMCP is disabled'

check=$(
while IFS= read -r l_file; do
awk '/\[xdmcp\]/{ f = 1;next } /\[/{ f = 0 } f {if (/^\s*Enable\s*=\s*true/) print "The file: \"'"$l_file"'\" includes: \"" $0 "\" in the \"[xdmcp]\" block"}' "$l_file"
done < <(grep -Psil -- '^\h*\[xdmcp\]' /etc/{gdm3,gdm}/{custom,daemon}.conf)
)

[ -z "$check" ] && { d="XDMCP is disabled"; e="PASS"; } || { d="XDMCP is enabled"; e="FAIL"; }

f='
Edit all files returned by the audit and remove or commend out the Enable=true line
in the [xdmcp] block'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.1 Ensure autofs services are not in use"

#no output 

b='
Autofs allows automatic mounting of devices, typically including CD/DVDs and USB drives.

Rationale:

With automounting enabled anyone with physical access could attach a USB drive or disc 
and have its contents available in the filesystem even if they lacked permissions to
mount it themselves.'

c='autofs is not installed'

d=$( dpkg-query -s autofs &>/dev/null && echo "autofs is installed" || echo "autofs is not installed" )

[ "$d" == "autofs is not installed"  ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop autofs.service and remove the autofs package:
# systemctl stop autofs.service
# apt purge autofs

or

If the autofs package is required as a dependency:
Run the following commands to stop and mask autofs.service:
# systemctl stop autofs.service
# systemctl mask autofs.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.2 Ensure avahi daemon services are not in use  "

#no output 

b='
Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD
service discovery. Avahi allows programs to publish and discover services and hosts
running on a local network with no specific configuration. 

Rationale:

Automatic discovery of network services is not required for system functionality.
It is recommended to remove this package to reduce the potential attack surface.'

c='avahi-daemon is not installed'

d=$( dpkg-query -s avahi-daemon &>/dev/null && echo "avahi-daemon is installed"|| echo "avahi-daemon is not installed")

[ "$d" == "avahi-daemon is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop avahi-daemon.socket and avahi-daemon.service, 
and remove the avahi-daemon package:
# systemctl stop avahi-daemon.socket avahi-daemon.service
# apt purge avahi-daemon

or

If the avahi-daemon package is required as a dependency:
Run the following commands to stop and mask the avahi-daemon.socket and avahi-daemon.service:
# systemctl stop avahi-daemon.socket avahi-daemon.service
# systemctl mask avahi-daemon.socket avahi-daemon.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.3 Ensure dhcp server services are not in use"

#no output 

b='
The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to
be dynamically assigned IP addresses. There are two versions of the DHCP protocol
DHCPv4 and DHCPv6. At startup the server may be started for one or the other via the -4
or -6 arguments.

Rationale:

Unless a system is specifically set up to act as a DHCP server, it is recommended that
this package be removed to reduce the potential attack surface.'

c='isc-dhcp-server is not installed'

d=$( dpkg-query -s isc-dhcp-server &>/dev/null && echo "isc-dhcp-server is installed" || echo "isc-dhcp-server is not installed" )

[ "$d" == "isc-dhcp-server is not installed" ] && e="PASS" || e="FAIL"

f='Run the following commands to stop isc-dhcp-server.service and isc-dhcp-
server6.service and remove the isc-dhcp-server package:
# systemctl stop isc-dhcp-server.service isc-dhcp-server6.service
# apt purge isc-dhcp-server

or

If the isc-dhcp-server package is required as a dependency:
Run the following commands to stop and mask isc-dhcp-server.service and isc-dhcp-server6.service:
# systemctl stop isc-dhcp-server.service isc-dhcp-server6.service
# systemctl mask isc-dhcp-server isc-dhcp-server6.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.4 Ensure dns server services are not in use "

#no output 

b='
The Domain Name System (DNS) is a hierarchical naming system that maps names to
IP addresses for computers, services and other resources connected to a network.
Note: bind9 is the package and bind.service is the alias for named.service.

Rationale:
Unless a system is specifically designated to act as a DNS server, it is recommended
that the package be deleted to reduce the potential attack surface.'

c='bind9 is not installed'

d=$( dpkg-query -s bind9 &>/dev/null && echo "bind9 is installed" || echo "bind9 is not installed" )

[ "$d" == "bind9 is not installed" ] && e="PASS" || e="FAIL"

f='Run the following commands to stop named.service and remove the bind9 package:
# systemctl stop named.service
# apt purge bind9

or

If the bind9 package is required as a dependency:
Run the following commands to stop and mask bind9.service:
# systemctl stop named.service
# systemctl mask named.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.5 Ensure dnsmasq services are not in use "

#no output 

b='
dnsmasq is a lightweight tool that provides DNS caching, DNS forwarding and DHCP services.

Rationale:
Unless a system is specifically designated to act as a DNS caching, DNS forwarding
and/or DHCP server, it is recommended that the package be removed to reduce the
potential attack surface.'

c='dnsmasq is not installed'

d=$( dpkg-query -s dnsmasq &>/dev/null && echo "dnsmasq is installed" || echo "dnsmasq is not installed" )

[ "$d" == "dnsmasq is not installed" ] && e="PASS" || e="FAIL"

f='Run the following commands to stop dnsmasq.service and remove dnsmasq package:
# systemctl stop dnsmasq.service
# apt purge dnsmasq

or

If the dnsmasq package is required as a dependency:
Run the following commands to stop and mask the dnsmasq.service:
# systemctl stop dnsmasq.service
# systemctl mask dnsmasq.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.6 Ensure ftp server services are not in use  "

#no output 

b="
The File Transfer Protocol (FTP) provides networked computers with the ability to
transfer files. vsftpd is the Very Secure File Transfer Protocol Daemon.

Rationale:

FTP does not protect the confidentiality of data or authentication credentials. It is
recommended SFTP be used if file transfer is required. Unless there is a need to run
the system as a FTP server (for example, to allow anonymous downloads), it is
recommended that the package be deleted to reduce the potential attack surface."

c="vsftpd is not installed"

d=$( dpkg-query -s vsftpd &>/dev/null && echo "vsftpd is installed" || echo "vsftpd is not installed" )

[ "$d" == "vsftpd is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop vsftpd.service and remove the vsftpd
package:
# systemctl stop vsftpd.service
# apt purge vsftpd

or

- IF - the vsftpd package is required as a dependency:
Run the following commands to stop and mask the vsftpd.service:
# systemctl stop vsftpd.service
# systemctl mask vsftpd.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.7 Ensure ldap server services are not in use "

#no output 

b='
The LDAP was introduced as a replacement for NIS/YP. It is a service that provides
a method for looking up information from a central database.

Rationale:
If the system will not need to act as an LDAP server, it is recommended that the
software be removed to reduce the potential attack surface.'

c='slapd is not installed'

d=$( dpkg-query -s slapd &>/dev/null && echo "slapd is installed" || echo "slapd is not installed" )

[ "$d" == "slapd is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop slapd.service and 
remove the slapd package:
# systemctl stop slapd.service
# apt purge slapd

or

If the slapd package is required as a dependency:
Run the following commands to stop and mask slapd.service:
# systemctl stop slapd.service
# systemctl mask slapd.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.8 Ensure message access server services are not in use "

#no output 

b='
dovecot-imapd and dovecot-pop3d are an open source IMAP and POP3 server for
Linux based systems.

Rationale:
Unless POP3 and/or IMAP servers are to be provided by this system, it is
recommended that the package be removed to reduce the potential attack surface.
Note: Several IMAP/POP3 servers exist and can use other service names. These
should also be audited and the packages removed if not required'

c='dovecot-imapd is not installed'

d=$( dpkg-query -s dovecot-imapd &>/dev/null && echo "dovecot-imapd is installed" || echo "dovecot-imapd is not installed" )

[ "$d" == "dovecot-imapd is not installed" ] && e="PASS" || e="FAIL"

f='
Run one of the following commands to remove dovecot-imapd and dovecot-pop3d:
Run the following commands to stop dovecot.socket and dovecot.service, and
remove the dovecot-imapd and dovecot-pop3d packages:
# systemctl stop dovecot.socket dovecot.service
# apt purge dovecot-imapd dovecot-pop3d

or

If the package is required for dependencies:
Run the following commands to stop and mask dovecot.socket and dovecot.service:
# systemctl stop dovecot.socket dovecot.service
# systemctl mask dovecot.socket dovecot.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.9 Ensure network file system services are not in use "

#no output 

b='
The Network File System (NFS) is one of the first and most widely distributed file
systems in the UNIX environment. It provides the ability for systems to mount file
systems of other servers through the network.

Rationale:
If the system does not export NFS shares, it is recommended that the nfs-kernel-
server package be removed to reduce the remote attack surface.'

c='nfs-kernel-server is not installed'

d=$(dpkg-query -s nfs-kernel-server &>/dev/null && echo "nfs-kernel-server is installed" || echo "nfs-kernel-server is not installed" )

[ "$d" == "nfs-kernel-server is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following command to stop nfs-server.service 
and remove nfs-kernel-server package:
# systemctl stop nfs-server.service
# apt purge nfs-kernel-server

or

If the nfs-kernel-server package is required as a dependency:
Run the following commands to stop and mask the nfs-server.service:
# systemctl stop nfs-server.service
# systemctl mask nfs-server.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.10 Ensure nis server services are not in use  "

#no output

b='
The NIS is a client-server directory service protocol for distributing system configuration files.
The NIS server is a collection of programs that allow for the distribution of configuration files
The NIS client (ypbind) was used to bind a machine to an NIS server and receive the
distributed configuration files.

Rationale:

ypserv.service is inherently an insecure system that has been vulnerable to DOS attacks, buffer
overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by
such protocols as Lightweight Directory Access Protocol (LDAP). 
It is recommended that ypserv.service be removed and other, more secure services be used'

c='ypserv is not installed'

d=$(dpkg-query -s ypserv &>/dev/null && echo "ypserv is installed" || echo "ypserv is not installed" )

[ "$d" == "ypserv is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop ypserv.service and remove ypserv package:
# systemctl stop ypserv.service
# apt purge ypserv

or

 If the ypserv package is required as a dependency:
Run the following commands to stop and mask ypserv.service:
# systemctl stop ypserv.service
# systemctl mask ypserv.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.11 Ensure print server services are not in use "

#no output 

b='
The Common Unix Print System (CUPS) provides the ability to print to both local and
network printers. A system running CUPS can also accept print jobs from remote
systems and print them to local printers. 
It also provides a web based remote administration capability.

Rationale:
If the system does not need to print jobs or accept print jobs from other systems, it is
recommended that CUPS be removed to reduce the potential attack surface.'

c='cups is not installed'

d=$( dpkg-query -s cups &>/dev/null && echo "cups is installed" || echo "cups is not installed" )

[ "$d" == "cups is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop cups.socket and cups.service,
and remove the cups package:
# systemctl stop cups.socket cups.service
# apt purge cups

or

If the cups package is required as a dependency:
Run the following commands to stop and mask the cups.socket and cups.service:
# systemctl stop cups.socket cups.service
# systemctl mask cups.socket cups.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.12 Ensure rpcbind services are not in use "

#no output 

b='The rpcbind utility maps RPC services to the ports on which they listen. RPC
processes notify rpcbind when they start, registering the ports they are listening on and
the RPC program numbers they expect to serve. The client system then contacts
rpcbind on the server with a particular RPC program number. The rpcbind.service
redirects the client to the proper port number so it can communicate with the requested service.

Portmapper is an RPC service, which always listens on tcp and udp 111, and is used to
map other RPC services (such as nfs, nlockmgr, quotad, mountd, etc.) to their
corresponding port number on the server. When a remote host makes an RPC call to
that server, it first consults with portmap to determine where the RPC server is listening.

Rationale:
A small request (~82 bytes via UDP) sent to the Portmapper generates a large
response (7x to 28x amplification), which makes it a suitable tool for DDoS attacks. If
rpcbind is not required, it is recommended to remove rpcbind package to reduce the
potential attack surface.'

c='rpcbind is not installed'

d=$( dpkg-query -s rpcbind &>/dev/null && echo "rpcbind is installed" || echo "rpcbind is not installed" )

[ "$d" == "rpcbind is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop rpcbind.socket and rpcbind.service, and
remove the rpcbind package:
# systemctl stop rpcbind.socket rpcbind.service
# apt purge rpcbind

(or)

If the rpcbind package is required as a dependency:
Run the following commands to stop and mask the rpcbind.socket and
rpcbind.service:
# systemctl stop rpcbind.socket rpcbind.service
# systemctl mask rpcbind.socket rpcbind.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.13 Ensure rsync services are not in use "

#no output 

b='
The rsync service can be used to synchronize files between systems over network links.

Rationale:
rsync.service presents a security risk as the rsync protocol is unencrypted.
The rsync package should be removed to reduce the attack area of the system'

c='rsync is not installed'

d=$( dpkg-query -s rsync &>/dev/null && echo "rsync is installed" || echo "rsync is not installed" )

[ "$d" == "rsync is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop rsync.service, and remove the rsync package:
# systemctl stop rsync.service
# apt purge rsync

(or)

If the rsync package is required as a dependency:
Run the following commands to stop and mask rsync.service:
# systemctl stop rsync.service
# systemctl mask rsync.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.14 Ensure samba file server services are not in use "

#no output 

b='
The Samba daemon allows system administrators to configure their Linux systems to
share file systems and directories with Windows desktops. Samba will advertise the file
systems and directories via the Server Message Block (SMB) protocol. Windows
desktop users will be able to mount these directories and file systems as letter drives on
their systems.

Rationale:
If there is no need to mount directories and file systems to Windows systems, then this
service should be deleted to reduce the potential attack surface'

c='samba is not installed'

d=$(dpkg-query -s samba &>/dev/null && echo "samba is installed" || echo "samba is not installed" )

[ "$d" == "samba is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop smbd.service and remove samba package:
# systemctl stop smbd.service
# apt purge samba

(or)

If the samba package is required as a dependency:
Run the following commands to stop and mask the smbd.service:
# systemctl stop smbd.service
# systemctl mask smbd.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.15 Ensure snmp services are not in use "

#no output 

b='
Simple Network Management Protocol (SNMP) is a widely used protocol for monitoring
the health and welfare of network equipment, computer equipment and devices.

The Simple Network Management Protocol (SNMP) server is used to listen for SNMP
commands from an SNMP management system, execute the commands or collect the
information and then send results back to the requesting system.

Rationale:

The SNMP server can communicate using SNMPv1, which transmits data in the clear
and does not require authentication to execute commands. SNMPv3 replaces the
simple/clear text password sharing used in SNMPv2 with more securely encoded
parameters. If the the SNMP service is not required, the snmpd package should be
removed to reduce the attack surface of the system.'

c='snmpd is not installed'

d=$( dpkg-query -s snmpd &>/dev/null && echo "snmpd is installed" || echo "snmpd is not installed" )

[ "$d" == "snmpd is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop snmpd.service and remove the snmpd package:
# systemctl stop snmpd.service
# apt purge snmpd

(or)

If the package is required for dependencies:
Run the following commands to stop and mask the snmpd.service:
# systemctl stop snmpd.service
# systemctl mask snmpd.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.16 Ensure tftp server services are not in use"

#no output 

b='
Trivial File Transfer Protocol (TFTP) is a simple protocol for exchanging files between
two TCP/IP machines. TFTP servers allow connections from a TFTP Client for sending
and receiving files.

Rationale:

Unless there is a need to run the system as a TFTP server, it is recommended that the
package be removed to reduce the potential attack surface.
TFTP does not have built-in encryption, access control or authentication. This makes it
very easy for an attacker to exploit TFTP to gain access to files'

c='tftpd-hpa is not installed'

d=$( dpkg-query -s tftpd-hpa &>/dev/null && echo "tftpd-hpa is installed" || echo "tftpd-hpa is not installed" )

[ "$d" == "tftpd-hpa is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop tftpd-hpa.service, and remove the tftpd-hpa
package:
# systemctl stop tftpd-hpa.service
# apt purge tftpd-hpa

(or)

If the tftpd-hpa package is required as a dependency:
Run the following commands to stop and mask tftpd-hpa.service:
# systemctl stop tftpd-hpa.service
# systemctl mask tftpd-hpa.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.17 Ensure web proxy server services are not in use"

#no output 

b='
Squid is a standard proxy server used in many distributions and environments.

Rationale:

Unless a system is specifically set up to act as a proxy server, it is recommended that
the squid package be removed to reduce the potential attack surface.'

c='squid is not installed'

d=$( dpkg-query -s squid &>/dev/null && echo "squid is installed" || echo "squid is not installed" )

[ "$d" == "squid is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop squid.service and remove the squid package:
# systemctl stop squid.service
# apt purge squid

(or)

If the squid package is required as a dependency:
Run the following commands to stop and mask the squid.service:
# systemctl stop squid.service
# systemctl mask squid.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.18 Ensure web server services are not in use  "

#no output 

b='
Web servers provide the ability to host web site content.

Rationale:
Unless there is a local site approved requirement to run a web server service on the
system, web server packages should be removed to reduce the potential attack surface.'

c='apache2 is not installed'

d=$( dpkg-query -s apache2 &>/dev/null && echo "apache2 is installed" || echo "apache2 is not installed" )

[ "$d" == "apache2 is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop httpd.socket, httpd.service, and
nginx.service, and remove apache2 and nginx packages:
# systemctl stop apache2.socket apache2.service nginx.service
# apt purge apache2 nginx

(or)

If a package is installed and is required for dependencies:
Run the following commands to stop and mask apache2.socket, apache2.service,
and nginx.service:
# systemctl stop apache2.socket apache2.service nginx.service
# systemctl mask apache2.socket apache2.service nginx.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.19 Ensure xinetd services are not in use  "

#no output 

b='
The eXtended InterNET Daemon (xinetd) listens for well known services and 
dispatches the appropriate daemon to properly respond to service requests.

Rationale:

If there are no xinetd services required, it is recommended that the package be
removed to reduce the attack surface are of the system.

Note: If an xinetd service or services are required, ensure that any xinetd service not
required is stopped and masked'

c='xinetd is not installed'

d=$( dpkg-query -s xinetd &>/dev/null && echo "xinetd is installed" || echo "xinetd is not installed" )

[ "$d" == "xinetd is not installed" ] && e="PASS" || e="FAIL"

f='Run the following commands to stop xinetd.service, and remove the xinetd
package:
# systemctl stop xinetd.service
# apt purge xinetd

(or)

If the xinetd package is required as a dependency:
Run the following commands to stop and mask the xinetd.service:
# systemctl stop xinetd.service
# systemctl mask xinetd.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.20 Ensure X window server services are not in use "

#no output

b='
The X Window System provides a Graphical User Interface (GUI) where users can have
multiple windows in which to run programs and various add on. The X Windows system
is typically used on workstations where users login, but not on servers where users
typically do not login.

Rationale:

Unless your organization specifically requires graphical login access via X Windows,
remove it to reduce the potential attack surface'

c='xserver-common is not installed'

d=$(dpkg-query -s xserver-common &>/dev/null && echo "xserver-common is installed"  || echo "xserver-common is not installed" )

[ "$d" == "xserver-common is not installed" ] && e="PASS" || e="FAIL"

f='
If a Graphical Desktop Manager or X-Windows server is not required
and approved by local site policy:

Run the following command to remove the X Windows Server package:
# apt purge xserver-common'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.1.21 Ensure mail transfer agent is configured for local-only mode "

b="
Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for
incoming mail and transfer the messages to the appropriate user or mail server. 
If the system is not intended to be a mail server, it is recommended that the MTA be
configured to only process local mail.

Rationale:

The software for all Mail Transfer Agents is complex and most have a long history of
security issues. While it is important to ensure that the system can process local mail
messages, it is not necessary to have the MTA's daemon listening on a port unless the
server is intended to be a mail server that receives and process mail from other systems "

c='
(List of ports)
or
MTA not detected or in use'

d1=$(
a_output=() 
a_output2=() 
a_port_list=("25" "465" "587")

for l_port_number in "${a_port_list[@]}"; do
    ss -plntu | grep -P -- ':'"$l_port_number"'\b' | grep -Pvq -- '\h+(127\.0\.0\.1|\[?::1\]?):'"$l_port_number"'\b' && 
    a_output2+=(" - Port \"$l_port_number\" is listening on a non-loopback network interface") || 
    a_output+=(" - Port \"$l_port_number\" is not listening on a non-loopback network interface")
done

command -v postconf &> /dev/null && l_interfaces="$(postconf -n inet_interfaces)" || 
command -v exim &> /dev/null && l_interfaces="$(exim -bP local_interfaces)" || 
command -v sendmail &> /dev/null && l_interfaces="$(grep -i "0 DaemonPortOptions=" /etc/mail/sendmail.cf | grep -oP '(?<=Addr=)[^,+]+')"

[ -n "$l_interfaces" ] && {
    grep -Pqi '\ball\b' <<< "$l_interfaces" && 
    a_output2+=(" - MTA is bound to all network interfaces") || 
    ! grep -Pqi '(inet_interfaces\h*=\h*)?(0\.0\.0\.0|::1|loopback-only)' <<< "$l_interfaces" && 
    a_output2+=(" - MTA is bound to a network interface \"$l_interfaces\"") || 
    a_output+=(" - MTA is not bound to a non-loopback network interface \"$l_interfaces\"")
} || a_output+=(" - MTA not detected or in use")

[ "${#a_output2[@]}" -le 0 ] && printf '%s\n' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" || {
    printf '%s\n' "" "- Audit Result:" " ** FAIL **" " * Reasons for audit failure *" "${a_output2[@]}" ""
    [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "- Correctly set:" "${a_output[@]}"
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f='
Edit /etc/postfix/main.cf and add the following line to the RECEIVING MAIL
section. If the line already exists, change it to look like the line below:

inet_interfaces = loopback-only

Run the following command to restart postfix:
# systemctl restart postfix'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="2.2.1 Ensure NIS Client is not installed"

#no output 

b='The Network Information Service (NIS),is a client-server directory service protocol 
used to distribute system configuration files. The NIS client was used to bind a machine
to an NIS server and receive the distributed configuration files.

Rationale:

The NIS service is inherently an insecure system that has been vulnerable to DOS
attacks, buffer overflows and has poor authentication for querying NIS maps. NIS
generally has been replaced by such protocols as Lightweight Directory Access
Protocol (LDAP). It is recommended that the service be removed'

c='NIS is not installed'

d=$( dpkg-query -s nis &>/dev/null && echo "NIS is installed" || echo "NIS is not installed" )

[ "$d" == "NIS is not installed" ] && e="PASS" || e="FAIL"

f='
Many insecure service clients are used as troubleshooting tools and in testing
environments. Uninstalling them can inhibit capability to test and troubleshoot.
If they are required it is advisable to remove the clients after use to prevent
accidental or intentional misuse.

Uninstall nis using:
# apt purge nis'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.2.2 Ensure rsh client is not installed "

#no output 

b='
The rsh-client package contains the client commands for the rsh services.

Rationale:

These legacy clients contain numerous security exposures and have been replaced with
the more secure SSH package. Even if the server is removed, it is best to ensure the
clients are also removed to prevent users from inadvertently attempting to use these
commands and therefore exposing their credentials.
Note that removing the rsh-client package removes the clients for rsh , rcp and rlogin'

c='rsh-client is not installed'

d=$( dpkg-query -s rsh-client &>/dev/null && echo "rsh-client is installed" || echo "rsh-client is not installed" )

[ "$d" == "rsh-client is not installed" ] && e="PASS" || e="FAIL"

f='
Uninstall rsh using :
# apt purge rsh-client'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.2.3 Ensure talk client is not installed "

#no output 

b='
The talk software makes it possible for users to send and receive messages across
systems through a terminal session. The talk client, which allows initialization of talk
sessions, is installed by default.

Rationale:

The software presents a security risk as it uses unencrypted protocols for
communication.'

c='talk is not installed'

d=$( dpkg-query -s talk &>/dev/null && echo "talk is installed" || echo "talk is not installed" )

[ "$d" == "talk is not installed" ] && e="PASS" || e="FAIL"

f='
Uninstall talk using :
# apt purge talk'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.2.4 Ensure telnet client is not installed  "

#no output 

b='The inetutils-telnet package contains the telnet client, which allows users to start
connections to other systems via the telnet protocol.

Rationale:

The telnet protocol is insecure and unencrypted. The use of an unencrypted
transmission medium could allow an unauthorized user to steal credentials. The ssh
package provides an encrypted session and stronger security and is included in most
Linux distributions.'

c='telnet is not installed'

d=$( dpkg-query -l | grep -E 'telnet|inetutils-telnet' &>/dev/null && echo "telnet is installed" || echo "telnet is not installed" )

[ "$d" == "telnet is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to uninstall telnet & inetutils-telnet:
# apt purge telnet
# apt purge inetutils-telnet'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.2.5 Ensure ldap client is not installed  "

#no output 

b='
The Lightweight Directory Access Protocol (LDAP)  is a service that provides
a method for looking up data from a central database.

Rationale:

If the system will not need to act as an LDAP client,
it is recommended that the software be removed to reduce the potential attack surface'

c='ldap-utils is not installed'

d=$( dpkg-query -s ldap-utils &>/dev/null && echo "ldap-utils is installed" || echo "ldap-utils is not installed" )

[ "$d" == "ldap-utils is not installed" ] && e="PASS" || e="FAIL"

f='
Uninstall ldap-utils:
# apt purge ldap-utils

Note: Removing the LDAP client will prevent or inhibit using LDAP for 
authentication in your environment'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.2.6 Ensure ftp client is not installed "

#no output 

b='
tnftp an enhanced FTP client, is the user interface to the Internet standard File
Transfer Protocol. The program allows a user to transfer files to and from a remote
network site.

Rationale:

Unless there is a need to run the system using Internet standard File Transfer Protocol,
it is recommended that the package be removed to reduce the potential attack surface'

c='ftp is not installed'

d=$(dpkg-query -l | grep -E 'ftp|tnftp' &>/dev/null && echo "ftp is installed" || echo "ftp is not installed" )

[ "$d" == "ftp is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to uninstall tnftp & ftp:
# apt purge ftp
# apt purge tnftp'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.3.1.1 Ensure a single time synchronization daemon is in use "

b='
System time should be synchronized between all systems in an environment. This is
typically done by establishing an authoritative time server or set of servers and having
all systems synchronize their clocks to them.

Rationale:

Time synchronization is important to support time sensitive security mechanisms and
ensures log files have consistent time records across the enterprise, which aids in
forensic investigations.'

c='Only one time sync daemon is in use on the system'

d1=$(
    
l_output="" 
l_output2=""

service_not_enabled_chk() {
    l_out2=""
    systemctl is-enabled "$l_service_name" 2>/dev/null | grep -q 'enabled' && 
    l_out2="$l_out2\n - Daemon: \"$l_service_name\" is enabled on the system"
    
    systemctl is-active "$l_service_name" 2>/dev/null | grep -q '^active' && 
    l_out2="$l_out2\n - Daemon: \"$l_service_name\" is active on the system"
}

l_service_name="systemd-timesyncd.service" # Check systemd-timesyncd daemon
service_not_enabled_chk
[ -n "$l_out2" ] && l_timesyncd="y" && l_out_tsd="$l_out2" || 
l_timesyncd="n" && l_out_tsd="\n - Daemon: \"$l_service_name\" is not enabled and not active on the system"

l_service_name="chrony.service" # Check chrony
service_not_enabled_chk
[ -n "$l_out2" ] && l_chrony="y" && l_out_chrony="$l_out2" || 
l_chrony="n" && l_out_chrony="\n - Daemon: \"$l_service_name\" is not enabled and not active on the system"

l_status="$l_timesyncd$l_chrony"

case "$l_status" in
    yy)
        l_output2=" - More than one time sync daemon is in use on the system$l_out_tsd$l_out_chrony"
        ;;
    nn)
        l_output2=" - No time sync daemon is in use on the system$l_out_tsd$l_out_chrony"
        ;;
    yn|ny)
        l_output=" - Only one time sync daemon is in use on the system$l_out_tsd$l_out_chrony"
        ;;
    *)
        l_output2=" - Unable to determine time sync daemon(s) status"
        ;;
esac

[ -z "$l_output2" ] && echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n" || 
echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure *:\n$l_output2\n"

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f='
On physical systems, and virtual systems where host based time synchronization is not
available.
Select one of the two time synchronization daemons; chrony (1) or systemd-
timesyncd (2) and following the remediation procedure for the selected daemon.
Note: enabling more than one synchronization daemon could lead to unexpected or
unreliable results:

1. chrony
Run the following command to install chrony:
# apt install chrony
Run the following commands to stop and mask the systemd-timesyncd daemon:
# systemctl stop systemd-timesyncd.service
# systemctl mask systemd-timesyncd.service

Note:
• Subsection: Configure chrony should be followed
• Subsection: Configure systemd-timesyncd should be skipped

2. systemd-timesyncd
Run the following command to remove the chrony package:
# apt purge chrony
# apt autoremove chrony

Note:
• Subsection: Configure systemd-timesyncd should be followed
• Subsection: Configure chrony should be skipped'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="2.3.2.1 Ensure systemd-timesyncd configured with authorized timeserver"

b='
NTP=
• A space-separated list of NTP server host names or IP addresses. During
runtime this list is combined with any per-interface NTP servers acquired from
systemd-networkd.service(8). systemd-timesyncd will contact all configured
system or per-interface servers in turn, until one responds. When the empty
string is assigned, the list of NTP servers is reset, and all prior assignments will
have no effect. This setting defaults to an empty list.

FallbackNTP=
• A space-separated list of NTP server host names or IP addresses to be used as
the fallback NTP servers. Any per-interface NTP servers obtained from systemd-
networkd.service(8) take precedence over this setting, as do any servers set via
NTP= above. This setting is hence only relevant if no other NTP server
information is known. When the empty string is assigned, the list of NTP servers
is reset, and all prior assignments will have no effect. If this option is not given, a
compiled-in list of NTP servers is used.

Rationale:

Time synchronization is important to support time sensitive security mechanisms and to
ensure log files have consistent time records across the enterprise to aid in forensic
investigations'

c='Time synchronization is correctly set'

d1=$(
a_output=(); a_output2=(); a_parlist=("NTP=[^#\n\r]+" "FallbackNTP=[^#\n\r]+")
l_systemd_config_file="/etc/systemd/timesyncd.conf" # Main systemd configuration file

f_config_file_parameter_chk() {
    unset A_out; declare -A A_out # Check config file(s) setting
    while read -r l_out; do
        [ -n "$l_out" ] && {
            [[ $l_out =~ ^\s*# ]] && l_file="${l_out//# /}" || {
                l_systemd_parameter="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<< "$l_systemd_parameter" &&
                A_out+=(["$l_systemd_parameter"]="$l_file")
            }
        }
    done < <("$l_systemdanalyze" cat-config "$l_systemd_config_file" | grep -Pio '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')

    (( ${#A_out[@]} > 0 )) && {
        while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
            l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}"
            l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}"
            grep -Piq "\b$l_systemd_parameter_value\b" <<< "$l_systemd_file_parameter_value" &&
            a_output+=(" - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\"") || 
            a_output2+=(" - \"$l_systemd_parameter_name\" is incorrectly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value matching: \"$l_value_out\"")
        done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}")
    } || {
        a_output2+=(" - \"$l_systemd_parameter_name\" is not set in an included file *** Note: \"$l_systemd_parameter_name\" May be set in a file that's ignored by load procedure ***")
    }
}

l_systemdanalyze="$(readlink -f /bin/systemd-analyze)"
while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters
    l_systemd_parameter_name="${l_systemd_parameter_name// /}";
    l_systemd_parameter_value="${l_systemd_parameter_value// /}"
    l_value_out="${l_systemd_parameter_value//-/ through }"; 
    l_value_out="${l_value_out//|/ or }"
    l_value_out="$(tr -d '(){}' <<< "$l_value_out")"
    f_config_file_parameter_chk
done < <(printf '%s\n' "${a_parlist[@]}")

[ "${#a_output2[@]}" -le 0 ] && printf '%s\n' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" || {
    printf '%s\n' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
    [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f="Set NTP and/or FallbackNPT parameters to local site approved authoritative time
server(s) in /etc/systemd/timesyncd.conf or a file in
/etc/systemd/timesyncd.conf.d/ ending in .conf in the [Time] section:

Example file:
[Time]
NTP=time.nist.gov # Uses the generic name for NIST's time servers
FallbackNTP=time-a-g.nist.gov time-b-g.nist.gov time-c-g.nist.gov
# Space separated list of NIST time servers"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="2.3.2.2 Ensure systemd-timesyncd is enabled and running"

b='
systemd-timesyncd is a daemon that has been added for synchronizing the system
clock across the network

Rationale:

systemd-timesyncd needs to be active in order to synchronize the system to a timeserver.
Time synchronization is important to support time sensitive security mechanisms and to
ensure log files have time records across the enterprise to aid in forensic investigations'

c='enabled,active'

d1=$(systemctl is-enabled systemd-timesyncd.service)

d2=$(systemctl is-active systemd-timesyncd.service)

d="$d1,$d2"

[ "$d1" == "enabled" ] && [ "$d2" == "active" ] && e="PASS" || e="FAIL"

f='
If systemd-timesyncd is in use on the system, run the following commands:
Run the following command to unmask systemd-timesyncd.service:
# systemctl unmask systemd-timesyncd.service

Run the following command to enable and start systemd-timesyncd.service:
# systemctl --now enable systemd-timesyncd.service

(or)

If another time synchronization service is in use on the system, run the
following command to stop and mask systemd-timesyncd:
# systemctl --now mask systemd-timesyncd.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.3.3.1 Ensure chrony is configured with authorized timeserver"

b='
• server
o The server directive specifies an NTP server which can be used as a time
source. The client-server relationship is strictly hierarchical: a client might
synchronize its system time to that of the server, but the server’s system
time will never be influenced by that of a client.
o This directive can be used multiple times to specify multiple servers.
o The directive is immediately followed by either the name of the server, or
its IP address.

• pool
o The syntax of this directive is similar to that for the server directive, except
that it is used to specify a pool of NTP servers rather than a single NTP
server. The pool name is expected to resolve to multiple addresses which
might change over time.
o This directive can be used multiple times to specify multiple pools.
o All options valid in the server directive can be used in this directive too.'

c='chrony exists in the file(name)'

d1=$(
a_output=()
a_output2=()
a_config_files=("/etc/chrony/chrony.conf")

l_include='(confdir|sourcedir)'
l_parameter_name='(server|pool)'
l_parameter_value='.+'

# Read configuration locations
while IFS= read -r l_conf_loc; do
    l_dir=""
    l_ext=""

    # Determine if l_conf_loc is a directory or a file
    [ -d "$l_conf_loc" ] && l_dir="$l_conf_loc" && l_ext="*" ||
    (grep -Psq '\/\*\.([^#/\n\r]+)?\h*$' <<< "$l_conf_loc" && l_dir="$(dirname "$l_conf_loc")" && l_ext="$(basename "$l_conf_loc")") ||
    [ -f "$(readlink -f "$l_conf_loc")" ] && l_dir="$(dirname "$l_conf_loc")" && l_ext="$(basename "$l_conf_loc")"

    # Find files based on the directory and extension
    [[ -n "$l_dir" && -n "$l_ext" ]] && {
        while IFS= read -r -d $'\0' l_file_name; do
            [ -f "$(readlink -f "$l_file_name")" ] && a_config_files+=("$(readlink -f "$l_file_name")")
        done < <(find -L "$l_dir" -type f -name "$l_ext" -print0 2>/dev/null)
    }
done < <(awk '$1 ~ /^\s*'"$l_include"'$/{print $2}' "${a_config_files[@]}" 2>/dev/null)

# Audit the configuration files for the specified parameters
for l_file in "${a_config_files[@]}"; do
    l_parameter_line="$(grep -Psi '^\h*'"$l_parameter_name"'(\h+|\h*:\h*)'"$l_parameter_value"'\b' "$l_file")"
    
    [ -n "$l_parameter_line" ] && a_output+=(" - Parameter: \"$(tr -d '()' <<< ${l_parameter_name//|/ or })\" Exists in the file: \"$l_file\" as: $l_parameter_line")
done

# Check if any parameters were found
[ "${#a_output[@]}" -le 0 ] && a_output2+=(" - Parameter: \"$(tr -d '()' <<< ${l_parameter_name//|/ or })\" Does not exist in the chrony configuration")

# Output the results
[ "${#a_output2[@]}" -le 0 ] && {
    printf '%s\n' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" ""
} || {
    printf '%s\n' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g')  

[ "$d" == *PASS* ] && e="PASS" || e="FAIL"

f="
Edit /etc/chrony/chrony.conf or a file ending in .sources in
/etc/chrony/sources.d/ and add or edit server or pool lines as appropriate
according to local site policy:

Edit the Chrony configuration and add or edit the server and/or pool lines returned by
the Audit Procedure as appropriate according to local site policy
<[server|pool]> <[remote-server|remote-pool]>"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.3.3.2 Ensure chrony is running as user _chrony "

#no output 

b='
The chrony package is installed with a dedicated user account _chrony. This account
is granted the access required by the chronyd service

Rationale:

The chronyd service should run with only the required privlidges'

c='chrony is running as user _chrony'

check=$( ps -ef | awk '(/[c]hronyd/ && $1!="_chrony") { print $1 }' )

[ -z "$check" ] && { d="chrony is running as user _chrony"; e="PASS"; } || { d="chrony is running as another user"; e="FAIL"; }

f="
Add or edit the user line to /etc/chrony/chrony.conf or a file ending in .conf in
/etc/chrony/conf.d/:
user _chrony

(or)

If another time synchronization service is in use on the system, run the following
command to remove chrony from the system:
# apt purge chrony
# apt autoremove chrony"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.3.3.3 Ensure chrony is enabled and running "

b='
chrony is a daemon for synchronizing the system clock across the network

Rationale:

chrony needs to be enabled and running in order to synchronize the system to a
timeserver.'

c='enabled,
active'

d1=$(systemctl is-enabled chrony.service 2>&1)

d2=$(systemctl is-active chrony.service 2>&1)

d="$d1,
$d2"

[ "$d1" == "enabled" ] && [ "$d2" == "active" ] && e="PASS" || e="FAIL"

f='
Ifchrony is in use on the system, run the following commands:
Run the following command to unmask chrony.service:
# systemctl unmask chrony.service
Run the following command to enable and start chrony.service:
# systemctl --now enable chrony.service

(or)

If another time synchronization service is in use on the system, run the following
command to remove chrony:
# apt purge chrony
# apt autoremove chron'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.4.1.1 Ensure cron daemon is enabled and active"

b='
The cron daemon is used to execute batch jobs on the system.

Rationale:

While there may not be user jobs that need to be run on the system, the system does
have maintenance jobs that may include security monitoring that have to run, and cron
is used to execute them'

c='enabled,
active'

d1=$(systemctl list-unit-files | awk '$1~/^crond?\.service/{print $2}' 2>&1)

d2=$(systemctl list-units | awk '$1~/^crond?\.service/{print $3}' 2>&1)

d="$d1,
$d2"

[ "$d1" == "enabled" ] && [ "$d2" == "active" ] && e="PASS" || e="FAIL"

f='
If cron is installed on the system:
Run the following commands to unmask, enable, and start cron:

#systemctl unmask cron.service crond.service
#systemctl start cron.service crond.service
#systemctl enable cron.service crond.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.4.1.2 Ensure permissions on /etc/crontab are configured"

b='
The /etc/crontab file is used by cron to control its own jobs. The commands in this
item make sure that root is the user and group owner of the file and that only the owner
can access the file.

Rationale:

This file contains information on what system jobs are run by cron. Write access to
these files could provide unprivileged users with the ability to elevate their privileges.
Read access to these files could provide users with the ability to gain insight on system
jobs that run on the system and could provide unauthorized privileged access'

c='Access: ('≤600'/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)'

d=$(stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/crontab 2>&1)

access=$(echo "$d" | grep -oP 'Access: \(\K[0-9]+')
uid=$(echo "$d" | grep -oP 'Uid: \( \K[0-9]+')
gid=$(echo "$d" | grep -oP 'Gid: { \K[0-9]+')

[ "$access" -le 600 ] && [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ] && e="PASS" || e="FAIL"

f='
If cron is installed on the system:
Run the following commands to set ownership and permissions on /etc/crontab:
# chown root:root /etc/crontab
# chmod og-rwx /etc/crontab'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.4.1.3 Ensure permissions on /etc/cron.hourly are configured"

b='
This directory contains system cron jobs that need to run on an hourly basis. The files
in this directory cannot be manipulated by the crontab command, but are instead
edited by system administrators using a text editor. The commands below restrict
read/write and search access to user and group root, preventing regular users from
accessing this directory.

Rationale:

Granting write access to this directory for non-privileged users could provide them the
means for gaining unauthorized elevated privileges. Granting read access to this
directory could give an unprivileged user insight in how to gain elevated privileges or
circumvent auditing controls.'

c='Access: ( ≤700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)'

d=$( stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.hourly/ 2>&1)

access=$(echo "$d" | grep -oP 'Access: \(\K[0-9]+')
uid=$(echo "$d" | grep -oP 'Uid: \( \K[0-9]+')
gid=$(echo "$d" | grep -oP 'Gid: { \K[0-9]+')

[ "$access" -le 700 ] && [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ] && e="PASS" || e="FAIL"

f='
If cron is installed on the system:
Run the following commands to set ownership and permissions on the /etc/cron.hourly directory:

# chown root:root /etc/cron.hourly/
# chmod og-rwx /etc/cron.hourly/'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.4.1.4 Ensure permissions on /etc/cron.daily are configured"

b='
The /etc/cron.daily directory contains system cron jobs that need to run on a daily
basis. The files in this directory cannot be manipulated by the crontab command, but
are instead edited by system administrators using a text editor. The commands below
restrict read/write and search access to user and group root, preventing regular users
from accessing this directory.

Rationale:

Granting write access to this directory for non-privileged users could provide them the
means for gaining unauthorized elevated privileges. Granting read access to this
directory could give an unprivileged user insight in how to gain elevated privileges or
circumvent auditing controls.'

c='Access: ( ≤700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)'

d=$( stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.daily/ 2>&1)

access=$(echo "$d" | grep -oP 'Access: \(\K[0-9]+')
uid=$(echo "$d" | grep -oP 'Uid: \( \K[0-9]+')
gid=$(echo "$d" | grep -oP 'Gid: { \K[0-9]+')

[ "$access" -le 700 ] && [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ] && e="PASS" || e="FAIL"

f='
- IF - cron is installed on the system:
Run the following commands to set ownership and permissions on the /etc/cron.daily directory:

# chown root:root /etc/cron.daily/
# chmod og-rwx /etc/cron.daily/'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.4.1.5 Ensure permissions on /etc/cron.weekly are configured"

b='
The /etc/cron.weekly directory contains system cron jobs that need to run on a
weekly basis. The files in this directory cannot be manipulated by the crontab
command but are instead edited by system administrators using a text editor. The
commands below restrict read/write and search access to user and group root,
preventing regular users from accessing this directory.

Rationale:

Granting write access to this directory for non-privileged users could provide them the
means for gaining unauthorized elevated privileges. Granting read access to this
directory could give an unprivileged user insight in how to gain elevated privileges or
circumvent auditing controls'

c='Access: ( ≤700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)'

d=$( stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.weekly/ 2>&1)

access=$(echo "$d" | grep -oP 'Access: \(\K[0-9]+')
uid=$(echo "$d" | grep -oP 'Uid: \( \K[0-9]+')
gid=$(echo "$d" | grep -oP 'Gid: { \K[0-9]+')

[ "$access" -le 700 ] && [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ] && e="PASS" || e="FAIL"

f='
If cron is installed on the system:
Run the following commands to set ownership and permissions on /etc/cron.weekly directory:

# chown root:root /etc/cron.weekly/
# chmod og-rwx /etc/cron.weekly/'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.4.1.6 Ensure permissions on /etc/cron.monthly are configured"

b='
The /etc/cron.monthly directory contains system cron jobs that need to run on a
monthly basis. The files in this directory cannot be manipulated by the crontab
command but are instead edited by system administrators using a text editor. The
commands below restrict read/write and search access to user and group root,
preventing regular users from accessing this directory.

Rationale:

Granting write access to this directory for non-privileged users could provide them the
means for gaining unauthorized elevated privileges. Granting read access to this
directory could give an unprivileged user insight in how to gain elevated privileges or
circumvent auditing controls.'

c='Access: ( ≤700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)'

d=$( stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.monthly/ 2>&1)

access=$(echo "$d" | grep -oP 'Access: \(\K[0-9]+')
uid=$(echo "$d" | grep -oP 'Uid: \( \K[0-9]+')
gid=$(echo "$d" | grep -oP 'Gid: { \K[0-9]+')

[ "$access" -le 700 ] && [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ] && e="PASS" || e="FAIL"

f='
- IF - cron is installed on the system:
Run the following commands to set ownership and permissions on /etc/cron.monthly directory:

# chown root:root /etc/cron.monthly/
# chmod og-rwx /etc/cron.monthly/'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.4.1.7 Ensure permissions on /etc/cron.d are configured"

b='
The /etc/cron.d directory contains system cron jobs that need to run in a similar
manner to the hourly, daily weekly and monthly jobs from /etc/crontab, but require
more granular control as to when they run. The files in this directory cannot be
manipulated by the crontab command but are instead edited by system administrators
using a text editor. The commands below restrict read/write and search access to user
and group root, preventing regular users from accessing this directory.

Rationale:

Granting write access to this directory for non-privileged users could provide them the
means for gaining unauthorized elevated privileges. Granting read access to this
directory could give an unprivileged user insight in how to gain elevated privileges or
circumvent auditing controls.'

c='Access: ( ≤700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)'

d=$(stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.d/ )

access=$(echo "$d" | grep -oP 'Access: \(\K[0-9]+')
uid=$(echo "$d" | grep -oP 'Uid: \( \K[0-9]+')
gid=$(echo "$d" | grep -oP 'Gid: { \K[0-9]+')

[ "$access" -le 700 ] && [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ] && e="PASS" || e="FAIL"

f='
If cron is installed on the system:
Run the following commands to set ownership and permissions on /etc/cron.d directory:

# chown root:root /etc/cron.d/
# chmod og-rwx /etc/cron.d/'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="2.4.1.8 Ensure crontab is restricted to authorized users"

b="
The files /etc/cron.allow and /etc/cron.deny, if they exist, must be either world-
readable, or readable by group crontab. If they are not, then cron will deny access to
all users until the permissions are fixed.
There is one file for each user's crontab under the /var/spool/cron/crontabs
directory. Users are not allowed to edit the files under that directory directly to ensure
that only users allowed by the system to run periodic tasks can add them, and only
syntactically correct crontabs will be written there. This is enforced by having the
directory writable only by the crontab group and configuring crontab command with the
setgid bid set for that specific group.

Rationale:

On many systems, only the system administrator is authorized to schedule cron jobs.
Using the cron.allow file to control who can run cron jobs enforces this policy. It is
easier to manage an allow list than a deny list. In a deny list, you could potentially add a
user ID to the system and forget to add it to the deny files."

c='
Access: ( ≤640/-rw-r-----) Owner: (root) Group: (root) or (crontab)'

#allow
d1=$(stat -Lc 'Access: (%a/%A) Owner: (%U) Group: (%G)' /etc/cron.allow 2>&1)

access_mode1=$(echo "$d1" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid1=$(echo "$d1" | awk '{print $4}')
gid1=$(echo "$d1" | awk '{print $6}')

#deny
d2=$(stat -Lc 'Access: (%a/%A) Owner: (%U) Group:(%G)' /etc/cron.deny 2>&1)

access_mode2=$(echo "$d2" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid2=$(echo "$d2" | awk '{print $4}')
gid2=$(echo "$d2" | awk '{print $6}')


[[ "$access_mode1" -le 640 && "$uid1" == "root" && ("$gid1" == "(root)" || "$gid1" == "(crontab)") ]] &&
[[ "$access_mode2" -le 640 && "$uid2" == "root" && ("$gid2" == "(root)" || "$gid2" == "(crontab)") ]]  && e="PASS" || e="FAIL"

d="$d1
$d2"

f1='
# IF - cron is installed on the system:
# Run the following script to:

# • Create /etc/cron.allow if it doesn'\''t exist
# • Change owner to user root
# • Change group owner to group root - OR - group crontab if it exists
# • Change mode to 640 or more restrictive

#!/usr/bin/env bash
{
[ ! -e "/etc/cron.deny" ] && touch /etc/cron.allow
chmod u-x,g-wx,o-rwx /etc/cron.allow
if grep -Pq -- "^\h*crontab\:" /etc/group; then
     chown root:crontab /etc/cron.allow
else
     chown root:root /etc/cron.allow
fi
}

# IF - /etc/cron.deny exists, run the following script to:
# • Change owner to user root
# • Change group owner to group root - OR - group crontab if it exists
# • Change mode to 640 or more restrictive

#!/usr/bin/env bash
{
if [ -e "/etc/cron.deny" ]; then
chmod u-x,g-wx,o-rwx /etc/cron.deny
if grep -Pq -- "^\h*crontab\:" /etc/group; then
  chown root:crontab /etc/cron.deny
else
  chown root:root /etc/cron.deny
 fi
fi
}
'
f=$(printf "%s\n" "$f1" | sed 's/"/""/g')  

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="2.4.2.1 Ensure at is restricted to authorized users"

b='
The at command allows users to schedule one-time tasks to run at a specific time,
which can be useful for automating tasks.

The /etc/at.allow and /etc/at.deny file directory is used to store configuration files 
for the at command,which is a Unix utility that schedules commands to be run at a specified time

Rationale:

On many systems, only the system administrator is authorized to schedule at jobs.
Using the at.allow file to control who can run at jobs enforces this policy. It is easier
to manage an allow list than a deny list. In a deny list, you could potentially add a user
ID to the system and forget to add it to the deny files.'

c='Access: ( ≤640/-rw-r-----) Owner: (root) Group: (daemon) or (root)'

#allow
d1=$(stat -Lc 'Access: (%a/%A) Owner: (%U) Group: (%G)' /etc/at.allow 2>&1) 

access_mode1=$(echo "$d1" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid1=$(echo "$d1" | awk '{print $4}')
gid1=$(echo "$d1" | awk '{print $6}')

#deny
d2=$(stat -Lc 'Access: (%a/%A) Owner: (%U) Group: (%G)' /etc/at.deny 2>&1)

access_mode2=$(echo "$d2" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid2=$(echo "$d2" | awk '{print $4}')
gid2=$(echo "$d2" | awk '{print $6}')


[[ "$access_mode1" -le 640 && "$uid1" == "root" && ("$gid1" == "(root)" || "$gid1" == "(daemon)") ]] &&
[[ "$access_mode2" -le 640 && "$uid2" == "root" && ("$gid2" == "(root)" || "$gid2" == "(daemon)") ]]  && e="PASS" || e="FAIL"

d="$d1
$d2"

f1='
# IF - at is installed on the system:

# Run the following script to:

# • /etc/at.allow:
#   o Create the file if it doesn'\''t exist
#   o Change owner or user root
#   o If group daemon exists, change to group daemon, else change group to root
#   o Change mode to 640 or more restrictive
# • IF - /etc/at.deny exists:
#   o Change owner or user root
#   o If group daemon exists, change to group daemon, else change group to root
#   o Change mode to 640 or more restrictive

#!/usr/bin/env bash
{
grep -Pq -- '^daemon\b' /etc/group && l_group="daemon" || l_group="root"
[ ! -e "/etc/at.allow" ] && touch /etc/at.allow
chown root:"$l_group" /etc/at.allow
chmod u-x,g-wx,o-rwx /etc/at.allow
[ -e "/etc/at.deny" ] && chown root:"$l_group" /etc/at.deny
[ -e "/etc/at.deny" ] && chmod u-x,g-wx,o-rwx /etc/at.deny
}
'
f=$(printf "%s\n" "$f1" | sed 's/"/""/g')  

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="3.1.2 Ensure wireless interfaces are disabled "

b="
If wireless is not to be used, wireless devices can be disabled to reduce the potential
attack surface.
Note: Many if not all laptop workstations and some desktop workstations will connect via
wireless requiring these interfaces be enabled."

c="
Review the device types with wireless connection 
and disconnect them"

d=$(nmcli device status)

echo "$d" | grep -q "wireless" && e="FAIL" || e="PASS"

f='
The wireless interfaces can be disabled using the nmcli command:

#nmcli device disconnect <interface_name>'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.1.3 Ensure bluetooth services are not in use "

#no output 

b='
An attacker may be able to find a way to access or corrupt your data. One example of
this type of activity is bluesnarfing, which refers to attackers using a Bluetooth
connection to steal information off of your Bluetooth device. Also, viruses or other
malicious code can take advantage of Bluetooth technology to infect other devices. If
you are infected, your data may be corrupted, compromised, stolen, or lost.

Note:
There may be packages that are dependent on the bluez package. If the bluez
package is removed, these dependent packages will be removed as well. Before
removing the bluez package, review any dependent packages to determine if they are
required on the system.
If a dependent package is required: stop and mask bluetooth.service leaving the
bluez package installed.'

c='bluez is not installed'

d=$( dpkg-query -s bluez &>/dev/null && echo "bluez is installed" || echo "bluez is not installed")

[ "$d" == "bluez is not installed" ] && e="PASS" || e="FAIL"

f='
Run the following commands to stop bluetooth.service, 
and remove the bluez package:
# systemctl stop bluetooth.service
# apt purge bluez

(or)

If the bluez package is required as a dependency:
Run the following commands to stop and mask bluetooth.service:
# systemctl stop bluetooth.service
# systemctl mask bluetooth.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.2.1 Ensure dccp kernel module is not available"

#no output

b='
The Datagram Congestion Control Protocol (DCCP) is a transport layer protocol that
supports streaming media and telephony. DCCP provides a way to gain access to
congestion control, without having to do it at the application layer, but does not provide
in-sequence delivery.

Rationale:

If the protocol is not required, it is recommended that the drivers not be installed to
reduce the potential attack surface.'

c='dccp kernel module is not installed'

check=$( lsmod | grep dccp )

[ -z "$check" ] && { d="dccp kernel module is not installed"; e="PASS"; } || { d="dccp kernel module is installed"; e="FAIL"; }

f='
To remove the DCCP kernel module, execute the modprobe command :

#modprobe -r dccp'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.2.2 Ensure tipc kernel module is not available "

#no output

b='
The Transparent Inter-Process Communication (TIPC) protocol is designed to provide
communication between cluster nodes.

Rationale:

If the protocol is not being used, it is recommended that kernel module not be
loaded, disabling the service to reduce the potential attack surface.'

c='tipc kernel module is not installed'

check=$( lsmod | grep tipc )

[ -z "$check" ] && { d="tipc kernel module is not installed"; e="PASS"; } || { d="tipc kernel module is installed"; e="FAIL"; }

f='
To remove the tipc kernel module, execute the modprobe command :

#modprobe -r tipc'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.2.3 Ensure rds kernel module is not available"

#no output

b='
The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to
provide low-latency, high-bandwidth communications between cluster nodes. It was
developed by the Oracle Corporation.

Rationale:

If the protocol is not being used, it is recommended that kernel module not be
loaded, disabling the service to reduce the potential attack surface.'

c='rds kernel module is not installed'

check=$( lsmod | grep rds )

[ -z "$check" ] && { d="rds kernel module is not installed"; e="PASS"; } || { d="rds kernel module is installed"; e="FAIL"; }

f='
To remove the rds kernel module, execute the modprobe command :

#modprobe -r rds'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.2.4 Ensure sctp kernel module is not available"

#no output

b='
The Stream Control Transmission Protocol (SCTP) is a transport layer protocol used to
support message oriented communication, with several streams of messages in one
connection. It serves a similar function as TCP and UDP, incorporating features of both.
It is message-oriented like UDP, and ensures reliable in-sequence transport of
messages with congestion control like TCP.

Rationale:

If the protocol is not being used, it is recommended that kernel module not be
loaded, disabling the service to reduce the potential attack surface.'

c='sctp kernel module is not installed'

check=$( lsmod | grep sctp )

[ -z "$check" ] && { d="sctp kernel module is not installed"; e="PASS"; } || { d="sctp kernel module is installed"; e="FAIL"; }

f='
To remove the sctp kernel module, execute the modprobe command :

#modprobe -r sctp'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.3.1 Ensure ip forwarding is disabled"

b='
The net.ipv4.ip_forward and net.ipv6.conf.all.forwarding flags are used to
tell the system whether it can forward packets or not.

Rationale:

Setting net.ipv4.ip_forward and net.ipv6.conf.all.forwarding to 0 ensures
that a system with multiple interfaces (for example, a hard proxy), will never be able to
forward packets, and therefore, never serve as a router.

Impact:

IP forwarding is required on systems configured to act as a router. If these parameters
are disabled, the system will not be able to perform as a router.'

c='net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0'

d1=$(sysctl net.ipv4.ip_forward)
d2=$(sysctl net.ipv6.conf.all.forwarding)

e="FAIL"
[[ "$d1" == "net.ipv4.ip_forward = 0" ]] && [[ "$d2" == "net.ipv6.conf.all.forwarding = 0" ]] && e="PASS"

d="$d1
$d2"

f='
To set the net.ipv4.ip_forward parameter to 0 
ot if IPv6 is configured set net.ipv6.conf.all.forwarding = 0,

Open the sysctl.conf file in a text editor:
#nano /etc/sysctl.conf

Add or modify the following line:
#net.ipv4.ip_forward = 0
or
#net.ipv6.conf.all.forwarding = 0

Save the file and exit the editor
(in Nano, press CTRL + O to save and CTRL + X to exit).

Apply the changes by running:
#sysctl -p

To verify that the setting has been applied, execute:
#sysctl net.ipv4.ip_forward
or
#sysctl net.ipv6.conf.all.forwarding = 0

If it returns net.ipv4.ip_forward = 0 or net.ipv6.conf.all.forwarding = 0
then the parameter have successfully set it to 0.
'
echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.3.2 Ensure packet redirect sending is disabled "

b='
ICMP Redirects are used to send routing information to other hosts. As a host does
not act as a router (in host only configuration), there is no need to send redirects.

Rationale:

An attacker could use a compromised host to send invalid ICMP redirects to other
router devices in an attempt to corrupt routing and have users access a system set up
by the attacker as opposed to a valid system.

Impact:

IP forwarding is required on systems configured to act as a router.
If these parameters are disabled, the system will not be able to perform as a router.'

c='net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0'

d1=$(sysctl net.ipv4.conf.all.send_redirects )
d2=$(sysctl net.ipv4.conf.default.send_redirects)

e="FAIL"
[[ "$d1" == "net.ipv4.conf.all.send_redirects = 0" ]] && [[ "$d2" == "net.ipv4.conf.default.send_redirects = 0" ]] && e="PASS"

d="$d1
$d2"

f='
Open the sysctl.conf file in a text editor:
#nano /etc/sysctl.conf

Add or modify the following line:
#net.ipv4.conf.all.send_redirects = 0 
and 
#ipv4.conf.default.send_redirects = 0

Save the file and exit the editor
(in Nano, press CTRL + O to save and CTRL + X to exit).

Apply the changes by running:
#sysctl -p

To verify that the setting has been applied, execute:
#sysctl net.ipv4.conf.all.send_redirects = 0
and
#sysctl ipv4.conf.default.send_redirects = 0

If it returns net.ipv4.conf.all.send_redirects = 0
and
ipv4.conf.default.send_redirects = 0
then the parameter have successfully set it to 0.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.3.3 Ensure bogus icmp responses are ignored "

b='
Setting net.ipv4.icmp_ignore_bogus_error_responses to 1 prevents the kernel
from logging bogus responses (RFC-1122 non-compliant) from broadcast reframes,
keeping file systems from filling up with useless log messages.

Rationale:

Some routers (and some attackers) will send responses that violate RFC-1122 and
attempt to fill up a log file system with many useless error messages'

c='net.ipv4.icmp_ignore_bogus_error_responses = 1'

d=$(sysctl net.ipv4.icmp_ignore_bogus_error_responses 2>&1)

[[ "$d" == "net.ipv4.icmp_ignore_bogus_error_responses = 1" ]] && e="PASS" || e="FAIL"

f='
Open the sysctl.conf file in a text editor:
#nano /etc/sysctl.conf

Add or modify the following line:
#net.ipv4.icmp_ignore_bogus_error_responses = 1

Save the file and exit the editor
(in Nano, press CTRL + O to save and CTRL + X to exit).

Apply the changes by running:
#sysctl -p

To verify that the setting has been applied, execute:
#net.ipv4.icmp_ignore_bogus_error_responses

If it returns net.ipv4.icmp_ignore_bogus_error_responses = 1,
then the parameter have successfully set it to 1.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="3.3.4 Ensure broadcast icmp requests are ignored"

b='
Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to
ignore all ICMP echo and timestamp requests to broadcast and multicast addresses.

Rationale:

Accepting ICMP echo and timestamp requests with broadcast or multicast destinations
for your network could be used to trick your host into starting in a Smurf attack.
A Smurf attack relies on an attacker sending large amounts of ICMP
broadcast messages with a spoofed source address. All hosts receiving this message
and responding would send echo-reply messages back to the spoofed address, which is
probably not routable. If many hosts respond to the packets, the amount of traffic on the
network could be significantly multiplied.'

c='net.ipv4.icmp_echo_ignore_broadcasts = 1'

d=$(sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>&1)

[[ "$d" == "net.ipv4.icmp_echo_ignore_broadcasts = 1" ]] && e="PASS" || e="FAIL"

f='
Open the sysctl.conf file in a text editor:
#nano /etc/sysctl.conf

Add or modify the following line:
#net.ipv4.icmp_echo_ignore_broadcasts = 1

Save the file and exit the editor
(in Nano, press CTRL + O to save and CTRL + X to exit).

Apply the changes by running:
#sysctl -p

To verify that the setting has been applied, execute:
#net.ipv4.icmp_echo_ignore_broadcasts

If it returns net.ipv4.icmp_echo_ignore_broadcasts = 1,
then the parameter have successfully set it to 1.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="3.3.5 Ensure icmp redirects are not accepted "

b="
ICMP redirect messages are packets that convey routing information and tell your host
(acting as a router) to send packets via an alternate path. It is a way of allowing an
outside routing device to update your system routing tables.
By setting those parameter to 0, the system will not accept any ICMP redirect messages,
and therefore, won't allow outsiders to update the system's routing tables."

c='
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0'

d1=$(sysctl net.ipv4.conf.all.accept_redirects)
d2=$(sysctl net.ipv4.conf.default.accept_redirects)
d3=$(sysctl net.ipv6.conf.all.accept_redirects)
d4=$(sysctl net.ipv6.conf.default.accept_redirects)

[[ "$d1" == "net.ipv4.conf.all.accept_redirects = 0" ]] && \
[[ "$d2" == "net.ipv4.conf.default.accept_redirects = 0" ]] && \
[[ "$d3" == "net.ipv6.conf.all.accept_redirects = 0" ]] && \
[[ "$d4" == "net.ipv6.conf.default.accept_redirects = 0" ]]  && e="PASS" || e="FAIL"

d="$d1
$d2
$d3
$d4"

f='
Open the sysctl.conf file in a text editor:
#nano /etc/sysctl.conf

Add or modify the following line:
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv4.conf.default.accept_redirects = 0
#net.ipv6.conf.all.accept_redirects = 0
#net.ipv6.conf.default.accept_redirects = 0

Save the file and exit the editor.
(in Nano, press CTRL + O to save and CTRL + X to exit).

Apply the changes by running:
#sysctl -p'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="3.3.6 Ensure secure icmp redirects are not accepted"

b='
Secure ICMP redirects are the same as ICMP redirects, except they come from
gateways listed on the default gateway list. It is assumed that these gateways are
known to your system, and that they are likely to be secure.

Rationale:

It is still possible for even known gateways to be compromised. Setting
net.ipv4.conf.all.secure_redirects and
net.ipv4.conf.default.secure_redirects to 0 protects the system from routing
table updates by possibly compromised known gateways'

c='net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0'

d1=$(sysctl net.ipv4.conf.all.secure_redirects )
d2=$(sysctl net.ipv4.conf.default.secure_redirects )

e="FAIL"
[[ "$d1" == "net.ipv4.conf.all.secure_redirects = 0" ]] && [[ "$d2" == "net.ipv4.conf.default.secure_redirects = 0" ]] && e="PASS"

d="$d1
$d2"

f='
Open the sysctl.conf file in a text editor:
#nano /etc/sysctl.conf

Add or modify the following line:
#net.ipv4.conf.all.secure_redirects = 0
#net.ipv4.conf.default.secure_redirects = 0

Save the file and exit the editor.
(in Nano, press CTRL + O to save and CTRL + X to exit).

Apply the changes by running:
#sysctl -p'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.3.7 Ensure reverse path filtering is enabled"

b='
Setting net.ipv4.conf.all.rp_filter and net.ipv4.conf.default.rp_filter to
1 forces the Linux kernel to utilize reverse path filtering on a received packet to
determine if the packet was valid.

Setting those parameters to 1 is a good way to deter attackers from sending your system 
bogus packets that cannot be responded to.

Note; If you are using asymmetrical routing on your system,
you will not be able to enable this feature without breaking the routing.'

c='net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1'

d1=$(sysctl net.ipv4.conf.all.rp_filter )
d2=$(sysctl net.ipv4.conf.default.rp_filter )

e="FAIL"
[[ "$d1" == "net.ipv4.conf.all.rp_filter = 1" ]] && [[ "$d2" == "net.ipv4.conf.default.rp_filter = 1" ]] && e="PASS"

d="$d1
$d2"

f='
Open the sysctl.conf file in a text editor:
#nano /etc/sysctl.conf

Add or modify the following line:
#net.ipv4.conf.all.rp_filter = 1
#net.ipv4.conf.default.rp_filter = 1

Save the file and exit the editor.
(in Nano, press CTRL + O to save and CTRL + X to exit).

Apply the changes by running:
#sysctl -p'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.3.8 Ensure source routed packets are not accepted"

b='
In networking, source routing allows a sender to partially or fully specify the route
packets take through a network. In contrast, non-source routed packets travel a path
determined by routers in the network. In some cases, systems may not be routable or
reachable from some locations, and so source routed packets would need to be used.

Rationale:

Setting those parameters to 0 disables the system from accepting source routed packets.
Assume this system was capable of routing packets to Internet routable addresses on
one interface and private addresses on another interface.
Assume that the private addresses were not routable to the Internet routable
addresses and vice versa. Under normal routing circumstances, an attacker from the
Internet routable addresses could not use the system as a way to reach the private
address systems.'

c='
net.ipv4.conf.all.accept_source_route = 0,
net.ipv4.conf.default.accept_source_route = 0,
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route  = 0'

d1=$(sysctl net.ipv4.conf.all.accept_source_route)
d2=$(sysctl net.ipv4.conf.default.accept_source_route)
d3=$(sysctl net.ipv6.conf.all.accept_source_route)
d4=$(sysctl net.ipv6.conf.default.accept_source_route)

[[ "$d1" == "net.ipv4.conf.all.accept_source_route = 0" ]] && \
[[ "$d2" == "net.ipv4.conf.default.accept_source_route = 0" ]] && \
[[ "$d3" == "net.ipv6.conf.all.accept_source_route = 0" ]] && \
[[ "$d4" == "net.ipv6.conf.default.accept_source_route = 0" ]]  && e="PASS" || e="FAIL"

d="$d1
$d2
$d3
$d4"

f='
Open the sysctl.conf file in a text editor:
#nano /etc/sysctl.conf

Add or modify the following line:
net.ipv4.conf.all.accept_source_route = 0,
net.ipv4.conf.default.accept_source_route = 0,
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route  = 0

Save the file and exit the editor.
(in Nano, press CTRL + O to save and CTRL + X to exit).

Apply the changes by running:
#sysctl -p'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="3.3.9 Ensure suspicious packets are logged "

b='
When enabled, this feature logs packets with un-routable
source addresses to the kernel log.

Rationale:
Logging these packets allows an administrator to investigate the
possibility that an attacker is sending spoofed packets to the system.'

c='net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1'

d1=$(sysctl net.ipv4.conf.all.log_martians )
d2=$(sysctl net.ipv4.conf.default.log_martians )

e="FAIL"
[[ "$d1" == "net.ipv4.conf.all.log_martians = 1" ]] && [[ "$d2" == "net.ipv4.conf.default.log_martians = 1" ]] && e="PASS"

d="$d1
$d2"

f='
Open the sysctl.conf file in a text editor:
#nano /etc/sysctl.conf

Add or modify the following line:
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

Save the file and exit the editor.
(in Nano, press CTRL + O to save and CTRL + X to exit).

Apply the changes by running:
#sysctl -p'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="3.3.10 Ensure tcp syn cookies is enabled"

b="
When tcp_syncookies is set, the kernel will handle TCP SYN packets
normally until the half-open connection queue is full, at which time,
the SYN cookie functionality kicks in.
Attackers use SYN flood attacks to perform a denial of service attacked on a system by
sending many SYN packets without completing the three way handshake. This will
quickly use up slots in the kernel's half-open connection queue and prevent legitimate
connections from succeeding.
Setting net.ipv4.tcp_syncookies to 1 enables SYN cookies, allowing the system to keep
accepting valid connections, even if under a denial of service attack."

c="net.ipv4.tcp_syncookies = 1"

d=$(sysctl net.ipv4.tcp_syncookies 2>&1)

[[ "$d" == "net.ipv4.tcp_syncookies = 1" ]] && e="PASS" || e="FAIL"

f='
Open the sysctl.conf file in a text editor:
#nano /etc/sysctl.conf

Add or modify the following line:
net.ipv4.tcp_syncookies = 1

Save the file and exit the editor.
(in Nano, press CTRL + O to save and CTRL + X to exit).

Apply the changes by running:
#sysctl -p'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#-------------------------------------------------------------------------------------------------------------------------------------

a="3.3.11 Ensure ipv6 router advertisements are not accepted "

b="
Routers periodically multicast Router Advertisement messages to announce their
availability and convey information to neighboring nodes that enable them to be
automatically configured on the network.

Rationale:

It is recommended that systems do not accept router advertisements as they could be
tricked into routing traffic to compromised machines. Setting hard routes within the
system protects the system from bad routes.
Setting net.ipv6.conf.all.accept_ra and net.ipv6.conf.default.accept_ra to 0 disables
the system's ability to accept IPv6 router advertisements."

c='net.ipv6.conf.all.accept_ra = 1
net.ipv6.conf.default.accept_ra = 1'

d1=$(sysctl net.ipv6.conf.all.accept_ra )
d2=$(sysctl net.ipv6.conf.default.accept_ra )

e="FAIL"
[[ "$d1" == "net.ipv6.conf.all.accept_ra = 1" ]] && [[ "$d2" == "net.ipv6.conf.default.accept_ra = 1" ]] && e="PASS"

d="$d1
$d2"

f='
Open the sysctl.conf file in a text editor:
#nano /etc/sysctl.conf

Add or modify the following line:
net.ipv6.conf.all.accept_ra = 1
net.ipv6.conf.default.accept_ra = 1

Save the file and exit the editor.
(in Nano, press CTRL + O to save and CTRL + X to exit).

Apply the changes by running:
#sysctl -p'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="4.1.1 Ensure a single firewall configuration utility is in use"

b='
In Linux security, employing a single, effective firewall configuration utility ensures that
only legitimate traffic gets processed, reducing the system’s exposure to potential
threats. The choice between ufw, nftables, and firewalld depends on organizational needs.

Rationale:

Proper configuration of a single firewall utility minimizes cyber threats and protects
services and data, while avoiding vulnerabilities like open ports or exposed services.
Standardizing on a single tool simplifies management, reduces errors, and fortifies
security across Linux systems.

Impact:

The use of more than one firewall utility may produce unexpected results'

c='A single firewall is in use; follow the recommendation in (active firewall) subsection only'

d1=$(
active_firewall=() 
firewalls=("ufw" "nftables" "iptables")

# Determine which firewall is in use
for firewall in "${firewalls[@]}"; do
    case $firewall in
        nftables)
            cmd="nft" ;;
        *)
            cmd=$firewall ;;
    esac

    # Check if the command exists, and the service is enabled and active
    command -v $cmd &> /dev/null && \
    systemctl is-enabled --quiet $firewall && \
    systemctl is-active --quiet $firewall && active_firewall+=("$firewall")
done

# Display audit results
result_count=${#active_firewall[@]}
[ $result_count -eq 1 ] && \
    printf '%s\n' "" "Audit Results:" " ** PASS **" " - A single firewall is in use; follow the recommendation in ${active_firewall[0]} subsection only" || \
    { 
        [ $result_count -eq 0 ] && \
        printf '%s\n' "" "Audit Results:" " ** FAIL **" "- No firewall in use or unable to determine firewall status" || \
        printf '%s\n' "" "Audit Results:" " ** FAIL **" " - Multiple firewalls are in use: ${active_firewall[*]}"
    }


)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -q "PASS" && e="PASS" || e="FAIL"

f='Disable the inactive firewalls'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="4.2.1 Ensure ufw is installed"

b="
The Uncomplicated Firewall (ufw) is a frontend for iptables and is particularly well-suited
for host-based firewalls. ufw provides a framework for managing netfilter, as well as a
command-line interface for manipulating the firewall

Rationale:

A firewall utility is required to configure the Linux kernel's netfilter framework via the
iptables or nftables back-end.
The Linux kernel's netfilter framework host-based firewall can protect against threats
originating from within a corporate network to include malicious mobile code and poorly
configured software on a host.

Note: Only one firewall utility should be installed and configured. UFW is dependent on
the iptables package"

c='ufw is installed'

d=$( dpkg-query -s ufw &>/dev/null && echo "ufw is installed" || echo "ufw is not installed" )

[ "$d" == "ufw is installed" ] && e="PASS" || e="FAIL"

f='Run the following command to install Uncomplicated Firewall (UFW):

# apt install ufw'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="4.2.2 Ensure iptables-persistent is not installed with ufw"

#no output

b='The iptables-persistent is a boot-time loader for netfilter rules, iptables plugin

Rationale:

Running both ufw and the iptables-persistent package may lead to conflict'

c='iptables-persistent is not installed'

d=$( dpkg-query -s iptables-persistent &>/dev/null && echo "iptables-persistent is installed" || echo "iptables-persistent is not installed" )

[ "$d" == "iptables-persistent is not installed"  ] && e="PASS" || e="FAIL"

f='Run the following command to remove the iptables-persistent package:

# apt purge iptables-persistent'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="4.2.3 Ensure ufw service is enabled and active"

b='
UncomplicatedFirewall (ufw) is a frontend for iptables. ufw provides a framework for
managing netfilter, as well as a command-line and available graphical user interface for
manipulating the firewall.

Rationale:

The ufw service must be enabled and running in order for ufw to protect the system

Impact:

Changing firewall settings while connected over network can result in being locked out
of the system.'

c='
ufw daemon is enabled
ufw daemon is active
ufw Status: active'

d1=$(systemctl is-enabled ufw.service)
d2=$(systemctl is-active ufw)
d3=$(ufw status)

[[ "$d1" == "enabled" ]] && \
[[ "$d2" == "active" ]] && \
[[ "$d3" == "Status: active" ]]  && e="PASS" || e="FAIL"

d="ufw daemon is $d1
ufw daemon is $d2
ufw $d3"

f='
Run the following command to unmask the ufw daemon:
# systemctl unmask ufw.service

Run the following command to enable and start the ufw daemon:
# systemctl --now enable ufw.service

Run the following command to enable ufw:
# ufw enable'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="4.2.4 Ensure ufw loopback traffic is configured"

b='
Configure the loopback interface to accept traffic. Configure all other interfaces to deny
traffic to the loopback network (127.0.0.0/8 for IPv4 and ::1/128 for IPv6).

Rationale:

Loopback traffic is generated between processes on machine and is typically critical to
operation of the system. The loopback interface is the only place that loopback network
(127.0.0.0/8 for IPv4 and ::1/128 for IPv6) traffic should be seen, all other interfaces
should ignore traffic on this network as an anti-spoofing measure.'

c='# allow all on loopback
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT'

d=$(grep -P 'lo|127.0.0.0' /etc/ufw/before.rules | sed -n '2,4p')

[ "$d" == *"-A ufw-before-input -i lo -j ACCEPT"* ] &&
[ "$d" == *"-A ufw-before-output -o lo -j ACCEPT"* ] &&  e="FAIL" || e="PASS"

f='
To configure the loopback interface to accept traffic:
# ufw allow in on lo
# ufw allow out on lo

To configure all other interfaces to deny traffic to the loopback network:
# ufw deny in from 127.0.0.0/8
# ufw deny in from ::1'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="4.2.6 Ensure ufw firewall rules exist for all open ports"

b='
To reduce the attack surface of a system, all services and ports should be blocked unless required.
• Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.
• Without a firewall rule configured for open ports, the default firewall policy will
drop all packets to these ports.
• Required ports should have a firewall rule created to allow approved connections
in accordance with local site policy.
• Unapproved ports should have an explicit deny rule created.

Note:
Changing firewall settings while connected over network can result in being
locked out of the system
• The remediation command opens up the port to traffic from all sources. Consult
ufw documentation and set any restrictions in compliance with site policy'

c='All open ports have a rule in UFW'

d1=$(

{
    unset a_ufwout; unset a_openports

    while read -r l_ufwport; do
        [ -n "$l_ufwport" ] && a_ufwout+=("$l_ufwport")
    done < <(ufw status verbose | grep -Po '^\h*\d+\b' | sort -u)

    while read -r l_openport; do
        [ -n "$l_openport" ] && a_openports+=("$l_openport")
    done < <(ss -tuln | awk '($5!~/%lo:/ && $5!~/127.0.0.1:/ &&
    $5!~/\[?::1\]?:/) {split($5, a, ":"); print a[2]}' | sort -u)

    a_diff=($(printf '%s\n' "${a_openports[@]}" "${a_ufwout[@]}" "${a_ufwout[@]}" | sort | uniq -u))

    [[ -n "${a_diff[*]}" ]] && \
    echo -e "\n- Audit Result:\n ** FAIL **\n- The following port(s) don't have a rule in UFW: $(printf '%s\n' \\n"${a_diff[*]}")" || \
    echo -e "\n - Audit Passed -\n- All open ports have a rule in UFW\n"
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g')

echo "$d1" | grep -q "FAIL" && e="FAIL" || e="PASS"

f='
For each port identified in the audit which does not have a firewall rule,evaluate the
service listening on the port and add a rule for accepting or denying inbound
connections in accordance with local site policy:

Examples:
# ufw allow in <port>/<tcp or udp protocol>
# ufw deny in <port>/<tcp or udp protocol>'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="4.2.7 Ensure ufw default deny firewall policy "

b='
A default deny policy on connections ensures that any unconfigured network usage will be rejected.
Note: Any port or protocol without a explicit allow before the default deny will be blocked

Rationale:

With a default accept policy the firewall will accept any packet that is not configured to
be denied. It is easier to allow list acceptable usage than to deny list unacceptable usage.


Impact:
Any port and protocol not explicitly allowed will be blocked. The following rules should be
considered before applying the default deny'

c="Status: active
deny (incoming), deny (outgoing), disabled (routed)"

d1=$( ufw status verbose )

d2=$(ufw status verbose | grep Default:)

[ "$d1" == "Status: active" ] && [ "$d2" == "$c" ] && e="PASS" || e="FAIL"

d="$d1
$d2"

f='
Run the following commands to implement a default deny policy:
# ufw default deny incoming
# ufw default deny outgoing
# ufw default deny routed'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.1 Ensure permissions on /etc/ssh/sshd_config are configured "

b='The file /etc/ssh/sshd_config, and files ending in .conf in the
/etc/ssh/sshd_config.d directory, contain configuration specifications for sshd.

Rationale:

configuration specifications for sshd need to be protected from unauthorized changes
by non-privileged users.'

c='Access: ( ≤0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)'

d=$( stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/ssh/sshd_config 2>&1)

access=$(echo "$d" | grep -oP 'Access: \(\K[0-9]+')
uid=$(echo "$d" | grep -oP 'Uid: \( \K[0-9]+')
gid=$(echo "$d" | grep -oP 'Gid: { \K[0-9]+')

[ "$access" -le 0600 ] && [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ] && e="PASS" || e="FAIL"

f='Run the following commands to set ownership and permissions on /etc/ssh/sshd_config:
# chown root:root /etc/ssh/sshd_config
# chmod og-rwx /etc/ssh/sshd_config'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.1.2 Ensure permissions on SSH private host key files are configured"

b='An SSH private key is one of two files used in SSH public key authentication.
In this authentication method, the possession of the private key is proof of identity.
Only a private key that corresponds to a public key will be able to authenticate successfully.
The private keys need to be stored and handled carefully, and no copies of the private
key should be distributed.

Rationale:

If an unauthorized user obtains the private SSH host key file, the host could be
impersonated'

c='Verify SSH private host key files are owned by the root user and either:
• owned by the group root and mode 0600 or more restrictive
- OR -
• owned by the group designated to own openSSH private keys and mode 0640 or
more restrictive'

d=$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat -Lc 'Access: (%#a/%A) Uid: (%u/%U) Gid: (%g/%G)' {} \; 2>&1)

e="PASS"

for file in $(find /etc/ssh -xdev -type f -name 'ssh_host_*_key'); do
    # Get the file's UID, GID, and permissions
    uid=$(stat -c %u "$file")
    gid=$(stat -c %g "$file")
    permissions=$(stat -c %a "$file")

    # Check if UID and GID are both 0 (root)
    [[ "$uid" -ne 0 || "$gid" -ne 0 ]] && { e="FAIL"; break; }

    # Check if permissions are 0600 or more restrictive
    [[ "$permissions" -gt 600 ]] && { e="FAIL"; break; }
done

f='
Run the following commands to set permissions, ownership, and group on the private SSH host key files:

# find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,g-wx,o-rwx {} \;
# find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:ssh_keys {} \;'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.1.3 Ensure permissions on SSH public host key files are configured"

b='An SSH public key is one of two files used in SSH public key authentication.
In this authentication method, a public key is a key that can be used for verifying
digital signatures generated using a corresponding private key.Only a public key
that corresponds to a private key will be able to authenticate successfully.

Rationale:

If a public host key file is modified by an unauthorized user, the SSH service may be
compromised.'

c='Verify SSH public host key files are mode 0644 or more
restrictive, owned by the root user, and owned by the root group'

d1=$(
a_output=(); a_output2=(); a_parlist=("NTP=[^#\n\r]+" "FallbackNTP=[^#\n\r]+")
l_systemd_config_file="/etc/systemd/timesyncd.conf" # Main systemd configuration file

f_config_file_parameter_chk() {
    unset A_out; declare -A A_out # Check config file(s) setting
    while read -r l_out; do
        [ -n "$l_out" ] && {
            [[ $l_out =~ ^\s*# ]] && l_file="${l_out//# /}" || {
                l_systemd_parameter="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<< "$l_systemd_parameter" &&
                A_out+=(["$l_systemd_parameter"]="$l_file")
            }
        }
    done < <("$l_systemdanalyze" cat-config "$l_systemd_config_file" | grep -Pio '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')

    (( ${#A_out[@]} > 0 )) && {
        while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
            l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}"
            l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}"
            grep -Piq "\b$l_systemd_parameter_value\b" <<< "$l_systemd_file_parameter_value" &&
            a_output+=(" - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\"") || 
            a_output2+=(" - \"$l_systemd_parameter_name\" is incorrectly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value matching: \"$l_value_out\"")
        done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}")
    } || {
        a_output2+=(" - \"$l_systemd_parameter_name\" is not set in an included file *** Note: \"$l_systemd_parameter_name\" May be set in a file that's ignored by load procedure ***")
    }
}

l_systemdanalyze="$(readlink -f /bin/systemd-analyze)"
while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters
    l_systemd_parameter_name="${l_systemd_parameter_name// /}";
    l_systemd_parameter_value="${l_systemd_parameter_value// /}"
    l_value_out="${l_systemd_parameter_value//-/ through }"; 
    l_value_out="${l_value_out//|/ or }"
    l_value_out="$(tr -d '(){}' <<< "$l_value_out")"
    f_config_file_parameter_chk
done < <(printf '%s\n' "${a_parlist[@]}")

[ "${#a_output2[@]}" -le 0 ] && printf '%s\n' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" || {
    printf '%s\n' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
    [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g')  

echo "$d1" | grep -q "FAIL" && e="FAIL" || e="PASS"

f='
Run the following commands to set permissions and ownership on the SSH host public key files
# find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \;
#find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.4 Ensure sshd access is configured "

b="
There are several options available to limit which users and group can access the
system via SSH. It is recommended that at least one of the following options be leveraged

Verify that the output matches at least one of the following lines:
allowusers <userlist>
-OR-
allowgroups <grouplist>
-OR-
denyusers <userlist>
-OR-
denygroups <grouplist>

Review the list(s) to ensure included users and/or groups follow local site policy"

c='(List of users)'

d=$( sshd -T | grep -Pi -- '^\h*(allow|deny)(users|groups)\h+\H+' 2>&1)

[ -z "$d" ] && e="FAIL" || e="PASS"

f='
Edit the /etc/ssh/sshd_config file to set one or more of the
parameters above any Include and Match set statements as follows:

AllowUsers <userlist>
- AND/OR -
AllowGroups <grouplist>'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.1.5 Ensure sshd Banner is configured "

b="
The Banner parameter specifies a file whose contents must be sent to the remote user
before authentication is permitted. By default, no banner is displayed.

Rationale:

Banners are used to warn connecting users of the particular site's policy regarding
connection. Presenting a warning message prior to the normal user login may assist the
prosecution of trespassers on the computer system."

c='banner /etc/issue.net'

d=$( sshd -T | grep -Pi -- '^banner\h+\/\H+' )

[ -z "$d" ] && e="FAIL" || e="PASS"

f='
Edit the /etc/ssh/sshd_config file to set the Banner parameter above any Include
and Match entries as follows:

Banner /etc/issue.net'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.1.6 Ensure sshd Ciphers are configured "

b='This variable limits the ciphers that SSH can use during communication.

Rationale:

Weak ciphers that are used for authentication to the cryptographic module cannot be
relied upon to provide confidentiality or integrity, and system data may be compromised'

c="
No weak ciphers in the list
below should be returned:
3des-cbc
aes128-cbc
aes192-cbc
aes256-cbc"

weak_ciphers=("3des-cbc" "aes128-cbc" "aes192-cbc" "aes256-cbc")

d=$(sshd -T | grep ciphers 2>&1)

e="PASS"

for cipher in "${weak_ciphers[@]}"; do
    echo "$c" | grep -q "$cipher" && { e="FAIL"; break; }
done

f='
Edit the /etc/ssh/sshd_config file and add/modify the Ciphers line to contain a comma
separated list of the site unapproved (weak) Ciphers preceded with a - above any
Include entries:
Example: Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com

If CVE-2023-48795 has been addressed, and it meets local site policy,
chacha20-poly1305@openssh.com may be removed from the list of excluded ciphers.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

csv_file="Results.csv"

a="5.1.7 Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured  "

b='
The two options ClientAliveInterval and ClientAliveCountMax control the timeout
of SSH sessions. Taken directly from man 5 sshd_config:
• ClientAliveInterval Sets a timeout interval in seconds after which if no data
has been received from the client, sshd(8) will send a message through the
encrypted channel to request a response from the client. The default is 0,
indicating that these messages will not be sent to the client.
• ClientAliveCountMax Sets the number of client alive messages which may be
sent without sshd(8) receiving any messages back from the client. If this
threshold is reached while client alive messages are being sent, sshd will
disconnect the client, terminating the session.'

c='
clientaliveinterval ≤ 15 seconds
clientalivecountmax ≤ 3 attempts'

d1=$(sshd -T | grep clientaliveinterval 2>&1)

current_value_1=$(echo "$d1" | awk '{print $2}')


d2=$(sshd -T | grep clientalivecountmax 2>&1)

current_value_2=$(echo "$d2" | awk '{print $2}')

d="$d1
$d2"

[[ -n "$current_value_1" && "$current_value_1" -le 15 && "$current_value_1" -ne 0 ]] && \

[[ -n "$current_value_2" && "$current_value_2" -le 3 && "$current_value_2" -ne 0 ]] && e="PASS" || e="FAIL"

f='
Edit the /etc/ssh/sshd_config file to set the ClientAliveInterval and
ClientAliveCountMax parameters above any Include and Match entries according to
site policy.

Example:
lientaliveinterval ≤ 15 seconds
clientalivecountmax ≤ 3 attempts'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.1.8 Ensure sshd DisableForwarding is enabled "

b='
The DisableForwarding parameter disables all forwarding features, including X11,
ssh-agent(1), TCP and StreamLocal. This option overrides all other forwarding-related
options and may simplify restricted configurations.

• X11Forwarding provides the ability to tunnel X11 traffic through the connection to
enable remote graphic connections

Disable X11 forwarding unless there is an operational requirement to use X11
applications directly. There is a small risk that the remote X11 servers of users who are
logged in via SSH with X11 forwarding could be compromised by other users on the
X11 server. Note that even if X11 forwarding is disabled, users can always install their
own forwarders.'

c="disableforwarding yes"

d=$(sshd -T | grep -i disableforwarding)

[ "$d" == "$c" ] && e="PASS" || e="FAIL"

f='
Edit the /etc/ssh/sshd_config file to set the DisableForwarding parameter to yes
above any Include entry as follows:

DisableForwarding yes'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.9 Ensure sshd GSSAPIAuthentication is disabled "

b="
The GSSAPIAuthentication parameter specifies whether user authentication based on
GSSAPI is allowed

Rationale:

Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote
hosts, and should be disabled to reduce the attack surface of the system"

c="gssapiauthentication no"

d=$(sshd -T | grep gssapiauthentication)

[ "$d" == "$c" ] && e="PASS" || e="FAIL"

f='
Edit the /etc/ssh/sshd_config file to set the GSSAPIAuthentication parameter to
no above any Include and Match entries as follows:

GSSAPIAuthentication no'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.10 Ensure sshd HostbasedAuthentication is disabled"

b='
The HostbasedAuthentication parameter specifies if authentication is allowed
through trusted hosts via the user of .rhosts, or /etc/hosts.equiv, along with
successful public key client host authentication.

Rationale:

Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf,
disabling the ability to use .rhosts files in SSH provides an additional layer of
protection.'

c="hostbasedauthentication no"

d=$(sshd -T | grep hostbasedauthentication)

[ "$d" == "$c" ] && e="PASS" || e="FAIL"

f='Edit the /etc/ssh/sshd_config file to set the HostbasedAuthentication parameter
to no above any Include and Match entries as follows:

HostbasedAuthentication no'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.11 Ensure sshd IgnoreRhosts is enabled "

b='
The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used
in RhostsRSAAuthentication or HostbasedAuthentication.

Rationale:
Setting this parameter forces users to enter a password when authenticating with SSH.'

c="ignorerhosts yes"

d=$(sshd -T | grep ignorerhosts)

[ "$d" == "$c" ] && e="PASS" || e="FAIL"

f='
Edit the /etc/ssh/sshd_config file to set the IgnoreRhosts parameter to yes above
any Include and Match entries as follows:

IgnoreRhosts yes'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.12 Ensure sshd KexAlgorithms is configured "

b='
Key exchange is any method in cryptography by which cryptographic keys are
exchanged between two parties, allowing use of a cryptographic algorithm. If the sender
and receiver wish to exchange encrypted messages, each must be equipped to encrypt
messages to be sent and decrypt messages received

Rationale:

Key exchange methods that are considered weak should be removed. A key exchange
method may be weak because too few bits are used, or the hashing algorithm is
considered too weak. Using weak algorithms could expose connections to man-in-the-
middle attacks'

c='
The following weak Key Exchange Algorithms, and should not be used:

diffie-hellman-group1-sha1
diffie-hellman-group14-sha1
diffie-hellman-group-exchange-sha1'

d=$(sshd -T | grep kexalgorithms 2>&1)

e="PASS"

for weak_kex in diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 \
                diffie-hellman-group-exchange-sha1; do
    echo "$c" | grep -q "$weak_kex" && { e="FAIL"; break; }
done

f='
Edit the /etc/ssh/sshd_config file and add/modify the KexAlgorithms line to contain
a comma separated list of the site unapproved (weak) KexAlgorithms preceded with a -
above any Include entries:

Example:
KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-
hellman-group-exchange-sha1'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.13 Ensure sshd LoginGraceTime is configured "

b='
The LoginGraceTime parameter specifies the time allowed for successful
authentication to the SSH server. The longer the Grace period is the more open
unauthenticated connections can exist. Like other session controls in this session the
Grace Period should be limited to appropriate organizational limits to ensure the service
is available for needed access.

Rationale:

Setting the LoginGraceTime parameter to a low number will minimize the risk of
successful brute force attacks to the SSH server. It will also limit the number of
concurrent unauthenticated connections While the recommended setting is 60 seconds
(1 Minute), set the number based on site policy.'

c='LoginGraceTime (≤60) seconds'

d=$(sshd -T | grep logingracetime 2>&1)

d1=$(echo "$d" | awk '{print $2}')

[[ -n "$d1" && "$d1" -le 60 && "$d1" -ne 0 ]] && e="PASS" || e="FAIL"

f='Edit the /etc/ssh/sshd_config file to set the LoginGraceTime parameter to 60
seconds or less above any Include entry as follows:

LoginGraceTime (≤)60'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.14 Ensure sshd LogLevel is configured "

b='
SSH provides several logging levels with varying amounts of verbosity. The DEBUG
options are specifically not recommended other than strictly for debugging SSH
communications. These levels provide so much data that it is difficult to identify
important security information, and may violate the privacy of users.

Rationale:

1.The INFO level is the basic level that only records login activity of SSH users. In many
situations, such as Incident Response, it is important to determine when a particular
user was active on a system. The logout record can eliminate those users who
disconnected, which helps narrow the field.

2.The VERBOSE level specifies that login and logout activity as well as the key fingerprint
for any SSH key used for login will be logged. This information is important for SSH key
management, especially in legacy environments.'

c='LogLevel VERBOSE (or) LogLevel INFO'

d=$(sshd -T | grep loglevel 2>&1)

[[ "$d" == "loglevel VERBOSE" || "$d" == "loglevel INFO" ]] && e="PASS" || e="FAIL"

f='
Edit the /etc/ssh/sshd_config file to set the LogLevel parameter to VERBOSE or
INFO above any Include and Match entries as follows:

LogLevel VERBOSE (or) LogLevel INFO'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.15 Ensure sshd MACs are configured"

b="
This variable limits the types of MAC algorithms that SSH can use during
communication.

Notes:
• Some organizations may have stricter requirements for approved MACs.
• Ensure that MACs used are in compliance with site policy.

• The only "strong" MACs currently FIPS 140 approved are:
o HMAC-SHA1
o HMAC-SHA2-256
o HMAC-SHA2-384
o HMAC-SHA2-512"

c="
The following weak MACs should not be used:

hmac-md5
hmac-md5-96
hmac-ripemd160
hmac-sha1-96
umac-64@openssh.com
hmac-md5-etm@openssh.com
hmac-md5-96-etm@openssh.com
hmac-ripemd160-etm@openssh.com
hmac-sha1-96-etm@openssh.com
umac-64-etm@openssh.com
umac-128-etm@openssh.com"

check="hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh.com|hmac-md5-etm@openssh.com|hmac-md5-96-etm@openssh.com|
hmac-ripemd160-etm@openssh.com|hmac-sha1-96-etm@openssh.com|umac-64-etm@openssh.com|umac-128-etm@openssh.com"

d=$(sshd -T | grep -i "MACs" 2>&1)

echo "$d" | grep -E -q "$check" && e="FAIL" || e="PASS"

f='
Edit the /etc/ssh/sshd_config file and add/modify the MACs line to contain a comma
separated list of the site unapproved (weak) MACs preceded with a - above any
Include entries'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.16 Ensure sshd MaxAuthTries is configured "

b='
The MaxAuthTries parameter specifies the maximum number of authentication
attempts permitted per connection. When the login failure count reaches half the
number, error messages will be written to the syslog file detailing the login failure.

Rationale:

Setting the MaxAuthTries parameter to a low number will minimize the risk of
successful brute force attacks to the SSH server. While the recommended setting is 4,
set the number based on site policy.'

c='maxauthtries ≤4'

d=$(sshd -T | grep maxauthtries 2>&1)

check=$(echo "$d" | awk '{print $2}')

[[ -n "$check" && "$check" -le 4 && "$check" -ne 0 ]]  && e="PASS" || e="FAIL"

f='
Edit the /etc/ssh/sshd_config file to set the MaxAuthTries parameter to 4 or less
above any Include and Match entries as follows:

MaxAuthTries ≤4'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.17 Ensure sshd MaxSessions is configured"

b='
The MaxSessions parameter specifies the maximum number of open sessions
permitted from a given connection.

Rationale:

To protect a system from denial of service due to a large number of concurrent
sessions, use the rate limiting function of MaxSessions to protect availability of sshd
logins and prevent overwhelming the daemon.'

c='maxsessions ≤10'

d=$(sshd -T | grep -i maxsessions 2>&1)

check=$(echo "$d" | awk '{print $2}')

[[ -n "$check" && "$check" -le 10 && "$check" -ne 0 ]] && e="PASS" || e="FAIL"

f='
Edit the /etc/ssh/sshd_config file to set the MaxSessions parameter to 10 or less
above any Include and Match entries as follows:

MaxSessions ≤10'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.18 Ensure sshd MaxStartups is configured "

b='
The MaxStartups parameter specifies the maximum number of concurrent
unauthenticated connections to the SSH daemon.

Rationale:

To protect a system from denial of service due to a large number of pending
authentication connection attempts, use the rate limiting function of MaxStartups to
protect availability of sshd logins and prevent overwhelming the daemon'

c='MaxStartups is 10:30:60 or more restrictive'

d=$(sshd -T | awk '$1 ~ /^\s*maxstartups/{split($2, a, ":");{if(a[1] > 10 || a[2] > 30 || a[3] > 60) print $0}}' 2>&1)

[ -z "$check" ] && { d="MaxStartups is 10:30:60 or more restrictive"; e="PASS"; } || { d="MaxStartups is not restrictive"; e="FAIL"; }

f='
Edit the /etc/ssh/sshd_config file to set the MaxStartups parameter to 10:30:60 or
more restrictive above any Include entries as follows:

MaxStartups 10:30:60'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.19 Ensure sshd PermitEmptyPasswords is disabled"

b='
The PermitEmptyPasswords parameter specifies if the SSH server allows login to
accounts with empty password strings.

Rationale:

Disallowing remote shell access to accounts that have an empty password reduces the
probability of unauthorized access to the system.'

c="permitemptypasswords no"

d=$(sshd -T | grep permitemptypasswords)

[ "$d" == "$c" ] && e="PASS" || e="FAIL"

f='
Edit /etc/ssh/sshd_config and set the PermitEmptyPasswords parameter to no
above any Include and Match entries as follows:

PermitEmptyPasswords no'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.20 Ensure sshd PermitRootLogin is disabled "

b='
The PermitRootLogin parameter specifies if the root user can log in using SSH. The
default is prohibit-password.

Rationale:

Disallowing root logins over SSH requires system admins to authenticate using their
own individual account, then escalating to root. This limits opportunity for non-
repudiation and provides a clear audit trail in the event of a security incident.'

c="permitrootlogin no"

d=$(sshd -T | grep permitrootlogin)

[ "$d" == "$c" ] && e="PASS" || e="FAIL"

f='
Edit the /etc/ssh/sshd_config file to set the PermitRootLogin parameter to no
above any Include and Match entries as follows:

PermitRootLogin no'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.21 Ensure sshd PermitUserEnvironment is disabled"

b="
The PermitUserEnvironment option allows users to present environment options to SSH daemon.

Rationale:

Permitting users the ability to set environment variables through the SSH daemon could
potentially allow users to bypass security controls (e.g. setting an execution path that
has SSH executing trojan'd programs)"

c="permituserenvironment no"

d=$(sshd -T | grep permituserenvironment)

[ "$d" == "$c" ] && e="PASS" || e="FAIL"

f='
Edit the /etc/ssh/sshd_config file to set the PermitUserEnvironment parameter to
no above any Include entries as follows:

PermitUserEnvironment no'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.1.22 Ensure sshd UsePAM is enabled "

b='
The UsePAM directive enables the Pluggable Authentication Module (PAM) interface. If
set to yes this will enable PAM authentication using ChallengeResponseAuthentication
and PasswordAuthentication directives in addition to PAM account and session module
processing for all authentication types.

Rationale:

When usePAM is set to yes, PAM runs through account and session types properly. This
is important if you want to restrict access to services based off of IP, time or other
factors of the account. Additionally, you can make sure users inherit certain
environment variables on login or disallow access to the server'

c="usepam yes"

d=$(sshd -T | grep -i usepam)

[ "$d" == "$c" ] && e="PASS" || e="FAIL"

f='
Edit the /etc/ssh/sshd_config file to set the UsePAM parameter to yes
above any Include entries as follows:

UsePAM yes'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.2.1 Ensure sudo is installed"

b="
sudo allows a permitted user to execute a command as the superuser or another user,
as specified by the security policy. The invoking user's real (not effective) user ID is
used to determine the user name with which to query the security policy."

c='Latest version of sudo'

d=$( sudo --version | grep "Sudo version" )

[[ "$d" ==  *version* ]] && e="PASS" || e="FAIL"

f='
First determine if LDAP functionality is required.
If so, then install sudo-ldap, else install sudo.

# apt install sudo'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.2.2 Ensure sudo commands use pty"

b='
sudo can be configured to run only from a pseudo terminal (pseudo-pty).

Rationale:

Attackers can run a malicious program using sudo which would fork a background
process that remains even when the main program has finished executing.

Note: Editing the sudo configuration incorrectly can cause sudo to stop
functioning. Always use visudo to modify sudo configuration files.'

c='/etc/sudoers:Defaults use_pty'

d1=$( grep -Ei '^\s*Defaults\s+([^#]\S+,\s*)?use_pty\b' /etc/sudoers /etc/sudoers.d/* 2>&1 )

d2=$( grep -rPi -- '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' /etc/sudoers* 2>&1)

[[ "$d1" == *"use_pty"* ]] && [[ -z "$d2" ]]  && e="PASS" || e="FAIL"

d="$d1
$d2"

f='
Edit the file /etc/sudoers with visudo or a file in /etc/sudoers.d/ with visudo
-f<PATH TO FILE> and add the following line:
Defaults use_pty

Edit the file /etc/sudoers with visudo and any files in /etc/sudoers.d/ with visudo
-f <PATH TO FILE> and remove any occurrence of !use_pty'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.2.3 Ensure sudo log file exists"

b='
sudo can use a custom log file

Rationale:
A sudo log file simplifies auditing of sudo commands

NOte: Editing the sudo configuration incorrectly can cause sudo to stop
functioning. Always use visudo to modify sudo configuration files.'

c1='Defaults logfile="/var/log/sudo.log"'

d=$( grep -rPsi "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h* (#.*)?$" /etc/sudoers* 2>&1 )

[[ "$d" == *"sudo.log"* ]] && e="PASS" || e="FAIL"

f='
Edit the file /etc/sudoers or a file in /etc/sudoers.d/ with visudo or visudo
-f <PATH TO FILE> and add the following line:

Defaults logfile="/var/log/sudo.log"'

c=$(printf "%s\n" "$c1" | sed 's/"/""/g') 

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.2.4 Ensure users must provide password for privilege escalation"

b='
The operating system must be configured so that users must provide a password for
privilege escalation.
Ensure no line is returned with occurrences of NOPASSWD tags in the file.

Rationale:

Without (re-)authentication, users may access resources or perform tasks for which they
do not have authorization.
When operating systems provide the capability to escalate a functional capability, it is
critical the user (re-)authenticate.'

c='
Password is set for /etc/sudoers
and /etc/sudoers.d/* files '

check=$( grep -r "^[^#].*NOPASSWD" /etc/sudoers* )

[ -z "$check" ] && { d="Password is set"; e="PASS"; } || { d="Password is not set"; e="FAIL"; }

f='
Based on the outcome of the audit procedure, use visudo
-f <PATH TO FILE> to edit the relevant sudoers file.

Remove any line with occurrences of NOPASSWD tags in the file.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.2.5 Ensure re-authentication for privilege escalation is not disabled globally "

b='
The operating system must be configured so that users must re-authenticate for
privilege escalation.

Rationale:

Without re-authentication, users may access resources or perform tasks for which they
do not have authorization.
When operating systems provide the capability to escalate a functional capability, it is
critical the user re-authenticate.'

c='Requires users to re-authenticate'

check=$( grep -r "^[^#].*\!authenticate" /etc/sudoers* )

[ -z "$check" ] && { d="Requires users to re-authenticate"; e="PASS"; } || { d="Disabled"; e="FAIL"; }

f='
Use visudo -f <PATH TO FILE> to edit the relevant sudoers file.

Remove any occurrences of !authenticate tags in the file(s).'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.2.6 Ensure sudo authentication timeout is configured correctly "

b='
sudo caches used credentials for a default of 15 minutes. This is for ease of use when
there are multiple administrative tasks to perform. The timeout can be modified to suit
local security policies.
This default is distribution specific. See audit section for further information.

Rationale:

Setting a timeout value reduces the window of opportunity for unauthorized privileged
access to another user.'

c='Authentication timestamp timeout: ≤15.0 minutes'

check=$( sudo -V | grep "Authentication timestamp timeout:" | awk '{print $4}' )

d="Authentication timestamp timeout: "$check" minutes"

[[ -n "$check" && $(echo "$check <= 15.0" | bc -l) -eq 1 ]] && e="PASS" || e="FAIL"

f="
If the currently configured timeout is larger than 15 minutes, edit the file listed in the
audit section with visudo -f <PATH TO FILE> and modify the entry
timestamp_timeout= to 15 minutes or less as per your site policy.

The value is in minutes. This particular entry may appear on it's own, or on the same line as
env_reset. See the following two examples:

Defaults env_reset, timestamp_timeout=15
Defaults timestamp_timeout=15
Defaults env_reset"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.2.7 Ensure access to the su command is restricted"

b='
Restricting the use of su , and using sudo in its place, provides system administrators
better control of the escalation of user privileges to execute privileged commands.
The sudo utility also provides a better logging and audit mechanism, as it can log each
command executed via sudo , whereas su can only record that a user executed the su program.'

c='auth required pam_wheel.so use_uid group=(group name)'

d=$( grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2) (use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su )

[[ "$d" == *"use_uid group="* ]] && e="PASS" || e="FAIL"

f='
Create an empty group that will be specified for use of the su command. The group
should be named according to site policy.
Example:
# groupadd sugroup

Add the following line to the /etc/pam.d/su file, specifying the empty group:
auth required pam_wheel.so use_uid group=sugroup'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.1.1 Ensure latest version of pam is installed "

b='
Updated versions of PAM include additional functionality

Rationale:

To ensure the system has full functionality and access to the options covered by this
Benchmark the latest version of libpam-runtime should be installed on the system'

c='Latest version of PAM'

d=$( dpkg-query -s libpam-runtime | grep -P -- '^(Version)\b' )

[[ "$d" == *"Version"* ]] && e="PASS" || e="FAIL"

f='
Run the following command to update to the latest version of PAM:

# apt upgrade libpam-runtime'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.1.2 Ensure libpam-modules is installed"

b='
Ensure the system has full functionality and access to the PAM options covered by
this Benchmark'

c='Latest version of libpam-modules'

d=$( dpkg-query -s libpam-modules | grep -P -- '^(Version)\b' )

[[ "$d" == *"Version"* ]] && e="PASS" || e="FAIL"

f='
Run the following command to update to the latest version of PAM:

# apt upgrade libpam-modules'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.1.3 Ensure libpam-pwquality is installed"

b='
libpwquality provides common functions for password quality checking and scoring
them based on their apparent randomness. The library also provides a function for
generating random passwords with good pronounceability.

This module can be plugged into the password stack of a given service to provide some
plug-in strength-checking for passwords. The code was originally based on
pam_cracklib module and the module is backwards compatible with its options.

Rationale:
Strong passwords reduce the risk of systems being hacked through brute force
methods'

c='Latest version of libpam-pwquality'

d=$( dpkg-query -s libpam-pwquality | grep -P -- '^(Version)\b' )

[[ "$d" == *"Version"* ]] && e="PASS" || e="FAIL"

f='
Run the following command to install libpam-pwquality:

# apt upgrade libpam-pwquality'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.2.1 Ensure pam_unix module is enabled "

b="
pam_unix is the standard Unix authentication module. It uses standard calls from the
system's libraries to retrieve and set account information as well as authentication.
Usually this is obtained from the /etc/passwd and if shadow is enabled, the
/etc/shadow file as well."

c='
/etc/pam.d/common-account:account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so
/etc/pam.d/common-session:session required pam_unix.so
/etc/pam.d/common-auth:auth [success=2 default=ignore] pam_unix.so try_first_pass
/etc/pam.d/common-password:password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt'

d=$( grep -P -- '\bpam_unix\.so\b' /etc/pam.d/common-{account,session,auth,password})

[[ -n "$d" ]] && e="PASS" || e="FAIL"

f='Run the following command to enable the pam_unix module:

# pam-auth-update --enable unix'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.2.2 Ensure pam_faillock module is enabled"

b='
The pam_faillock.so module maintains a list of failed authentication attempts per
user during a specified interval and locks the account in case there were more than the
configured number of consecutive failed authentications (this is defined by the deny
parameter in the faillock configuration). It stores the failure records into per-user files in
the tally directory.

Rationale:

Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute
force password attacks against your systems.'

c='
/etc/pam.d/common-auth:auth requisite pam_faillock.so preauth
/etc/pam.d/common-auth:auth [default=die] pam_faillock.so authfail
/etc/pam.d/common-account:account required pam_faillock.so'

d=$( grep -P -- '\bpam_faillock\.so\b' /etc/pam.d/common-{auth,account} )

[[ -n "$d" ]] && e="PASS" || e="FAIL"

f='
Create two pam-auth-update profiles in /usr/share/pam-configs/:
1. Create the faillock profile in /usr/share/pam-configs/
2. Create the faillock_notify profile in /usr/share/pam-configs/

Run the following command to update the common-auth and common-account PAM
files with the new profiles:

pam-auth-update --enable (faillock profile name)
# pam-auth-update --enable (faillock_notify profile name)'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.2.3 Ensure pam_pwquality module is enabled "

b='
The pam_pwquality.so module performs password quality checking. This module can
be plugged into the password stack of a given service to provide strength-checking for
passwords. The code was originally based on pam_cracklib module and the module is
backwards compatible with its options.

Rationale:

Use of a unique, complex passwords helps to increase the time and resources required
to compromise the password.'

c='password requisite pam_pwquality.so retry=3'

d=$( grep -P -- '\bpam_pwquality\.so\b' /etc/pam.d/common-password )

[[ "$d" == *"retry=3"* ]] && e="PASS" || e="FAIL"

f='
Create a pam-auth-update profile in /usr/share/pam-configs/
with the following lines:

Name: Pwquality 
Default: yes
Priority: 1024
Conflicts: cracklib
Password-Type: Primary
Password:
requisite pam_pwquality.so retry=3

Run the following command to update /etc/pam.d/common-password with the
pwquality profile:

# pam-auth-update --enable pwquality'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.2.4 Ensure pam_pwhistory module is enabled "

b='
The pam_pwhistory.so module saves the last passwords for each user in order to
force password change history and keep the user from alternating between the same
password too frequently.
This module does not work together with kerberos. In general, it does not make much
sense to use this module in conjunction with NIS or LDAP, since the old passwords are
stored on the local machine and are not available on another machine for password
history checking.

Rationale:
Use of a unique, complex passwords helps to increase the time and resources required
to compromise the password.'

c='password requisite pam_pwhistory.so remember=24 enforce_for_root
try_first_pass use_authtok'

d=$(  grep -P -- '\bpam_pwhistory\.so\b' /etc/pam.d/common-password )

[[ "$d" == *"pam_pwhistory.so"* ]] && e="PASS" || e="FAIL"

f='
reate a pwhistory profile in /usr/share/pam-configs/ with the following lines:

Name: pwhistory 
Default: yes
Priority: 1024
Password-Type: Primary
Password: requisite pam_pwhistory.so remember=24 enforce_for_root
try_first_pass use_authtok

Run the following command to update /etc/pam.d/common-password with the
pwhistory profile:

# pam-auth-update --enable pwhistory'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.1.1 Ensure password failed attempts lockout is configured"

b='
The deny=<n> option will deny access if the number of consecutive authentication
failures for this user during the recent interval exceeds.

Rationale:

Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute
force password attacks against your systems'

c='deny = 5'

d=$( grep -Pi -- '^\h*deny\h*=\h*[1-5]\b' /etc/security/faillock.conf | awk '{print $3}' )

[[ -n "$d" && "$d" -le 5 && "$d" -ne 0 ]] && e="PASS" || e="FAIL"

f="
Create or edit the following line in /etc/security/faillock.conf setting the deny option to 5 or less:
deny = 5

Run the following command:
# grep -Pl -- '\bpam_faillock\.so\h+([^#\n\r]+\h+)?deny\b' /usr/share/pam-configs/*

Edit any returned files and remove the deny=<N> arguments from the pam_faillock.so line(s):"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.1.2 Ensure password unlock time is configured "

b='
unlock_time=<n> - The access will be re-enabled after seconds after the lock out. The
value 0 has the same meaning as value never - the access will not be re-enabled
without resetting the faillock entries by the faillock(8) command.

Rationale:

Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute
force password attacks against your systems.'

c='unlock_time = ≤ 900 seconds'

check=$( grep -Pi -- '^\h*unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf | awk '{print $3}' )

[[ -n "$check" && "$check" -le 900 ]] && e="PASS" || e="FAIL"

d="unlock_time = "$check" seconds"

f='
Set password unlock time to conform to site policy. 
unlock_time should be 0 (never),or 900 seconds or greater.

Edit /etc/security/faillock.conf and update or add the following line:
unlock_time = ≤900'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.1.3 Ensure password failed attempts lockout includes root account"

b='
even_deny_root - Root account can become locked as well as regular accounts
root_unlock_time=n - This option implies even_deny_root option.
Allow access after n seconds to root account after the account is locked.
In case the option is not specified the value is the same as of the unlock_time option.

Rationale:
Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute
force password attacks against your systems.

Note:
Use of unlock_time=0 or root_unlock_time=0 may allow an attacker to cause denial
of service to legitimate users.'

c='
even_deny_root
--AND/OR--
root_unlock_time = (no.of sec)'

d=$( grep -Pi -- '^\h*(even_deny_root|root_unlock_time\h*=\h*\d+)\b' /etc/security/faillock.conf)

[[ "$d" == *"even_deny_root"* ]] && \
[[ "$d" == *"root_unlock_time"* ]]  && e="PASS" || e="FAIL"

f='
Edit /etc/security/faillock.conf:
• Remove or update any line containing root_unlock_time, - OR - set it to a
value of 60 or more

• Update or add the following line:
even_deny_root'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.2.1 Ensure password number of changed characters is configured"

b='
The pwquality difok option sets the number of characters in a password that must not
be present in the old password.'

c='/etc/security/pwquality.conf.d/50-pwdifok.conf:difok = 2'

d=$( grep -Psi -- '^\h*difok\h*=\h*([2-9]|[1-9][0-9]+)\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf )

check=$(echo "$d" | awk -F '=' '{print $2}' | xargs)

[[ -n "$check" && "$check" -le 2 && "$check" -ne 0 ]] && e="PASS" || e="FAIL"

f='
Create or modify a file ending in .conf in the /etc/security/pwquality.conf.d/
directory or the file /etc/security/pwquality.conf and add or modify the following
line to set difok to 2 or more. Ensure setting conforms to local site policy'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.2.2 Ensure minimum password length is configured"

b="
The minimum password length setting determines the lowers number of characters that
make up a password for a user account. There are many different theories about how to
determine the best password length for an organization, but perhaps "passphrase" is a
better term than password.

The minlen option sets the minimum acceptable size for the new password. 
Cannot be set to lower value than 6."

c='/etc/security/pwquality.conf.d/50-pwlength.conf:minlen = 14'

d=$( grep -Psi -- '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)

check=$(echo "$d" | awk -F '=' '{print $2}' | xargs)

[[ -n "$check" && "$check" -le 14 ]] && e="PASS" || e="FAIL"

f='
Create or modify a file ending in .conf in the /etc/security/pwquality.conf.d/
directory or the file /etc/security/pwquality.conf and add or modify the following
line to set password length of 14 or more characters. Ensure that password length
conforms to local site policy'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.2.4 Ensure password same consecutive characters is configured "

b='
The pwquality maxrepeat option sets the maximum number of allowed same
consecutive characters in a new password.'

c='/etc/security/pwquality.conf.d/50-pwrepeat.conf:maxrepeat = ( ≤ 3 but not 0)'

d=$( grep -Psi -- '^\h*maxrepeat\h*=\h*[1-3]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf )

check=$(echo "$d" | awk -F '=' '{print $2}' | xargs)

[[ -n "$check" && "$check" -gt 0 && "$check" -le 3 ]] && e="PASS" || e="FAIL"

f='
Create or modify a file ending in .conf in the /etc/security/pwquality.conf.d/
directory or the file /etc/security/pwquality.conf and add or modify the following
line to set maxrepeat to 3 or less and not 0. Ensure setting conforms to local site policy'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.2.5 Ensure password maximum sequential characters is configured  "

b='
The pwquality maxsequence option sets the maximum length of monotonic character
sequences in the new password. Examples of such sequence are 12345 or fedcb. The
check is disabled if the value is 0.

Note: Most such passwords will not pass the simplicity check unless the sequence is
only a minor part of the password.'

c='/etc/security/pwquality.conf.d/50-pwmaxsequence.conf:maxsequence = 3'

d=$( grep -Psi -- '^\h*maxsequence\h*=\h*[1-3]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf )

check=$(echo "$d" | awk -F '=' '{print $2}' | xargs)

[[ -n "$check" && "$check" -gt 0 && "$check" -le 3 ]] && e="PASS" || e="FAIL"

f='
Create or modify a file ending in .conf in the /etc/security/pwquality.conf.d/
or the file /etc/security/pwquality.conf and add or modify the following line to 
set maxsequence to 3 or less and not 0. Ensure setting conforms to local site policy'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.2.6 Ensure password dictionary check is enabled "

#no output 

b='
The pwquality dictcheck option sets whether to check for the words from the cracklib dictionary.

Rationale:

If the operating system allows the user to select passwords based on dictionary words,
this increases the chances of password compromise by increasing the opportunity for
successful guesses, and brute-force attacks.'

c='dictcheck is enabled'

d1=$( grep -Psi -- '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf )

d2=$( grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\ r]+\h+)?dictcheck\h*=\h*0\b' /etc/pam.d/common-password )

[ -z "$d1" ] && [ -z "$d2" ] && { d="dictcheck is enabled"; e="PASS"; } || { d="dictcheck is disabled"; e="FAIL"; }

f='
Edit any file ending in .conf in the /etc/security/pwquality.conf.d/ directory
and/or the file /etc/security/pwquality.conf and comment out or remove any
instance of dictcheck = 0'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.2.7 Ensure password quality checking is enforced "

b='
The pam_pwquality module can be configured to either reject a password if it fails the
checks, or only print a warning.
This is configured by setting the enforcing=<N> argument. If nonzero, a password will
be rejected if it fails the checks, otherwise only a warning message will be provided.

This setting applies only to the pam_pwquality module and possibly other applications
that explicitly change their behavior based on it. It does not affect pwmake(1) and
pwscore(1)'

c='enforcing=1'

#no output 

d1=$( grep -PHsi -- '^\h*enforcing\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf )

d2=$( grep -PHsi -- '^\h*password\h+[^#\n\r]+\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?enforcing=0\b' /etc/pam.d/common-password )

[ -z "$d1" ] && [ -z "$d2" ] && { d="enforcing=1"; e="PASS"; } || { d="quality checking is not enforced"; e="FAIL"; }

f="
Run the following command:
# grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?enforcing=0\b'/usr/share/pam-configs/*

Edit any returned files and remove the enforcing=0 argument from the
pam_pwquality.so line(s)

Edit /etc/security/pwquality.conf and all files ending in .conf in the
/etc/security/pwquality.conf.d/ directory and remove or comment out any line
containing the enforcing = 0 argument"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.2.8 Ensure password quality is enforced for the root user"

b='
If the pwquality enforce_for_root option is enabled, the module will return error on
failed check even if the user changing the password is root.

This option is off by default which means that just the message about the failed check is
printed but root can change the password anyway.

Note: The root is not asked for an old password so the checks that compare the old and
new password are not performed'

c='/etc/security/pwquality.conf.d/50-pwroot.conf:enforce_for_root'

d=$( grep -Psi -- '^\h*enforce_for_root\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf )

[[ "$d" == *"enforce_for_root"* ]] && e="PASS" || e="FAIL"

f='
Edit or add the following line in a *.conf file in 
/etc/security/pwquality.conf.d orin /etc/security/pwquality.conf'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.3.1 Ensure password history remember is configured"

b="
The /etc/security/opasswd file stores the users' old passwords and can be checked
to ensure that users are not recycling recent passwords. The number of passwords
remembered is set via the remember argument value in set for the pam_pwhistory module.
• remember=<N> - <N> is the number of old passwords to remember

Rationale:

Requiring users not to reuse their passwords make it less likely that an attacker will be
able to guess the password or use a compromised password."

c='password requisite pam_pwhistory.so remember=24 enforce_for_root
try_first_pass use_authtok'

d=$( grep -Psi -- '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=\d+\b ' /etc/pam.d/common-password )

[[ "$d" == *"enforce_for_root"* ]] && \
[[ "$d" == *"remember="* ]]  && e="PASS" || e="FAIL"

f="
Run the following command:
# awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } 
f {if(/pam_pwhistory\.so/) print FILENAME}' /usr/share/pam-configs/*

Edit any returned files and edit or add the remember= argument, with a value of 24 or
more, that meets local site policy to the pam_pwhistory line in the Password section"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.3.2 Ensure password history is enforced for the root user"

b='
If the pwhistory enforce_for_root option is enabled, the module will enforce
password history for the root user as well

Rationale:

Requiring users not to reuse their passwords make it less likely that an attacker will be
able to guess the password or use a compromised password'

c='
password requisite pam_pwhistory.so remember=24 enforce_for_root
try_first_pass use_authtok'

d=$( grep -Psi -- '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?enforce_for_root\b' /etc/pam.d/common-password )

[[ "$d" == *"enforce_for_root"* ]] && \
[[ "$d" == *"remember="* ]]  && e="PASS" || e="FAIL"

f="
Run the following command:
# awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if
(/pam_pwhistory\.so/) print FILENAME}' /usr/share/pam-configs/*

Edit any returned files and add the enforce_for_root argument to the
pam_pwhistory line in the Password section"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.3.3 Ensure pam_pwhistory includes use_authtok"

b='
use_authtok - When password changing enforce the module to set the new password
to the one provided by a previously stacked password module

Rationale:

use_authtok allows multiple pam modules to confirm a new password before it is
accepted'

c='
password requisite pam_pwhistory.so remember=24 enforce_for_root
try_first_pass use_authtok'

d=$( grep -Psi -- '^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b' /etc/pam.d/common-password )

[[ "$d" == *"use_authtok"* ]]  && e="PASS" || e="FAIL"

f="
Run the following command:

# awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if
(/pam_pwhistory\.so/) print FILENAME}' /usr/share/pam-configs/*

Edit any returned files and add the use_authtok argument to the pam_pwhistory line
in the Password section"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.4.1 Ensure pam_unix does not include nullok "

b='
The nullok argument overrides the default action of pam_unix.so to not permit the
user access to a service if their official password is blank.

Rationale:

Using a strong password is essential to helping protect personal and sensitive
information from unauthorized access'

c='
Verify that the nullok argument is
not set on the pam_unix.so module'

d=$( grep -PH -- '^\h*^\h*[^#\n\r]+\h+pam_unix\.so\b' /etc/pam.d/common-{password,auth,account,session,session-noninteractive} | grep -Pv -- '\bnullok\b' )

[[ "$d" == *"nullok"* ]]  && e="FAIL" || e="PASS"

f="
Run the following command:

# grep -PH -- '^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b'/usr/share/pam-configs/*

Edit any files returned and remove the nullok argument for the pam_unix lines"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.4.2 Ensure pam_unix does not include remember"

b="
The remember=n argument should be removed to ensure a strong password hashing
algorithm is being used. A stronger hash provides additional protection to the system by
increasing the level of effort needed for an attacker to successfully determine local
user's old passwords stored in /etc/security/opasswd."

c='
Verify that the remember argument is
not set on the pam_unix.so module'

d=$( grep -PH -- '^\h*^\h*[^#\n\r]+\h+pam_unix\.so\b' /etc/pam.d/common- {password,auth,account,session,session-noninteractive} | grep -Pv -- '\bremember=\d+\b' 2>&1 )

[[ -z "$d" && "$d" == *"remember"* ]]  && e="FAIL" || e="PASS"

f="
Run the following command:

# grep -PH -- '^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?remember\b'/usr/share/pam-configs/*

Edit any files returned and remove the remember=_<N>_ argument for the pam_unix lines"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.4.3 Ensure pam_unix includes a strong password hashing algorithm "

b='
The SHA-512 and yescrypt algorithms provide a stronger hash than other algorithms
used by Linux for password hash generation. A stronger hash provides additional
protection to the system by increasing the level of effort needed for an attacker to
successfully determine local user passwords.'

c="
/etc/pam.d/common-password:password [success=1 default=ignore]
pam_unix.so obscure use_authtok try_first_pass (sha512 or yescrypt)"

d=$( grep -PH -- '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?(sha512|yescrypt) \b' /etc/pam.d/common-password )

echo "$d" | grep -qE "SHA512|YESCRYPT" && e="PASS" || e="FAIL"

f="
Run the following command:
# awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if(/pam_unix\.so/) print FILENAME}' /usr/share/pam-configs/*

Edit any returned files and edit or add a strong hashing algorithm, either sha512 or
yescrypt, that meets local site policy to the pam_unix lines in the Password section:"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.3.3.4.4 Ensure pam_unix includes use_authtok"

b='
use_authtok - When password changing enforce the module to set the new password
to the one provided by a previously stacked password module

Rationale:

It allows multiple pam modules to confirm a new password before it is accepted.'

c='
/etc/pam.d/common-password:password [success=1 default=ignore]
pam_unix.so obscure use_authtok try_first_pass yescrypt'

d=$( grep -PH -- '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b' /etc/pam.d/common-password )

[[ "$d" == *"use_authtok"* ]]  && e="PASS" || e="FAIL"

f="
Run the following command:
# awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if(/pam_unix\.so/) print FILENAME}' /usr/share/pam-configs/*

Edit any returned files add use_authtok to the pam_unix line in the Password section
under Password: subsection"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.4.1.1 Ensure password expiration is configured "

b="
The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force
passwords to expire once they reach a defined age.
PASS_MAX_DAYS <N> - The maximum number of days a password may be used. If the
password is older than this, a password change will be forced.
If not specified, -1 will be assumed (which disables the restriction).

Rationale:

The window of opportunity for an attacker to leverage compromised credentials or
successfully compromise credentials via an online brute force attack is limited by the
age of the password. Therefore, reducing the maximum age of a password also reduces
an attacker's window of opportunity"

c='
Verify PASS_MAX_DAYS is set to 365 days or less
and conforms to local site policy:'

d=$(grep -Pi -- '^\h*PASS_MAX_DAYS\h+\d+\b' /etc/login.defs)

check=$(echo "$d" | awk '{print $2}')

[[ -n "$check" && "$check" -le 365 && "$check" -ne 0 ]] && e="PASS" || e="FAIL"

f='
Set the PASS_MAX_DAYS parameter to conform to site policy in /etc/login.defs :

PASS_MAX_DAYS ≤ 365'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.4.1.2 Ensure minimum password days is configured "

b="
PASS_MIN_DAYS <N> - The minimum number of days allowed between password
changes. Any password changes attempted sooner than this will be rejected. If not
specified, 0 will be assumed (which disables the restriction)"

c='
Verify that PASS_MIN_DAYS is set to a
value greater than 0 for all passwords
and follows local site policy'

d1=$( grep -Pi -- '^\h*PASS_MIN_DAYS\h+\d+\b' /etc/login.defs )

check=$(echo "$d1" | awk '{print $2}')

d2=$(awk -F: '($2~/^\$.+\$/) {if($4 < 1)print "User: " $1 " PASS_MIN_DAYS: " $4}' /etc/shadow)

[[ -n "$check" && "$check" -ne 0 && -z "$d2" ]] && e="PASS" || e="FAIL"

d="$d1

$d2"

f="
Edit /etc/login.defs and set PASS_MIN_DAYS to a value > 0 that follows local site policy:
Example: PASS_MIN_DAYS 1

Run the following command to modify user parameters for all users with a password set
to a minimum days greater than zero that follows local site policy:

# chage --mindays <N> <user>"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.4.1.3 Ensure password expiration warning days is configured"

b="
The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify
users that their password will expire in a defined number of days.

PASS_WARN_AGE <N> - The number of days warning given before a password expires. A
zero means warning is given only upon the day of expiration, a negative value means
no warning is given. If not specified, no warning will be provided.

Rationale:

Providing an advance warning that a password will be expiring gives users time to think
of a secure password. Users caught unaware may choose a simple password or write it
down where it may be discovered."

c='
Verify PASS_WARN_AGE is 7 or more for all 
passowrds and follows local site policy'

d1=$( grep -Pi -- '^\h*PASS_WARN_AGE\h+\d+\b' /etc/login.defs )

check=$(echo "$d1" | awk '{print $2}')

d2=$(awk -F: '($2~/^\$.+\$/) {if($6 < 7)print "User: " $1 " PASS_WARN_AGE: " $6}' /etc/shadow)

[[ -n "$check" && "$check" -ge 7 && "$check" -ne 0 && -z "$d2" ]] && e="PASS" || e="FAIL"

d="$d1

$d2"

f='
Edit /etc/login.defs and set PASS_WARN_AGE to a value of 7 or more:

Example: PASS_WARN_AGE 7

Run the following command to modify user parameters for all users with a password set
to a minimum warning to 7 or more days that follows local site policy:

# chage --warndays <N> <user>'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.4.1.4 Ensure strong password hashing algorithm is configured"

b='
A cryptographic hash function converts an arbitrary-length input into a fixed length
output. Password hashing performs a one-way transformation of a password, turning
the password into another string, called the hashed password.
ENCRYPT_METHOD (string) - This defines the system default encryption algorithm for
encrypting passwords (if no algorithm are specified on the command line).

Rationale:

The SHA-512 and yescrypt algorithms provide a stronger hash than other algorithms
used by Linux for password hash generation. A stronger hash provides additional
protection to the system by increasing the level of effort needed for an attacker to
successfully determine local group passwords.'

c='
ENCRYPT_METHOD SHA512
       (or)
ENCRYPT_METHOD YESCRYPT'

d=$( grep -Pi -- '^\h*ENCRYPT_METHOD\h+(SHA512|yescrypt)\b' /etc/login.defs )

echo "$d" | grep -qE "SHA512|YESCRYPT" && e="PASS" || e="FAIL"

f='
Edit /etc/login.defs and set the ENCRYPT_METHOD

ENCRYPT_METHOD SHA512 (or) YESCRYPT'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.4.1.5 Ensure inactive password lock is configured"

b='
Inactive user accounts for over a given period of time can be automatically disabled.
INACTIVE - Defines the number of days after the password exceeded its maximum age
where the user is expected to replace this password.
The value is stored in the shadow password file. An input of 0 will disable an expired
password with no delay. An input of -1 will blank the respective field in the shadow
password file.

Rationale:

Inactive accounts pose a threat to system security since the users are not logging in to
notice failed login attempts or other anomalies.'

c='
Verify all users with a password have
Password inactive no more than 45 days
after password expires'

d1=$( useradd -D | grep INACTIVE )

check=$(echo "$d1" | awk '{print $2}')

d2=$(awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print "User: " $1 " INACTIVE:" $7}' /etc/shadow)

[[ -n "$check" && "$check" -le 45 && "$check" -ne 0 && -z "$d2" ]] && e="PASS" || e="FAIL"

d="$d1

$d2"

f='
Run the following command to set the default password inactivity period to 45 days or
less that meets local site policy:
# useradd -D -f (≤45)

Run the following command to modify user parameters for all users with a password set
to a inactive age of 45 days or less that follows local site policy:

# chage --inactive <No.of days> <user name>'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.4.1.6 Ensure all users last password change date is in the past"

#no output

b="
All users should have a password change date in the past.
If a user's recorded password change date is in the future,
then they could bypass any set password expiration."

c='All users have a password change date in the past'

check=$(

while IFS= read -r l_user; do
    l_change=$(date -d "$(chage --list "$l_user" | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')" +%s) && \
    [[ "$l_change" -gt "$(date +%s)" ]] && \
    echo "User: \"$l_user\" last password change was \"$(chage --list "$l_user" | grep '^Last password change' | cut -d: -f2)\""
done < <(awk -F: '$2~/^\$.+\$/{print $1}' /etc/shadow)

)

[ -z "$check" ] && { d="All users have a password change date in the past"; e="PASS"; } || { d="A number of users does not have a password change date in the past"; e="FAIL"; }

f="
Review any users with a password change date in the future and rectify them by
locking the account, expiring the password, or resetting the password manually"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.4.2.1 Ensure root is the only UID 0 account "

b="
Any account with UID 0 has superuser privileges on the system.

Rationale:

This access must be limited to only the default root account and only from the system
console. Administrative access must be through an unprivileged account using an
approved mechanism as noted in Item 5.6 Ensure access to the su command is restricted."

c='Verify that only root is returned'

d=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)

[ "$d" == "root" ] && e="PASS" || e="FAIL"

f='
Run the following command to change the root account UID to 0:
# usermod -u 0 root
Modify any users other than root with UID 0 and assign them a new UID.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.4.2.2 Ensure root is the only GID 0 account"

b='
The usermod command can be used to specify which group the root account belongs
to. This affects permissions of files that are created by the root account.

Rationale:

Using GID 0 for the root account helps prevent root -owned files from accidentally
becoming accessible to non-privileged users.'

c='root:0'

d=$(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print $1":"$4}' /etc/passwd)

[ "$d" == "root:0" ] && e="PASS" || e="FAIL"

f="
Run the following command to set the root user's GID to 0:
# usermod -g 0 root

Run the following command to set the root group's GID to 0:
# groupmod -g 0 root

Remove any users other than the root user with GID 0 or
assign them a new GID if appropriate."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.4.2.3 Ensure group root is the only GID 0 group "

b='
The groupmod command can be used to specify which group the root group belongs
to. This affects permissions of files that are group owned by the root group.

Rationale:

Using GID 0 for the root group helps prevent root group owned files from accidentally
becoming accessible to non-privileged users.'

c='Verify no group other than root is assigned GID 0'

d=$(awk -F: '$3=="0"{print $1":"$3}' /etc/group)

[ "$d" == "root:0" ] && e="PASS" || e="FAIL"

f="
Run the following command to set the root group's GID to 0:
# groupmod -g 0 root
Remove any groups other than the root group with GID 0 or
assign them a new GID if appropriate."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.4.2.4 Ensure root account access is controlled"

b='
There are a number of methods to access the root account directly. Without a password
set any user would be able to gain access and thus control over the entire system.
Rationale: Access to root should be secured at all times.

Note: If there are any automated processes that relies on access to the root
account without authentication, they will fail after remediation.'

c="
User: "root" Password is status: P
             (or)
User: "root" Password is status: L

Note:
P - Password is set
L - Password is locked"

d1=$(passwd -S root | awk '$2 ~ /^(P|L)/ {print "User: \"" $1 "\" Password is status: " $2}')

check=$(echo "$d1" | awk '{print $6}')

[[ "$check" == "P" || "$check" == "L" ]] && e="PASS" || e="FAIL"

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

f='
Run the following command to set a password for the root user:
# passwd root

Run the following command to lock the root user account:
# usermod -L root'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.4.2.5 Ensure root path integrity"

b="
The root user can execute any command on the system and could be fooled into
executing programs unintentionally if the PATH is not set correctly.

Rationale:

Including the current working directory (.) or other writable directory in root's
executable path makes it likely that an attacker can gain superuser access by forcing an
administrator operating as root to execute a Trojan horse program."

c="Root's path is correctly configured"

d1=$(

{
    l_output2=""
    l_pmask="0022"
    l_maxperm="$(printf '%o' $(( 0777 & ~$l_pmask )))"
    l_root_path="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
    unset a_path_loc && IFS=":" read -ra a_path_loc <<< "$l_root_path"

    grep -q "::" <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains an empty directory (::)"
    grep -Pq ":\h*$" <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains a trailing (:)"
    grep -Pq '(\h+|:)\.(:|\h*$)' <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains current working directory (.)"

    while read -r l_path; do
        [ -d "$l_path" ] && {
            while read -r l_fmode l_fown; do
                [ "$l_fown" != "root" ] && l_output2="$l_output2\n - Directory: \"$l_path\" is owned by: \"$l_fown\"; should be owned by \"root\""
                [ $(( $l_fmode & $l_pmask )) -gt 0 ] && l_output2="$l_output2\n - Directory: \"$l_path\" is mode: \"$l_fmode\"; should be mode: \"$l_maxperm\" or more restrictive"
            done <<< "$(stat -Lc '%#a %U' "$l_path")"
        } || l_output2="$l_output2\n - \"$l_path\" is not a directory"
    done <<< "$(printf "%s\n" "${a_path_loc[@]}")"

    [ -z "$l_output2" ] && echo -e "\n- Audit Result:\n *** PASS ***\n - Root's path is correctly configured\n" || \
    echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n"
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f='
Correct or justify any:
• Locations that are not directories
• Empty directories (::)
• Trailing (:)
• Current working directory (.)
• Non root owned directories
• Directories that less restrictive than mode 0755'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.4.2.6 Ensure root user umask is configured "

#no output 

b='
The user file-creation mode mask (umask) is used to determine the file permission for
newly created directories and files.
In Linux, the default permissions for any newly created directory is 0777 (rwxrwxrwx),
and for any newly created file it is 0666 (rw-rw-rw-).
The umask modifies the default Linux permissions by restricting these permissions.

Rationale:

Setting a secure value for umask ensures that users make a conscious choice about
their file permissions. A permissive umask value could result in directories or files with
excessive permissions that can be read and/or written to by unauthorized users.'

c="umask is configured"

check=$(grep -Psi -- '^\h*umask\h+(([0-7][0-7][0-7][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][0-7][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc)

[ -z "$check" ] && { d="umask is configured"; e="PASS"; } || { d="umask is not configured"; e="FAIL"; }

f='
Edit /root/.bash_profile and /root/.bashrc and remove, comment out,
or update any line with umask to be 0027 or more restrictive.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.4.2.7 Ensure system accounts do not have a valid login shell"

#no output

b="
There are a number of accounts provided with most distributions that are used to
manage applications and are not intended to provide an interactive shell. Furthermore,
a user may add special accounts that are not intended to provide an interactive shell.

Rationale:

It is important to make sure that accounts that are not being used by regular users are
prevented from being used to provide an interactive shell. By default, most distributions
set the password field for these accounts to an invalid string, but it is also recommended
that the shell field in the password file be set to the nologin shell. This prevents the
account from potentially being used to run any commands."

c="
system accounts, except for root, halt, sync,
shutdown or nfsnobody, do not have a valid login shell"

check=$(
    l_valid_shells="^($(awk -F/ '$NF != \"nologin\" {print}' /etc/shells | 
    sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|'))$"

    awk -v pat="$l_valid_shells" -F: '
    ($1 !~ /^(root|halt|sync|shutdown|nfsnobody)$/ && 
     ($3 < uid_min || $3 == 65534) && 
     $(NF) ~ pat)
    {print "Service account: \"" $1 "\" has a valid shell: " $7}' uid_min="$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)" /etc/passwd
)

[ -z "$check" ] && { d="System accounts, except for root, halt, sync,
shutdown or nfsnobody, do not have a valid login shell"; e="PASS"; } || { d="All system accounts have a valid login shell"; e="FAIL"; }

f='
Run the following command to set the shell for any
service accounts returned by the audit to nologin:

# usermod -s $(command -v nologin) <user>'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.4.2.8 Ensure accounts without a valid login shell are locked"

#no output

b="
There are a number of accounts provided with most distributions that are used to
manage applications and are not intended to provide an interactive shell. Furthermore,
a user may add special accounts that are not intended to provide an interactive shell.

Rationale:

It is important to make sure that accounts that are not being used by regular users are
prevented from being used to provide an interactive shell. By default, most distributions
set the password field for these accounts to an invalid string, but it is also recommended
that the shell field in the password file be set to the nologin shell. This prevents the
account from potentially being used to run any commands."

c="
All non-root accounts without a
valid login shell are locked."

check=$(
    l_valid_shells="^($(awk -F/ '$NF != \"nologin\" {print}' /etc/shells | 
    sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|'))$"

    while IFS= read -r l_user; do
        passwd -S "$l_user" | awk '$2 !~ /^L/ {print "Account: \"" $1 "\" does not have a valid login shell and is not locked"}'
    done < <(awk -v pat="$l_valid_shells" -F: '($1 != "root" && $(NF) !~ pat) {print $1}' /etc/passwd)
)

[ -z "$check" ] && { d="All non-root accounts without a valid login shell are locked."; e="PASS"; } || { d="Failed to lock"; e="FAIL"; }

f='
Run the following command to lock any non-root accounts
without a valid login shell returned by the audit:

# usermod -L <user>'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.4.3.1 Ensure nologin is not listed in /etc/shells "

#no output

b="
/etc/shells is a text file which contains the full pathnames of valid login shells. This
file is consulted by chsh and available to be queried by other programs.
Be aware that there are programs which consult this file to find out if a user is a normal
user; for example, FTP daemons traditionally disallow access to users with shells not
included in this file.

Rationale:

A user can use chsh to change their configured shell.
If a user has a shell configured that isn't in in /etc/shells, then the system assumes
that they're somehow restricted.
In the case of chsh it means that the user cannot change that value."

c="nologin is not listed in the /etc/shells file"

check=$(grep -Ps '^\h*([^#\n\r]+)?\/nologin\b' /etc/shells)

[ -z "$check" ] && { d="nologin is not listed in the /etc/shells file"; e="PASS"; } || { d="nologin is listed in the /etc/shells file"; e="FAIL"; }

f='Edit /etc/shells and remove any lines that include nologin'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="5.4.3.2 Ensure default user shell timeout is configured "

b="
TMOUT is an environmental setting that determines the timeout of a shell in seconds.
• TMOUT=n - Sets the shell timeout to n seconds. A setting of TMOUT=0 disables
timeout.
• readonly TMOUT- Sets the TMOUT environmental variable as readonly,
preventing unwanted modification during run-time.
• export TMOUT - exports the TMOUT variable

Rationale:

Setting a timeout value reduces the window of opportunity for unauthorized user access
to another user's shell session that has been left unattended. It also ends the inactive
session and releases the resources associated with that session."

c='TMOUT is configured'

d1=$(

output1="" 
output2=""

[ -f /etc/bashrc ] && BRC="/etc/bashrc"

for f in "$BRC" /etc/profile /etc/profile.d/*.sh; do
    grep -Pq '^\s*([^#]+\s+)?TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' "$f" && \
    grep -Pq '^\s*([^#]+;\s*)?readonly\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' "$f" && \
    grep -Pq '^\s*([^#]+;\s*)?export\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' "$f" && \
    output1="$f"
done

grep -Pq '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh "$BRC" && \
output2=$(grep -Ps '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh "$BRC")

[ -n "$output1" ] && [ -z "$output2" ] && echo -e "\nPASSED\n\nTMOUT is configured in: \"$output1\"\n" || {
    [ -z "$output1" ] && echo -e "\nFAILED\n\nTMOUT is not configured\n"
    [ -n "$output2" ] && echo -e "\nFAILED\n\nTMOUT is incorrectly configured in: \"$output2\"\n"
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASSED" && e="PASS" || e="FAIL"

f="
Review /etc/bashrc, /etc/profile, and all files ending in *.sh in the
/etc/profile.d/ directory and remove or edit all TMOUT=_n_ entries to
follow local site policy. TMOUT should not exceed 900 or be equal to 0.

Configure TMOUT in one of the following files:
• A file in the /etc/profile.d/ directory ending in .sh
• /etc/profile
• /etc/bashrc
TMOUT configuration examples:

• As multiple lines:
TMOUT=900
readonly TMOUT
export TMOUT

• As a single line:
readonly TMOUT=900 ; export TMOUT"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="5.4.3.3 Ensure default user umask is configured "

b='
Setting a secure default value for umask ensures that users make a conscious choice
about their file permissions. A permissive umask value could result in directories or files
with excessive permissions that can be read and/or written to by unauthorized users.'

c='Correctly configured'

d1=$(
{
    l_output="" 
    l_output2=""

    file_umask_chk() {
        grep -Psiq -- '^\h*umask\h+(0?[0-7][2-7]7|u(=[rwx]{0,3}),g=([rx]{0,2}),o=)(\h*#.*)?$' "$l_file" && \
            l_output="$l_output\n - umask is set correctly in \"$l_file\"" || \
        grep -Psiq -- '^\h*umask\h+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' "$l_file" && \
            l_output2="$l_output2\n - umask is incorrectly set in \"$l_file\""
    }

    while IFS= read -r -d $'\0' l_file; do
        file_umask_chk
    done < <(find /etc/profile.d/ -type f -name '*.sh' -print0)

    [ -z "$l_output" ] && l_file="/etc/profile" && file_umask_chk
    [ -z "$l_output" ] && l_file="/etc/bashrc" && file_umask_chk
    [ -z "$l_output" ] && l_file="/etc/bash.bashrc" && file_umask_chk
    [ -z "$l_output" ] && l_file="/etc/pam.d/postlogin"

    [ -z "$l_output" ] && {
        grep -Psiq -- '^\h*session\h+[^#\n\r]+\h+pam_umask\.so\h+([^#\n\r]+\h+)?umask=(0?[0-7][2-7]7)\b' "$l_file" && \
            l_output1="$l_output1\n - umask is set correctly in \"$l_file\"" || \
        grep -Psiq '^\h*session\h+[^#\n\r]+\h+pam_umask\.so\h+([^#\n\r]+\h+)?umask=(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b))' "$l_file" && \
            l_output2="$l_output2\n - umask is incorrectly set in \"$l_file\""
    }

    [ -z "$l_output" ] && l_file="/etc/login.defs" && file_umask_chk
    [ -z "$l_output" ] && l_file="/etc/default/login" && file_umask_chk

    [[ -z "$l_output" && -z "$l_output2" ]] && l_output2="$l_output2\n - umask is not set"

    [ -z "$l_output2" ] && echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured *:\n$l_output\n" || {
        echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure *:\n$l_output2"
        [ -n "$l_output" ] && echo -e "\n- * Correctly configured *:\n$l_output\n"
    }
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f="
Set the default umask for all users, you can modify the global configuration files.
Common files include:

For Bash: Edit /etc/profile or add to /etc/profile.d/custom.sh:
umask 027

For Other Shells: Look for /etc/login.defs or relevant files in /etc/profile.d/."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.1.1 Ensure journald service is configured "

b='
Ensure that the systemd-journald service is enabled, 
if the service is not enabled to start on boot,
the system will not capture logging events.'

c='static

active'

d1=$(systemctl is-enabled systemd-journald.service)
d2=$(systemctl is-active systemd-journald.service)

[[ "$d1" == "static" ]] && \
[[ "$d2" == "active" ]] && e="PASS" || e="FAIL"

d="$d1

$d2"

f='
Run the following commands to unmask and start systemd-journald.service

# systemctl unmask systemd-journald.service
# systemctl start systemd-journald.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.1.4 Ensure only one logging system is in use"

b='
It is recommended that a single centralized logging system be used for log
management, choose a single service either rsyslog or journald to be used as a
single centralized logging system.

Rationale:
Configuring only one logging service either rsyslog or journald avoids
redundancy, optimizes resources, simplifies configuration and management, and
ensures consistency.

Note: Transitioning from one logging service to another can be complex and time consuming,
it involves reconfiguration and may result in data loss if not managed and reconfigured properly.'

c="
(rsyslog or journald)  is in use
follow the recommendations in Configure (rsyslog or journald) subsection only"

d1=$(
l_output=""
l_output2=""

systemctl is-active --quiet rsyslog && l_output="$l_output\n - rsyslog is in use\n- follow the recommendations in Configure rsyslog subsection only" ||
systemctl is-active --quiet systemd-journald && l_output="$l_output\n - journald is in use\n- follow the recommendations in Configure journald subsection only" ||
{
    echo -e "unable to determine system logging"
    l_output2="$l_output2\n - unable to determine system logging\n- Configure only ONE system logging: rsyslog OR journald"
}

[ -z "$l_output2" ] && echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n" || echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2"

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f='
1. Determine whether to use journald or rsyslog depending on site needs
2. Configure systemd-jounald.service
3. Configure only ONE either journald or rsyslog and complete the recommendations
4. Return to this recommendation to ensure only one logging system is in use'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.2.1.1 Ensure systemd-journal-remote is installed"

b='
journald systemd-journal-remote supports the ability to send log events it gathers to
a remote log host or to receive messages from remote hosts, thus enabling centralized log management.

Rationale:

Storing log data on a remote host protects log integrity from local attacks.
If an attacker gains root access on the local system, they could tamper with or
remove log data that is stored on the local system.'

c="systemd-journal-remote is installed"

d=$( dpkg-query -s systemd-journal-remote &>/dev/null && echo "$c" || echo "systemd-journal-remote is not installed" )

[ "$d" == "$c" ] && e="PASS" || e="FAIL"

f='
Run the following command to install systemd-journal-remote:

# apt install systemd-journal-remote'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="6.1.2.1.3 Ensure systemd-journal-upload is configured"

b='
It supports the ability to send log events it gathers to a remote log host.

Rationale:

Storing log data on a remote host protects log integrity from local attacks.
If an attacker gains root access on the local system, they could tamper with
or remove log data that is stored on the local system.'

c='
enabled

active'

d1=$(systemctl is-enabled systemd-journal-upload.service 2>&1)
d2=$(systemctl is-active systemd-journal-upload.service 2>&1)

[[ "$d1" == "enabled" ]] && \
[[ "$d2" == "active" ]] && e="PASS" || e="FAIL"

d="$d1

$d2"

f='
Run the following commands to unmask, enable and start systemd-journal-upload:

# systemctl unmask systemd-journal-upload.service
# systemctl --now enable systemd-journal-upload.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.2.1.4 Ensure systemd-journal-remote service is not in use"

#no output

b="
journald systemd-journal-remote supports the ability to receive messages from
remote hosts, thus acting as a log server. Clients should not receive data from other hosts.

Rationale:

If a client is configured to also receive data, thus turning it into a server, the client
system is acting outside it's operational boundary.'"

c='Disabled and Inactive'

check1=$(systemctl is-enabled systemd-journal-remote.socket systemd-journal-remote.service | grep -P -- '^enabled')

check2=$( systemctl is-active systemd-journal-remote.socket systemd-journal-remote.service | grep -P -- '^active')

[[ -z "$check1" && -z "$check2"  ]] && { d="Disabled and Inactive"; e="PASS"; } || { d="Enabled and Active"; e="FAIL"; }

f='
Run the following commands to stop and mask
systemd-journal-remote.socket and systemd-journal-remote.service:

# systemctl stop systemd-journal-remote.socket systemd-journal-remote.service
# systemctl mask systemd-journal-remote.socket systemd-journal-remote.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.2.2 Ensure journald ForwardToSyslog is disabled "

b='
Data from journald should be kept in the confines and not forwarded to other services.

Rationale:

If journald is the method for capturing logs, all logs of the system should be
handled by journald and not forwarded to other logging mechanisms.'

c="#ForwardToSyslog=no"

d=$(grep -E '^\s*#?\s*ForwardToSyslog' /etc/systemd/journald.conf)

[[ "$d" == "#ForwardToSyslog=no" ]] && e="PASS" || e="FAIL"

f='
Set the following parameter in the [Journal] section in
/etc/systemd/journald.conf or a file in
/etc/systemd/journald.conf.d/ ending in .conf:

ForwardToSyslog=no'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.2.3 Ensure journald Compress is configured"

b='
The journald system includes the capability of compressing overly large files to avoid
filling up the system with logs or making the logs unmanageably large.

Rationale:

Uncompressed large files may unexpectedly fill a filesystem leading to resource
unavailability. Compressing logs prior to write can prevent sudden, unexpected
filesystem impacts'

c='#Compress=yes'

d=$(grep -E '^\s*#?\s*Compress' /etc/systemd/journald.conf)

[[ "$d" == "#Compress=yes" ]] && e="PASS" || e="FAIL"

f='
Set the following parameter in the [Journal] section in
/etc/systemd/journald.conf or 
file in /etc/systemd/journald.conf.d/ ending in .conf:

Compress=yes'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.2.4 Ensure journald Storage is configured"

b='
Data from journald may be stored in volatile memory or persisted locally on the server.
Logs in memory will be lost upon a system reboot. By persisting logs to local disk on the
server they are protected from loss due to a reboot.

Rationale:

Writing log data to disk will provide the ability to forensically reconstruct events which
may have impacted the operations or security of a system even after a system crash or reboot.'

c='#Storage=persistent'

d=$(grep -E '^\s*#?\s*Storage' /etc/systemd/journald.conf)

[[ "$d" == "#Storage=persistent" ]] && e="PASS" || e="FAIL"

f='
Set the following parameter in the [Journal] section in
/etc/systemd/journald.conf or a file in /etc/systemd/journald.conf.d/ 
ending in .conf:

Storage=persistent'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.3.1 Ensure rsyslog is installed"

b='
The rsyslog software is recommended in environments where journald does not
meet operation requirements.

Rationale:

The security enhancements of rsyslog such as connection-oriented (i.e. TCP)
transmission of logs, the option to log to database formats, and the encryption of log
data en route to a central logging server) justify installing and configuring the package.'

c="rsyslog is installed"

d=$( dpkg-query -s rsyslog &>/dev/null && echo "rsyslog is installed" || echo "rsyslog is not installed" )

[[ "$d" == *"rsyslog is installed"* ]] && e="PASS" || e="FAIL"

f='
Run the following command to install rsyslog:

# apt install rsyslog'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.3.2 Ensure rsyslog service is configured"

b='
Ensure that the service is enabled,
if the service is not enabled to start on boot,
the system will not capture logging events'

c='enabled

active'

d1=$(systemctl is-enabled rsyslog)
d2=$(systemctl is-active rsyslog.service)

[[ "$d1" == "enabled" ]] && \
[[ "$d2" == "active" ]] && e="PASS" || e="FAIL"

d="$d1

$d2"

f='
If rsyslog is being used for logging on the system:
Run the following commands to unmask, enable, and start rsyslog.service:

# systemctl unmask rsyslog.service
# systemctl enable rsyslog.service
# systemctl start rsyslog.service'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.3.3 Ensure journald is configured to send logs to rsyslog"

b='
Data from systemd-journald may be stored in volatile memory or persisted locally on
the server. Utilities exist to accept remote export of systemd-journald logs, however,
use of the rsyslog service provides a consistent means of log collection and export.

Rationale:

If rsyslog is the preferred method for capturing logs, all logs of the system should
be sent to it for further processing'

c='#ForwardToSyslog=yes'

d=$(grep -E '^\s*#?\s*ForwardToSyslog' /etc/systemd/journald.conf )

[[ "$d" == "#ForwardToSyslog=yes" ]] && e="PASS" || e="FAIL"

f='
Set the following parameter in the [Journal] section in
/etc/systemd/journald.conf or a file in /etc/systemd/journald.conf.d/
ending in .conf:

ForwardToSyslog=yes'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.3.4 Ensure rsyslog log file creation mode is configured"

b='
Rsyslog will create logfiles that do not already exist on the system.
The legacy $FileCreateMode parameter allows the setting of the mode with which
rsyslogd creates new files. If not specified, the value 0644 is used.

It is important to ensure that log files have the correct permissions to ensure that
sensitive data is archived and protected.'

c='$FileCreateMode ≤0640'

d=$(grep -E '^\$FileCreateMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf )

check=$(echo "$d" | awk '{print $2}')

[[ "$check" -le 0640 && -n "$check" && "$check" -ne 0 ]] && e="PASS" || e="FAIL"

f='
Edit either /etc/rsyslog.conf or a dedicated .conf file in /etc/rsyslog.d/ and set

$FileCreateMode (0640 or more restrictive)'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.3.7 Ensure rsyslog is not configured to receive logs from a remote client "

b="
rsyslog supports the ability to receive messages from remote hosts, thus acting as a
log server. Clients should not receive data from other hosts.

Rationale:

If a client is configured to also receive data, thus turning it into a server, the client
system is acting outside its operational boundary."

c='No entries to accept incoming logs found'

d1=$(

# Initialize output array
a_output2=()
l_analyze_cmd="$(readlink -f /bin/systemd-analyze)"
l_include='\$IncludeConfig'
a_config_files=("rsyslog.conf")

# Gather included configuration files
while IFS= read -r l_file; do
    l_conf_loc="$(awk '$1~/^\s*'"$l_include"'$/ {print $2}' "$(tr -d '# ' <<< "$l_file")" | tail -n 1)"
    [ -n "$l_conf_loc" ] && break
done < <($l_analyze_cmd cat-config "${a_config_files[@]}" | tac | grep -Pio '^\h*#\h*\/[^#\n\r\h]+\.conf\b')

# Determine if config is a directory or a specific file
[ -d "$l_conf_loc" ] && { l_dir="$l_conf_loc"; l_ext="*"; } || {
    grep -Psq '\/\*\.([^#/\n\r]+)?\h*$' <<< "$l_conf_loc" && { l_dir="$(dirname "$l_conf_loc")"; l_ext="$(basename "$l_conf_loc")"; } || {
        [ -f "$(readlink -f "$l_conf_loc")" ] && { l_dir="$(dirname "$l_conf_loc")"; l_ext="$(basename "$l_conf_loc")"; }
    }
}

# Find configuration files
while IFS= read -r -d $'\0' l_file_name; do
    [ -f "$(readlink -f "$l_file_name")" ] && a_config_files+=("$(readlink -f "$l_file_name")")
done < <(find -L "$l_dir" -type f -name "$l_ext" -print0 2>/dev/null)

# Audit for imtcp entries
for l_logfile in "${a_config_files[@]}"; do
    for entry in "module(load=\"?imtcp\"?)" "input(type=\"?imtcp\"?)"; do
        l_fail="$(grep -Psi -- "^\h*$entry" "$l_logfile")"
        [ -n "$l_fail" ] && a_output2+=("- Found entry for incoming logs: \"$l_fail\"" "in: \"$l_logfile\"")
    done
done

# Output results
{ [ "${#a_output2[@]}" -le "0" ] && printf '%s\n' "" "- Audit Result:" " ** PASS **" " - No entries to accept incoming logs found"; } || {
    printf '%s\n' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f="
Unless the system's primary function is to serve as a logfile server , modify the files
returned by the Audit Procedure and remove the specific lines highlighted by the audit.
Verify none of the following entries are present in the rsyslog configuration.

advanced format
module(load="imtcp")
input(type="imtcp" port="514")

deprecated legacy format
ModLoad imtcp
InputTCPServerRun

Reload the service:
# systemctl reload-or-restart rsyslog"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.1.4.1 Ensure access to all logfiles has been configured"

b='
Log files contain information from many services on the the local system, or in the event
of a centralized log server, others systems logs as well.
In general log files are found in /var/log/, although application can be configured to
store logs elsewhere. Should your application store logs in another, ensure to run the
same test on that location.

Rationale:

It is important that log files have the correct permissions to ensure that sensitive data is
protected and that only the appropriate users / groups have access to them.'

c1='All files in \"/var/log/\" have appropriate permissions and ownership'

d1=$(

a_output=()
a_output2=()

f_file_test_chk() {
    a_out2=()
    maxperm="$(printf '%o' $((0777 & ~$perm_mask)))"
    
    # Check file permissions and ownership
    [ $((l_mode & perm_mask)) -gt 0 ] && \
    a_out2+=(" o Mode: \"$l_mode\" should be \"$maxperm\" or more restrictive")
    
    [[ ! "$l_user" =~ $l_auser ]] && \
    a_out2+=(" o Owned by: \"$l_user\" and should be owned by \"${l_auser//|/ or }\"")
    
    [[ ! "$l_group" =~ $l_agroup ]] && \
    a_out2+=(" o Group owned by: \"$l_group\" and should be group owned by \"${l_agroup//|/ or }\"")
    
    [ "${#a_out2[@]}" -gt 0 ] && a_output2+=(" - File: \"$l_fname\" is:" "${a_out2[@]}")
}

# Find and process log files
while IFS= read -r -d $'\0' l_file; do
    while IFS=: read -r l_fname l_mode l_user l_group; do
        # Check file conditions based on path or name
        grep -Pq -- '\/(apt)\h*$' <<< "$(dirname "$l_fname")" && {
            perm_mask='0133'
            l_auser="root"
            l_agroup="(root|adm)"
        } || {
            case "$(basename "$l_fname")" in
                lastlog | lastlog.* | wtmp | wtmp.* | wtmp-* | btmp | btmp.* | btmp-*)
                    perm_mask='0113'
                    l_auser="root"
                    l_agroup="(root|utmp)" ;;
                cloud-init.log* | localmessages* | waagent.log*)
                    perm_mask='0133'
                    l_auser="(root|syslog)"
                    l_agroup="(root|adm)" ;;
                secure{,*.*,.*,-*} | auth.log | syslog | messages)
                    perm_mask='0137'
                    l_auser="(root|syslog)"
                    l_agroup="(root|adm)" ;;
                SSSD | sssd)
                    perm_mask='0117'
                    l_auser="(root|SSSD)"
                    l_agroup="(root|SSSD)" ;;
                gdm | gdm3)
                    perm_mask='0117'
                    l_auser="root"
                    l_agroup="(root|gdm|gdm3)" ;;
                *.journal | *.journal~)
                    perm_mask='0137'
                    l_auser="root"
                    l_agroup="(root|systemd-journal)" ;;
                *)
                    perm_mask='0137'
                    l_auser="(root|syslog)"
                    l_agroup="(root|adm)"
                    
                    # Additional ownership checks
                    ([ "$l_user" = "root" ] || ! grep -q -- "^\h*$(awk -F: -v user="$l_user" '$1==user {print $7}' /etc/passwd)\b" /etc/shells) && {
                        ! grep -q -- "$l_auser" <<< "$l_user" && l_auser="(root|syslog|$l_user)"
                        ! grep -q -- "$l_agroup" <<< "$l_group" && l_agroup="(root|adm|$l_group)"
                    }
                    ;;
            esac
        }
        f_file_test_chk
    done < <(stat -Lc '%n:%#a:%U:%G' "$l_file")
done < <(find -L /var/log -type f \( -perm /0137 -o ! -user root -o ! -group root \) -print0)

# Final audit result
([ "${#a_output2[@]}" -le 0 ] && {
    a_output+=(" - All files in \"/var/log/\" have appropriate permissions and ownership")
    printf '\n%s' "- Audit Result:" " ** PASS **" "${a_output[@]}" ""
}) || {
    printf '\n%s' "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:"
    printf '%s\n' "${a_output2[@]}"
}

)

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f1='
Run the following commands to set permissions on all existing log files:
find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-wx,o-rwx "{}" +

Note: The configuration for your logging software or services may need to also be modified for
any logs that had incorrect permissions, otherwise, the permissions may be reverted to the
incorrect permissions'

c=$(printf "%s\n" "$c1" | sed 's/"/""/g')

d=$(printf "%s\n" "$d1" | sed 's/"/""/g')

f=$(printf "%s\n" "$f1" | sed 's/"/""/g')

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.1.1 Ensure auditd packages are installed "

b="
auditd is the userspace component to the Linux Auditing System. It's responsible for
writing audit records to the disk

Rationale:

The capturing of system events provides system administrators with information to allow
them to determine if unauthorized access to their system is occurring."

c='auditd is installed

audispd-plugins is installed'

d1=$(dpkg-query -s auditd &>/dev/null && echo auditd is installed || echo auditd is not installed) 
d2=$(dpkg-query -s audispd-plugins &>/dev/null && echo audispd-plugins is installed || echo audispd-plugins is not installed)

[[ "$d1" == "auditd is installed" ]] && \
[[ "$d2" == "audispd-plugins is installed" ]] && e="PASS" || e="FAIL"

d="$d1

$d2"

f='
Run the following command to Install auditd and audispd-plugins

# apt install auditd audispd-plugins'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.1.2 Ensure auditd service is enabled and active "

b="
Turn on the auditd daemon to record system events.The capturing of system events
provides system administrators with information to allow them to determine 
if unauthorized access to their system is occurring."

c='enabled

active'

d1=$(systemctl is-enabled auditd | grep '^enabled' 2>&1)
d2=$( systemctl is-active auditd | grep '^active' 2>&1)

[[ "$d1" == "enabled" ]] && \
[[ "$d2" == "active" ]] && e="PASS" || e="FAIL"

d="$d1

$d2"

f='
Run the following commands to unmask, enable and start auditd:

# systemctl unmask auditd
# systemctl enable auditd
# systemctl start auditd'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.1.3 Ensure auditing for processes that start prior to auditd is enabled "

b='
Configure grub2 so that processes that are capable of being audited can be audited
even if they start up prior to auditd startup.

Rationale:

Audit events need to be captured on processes that start up prior to auditd , so that
potential malicious activity cannot go undetected.'

c='Enabled'

check=$( find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | grep -v 'audit=1')

[ -z "$check" ] && { d="Enabled"; e="PASS"; } || { d="Disabled"; e="FAIL"; }

f='
Edit /etc/default/grub and add audit=1 after GRUB_CMDLINE_LINUX:

Run the following command to update the grub2 configuration:
# update-grub'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="6.2.1.4 Ensure audit_backlog_limit is sufficient "

b='
In the kernel-level audit subsystem, a socket buffer queue is used to hold audit events.
Whenever a new audit event is received, it is logged and prepared to be added to this queue.
The kernel boot parameter audit_backlog_limit=N, with N representing the amount of
messages, will ensure that a queue cannot grow beyond a certain size. If an audit event
is logged which would grow the queue beyond this limit, then a failure occurs and is
handled according to the system configuration

Rationale:

If an audit event is logged which would grow the queue beyond the
audit_backlog_limit, then a failure occurs, auditd records will be lost, and potential
malicious activity could go undetected'

c='
Review the size of
audit_backlog_limit
with site policy'

d=$( find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | grep -Pv 'audit_backlog_limit=\d+\b')

[ -z "$d" ] && e="PASS" || e="FAIL"

f='
dit /etc/default/grub and add audit_backlog_limit=N after
GRUB_CMDLINE_LINUX. The recommended size for N is 8192 or larger.

Run the following command to update the grub2 configuration:
# update-grub'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="6.2.2.1 Ensure audit log storage size is configured "

b='
Configure the maximum size of the audit log file. Once the log reaches the maximum
size, it will be rotated and a new log file will be started.

Rationale:

It is important that an appropriate size is determined for log files so that they do not
impact the system and audit data is not lost'

c='
Ensure audit log storage size is
in compliance with site policy'

d=$( grep -Po -- '^\h*max_log_file\h*=\h*\d+\b' /etc/audit/auditd.conf 2>&1 )

[[ "$d" == *"max_log_file"* ]] && e="PASS" || e="FAIL"

f='
Set the following parameter in /etc/audit/auditd.conf
in accordance with site policy:

max_log_file = (audit log storage size in MB)'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.2.2 Ensure audit logs are not automatically deleted"

b='
The max_log_file_action setting determines how to handle the audit log file reaching
the max file size. A value of keep_logs will rotate the logs but never delete old logs.

Rationale:

In high security contexts, the benefits of maintaining a long audit history exceed the cost
of storing the audit history.'

c='max_log_file_action = keep_logs'

d=$( grep max_log_file_action /etc/audit/auditd.conf 2>&1 )

[[ "$d" == *"max_log_file_action = keep_logs"* ]] && e="PASS" || e="FAIL"

f='
Set the following parameter in /etc/audit/auditd.conf:

max_log_file_action = keep_logs'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.2.3 Ensure system is disabled when audit logs are full"

b='
The auditd daemon can be configured to halt the system or put the system in single
user mode, if no free space is available or an error is detected on the partition that holds
the audit log files.

The disk_full_action parameter tells the system what action to take when no free
space is available on the partition that holds the audit log files. Valid values are ignore,
syslog, rotate, exec, suspend, single, and halt.

The disk_error_action parameter tells the system what action to take when an error
is detected on the partition that holds the audit log files. Valid values are ignore,
syslog, exec, suspend, single, and halt.'

c='disk_full_action = <halt|single>

disk_error_action = <syslog|single|halt>'

d1=$(grep -Pi -- '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf 2>&1)
d2=$( grep -Pi -- '^\h*disk_error_action\h*=\h*(syslog|single|halt)\b' /etc/audit/auditd.conf 2>&1)

[[ "$d1" == "disk_full_action = <halt|single>" ]] && \
[[ "$d2" == "disk_error_action = <syslog|single|halt>" ]] && e="PASS" || e="FAIL"

d="$d1

$d2"

f='
Set one of the following parameters in /etc/audit/auditd.conf
depending on your local security policies.

disk_full_action = <halt|single>
disk_error_action = <syslog|single|halt>'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.2.4 Ensure system warns when audit logs are low on space"

b='
The auditd daemon can be configured to halt the system, put the system in single user
mode or send a warning message, if the partition that holds the audit log files is low on space.

The space_left_action parameter tells the system what action to take when the
system has detected that it is starting to get low on disk space. Valid values are ignore,
syslog, rotate, email, exec, suspend, single, and halt.

The admin_space_left_action parameter tells the system what action to take when
the system has detected that it is low on disk space. Valid values are ignore, syslog,
rotate, email, exec, suspend, single, and halt.'

c='space_left_action = email|exec|single|halt

admin_space_left_action = single|halt'

d1=$(grep -P -- '^\h*space_left_action\h*=\h*(email|exec|single|halt)\b' /etc/audit/auditd.conf 2>&1)

d2=$(grep -P -- '^\h*admin_space_left_action\h*=\h*(single|halt)\b' /etc/audit/auditd.conf 2>&1)

[[ "$d1" == *"space_left_action"* ]] && \
[[ "$d2" == *"admin_space_left_action"* ]] && e="PASS" || e="FAIL"

d="$d1

$d2"

f='
Set the space_left_action parameter in /etc/audit/auditd.conf to email, exec, single, or halt:
Example:  space_left_action = email

Set the admin_space_left_action parameter in /etc/audit/auditd.conf to
single or halt:
Example:  admin_space_left_action = single

Note: A Mail Transfer Agent (MTA) must be installed and configured properly to set
space_left_action = email'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.1 Ensure changes to system administration scope (sudoers) is collected "

b='
Monitor scope changes for system administrators. If the system has been properly
configured to force system administrators to log in as themselves first and then use the
sudo command to execute privileged commands, it is possible to monitor changes in scope.

The file /etc/sudoers, or files in /etc/sudoers.d, will be written to when the
file(s) or related attributes have changed. The audit records will be tagged with the
identifier "scope".

Rationale:

Changes in the /etc/sudoers and /etc/sudoers.d files can indicate that an
unauthorized change has been made to the scope of system administrator activity.'

c='
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope'

d=$( 
    
awk '/^ *-w/ \
&&/\/etc\/sudoers/ \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>&1 )

[[ "$d" == *"scope"* ]] && e="PASS" || e="FAIL"

f='
Edit or create a file in the /etc/audit/rules.d/ directory,
ending in .rules extension, with the relevant rules to monitor
scope changes for system administrators'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.2 Ensure actions as another user are always logged "

b="
sudo provides users with temporary elevated privileges to perform operations, either as
the superuser or another user.

Rationale:

Creating an audit log of users with temporary elevated privileges and the operation(s)
they performed is essential to reporting.
Administrators will want to correlate the events written to the audit trail with the
records written to sudo's logfile to verify if unauthorized commands have been executed."

c="
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation"

d=$( 
    
awk '/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&(/ -C *euid!=uid/||/ -C *uid!=euid/) \
&&/ -S *execve/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>&1 )

[[ "$d" == *"user_emulation"* ]] && e="PASS" || e="FAIL"

f='
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor elevated privileges'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.3 Ensure events that modify the sudo log file are collected"

b='
Monitor the sudo log file. If the system has been properly configured to disable the use
of the su command and force all administrators to have to log in first and then use sudo
to execute privileged commands, then all administrator commands will be logged to
/var/log/sudo.log . Any time a command is executed, an audit event will be
triggered as the /var/log/sudo.log file will be opened for write and the executed
administration command will be written to the log.

Rationale:

Changes in /var/log/sudo.log indicate that an administrator has executed a
command or the log file itself has been tampered with. Administrators will want to
correlate the events written to the audit trail with the records written to
/var/log/sudo.log to verify if unauthorized commands have been executed.'

c='-w /var/log/sudo.log -p wa -k sudo_log_file'

d=$( 
    
SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g' -e 's|/|\\/|g')
[ -n "${SUDO_LOG_FILE}" ] && awk "/^ *-w/ \
&&/"${SUDO_LOG_FILE}"/ \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
|| printf "ERROR: Variable 'SUDO_LOG_FILE' is unset.\n" 2>&1 )

[[ "$d" == *"sudo_log_file"* ]] && e="PASS" || e="FAIL"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor events that modify the sudo log file."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.4 Ensure events that modify date and time information are collected "

b='
Capture events where the system date and/or time has been modified.
Unexpected changes in system date and/or time could be a
sign of malicious activity on the system'

c='
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change'

d=$( 
    
awk '/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&/ -S/ \
&&(/adjtimex/ \
||/settimeofday/ \
||/clock_settime/ ) \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
awk '/^ *-w/ \
&&/\/etc\/localtime/ \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>&1 )

[[ "$d" == *"adjtimex|settimeofday|clock_settime"* ]] && e="PASS" || e="FAIL"

f="Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor events that modify date and time information."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.5 Ensure events that modify the system's network environment are collected "

b='
Record changes to network environment files or system calls. The below parameters
monitors the following system calls, and write an audit event on system call exit:
• sethostname - set the systems host name
• setdomainname - set the systems domain name
s
The files being monitored are:
• /etc/issue and /etc/issue.net - messages displayed pre-login
• /etc/hosts - file containing host names and associated IP addresses
• /etc/networks - symbolic names for networks
• /etc/network/ - directory containing network interface scripts and
configurations files
• /etc/netplan/ - central location for YAML networking configurations files'

c='
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/netplan -p wa -k system-locale'

d=$( 
    
awk '/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&/ -S/ \
&&(/sethostname/ \
||/setdomainname/) \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
awk '/^ *-w/ \
&&(/\/etc\/issue/ \
||/\/etc\/issue.net/ \
||/\/etc\/hosts/ \
||/\/etc\/network/ \
||/\/etc\/netplan/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>&1 )

[[ "$d" == *"system-locale"* ]] && e="PASS" || e="FAIL"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor events that modify the system's network environment."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.6 Ensure use of privileged commands are collected "

b='
Monitor privileged programs, those that have the setuid and/or setgid bit set on
execution, to determine if unprivileged users are running these commands.

Rationale:

Execution of privileged commands by non-privileged users could be an indication of
someone trying to gain unauthorized access to the system'

c='
(loaded rules) found in auditing rules'

d=$( 

for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk '{print $1}'); do
    for PRIVILEGED in $(find "${PARTITION}" -xdev -perm /6000 -type f); do
        grep -qr "${PRIVILEGED}" /etc/audit/rules.d && \
        printf "PASS: '${PRIVILEGED}' found in auditing rules.\n" || \
        printf "FAIL: '${PRIVILEGED}' not found in on-disk configuration.\n"
    done
done

)

[[ "$d" == *"PASS"* ]] && e="PASS" || e="FAIL"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor the use of privileged commands"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.7 Ensure unsuccessful file access attempts are collected "

b='
Monitor for unsuccessful attempts to access files. The following parameters are
associated with system calls that control files:
• creation - creat
• opening - open , openat
• truncation - truncate , ftruncate

An audit log record will only be written if all of the following criteria is met for the user
when trying to access a file:
• a non-privileged user (auid>=UID_MIN)
• is not a Daemon event (auid=4294967295/unset/-1)
• if the system call returned EACCES (permission denied) or EPERM (some other
permanent error associated with the specific system call)

Rationale:
Failed attempts to open, create or truncate files could be an indication that an individual
or process is trying to gain unauthorized access to the system'

c='
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access'

d=$( 

UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&/ -F *auid>=${UID_MIN}/ \
&&(/ -F *exit=-EACCES/||/ -F *exit=-EPERM/) \
&&/ -S/ \
&&/creat/ \
&&/open/ \
&&/truncate/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n"
 2>&1 )

[[ "$d" == *"ERROR"* ]] && e="FAIL" || e="PASS"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor unsuccessful file access attempts."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.8 Ensure events that modify user/group information are collected "

b='
Record events affecting the modification of user or group information,
including that of passwords and old passwords if in use.
Unexpected changes to these files could be an indication that the system has been
compromised and that an unauthorized user is attempting to hide their activities or
compromise additional accounts'

c='
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity'

d=$( 

awk '/^ *-w/ \
&&(/\/etc\/group/ \
||/\/etc\/passwd/ \
||/\/etc\/gshadow/ \
||/\/etc\/shadow/ \
||/\/etc\/security\/opasswd/ \
||/\/etc\/nsswitch.conf/ \
||/\/etc\/pam.conf/ \
||/\/etc\/pam.d/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>&1)

[[ "$d" == *"identity"* ]] && e="PASS" || e="FAIL"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor events that modify user/group information."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.9 Ensure discretionary access control permission modification events are collected "

b='
Monitor changes to file permissions, attributes, ownership and group. The parameters in
this section track changes for system calls that affect file permissions and attributes.

Monitoring for changes in file attributes could alert a system administrator to activity that
could indicate intruder activity or policy violation.'

c='
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F 
   auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F
   auid>=1000 -F auid!=unset -F key=perm_mod'

d=$( 
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&/ -S/ \
&&/ -F *auid>=${UID_MIN}/ \
&&(/chmod/||/fchmod/||/fchmodat/ \
||/chown/||/fchown/||/fchownat/||/lchown/ \
||/setxattr/||/lsetxattr/||/fsetxattr/ \
||/removexattr/||/lremovexattr/||/fremovexattr/) \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n")

[[ "$d" == *"ERROR"* ]] && e="FAIL" || e="PASS"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor discretionary access control permission modification events."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.10 Ensure successful file system mounts are collected"

b='
Monitor the use of the mount system call. The mount and umount system call
controls the mounting and unmounting of file systems.
The parameters below configure the system to create an audit record when the
mount system call is used by a non-privileged user'

c='
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts'

d=$( 
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&/ -F *auid>=${UID_MIN}/ \
&&/ -S/ \
&&/mount/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n")

[[ "$d" == *"ERROR"* ]] && e="FAIL" || e="PASS"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor successful file system mounts."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.11 Ensure session initiation information is collected"

b="
Monitor session initiation events. The parameters in this section track changes to the
files associated with session events.
• /var/run/utmp - tracks all currently logged in users.
• /var/log/wtmp - file tracks logins, logouts, shutdown, and reboot events.
• /var/log/btmp - keeps track of failed login attempts and can be read by
entering the command /usr/bin/last -f /var/log/btmp.
All audit records will be tagged with the identifier "session."

Rationale:

Monitoring these files for changes could alert a system administrator to logins occurring
at unusual hours, which could indicate intruder activity (i.e. a user logging in at a time
when they do not normally log in)"

c='
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session'

d=$( 
awk '/^ *-w/ \
&&(/\/var\/run\/utmp/ \
||/\/var\/log\/wtmp/ \
||/\/var\/log\/btmp/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>&1 )

[[ "$d" == *"session"* ]] && e="PASS" || e="FAIL"

f='
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor session initiation information.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.12 Ensure login and logout events are collected"

b="
Monitor login and logout events. The parameters below track changes to files
associated with login/logout events.
• /var/log/lastlog - maintain records of the last time a user successfully logged in.
• /var/run/faillock - directory maintain records of login failures via the pam_faillock.

Rationale:

Monitoring login/logout events could provide a system administrator with information
associated with brute force attacks against user logins"

c='
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins'

d=$( 
awk '/^ *-w/ \
&&(/\/var\/log\/lastlog/ \
||/\/var\/run\/faillock/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>&1 )

[[ "$d" == *"logins"* ]] && e="PASS" || e="FAIL"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor login and logout events."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.13 Ensure file deletion events by users are collected"

b='
Monitor the use of system calls associated with the deletion or renaming of files and file
attributes. This configuration statement sets up monitoring for:
• unlink - remove a file
• unlinkat - remove a file attribute
• rename - rename a file
• renameat rename a file attribute system calls and tags them with the identifier "delete".

Rationale:

Monitoring these calls from non-privileged users could provide a system administrator
with evidence that inappropriate removal of files and file attributes associated with
protected files is occurring. While this audit option will look at all events, system
administrators will want to look for specific privileged files that are being deleted or
altered.'

c='
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete'

d=$( 
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&/ -F *auid>=${UID_MIN}/ \
&&/ -S/ \
&&(/unlink/||/rename/||/unlinkat/||/renameat/) \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n" )

[[ "$d" == *"ERROR"* ]] && e="FAIL" || e="PASS"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor file deletion events by users."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.14 Ensure events that modify the system's Mandatory Access Controls are collected "

b='
Monitor AppArmor, an implementation of mandatory access controls. The parameters
below monitor any write access (potential additional, deletion or modification of files in
the directory) or attribute changes to the /etc/apparmor/ and /etc/apparmor.d/ directories.

Note: If a different Mandatory Access Control method is used, changes to the
corresponding directories should be audited.

Rationale:

Changes to files in the /etc/apparmor/ and /etc/apparmor.d/ directories could
indicate that an unauthorized user is attempting to modify access controls and change
security contexts, leading to a compromise of the system.'

c='
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy'

d=$( 
awk '/^ *-w/ \
&&(/\/etc\/apparmor/ \
||/\/etc\/apparmor.d/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules 2>&1 )

[[ "$d" == *"MAC-policy"* ]] && e="PASS" || e="FAIL"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor events that modify the system's Mandatory Access Controls."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.15 Ensure successful and unsuccessful attempts to use the chcon command are collected "

b='
The operating system must generate audit records for successful/unsuccessful uses of
the chcon command.

Rationale:

The chcon command is used to change file security context. Without generating audit
records that are specific to the security and mission needs of the organization, it would
be difficult to establish, correlate, and investigate the events relating to an incident or
identify those responsible for one.
Audit records can be generated from various components within the information system'

c='-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng'

d=$( 
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&/ -F *auid>=${UID_MIN}/ \
&&/ -F *perm=x/ \
&&/ -F *path=\/usr\/bin\/chcon/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n" 2>&1 )

[[ "$d" == *"ERROR"* ]] && e="FAIL" || e="PASS"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor successful and unsuccessful attempts to use the
chcon command."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are collected "

b='
The operating system must generate audit records for successful/unsuccessful uses of
the setfacl command

Rationale:

This utility sets Access Control Lists (ACLs) of files and directories. Without generating
audit records that are specific to the security and mission needs of the organization, it
would be difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.'

c='-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng'

d=$( 
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&/ -F *auid>=${UID_MIN}/ \
&&/ -F *perm=x/ \
&&/ -F *path=\/usr\/bin\/setfacl/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules ||
printf "ERROR: Variable 'UID_MIN' is unset.\n" 2>&1 )

[[ "$d" == *"ERROR"* ]] && e="FAIL" || e="PASS"

f='
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor successful and unsuccessful attempts to use the
setfacl command'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.17 Ensure successful and unsuccessful attempts to use the chacl command are collected "

b='
The operating system must generate audit records for successful/unsuccessful uses of
the chacl command.
chacl is an IRIX-compatibility command, and is maintained for those users who are
familiar with its use from either XFS or IRIX.

Rationale:

chacl changes the ACL(s) for a file or directory. Without generating audit records that
are specific to the security and mission needs of the organization, it would be difficult to
establish, correlate, and investigate the events relating to an incident or identify those
responsible for one.'

c='-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng'

d=$( 
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&/ -F *auid>=${UID_MIN}/ \
&&/ -F *perm=x/ \
&&/ -F *path=\/usr\/bin\/chacl/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n")

[[ "$d" == *"ERROR"* ]] && e="FAIL" || e="PASS"

f='
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor successful and unsuccessful attempts to use the
chacl command'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.18 Ensure successful and unsuccessful attempts to use the usermod command are collected "

b='
The operating system must generate audit records for successful/unsuccessful uses of
the usermod command.

Rationale:

The usermod command modifies the system account files to reflect the changes that are
specified on the command line. Without generating audit records that are specific to the
security and mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those responsible
for one.'

c='-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod'

d=$( 
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&/ -F *auid>=${UID_MIN}/ \
&&/ -F *perm=x/ \
&&/ -F *path=\/usr\/sbin\/usermod/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n" )

[[ "$d" == *"ERROR"* ]] && e="FAIL" || e="PASS"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor successful and unsuccessful attempts to use the usermod command."

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.19 Ensure kernel module loading unloading and modification is collected "

b='
Monitor the loading and unloading of kernel modules. All the loading / listing /
dependency checking of modules is done by kmod via symbolic links.
The following system calls control loading and unloading of modules:
• init_module - load a module
• finit_module - load a module (used when the overhead of using
cryptographically signed modules to determine the authenticity of a module can
be avoided)
• delete_module - delete a module
• create_module - create a loadable module entry
• query_module - query the kernel for various bits pertaining to modules
Any execution of the loading and unloading module programs and system calls will
trigger an audit record with an identifier of modules.
Rationale:
Monitoring the use of all the various ways to manipulate kernel modules could provide
system administrators with evidence that an unauthorized change was made to a kernel
module, possibly compromising the security of the system.'

c='
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F
auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules'

d=$( 
awk '/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&(/ -F auid!=unset/||/ -F auid!=-1/||/ -F auid!=4294967295/) \
&&/ -S/ \
&&(/init_module/ \
||/finit_module/ \
||/delete_module/ \
||/create_module/ \
||/query_module/) \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&/ -F *auid>=${UID_MIN}/ \
&&/ -F *perm=x/ \
&&/ -F *path=\/usr\/bin\/kmod/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n")

[[ "$d" == *"ERROR"* ]] && e="FAIL" || e="PASS"

f="
Edit or create a file in the /etc/audit/rules.d/ directory, ending in .rules extension,
with the relevant rules to monitor kernel module modification"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.3.20 Ensure the audit configuration is immutable"

b='
Set system audit so that audit rules cannot be modified with auditctl . Setting the flag
-e 2 forces audit to be put in immutable mode. Audit changes can only be made on reboot.

Note: This setting will require the system to be rebooted to update the active auditd
configuration settings.

Rationale:

In immutable mode, unauthorized users cannot execute changes to the audit system to
potentially hide malicious activity and then put the audit rules back. Users would most
likely notice a system reboot and that could alert administrators of an attempt to make
unauthorized audit changes.'

c='-e 2'

d=$( grep -Ph -- '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules | tail -1 2>&1 )

[[ "$d" == *"-e 2"* ]] && e="PASS" || e="FAIL"

f='
Edit or create the file /etc/audit/rules.d/99-finalize.rules and
add the line -e 2 at the end of the file:

Example:
# printf '\n%s' -e 2 >> /etc/audit/rules.d/99-finalize.rules'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.4.1 Ensure audit log files mode is configured "

b='
Audit log files contain information about the system and system activity.

Rationale:

Access to audit records can reveal system and configuration data to attackers,
potentially compromising its confidentiality.'

c='All files in audit_log_directory are 0640 or more restrictive'

d1=$(
l_perm_mask="0137"

# Check if auditd.conf exists and set the log directory
[ -e "/etc/audit/auditd.conf" ] && l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print$2}' /etc/audit/auditd.conf | xargs)")" || {
    echo -e "\n- Audit Result:\n ** FAIL **\n - File: \"/etc/audit/auditd.conf\" not found.\n - ** Verify auditd is installed **"
    exit 1
}

# Check if the log directory is valid
[ -d "$l_audit_log_directory" ] || {
    echo -e "\n- Audit Result:\n ** FAIL **\n - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory"
    exit 1
}

l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"
a_files=()

# Find files with the specified permission mask
while IFS= read -r -d $'\0' l_file; do
    [ -e "$l_file" ] && a_files+=("$l_file")
done < <(find "$l_audit_log_directory" -maxdepth 1 -type f -perm /"$l_perm_mask" -print0)

# Check the results
(( "${#a_files[@]}" > 0 )) && {
    for l_file in "${a_files[@]}"; do
        l_file_mode="$(stat -Lc '%#a' "$l_file")"
        echo -e "\n- Audit Result:\n ** FAIL **\n - File: \"$l_file\" is mode: \"$l_file_mode\"\n (should be mode: \"$l_maxperm\" or more restrictive)\n"
    done
} || {
    echo -e "\n- Audit Result:\n ** PASS **\n - All files in \"$l_audit_log_directory\" are mode: \"$l_maxperm\" or more restrictive"
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f1="Run the following command to remove more permissive mode than 0640 from audit log files:
# [ -f /etc/audit/auditd.conf ] && find \"\$(dirname \$(awk -F \"=\" '/^\s*log_file/ {print \$2}' 
/etc/audit/auditd.conf | xargs))\" -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} +"

f=$(printf "%s\n" "$f1" | sed 's/"/""/g') 

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.4.2 Ensure audit log files owner is configured"

b='
Audit log files contain information about the system and system activity.

Rationale:

Access to audit records can reveal system and configuration data to attackers,
potentially compromising its confidentiality'

c='Correctly configured'

d1=$(
l_output="" 
l_output2=""

[ -e "/etc/audit/auditd.conf" ] && l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print$2}' /etc/audit/auditd.conf | xargs)")" || l_output2+="\n - File: \"/etc/audit/auditd.conf\" not found.\n - ** Verify auditd is installed **"

[ -d "$l_audit_log_directory" ] && {
    while IFS= read -r -d $'\0' l_file; do
        l_output2+="\n - File: \"$l_file\" is owned by user: \"$(stat -Lc '%U' "$l_file")\"\n (should be owned by user: \"root\")"
    done < <(find "$l_audit_log_directory" -maxdepth 1 -type f ! -user root -print0)
} || l_output2+="\n - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory"

[ -z "$l_output2" ] && l_output+="\n - All files in \"$l_audit_log_directory\" are owned by user: \"root\"\n"

[ -z "$l_output2" ] && echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured *:$l_output" || echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f1='
f="Run the following command to configure the audit log files to be owned by the root user:
# [ -f /etc/audit/auditd.conf ] && find \"\$(dirname \$(awk -F \"=\" '/^\s*log_file/' /
etc/audit/auditd.conf | xargs))\" -type f ! -user root -exec chown root {} +"'

f=$(printf "%s\n" "$f1" | sed 's/"/""/g') 

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.4.3 Ensure audit log files group owner is configured"

b='
Audit log files contain information about the system and system activity.

Rationale:

Access to audit records can reveal system and configuration data to attackers,
potentially compromising its confidentiality'

c='log_group parameter is set to either adm or root in /etc/audit/auditd.conf'

check=$( grep -Piws -- '^\h*log_group\h*=\h*\H+\b' /etc/audit/auditd.conf | grep -Pvi -- '(adm)'  )

[ -z "$check" ] && { d1="log_group parameter is set to either adm or root
in /etc/audit/auditd.conf"; e="PASS"; } || { d1="log_group parameter is not set"; e="FAIL"; }

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

f1="Run the following command to configure the audit log files to be group owned by adm:
# find \$(dirname \$(awk -F\"=\" '/^\\s*log_file/ {print \$2}' /etc/audit/auditd.conf | xargs)) 
-type f \( ! -group adm -a ! -group root \) -exec chgrp adm {} +

Run the following command to set the log_group parameter in the audit configuration file to log_group = adm:
# sed -ri 's/^\\s*#?\\s*log_group\\s*=\\s*\\S+(\\s*#.*)?$/log_group = adm\\1/' /etc/audit/auditd.conf

Run the following command to restart the audit daemon to reload the configuration file:
# systemctl restart auditd"

f=$(printf "%s\n" "$f1" | sed 's/"/""/g') 

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="6.2.4.4 Ensure the audit log file directory mode is configured"

b='
The audit log directory contains audit log files.

Rationale:

Audit information includes all information including: audit records, audit settings and
audit reports. This information is needed to successfully audit system activity. This
information must be protected from unauthorized modification or deletion. If this
information were to be compromised, forensic analysis and discovery of the true source
of potentially malicious system activity is impossible to achieve.'

c='Directory: audit_log_directory is should be mode 0640 or more restrictive'

d1=$(
l_perm_mask="0027"

[ -e "/etc/audit/auditd.conf" ] && l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print$2}' /etc/audit/auditd.conf | xargs)")" || {
    echo -e "\n- Audit Result:\n ** FAIL **\n - File:\"/etc/audit/auditd.conf\" not found\n - ** Verify auditd is installed **"
    exit 1
}

[ -d "$l_audit_log_directory" ] && {
    l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"
    l_directory_mode="$(stat -Lc '%#a' "$l_audit_log_directory")"
    
   
    [ $(( $l_directory_mode & $l_perm_mask )) -gt 0 ] && {
        echo -e "\n- Audit Result:\n ** FAIL **\n - Directory:\"$l_audit_log_directory\" is mode: \"$l_directory_mode\"\n (should be mode: \"$l_maxperm\" or more restrictive)\n"
    } || {
        echo -e "\n- Audit Result:\n ** PASS **\n - Directory: \"$l_audit_log_directory\" is mode: \"$l_directory_mode\"\n (should be mode: \"$l_maxperm\" or more restrictive)\n"
    }
} || {
    echo -e "\n- Audit Result:\n ** FAIL **\n - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory"
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f1="Run the following command to configure the audit log directory to have a mode of \"0750\" or less permissive:
# chmod g-w,o-rwx \"\$(dirname \$(awk -F= '/^\\s*log_file\\s*/{print \$2}' /etc/audit/auditd.conf | xargs))\" "

f=$(printf "%s\n" "$f1" | sed 's/"/""/g') 

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.4.5 Ensure audit configuration files mode is configured"

b="
Audit configuration files control auditd and what events are audited.

Rationale:

Access to the audit configuration files could allow unauthorized personnel to prevent the
auditing of critical events.
Misconfigured audit configuration files may prevent the auditing of critical events or
impact the system's performance by overwhelming the audit log. Misconfiguration of the
audit configuration files may also make it more difficult to establish and investigate
events relating to an incident"

c='All audit configuration files are mode 0640 or more restrictive'

d1=$(
l_output="" 
l_output2="" 
l_perm_mask="0137"
l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"

while IFS= read -r -d $'\0' l_fname; do
    l_mode=$(stat -Lc '%#a' "$l_fname")
    [ $(( "$l_mode" & "$l_perm_mask" )) -gt 0 ] && {
        l_output2+="\n - file: \"$l_fname\" is mode: \"$l_mode\"\n (should be mode: \"$l_maxperm\" or more restrictive)"
    }
done < <(find /etc/audit/ -type f \( -name "*.conf" -o -name '*.rules' \) -print0)

[ -z "$l_output2" ] && echo -e "\n- Audit Result:\n ** PASS **\n - All audit configuration files are mode: \"$l_maxperm\" or more restrictive" || echo -e "\n- Audit Result:\n ** FAIL **\n$l_output2"

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f1="Run the following command to remove more permissive mode than 0640 from the audit configuration files:
# find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) -exec chmod u-x,g-wx,o-rwx {} +"

f=$(printf "%s\n" "$f1" | sed 's/"/""/g') 

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.4.6 Ensure audit configuration files owner is configured"

#no output

b="
Access to the audit configuration files could allow unauthorized personnel to prevent the
auditing of critical events. Misconfigured audit configuration files may prevent the
auditing of critical events or impact the system's performance by overwhelming the audit log. 
Misconfiguration of the audit configuration files may also make it more difficult to
establish and investigate events relating to an incident"

c='Configured'

check=$( find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root)

[ -z "$check" ] && { d="Configured"; e="PASS"; } || { d="Unconfigured"; e="FAIL"; }

f="Run the following command to change ownership to root user:

# find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="6.2.4.7 Ensure audit configuration files group owner is configured"

#no output

b="
Access to the audit configuration files could allow unauthorized personnel to prevent the
auditing of critical events.
Misconfigured audit configuration files may prevent the auditing of critical events or
impact the system's performance by overwhelming the audit log. Misconfiguration of the
audit configuration files may also make it more difficult to establish and investigate
events relating to an incident"

c='Configured'

d=$( find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root)

[ -z "$d" ] && { d="Configured"; e="PASS"; } || { d="Unconfigured"; e="FAIL"; }

f="Run the following command to change group to root:

# find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="6.2.4.8 Ensure audit tools mode is configured"

b='
Audit tools include, but are not limited to, vendor-provided and open source audit tools
needed to successfully view and manipulate audit information system activity and
records. Audit tools include custom queries and report generators.

Rationale:

Protecting audit information includes identifying and protecting the tools used to view
and manipulate log data. Protecting audit tools is necessary to prevent unauthorized
operation on audit information.'

c='Correctly configured'

d1=$(
    
l_output="" 
l_output2="" 
l_perm_mask="0022"
l_maxperm="$( printf '%o' $(( 0777 & ~$l_perm_mask )) )"
a_audit_tools=("/sbin/auditctl" "/sbin/aureport" "/sbin/ausearch" "/sbin/autrace" "/sbin/auditd" "/sbin/augenrules")

for l_audit_tool in "${a_audit_tools[@]}"; do
    l_mode="$(stat -Lc '%#a' "$l_audit_tool")"

    # Ensure l_mode and l_perm_mask are numeric and perform permission checks
    [[ "$l_mode" =~ ^[0-7]{3}$ && "$l_perm_mask" =~ ^[0-7]{3}$ ]] && {
        [ $(( l_mode & l_perm_mask )) -gt 0 ] && 
            l_output2+="\n - Audit tool \"$l_audit_tool\" is mode: \"$l_mode\" and should be mode: \"$l_maxperm\" or more restrictive" ||
            l_output+="\n - Audit tool \"$l_audit_tool\" is correctly configured to mode: \"$l_mode\""
    } || 
        l_output2+="\n - Audit tool \"$l_audit_tool\" has invalid mode: \"$l_mode\""
done

[ -z "$l_output2" ] && echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured *:$l_output" || {
    echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
    [ -n "$l_output" ] && echo -e "\n - * Correctly configured *:\n$l_output\n"
}

unset a_audit_tools)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f="Run the following command to remove more permissive mode from the audit tools:

# chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.2.4.9 Ensure audit tools owner is configured "

#no output

b='
Audit tools include, but are not limited to, vendor-provided and open source audit tools
needed to successfully view and manipulate audit information system activity and
records. Audit tools include custom queries and report generators.

Rationale:

Protecting audit information includes identifying and protecting the tools used to view
and manipulate log data. Protecting audit tools is necessary to prevent unauthorized
operation on audit information.'

c='Configured'

d=$(stat -Lc "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | awk '$2 != "root" {print}' )

[ -z "$d" ] && { d="Configured"; e="PASS"; } || { d="Unconfigured"; e="FAIL"; }

f='Run the following command to change the owner of the audit tools to the root user:

# chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="6.2.4.10 Ensure audit tools group owner is configured"

#no output

b='
Audit tools include, but are not limited to, vendor-provided and open source audit tools
needed to successfully view and manipulate audit information system activity and
records. Audit tools include custom queries and report generators.

Rationale:

Protecting audit information includes identifying and protecting the tools used to view
and manipulate log data. Protecting audit tools is necessary to prevent unauthorized
operation on audit information.'

c='Configured'

d=$( stat -Lc "%n %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | awk '$2 != "root" {print}' )

[ -z "$d" ] && { d="Configured"; e="PASS"; } || { d="Unconfigured"; e="FAIL"; }

f='Run the following command to change group ownership to the groop root:

# chgrp root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="6.3.1 Ensure AIDE is installed"

b='
AIDE takes a snapshot of filesystem state including modification times, permissions,
and file hashes which can then be used to compare against the current state of the
filesystem to detect modifications to the system.

Rationale:

By monitoring the filesystem state compromised files can be detected to prevent or limit
the exposure of accidental or malicious misconfigurations or modified binaries.'

c='
aide is installed
aide-common is installed'

d1=$( dpkg-query -s aide &>/dev/null && echo "aide is installed" 2>&1)
d2=$( dpkg-query -s aide-common &>/dev/null && echo "aide-common is installed" 2>&1)

[[ "$d1" == "aide is installed" ]] && \
[[ "$d2" == "aide-common is installed" ]] && e="PASS" || e="FAIL"

d="$d1
$d2"

f='
Install AIDE using the appropriate package manager or manual installation:
# apt install aide aide-common
Configure AIDE as appropriate for your environment. Consult the AIDE documentation for options.

Run the following commands to initialize AIDE:
# aideinit
# mv /var/lib/aide/aide.db.new /var/lib/aide/aide.d'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.3.2 Ensure filesystem integrity is regularly checked "

b="
Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.

Rationale:

Periodic file checking allows the system administrator to determine on a regular basis if
critical files have been changed in an unauthorized fashion."

c='dailyaidecheck.timer is active'

d=$(systemctl is-active dailyaidecheck.timer)

[[ "$d" == "active" ]] && e="PASS" || e="FAIL"

f='
Run the following command to unmask dailyaidecheck.timer and dailyaidecheck.service:
# systemctl unmask dailyaidecheck.timer dailyaidecheck.service

Run the following command to enable and start dailyaidecheck.timer:
# systemctl --now enable dailyaidecheck.timer'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="6.3.3 Ensure cryptographic mechanisms are used to protect the integrity of audit tools "

b1='
Audit tools include, but are not limited to, vendor-provided and open source audit tools
needed to successfully view and manipulate audit information system activity and
records. Audit tools include custom queries and report generators.

Rationale:

Protecting the integrity of the tools used for auditing purposes is a critical step toward
ensuring the integrity of audit information. Audit information includes all information
(e.g., audit records, audit settings, and audit reports) needed to successfully audit
information system activity.
Attackers may replace the audit tools or inject code into the existing tools with the
purpose of providing the capability to hide or erase system activity from the audit logs.
Audit tools should be cryptographically signed in order to provide the capability to
identify when the audit tools have been modified, manipulated, or replaced. An example
is a checksum hash of the file or files

Verify that Advanced Intrusion Detection Environment (AIDE) is properly configured.
• AIDE is configured to use cryptographic mechanisms to protect the integrity of
audit tools:
• The following audit tool files include the options "p, i, n, u, g, s, b, acl, xattrs and
sha512"
o auditctl
o auditd
o ausearch
o aureport
o autrace
o augenrules'

b=$(printf "%s\n" "$b1" | sed 's/"/""/g') 

c='Correctly set'

d1=$(
a_output=() 
a_output2=() 
l_tool_dir="$(readlink -f /sbin)"
a_items=("p" "i" "n" "u" "g" "s" "b" "acl" "xattrs" "sha512")
l_aide_cmd="$(whereis aide | awk '{print $2}')"
a_audit_files=("auditctl" "auditd" "ausearch" "aureport" "autrace" "augenrules")

[ -f "$l_aide_cmd" ] && command -v "$l_aide_cmd" &>/dev/null && {
    a_aide_conf_files=("$(find -L /etc -type f -name 'aide.conf')")

    f_file_par_chk() {
        a_out2=()
        for l_item in "${a_items[@]}"; do
            ! grep -Psiq -- '(\h+|\+)'"$l_item"'(\h+|\+)' <<< "$l_out" && \
            a_out2+=(" - Missing the \"$l_item\" option")
        done
        
        [ "${#a_out2[@]}" -gt "0" ] && \
            a_output2+=(" - Audit tool file: \"$l_file\"" "${a_out2[@]}") || \
            a_output+=(" - Audit tool file: \"$l_file\" includes:" "\"${a_items[*]}\"")
    }

    for l_file in "${a_audit_files[@]}"; do
        [ -f "$l_tool_dir/$l_file" ] && {
            l_out="$("$l_aide_cmd" --config "${a_aide_conf_files[@]}" -p f:"$l_tool_dir/$l_file")"
            f_file_par_chk
        } || a_output+=(" - Audit tool file \"$l_file\" doesn't exist")
    done
} || a_output2+=(" - The command \"aide\" was not found" " Please install AIDE")

[ "${#a_output2[@]}" -le 0 ] && {
    printf '%s\n' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" ""
} || {
    printf '%s\n' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
    [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f1='Run the following command to determine the absolute path to the non-symlinked
version on the audit tools:
# readlink -f /sbin
The output will be either /usr/sbin - OR - /sbin. Ensure the correct path is used.
Edit /etc/aide/aide.conf and add or update the following selection lines replacing
<PATH> with the correct path returned in the command above:
# Audit Tools
<PATH>/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
<PATH>/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
<PATH>/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
<PATH>/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
<PATH>/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
<PATH>/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512

Example
# printf '%s\n' "" "# Audit Tools" "$(readlink -f /sbin/auditctl)
p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/auditd)
p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/ausearch)
p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/aureport)
p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/autrace)
p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/augenrules)
p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf

Note: - IF - /etc/aide/aide.conf includes a @@x_include statement:
• <DIRECTORY> and each executable config file must be owned by the current user or root
• They must not be group or world-writable

Example: @@x_include /etc/aide.conf.d ^[a-zA-Z0-9_-]+$'

f=$(printf "%s\n" "$f1" | sed 's/"/""/g') 

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.1 Ensure permissions on /etc/passwd are configured"

b='
The /etc/passwd file contains user account information that is used by many system
utilities and therefore must be readable for these utilities to operate.

Rationale:

It is critical to ensure that the /etc/passwd file is protected from unauthorized write
access. Although it is protected by default, the file permissions could be changed either
inadvertently or through malicious actions.'

c='Access: ( ≤ 0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)'

d=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/passwd)

access_mode=$(echo "$d" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid=$(echo "$d" | awk '{print $5}')
gid=$(echo "$d" | awk '{print $9}')

[[ "$access_mode" -le 644 && "$uid" == "0/" && "$gid" == "0/" ]] && e="PASS" || e="FAIL"

f="
Run the following commands to remove excess permissions, set owner, and set group
on /etc/passwd:

# chmod u-x,go-wx /etc/passwd
# chown root:root /etc/passwd"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.2 Ensure permissions on /etc/passwd- are configured"

b='
The /etc/passwd- file contains backup user account information.

Rationale:

It is critical to ensure that the /etc/passwd- file is protected from unauthorized access.
Although it is protected by default, the file permissions could be changed either
inadvertently or through malicious actions.'

c='Access: ( ≤ 0644/-rw-r--r--) Uid: ( 0/ root) Gid: { 0/ root)'

d=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: { %g/ %G)' /etc/passwd-)

access_mode=$(echo "$d" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid=$(echo "$d" | awk '{print $5}')
gid=$(echo "$d" | awk '{print $9}')

[[ "$access_mode" -le 644 && "$uid" == "0/" && "$gid" == "0/" ]] && e="PASS" || e="FAIL"

f="
Run the following commands to remove excess permissions, set owner, and set group
on /etc/passwd-:

# chmod u-x,go-wx /etc/passwd-
# chown root:root /etc/passwd-"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.3 Ensure permissions on /etc/group are configured"

b='
The /etc/group file contains a list of all the valid groups defined in the system. The
command below allows read/write access for root and read access for everyone else.

Rationale:

The /etc/group file needs to be protected from unauthorized changes by non-
privileged users, but needs to be readable as this information is used with many non-
privileged programs.'

c='Access: ( ≤ 0644/-rw-r--r--) Uid: ( 0/ root) Gid: { 0/ root)'

d=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/group)

access_mode=$(echo "$d" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid=$(echo "$d" | awk '{print $5}')
gid=$(echo "$d" | awk '{print $9}')

[[ "$access_mode" -le 644 && "$uid" == "0/" && "$gid" == "0/" ]] && e="PASS" || e="FAIL"

f='Run the following commands to remove excess permissions, set owner, and set group
on /etc/group:

# chmod u-x,go-wx /etc/group
# chown root:root /etc/group'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.4 Ensure permissions on /etc/group- are configured"

b='
The /etc/group- file contains a backup list of all the valid groups defined in the system.

Rationale:

It is critical to ensure that the /etc/group- file is protected from unauthorized access.
Although it is protected by default, the file permissions could be changed either
inadvertently or through malicious actions.'

c='Access: ( ≤ 0644/-rw-r--r--) Uid: ( 0/ root) Gid: { 0/ root)'

d=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/group-)

access_mode=$(echo "$d" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid=$(echo "$d" | awk '{print $5}')
gid=$(echo "$d" | awk '{print $9}')

[[ "$access_mode" -le 644 && "$uid" == "0/" && "$gid" == "0/" ]] && e="PASS" || e="FAIL"

f='
Run the following commands to remove excess permissions, set owner, and set group
on /etc/group-:

# chmod u-x,go-wx /etc/group-
# chown root:root /etc/group-'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.5 Ensure permissions on /etc/shadow are configured"

b='
The /etc/shadow file is used to store the information about user accounts that is critical
to the security of those accounts, such as the hashed password and other security information.

Rationale:

If attackers can gain read access to the /etc/shadow file, they can easily run a
password cracking program against the hashed password to break it. Other security
information that is stored in the /etc/shadow file (such as expiration) could also be
useful to subvert the user accounts.'

c='Access: ( ≤ 0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 42/ shadow)'

d=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shadow)

access_mode=$(echo "$d" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid=$(echo "$d" | awk '{print $5}')
gid=$(echo "$d" | awk '{print $9}')

[[ "$access_mode" -le 0640 && "$uid" == "0/" && "$gid" == "42/" ]] && e="PASS" || e="FAIL"

f='
Run one of the following commands to set ownership of /etc/shadow to root and
group to either root or shadow:
# chown root:shadow /etc/shadow
-OR-
# chown root:root /etc/shadow

Run the following command to remove excess permissions form /etc/shadow:
# chmod u-x,g-wx,o-rwx /etc/shadow'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.6 Ensure permissions on /etc/shadow- are configured"

b='
The /etc/shadow- file is used to store backup information about user accounts that is
critical to the security of those accounts, such as the hashed password and other security information.

Rationale:

It is critical to ensure that the /etc/shadow- file is protected from unauthorized access.
Although it is protected by default, the file permissions could be changed either
inadvertently or through malicious actions'

c='Access: ( ≤ 0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 42/ shadow)'

d=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shadow-)

access_mode=$(echo "$d" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid=$(echo "$d" | awk '{print $5}')
gid=$(echo "$d" | awk '{print $9}')

[[ "$access_mode" -le 0640 && "$uid" == "0/" && "$gid" == "42/" ]] && e="PASS" || e="FAIL"

f='
Run one of the following commands to set ownership of /etc/shadow- to root and
group to either root or shadow:
# chown root:shadow /etc/shadow-
-OR-
# chown root:root /etc/shadow-

Run the following command to remove excess permissions form /etc/shadow-:
# chmod u-x,g-wx,o-rwx /etc/shadow-'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.7 Ensure permissions on /etc/gshadow are configured"

b='
The /etc/gshadow file is used to store the information about groups that is critical to
the security of those accounts, such as the hashed password and other security information.

Rationale:

If attackers can gain read access to the /etc/gshadow file, they can easily run a
password cracking program against the hashed password to break it. Other security
information that is stored in the /etc/gshadow file (such as group administrators) could
also be useful to subvert the group.'

c='Access: ( ≤ 0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 42/ shadow)'

d=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/gshadow)

access_mode=$(echo "$d" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid=$(echo "$d" | awk '{print $5}')
gid=$(echo "$d" | awk '{print $9}')

[[ "$access_mode" -le 0640 && "$uid" == "0/" && "$gid" == "42/" ]] && e="PASS" || e="FAIL"

f='
Run one of the following commands to set ownership of /etc/gshadow to root and
group to either root or shadow:
# chown root:shadow /etc/gshadow
-OR-
# chown root:root /etc/gshadow

Run the following command to remove excess permissions form /etc/gshadow:
# chmod u-x,g-wx,o-rwx /etc/gshadow'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.8 Ensure permissions on /etc/gshadow- are configured"

b='
The /etc/gshadow- file is used to store backup information about groups that is critical
to the security of those accounts, such as the hashed password and other security information.

Rationale:

It is critical to ensure that the /etc/gshadow- file is protected from unauthorized
access. Although it is protected by default, the file permissions could be changed either
inadvertently or through malicious actions.'

c='Access: ( ≤ 0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 42/ shadow)'

d=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/gshadow-)

access_mode=$(echo "$d" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid=$(echo "$d" | awk '{print $5}')
gid=$(echo "$d" | awk '{print $9}')

[[ "$access_mode" -le 0640 && "$uid" == "0/" && "$gid" == "42/" ]] && e="PASS" || e="FAIL"

f='
Run one of the following commands to set ownership of /etc/gshadow- to root and
group to either root or shadow:
# chown root:shadow /etc/gshadow-
-OR-
# chown root:root /etc/gshadow-

Run the following command to remove excess permissions form /etc/gshadow-:
# chmod u-x,g-wx,o-rwx /etc/gshadow-'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.9 Ensure permissions on /etc/shells are configured"

b='
/etc/shells is a text file which contains the full pathnames of valid login shells. This
file is consulted by chsh and available to be queried by other programs.

Rationale:

It is critical to ensure that the /etc/shells file is protected from unauthorized access.
Although it is protected by default, the file permissions could be changed either
inadvertently or through malicious actions'

c='Access: ( ≤ 0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)'

d=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shells)

access_mode=$(echo "$d" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid=$(echo "$d" | awk '{print $5}')
gid=$(echo "$d" | awk '{print $9}')

[[ "$access_mode" -le 0644 && "$uid" == "0/" && "$gid" == "0/" ]] && e="PASS" || e="FAIL"

f='
Run the following commands to remove excess permissions, set owner, and set group
on /etc/shells:

# chmod u-x,go-wx /etc/shells
# chown root:root /etc/shells'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.10.1 Ensure permissions on /etc/security/opasswd are configured "

b="
/etc/security/opasswd hold user's previous passwords if pam_unix or pam_pwhistory is in use.

Rationale:

It is critical to ensure that /etc/security/opasswd is protected from unauthorized
access. Although it is protected by default, the file permissions could be changed either
inadvertently or through malicious actions."

c='
Access: ( ≤ 0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/root)
-OR-
Lack of output implies that this configuration is passed'

d=$(stat -Lc '%n Access: (%#a/%A) Uid: (%u/ %U) Gid: ( %g/ %G)' /etc/security/opasswd | sed -E 's|^/etc/security/opasswd ||')

access_mode=$(echo "$d" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid=$(echo "$d" | awk '{print $4}')
gid=$(echo "$d" | awk '{print $8}')

[[ "$access_mode" -le 0600 && "$uid" == "(0/" && "$gid" == "0/" ]] || [[ -z "$d" ]] && e="PASS" || e="FAIL"

f="
Run the following commands to remove excess permissions, set owner, and set group
on /etc/security/opasswd is they exist:

# [ -e "/etc/security/opasswd" ] && chmod u-x,go-rwx /etc/security/opasswd
# [ -e "/etc/security/opasswd" ] && chown root:root /etc/security/opasswd"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.10.2 Ensure permissions on /etc/security/opasswd.old are configured "

b='/etc/security/opasswd.old is a backup folder of /etc/security/opasswd'

c='
Access: ( ≤ 0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/root)
-OR-
Lack of output implies that this configuration is passed'

d=$(stat -Lc '%n Access: (%#a/%A) Uid: (%u/ %U) Gid: ( %g/ %G)' /etc/security/opasswd.old | sed -E 's|^/etc/security/opasswd ||')

access_mode=$(echo "$d" | sed -E 's/.*\(([^/]+)\/-.*/\1/')
uid=$(echo "$d" | awk '{print $4}')
gid=$(echo "$d" | awk '{print $8}')

[[ "$access_mode" -le 0600 && "$uid" == "(0/" && "$gid" == "0/" ]] || [[ -z "$d" ]] && e="PASS" || e="FAIL"

f="
Run the following commands to remove excess permissions, set owner, and set group
on /etc/security/opasswd.old is they exist

[ -e "/etc/security/opasswd.old" ] && chmod u-x,go-rwx /etc/security/opasswd.old
# [ -e "/etc/security/opasswd.old" ] && chown root:root /etc/security/opasswd.old"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.11 Ensure world writable files and directories are secured"

b="
World writable files are the least secure. Data in world-writable files can be modified and
compromised by any user on the system. World writable files may also indicate an
incorrectly written script or program that could potentially be the cause of a larger
compromise to the system's integrity. See the chmod(2) man page for more information.
Setting the sticky bit on world writable directories prevents users from deleting or
renaming files in that directory that are not owned by them.

Rationale:

Data in world-writable files can be modified and compromised by any user on the
system. World writable files may also indicate an incorrectly written script or program
that could potentially be the cause of a larger compromise to the system's integrity.
This feature prevents the ability to delete or rename files in world writable directories
(such as /tmp ) that are owned by another user."

c='Correctly configured.No world writable files exist on the local filesystem'

d1=$(
l_output="" 
l_output2=""
l_smask='01000'
a_file=() 
a_dir=() # Initialize arrays
a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path \
"*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path \
"*/kubelet/plugins/*" -a ! -path "/sys/*" -a ! -path "/snap/*")

while IFS= read -r l_mount; do
    while IFS= read -r -d $'\0' l_file; do
        [ -e "$l_file" ] && {
            [ -f "$l_file" ] && a_file+=("$l_file") # Add WR files
            [ -d "$l_file" ] && { # Add directories w/o sticky bit
                l_mode="$(stat -Lc '%#a' "$l_file")"
                [ ! $(( $l_mode & $l_smask )) -gt 0 ] && a_dir+=("$l_file")
            }
        }
    done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) -perm -0002 -print0 2> /dev/null)
done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^(\/run\/user\/|\/tmp|\/var\/tmp)/){print $2}')

! (( ${#a_file[@]} > 0 )) && l_output="$l_output\n - No world writable files exist on the local filesystem." || l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_file[@]}")\" World writable files on the system.\n - The following is a list of World writable files:\n$(printf '%s\n' "${a_file[@]}")\n - end of list\n"

! (( ${#a_dir[@]} > 0 )) && l_output="$l_output\n - Sticky bit is set on world writable directories on the local filesystem." || l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_dir[@]}")\" World writable directories without the sticky bit on the system.\n - The following is a list of World writable directories without the sticky bit:\n$(printf '%s\n' "${a_dir[@]}")\n - end of list\n"

unset a_path; unset a_arr; unset a_file; unset a_dir # Remove arrays

# If l_output2 is empty, we pass
[ -z "$l_output2" ] && echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured *:\n$l_output\n" || {
    echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
    [ -n "$l_output" ] && echo -e "- * Correctly configured *:\n$l_output\n"
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f='
World Writable Files:
It is recommended that write access is removed from other with the
command ( chmod o-w <filename> ), but always consult relevant vendor
documentation to avoid breaking any application dependencies on a given file.

World Writable Directories:
Set the sticky bit on all world writable directories with the command 
(chmod a+t <directory_name> )'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.1.12 Ensure no files or directories without an owner and a group exist "

b="
dministrators may delete users or groups from the system and neglect to remove all
files and/or directories owned by those users or groups.

Rationale:

A new user or group who is assigned a deleted user's user ID or group ID may then end
up "owning" a deleted user or group's files, and thus have more access on the system
than was intended."

c='No files or directories without an owner exist on the local filesystem'

d1=$(
l_output="" 
l_output2=""
a_nouser=() 
a_nogroup=() # Initialize arrays
a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path \
"*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path \
"*/kubelet/plugins/*" -a ! -path "/sys/fs/cgroup/memory/*" -a ! -path \
"/var/*/private/*")

while IFS= read -r l_mount; do
    while IFS= read -r -d $'\0' l_file; do
        [ -e "$l_file" ] && {
            while IFS=: read -r l_user l_group; do
                [ "$l_user" = "UNKNOWN" ] && a_nouser+=("$l_file")
                [ "$l_group" = "UNKNOWN" ] && a_nogroup+=("$l_file")
            done < <(stat -Lc '%U:%G' "$l_file")
        }
    done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) \( -nouser -o -nogroup \) -print0 2> /dev/null)
done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^\/run\/user\//){print $2}')

! (( ${#a_nouser[@]} > 0 )) && l_output="$l_output\n - No files or directories without an owner exist on the local filesystem." || \
    l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_nouser[@]}")\" unowned files or directories on the system.\n - The following is a list of unowned files and/or directories:\n$(printf '%s\n' "${a_nouser[@]}")\n - end of list"

! (( ${#a_nogroup[@]} > 0 )) && l_output="$l_output\n - No files or directories without a group exist on the local filesystem." || \
    l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_nogroup[@]}")\" ungrouped files or directories on the system.\n - The following is a list of ungrouped files and/or directories:\n$(printf '%s\n' "${a_nogroup[@]}")\n - end of list"

unset a_path; unset a_arr; unset a_nouser; unset a_nogroup # Remove arrays

[ -z "$l_output2" ] && echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured *:\n$l_output\n" || {
    echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
    [ -n "$l_output" ] && echo -e "\n- * Correctly configured *:\n$l_output\n"
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f='Remove or set ownership and group ownership of these files and/or directories to an
active user on the system as appropriate'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.2.1 Ensure accounts in /etc/passwd use shadowed passwords"

b="
Local accounts can uses shadowed passwords. With shadowed passwords, The passwords are saved
in shadow password file, /etc/shadow, encrypted by a salted one-way hash.
Accounts with a shadowed password have an x in the second field in /etc/passwd.

Rationale:

The /etc/passwd file also contains information like user ID's and group ID's that are
used by many system programs. Therefore, the /etc/passwd file must remain world
readable. In spite of encoding the password with a randomly-generated one-way hash
function, an attacker could still break the system if they got access to the /etc/passwd file. 
This can be mitigated by using shadowed passwords, thus moving the passwords in
the /etc/passwd file to /etc/shadow. The /etc/shadow file is set so only root will be
able to read and write. This helps mitigate the risk of an attacker gaining access to the
encoded passwords with which to perform a dictionary attack.

Note:
• All accounts must have passwords or be locked to prevent the account 
from being used by an unauthorized user.
• A user account with an empty second field in /etc/passwd allows the account to
be logged into by providing only the username"

c='Shadowed passwords are in use'

#no output 

check=$(  awk -F: '($2 != "x" ) { print "User: \"" $1 "\" is not set to shadowed passwords "}' /etc/passwd )

[ -z "$check" ] && { d1="Shadowed passwords are in use"; e="PASS"; } || { d1="$check"; e="FAIL"; }

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

f='
Run the following command to set accounts to use shadowed passwords and migrate
passwords in /etc/passwd to /etc/shadow:

# pwconv

Investigate to determine if the account is logged in and what it is being used for,
to determine if it needs to be forced off.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="7.2.2 Ensure /etc/shadow password fields are not empty"

#no output 

b='
An account with an empty password field means that anybody may log in as that user
without providing a password.

Rationale:

All accounts must have passwords or be locked to prevent the account from being used
by an unauthorized user.'

c='Password fields are loaded'

check=$( awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow )

[ -z "$check" ] && { d1="Password fields are loaded"; e="PASS"; } || { d1="$check"; e="FAIL"; }

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

f='
If any accounts in the /etc/shadow file do not have a password, run the following
command to lock the account until it can be determined why it does not have a password:

# passwd -l <username>

Also, check to see if the account is logged in and investigate what it is being used for to
determine if it needs to be forced off.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="7.2.3 Ensure all groups in /etc/passwd exist in /etc/group"

#no output 

b='
Over time, system administration errors and changes can lead to groups being defined
in /etc/passwd but not in /etc/group.

Rationale:

Groups defined in the /etc/passwd file but not in the /etc/group file pose a threat to
system security since group permissions are not properly managed.'

c='All GIDs in /etc/passwd exist in /etc/group'

check=$( 
a_passwd_group_gid=("$(awk -F: '{print $4}' /etc/passwd | sort -u)")
a_group_gid=("$(awk -F: '{print $3}' /etc/group | sort -u)")
a_passwd_group_diff=("$(printf '%s\n' "${a_group_gid[@]}" "${a_passwd_group_gid[@]}" | sort | uniq -u)")

while IFS= read -r l_gid; do
    awk -F: '($4 == '"$l_gid"') {print " - User: \"" $1 "\" has GID: \"" $4 "\" which does not exist in /etc/group" }' /etc/passwd
done < <(printf '%s\n' "${a_passwd_group_gid[@]}" "${a_passwd_group_diff[@]}" | sort | uniq -D | uniq)

unset a_passwd_group_gid; unset a_group_gid; unset a_passwd_group_diff)

[ -z "$check" ] && { d1="All GIDs in /etc/passwd exist in /etc/group"; e="PASS"; } || { d1="$check"; e="FAIL"; }

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

f='Analyze the output of the Audit step above and perform the appropriate action
to correct any discrepancies found'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="7.2.4 Ensure shadow group is empty "

#no output 

b='
The shadow group allows system programs which require access the ability to read the
/etc/shadow file. No users should be assigned to the shadow group.

Rationale:

Any users assigned to the shadow group would be granted read access to the
/etc/shadow file. If attackers can gain read access to the /etc/shadow file, they can
easily run a password cracking program against the hashed passwords to break them.
Other security information that is stored in the /etc/shadow file (such as expiration)
could also be useful to subvert additional user accounts.'

c='No users are assigned to the shadow group'

check=$( getent group shadow | awk -F: '{print $4}')

[ -z "$check" ] && { d1="No users are assigned to the shadow group"; e="PASS"; } || { d1="$check"; e="FAIL"; }

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

f1="
Run the following command to remove all users from the shadow group
# sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' /etc/group

Change the primary group of any users with shadow as their primary group.
# usermod -g <primary group> <user>"

f=$(printf "%s\n" "$f1" | sed 's/"/""/g') 

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="7.2.5 Ensure no duplicate UIDs exist"

#no output 

b='
Although the useradd program will not let you create a duplicate User ID (UID), it is
possible for an administrator to manually edit the /etc/passwd file and change the UID field.

Rationale:

Users must be assigned unique UIDs for accountability and to ensure appropriate access protections'

c='No duplicate UIDs exist'

check=$( 
while read -r l_count l_uid; do
    [ "$l_count" -gt 1 ] && echo -e "Duplicate UID: \"$l_uid\" Users: \"$(awk -F: '($3 == n) {print $1 }' n=$l_uid /etc/passwd | xargs)\""
done < <(cut -f3 -d":" /etc/passwd | sort -n | uniq -c)
)

[ -z "$check" ] && { d1="No duplicate UIDs exist"; e="PASS"; } || { d1="$check"; e="FAIL"; }

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

f='
Based on the results of the audit script, establish unique UIDs and review all files owned
by the shared UIDs to determine which UID they are supposed to belong to.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="7.2.6 Ensure no duplicate GIDs exist "

#no output 

b='
Although the groupadd program will not let you create a duplicate Group ID (GID), it is
possible for an administrator to manually edit the /etc/group file and change the GID field.

Rationale:

User groups must be assigned unique GIDs for accountability and to ensure appropriate
access protections.'

c='No duplicate GIDs exist'

check=$( 
while read -r l_count l_gid; do
    [ "$l_count" -gt 1 ] && echo -e "Duplicate GID: \"$l_gid\" Groups: \"$(awk -F: '($3 == n) {print $1 }' n=$l_gid /etc/group | xargs)\""
done < <(cut -f3 -d":" /etc/group | sort -n | uniq -c)
)

[ -z "$check" ] && { d1="No duplicate GIDs exist"; e="PASS"; } || { d1="$check"; e="FAIL"; }

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

f='
Based on the results of the audit script, establish unique GIDs and review all files
owned by the shared GID to determine which group they are supposed to belong to.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="7.2.7 Ensure no duplicate user names exist "

#no output 

b1='
Although the useradd program will not let you create a duplicate user name, it is
possible for an administrator to manually edit the /etc/passwd file and change the user name.

Rationale:

If a user is assigned a duplicate user name, it will create and have access to files with
the first UID for that username in /etc/passwd . For example, if "test4" has a UID of
1000 and a subsequent "test4" entry has a UID of 2000, logging in as "test4" will use
UID 1000. Effectively, the UID is shared, which is a security problem'

c='No duplicate user names exist'

check=$( 
while read -r l_count l_user; do
    [ "$l_count" -gt 1 ] && echo -e "Duplicate User: \"$l_user\" Users: \"$(awk -F: '($1 == n) {print $1 }' n=$l_user /etc/passwd | xargs)\""
done < <(cut -f1 -d":" /etc/group | sort -n | uniq -c)

)

[ -z "$check" ] && { d1="No duplicate user names exist "; e="PASS"; } || { d1="$check"; e="FAIL"; }

b=$(printf "%s\n" "$b1" | sed 's/"/""/g') 

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

f='
Based on the results of the audit script, establish unique user names for the users. File
ownerships will automatically reflect the change as long as the users have unique UIDs'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="7.2.8 Ensure no duplicate group names exist "

#no output 

b='
Although the groupadd program will not let you create a duplicate group name, it is
possible for an administrator to manually edit the /etc/group file and change the group name.

Rationale:

If a group is assigned a duplicate group name, it will create and have access to files
with the first GID for that group in /etc/group . Effectively, the GID is shared, which is
a security problem.'

c='No duplicate group names exist'

check=$( 
while read -r l_count l_group; do
    [ "$l_count" -gt 1 ] && echo -e "Duplicate Group: \"$l_group\" Groups: \"$(awk -F: '($1 == n) { print $1 }' n=$l_group /etc/group | xargs)\""
done < <(cut -f1 -d":" /etc/group | sort | uniq -c)

)

[ -z "$check" ] && { d1="No duplicate group names exist"; e="PASS"; } || { d1="$check"; e="FAIL"; }

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

f='
Based on the results of the audit script, establish unique names for the user groups. File
group ownerships will automatically reflect the change as long as the groups have unique GIDs.'

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#----------------------------------------------------------------------------------------------------------------

a="7.2.9 Ensure local interactive user home directories are configured"

b="
The user home directory is space defined for the particular user to set local environment
variables and to store personal files. While the system administrator can establish
secure permissions for users' home directories, the users can easily override these.
Users can be defined in /etc/passwd without a home directory or with a home directory
that does not actually exist.

Rationale:

Since the user is accountable for files stored in the user home directory, the user must
be the owner of the directory. Group or world-writable user home directories may enable
malicious users to steal or modify other users' data or to gain another user's system
privileges. If the user's home directory does not exist or is unassigned, the user will be
placed in "/" and will not be able to write any files or have local environment variables set.

Ensure:
• local interactive user home directories exist
• Ensure local interactive users own their home directories
• Ensure local interactive user home directories are mode 750 or more restrictive"

c='Correctly configured'

d1=$(
l_output="" l_output2="" l_heout2="" l_hoout2="" l_haout2=""
l_valid_shells="^($( awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
unset a_uarr && a_uarr=() # Clear and initialize array

while read -r l_epu l_eph; do # Populate array with users and user home location
    a_uarr+=("$l_epu $l_eph")
done <<< "$(awk -v pat="$l_valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd)"

l_asize="${#a_uarr[@]}" # Here if we want to look at number of users before proceeding
[ "$l_asize " -gt "10000" ] && echo -e "\n ** INFO **\n - \"$l_asize\" Local interactive users found on the system\n - This may be a long running check\n"

while read -r l_user l_home; do
    [ -d "$l_home" ] && l_mask='0027' && l_max="$( printf '%o' $(( 0777 & ~$l_mask)) )" &&
    while read -r l_own l_mode; do
        [ "$l_user" != "$l_own" ] && l_hoout2="$l_hoout2\n - User: \"$l_user\" Home \"$l_home\" is owned by: \"$l_own\"" ||
        [ $(( $l_mode & $l_mask )) -gt 0 ] && l_haout2="$l_haout2\n - User: \"$l_user\" Home \"$l_home\" is mode: \"$l_mode\" should be mode: \"$l_max\" or more restrictive"
    done <<< "$(stat -Lc '%U %#a' "$l_home")" ||
    l_heout2="$l_heout2\n - User: \"$l_user\" Home \"$l_home\" Doesn't exist"
done <<< "$(printf '%s\n' "${a_uarr[@]}")"

[ -z "$l_heout2" ] && l_output="$l_output\n - home directories exist" || l_output2="$l_output2$l_heout2"
[ -z "$l_hoout2" ] && l_output="$l_output\n - own their home directory" || l_output2="$l_output2$l_hoout2"
[ -z "$l_haout2" ] && l_output="$l_output\n - home directories are mode: \"$l_max\" or more restrictive" || l_output2="$l_output2$l_haout2"

[ -n "$l_output" ] && l_output=" - All local interactive users:$l_output"
[ -z "$l_output2" ] && echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured *:\n$l_output" ||
{
    echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure *:\n$l_output2"
    [ -n "$l_output" ] && echo -e "\n- * Correctly configured *:\n$l_output"
}

)

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f="
If a local interactive users' home directory is undefined and/or doesn't exist, follow local
site policy and perform one of the following:

• Lock the user account
• Remove the user from the system
• create a directory for the user. If undefined, edit /etc/passwd and add the
absolute path to the directory to the last field of the user.

• Remove excessive permissions from local interactive users home directories
• Update the home directory's owner"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

sleep 1

#--------------------------------------------------------------------------------------------------------------------------------------

a="7.2.10 Ensure local interactive user dot files access is configured"

b1='
While the system administrator can establish secure permissions for users'"'"' dot" files,
the users can easily override these.
• .forward file specifies an email address to forward the user'"'"'s mail to.
• .rhost file provides the "remote authentication" database for the rcp, rlogin, and
rsh commands and the rcmd() function. These files bypass the standard
password-based user authentication mechanism. They specify remote hosts and
users that are considered trusted (i.e. are allowed to access the local system
without supplying a password)
• .netrc file contains data for logging into a remote host or passing authentication
to an API.
• .bash_history file keeps track of the user'"'"'s commands.
Rationale:
User configuration files with excessive or incorrect access may enable malicious users
to steal or modify other users'"'"' data or to gain another user'"'"'s system privileges.'


c='Access to dot files is configured'

d1=$(

a_output2=() a_output3=()
l_maxsize="1000" # Maximum number of local interactive users before warning (Default 1,000)
l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
a_user_and_home=() # Create array with local users and their home directories

while read -r l_local_user l_local_user_home; do # Populate array with users and user home location
    [[ -n "$l_local_user" && -n "$l_local_user_home" ]] && a_user_and_home+=("$l_local_user:$l_local_user_home")
done <<< "$(awk -v pat="$l_valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd)"

l_asize="${#a_user_and_home[@]}" # Here if we want to look at number of users before proceeding
[ "${#a_user_and_home[@]}" -gt "$l_maxsize" ] && printf '%s\n' "" " ** INFO **" \
    " - \"$l_asize\" Local interactive users found on the system" \
    " - This may be a long running check" ""

file_access_chk() {
    a_access_out=()
    l_max="$(printf '%o' $(( 0777 & ~$l_mask)) )"
    [ $(( $l_mode & $l_mask )) -gt 0 ] && a_access_out+=(" - File: \"$l_hdfile\" is mode: \"$l_mode\" and should be mode: \"$l_max\" or more restrictive")
    [[ ! "$l_owner" =~ ($l_user) ]] && a_access_out+=(" - File: \"$l_hdfile\" owned by: \"$l_owner\" and should be owned by \"${l_user//|/ or }\"")
    [[ ! "$l_gowner" =~ ($l_group) ]] && a_access_out+=(" - File: \"$l_hdfile\" group owned by: \"$l_gowner\" and should be group owned by \"${l_group//|/ or }\"")
}

while IFS=: read -r l_user l_home; do
    a_dot_file=() a_netrc=() a_netrc_warn=() a_bhout=() a_hdirout=()
    [ -d "$l_home" ] && l_group="$(id -gn "$l_user" | xargs)"; l_group="${l_group// /|}" &&
    while IFS= read -r -d $'\0' l_hdfile; do
        while read -r l_mode l_owner l_gowner; do
            case "$(basename "$l_hdfile")" in
                .forward | .rhosts ) a_dot_file+=(" - File: \"$l_hdfile\" exists") ;;
                .netrc )
                    l_mask='0177'; file_access_chk
                    [ "${#a_access_out[@]}" -gt 0 ] && a_netrc+=("${a_access_out[@]}") || a_netrc_warn+=(" - File: \"$l_hdfile\" exists") ;;
                .bash_history )
                    l_mask='0177'; file_access_chk
                    [ "${#a_access_out[@]}" -gt 0 ] && a_bhout+=("${a_access_out[@]}") ;;
                * )
                    l_mask='0133'; file_access_chk
                    [ "${#a_access_out[@]}" -gt 0 ] && a_hdirout+=("${a_access_out[@]}") ;;
            esac
        done < <(stat -Lc '%#a %U %G' "$l_hdfile")
    done < <(find "$l_home" -xdev -type f -name '.*' -print0)
    
    ([[ "${#a_dot_file[@]}" -gt 0 ]] || [[ "${#a_netrc[@]}" -gt 0 ]] || [[ "${#a_bhout[@]}" -gt 0 ]] || [[ "${#a_hdirout[@]}" -gt 0 ]]) &&
    a_output2+=(" - User: \"$l_user\" Home Directory: \"$l_home\"" "${a_dot_file[@]}" "${a_netrc[@]}" "${a_bhout[@]}" "${a_hdirout[@]}") &&
    [ "${#a_netrc_warn[@]}" -gt 0 ] && a_output3+=(" - User: \"$l_user\" Home Directory: \"$l_home\"" "${a_netrc_warn[@]}")
done <<< "$(printf '%s\n' "${a_user_and_home[@]}")"

[ "${#a_output2[@]}" -le 0 ] && (
    [ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' " ** WARNING **" "${a_output3[@]}" &&
    printf '%s\n' "Access to dot files is configured"
) || (
    printf '%s\n' "- Audit Result:" " ** FAIL **" " - * Reasons for audit failure * :" "${a_output2[@]}" ""
    [ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' " ** WARNING **" "${a_output3[@]}"
)

)

b=$(printf "%s\n" "$b1" | sed 's/"/""/g') 

d=$(printf "%s\n" "$d1" | sed 's/"/""/g') 

echo "$d1" | grep -qE "PASS" && e="PASS" || e="FAIL"

f="
Making global modifications to users' files without alerting the user community can result
in unexpected outages and unhappy users. Therefore, it is recommended that a
monitoring policy be established to report user dot file permissions and determine the
action to be taken in accordance with site policy.
The following script will:
• remove excessive permissions on dot files within interactive users' home directories
• change ownership of dot files within interactive users' home directories to the user
• change group ownership of dot files within interactive users' home directories to the user's primary group
• list .forward and .rhost files to be investigated and manually deleted"

echo "\"$a\",\"$b\",\"$c\",\"$d\",\"$e\",\"$f\"" >>$csv_file

#--------------------------------------------------------------------------------------------------------------------------------------

echo "------------------------------------------------AUDIT COMPLETED----------------------------------------"
echo -e "\n                  Check for a file named 'Results.csv' in the same folder of ubuntu.sh \n"

























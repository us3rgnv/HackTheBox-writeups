HackTheBox — Abducted
Overview
FieldDetailsOSLinux (Ubuntu)DifficultyMediumUser FlagVia SSH as scottRoot FlagVia systemd drop-in + polkit
Attack Chain
nmap → SMB Enumeration → CVE-2026-4480 RCE (nobody)
→ rclone credentials (scott) → SMB Symlink Attack (marcus)
→ systemd drop-in + polkit (root)
Files

writeup.md — Full step-by-step walkthrough

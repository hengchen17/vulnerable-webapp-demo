# PoC: Insecure Direct Object Reference (IDOR) — Salary Disclosure

## Location
`GET /profile?employee_id=` in `app.py`

## Root cause
```python
employee_id = request.args.get("employee_id", session["user_id"])
user = db.execute("SELECT * FROM users WHERE id = ?", (employee_id,)).fetchone()
```
The route trusts the `employee_id` query parameter with no check that it
matches the logged-in user, and no role-based access check.

## Exploitation

1. Log in as a normal employee (`alice` / `alice123`).
2. Visit your own profile: `/profile?employee_id=1` (works normally).
3. Change the parameter to another user's id, e.g. the admin account:
   `/profile?employee_id=3`

The response discloses the admin's department and **salary**, with no
authorization check at all.

### curl
```bash
curl -c cookies.txt -X POST http://127.0.0.1:5000/login -d "username=alice" -d "password=alice123"
curl -b cookies.txt "http://127.0.0.1:5000/profile?employee_id=3"
```

## Impact
Any authenticated employee can enumerate `employee_id` values (they're
sequential integers) and read every other employee's salary and department —
a serious confidentiality breach and a common real-world finding in HR/payroll
systems.

## Verified

Reproduced locally against the `vulnerable` branch (port 5000): logged in as
`alice` (`employee_id=1`), then requested `/profile?employee_id=3` and
successfully viewed the admin account's department and $120,000 salary with
no error or access check.

Re-tested against the `patched` branch (port 5001): the same request returns
`403 Forbidden — admin only.` while `alice` can still view her own profile
normally.

## Fix (see `patched` branch)
Enforce ownership or role at the server:
```python
if employee_id != str(session["user_id"]) and session.get("role") != "admin":
    abort(403)
```
More generally: never trust a client-supplied identifier as the sole access
check — always re-verify that the current session is authorized to view the
requested resource.

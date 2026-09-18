# Vulnerable Web App Demo — Acme Corp Employee Portal

A deliberately vulnerable Flask web app for security education and portfolio
purposes. This is the **`vulnerable`** branch — see the `patched` branch for
the fixed version of the same app.

⚠️ **Do not deploy this publicly or reuse this code in production.** It exists
solely to demonstrate, exploit, and then patch a set of classic web
vulnerabilities in a single connected attack chain.

## Scenario

An internal employee portal (`Acme Corp`) with a login page, employee profile
pages, an internal bulletin board, and a beta "AI assistant" that summarizes
messages. Each feature contains one intentional vulnerability, and together
they form a single attack chain from anonymous visitor to admin-level data
disclosure.

## Vulnerabilities

| # | Vulnerability | Location | OWASP Category |
|---|---|---|---|
| 1 | SQL Injection | `POST /login` | A03:2021 – Injection |
| 2 | IDOR | `GET /profile?employee_id=` | A01:2021 – Broken Access Control |
| 3 | Stored XSS | `POST /board` | A03:2021 – Injection |
| 4 | Prompt Injection | `POST /assistant` | LLM01 (OWASP Top 10 for LLM Apps) |

Full exploitation walkthroughs (PoC) for each are in [`docs/`](docs/):

- [docs/POC_SQLI.md](docs/POC_SQLI.md)
- [docs/POC_IDOR.md](docs/POC_IDOR.md)
- [docs/POC_XSS.md](docs/POC_XSS.md)
- [docs/POC_PROMPT_INJECTION.md](docs/POC_PROMPT_INJECTION.md)

## Attack chain

1. **SQLi** bypasses login with no valid credentials (`' -- ` as username).
2. Logged in as a low-privilege employee, **IDOR** on `/profile?employee_id=`
   exposes every other employee's salary — including the admin account.
3. A **stored XSS** payload on `/board` can hijack an admin's session cookie
   when they view the page.
4. The beta **AI assistant** has no separation between trusted instructions
   and user input, so a crafted message makes it leak the admin's flag/salary
   directly — no session hijacking needed.

Each vector reaches the same target: the confidential flag stored on the
admin account, retrievable via `/admin` once role=admin is obtained.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

The app seeds a fresh SQLite DB (`vulnerable.db`) on first run with three
demo accounts:

| username | password | role |
|---|---|---|
| alice | alice123 | employee |
| bob | bob123 | employee |
| admin | SuperSecretAdminPW! | admin |

Visit `http://127.0.0.1:5000`.

## Branches

- `vulnerable` (this branch) — intentionally insecure implementation.
- `patched` — same app, each vulnerability fixed, with the specific fix
  explained in that branch's README.

## Notes on the AI assistant

The "AI assistant" is currently a **mock function** (`mock_ai_summarize` in
`app.py`) that simulates how an unguarded LLM call would behave when given
untrusted user input mixed into its context — it is not wired to a real LLM
API yet. The vulnerability (no instruction/data separation) and its fix
generalize directly to a real API integration.

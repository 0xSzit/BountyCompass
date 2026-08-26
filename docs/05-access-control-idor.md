# 5. Access Control & IDOR

## IDOR

- Find and replace IDs in URLs, headers, or body with another user's ID.
- **Parameter pollution:** `user=1` → `user=1&user=2`.
- **Special characters:** `/user/01*` or `/user/*` → sometimes discloses all users.
- Try older API versions: `/api/v3/user/1` → `/api/v1/user/2`.
- **Add an extension:** `/user/1` → `/user/1.json`.
- **Change the request method:** `POST /user/1` → `GET`, `PUT`, `PATCH`, `DELETE`, etc.
- Check whether the `Referer` header or another header is (wrongly) used to validate the ID.
- **Encrypted IDs:** if the app uses encrypted identifiers, try known-hash-cracking services or other tools to decrypt them.
- **Replace GUID/UUID with a numeric ID or email:** `/user/{uuid}` → `/user/1` or `/user/name@example.com`.
- Try well-known placeholder GUIDs: `00000000-0000-0000-0000-000000000000` and `11111111-1111-1111-1111-111111111111`.
- **GUID enumeration:** search Google Dorks, GitHub, Wayback, and your own Burp history for leaked GUIDs.
- If GUID enumeration comes up empty, check signup, password reset, and other endpoint responses — they frequently disclose the current user's GUID.
- **403/401 bypass via brute force:** use Burp Intruder to send 50–100 requests across a range of IDs (e.g. `/user/1` through `/user/100`) — some apps only block a subset.
- If the server returns 403/401, double-check whether the underlying action was actually performed anyway — some apps throw the error but still execute the request.
- **Blind IDORs:** information isn't always disclosed directly. Watch for exports, emails, or message/notification alerts that leak data indirectly.
- **Chain IDOR with XSS** for full account takeover.

## Access Control Vulnerabilities

Treat every role/permission boundary as untrusted client input until proven otherwise. Combine this section with the API manipulation techniques in [API & Session Security](03-api-session-security.md) (ID wrapping, version rollback, method switching) — most access-control bugs surface from exactly those manipulations applied to authorization-sensitive endpoints.

# 2. Authentication & Account Security

Checklist for signup, email verification, password reset, login, and OTP/2FA flows — the highest-value target surface on most programs.

---

## Signup

- Sign up via a third-party provider (Google/Facebook/etc.), log out, then sign up again with email. Can you access the account created via third-party login? Did the new password take effect?
- **Pre-Account-Takeover:** sign up using the victim's email address and a password of your choosing. When the victim later signs up via a third-party provider, check whether your password still works on their account.
- Sign up with an email address ending in the target's own domain — e.g. if the target is `google.com`, try `you@google.com`.
- Overwrite an existing user via capitalization, whitespace, encoding, or the `+` sign in the email address.
- DoS via long strings in input fields.
- No rate limiting on the signup endpoint.
- XSS in registration form fields.
- Inspect the signup request for a role parameter — e.g. `"role":"user"` → try `"role":"admin"`. If present, check JS files for the full list of valid role values.

## Email Verification

- Attempt to bypass email verification entirely.
- Response manipulation — flip `false` to `true`, `403` to `200`, or hit endpoints that should only be reachable post-verification.

## Password Reset

- **Host header injection → one-click ATO:** try a duplicate `Host` header, and headers like `X-Forwarded-Host`, `X-Forwarded-For`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`, `X-Host`.
- **Parameter pollution:** `email=victim@yahoo.com&email=hacker@yahoo.com`, or `{"email":["victim@yahoo.com","hacker@yahoo.com"]}`.
- **Array-based code guessing:** `{"code":["111111","222222","333333", ...]}`.
- Reset links/codes that don't expire after the password is actually changed.
- Old reset links/codes that remain valid after requesting new ones.
- Reset links/codes that remain valid after changing the password from account settings.
- Reset links/codes that remain valid after changing the account email address.
- **IDOR in the reset flow:** substituting the victim's email in the reset request lets you change *their* password (missing authorization check).
- Reset link leaked via the `Referer` header.
- App not validating the provided email/phone during reset — check if it's silently reading the value from the session instead.
- Reset link/token/code leaked in an API response — search your proxy history for the code you received by mail.
- No rate limit on password reset → OTP brute-force.
- **JSON type confusion:** if the request body is JSON, try replacing the reset token/code with `"token": true`, `"token": false`, or `"token": null` — see [JSON Type Confusion](03-api-session-security.md#json-type-confusion--type-juggling) for the full technique.
- Resetting the password doesn't expire previous sessions.
- Weak/predictable cryptography used to generate reset tokens.
- User enumeration via the password-reset or signup response (different messages for existing vs. non-existing accounts, timing differences, etc.).
- SQL injection, XSS, and HTML injection in reset-flow fields (including the reset email template itself).

## Login

- SQL injection.
- Authentication bypass (logic flaws, JWT issues — see [API & Session Security](03-api-session-security.md)).
- XSS.

## OTP / 2FA

- Response manipulation — flip a `false` result to `true` (or any other successful response shape).
- Status code manipulation — `403` to `200` (or another successful code).
- OTP code leaked in the response body.
- Check JS files — rare, but some leak information about the verification logic.
- **Code reusability:** test whether an already-used code can be reused.
- Lack of brute-force protection / rate limiting on the code field.
- **Missing integrity binding:** does the 2FA code for *any* account work when submitted against a different account's session?
- CSRF on the "disable 2FA" action.
- Does resetting the password or changing the email address silently disable 2FA?
- **Bypass with degenerate values:** try `000000`, `true`, `false`, `null`, or removing the parameter entirely.
- Does enabling 2FA fail to expire previous (pre-2FA) sessions?
- Direct access to post-2FA pages by spoofing the `Referer` header as if you came from the confirmation step.
- 2FA bypass via headers: `X-Forwarded-Host`, `X-Forwarded-For`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`, `X-Host`.
- **Array-based code acceptance:** `{"code":["1000","1001","1002", ..., "9999"]}`.

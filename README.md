# 🧭 BountyCompass

**A structured, practical field manual for web application bug bounty hunting** — recon pipelines, vulnerability checklists, and exploitation methodology, organized so you can actually use it mid-engagement instead of scrolling through a wall of notes.

<p align="left">
  <img src="https://img.shields.io/badge/status-active-brightgreen" alt="status">
  <img src="https://img.shields.io/badge/scope-authorized%20testing%20only-red" alt="scope">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="license">
  <img src="https://img.shields.io/badge/PRs-welcome-orange" alt="prs welcome">
</p>

---

## ⚠️ Read This First

Everything in this repository is intended **exclusively** for:

- Targets you **own**, or
- Targets where you have **explicit, written authorization** to test (an active bug bounty program, a signed pentest engagement, a CTF/lab environment, etc.)

Several techniques described here are **active/intrusive** (fuzzing, injection payloads, write tests via HTTP `PUT`). Running them against systems you are not authorized to test is illegal in most jurisdictions. Always check the program's scope and rules of engagement before running anything active. Passive recon (subdomain enumeration, archive pulls, takeover checks) is read-only and lower-risk, but scope rules still apply.

This repository is a **methodology and checklist reference**, not a tool. It doesn't automate attacks — it tells you what to try, why, and how to interpret the result.

---

## 📚 Table of Contents

| # | Section | Covers |
|---|---------|--------|
| 1 | [Recon & Scoping](...) | Subdomain enum, httpx, vhost fuzzing, DNS brute-force/permutation, JS endpoint mining, takeover checks, Nuclei, archive/URL collection, content discovery, `.git` exposure, API/spec discovery — the full 20-stage pipeline in order
| 2 | [Authentication & Account Security](docs/02-authentication-account-security.md) | Signup abuse, pre-account-takeover, email verification bypass, password reset flaws, login, OTP/2FA bypass |
| 3 | [API & Session Security](docs/03-api-session-security.md) | API manipulation techniques, JSON type confusion / type juggling, JWT misconfigurations |
| 4 | [Injection & XSS](docs/04-injection-xss.md) | SQL injection, XSS, SSTI — detection payloads and confirmation methodology |
| 5 | [Access Control & IDOR](docs/05-access-control-idor.md) | IDOR hunting techniques, GUID/UUID enumeration, 403/401 bypass patterns |
| 6 | [File Upload & Other Vulnerabilities](docs/06-file-upload-other-vulns.md) | File upload attack surface, extension/blacklist/whitelist bypasses, CAPTCHA bypass, CSRF, open redirect, rate-limit bypass |
| 7 | [OSINT & Leak Hunting](docs/07-osint-leak-hunting.md) | External sources for finding leaked credentials, exposed assets, and historical data |

---

## 🗺️ Suggested Workflow

```
Recon & Scoping (Section 1)
        │
        ▼
Authentication & Session Testing (Sections 2–3)
        │
        ▼
Injection & Access Control Testing (Sections 4–5)
        │
        ▼
File Upload / Misc Checks (Section 6)
        │
        ▼
OSINT Cross-Reference (Section 7)
```

In practice these overlap — recon output (live hosts, parameters, endpoints) feeds every later stage, and OSINT is worth revisiting throughout an engagement, not just at the start.

---

## 🤝 Contributing

Found a technique that's missing, outdated, or could be explained more clearly? Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## 📄 License

Released under the [MIT License](LICENSE). Use responsibly.

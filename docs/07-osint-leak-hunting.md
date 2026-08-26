# 7. OSINT & Leak Hunting

External sources worth checking throughout an engagement — not just at the start — for leaked credentials, exposed infrastructure, and historical artifacts tied to the target.

| Source | What to look for |
|---|---|
| **VirusTotal** | Passive DNS, related domains/subdomains, historical file/URL relationships |
| **GitHub** | Leaked API keys, credentials, internal hostnames, config files committed by employees or in old commits/branches |
| **Shodan** | Exposed services, open ports, banners, misconfigured infrastructure tied to the target's ASN/IP ranges |
| **AlienVault OTX** | Threat intel pulses referencing the target's domains/IPs |
| **URLScan.io** | Historical scans of the target's pages — can reveal old parameters, redirects, and third-party resources |
| **Censys** | Certificate transparency data, exposed hosts and services across the target's infrastructure |

These pair naturally with the archive-pull stages in [Recon & Scoping](01-recon-and-scoping.md) (Stage 6, Stage 12) — OSINT sources often surface the seed URLs and hostnames that Wayback/waymore/gau pulls then expand on.

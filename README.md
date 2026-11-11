# Email Health Audit

A free, single-page audit of a domain's email DNS setup with an overall A to F grade. Live at [email.hbenali.ovh](https://email.hbenali.ovh).

No backend, no build step, no dependencies: static HTML, CSS and one small script calling a public DNS-over-HTTPS API from the browser.

## What it checks

| Area | Checks |
| --- | --- |
| MX | records present, null MX (RFC 7505), every host resolves, no CNAME or IP target, no private address |
| SPF | exactly one `v=spf1` record, ends in `-all` or `~all`, `+all` and `ptr` flagged, DNS-lookup mechanisms counted through the include chain (warn above 10) |
| DKIM | 13 common selectors probed (default, google, selector1, selector2, k1, k2, s1, s2, mail, dkim, smtp, mandrill, zoho); key type and RSA length parsed. A missing selector is not a failure. |
| DMARC | `p=`, `sp=`, `pct=`, `rua`/`ruf`, alignment, `p=none` warning, external `rua` authorization record |
| BIMI | `default._bimi` record (not scored) |
| MTA-STS, TLS-RPT | TXT records only |
| DNSSEC | AD flag reported by Google Public DNS |

Every finding has a level (pass, warn, fail, info) and a one-line fix hint, and each area links to the dedicated sibling tool for the same domain.

## The grade is a heuristic

The score weights MX 15, SPF 25, DKIM 15, DMARC 30, MTA-STS 4, TLS-RPT 3 and DNSSEC 8 points; areas that do not apply or could not be looked up are left out. A to F start at 85, 70, 55 and 40 points, and a failure in MX, SPF or DMARC caps the grade at C. It is an opinion about DNS records, not a standard and not a deliverability guarantee.

## What a browser cannot do

- Fetch the MTA-STS policy file (CORS), so only the TXT record is checked
- Open SMTP or TLS connections, query blocklists or measure sender reputation
- List a DNS zone, so DKIM selectors are probed from a fixed list

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

`?domain=example.com` runs the audit on load.

## Data sources

- [dns.google](https://developers.google.com/speed/public-dns/docs/doh): DNS-over-HTTPS for all lookups

## Deployment

GitHub Pages, deployed on every push to `main` (see `.github/workflows/`).

## License

MIT, see [LICENSE](LICENSE).

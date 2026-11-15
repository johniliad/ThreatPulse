# Security policy

ThreatPulse is a public, read-only cyber threat intelligence product. Security
matters here twice over: the site and API are reachable by anyone, and the data
they serve is relied on by people making remediation decisions. This page states
how to report a problem, what is in scope, what you can expect in return, and the
commitments made to researchers who report in good faith.

The machine-readable version of this policy, as defined by
[RFC 9116](https://www.rfc-editor.org/rfc/rfc9116), is served at
<https://threatpulse.iliadis.net/.well-known/security.txt>. It carries the same
contacts and expires on the date recorded there; this page is the authoritative
human-readable version.

## Supported versions

ThreatPulse is deployed continuously from the `main` branch. Only the latest
release receives security fixes; there are no maintained older branches.

| Version | Supported |
| --- | --- |
| 1.0.x | yes |
| earlier | no |

## Reporting a vulnerability

Please **do not** open a public issue, and do not publish proof-of-concept details
before a fix is available. Two private channels are provided; either is acceptable.

1. **GitHub private vulnerability reporting (preferred).** Open the repository's
   Security tab and choose *Report a vulnerability*:
   <https://github.com/johniliad/ThreatPulse/security/advisories/new>. This creates
   a private advisory that only the maintainer can see, and keeps the discussion,
   the proof of concept and the fix in one place.
2. **Email** `john@iliadis.net`, with `ThreatPulse security` in the subject. Use
   this if GitHub is unavailable, you do not have an account, or you prefer email.

Please include:

- **what you found** and where — the URL, endpoint or file;
- **how to reproduce it** — the request, the steps, or a minimal proof of concept;
- **the impact you believe it has**, including what an attacker gains;
- **how you would like to be credited**, or say "no credit".

Please do not send real user data, other people's personal information, or data
taken from a third party. ThreatPulse holds no user accounts and no personal data,
so there is no need to exfiltrate anything to demonstrate a finding: a minimal
proof is enough.

There is no published PGP key at present. If you need to send something sensitive,
email first and ask; do not attach secrets to an unsolicited message.

## What you can expect

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | within 3 working days |
| Initial assessment: severity, scope, and whether it is a vulnerability | within 10 working days |
| Fix or documented mitigation for a confirmed critical or high issue | within 30 days |
| Coordinated public disclosure | by agreement; 90 days after the report by default |

These are targets, not contractual guarantees: this is an independently funded,
single-maintainer project, and a fix can depend on a third party (PHP, Apache,
Cloudflare, cPanel). Where a fix will take longer, you will be told why and given
the mitigation in the meantime. If a report cannot be reproduced, is out of scope,
or is a known issue, you will be told that too, with the reasoning.

## Coordinated disclosure

We ask for a reasonable window between the report and publication, and we will not
ask for silence indefinitely.

- The default window is **90 days** from the report.
- If a fix ships earlier, a disclosure date is agreed with you and the advisory is
  published then.
- If the issue cannot be fixed within the window, you will be told what is being
  done, what the interim mitigation is, and when the next update will come.
- Credit is given in the advisory and in `CHANGELOG.md` unless you ask to remain
  anonymous. If you would like a link to your profile or site, say so.

## Safe harbour

We will not initiate or support legal action against researchers who:

- act in good faith, and only as far as needed to demonstrate the issue;
- do not access, modify, exfiltrate or retain data that is not their own, and do
  not degrade the service for other people;
- do not test against third-party data, and do not run denial-of-service, spam,
  phishing or social-engineering campaigns;
- report privately, and give a reasonable opportunity to fix the issue before any
  public disclosure;
- comply with applicable law.

This is a statement of intent, not a contract. It does not bind third parties such
as the hosting provider or the network operator, and it does not override the law.

## Scope

In scope:

- the public site at <https://threatpulse.iliadis.net/> and its static assets;
- the read API under `/api/cti/v1/` — every endpoint, including parameter handling,
  JSON output and CORS behaviour;
- the authentication and authorisation of `publish.php` (a bypass or a token leak,
  not a token you were never given);
- the pipeline in `backend/` — collectors, normalisers, correlation, scoring and the
  quality gate — for injection, unsafe deserialisation, SSRF, path traversal and
  similar classes of defect;
- the deployment assets in `deployment/` and the `.htaccess` files, where a rule
  fails open or can be bypassed.

Out of scope:

- findings that require a compromised device, a malicious browser extension or
  physical access;
- volumetric denial of service, stress testing, and observations about rate limits
  with no demonstrated impact;
- scanner output with no demonstrated impact — a missing header, a banner or a TLS
  preference is not by itself a vulnerability. If you believe one is exploitable
  here, say how, and it becomes in scope;
- the accuracy of third-party threat intelligence (a wrong CVE, a stale advisory, a
  disputed attribution). That is a data question: use the Sources page or open a
  normal issue;
- third-party services themselves (Cloudflare, the cPanel host, GitHub) — report
  those to the provider;
- social engineering, phishing simulations and physical attacks.

If you are unsure whether something is in scope, report it and ask. The list exists
to keep reports actionable, not to discourage them.

## No bug bounty

There is no paid bounty. ThreatPulse is independently funded and has no security
budget to distribute. Reports are still valued, are answered, and are credited.

## Credit

With your permission, the advisory and `CHANGELOG.md` will name you (or your
organisation) and describe the issue and the fix. If you prefer to remain
anonymous, that preference is recorded and respected.

## Non-security issues

- **Bugs and features:** open a normal GitHub issue.
- **Data corrections:** the Sources page lists where each record came from; the
  provider is the authority on its own advisory.
- **This policy:** disagreements about scope or process are worth raising — email
  the address above rather than opening an issue.

## Changes to this policy

This policy is reviewed when the deployment model changes. Last reviewed
15 November 2026.

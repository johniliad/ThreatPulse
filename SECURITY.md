# Security policy

## Supported versions

ThreatPulse is deployed continuously from the `main` branch. Only the latest
release receives fixes; there are no maintained older branches.

| Version | Supported |
| --- | --- |
| 1.0.x | yes |
| earlier | no |

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub private vulnerability reporting on this repository (Security, then
"Report a vulnerability"), or email john@iliadis.net with:

- what you found and where (URL or file),
- how to reproduce it,
- the impact you believe it has.

You can expect an acknowledgement within a few days. Please allow a reasonable
window for a fix before any public disclosure.

## Scope

In scope: the public site at threatpulse.iliadis.net, the read API under
`/api/cti/v1/`, the pipeline in `backend/`, and the deployment assets in
`deployment/`.

Out of scope: findings that require a compromised device or browser extension,
volumetric denial of service, scanner output with no demonstrated impact, and the
accuracy of third-party threat intelligence, which is a data question rather than
a vulnerability.
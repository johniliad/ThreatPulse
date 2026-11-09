# api-backups — pre-change copies of the public API

This project is not under version control, so the three files changed for the
CVE → threat resolution enhancement were copied here first:

| Backup | Replaces |
| --- | --- |
| `threats.php.before-cve-filter` | `api/cti/v1/threats.php` |
| `vulnerabilities.php.before-threat-relationship` | `api/cti/v1/vulnerabilities.php` |
| `index.php.before-discovery-update` | `api/cti/v1/index.php` |

**Do not deploy this directory.** It contains a copy of the API source and
must never be placed inside the web root.

To roll back, copy a backup over the corresponding file in
`api/cti/v1/` (dropping the `.before-*` suffix) and redeploy it.

Files that were **not** modified: `db.php`, `status.php`, `threat.php`,
`sources.php`, `publications.php`, `publish.php`.

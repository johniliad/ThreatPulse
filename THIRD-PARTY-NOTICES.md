# Third-party notices

ThreatPulse source code is licensed under the Apache License 2.0 (see `LICENSE`).
This file lists what it bundles, depends on and republishes, and the notices that
must travel with it.

## 1. Code shipped to browsers

The production build (`frontend/dist/`) contains these packages. They are MIT
licensed, which requires that the copyright notice and this permission notice be
included in all copies of the software — including minified bundles, which is why
this section exists.

| Package | Version | Copyright |
| --- | --- | --- |
| `react` | 19.3.1 | Copyright (c) Meta Platforms, Inc. and affiliates. |
| `react-dom` | 19.3.1 | Copyright (c) Meta Platforms, Inc. and affiliates. |
| `scheduler` | 0.28.0 | Copyright (c) Meta Platforms, Inc. and affiliates. |
| `react-router` | 7.18.5 | Copyright (c) React Training LLC 2015-2019; Remix Software Inc. 2020-2021; Shopify Inc. 2022-2023 |
| `react-router-dom` | 7.18.5 | Copyright (c) React Training LLC 2015-2019; Remix Software Inc. 2020-2021; Shopify Inc. 2022-2023 |
| `cookie` | 1.1.1 | Copyright (c) 2012-2014 Roman Shtylman; 2015 Douglas Christopher Wilson |

MIT License (applies to every package in the table above)

```text
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## 2. Build and test tooling (not distributed)

These run on a developer machine only. Nothing here ships to a visitor, so no
notice is owed to them; they are listed so the inventory is complete.

| Package | Licence |
| --- | --- |
| `typescript` | Apache-2.0 |
| `vite`, `vitest`, `jsdom`, `@vitejs/plugin-react`, `@testing-library/*`, `@types/*` | MIT |

## 3. Backend

The pipeline in `backend/` is Python standard library only: no third-party
packages, no vendored modules, no lockfile. There is nothing to attribute.

## 4. Data and content sources

ThreatPulse collects and republishes derived intelligence. The data is **not**
covered by the Apache License 2.0 and stays subject to each provider terms. This
table is generated from `backend/data/attribution.json`; that file is the
authoritative register and is published by the API at
`/api/cti/v1/attribution.php`.

| Source key | Provider | Licence | Terms |
| --- | --- | --- | --- |
| `cisa_kev` | Cybersecurity and Infrastructure Security Agency (CISA), United States | US Government work — not subject to copyright protection in the United States (17 U.S.C. §105) | [https://www.cisa.gov/about/legal](https://www.cisa.gov/about/legal) |
| `cisa_advisories` | Cybersecurity and Infrastructure Security Agency (CISA), United States | US Government work — not subject to copyright protection in the United States (17 U.S.C. §105) | [https://www.cisa.gov/about/legal](https://www.cisa.gov/about/legal) |
| `cisa_csaf` | Cybersecurity and Infrastructure Security Agency (CISA), United States | US Government work — not subject to copyright protection in the United States (17 U.S.C. §105) | [https://www.cisa.gov/about/legal](https://www.cisa.gov/about/legal) |
| `cert_eu_advisories` | CERT-EU — Computer Emergency Response Team for the EU institutions, bodies and agencies | CERT-EU legal notice — public advisories published for reuse with attribution | [https://www.cert.europa.eu/legal-notice](https://www.cert.europa.eu/legal-notice) |
| `cert_eu_threat_intel` | CERT-EU — Computer Emergency Response Team for the EU institutions, bodies and agencies | CERT-EU legal notice — public reports published for reuse with attribution | [https://www.cert.europa.eu/legal-notice](https://www.cert.europa.eu/legal-notice) |
| `enisa_euvd` | European Union Agency for Cybersecurity (ENISA) | ENISA public vulnerability data — reuse permitted with attribution to ENISA | [https://euvd.enisa.europa.eu/](https://euvd.enisa.europa.eu/) |
| `epss_first` | FIRST — Forum of Incident Response and Security Teams | Provided free of charge by FIRST for vulnerability prioritisation; attribution to FIRST and the EPSS model authors required | [https://www.first.org/epss/](https://www.first.org/epss/) |
| `circl_vulnerability_lookup` | CIRCL — Computer Incident Response Center Luxembourg | Aggregated public vulnerability data; the Vulnerability-Lookup software is AGPL-3.0. Upstream sources (cvelistv5, NVD, GitHub advisories, CISA KEV) retain their own terms | [https://www.gnu.org/licenses/agpl-3.0.html](https://www.gnu.org/licenses/agpl-3.0.html) |
| `cisa_vulnrichment` | Cybersecurity and Infrastructure Security Agency (CISA), United States | US Government work — public domain (verify the repository licence at first ingest) | [https://github.com/cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) |
| `mitre_attack` | The MITRE Corporation | MITRE ATT&CK is released under the MITRE ATT&CK terms of use; attribution to MITRE required | [https://attack.mitre.org/resources/legal/](https://attack.mitre.org/resources/legal/) |
| `ransomware_live` | Ransomware.live | Data provided free of charge; attribution and a link to ransomware.live required | [https://www.ransomware.live/](https://www.ransomware.live/) |
| `ncsa_greece` | National Cyber Security Authority (NCSA), Hellenic Republic | Greek public authority publication — reuse with attribution to the National Cyber Security Authority | [https://cyber.gov.gr/](https://cyber.gov.gr/) |
| `national_cert_feeds` | Multiple national CERTs/CSIRTs (EU/EEA and partner states) | Each national CERT publishes under its own government reuse terms; attribution to the individual CERT is required per item | [https://github.com/pulsedive/certrss](https://github.com/pulsedive/certrss) |
| `exploit_availability` | Offensive Security (Exploit-DB), ProjectDiscovery (Nuclei), Rapid7 (Metasploit), GitHub PoC repositories | Mixed: Exploit-DB is GPL-2.0, Nuclei templates are MIT, Metasploit is BSD-3-Clause, public PoC repositories vary per repository | [https://gitlab.com/exploit-database/exploitdb/-/blob/master/LICENSE.md](https://gitlab.com/exploit-database/exploitdb/-/blob/master/LICENSE.md) |
| `osv_dev` | Google (OSV), aggregating ecosystem advisory databases | OSV data is provided under CC-BY-4.0; underlying advisories retain their own licences | [https://osv.dev/docs/](https://osv.dev/docs/) |
| `redhat_security` | Red Hat, Inc. | Red Hat security data — reuse permitted with attribution to Red Hat | [https://www.redhat.com/en/about/terms-use](https://www.redhat.com/en/about/terms-use) |
| `spamhaus_drop` | The Spamhaus Project | Free for use in security products and services with attribution to The Spamhaus Project; commercial redistribution requires a Spamhaus data licence | [https://www.spamhaus.org/organization/terms-of-use/](https://www.spamhaus.org/organization/terms-of-use/) |
| `sans_isc` | SANS Technology Institute — Internet Storm Center | DShield data provided by the SANS Internet Storm Center for community use with attribution | [https://isc.sans.edu/](https://isc.sans.edu/) |
| `vendor_advisories` | Multiple vendors, including Microsoft, Cisco, Fortinet, Ivanti, Oracle, Adobe, Atlassian, GitLab, SAP, Apache, VMware, JetBrains, WordPress and Linux distributions | Each vendor publishes under its own advisory terms; attribution to the publishing vendor is required per item | [https://www.microsoft.com/en-us/legal/intellectualproperty/copyright](https://www.microsoft.com/en-us/legal/intellectualproperty/copyright) |
| `cwe` | The MITRE Corporation | CWE is made available royalty-free by MITRE with attribution | [https://cwe.mitre.org/about/termsofuse.html](https://cwe.mitre.org/about/termsofuse.html) |
| `sigma_rules` | SigmaHQ community project | Detection Rule License (DRL) 1.1 | [https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md](https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md) |
| `misp_galaxy` | MISP project | MISP Galaxy cluster data — AGPL-3.0 project, reused with attribution | [https://www.gnu.org/licenses/agpl-3.0.html](https://www.gnu.org/licenses/agpl-3.0.html) |
| `fortinet_psirt` | Fortinet | Fortinet product security advisories, published openly for the use of Fortinet customers and the wider community | [https://www.fortinet.com/corporate/about-us/legal](https://www.fortinet.com/corporate/about-us/legal) |
| `wordpress_security` | WordPress (WordPress Foundation) | WordPress security announcements, published openly | [https://wordpress.org/about/license/](https://wordpress.org/about/license/) |
| `msrc` | Microsoft | Microsoft Security Update Guide data, published openly for Microsoft customers and the wider community | [https://www.microsoft.com/en-us/legal/terms-of-use](https://www.microsoft.com/en-us/legal/terms-of-use) |
| `circl_misp_osint` | CIRCL (Computer Incident Response Center Luxembourg) | Community-contributed MISP event data, published by CIRCL as an open feed | [https://www.circl.lu/](https://www.circl.lu/) |
| `capec` | MITRE | CAPEC is published by MITRE for public use with attribution | [https://capec.mitre.org/about/termsofuse.html](https://capec.mitre.org/about/termsofuse.html) |
| `cisco_security_advisories` | Cisco | Cisco publishes its security advisories publicly for the use of its customers and the wider community | [https://www.cisco.com/c/en/us/about/legal/terms-conditions.html](https://www.cisco.com/c/en/us/about/legal/terms-conditions.html) |
| `ubuntu_security` | Canonical | Canonical publishes its security notices publicly for the use of its users and the wider community | [https://ubuntu.com/legal](https://ubuntu.com/legal) |
| `sigma` | SigmaHQ | Sigma rules are published under the Detection Rule License (DRL) 1.1 | [https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md](https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md) |
| `nvd` | National Institute of Standards and Technology (NIST), United States | US Government work — public domain; API access is rate-limited and an API key is recommended | [https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications](https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications) |

### Required designations

- **MITRE ATT&CK**: any copy of ATT&CK content must reproduce MITRE copyright
designation and the licence. Required text: `© 2026 The MITRE Corporation. This
work is reproduced and distributed with the permission of The MITRE Corporation.`
- **FIRST EPSS**: MIT License, Copyright (c) 2022 FIRST.Org, Inc. The permission
notice above applies.
- **MISP Galaxy**: the JSON clusters are dual-licensed CC0 1.0 Universal or a
BSD-2-Clause-style licence. ThreatPulse attributes them to the MISP project and
relies on the CC0 option.
- **Sigma (DRL 1.1)**: ThreatPulse does not redistribute rule text. Only counts
and coverage derived from the rules are used; if rule text or match output were
ever exposed, the rule author would have to be credited alongside it.
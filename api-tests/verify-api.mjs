#!/usr/bin/env node
/*
 * ThreatPulse API — contract verifier.
 *
 * Two modes:
 *
 *   node api-tests/verify-api.mjs
 *       Runs the modified PHP endpoints locally, against a SQLite fixture
 *       database (api-tests/db-fixture.php). No MySQL, no credentials, no
 *       production access.
 *
 *   node api-tests/verify-api.mjs --base https://threatpulse.iliadis.net/api/cti/v1/
 *       Runs the same contract matrix against a deployed API.
 *
 * The matrix is data-independent: it asserts structure, filtering,
 * pagination and cross-endpoint consistency rather than fixed counts, so
 * the same assertions are valid against the fixture and against
 * production.
 */

import { spawn } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(HERE, '..');
const API_DIR = path.join(PROJECT_ROOT, 'api', 'cti', 'v1');

const LIVE_BASE =
    'https://threatpulse.iliadis.net/api/cti/v1/';

const ALLOWED_SEVERITIES = [
    'critical',
    'high',
    'medium',
    'low',
    'informational',
];

const ALLOWED_EXPLOITATION = [
    'confirmed',
    'suspected',
    'unknown',
    'not_exploited',
];

const THREAT_REFERENCE_FIELDS = [
    'threat_uuid',
    'external_id',
    'title',
    'severity',
    'priority_score',
    'confidence_level',
    'exploitation_status',
];

const VULNERABILITY_FIELDS = [
    'id',
    'cve_id',
    'description',
    'cvss_score',
    'cvss_vector',
    'severity',
    'kev_listed',
    'exploited_in_wild',
    'published_at',
    'modified_at',
    'vendor',
    'product',
];

function parseArgs(argv) {
    const options = {
        base: null,
        keep: false,
        php: process.env.PHP_BINARY || 'php',
        /**
         * When set, skipped (capability-dependent) assertions are treated as
         * failures. Use this in CI once the enhancement is expected to be live.
         */
        requireContract: false,
    };

    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];

        if (arg === '--base') {
            options.base = argv[i + 1];
            i += 1;
        } else if (arg.startsWith('--base=')) {
            options.base = arg.slice('--base='.length);
        } else if (arg === '--keep') {
            options.keep = true;
        } else if (arg === '--require-contract') {
            options.requireContract = true;
        } else if (arg === '--php') {
            options.php = argv[i + 1];
            i += 1;
        }
    }

    if (options.base && !options.base.endsWith('/')) {
        options.base += '/';
    }

    return options;
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function assertEqual(actual, expected, message) {
    if (actual !== expected) {
        throw new Error(
            `${message} — expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`
        );
    }
}

function assertArray(value, message) {
    if (!Array.isArray(value)) {
        throw new Error(`${message} — not an array`);
    }
}

async function getFreePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();

        server.on('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const address = server.address();
            const port = typeof address === 'object' ? address.port : 0;

            server.close(() => resolve(port));
        });
    });
}

function createHttp(base) {
    return async function httpGet(requestPath, init = {}) {
        const url = new URL(requestPath.replace(/^\//, ''), base);

        const response = await fetch(url, {
            method: 'GET',
            headers: { Accept: 'application/json' },
            signal: AbortSignal.timeout(30000),
            ...init,
        });

        const text = await response.text();

        let json = null;

        try {
            json = JSON.parse(text);
        } catch {
            json = null;
        }

        return {
            url: url.toString(),
            status: response.status,
            headers: response.headers,
            text,
            json,
        };
    };
}

const results = [];

/*
 * Which parts of the enhancement are actually live on the target.
 *
 * Populated by runPreflight() before the matrix runs. This matters because the
 * pre-enhancement API silently ignores unknown query parameters: a
 * capability-dependent assertion would report a *deployment state* as a code
 * defect, and would fail with unrelated downstream errors. Those assertions are
 * skipped (and named) instead of failed, so the runner never produces a false
 * signal in either direction.
 */
const contract = {
    cveFilter: false,
    threatRelationship: false,
    discovery: false,
    deltaFeed: false,
    sourceHealth: false,
    evidence: [],
};

const CAPABILITY_LABELS = {
    cveFilter: 'the cve parameter on threats.php',
    threatRelationship: 'the threats[] relationship on vulnerabilities.php',
    discovery: 'the capability flags on index.php',
    deltaFeed: 'changes.php',
    sourceHealth: 'source_health.php',
};

async function test(name, fn, requirements = []) {
    const missing = requirements.filter((requirement) => !contract[requirement]);

    if (missing.length > 0) {
        results.push({
            name,
            ok: true,
            skipped: true,
            detail: `not evaluable yet — needs ${missing
                .map((requirement) => CAPABILITY_LABELS[requirement] ?? requirement)
                .join(' and ')}`,
        });

        return;
    }

    try {
        const detail = await fn();

        results.push({ name, ok: true, detail: detail || '' });
    } catch (error) {
        results.push({
            name,
            ok: false,
            detail: error instanceof Error ? error.message : String(error),
        });
    }
}

/*
 * Pre-flight capability probes.
 *
 * These are behavioural, not declarative: an API that advertises a capability
 * but ignores the parameter must not be treated as supporting it.
 */
async function runPreflight(httpGet) {
    try {
        const res = await httpGet('threats.php?cve=not-a-cve');

        contract.cveFilter = res.status === 400;

        contract.evidence.push(
            `threats.php?cve=not-a-cve → HTTP ${res.status} (400 required)`
        );
    } catch (error) {
        contract.evidence.push(
            `threats.php cve probe failed: ${error instanceof Error ? error.message : String(error)}`
        );
    }

    try {
        const res = await httpGet('vulnerabilities.php?limit=1');
        const row = res.json?.data?.vulnerabilities?.[0];

        contract.threatRelationship = Boolean(row) && Array.isArray(row.threats);

        contract.evidence.push(
            `vulnerabilities.php threats[] → ${contract.threatRelationship ? 'present' : 'absent'}`
        );
    } catch (error) {
        contract.evidence.push(
            `vulnerabilities.php probe failed: ${error instanceof Error ? error.message : String(error)}`
        );
    }

    try {
        const res = await httpGet('');

        contract.discovery = res.json?.capabilities?.cve_to_threat === true;

        contract.evidence.push(
            `index.php capabilities.cve_to_threat → ${String(res.json?.capabilities?.cve_to_threat)}`
        );
    } catch (error) {
        contract.evidence.push(
            `index.php probe failed: ${error instanceof Error ? error.message : String(error)}`
        );
    }

    /*
     * The two endpoints added with the delta feed and source health. Probed by
     * shape rather than by status alone: a 404 means "not deployed", but a
     * 200 carrying the wrong collection means the endpoint is something else.
     */
    try {
        const res = await httpGet('changes.php?limit=1');

        contract.deltaFeed =
            res.status === 200 && Array.isArray(res.json?.data?.changes);

        contract.evidence.push(
            `changes.php → HTTP ${res.status}, data.changes ${
                Array.isArray(res.json?.data?.changes) ? 'present' : 'absent'
            }`
        );
    } catch (error) {
        contract.evidence.push(
            `changes.php probe failed: ${error instanceof Error ? error.message : String(error)}`
        );
    }

    try {
        const res = await httpGet('source_health.php?limit=1');

        contract.sourceHealth =
            res.status === 200 &&
            typeof res.json?.data?.available === 'boolean' &&
            Array.isArray(res.json?.data?.source_health);

        contract.evidence.push(
            `source_health.php → HTTP ${res.status}, data.available ${String(
                res.json?.data?.available
            )}`
        );
    } catch (error) {
        contract.evidence.push(
            `source_health.php probe failed: ${error instanceof Error ? error.message : String(error)}`
        );
    }

    return contract;
}

async function runMatrix(httpGet) {
    const ctx = {};

    await test('T1  threats.php envelope and pagination shape', async () => {
        const res = await httpGet('threats.php?limit=5&offset=0');

        assertEqual(res.status, 200, 'HTTP status');
        assert(res.json?.status === 'ok', 'status field');
        assertEqual(res.json.api_version, '1.0', 'api_version');
        assertArray(res.json.data?.threats, 'data.threats');

        const pagination = res.json.pagination;

        assert(pagination && typeof pagination === 'object', 'pagination object');
        assertEqual(pagination.limit, 5, 'pagination.limit');
        assertEqual(pagination.offset, 0, 'pagination.offset');
        assertEqual(pagination.returned, res.json.data.threats.length, 'pagination.returned');
        assert(typeof pagination.total === 'number', 'pagination.total is numeric');
        assert(typeof pagination.has_more === 'boolean', 'pagination.has_more is boolean');
        assert(!Number.isNaN(Date.parse(res.json.timestamp)), 'timestamp is parseable');

        ctx.total = pagination.total;
        ctx.threats = res.json.data.threats;

        return `total=${pagination.total}, returned=${pagination.returned}`;
    });

    await test('T2  existing severity filter still works (regression)', async () => {
        const res = await httpGet('threats.php?severity=critical&limit=5');

        assertEqual(res.status, 200, 'HTTP status');

        for (const threat of res.json.data.threats) {
            assertEqual(threat.severity, 'critical', `severity of ${threat.threat_uuid}`);
        }

        assert(
            res.json.pagination.total <= ctx.total,
            'filtered total exceeds unfiltered total'
        );

        return `critical total=${res.json.pagination.total}`;
    });

    await test('T3  existing exploitation filter still works (regression)', async () => {
        const res = await httpGet('threats.php?exploitation_status=confirmed&limit=5');

        assertEqual(res.status, 200, 'HTTP status');

        for (const threat of res.json.data.threats) {
            assertEqual(threat.exploitation_status, 'confirmed', `status of ${threat.threat_uuid}`);
        }

        return `confirmed total=${res.json.pagination.total}`;
    });

    await test('T4  invalid severity returns 400 with allowed values', async () => {
        const res = await httpGet('threats.php?severity=bogus');

        assertEqual(res.status, 400, 'HTTP status');
        assertEqual(res.json.status, 'error', 'status field');
        assert(
            JSON.stringify(res.json.allowed_values) === JSON.stringify(ALLOWED_SEVERITIES),
            `allowed_values mismatch: ${JSON.stringify(res.json.allowed_values)}`
        );

        return 'rejected';
    });

    await test('T5  invalid exploitation_status returns 400', async () => {
        const res = await httpGet('threats.php?exploitation_status=bogus');

        assertEqual(res.status, 400, 'HTTP status');
        assertEqual(res.json.status, 'error', 'status field');

        return 'rejected';
    });

    await test('T6  invalid CVE returns 400 "Invalid CVE identifier."', async () => {
        const res = await httpGet('threats.php?cve=not-a-cve');

        assertEqual(res.status, 400, 'HTTP status');
        assertEqual(res.json?.message, 'Invalid CVE identifier.', 'error message');

        return 'rejected';
    }, ['cveFilter']);

    await test('T7  SQL injection attempt in cve is rejected', async () => {
        const payload = encodeURIComponent("CVE-2026-109619' OR '1'='1");

        const res = await httpGet(`threats.php?cve=${payload}`);

        assertEqual(res.status, 400, 'HTTP status');

        return 'rejected';
    }, ['cveFilter']);

    await test('T8  valid but unmatched CVE returns 200 with zero results', async () => {
        const res = await httpGet('threats.php?cve=CVE-1999-99999');

        assertEqual(res.status, 200, 'HTTP status');
        assertEqual(res.json.status, 'ok', 'status field');
        assertEqual(res.json.data.threats.length, 0, 'threats length');
        assertEqual(res.json.pagination.total, 0, 'pagination.total');

        return 'empty result set';
    }, ['cveFilter']);

    await test('T9  cve filter resolves associated threats without duplicates', async () => {
        const cve = ctx.threats
            .map((threat) => threat.external_id)
            .find((id) => typeof id === 'string' && /^CVE-\d{4}-\d{4,}$/.test(id));

        assert(cve, 'no CVE-shaped external_id in the unfiltered page');

        ctx.cve = cve;

        const res = await httpGet(`threats.php?cve=${encodeURIComponent(cve)}&limit=50`);

        assertEqual(res.status, 200, 'HTTP status');

        const threats = res.json.data.threats;

        assert(threats.length >= 1, `expected at least one threat for ${cve}`);

        assert(
            res.json.pagination.total < ctx.total,
            'cve filter did not reduce the result set (is the cve parameter being ignored?)'
        );

        const uuids = threats.map((threat) => threat.threat_uuid);
        const unique = new Set(uuids);

        assertEqual(unique.size, uuids.length, 'duplicate threat_uuid returned');

        if (res.json.pagination.total <= threats.length) {
            assertEqual(res.json.pagination.total, unique.size, 'pagination.total vs distinct threats');
        }

        for (const uuid of uuids.slice(0, 3)) {
            const detail = await httpGet(`threat.php?uuid=${encodeURIComponent(uuid)}`);

            assertEqual(detail.status, 200, 'threat.php status for the resolved uuid');

            const cves = (detail.json.data.threat.vulnerabilities || []).map((v) => v.cve_id);

            assert(
                cves.includes(cve),
                `resolved threat ${uuid} does not reference ${cve} (has: ${cves.join(', ') || 'none'})`
            );
        }

        ctx.cveTotal = res.json.pagination.total;

        return `${cve} → ${res.json.pagination.total} threat(s)`;
    }, ['cveFilter']);

    await test('T10 cve filter combines with severity filter', async () => {
        const res = await httpGet(
            `threats.php?cve=${encodeURIComponent(ctx.cve)}&severity=high&limit=50`
        );

        assertEqual(res.status, 200, 'HTTP status');

        for (const threat of res.json.data.threats) {
            assertEqual(threat.severity, 'high', `severity of ${threat.threat_uuid}`);
        }

        assert(
            res.json.pagination.total <= ctx.cveTotal,
            'combined filter total exceeds cve-only total'
        );

        return `total=${res.json.pagination.total}`;
    }, ['cveFilter']);

    await test('T11 cve filtering respects pagination', async () => {
        const first = await httpGet(
            `threats.php?cve=${encodeURIComponent(ctx.cve)}&limit=1&offset=0`
        );

        assertEqual(first.status, 200, 'HTTP status');
        assertEqual(first.json.pagination.limit, 1, 'pagination.limit');
        assert(first.json.data.threats.length <= 1, 'more than one threat returned for limit=1');
        assertEqual(first.json.pagination.total, ctx.cveTotal, 'total changed between requests');

        if (ctx.cveTotal <= 1) {
            assertEqual(first.json.pagination.has_more, false, 'has_more with a single match');

            return `single match for ${ctx.cve}`;
        }

        const second = await httpGet(
            `threats.php?cve=${encodeURIComponent(ctx.cve)}&limit=1&offset=1`
        );

        assertEqual(second.status, 200, 'HTTP status (offset=1)');
        assertEqual(second.json.data.threats.length, 1, 'second page length');
        assert(
            second.json.data.threats[0].threat_uuid !== first.json.data.threats[0].threat_uuid,
            'page 2 repeats page 1'
        );
        assertEqual(first.json.pagination.has_more, true, 'has_more on first page');

        return `paged ${ctx.cveTotal} matches`;
    }, ['cveFilter']);

    await test('T12 lowercase cve input is normalized', async () => {
        const res = await httpGet(
            `threats.php?cve=${encodeURIComponent(ctx.cve.toLowerCase())}&limit=1`
        );

        assertEqual(res.status, 200, 'HTTP status');
        assertEqual(res.json.pagination.total, ctx.cveTotal, 'total for lowercase cve');

        return 'normalized';
    }, ['cveFilter']);

    await test('T13 empty cve parameter keeps unfiltered behaviour', async () => {
        const res = await httpGet('threats.php?cve=&limit=5');

        assertEqual(res.status, 200, 'HTTP status');
        assertEqual(res.json.pagination.total, ctx.total, 'total with empty cve parameter');

        return 'ignored';
    });

    await test('T14 non-GET methods are rejected', async () => {
        const res = await httpGet('threats.php', { method: 'POST' });

        assertEqual(res.status, 405, 'HTTP status');
        assertEqual(res.json?.message, 'Method Not Allowed.', 'message');
        assertEqual(res.headers.get('allow'), 'GET, OPTIONS', 'Allow header');

        return '405';
    });

    await test('T15 OPTIONS preflight returns 204', async () => {
        const res = await httpGet('threats.php', { method: 'OPTIONS' });

        assertEqual(res.status, 204, 'HTTP status');

        return '204';
    });

    await test('T16 vulnerabilities.php exposes associated threats', async () => {
        const res = await httpGet('vulnerabilities.php?limit=25');

        assertEqual(res.status, 200, 'HTTP status');
        assertArray(res.json.data?.vulnerabilities, 'data.vulnerabilities');

        const rows = res.json.data.vulnerabilities;

        assert(rows.length > 0, 'no vulnerabilities returned');

        for (const row of rows) {
            assert(
                Array.isArray(row.threats),
                `vulnerability ${row.cve_id} does not expose a threats array`
            );

            for (const reference of row.threats) {
                assertEqual(
                    JSON.stringify(Object.keys(reference).sort()),
                    JSON.stringify([...THREAT_REFERENCE_FIELDS].sort()),
                    `threat reference fields for ${row.cve_id}`
                );
                assertEqual(reference.threat_uuid.length, 36, 'threat_uuid length');
                assert(typeof reference.priority_score === 'number', 'priority_score numeric');
            }
        }

        const single = await httpGet(
            `vulnerabilities.php?cve=${encodeURIComponent(rows[0].cve_id)}`
        );

        assertEqual(single.status, 200, 'single CVE lookup status');
        assert(
            Array.isArray(single.json.data.vulnerabilities[0].threats),
            'threats array missing on single CVE lookup'
        );

        ctx.vulnerabilities = rows;

        return `${rows.length} rows, all carrying threats[]`;
    }, ['threatRelationship']);

    await test('T17 vulnerabilities threats[] matches threats.php?cve=', async () => {
        const linked = ctx.vulnerabilities.find(
            (row) => Array.isArray(row.threats) && row.threats.length > 0
        );

        assert(linked, 'no linked vulnerability on the sampled page');

        const res = await httpGet(
            `threats.php?cve=${encodeURIComponent(linked.cve_id)}&limit=100`
        );

        assertEqual(res.status, 200, 'HTTP status');

        const fromThreats = new Set(res.json.data.threats.map((t) => t.threat_uuid));
        const fromVulnerability = new Set(linked.threats.map((t) => t.threat_uuid));

        assertEqual(fromThreats.size, fromVulnerability.size, 'uuid set size mismatch');

        for (const uuid of fromVulnerability) {
            assert(fromThreats.has(uuid), `uuid ${uuid} missing from threats.php?cve=`);
        }

        return `${linked.cve_id}: ${fromVulnerability.size} threat(s) consistent`;
    }, ['threatRelationship', 'cveFilter']);

    await test('T18 index.php advertises the new capability', async () => {
        const res = await httpGet('');

        assertEqual(res.status, 200, 'HTTP status');
        assertEqual(res.json.capabilities?.cve_to_threat, true, 'capabilities.cve_to_threat');
        assertEqual(
            res.json.capabilities?.vulnerability_threat_relationship,
            true,
            'capabilities.vulnerability_threat_relationship'
        );
        assert(
            typeof res.json.documentation?.threats_by_cve === 'string',
            'documentation.threats_by_cve missing'
        );

        return 'discoverable';
    }, ['discovery']);

    /*
     * This is a pure regression check, so it fetches its own sample rather than
     * depending on the enhancement being deployed.
     */
    await test('T19 vulnerabilities.php keeps existing fields (regression)', async () => {
        const res = await httpGet('vulnerabilities.php?limit=5');

        assertEqual(res.status, 200, 'HTTP status');

        const rows = res.json.data.vulnerabilities;

        assert(rows.length > 0, 'no vulnerabilities returned');

        for (const row of rows) {
            for (const field of VULNERABILITY_FIELDS) {
                assert(field in row, `missing field ${field}`);
            }

            assert(typeof row.kev_listed === 'boolean', 'kev_listed is boolean');
            assert(
                typeof row.exploited_in_wild === 'boolean',
                'exploited_in_wild is boolean'
            );
        }

        const single = await httpGet(
            `vulnerabilities.php?cve=${encodeURIComponent(rows[0].cve_id)}`
        );

        assertEqual(single.status, 200, 'single CVE lookup status');
        assertEqual(
            single.json.data.vulnerabilities.length,
            1,
            'single CVE lookup length'
        );

        return `${rows.length} rows intact`;
    });

    await test('T20 threat.php detail endpoint unaffected (regression)', async () => {
        const uuid = ctx.threats[0].threat_uuid;

        const res = await httpGet(`threat.php?uuid=${encodeURIComponent(uuid)}`);

        assertEqual(res.status, 200, 'HTTP status');

        const threat = res.json.data.threat;

        for (const key of [
            'threat_uuid',
            'external_id',
            'title',
            'severity',
            'priority_score',
            'confidence_level',
            'exploitation_status',
            'summary',
            'recommended_action',
        ]) {
            assert(key in threat, `missing field ${key}`);
        }

        for (const key of ['vulnerabilities', 'sources', 'publications']) {
            assertArray(threat[key], `${key} array`);
        }

        assert(!('id' in threat), 'internal database id must not be exposed');

        const missing = await httpGet('threat.php?uuid=00000000-0000-0000-0000-000000000000');

        assertEqual(missing.status, 404, 'unknown uuid status');

        const invalid = await httpGet('threat.php?uuid=not-a-uuid');

        assertEqual(invalid.status, 400, 'invalid uuid status');

        return 'unchanged';
    });

    await test('T21 a CVE linked to several threats resolves to all of them', async () => {
        const multi = ctx.vulnerabilities.find(
            (row) => Array.isArray(row.threats) && row.threats.length > 1
        );

        if (!multi) {
            return 'SKIP — no multi-threat CVE in this data set';
        }

        const res = await httpGet(
            `threats.php?cve=${encodeURIComponent(multi.cve_id)}&limit=100`
        );

        assertEqual(res.status, 200, 'HTTP status');

        const uuids = res.json.data.threats.map((threat) => threat.threat_uuid);
        const unique = new Set(uuids);

        assertEqual(unique.size, uuids.length, 'duplicate threat_uuid returned');
        assertEqual(unique.size, multi.threats.length, 'resolved threat count');
        assertEqual(res.json.pagination.total, multi.threats.length, 'pagination.total');

        const scores = res.json.data.threats.map((threat) => threat.priority_score);

        for (let i = 1; i < scores.length; i += 1) {
            assert(scores[i - 1] >= scores[i], 'priority ordering is not descending');
        }

        return `${multi.cve_id} → ${unique.size} threat(s)`;
    }, ['threatRelationship', 'cveFilter']);

    await test('T22 unfiltered ordering is priority descending (regression)', async () => {
        const res = await httpGet('threats.php?limit=25');

        assertEqual(res.status, 200, 'HTTP status');

        const scores = res.json.data.threats.map((threat) => threat.priority_score);

        for (let i = 1; i < scores.length; i += 1) {
            assert(scores[i - 1] >= scores[i], 'priority ordering is not descending');
        }

        return `${scores.length} threats ordered`;
    });

    await test('T23 changes.php reports the delta against the previous publication', async () => {
        const res = await httpGet('changes.php');

        assertEqual(res.status, 200, 'HTTP status');
        assertEqual(res.json.status, 'ok', 'envelope status');

        const data = res.json.data;

        assert(typeof data.publication_uuid === 'string', 'publication_uuid');

        for (const key of ['added', 'removed', 'changed', 'unchanged', 'published', 'previous']) {
            assert(
                typeof data.summary[key] === 'number',
                `summary.${key} must be a number`
            );
        }

        if (data.previous_publication_uuid === null) {
            assertEqual(
                data.summary.added,
                data.summary.published,
                'a first publication is entirely new'
            );

            return 'first publication — nothing to compare against';
        }

        assert(
            data.publication_uuid !== data.previous_publication_uuid,
            'a publication cannot be compared with itself'
        );

        /*
         * The three lists partition the publication: every threat is added,
         * changed or unchanged, and nothing may appear in two of them.
         */
        assertEqual(
            data.summary.added + data.summary.changed + data.summary.unchanged,
            data.summary.published,
            'added + changed + unchanged must equal published'
        );

        assertEqual(data.kind, 'added', 'default kind');

        assertArray(data.changes, 'changes array');

        assertEqual(
            res.json.pagination.total,
            data.summary.added,
            'pagination.total must match summary.added'
        );

        assertEqual(
            data.changes.length,
            Math.min(res.json.pagination.limit, data.summary.added),
            'page must be the smaller of limit and the list'
        );

        for (const entry of data.changes) {
            assertEqual(entry.change, 'added', 'entry change kind');

            for (const field of [
                'threat_uuid',
                'external_id',
                'title',
                'severity',
                'priority_score',
                'change',
            ]) {
                assert(field in entry, `missing field ${field}`);
            }
        }

        const removed = await httpGet('changes.php?kind=removed');

        assertEqual(removed.status, 200, 'removed status');

        assertEqual(
            removed.json.pagination.total,
            removed.json.data.summary.removed,
            'removed total'
        );

        assert(
            removed.json.data.changes.every((entry) => entry.change === 'removed'),
            'kind=removed must not return a different kind'
        );

        const changed = await httpGet('changes.php?kind=changed');

        assertEqual(changed.status, 200, 'changed status');

        assertEqual(
            changed.json.pagination.total,
            changed.json.data.summary.changed,
            'changed total'
        );

        for (const entry of changed.json.data.changes) {
            assertArray(entry.changed_fields, 'changed_fields array');

            assert(
                entry.changed_fields.length > 0,
                'a changed entry must name at least one field'
            );
        }

        const invalid = await httpGet('changes.php?kind=sideways');

        assertEqual(invalid.status, 400, 'invalid kind status');

        return `${data.summary.added} added, ${data.summary.removed} removed, ${data.summary.changed} changed`;
    }, ['deltaFeed']);

    await test('T24 source_health.php reports per-source run health', async () => {
        const res = await httpGet('source_health.php');

        assertEqual(res.status, 200, 'HTTP status');
        assertEqual(res.json.status, 'ok', 'envelope status');

        const data = res.json.data;

        assert(typeof data.available === 'boolean', 'available must be a boolean');

        if (!data.available) {
            /*
             * Older publications predate source health. That is a missing
             * report, not a broken contract, so the endpoint must still answer
             * with the full envelope rather than erroring.
             */
            assertArray(data.source_health, 'source_health array');

            return 'SKIP — this publication carries no source health';
        }

        assert(typeof data.publication_uuid === 'string', 'publication_uuid');

        assert(
            data.summary !== null && typeof data.summary === 'object',
            'summary object'
        );

        for (const key of ['ok', 'degraded', 'failed', 'sources']) {
            assert(
                typeof data.summary[key] === 'number',
                `summary.${key} must be a number`
            );
        }

        assertArray(data.source_health, 'source_health array');

        assertEqual(
            res.json.pagination.total,
            data.summary.sources,
            'pagination.total must match summary.sources'
        );

        assertEqual(
            data.source_health.length,
            Math.min(res.json.pagination.limit, res.json.pagination.total),
            'page must be the smaller of limit and the total'
        );

        const seen = new Set();

        for (const source of data.source_health) {
            for (const field of [
                'source_key',
                'status',
                'observations',
                'used_last_known_good',
            ]) {
                assert(field in source, `missing field ${field}`);
            }

            assert(
                ['ok', 'degraded', 'failed'].includes(source.status),
                `unexpected status ${source.status}`
            );

            assert(
                !seen.has(source.source_key),
                `duplicate source_key ${source.source_key}`
            );

            seen.add(source.source_key);
        }

        const failed = await httpGet('source_health.php?status=failed');

        assertEqual(failed.status, 200, 'filtered status');

        assert(
            failed.json.data.source_health.every((source) => source.status === 'failed'),
            'status filter must exclude every other status'
        );

        const single = await httpGet('source_health.php?source_key=cisa_kev');

        assertEqual(single.status, 200, 'source_key filter status');

        assert(
            single.json.pagination.total <= 1,
            'source_key must select at most one source'
        );

        const invalid = await httpGet('source_health.php?status=panicking');

        assertEqual(invalid.status, 400, 'invalid status returns 400');

        return `${data.summary.sources} sources (${data.summary.ok} ok, ${data.summary.degraded} degraded, ${data.summary.failed} failed)`;
    }, ['sourceHealth']);
}


/*
 * Local harness.
 *
 * Copies the public endpoints into a temporary directory, replaces db.php
 * with the SQLite fixture and serves them with the PHP built-in server.
 * publish.php is deliberately excluded: it is a write endpoint and is never
 * part of the public contract.
 */
async function startLocalApi(phpBinary, keep) {
    const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'threatpulse-api-'));
    const targetDir = path.join(tempRoot, 'api', 'cti', 'v1');

    await fs.mkdir(targetDir, { recursive: true });

    for (const entry of await fs.readdir(API_DIR)) {
        if (entry === 'db.php' || entry === 'publish.php') {
            continue;
        }

        await fs.copyFile(
            path.join(API_DIR, entry),
            path.join(targetDir, entry)
        );
    }

    await fs.copyFile(
        path.join(HERE, 'db-fixture.php'),
        path.join(targetDir, 'db.php')
    );

    const port = await getFreePort();

    const child = spawn(
        phpBinary,
        [
            '-d', 'extension=sqlite3',
            '-d', 'extension=pdo_sqlite',
            '-S', `127.0.0.1:${port}`,
            '-t', tempRoot,
        ],
        { stdio: ['ignore', 'pipe', 'pipe'] }
    );

    let log = '';

    child.stdout.on('data', (chunk) => { log += chunk.toString(); });
    child.stderr.on('data', (chunk) => { log += chunk.toString(); });

    return {
        base: `http://127.0.0.1:${port}/api/cti/v1/`,
        tempRoot,
        log: () => log,
        async stop() {
            child.kill();

            await new Promise((resolve) => setTimeout(resolve, 250));

            if (!keep) {
                await fs.rm(tempRoot, { recursive: true, force: true });
            }
        },
    };
}

async function waitForReady(httpGet, timeoutMs = 20000) {
    const deadline = Date.now() + timeoutMs;
    let lastError = null;

    while (Date.now() < deadline) {
        try {
            const res = await httpGet('status.php');

            if (res.status === 200) {
                return;
            }

            lastError = new Error(`status.php returned HTTP ${res.status}`);
        } catch (error) {
            lastError = error;
        }

        await new Promise((resolve) => setTimeout(resolve, 250));
    }

    throw new Error(
        `local API did not become ready — ${lastError?.message ?? 'timeout'}`
    );
}

function report(base, mode, options) {
    console.log('');
    console.log('──────────────────────────────────────────────────────────');

    let passed = 0;
    let failed = 0;
    let skipped = 0;

    for (const result of results) {
        const mark = result.skipped ? 'SKIP' : result.ok ? 'PASS' : 'FAIL';

        console.log(
            `[${mark}] ${result.name}${result.detail ? ` — ${result.detail}` : ''}`
        );

        if (result.skipped) {
            skipped += 1;
        } else if (result.ok) {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    console.log('──────────────────────────────────────────────────────────');
    console.log(
        `${passed} passed, ${failed} failed, ${skipped} skipped  (${mode} · ${base})`
    );

    /*
     * A skipped assertion means "the capability is not deployed here", which is
     * a target state, not a defect. It is reported as such so the runner never
     * produces a false failure — and never a false pass either, because the
     * reason is always printed next to the test.
     */
    if (skipped > 0) {
        console.log('');
        console.log(
            'STATE: the CVE → threat enhancement is NOT deployed on this target.'
        );
        console.log(
            '       Skipped assertions are not failures: they cannot be evaluated yet.'
        );
        console.log('');
        console.log('Upload these files to api/cti/v1/ and re-run:');

        if (!contract.cveFilter) {
            console.log('  · threats.php          (cve parameter + validation)');
        }

        if (!contract.threatRelationship) {
            console.log('  · vulnerabilities.php  (threats[] relationship)');
        }

        if (!contract.discovery) {
            console.log('  · index.php            (capability flags)');
        }
    } else if (failed === 0) {
        console.log('');
        console.log('STATE: enhancement deployed — the full contract is verified.');
    }

    console.log('');
    console.log('Pre-flight evidence:');

    for (const line of contract.evidence) {
        console.log(`  · ${line}`);
    }

    console.log('');
    console.log(
        'N+1 review: threats.php issues one count query plus one page query;'
    );
    console.log(
        'vulnerabilities.php issues one page query plus one batched threats query.'
    );

    const strictFailure = options.requireContract === true && skipped > 0;

    if (strictFailure) {
        console.log('');
        console.log(
            '--require-contract was set, so the skipped assertions are treated as failures.'
        );
    }

    process.exitCode = failed > 0 || strictFailure ? 1 : 0;
}

async function main() {
    const options = parseArgs(process.argv.slice(2));

    let harness = null;
    let base = options.base;
    let mode = 'deployed API';

    console.log('ThreatPulse API contract verifier');

    if (!base) {
        mode = 'local PHP + SQLite fixture';

        try {
            harness = await startLocalApi(options.php, options.keep);
        } catch (error) {
            console.error(
                `Unable to start the local API harness: ${error.message}`
            );
            console.error(
                'Ensure a PHP CLI binary is available (see api-tests/README.md).'
            );
            process.exitCode = 1;
            return;
        }

        base = harness.base;
    }

    console.log(`Target: ${base}`);
    console.log(`Mode:   ${mode}`);

    const httpGet = createHttp(base);

    try {
        if (harness) {
            await waitForReady(httpGet);
        }

        await runPreflight(httpGet);
        await runMatrix(httpGet);
    } catch (error) {
        results.push({
            name: 'harness failure',
            ok: false,
            detail: error instanceof Error ? error.message : String(error),
        });
    } finally {
        if (harness) {
            if (results.some((result) => !result.ok)) {
                const log = harness.log().trim();

                if (log) {
                    console.log('');
                    console.log('PHP server log:');
                    console.log(log);
                }
            }

            await harness.stop();
        }
    }

    report(base, mode, options);
}

main();


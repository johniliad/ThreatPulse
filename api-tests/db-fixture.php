<?php

declare(strict_types=1);

/*
 * ThreatPulse API — local test fixture.
 *
 * This file is a drop-in replacement for api/cti/v1/db.php used ONLY by
 * api-tests/verify-api.mjs. It returns a PDO connection to a local SQLite
 * database seeded with a small, fixed data set, so that the public API
 * endpoints can be executed and asserted locally without any access to
 * the production MySQL database and without any credentials.
 *
 * It is never deployed and never included by the production API.
 */

function threatpulse_db(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dbFile = dirname(__DIR__) . '/fixture.sqlite';

    $isNew = !file_exists($dbFile);

    $pdo = new PDO('sqlite:' . $dbFile);

    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(
        PDO::ATTR_DEFAULT_FETCH_MODE,
        PDO::FETCH_ASSOC
    );

    if ($isNew) {
        threatpulse_fixture_seed($pdo);
    }

    return $pdo;
}

function threatpulse_fixture_seed(PDO $pdo): void
{
    $pdo->exec(
        '
        CREATE TABLE threats (
            id INTEGER PRIMARY KEY,
            threat_uuid TEXT NOT NULL,
            external_id TEXT,
            title TEXT,
            threat_type TEXT,
            severity TEXT,
            priority_score REAL,
            confidence_score REAL,
            confidence_level TEXT,
            exploitation_status TEXT,
            first_seen TEXT,
            last_seen TEXT,
            summary TEXT,
            recommended_action TEXT,
            metadata TEXT
        );

        CREATE TABLE vulnerabilities (
            id INTEGER PRIMARY KEY,
            cve_id TEXT NOT NULL,
            description TEXT,
            cvss_score REAL,
            cvss_vector TEXT,
            severity TEXT,
            kev_listed INTEGER,
            exploited_in_wild INTEGER,
            published_at TEXT,
            modified_at TEXT,
            vendor TEXT,
            product TEXT,
            metadata TEXT
        );

        CREATE TABLE threat_vulnerabilities (
            threat_id INTEGER NOT NULL,
            vulnerability_id INTEGER NOT NULL,
            relationship TEXT,
            PRIMARY KEY (threat_id, vulnerability_id)
        );

        CREATE TABLE sources (
            id INTEGER PRIMARY KEY,
            source_key TEXT NOT NULL,
            name TEXT,
            source_type TEXT,
            url TEXT,
            provider TEXT,
            reliability TEXT,
            enabled INTEGER,
            metadata TEXT
        );

        CREATE TABLE threat_sources (
            threat_id INTEGER NOT NULL,
            source_id INTEGER NOT NULL,
            relationship TEXT,
            PRIMARY KEY (threat_id, source_id)
        );

        CREATE TABLE publications (
            id INTEGER PRIMARY KEY,
            publication_uuid TEXT NOT NULL,
            schema_version TEXT,
            generated_at TEXT,
            created_at TEXT,
            status TEXT,
            source_health TEXT
        );

        CREATE TABLE publication_threats (
            publication_id INTEGER NOT NULL,
            threat_id INTEGER NOT NULL,
            PRIMARY KEY (publication_id, threat_id)
        );

        CREATE TABLE source_attribution (
            id INTEGER PRIMARY KEY,
            source_key TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            provider TEXT,
            homepage TEXT,
            licence TEXT,
            licence_url TEXT,
            terms_url TEXT,
            tlp_default TEXT,
            ingested INTEGER NOT NULL DEFAULT 0,
            attribution_text TEXT,
            tier INTEGER,
            notes TEXT,
            updated_at TEXT
        );
        '
    );

    threatpulse_fixture_data($pdo);
}

function threatpulse_fixture_data(PDO $pdo): void
{
    $metadata = json_encode(
        [
            'cwes' => ['CWE-416', 'CWE-755'],
            'vendor' => 'PHP Group',
            'product' => 'PHP',
            'due_date' => '2026-10-29',
            'reasoning' => [
                'Listed in the CISA Known Exploited Vulnerabilities catalog.',
                'CISA remediation deadline has been reached or passed.',
            ],
            'cisa_notes' => 'Fixture note: https://nvd.nist.gov/vuln/detail/CVE-2026-109619',
            'score_factors' => [
                'impact' => 100,
                'recency' => 100,
                'urgency' => 100,
                'forensic' => 100,
                'ransomware' => 50,
                'exploitation' => 100,
            ],
            'score_weights' => [
                'impact' => 0.1,
                'recency' => 0.2,
                'urgency' => 0.2,
                'forensic' => 0.05,
                'ransomware' => 0.15,
                'exploitation' => 0.3,
            ],
            'scoring_model' => 'threatpulse_priority_v0.1',
            'forensic_triage' => 'Yes',
            'source_attribution' => [
                'source_key' => 'cisa_kev',
                'source_name' => 'CISA Known Exploited Vulnerabilities Catalog',
                'retrieved_at' => '2026-10-30T01:36:50Z',
                'source_record_id' => 'CVE-2026-109619',
            ],
            'known_ransomware_campaign_use' => 'Unknown',
        ],
        JSON_UNESCAPED_SLASHES
    );

    /*
     * The second fixture publication reports one threat as changed since the
     * previous publication, and one source as failed. Both are written by the
     * pipeline at publish time; the API only ever reads them, so the fixture has
     * to carry them for `changes.php` and `source_health.php` to be exercised.
     */
    $metadataChanged = json_encode(
        array_merge(
            json_decode($metadata, true),
            [
                'temporal' => [
                    'first_published_at' => '2026-10-30T01:36:50Z',
                    'revision' => 2,
                    'changed_since_previous' => ['priority_score'],
                ],
            ]
        ),
        JSON_UNESCAPED_SLASHES
    );

    $threats = [
        [
            1,
            '11111111-1111-4111-8111-111111111111',
            'CVE-2026-109619',
            'Fixture PHP Remote Code Execution Vulnerability',
            'vulnerability',
            'critical',
            92.5,
            100,
            'high',
            'confirmed',
            '2026-10-26 00:00:00',
            '2026-10-30 01:36:50',
            'Fixture summary for the linked CVE.',
            'Apply vendor mitigations.',
            $metadata,
        ],
        [
            2,
            '22222222-2222-4222-8222-222222222222',
            'CVE-2026-111111',
            'Fixture Multi-CVE Threat',
            'vulnerability',
            'high',
            80.5,
            90,
            'high',
            'confirmed',
            '2026-10-20 00:00:00',
            '2026-10-29 01:00:00',
            'Fixture summary for the cross-linked CVE.',
            'Apply vendor mitigations.',
            $metadataChanged,
        ],
        [
            3,
            '33333333-3333-4333-8333-333333333333',
            'CVE-2026-222222',
            'Fixture Medium Severity Threat',
            'vulnerability',
            'medium',
            60.0,
            75,
            'medium',
            'confirmed',
            '2026-09-01 00:00:00',
            '2026-10-28 01:00:00',
            'Fixture summary for a medium severity threat.',
            'Apply vendor mitigations.',
            null,
        ],
        [
            4,
            '44444444-4444-4444-8444-444444444444',
            null,
            'Fixture Threat Without Vulnerability',
            'campaign',
            'medium',
            55.0,
            70,
            'medium',
            'unknown',
            '2026-08-01 00:00:00',
            '2026-10-27 01:00:00',
            'Fixture summary for a threat with no vulnerability.',
            'Monitor.',
            null,
        ],
    ];

    $threatInsert = $pdo->prepare(
        '
        INSERT INTO threats (
            id, threat_uuid, external_id, title, threat_type, severity,
            priority_score, confidence_score, confidence_level,
            exploitation_status, first_seen, last_seen, summary,
            recommended_action, metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '
    );

    foreach ($threats as $threat) {
        $threatInsert->execute($threat);
    }

    $vulnerabilities = [
        [
            1,
            'CVE-2026-109619',
            'Fixture vulnerability linked to one threat.',
            'critical',
            1,
            1,
            'PHP Group',
            'PHP',
        ],
        [
            2,
            'CVE-2026-111111',
            'Fixture vulnerability linked to two threats.',
            'high',
            1,
            1,
            'Fixture Vendor',
            'Fixture Product',
        ],
        [
            3,
            'CVE-2026-222222',
            'Fixture vulnerability linked to one threat.',
            'medium',
            1,
            1,
            'Fixture Vendor',
            'Another Product',
        ],
        [
            4,
            'CVE-2026-999999',
            'Fixture vulnerability with no ThreatPulse threat.',
            'low',
            0,
            0,
            'Fixture Vendor',
            'Unlinked Product',
        ],
    ];

    $vulnerabilityInsert = $pdo->prepare(
        '
        INSERT INTO vulnerabilities (
            id, cve_id, description, severity, kev_listed,
            exploited_in_wild, vendor, product
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '
    );

    foreach ($vulnerabilities as $vulnerability) {
        $vulnerabilityInsert->execute($vulnerability);
    }

    $links = [
        [1, 1, 'affects'],
        [1, 2, 'affects'],
        [2, 2, 'affects'],
        [3, 3, 'affects'],
    ];

    $linkInsert = $pdo->prepare(
        '
        INSERT INTO threat_vulnerabilities (
            threat_id, vulnerability_id, relationship
        )
        VALUES (?, ?, ?)
        '
    );

    foreach ($links as $link) {
        $linkInsert->execute($link);
    }

    $pdo->exec(
        "
        INSERT INTO sources (
            id, source_key, name, source_type, url, provider,
            reliability, enabled, metadata
        )
        VALUES (
            1,
            'cisa_kev',
            'CISA Known Exploited Vulnerabilities Catalog',
            'advisory',
            'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
            'CISA',
            'high',
            1,
            NULL
        );

        INSERT INTO threat_sources (threat_id, source_id, relationship)
        VALUES (1, 1, 'reported'), (2, 1, 'reported'), (3, 1, 'reported');

        INSERT INTO publications (
            id, publication_uuid, schema_version, generated_at, created_at,
            status
        )
        VALUES (
            1,
            '8585c51f-706c-43a1-bab3-75ad4f4a2e62',
            '1.0',
            '2026-10-30 01:36:50',
            '2026-10-30 17:32:18',
            'published'
        );

        INSERT INTO publications (
            id, publication_uuid, schema_version, generated_at, created_at,
            status
        )
        VALUES (
            2,
            '99999999-9999-4999-8999-999999999999',
            '1.0',
            '2026-11-01 02:00:00',
            '2026-11-01 02:04:11',
            'published'
        );

        INSERT INTO publication_threats (publication_id, threat_id)
        VALUES (1, 1), (1, 2), (1, 3);

        INSERT INTO publication_threats (publication_id, threat_id)
        VALUES (2, 1), (2, 2), (2, 4);
        "
    );

    /*
     * Source health for the current publication: one healthy source, one that
     * fell back to a last-known-good snapshot, and one that failed outright — so
     * that filtering by status has something to separate.
     */
    $sourceHealthStmt = $pdo->prepare(
        '
        UPDATE publications
        SET source_health = ?
        WHERE id = ?
        '
    );

    $sourceHealthStmt->execute([
        json_encode(
            [
                'generated_at' => '2026-11-01T02:00:00Z',
                'summary' => [
                    'ok' => 1,
                    'degraded' => 1,
                    'failed' => 1,
                    'sources' => 3,
                ],
                'sources' => [
                    [
                        'source_key' => 'cisa_kev',
                        'status' => 'ok',
                        'observations' => 1766,
                        'used_last_known_good' => false,
                        'failure_reason' => null,
                        'metrics' => ['records' => 1766],
                    ],
                    [
                        'source_key' => 'epss',
                        'status' => 'degraded',
                        'observations' => 0,
                        'used_last_known_good' => true,
                        'failure_reason' => 'HTTP 503 from the EPSS API.',
                        'metrics' => ['cache_hits' => 393],
                    ],
                    [
                        'source_key' => 'redhat_security',
                        'status' => 'failed',
                        'observations' => 0,
                        'used_last_known_good' => false,
                        'failure_reason' => 'Connection timed out.',
                        'metrics' => [],
                    ],
                ],
            ],
            JSON_UNESCAPED_SLASHES
        ),
        2,
    ]);
}

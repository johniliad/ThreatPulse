<?php

declare(strict_types=1);

/*
 * ThreatPulse public API — HTTP policy
 */

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Accept');
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    header('Allow: GET, OPTIONS');
    header('Content-Type: application/json; charset=utf-8');

    http_response_code(405);

    echo json_encode(
        [
            'status' => 'error',
            'message' => 'Method Not Allowed.',
            'allowed_methods' => ['GET', 'OPTIONS'],
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );

    exit;
}

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Accept');

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

header(
    'Permissions-Policy: camera=(), microphone=(), geolocation=()'
);

header('Cache-Control: public, max-age=60');


require_once __DIR__ . '/db.php';

try {
    $uuid = isset($_GET['uuid'])
        ? trim((string) $_GET['uuid'])
        : '';

    if ($uuid === '') {
        http_response_code(400);

        echo json_encode(
            [
                'status' => 'error',
                'message' => 'Missing required parameter: uuid.',
            ],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

        exit;
    }

    if (
    !preg_match(
        '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/',
        $uuid
        )
    ) {
        http_response_code(400);

        echo json_encode(
            [
                'status' => 'error',
                'message' => 'Invalid threat UUID.',
            ],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

        exit;
    }

    $pdo = threatpulse_db();

    /*
     * Main threat record
     */
    $stmt = $pdo->prepare(
        "
        SELECT
            id,
            threat_uuid,
            external_id,
            title,
            threat_type,
            severity,
            priority_score,
            confidence_score,
            confidence_level,
            exploitation_status,
            first_seen,
            last_seen,
            summary,
            recommended_action,
            metadata
        FROM threats
        WHERE threat_uuid = ?
        LIMIT 1
        "
    );

    $stmt->execute([$uuid]);

    $threat = $stmt->fetch();

    if (!$threat) {
        http_response_code(404);

        echo json_encode(
            [
                'status' => 'error',
                'message' => 'Threat not found.',
            ],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

        exit;
    }

    /*
     * Normalize numeric fields.
     */
    $threat['id'] = (int) $threat['id'];
    $threat['priority_score'] =
        (float) $threat['priority_score'];
    $threat['confidence_score'] =
        (float) $threat['confidence_score'];

    /*
     * Decode metadata JSON.
     */
    if (
        isset($threat['metadata'])
        && $threat['metadata'] !== null
        && $threat['metadata'] !== ''
    ) {
        $decodedMetadata = json_decode(
            $threat['metadata'],
            true
        );

        $threat['metadata'] =
            is_array($decodedMetadata)
                ? $decodedMetadata
                : null;
    } else {
        $threat['metadata'] = null;
    }

    /*
     * Associated vulnerabilities.
     */
    $stmt = $pdo->prepare(
        "
        SELECT
            v.id,
            v.cve_id,
            v.description,
            v.cvss_score,
            v.cvss_vector,
            v.severity,
            v.kev_listed,
            v.exploited_in_wild,
            v.published_at,
            v.modified_at,
            v.vendor,
            v.product
        FROM vulnerabilities v
        INNER JOIN threat_vulnerabilities tv
            ON tv.vulnerability_id = v.id
        WHERE tv.threat_id = ?
        ORDER BY v.cve_id ASC, v.id ASC
        "
    );

    $stmt->execute([(int) $threat['id']]);

    $vulnerabilities = $stmt->fetchAll();

    foreach ($vulnerabilities as &$vulnerability) {
        $vulnerability['id'] =
            (int) $vulnerability['id'];

        if ($vulnerability['cvss_score'] !== null) {
            $vulnerability['cvss_score'] =
                (float) $vulnerability['cvss_score'];
        }

        $vulnerability['kev_listed'] =
            (bool) $vulnerability['kev_listed'];

        $vulnerability['exploited_in_wild'] =
            (bool) $vulnerability['exploited_in_wild'];
    }

    unset($vulnerability);

    /*
     * Associated sources.
     */
    $stmt = $pdo->prepare(
        "
        SELECT
            s.id,
            s.source_key,
            s.name,
            s.source_type,
            s.url,
            s.provider,
            s.reliability,
            ts.relationship
        FROM sources s
        INNER JOIN threat_sources ts
            ON ts.source_id = s.id
        WHERE ts.threat_id = ?
        ORDER BY s.name ASC, s.id ASC
        "
    );

    $stmt->execute([(int) $threat['id']]);

    $sources = $stmt->fetchAll();

    foreach ($sources as &$source) {
        $source['id'] = (int) $source['id'];
    }

    unset($source);

    /*
     * Publication history.
     */
    $stmt = $pdo->prepare(
        "
        SELECT
            p.id,
            p.publication_uuid,
            p.schema_version,
            p.generated_at,
            p.created_at
        FROM publications p
        INNER JOIN publication_threats pt
            ON pt.publication_id = p.id
        WHERE pt.threat_id = ?
        ORDER BY p.generated_at DESC, p.id DESC
        "
    );

    $stmt->execute([(int) $threat['id']]);

    $publications = $stmt->fetchAll();

    foreach ($publications as &$publication) {
        $publication['id'] = (int) $publication['id'];
    }

    unset($publication);

    /*
     * Remove internal database ID from the public threat object.
     */
    unset($threat['id']);

    $threat['vulnerabilities'] = $vulnerabilities;
    $threat['sources'] = $sources;
    $threat['publications'] = $publications;

    echo json_encode(
        [
            'status' => 'ok',
            'api_version' => '1.0',
            'data' => [
                'threat' => $threat,
            ],
            'timestamp' => gmdate('c'),
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );

} catch (Throwable $exc) {

    error_log(
        'ThreatPulse public threat API error: '
        . $exc->getMessage()
    );

    http_response_code(500);

    echo json_encode(
        [
            'status' => 'error',
            'message' => 'Unable to retrieve threat intelligence.',
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
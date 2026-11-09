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
    $pdo = threatpulse_db();

    /*
     * Pagination
     */
    $limit = filter_input(
        INPUT_GET,
        'limit',
        FILTER_VALIDATE_INT
    );

    $offset = filter_input(
        INPUT_GET,
        'offset',
        FILTER_VALIDATE_INT
    );

    $limit = $limit === false || $limit === null
        ? 50
        : max(1, min($limit, 100));

    $offset = $offset === false || $offset === null
        ? 0
        : max(0, $offset);

    /*
     * Optional filters
     */
    $severity = isset($_GET['severity'])
        ? strtolower(trim((string) $_GET['severity']))
        : null;

    $exploitationStatus = isset($_GET['exploitation_status'])
        ? strtolower(trim((string) $_GET['exploitation_status']))
        : null;

    /*
     * Optional CVE filter.
     *
     * Resolves a CVE identifier to the ThreatPulse threat records it
     * is associated with through the threat_vulnerabilities
     * relationship. Supplied values are normalized to uppercase.
     */
    $cve = isset($_GET['cve'])
        ? strtoupper(trim((string) $_GET['cve']))
        : null;

    $allowedSeverities = [
        'critical',
        'high',
        'medium',
        'low',
        'informational',
    ];

    $allowedExploitationStatuses = [
        'confirmed',
        'suspected',
        'unknown',
        'not_exploited',
    ];

    if ($cve !== null && $cve !== '') {
        if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve)) {
            http_response_code(400);

            echo json_encode(
                [
                    'status' => 'error',
                    'message' => 'Invalid CVE identifier.',
                ],
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            );

            exit;
        }
    } else {
        $cve = null;
    }

    /*
     * Build WHERE clause using only whitelisted filters.
     *
     * The threats table is always aliased as `t`, so that the optional
     * CVE filter can join the vulnerability relationship while the
     * severity and exploitation predicates remain unchanged.
     */
    $cveFilter = $cve !== null;

    $where = [];
    $params = [];

    if ($severity !== null && $severity !== '') {
        if (!in_array($severity, $allowedSeverities, true)) {
            http_response_code(400);

            echo json_encode(
                [
                    'status' => 'error',
                    'message' => 'Invalid severity.',
                    'allowed_values' => $allowedSeverities,
                ],
                JSON_UNESCAPED_SLASHES
                | JSON_UNESCAPED_UNICODE
            );

            exit;
        }

        $where[] = 't.severity = ?';
        $params[] = $severity;
    }

    if (
        $exploitationStatus !== null
        && $exploitationStatus !== ''
    ) {
        if (
            !in_array(
                $exploitationStatus,
                $allowedExploitationStatuses,
                true
            )
        ) {
            http_response_code(400);

            echo json_encode(
                [
                    'status' => 'error',
                    'message' => 'Invalid exploitation_status.',
                    'allowed_values' =>
                        $allowedExploitationStatuses,
                ],
                JSON_UNESCAPED_SLASHES
                | JSON_UNESCAPED_UNICODE
            );

            exit;
        }

        $where[] = 't.exploitation_status = ?';
        $params[] = $exploitationStatus;
    }

    /*
     * Threat source.
     *
     * The CVE filter joins the vulnerability relationship; every other
     * request shape is unchanged apart from the table alias.
     */
    $fromSql = '
        FROM threats t
    ';

    if ($cveFilter) {
        $fromSql .= '
        INNER JOIN threat_vulnerabilities tv
            ON tv.threat_id = t.id
        INNER JOIN vulnerabilities v
            ON v.id = tv.vulnerability_id
        ';

        $where[] = 'v.cve_id = ?';
        $params[] = $cve;
    }

    $whereSql = $where
        ? 'WHERE ' . implode(' AND ', $where)
        : '';

    /*
     * Total matching records.
     *
     * A threat may be associated with more than one vulnerability, so a
     * CVE-filtered count must be distinct.
     */
    $countExpression = $cveFilter
        ? 'COUNT(DISTINCT t.id)'
        : 'COUNT(*)';

    $countSql = "
        SELECT $countExpression
        $fromSql
        $whereSql
    ";

    $stmt = $pdo->prepare($countSql);
    $stmt->execute($params);

    $total = (int) $stmt->fetchColumn();

    /*
     * Threat data.
     *
     * Explicit columns only — never SELECT *.
     */
    $distinct = $cveFilter ? 'DISTINCT' : '';

    $sql = "
        SELECT $distinct
            t.id,
            t.threat_uuid,
            t.external_id,
            t.title,
            t.threat_type,
            t.severity,
            t.priority_score,
            t.confidence_score,
            t.confidence_level,
            t.exploitation_status,
            t.first_seen,
            t.last_seen,
            t.summary,
            t.recommended_action,
            t.metadata
        $fromSql
        $whereSql
        ORDER BY
            t.priority_score DESC,
            t.last_seen DESC,
            t.id DESC
        LIMIT $limit
        OFFSET $offset
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    $threats = $stmt->fetchAll();

    /*
     * Normalize numeric fields and decode metadata.
     */
    foreach ($threats as &$threat) {

        $threat['id'] = (int) $threat['id'];

        $threat['priority_score'] =
            (float) $threat['priority_score'];

        $threat['confidence_score'] =
            (float) $threat['confidence_score'];

        if (
            isset($threat['metadata'])
            && $threat['metadata'] !== null
            && $threat['metadata'] !== ''
        ) {
            $decoded = json_decode(
                $threat['metadata'],
                true
            );

            $threat['metadata'] =
                is_array($decoded)
                    ? $decoded
                    : null;
        } else {
            $threat['metadata'] = null;
        }
    }

    unset($threat);

    /*
     * Pagination metadata.
     */
    $hasMore = ($offset + count($threats)) < $total;

    echo json_encode(
        [
            'status' => 'ok',
            'api_version' => '1.0',
            'data' => [
                'threats' => $threats,
            ],
            'pagination' => [
                'limit' => $limit,
                'offset' => $offset,
                'returned' => count($threats),
                'total' => $total,
                'has_more' => $hasMore,
            ],
            'timestamp' => gmdate('c'),
        ],
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );

} catch (Throwable $exc) {

    error_log(
        'ThreatPulse public threats API error: '
        . $exc->getMessage()
    );

    http_response_code(500);

    echo json_encode(
        [
            'status' => 'error',
            'message' => 'Unable to retrieve threat intelligence.',
        ],
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );
}
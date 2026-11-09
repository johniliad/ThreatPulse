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

    $cve = isset($_GET['cve'])
        ? strtoupper(trim((string) $_GET['cve']))
        : null;

    $severity = isset($_GET['severity'])
        ? strtolower(trim((string) $_GET['severity']))
        : null;

    $kevListed = isset($_GET['kev_listed'])
        ? strtolower(trim((string) $_GET['kev_listed']))
        : null;

    $where = [];
    $params = [];

    if ($cve !== null && $cve !== '') {
        if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve)) {
            http_response_code(400);

            echo json_encode(
                [
                    'status' => 'error',
                    'message' => 'Invalid CVE format.',
                ],
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            );

            exit;
        }

        $where[] = 'v.cve_id = ?';
        $params[] = $cve;
    }

    $allowedSeverities = [
        'critical',
        'high',
        'medium',
        'low',
        'informational',
    ];

    if ($severity !== null && $severity !== '') {
        if (!in_array($severity, $allowedSeverities, true)) {
            http_response_code(400);

            echo json_encode(
                [
                    'status' => 'error',
                    'message' => 'Invalid severity.',
                    'allowed_values' => $allowedSeverities,
                ],
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            );

            exit;
        }

        $where[] = 'v.severity = ?';
        $params[] = $severity;
    }

    if ($kevListed !== null && $kevListed !== '') {
        if (!in_array($kevListed, ['true', 'false'], true)) {
            http_response_code(400);

            echo json_encode(
                [
                    'status' => 'error',
                    'message' => 'Invalid kev_listed value. Use true or false.',
                ],
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            );

            exit;
        }

        $where[] = 'v.kev_listed = ?';
        $params[] = $kevListed === 'true' ? 1 : 0;
    }

    $whereSql = $where
        ? 'WHERE ' . implode(' AND ', $where)
        : '';

    /*
     * Total vulnerability count.
     */
    $countSql = "
        SELECT COUNT(*)
        FROM vulnerabilities v
        $whereSql
    ";

    $stmt = $pdo->prepare($countSql);
    $stmt->execute($params);

    $total = (int) $stmt->fetchColumn();

    /*
     * Vulnerability records.
     */
    $sql = "
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
        $whereSql
        ORDER BY
            v.cve_id DESC,
            v.id DESC
        LIMIT $limit
        OFFSET $offset
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

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
     * Associated ThreatPulse threats.
     *
     * Resolved with a single batched query (never one query per row), so
     * that a vulnerability can navigate directly to the threat
     * intelligence records it is associated with through
     * threat_vulnerabilities.
     */
    $vulnerabilityIds = [];

    foreach ($vulnerabilities as $vulnerability) {
        $vulnerabilityIds[] = (int) $vulnerability['id'];
    }

    $threatsByVulnerability = [];

    if ($vulnerabilityIds) {

        $placeholders = implode(
            ', ',
            array_fill(0, count($vulnerabilityIds), '?')
        );

        $threatSql = "
            SELECT
                tv.vulnerability_id,
                t.threat_uuid,
                t.external_id,
                t.title,
                t.severity,
                t.priority_score,
                t.confidence_level,
                t.exploitation_status
            FROM threat_vulnerabilities tv
            INNER JOIN threats t
                ON t.id = tv.threat_id
            WHERE tv.vulnerability_id IN ($placeholders)
            ORDER BY
                t.priority_score DESC,
                t.id DESC
        ";

        $stmt = $pdo->prepare($threatSql);

        foreach ($vulnerabilityIds as $index => $vulnerabilityId) {
            $stmt->bindValue(
                $index + 1,
                $vulnerabilityId,
                PDO::PARAM_INT
            );
        }

        $stmt->execute();

        foreach ($stmt->fetchAll() as $row) {

            $vulnerabilityId = (int) $row['vulnerability_id'];

            unset($row['vulnerability_id']);

            $row['priority_score'] = (float) $row['priority_score'];

            $threatsByVulnerability[$vulnerabilityId][] = $row;
        }
    }

    foreach ($vulnerabilities as &$vulnerability) {

        $vulnerability['threats'] =
            $threatsByVulnerability[(int) $vulnerability['id']]
                ?? [];
    }

    unset($vulnerability);

    $returned = count($vulnerabilities);

    $hasMore = ($offset + $returned) < $total;

    echo json_encode(
        [
            'status' => 'ok',
            'api_version' => '1.0',
            'data' => [
                'vulnerabilities' => $vulnerabilities,
            ],
            'pagination' => [
                'limit' => $limit,
                'offset' => $offset,
                'returned' => $returned,
                'total' => $total,
                'has_more' => $hasMore,
            ],
            'timestamp' => gmdate('c'),
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );

} catch (Throwable $exc) {

    error_log(
        'ThreatPulse public vulnerabilities API error: '
        . $exc->getMessage()
    );

    http_response_code(500);

    echo json_encode(
        [
            'status' => 'error',
            'message' => 'Unable to retrieve vulnerabilities.',
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
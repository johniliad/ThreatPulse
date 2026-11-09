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

    $sourceKey = isset($_GET['source_key'])
        ? trim((string) $_GET['source_key'])
        : null;

    $sourceType = isset($_GET['source_type'])
        ? strtolower(trim((string) $_GET['source_type']))
        : null;

    $where = [];
    $params = [];

    if ($sourceKey !== null && $sourceKey !== '') {
        if (!preg_match('/^[a-zA-Z0-9_.-]{1,100}$/', $sourceKey)) {
            http_response_code(400);

            echo json_encode(
                [
                    'status' => 'error',
                    'message' => 'Invalid source_key.',
                ],
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            );

            exit;
        }

        $where[] = 's.source_key = ?';
        $params[] = $sourceKey;
    }

    if ($sourceType !== null && $sourceType !== '') {
        if (!preg_match('/^[a-zA-Z0-9_.-]{1,100}$/', $sourceType)) {
            http_response_code(400);

            echo json_encode(
                [
                    'status' => 'error',
                    'message' => 'Invalid source_type.',
                ],
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            );

            exit;
        }

        $where[] = 's.source_type = ?';
        $params[] = $sourceType;
    }

    $whereSql = $where
        ? 'WHERE ' . implode(' AND ', $where)
        : '';

    /*
     * Count sources.
     */
    $countSql = "
        SELECT COUNT(*)
        FROM sources s
        $whereSql
    ";

    $stmt = $pdo->prepare($countSql);
    $stmt->execute($params);

    $total = (int) $stmt->fetchColumn();

    /*
     * Retrieve sources and actual relationship counts.
     */
    $sql = "
        SELECT
            s.id,
            s.source_key,
            s.name,
            s.source_type,
            s.url,
            s.provider,
            s.reliability,

            COUNT(DISTINCT ts.threat_id) AS threat_count

        FROM sources s

        LEFT JOIN threat_sources ts
            ON ts.source_id = s.id

        $whereSql

        GROUP BY
            s.id,
            s.source_key,
            s.name,
            s.source_type,
            s.url,
            s.provider,
            s.reliability

        ORDER BY
            s.name ASC,
            s.id ASC

        LIMIT $limit
        OFFSET $offset
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    $sources = $stmt->fetchAll();

    foreach ($sources as &$source) {
        $source['id'] = (int) $source['id'];
        $source['threat_count'] =
            (int) $source['threat_count'];
    }

    unset($source);

    $returned = count($sources);

    $hasMore = ($offset + $returned) < $total;

    echo json_encode(
        [
            'status' => 'ok',
            'api_version' => '1.0',
            'data' => [
                'sources' => $sources,
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
        'ThreatPulse public sources API error: '
        . $exc->getMessage()
    );

    http_response_code(500);

    echo json_encode(
        [
            'status' => 'error',
            'message' => 'Unable to retrieve intelligence sources.',
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
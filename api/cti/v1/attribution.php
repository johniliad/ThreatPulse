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

header('Cache-Control: public, max-age=300');


require_once __DIR__ . '/db.php';

/*
 * The source and attribution register.
 *
 * This is the product's statement of what it uses and on what terms — including
 * sources that are declared but deliberately **not** ingested, which a page built
 * only from the `sources` table can never show. The `sources` table records what
 * contributed a threat; this records what the product decided, and why.
 *
 * The register is written by publish.php from the backend's own register, so what
 * is served here is the register that produced the data being served alongside it.
 */
try {
    $pdo = threatpulse_db();

    /*
     * Pagination
     */
    $limit = filter_input(INPUT_GET, 'limit', FILTER_VALIDATE_INT);
    $offset = filter_input(INPUT_GET, 'offset', FILTER_VALIDATE_INT);

    $limit = $limit === false || $limit === null
        ? 100
        : max(1, min($limit, 200));

    $offset = $offset === false || $offset === null
        ? 0
        : max(0, $offset);

    /*
     * Optional filters
     */
    $ingestedFilter = isset($_GET['ingested'])
        ? strtolower(trim((string) $_GET['ingested']))
        : null;

    $sourceKey = isset($_GET['source_key'])
        ? trim((string) $_GET['source_key'])
        : null;

    $tierFilter = filter_input(INPUT_GET, 'tier', FILTER_VALIDATE_INT);

    if (
        $ingestedFilter !== null
        && !in_array($ingestedFilter, ['true', 'false', '1', '0'], true)
    ) {
        http_response_code(400);

        echo json_encode(
            [
                'status' => 'error',
                'message' => 'Invalid ingested filter.',
                'expected' => ['true', 'false'],
            ],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

        exit;
    }

    $where = [];
    $parameters = [];

    if ($ingestedFilter !== null && $ingestedFilter !== '') {
        $where[] = 'ingested = ?';
        $parameters[] = in_array($ingestedFilter, ['true', '1'], true)
            ? 1
            : 0;
    }

    if ($sourceKey !== null && $sourceKey !== '') {
        $where[] = 'source_key = ?';
        $parameters[] = $sourceKey;
    }

    if ($tierFilter !== false && $tierFilter !== null) {
        $where[] = 'tier = ?';
        $parameters[] = (int) $tierFilter;
    }

    $whereSql = $where === []
        ? ''
        : ' WHERE ' . implode(' AND ', $where);

    /*
     * Total matching records.
     */
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM source_attribution' . $whereSql
    );

    $stmt->execute($parameters);

    $total = (int) $stmt->fetchColumn();

    $stmt = $pdo->prepare(
        "
        SELECT
            source_key,
            name,
            provider,
            homepage,
            licence,
            licence_url,
            terms_url,
            tlp_default,
            ingested,
            attribution_text,
            tier,
            notes,
            updated_at
        FROM source_attribution
        " . $whereSql . "
        ORDER BY ingested DESC, source_key ASC
        LIMIT " . (int) $limit . " OFFSET " . (int) $offset
    );

    $stmt->execute($parameters);

    $sources = $stmt->fetchAll();

    foreach ($sources as &$source) {
        $source['ingested'] = (bool) $source['ingested'];

        if ($source['tier'] !== null) {
            $source['tier'] = (int) $source['tier'];
        }
    }

    unset($source);

    $returned = count($sources);

    $hasMore = ($offset + $returned) < $total;

    echo json_encode(
        [
            'status' => 'ok',
            'api_version' => '1.0',
            'data' => [
                'attribution' => [
                    'policy' => (
                        'Every ingested source is attributed. Attribution is '
                        . 'provenance, not endorsement. Sources listed with '
                        . 'ingested=false are declared and deliberately not used.'
                    ),
                    'stored' => true,
                    'sources' => $sources,
                ],
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
        'ThreatPulse public attribution API error: '
        . $exc->getMessage()
    );

    /*
     * The register table is optional: publishing works without it. When it is
     * absent, say so precisely, because "the register is empty" and "the register
     * has never been stored" are different facts and only one of them is a
     * deployment problem.
     */
    http_response_code(200);

    echo json_encode(
        [
            'status' => 'ok',
            'api_version' => '1.0',
            'data' => [
                'attribution' => [
                    'policy' => (
                        'Every ingested source is attributed. Attribution is '
                        . 'provenance, not endorsement.'
                    ),
                    'stored' => false,
                    'message' => (
                        'The attribution register has not been stored on this '
                        . 'deployment. Create the source_attribution table (see '
                        . 'deployment/DEPLOYMENT.md) and publish once; the backend '
                        . 'sends its register with every publication.'
                    ),
                    'sources' => [],
                ],
            ],
            'timestamp' => gmdate('c'),
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}

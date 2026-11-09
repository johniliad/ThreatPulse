<?php

declare(strict_types=1);

/*
 * ThreatPulse public API — source health
 *
 * How each source behaved on the run that produced the current publication.
 *
 * The attribution register says what a source is and on what terms it may be
 * used. This says whether it actually worked: ok, degraded (a retrieval failure
 * that fell back to a last-known-good snapshot) or failed, with the counts that
 * justify the verdict and, where a source failed, why.
 *
 * Health is per run, not per record, so it is stored as one JSON snapshot on the
 * publication rather than joined from the threat tables. That also means an older
 * publication can never be described using a newer run's health.
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

/**
 * Reject a query parameter that is not a plain token.
 *
 * Both filters are matched against keys the backend generates, so anything
 * outside that alphabet is a malformed request rather than an empty result.
 */
function respond_invalid_parameter(string $message): void
{
    http_response_code(400);

    echo json_encode(
        [
            'status' => 'error',
            'message' => $message,
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );

    exit;
}

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

    $status = isset($_GET['status'])
        ? strtolower(trim((string) $_GET['status']))
        : null;

    if (
        $sourceKey !== null &&
        $sourceKey !== '' &&
        !preg_match('/^[a-zA-Z0-9_.-]{1,100}$/', $sourceKey)
    ) {
        respond_invalid_parameter('Invalid source_key.');
    }

    if (
        $status !== null &&
        $status !== '' &&
        !in_array($status, ['ok', 'degraded', 'failed'], true)
    ) {
        respond_invalid_parameter(
            'Invalid status. Allowed: ok, degraded, failed.'
        );
    }

    /*
     * The health of the publication currently being served, not of the most
     * recent attempt: a publication still receiving chunks has no health worth
     * reporting, and a half-received run must never be described as healthy.
     */

    $healthJson = null;
    $publicationUuid = null;
    $generatedAt = null;

    try {
        $publicationStmt = $pdo->query(
            '
            SELECT
                publication_uuid,
                generated_at,
                source_health
            FROM publications
            WHERE status = \'published\'
            ORDER BY generated_at DESC, id DESC
            LIMIT 1
            '
        );

        $publicationRow = $publicationStmt->fetch();

        if ($publicationRow !== false) {
            $publicationUuid = $publicationRow['publication_uuid'];
            $generatedAt = $publicationRow['generated_at'];
            $healthJson = $publicationRow['source_health'];
        }

    } catch (Throwable $columnError) {

        /*
         * Older deployments predate the column. That is a missing report, not a
         * broken API, so it is logged and served as "not recorded" instead of
         * turning every request into a 500.
         */

        error_log(
            'ThreatPulse source health unavailable: ' .
            $columnError->getMessage()
        );
    }

    $health = is_string($healthJson) && $healthJson !== ''
        ? json_decode($healthJson, true)
        : null;

    if (!is_array($health)) {
        $health = [];
    }

    $healthAvailable = $health !== [];

    $allSources = isset($health['sources']) && is_array($health['sources'])
        ? $health['sources']
        : [];

    $sources = array_values(
        array_filter(
            $allSources,
            static function ($entry) use ($sourceKey, $status): bool {
                if (!is_array($entry)) {
                    return false;
                }

                if (
                    $sourceKey !== null &&
                    $sourceKey !== '' &&
                    ($entry['source_key'] ?? null) !== $sourceKey
                ) {
                    return false;
                }

                if (
                    $status !== null &&
                    $status !== '' &&
                    ($entry['status'] ?? null) !== $status
                ) {
                    return false;
                }

                return true;
            }
        )
    );

    $total = count($sources);

    $page = array_slice($sources, $offset, $limit);

    $returned = count($page);

    echo json_encode(
        [
            'status' => 'ok',
            'api_version' => '1.0',
            'data' => [
                'available' => $healthAvailable,
                'publication_uuid' => $publicationUuid,
                'generated_at' => $generatedAt,
                'summary' => isset($health['summary']) &&
                    is_array($health['summary'])
                    ? $health['summary']
                    : null,
                'source_health' => $page,
            ],
            'pagination' => [
                'limit' => $limit,
                'offset' => $offset,
                'returned' => $returned,
                'total' => $total,
                'has_more' => ($offset + $returned) < $total,
            ],
            'timestamp' => gmdate('c'),
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );

} catch (Throwable $error) {
    error_log(
        'ThreatPulse source health failure: ' . $error->getMessage()
    );

    http_response_code(500);

    echo json_encode(
        [
            'status' => 'error',
            'message' => 'Unable to retrieve source health.',
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}


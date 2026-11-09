<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

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
        ? 20
        : max(1, min($limit, 100));

    $offset = $offset === false || $offset === null
        ? 0
        : max(0, $offset);

    /*
     * Only completed publications are listed.
     *
     * A run interrupted between chunks leaves a row whose counters cover a
     * fraction of the snapshot. Listing it would report that fraction as the
     * published set: the dashboard's "latest publication" is items[0] and the
     * hero states its threat count as fact, so a partial row is not merely
     * untidy, it is wrong. changes.php and source_health.php already read only
     * completed publications, so this makes the three endpoints agree.
     *
     * `include_incomplete=1` lists them too, which is what an operator needs in
     * order to see a publication stuck mid-transfer.
     */
    $includeIncomplete = filter_input(
        INPUT_GET,
        'include_incomplete',
        FILTER_VALIDATE_BOOLEAN
    ) === true;

    $statusFilter = $includeIncomplete
        ? ''
        : "WHERE p.status = 'published'";

    /*
     * Count publications.
     */
    $stmt = $pdo->query(
        $includeIncomplete
            ? 'SELECT COUNT(*) FROM publications'
            : "SELECT COUNT(*) FROM publications WHERE status = 'published'"
    );

    $total = (int) $stmt->fetchColumn();

    /*
     * Retrieve publications.

     * Threat and relationship counts are calculated from the
     * relationship table rather than trusting publication
     * summary fields.
     */
    $sql = "
        SELECT
            p.id,
            p.publication_uuid,
            p.schema_version,
            p.generated_at,
            p.created_at,
            p.status,

            COUNT(DISTINCT pt.threat_id) AS threat_count,

            COUNT(DISTINCT v.id) AS vulnerability_count

        FROM publications p

        LEFT JOIN publication_threats pt
            ON pt.publication_id = p.id

        LEFT JOIN threat_vulnerabilities tv
            ON tv.threat_id = pt.threat_id

        LEFT JOIN vulnerabilities v
            ON v.id = tv.vulnerability_id

        $statusFilter

        GROUP BY
            p.id,
            p.publication_uuid,
            p.schema_version,
            p.generated_at,
            p.created_at,
            p.status

        ORDER BY
            p.generated_at DESC,
            p.id DESC

        LIMIT $limit
        OFFSET $offset
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute();

    $publications = $stmt->fetchAll();

    foreach ($publications as &$publication) {
        $publication['id'] = (int) $publication['id'];
        $publication['threat_count'] =
            (int) $publication['threat_count'];
        $publication['vulnerability_count'] =
            (int) $publication['vulnerability_count'];
    }

    unset($publication);

    $returned = count($publications);

    $hasMore = ($offset + $returned) < $total;

    echo json_encode(
        [
            'status' => 'ok',
            'api_version' => '1.0',
            'data' => [
                'publications' => $publications,
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
        'ThreatPulse public publications API error: '
        . $exc->getMessage()
    );

    http_response_code(500);

    echo json_encode(
        [
            'status' => 'error',
            'message' => 'Unable to retrieve publications.',
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}
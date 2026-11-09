<?php

declare(strict_types=1);

/*
 * ThreatPulse public API — what changed
 *
 * The delta between the publication being served and the one before it.
 *
 * A publication is a complete snapshot, which makes "what is in the product"
 * easy to answer and "what is new" impossible without holding the previous
 * snapshot too. This endpoint does that comparison server-side, so a consumer
 * never has to store a snapshot to find out what moved.
 *
 * Three kinds of movement, and nothing presumed:
 *
 *   added    — the threat is in this publication and was not in the previous one
 *   removed  — it was in the previous publication and is not in this one
 *   changed  — it is in both, and the pipeline recorded field-level movement in
 *              `metadata.temporal.changed_since_previous` when it published it
 *
 * "Unchanged" is reported as a count but is not listed: it is the complement of
 * the other three, and listing several thousand rows to say nothing happened is
 * not a feed.
 *
 * The comparison is always against the immediately preceding publication. Field
 * movement is recorded relative to that predecessor at publish time, so it
 * cannot be re-derived for an arbitrary earlier baseline. Use `kind` to select
 * one list; the summary counts are always for all three.
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
 * One threat as this endpoint reports it.
 *
 * Deliberately a summary, not the threat: a feed entry identifies the change and
 * gives enough context to judge it. The full record is one request away at
 * /threat.php?threat_uuid=…, and duplicating it here would make the feed as
 * large as the publication it describes.
 */
function change_entry(array $row, string $change): array
{
    $entry = [
        'threat_uuid' => $row['threat_uuid'],
        'external_id' => $row['external_id'],
        'title' => $row['title'],
        'severity' => $row['severity'],
        'priority_score' => $row['priority_score'] === null
            ? null
            : (float) $row['priority_score'],
        'change' => $change,
    ];

    if (isset($row['changed_fields'])) {
        $entry['changed_fields'] = $row['changed_fields'];
    }

    return $entry;
}

/**
 * Read the threat set behind one publication, keyed by threat_uuid.
 *
 * `metadata` is only requested when ``$withMetadata`` is true, because the
 * change flags live inside it and decoding several thousand JSON documents is
 * the single most expensive thing this endpoint can do.
 */
function publication_threats(
    PDO $pdo,
    int $publicationId,
    bool $withMetadata
): array {
    $columns = 't.threat_uuid, t.external_id, t.title, t.severity,
        t.priority_score';

    if ($withMetadata) {
        $columns .= ', t.metadata';
    }

    $stmt = $pdo->prepare(
        '
        SELECT ' . $columns . '
        FROM publication_threats pt
        INNER JOIN threats t ON t.id = pt.threat_id
        WHERE pt.publication_id = ?
        '
    );

    $stmt->execute([$publicationId]);

    $threats = [];

    while ($row = $stmt->fetch()) {
        $threats[$row['threat_uuid']] = $row;
    }

    return $threats;
}

/**
 * Field movement recorded for a threat when it was published.
 *
 * Written by the pipeline, not inferred here: the pipeline is the only place that
 * has seen both the old and the new value. Reading it back is what makes
 * "changed" honest rather than a guess from scores that happen to differ.
 */
function changed_fields(array $row): array
{
    $metadata = $row['metadata'] ?? null;

    if (!is_string($metadata) || $metadata === '') {
        return [];
    }

    $decoded = json_decode($metadata, true);

    if (!is_array($decoded)) {
        return [];
    }

    $temporal = $decoded['temporal'] ?? null;

    if (!is_array($temporal)) {
        return [];
    }

    $fields = $temporal['changed_since_previous'] ?? null;

    if (!is_array($fields)) {
        return [];
    }

    return array_values(
        array_filter($fields, static fn ($field): bool => is_string($field))
    );
}

/**
 * Highest priority first, then by external id, so the feed is stable between
 * requests without depending on the order rows happen to come back in.
 */
function sort_entries(array $entries): array
{
    usort(
        $entries,
        static function (array $a, array $b): int {
            $left = $a['priority_score'] ?? 0.0;
            $right = $b['priority_score'] ?? 0.0;

            if ($left !== $right) {
                return $right <=> $left;
            }

            return strcmp(
                (string) ($a['external_id'] ?? ''),
                (string) ($b['external_id'] ?? '')
            );
        }
    );

    return $entries;
}

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

    $limit = filter_input(INPUT_GET, 'limit', FILTER_VALIDATE_INT);
    $offset = filter_input(INPUT_GET, 'offset', FILTER_VALIDATE_INT);

    $limit = $limit === false || $limit === null
        ? 50
        : max(1, min($limit, 100));

    $offset = $offset === false || $offset === null
        ? 0
        : max(0, $offset);

    $kind = isset($_GET['kind'])
        ? strtolower(trim((string) $_GET['kind']))
        : 'added';

    if ($kind === '') {
        $kind = 'added';
    }

    if (!in_array($kind, ['added', 'removed', 'changed'], true)) {
        respond_invalid_parameter(
            'Invalid kind. Allowed: added, removed, changed.'
        );
    }

    /*
     * Only completed publications are compared. A run still receiving chunks is
     * a partial snapshot, and diffing against it would report everything it has
     * not received yet as removed.
     */

    $stmt = $pdo->query(
        '
        SELECT
            id,
            publication_uuid,
            generated_at
        FROM publications
        WHERE status = \'published\'
        ORDER BY generated_at DESC, id DESC
        LIMIT 2
        '
    );

    $rows = $stmt->fetchAll();

    if (!is_array($rows)) {
        $rows = [];
    }

    $latest = $rows[0] ?? null;
    $previous = $rows[1] ?? null;

    $latestThreats = $latest === null
        ? []
        : publication_threats($pdo, (int) $latest['id'], true);

    $previousThreats = $previous === null
        ? []
        : publication_threats($pdo, (int) $previous['id'], false);

    $added = [];
    $removed = [];
    $changed = [];
    $unchanged = 0;

    foreach ($latestThreats as $uuid => $row) {
        if (!isset($previousThreats[$uuid])) {
            $added[] = change_entry($row, 'added');

            continue;
        }

        $fields = changed_fields($row);

        if ($fields === []) {
            $unchanged++;

            continue;
        }

        $row['changed_fields'] = $fields;

        $changed[] = change_entry($row, 'changed');
    }

    foreach ($previousThreats as $uuid => $row) {
        if (!isset($latestThreats[$uuid])) {
            $removed[] = change_entry($row, 'removed');
        }
    }

    $lists = [
        'added' => sort_entries($added),
        'removed' => sort_entries($removed),
        'changed' => sort_entries($changed),
    ];

    $selected = $lists[$kind];

    $total = count($selected);

    $page = array_slice($selected, $offset, $limit);

    $returned = count($page);

    echo json_encode(
        [
            'status' => 'ok',
            'api_version' => '1.0',
            'data' => [
                'publication_uuid' => $latest['publication_uuid'] ?? null,
                'generated_at' => $latest['generated_at'] ?? null,
                'previous_publication_uuid' =>
                    $previous['publication_uuid'] ?? null,
                'previous_generated_at' =>
                    $previous['generated_at'] ?? null,
                'kind' => $kind,
                'summary' => [
                    'added' => count($lists['added']),
                    'removed' => count($lists['removed']),
                    'changed' => count($lists['changed']),
                    'unchanged' => $unchanged,
                    'published' => count($latestThreats),
                    'previous' => count($previousThreats),
                ],
                'changes' => $page,
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
    error_log('ThreatPulse changes failure: ' . $error->getMessage());

    http_response_code(500);

    echo json_encode(
        [
            'status' => 'error',
            'message' => 'Unable to retrieve publication changes.',
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
}


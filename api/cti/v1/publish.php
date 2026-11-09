<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

/*
 * Body size policy.
 *
 * The publication arrives as one POST body, so it must fit post_max_size. Keep
 * this value in step with publication.max_payload_bytes on the backend: the
 * backend refuses to transmit above its limit, and this refuses to accept above
 * its own, so the two ends agree rather than one silently truncating.
 */
const MAX_PUBLICATION_BYTES = 8 * 1024 * 1024;

/*
 * Resource limits, raised deliberately.
 *
 * A publication can be tens of megabytes: the body is decoded into PHP arrays that
 * cost an order of magnitude more memory than the JSON that produced them. The
 * stock limits are sized for a form post, not for this.
 *
 * These are raised rather than left to the host default because the failure mode
 * is a bare HTTP 500 with nothing in the response body — which is indistinguishable
 * from a dozen other faults and costs a deployment round-trip to diagnose. A limit
 * that is genuinely too low should be reported by the script, not enforced by
 * terminating it mid-transaction.
 *
 * `set_time_limit` is called with a bound rather than 0: an unbounded script that
 * hangs holds a database connection open, which is worse than one that fails.
 */
@ini_set('memory_limit', '512M');
@set_time_limit(300);


require_once __DIR__ . '/db.php';

$config = require '/home/iliadis/threatpulse-secrets/publisher-config.php';

$expectedToken = $config['publisher_token'] ?? '';

function respond(int $statusCode, array $payload): never
{
    /*
     * Discard anything already buffered. A warning, or text placed before the
     * opening <?php tag of an included secrets file, would otherwise be sent
     * before this JSON and make the response unparseable — the client would
     * report a failure for a request that succeeded.
     */
    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    http_response_code($statusCode);

    echo json_encode(
        $payload,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );

    exit;
}

function require_status_stored(
    PDO $pdo,
    int $publicationId,
    string $expectedStatus
): void {
    /*
     * Read the status back inside the transaction.
     *
     * MySQL does not fail when a value does not fit an ENUM or SET column in a
     * non-strict sql_mode: it stores the empty string and carries on. When that
     * happens to this column, the publication row exists with a status the next
     * chunk does not recognise, so every later chunk is refused as "already
     * complete" and the publication can never be finished — while each
     * individual request looks correct.
     *
     * That was a live failure, not a hypothesis: publications.status was
     * enum('draft','published','superseded'), 'receiving' was truncated to '',
     * and fourteen runs stored only their first chunk before being refused with
     * a message that pointed at the endpoint instead of the schema.
     *
     * Reading the value back turns the silent truncation into one named error on
     * the request that caused it.
     */
    $statusStmt = $pdo->prepare(
        'SELECT status FROM publications WHERE id = ?'
    );

    $statusStmt->execute([$publicationId]);

    $storedStatus = $statusStmt->fetchColumn();

    if ($storedStatus === $expectedStatus) {
        return;
    }

    $pdo->rollBack();

    respond(500, [
        'status' => 'error',
        'message' =>
            'publications.status cannot store "' . $expectedStatus . '"',
        'stored_status' => $storedStatus,
        'hint' =>
            'The column is probably an ENUM or SET without that value, and a '
            . 'non-strict sql_mode truncated it. Run: ALTER TABLE publications '
            . "MODIFY status VARCHAR(20) NOT NULL DEFAULT 'published';"
    ]);
}

/*
 * --------------------------------------------------------------------------
 * Authentication
 * --------------------------------------------------------------------------
 */

$authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

if (!preg_match('/^Bearer\s+(.+)$/i', $authorization, $matches)) {
    respond(401, [
        'status' => 'error',
        'message' => 'Missing authentication token'
    ]);
}

$providedToken = trim($matches[1]);

if (
    $expectedToken === '' ||
    !hash_equals($expectedToken, $providedToken)
) {
    respond(403, [
        'status' => 'error',
        'message' => 'Invalid authentication token'
    ]);
}

/*
 * --------------------------------------------------------------------------
 * HTTP method
 * --------------------------------------------------------------------------
 */

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');

    respond(405, [
        'status' => 'error',
        'message' => 'Method not allowed'
    ]);
}

/*
 * --------------------------------------------------------------------------
 * JSON body
 * --------------------------------------------------------------------------
 */

$declaredLength = isset($_SERVER['CONTENT_LENGTH'])
    ? (int) $_SERVER['CONTENT_LENGTH']
    : 0;

$rawBody = file_get_contents('php://input');

if ($declaredLength > MAX_PUBLICATION_BYTES) {
    respond(413, [
        'status' => 'error',
        'message' => 'Publication exceeds the accepted body size.',
        'declared_bytes' => $declaredLength,
        'max_bytes' => MAX_PUBLICATION_BYTES
    ]);
}

/*
 * When a body exceeds post_max_size, PHP discards it before the script runs, so
 * the request looks empty. Reporting that as "Request body is empty" sends the
 * operator looking in the wrong place, so it is distinguished explicitly.
 */
if (($rawBody === false || trim($rawBody) === '') && $declaredLength > 0) {
    respond(413, [
        'status' => 'error',
        'message' =>
            'Request body was discarded before reaching the API, which normally '
            . 'means it exceeded post_max_size.',
        'declared_bytes' => $declaredLength,
        'post_max_size' => (string) ini_get('post_max_size'),
        'max_bytes' => MAX_PUBLICATION_BYTES
    ]);
}

if ($rawBody === false || trim($rawBody) === '') {
    respond(400, [
        'status' => 'error',
        'message' => 'Request body is empty'
    ]);
}

try {
    $payload = json_decode(
        $rawBody,
        true,
        512,
        JSON_THROW_ON_ERROR
    );
} catch (JsonException $e) {
    respond(400, [
        'status' => 'error',
        'message' => 'Invalid JSON'
    ]);
}

if (!is_array($payload)) {
    respond(400, [
        'status' => 'error',
        'message' => 'JSON root must be an object'
    ]);
}

/*
 * --------------------------------------------------------------------------
 * Publication validation
 * --------------------------------------------------------------------------
 */

foreach (
    [
        'publication_uuid',
        'schema_version',
        'generated_at',
        'threats'
    ] as $field
) {
    if (!array_key_exists($field, $payload)) {
        respond(400, [
            'status' => 'error',
            'message' => "Missing required field: {$field}"
        ]);
    }
}

$publicationUuid = (string)$payload['publication_uuid'];

if (
    !preg_match(
        '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/',
        $publicationUuid
    )
) {
    respond(400, [
        'status' => 'error',
        'message' => 'Invalid publication_uuid'
    ]);
}

$schemaVersion = (string)$payload['schema_version'];

if ($schemaVersion !== '1.0') {
    respond(400, [
        'status' => 'error',
        'message' => 'Unsupported schema_version'
    ]);
}

$generatedTimestamp = strtotime(
    (string)$payload['generated_at']
);

if ($generatedTimestamp === false) {
    respond(400, [
        'status' => 'error',
        'message' => 'Invalid generated_at'
    ]);
}

if (!is_array($payload['threats'])) {
    respond(400, [
        'status' => 'error',
        'message' => 'threats must be an array'
    ]);
}

$sources = $payload['sources'] ?? [];

if (!is_array($sources)) {
    respond(400, [
        'status' => 'error',
        'message' => 'sources must be an array'
    ]);
}

/*
 * --------------------------------------------------------------------------
 * Chunked publication
 * --------------------------------------------------------------------------
 *
 * A publication too large for a single request is sent as several. Each carries
 * the same envelope, a `chunk` block, and a slice of `threats`, so nothing has to
 * be remembered between requests and any chunk can be retried on its own.
 *
 * `chunk` is optional. Absent means a single-request publication, which behaves
 * exactly as it did before chunking existed — an older backend keeps working
 * against a newer API.
 */

$chunkIndex = 0;
$chunkCount = 1;

if (array_key_exists('chunk', $payload)) {

    $chunk = $payload['chunk'];

    if (!is_array($chunk)) {
        respond(400, [
            'status' => 'error',
            'message' => 'chunk must be an object'
        ]);
    }

    $chunkIndex = filter_var(
        $chunk['index'] ?? null,
        FILTER_VALIDATE_INT
    );

    $chunkCount = filter_var(
        $chunk['count'] ?? null,
        FILTER_VALIDATE_INT
    );

    if (
        $chunkIndex === false ||
        $chunkCount === false ||
        $chunkIndex < 0 ||
        $chunkCount < 1 ||
        $chunkIndex >= $chunkCount
    ) {
        respond(400, [
            'status' => 'error',
            'message' =>
                'chunk.index must satisfy 0 <= index < chunk.count'
        ]);
    }
}

$isChunked = $chunkCount > 1;
$isFinalChunk = $chunkIndex === ($chunkCount - 1);

/*
 * --------------------------------------------------------------------------
 * Attribution register
 * --------------------------------------------------------------------------
 *
 * Optional. The backend sends its source register with the publication so that
 * the public Sources page can state what the product uses, on what terms, and
 * what it deliberately does not use — including sources that never contribute a
 * threat.
 */

$attribution = $payload['attribution'] ?? null;

if ($attribution !== null && !is_array($attribution)) {
    respond(400, [
        'status' => 'error',
        'message' => 'attribution must be an object'
    ]);
}

/*
 * --------------------------------------------------------------------------
 * Source health
 * --------------------------------------------------------------------------
 *
 * Optional. How each source behaved on the run that produced this publication:
 * ok, degraded or failed, with the counts and the failure reason. The register
 * above says what a source is; this says whether it actually worked, which is
 * the difference between "declared" and "contributing".
 *
 * It travels in every chunk because it belongs to the publication, not to a
 * slice of threats.
 */

$sourceHealth = $payload['source_health'] ?? null;

if ($sourceHealth !== null && !is_array($sourceHealth)) {
    respond(400, [
        'status' => 'error',
        'message' => 'source_health must be an object'
    ]);
}

/*
 * --------------------------------------------------------------------------
 * Database transaction
 * --------------------------------------------------------------------------
 */

try {

    $pdo = threatpulse_db_write();

    $pdo->beginTransaction();

    /*
     * Idempotency and continuation.
     *
     * A single-request publication is idempotent on publication_uuid, as before.
     * A chunked one is not: chunks 1..n-1 must find the row chunk 0 created and
     * append to it, so the rule depends on which chunk arrived.
     */

    $stmt = $pdo->prepare(
        'SELECT id, status
         FROM publications
         WHERE publication_uuid = ?
         LIMIT 1'
    );

    $stmt->execute([$publicationUuid]);

    $existingPublication = $stmt->fetch();

    $publicationId = null;

    if ($existingPublication) {

        if ($chunkIndex === 0) {
            $pdo->rollBack();

            respond(409, [
                'status' => 'error',
                'message' => 'Publication already exists',
                'publication_uuid' => $publicationUuid
            ]);
        }

        /*
         * A later chunk of a publication already in progress. If it has been
         * finalised, this is a late duplicate: accepting it would append threats
         * to a completed publication, so it is refused instead.
         */
        if ($existingPublication['status'] !== 'receiving') {
            $pdo->rollBack();

            respond(409, [
                'status' => 'error',
                'message' => 'Publication is already complete',
                'publication_uuid' => $publicationUuid,
                'publication_status' => $existingPublication['status']
            ]);
        }

        $publicationId = (int)$existingPublication['id'];

    } elseif ($chunkIndex !== 0) {

        /*
         * A chunk arrived before the one that creates the publication. That is a
         * client bug, and accepting it would leave a partial publication with no
         * first chunk ever able to complete it.
         */
        $pdo->rollBack();

        respond(409, [
            'status' => 'error',
            'message' => 'Chunk received before chunk 0; send chunks in order',
            'publication_uuid' => $publicationUuid,
            'chunk_index' => $chunkIndex
        ]);
    }

    /*
     * ----------------------------------------------------------------------
     * Sources
     * ----------------------------------------------------------------------
     */

    $sourceIds = [];

    $sourceUpsert = $pdo->prepare(
        '
        INSERT INTO sources (
            source_key,
            name,
            source_type,
            url,
            provider,
            reliability,
            enabled,
            metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, TRUE, ?)
        ON DUPLICATE KEY UPDATE
            name = VALUES(name),
            source_type = VALUES(source_type),
            url = VALUES(url),
            provider = VALUES(provider),
            reliability = VALUES(reliability),
            metadata = VALUES(metadata)
        '
    );

    $sourceLookup = $pdo->prepare(
        '
        SELECT id
        FROM sources
        WHERE source_key = ?
        LIMIT 1
        '
    );

    foreach ($sources as $source) {

        if (!is_array($source)) {
            throw new RuntimeException(
                'Invalid source object'
            );
        }

        $sourceKey = trim(
            (string)($source['source_key'] ?? '')
        );

        if ($sourceKey === '') {
            throw new RuntimeException(
                'Source source_key is required'
            );
        }

        $sourceUpsert->execute([
            $sourceKey,
            $source['name'] ?? $sourceKey,
            $source['source_type'] ?? 'other',
            $source['url'] ?? null,
            $source['provider'] ?? null,
            $source['reliability'] ?? 'unknown',
            isset($source['metadata'])
                ? json_encode(
                    $source['metadata'],
                    JSON_UNESCAPED_SLASHES |
                    JSON_UNESCAPED_UNICODE
                )
                : null
        ]);

        $sourceLookup->execute([$sourceKey]);

        $sourceRow = $sourceLookup->fetch();

        if (!$sourceRow) {
            throw new RuntimeException(
                "Unable to resolve source: {$sourceKey}"
            );
        }

        $sourceIds[$sourceKey] = (int)$sourceRow['id'];
    }

    /*
     * ----------------------------------------------------------------------
     * Source attribution register
     * ----------------------------------------------------------------------
     *
     * The register is the backend's own statement of what it uses and on what
     * terms. It is reference data rather than per-publication data, so it is
     * upserted rather than appended.
     *
     * A missing table is deliberately **not** fatal. The register is provenance
     * about the product; the intelligence in this publication is the product. A
     * failure to store an optional reference table should not stop the
     * intelligence from being published, so the failure is logged and reported in
     * the response as `attribution_stored: false` rather than raised. The absence
     * is therefore visible rather than silent.
     */

    $attributionStored = false;

    if (
        is_array($attribution) &&
        isset($attribution['sources']) &&
        is_array($attribution['sources'])
    ) {

        try {
            $attributionStmt = $pdo->prepare(
                '
                INSERT INTO source_attribution (
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
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP()
                )
                ON DUPLICATE KEY UPDATE
                    name = VALUES(name),
                    provider = VALUES(provider),
                    homepage = VALUES(homepage),
                    licence = VALUES(licence),
                    licence_url = VALUES(licence_url),
                    terms_url = VALUES(terms_url),
                    tlp_default = VALUES(tlp_default),
                    ingested = VALUES(ingested),
                    attribution_text = VALUES(attribution_text),
                    tier = VALUES(tier),
                    notes = VALUES(notes),
                    updated_at = UTC_TIMESTAMP()
                '
            );

            foreach ($attribution['sources'] as $entry) {

                if (!is_array($entry)) {
                    continue;
                }

                $entryKey = trim((string)($entry['source_key'] ?? ''));

                if ($entryKey === '') {
                    continue;
                }

                $attributionStmt->execute([
                    $entryKey,
                    (string)($entry['name'] ?? $entryKey),
                    $entry['provider'] ?? null,
                    $entry['homepage'] ?? null,
                    $entry['licence'] ?? null,
                    $entry['licence_url'] ?? null,
                    $entry['terms_url'] ?? null,
                    $entry['tlp_default'] ?? null,
                    !empty($entry['ingested']) ? 1 : 0,
                    $entry['attribution_text'] ?? null,
                    isset($entry['tier']) && is_numeric($entry['tier'])
                        ? (int)$entry['tier']
                        : null,
                    $entry['notes'] ?? null
                ]);
            }

            $attributionStored = true;

        } catch (Throwable $attributionError) {

            error_log(
                'ThreatPulse attribution register not stored: ' .
                $attributionError->getMessage()
            );
        }
    }

    /*
     * ----------------------------------------------------------------------
     * Publication counts
     * ----------------------------------------------------------------------
     */

    $threatCount = count($payload['threats']);

    $criticalCount = 0;
    $highCount = 0;
    $mediumCount = 0;
    $lowCount = 0;

    foreach ($payload['threats'] as $threat) {

        if (!is_array($threat)) {
            throw new RuntimeException(
                'Each threat must be an object'
            );
        }

        $severity = strtolower(
            (string)($threat['severity'] ?? 'medium')
        );

        switch ($severity) {
            case 'critical':
                $criticalCount++;
                break;

            case 'high':
                $highCount++;
                break;

            case 'medium':
                $mediumCount++;
                break;

            case 'low':
                $lowCount++;
                break;
        }
    }

    /*
     * ----------------------------------------------------------------------
     * Publication
     * ----------------------------------------------------------------------
     */

    /*
     * Publication row.
     *
     * Created by chunk 0 and updated by every later chunk. The counts accumulate
     * across chunks rather than being read from the summary, so the row states what
     * was actually stored — and after the final chunk the totals are the sum over
     * every slice, which is the whole publication.
     */

    if ($publicationId === null) {

        $publicationStmt = $pdo->prepare(
            '
            INSERT INTO publications (
                publication_uuid,
                schema_version,
                generated_at,
                published_at,
                status,
                threat_count,
                critical_count,
                high_count,
                medium_count,
                low_count,
                summary
            )
            VALUES (
                ?,
                ?,
                ?,
                UTC_TIMESTAMP(),
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            )
            '
        );

        $publicationStmt->execute([
            $publicationUuid,
            $schemaVersion,
            gmdate(
                'Y-m-d H:i:s',
                $generatedTimestamp
            ),
            $isChunked ? 'receiving' : 'published',
            $threatCount,
            $criticalCount,
            $highCount,
            $mediumCount,
            $lowCount,
            isset($payload['summary'])
                ? json_encode(
                    $payload['summary'],
                    JSON_UNESCAPED_SLASHES |
                    JSON_UNESCAPED_UNICODE
                )
                : null
        ]);

        $publicationId = (int)$pdo->lastInsertId();

        require_status_stored(
            $pdo,
            $publicationId,
            $isChunked ? 'receiving' : 'published'
        );

    } else {

        $publicationUpdate = $pdo->prepare(
            '
            UPDATE publications
            SET
                threat_count = threat_count + ?,
                critical_count = critical_count + ?,
                high_count = high_count + ?,
                medium_count = medium_count + ?,
                low_count = low_count + ?,
                status = ?,
                published_at = UTC_TIMESTAMP()
            WHERE id = ?
            '
        );

        $publicationUpdate->execute([
            $threatCount,
            $criticalCount,
            $highCount,
            $mediumCount,
            $lowCount,
            $isFinalChunk ? 'published' : 'receiving',
            $publicationId
        ]);

        require_status_stored(
            $pdo,
            $publicationId,
            $isFinalChunk ? 'published' : 'receiving'
        );
    }

    /*
     * ----------------------------------------------------------------------
     * Source health
     * ----------------------------------------------------------------------
     *
     * Stored as JSON on the publication row rather than in a table of its own:
     * it is a per-run snapshot, always read whole, never joined or filtered in
     * SQL.
     *
     * Optional, like the attribution register, and for the same reason — a
     * publication without it is still valid intelligence. A missing column or a
     * failed write is logged and reported as `source_health_stored: false`
     * rather than raised, because refusing to store threat data over a health
     * column would be a disproportionate failure.
     */

    $sourceHealthStored = false;

    if (
        is_array($sourceHealth) &&
        isset($sourceHealth['sources']) &&
        is_array($sourceHealth['sources'])
    ) {
        try {
            $sourceHealthStmt = $pdo->prepare(
                '
                UPDATE publications
                SET source_health = ?
                WHERE id = ?
                '
            );

            $sourceHealthStmt->execute([
                json_encode(
                    $sourceHealth,
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                ),
                $publicationId
            ]);

            $sourceHealthStored = true;

        } catch (Throwable $sourceHealthError) {

            error_log(
                'ThreatPulse source health not stored: ' .
                $sourceHealthError->getMessage()
            );
        }
    }

    /*
     * ----------------------------------------------------------------------
     * Prepared statements
     * ----------------------------------------------------------------------
     */

    $threatLookup = $pdo->prepare(
        '
        SELECT id
        FROM threats
        WHERE threat_uuid = ?
        LIMIT 1
        '
    );

    $threatInsert = $pdo->prepare(
        '
        INSERT INTO threats (
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
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '
    );

    $threatUpdate = $pdo->prepare(
        '
        UPDATE threats
        SET
            external_id = ?,
            title = ?,
            threat_type = ?,
            severity = ?,
            priority_score = ?,
            confidence_score = ?,
            confidence_level = ?,
            exploitation_status = ?,
            first_seen = ?,
            last_seen = ?,
            summary = ?,
            recommended_action = ?,
            metadata = ?
        WHERE id = ?
        '
    );

    $publicationThreatStmt = $pdo->prepare(
        '
        INSERT INTO publication_threats (
            publication_id,
            threat_id
        )
        VALUES (?, ?)
        '
    );


    $vulnerabilityLookup = $pdo->prepare(
        '
        SELECT id
        FROM vulnerabilities
        WHERE cve_id = ?
        LIMIT 1
        '
    );

    $vulnerabilityInsert = $pdo->prepare(
        '
        INSERT INTO vulnerabilities (
            cve_id,
            description,
            cvss_score,
            cvss_vector,
            severity,
            kev_listed,
            exploited_in_wild,
            published_at,
            modified_at,
            vendor,
            product,
            metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '
    );

    $threatVulnerabilityStmt = $pdo->prepare(
        '
        INSERT INTO threat_vulnerabilities (
            threat_id,
            vulnerability_id,
            relationship
        )
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE
            relationship = VALUES(relationship)
        '
    );

    $threatSourceStmt = $pdo->prepare(
        '
        INSERT INTO threat_sources (
            threat_id,
            source_id,
            relationship
        )
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE
            relationship = VALUES(relationship)
        '
    );

    /*
     * ----------------------------------------------------------------------
     * Process threats
     * ----------------------------------------------------------------------
     */

    $insertedThreats = 0;
    $processedVulnerabilities = 0;

    foreach ($payload['threats'] as $threat) {

        $threatUuid = (string)(
            $threat['threat_uuid'] ?? ''
        );

        if (
            !preg_match(
                '/^[0-9a-fA-F-]{36}$/',
                $threatUuid
            )
        ) {
            throw new RuntimeException(
                'Invalid threat_uuid'
            );
        }

        /*
         * Reuse an existing threat entity if this threat
         * appeared in an earlier publication.
         */

        $threatLookup->execute([$threatUuid]);

        $existingThreat = $threatLookup->fetch();

        $metadata = isset($threat['metadata'])
            ? json_encode(
                $threat['metadata'],
                JSON_UNESCAPED_SLASHES |
                JSON_UNESCAPED_UNICODE
            )
            : null;

        $threatData = [
            $threat['external_id'] ?? null,
            $threat['title'] ?? 'Untitled threat',
            $threat['threat_type'] ?? 'other',
            $threat['severity'] ?? 'medium',
            $threat['priority_score'] ?? 0,
            $threat['confidence_score'] ?? 0,
            $threat['confidence_level'] ?? 'medium',
            $threat['exploitation_status'] ?? 'unknown',
            $threat['first_seen'] ?? null,
            $threat['last_seen'] ?? null,
            $threat['summary'] ?? null,
            $threat['recommended_action'] ?? null,
            $metadata
        ];

        if ($existingThreat) {

            $threatId = (int)$existingThreat['id'];

            $threatUpdate->execute([
                ...$threatData,
                $threatId
            ]);

        } else {

            $threatInsert->execute([
                $threatUuid,
                ...$threatData
            ]);

            $threatId = (int)$pdo->lastInsertId();

            $insertedThreats++;
        }

        /*
         * Publication → Threat
         */

        $publicationThreatStmt->execute([
            $publicationId,
            $threatId
        ]);

        /*
         * Threat → Sources
         */

        foreach (($threat['source_keys'] ?? []) as $sourceKey) {

            if (!isset($sourceIds[$sourceKey])) {
                throw new RuntimeException(
                    "Unknown source_key: {$sourceKey}"
                );
            }

            $threatSourceStmt->execute([
                $threatId,
                $sourceIds[$sourceKey],
                'reported'
            ]);
        }

        /*
         * Threat → Vulnerabilities
         */

        foreach (($threat['vulnerabilities'] ?? []) as $vulnerability) {

            $cveId = strtoupper(
                trim((string)(
                    $vulnerability['cve_id'] ?? ''
                ))
            );

            if (
                !preg_match(
                    '/^CVE-\d{4}-\d{4,}$/',
                    $cveId
                )
            ) {
                throw new RuntimeException(
                    "Invalid CVE ID: {$cveId}"
                );
            }

            $vulnerabilityLookup->execute([
                $cveId
            ]);

            $existingVulnerability =
                $vulnerabilityLookup->fetch();

            if ($existingVulnerability) {

                $vulnerabilityId =
                    (int)$existingVulnerability['id'];

            } else {

                $vulnerabilityInsert->execute([
                    $cveId,
                    $vulnerability['description'] ?? null,
                    $vulnerability['cvss_score'] ?? null,
                    $vulnerability['cvss_vector'] ?? null,
                    $vulnerability['severity'] ?? 'unknown',
                    $vulnerability['kev_listed'] ?? false,
                    $vulnerability['exploited_in_wild'] ?? false,
                    $vulnerability['published_at'] ?? null,
                    $vulnerability['modified_at'] ?? null,
                    $vulnerability['vendor'] ?? null,
                    $vulnerability['product'] ?? null,
                    isset($vulnerability['metadata'])
                        ? json_encode(
                            $vulnerability['metadata'],
                            JSON_UNESCAPED_SLASHES |
                            JSON_UNESCAPED_UNICODE
                        )
                        : null
                ]);

                $vulnerabilityId =
                    (int)$pdo->lastInsertId();
            }

            $threatVulnerabilityStmt->execute([
                $threatId,
                $vulnerabilityId,
                'exploits'
            ]);

            $processedVulnerabilities++;
        }
    }

    /*
     * ----------------------------------------------------------------------
     * Commit
     * ----------------------------------------------------------------------
     */

    $pdo->commit();

    $response = [
        'status' => 'ok',
        'publication_id' => $publicationId,
        'publication_uuid' => $publicationUuid,
        'threat_count' => $threatCount,
        'new_threat_count' => $insertedThreats,
        'vulnerability_count' => $processedVulnerabilities,
        'chunk_index' => $chunkIndex,
        'chunk_count' => $chunkCount,
        'complete' => $isFinalChunk,
        'attribution_stored' => $attributionStored,
        'source_health_stored' => $sourceHealthStored,
        'timestamp' => gmdate('c')
    ];

    if ($isChunked && !$isFinalChunk) {

        /*
         * 202 Accepted: this slice is stored, but the publication is not complete.
         * 201 is reserved for a finished publication, so a publisher that saw 201
         * for an intermediate chunk would report success while the API was still
         * waiting for the rest.
         */
        $response['message'] =
            'Chunk accepted; awaiting the rest of the publication';

        respond(202, $response);
    }

    $response['message'] = 'Publication accepted';

    respond(201, $response);

} catch (Throwable $e) {

    if (
        isset($pdo) &&
        $pdo instanceof PDO &&
        $pdo->inTransaction()
    ) {
        $pdo->rollBack();
    }

    error_log(
        'ThreatPulse publication error: ' .
        get_class($e) . ': ' . $e->getMessage()
    );

    /*
     * The reason is returned, not just logged.
     *
     * This endpoint is token-authenticated and its only legitimate caller is the
     * operator's own publisher, so a generic 'processing failed' protects nothing
     * and costs a deployment round-trip every time something breaks: the caller
     * sees a bare 500, and the only place the cause exists is a log file on the
     * server. The class name and message are included for that reason.
     *
     * What is NOT returned is a stack trace or the SQL, because those leak paths
     * and schema to anyone holding a leaked token, and neither is needed to act.
     */
    respond(500, [
        'status' => 'error',
        'message' => 'Publication processing failed',
        'error_class' => get_class($e),
        'error_message' => $e->getMessage()
    ]);
}
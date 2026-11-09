<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    header('Allow: GET');
    http_response_code(405);

    echo json_encode(
        [
            'status' => 'error',
            'message' => 'Method Not Allowed.',
            'allowed_methods' => ['GET'],
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );

    exit;
}

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: public, max-age=300');

echo json_encode(
    [
        'status' => 'ok',
        'service' => 'ThreatPulse CTI API',
        'api_version' => '1.0',
        'description' =>
            'Public read-only cyber threat intelligence API.',
        'documentation' => [
            'status' => '/api/cti/v1/status.php',
            'publications' => '/api/cti/v1/publications.php',
            'changes' => '/api/cti/v1/changes.php?kind={added|removed|changed}',
            'threats' => '/api/cti/v1/threats.php',
            'threats_by_cve' =>
                '/api/cti/v1/threats.php?cve={cve_id}',
            'threat' => '/api/cti/v1/threat.php?uuid={threat_uuid}',
            'vulnerabilities' =>
                '/api/cti/v1/vulnerabilities.php',
            'sources' => '/api/cti/v1/sources.php',
            'source_health' => '/api/cti/v1/source_health.php',
        ],
        'capabilities' => [
            'read_only' => true,
            'authentication_required' => false,
            'pagination' => true,
            'severity_filtering' => true,
            'exploitation_filtering' => true,
            'cve_lookup' => true,
            'cve_to_threat' => true,
            'vulnerability_threat_relationship' => true,
            'publication_delta' => true,
            'source_health' => true,
        ],
        'data_provenance' => [
            /*
             * This key is retained for compatibility, but the value must stay true.
             * The published set is aggregated from many independent sources, so a
             * single name here would be a false statement. The register at
             * attribution.php is the authoritative list.
             */
            'primary_source' =>
                'Multiple independent sources',
            'attribution_endpoint' =>
                '/api/cti/v1/attribution.php',
            'note' =>
                'ThreatPulse aggregates many sources. The attribution register '
                . 'lists every declared source with its licence, terms and '
                . 'current contribution.',
        ],
        'timestamp' => gmdate('c'),
    ],
    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
);
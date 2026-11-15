<?php

declare(strict_types=1);

/*
 * Security headers for the whole /api/ tree are set in api/.htaccess, so they
 * also cover the responses Apache generates without running PHP. This file adds
 * what depends on the request: the CORS allowlist and the cookie attributes.
 * See http.php.
 */

require_once __DIR__ . '/http.php';

threatpulse_harden_session_cookies();

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    threatpulse_send_cors_headers();
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
threatpulse_send_cors_headers();

header('Cache-Control: public, max-age=60');



http_response_code(200);

echo json_encode(
    [
        'status' => 'ok',
        'service' => 'iliadis-cti-api',
        'version' => '1.1.0'
    ],
    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
);
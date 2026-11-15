<?php

declare(strict_types=1);

/*
 * ThreatPulse public API — shared HTTP policy.
 *
 * Security headers (Content-Security-Policy, Strict-Transport-Security,
 * X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy)
 * are set once, in api/.htaccess, with `Header always set`. That covers the
 * responses Apache produces without running PHP — a denied publish.php is a 403
 * from mod_authz_core, not from PHP — as well as the static documentation page,
 * and it keeps one copy of each value instead of two that can drift apart.
 *
 * What has to happen in PHP is what depends on the request itself:
 *
 *   threatpulse_send_cors_headers()        a CORS allowlist, not `*`
 *   threatpulse_harden_session_cookies()   HttpOnly/Secure/SameSite defaults
 *
 * CORS. The read endpoints used to answer `Access-Control-Allow-Origin: *`,
 * which lets any page read their responses from a browser and is reported by
 * scanners as a cross-domain misconfiguration. The dashboard calls the API
 * same-origin, so the wildcard bought nothing; an explicit allowlist keeps the
 * documented behaviour for the product's own hostnames and nothing more. No
 * cookie-based session exists, and `Access-Control-Allow-Credentials` is never
 * sent, so no third party can make a credentialed cross-origin request either.
 */

/**
 * Origins that may read an API response from a browser.
 *
 * Same-origin requests do not need CORS at all. These are the two hostnames the
 * dashboard is served from, and the only ones the header is echoed for; an
 * attacker-controlled Origin is answered without any CORS header, so the
 * browser applies the same-origin policy.
 */
const THREATPULSE_ALLOWED_ORIGINS = [
    'https://threatpulse.iliadis.net',
    'https://www.threatpulse.iliadis.net',
];

/**
 * Whether this request reached the application over TLS.
 *
 * Behind Cloudflare the origin may see plain HTTP with the scheme in
 * X-Forwarded-Proto, so both are consulted before deciding that a cookie may
 * carry the Secure flag or that HSTS is meaningful.
 */
function threatpulse_is_https(): bool
{
    $https = $_SERVER['HTTPS'] ?? '';

    if ($https !== '' && strtolower((string) $https) !== 'off') {
        return true;
    }

    if (strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') {
        return true;
    }

    return (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
}

/**
 * Answer the CORS part of the request.
 *
 * The value is echoed only for an allowlisted Origin. `Vary: Origin` is set
 * whenever the request carries an Origin header, because the response body is
 * identical but the headers are not, and a shared cache must not hand one
 * origin's answer to another.
 */
function threatpulse_send_cors_headers(string $methods = 'GET, OPTIONS'): void
{
    $origin = trim((string) ($_SERVER['HTTP_ORIGIN'] ?? ''));

    if ($origin === '') {
        return;
    }

    header('Vary: Origin');

    if (!in_array($origin, THREATPULSE_ALLOWED_ORIGINS, true)) {
        return;
    }

    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Methods: ' . $methods);
    header('Access-Control-Allow-Headers: Content-Type, Accept');
    header('Access-Control-Max-Age: 600');
}

/**
 * Harden the attributes of any session cookie this host may emit.
 *
 * None of these endpoints starts a session — the API is stateless and public —
 * but a host-level `session.auto_start` or a future change that does would
 * otherwise produce a cookie readable from JavaScript and sent over plain HTTP.
 * These are the php.ini defaults the application wants, set before any session
 * can be started. Apache appends the same flags defensively (api/.htaccess), so
 * a cookie set by a component that ignores these settings is still flagged.
 */
function threatpulse_harden_session_cookies(): void
{
    if (function_exists('session_status') && session_status() === PHP_SESSION_ACTIVE) {
        // Too late to change the parameters; leave the running session alone.
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Lax');

    if (threatpulse_is_https()) {
        ini_set('session.cookie_secure', '1');
    }
}

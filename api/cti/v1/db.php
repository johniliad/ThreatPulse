<?php

declare(strict_types=1);

/*
 * Database connections.
 *
 * Two connections, two privilege levels (least privilege):
 *
 *   threatpulse_db()        read-only   — every public read endpoint
 *   threatpulse_db_write()  read/write  — publish.php only
 *
 * Each reads its own secrets file. The write file is optional: when it is
 * absent the connection falls back to the shared configuration, so this change
 * can be deployed before the new MySQL users exist and nothing breaks.
 */

const THREATPULSE_DB_READ_CONFIG =
    '/home/iliadis/threatpulse-secrets/threatpulse-db-read-config.php';

const THREATPULSE_DB_WRITE_CONFIG =
    '/home/iliadis/threatpulse-secrets/threatpulse-db-write-config.php';

const THREATPULSE_DB_SHARED_CONFIG =
    '/home/iliadis/threatpulse-secrets/threatpulse-db-config.php';

const THREATPULSE_DB_REQUIRED_KEYS = [
    'host',
    'port',
    'database',
    'charset',
    'username',
    'password',
];

function threatpulse_db_diagnose(string $configPath, string $reason): void
{
    $owner = null;
    $phpUser = null;

    if (function_exists('posix_getpwuid')) {
        if (file_exists($configPath)) {
            $ownerId = @fileowner($configPath);

            if ($ownerId !== false) {
                $owner = posix_getpwuid($ownerId)['name'] ?? (string) $ownerId;
            }
        }

        if (function_exists('posix_geteuid')) {
            $phpUser = posix_getpwuid(posix_geteuid())['name'] ?? null;
        }
    }

    error_log(
        'ThreatPulse database configuration problem: ' . json_encode(
            [
                'reason' => $reason,
                'config' => $configPath,
                'exists' => file_exists($configPath),
                'readable' => is_readable($configPath),
                'realpath' => @realpath($configPath) ?: null,
                'file_owner' => $owner,
                'php_user' => $phpUser,
                'open_basedir' => ini_get('open_basedir') ?: null,
            ],
            JSON_UNESCAPED_SLASHES
        )
    );
}

function threatpulse_db_connect(string $configPath): PDO
{
    if (!is_readable($configPath)) {
        threatpulse_db_diagnose($configPath, 'file is missing or not readable');

        throw new RuntimeException(
            'Database configuration is missing or unreadable.'
        );
    }

    /*
     * A secrets file is hand-written, and anything placed before its opening
     * <?php tag is emitted as output. Inside a JSON endpoint a single stray line
     * makes every response unparseable — which happened once, reporting
     * "was not valid JSON" for a publication the API had in fact accepted.
     *
     * Buffer the include and discard whatever it prints, reporting it in the log
     * instead, so a cosmetic mistake in a configuration file can never corrupt
     * an API response. The buffer is closed before the connection is attempted,
     * so a connection failure cannot leave it open either.
     */
    ob_start();

    try {
        $config = require $configPath;
    } catch (Throwable $error) {
        ob_end_clean();

        threatpulse_db_diagnose(
            $configPath,
            'failed to load: ' . $error->getMessage()
        );

        throw new RuntimeException(
            'Database configuration could not be loaded.',
            0,
            $error
        );
    }

    $strayOutput = (string) ob_get_clean();

    if (trim($strayOutput) !== '') {
        threatpulse_db_diagnose(
            $configPath,
            'file emitted output before returning its array; look for text '
            . 'placed before the opening <?php tag'
        );
    }

    if (!is_array($config)) {
        threatpulse_db_diagnose(
            $configPath,
            'file did not return an array (missing <?php or return?)'
        );

        throw new RuntimeException('Database configuration is not an array.');
    }

    foreach (THREATPULSE_DB_REQUIRED_KEYS as $key) {
        if (!array_key_exists($key, $config)) {
            threatpulse_db_diagnose($configPath, "missing required key '{$key}'");

            throw new RuntimeException('Database configuration is incomplete.');
        }
    }

    $dsn = sprintf(
        'mysql:host=%s;port=%d;dbname=%s;charset=%s',
        (string) $config['host'],
        (int) $config['port'],
        (string) $config['database'],
        (string) $config['charset']
    );

    return new PDO(
        $dsn,
        (string) $config['username'],
        (string) $config['password'],
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
}

/**
 * Read-only connection, used by every public read endpoint.
 */
function threatpulse_db(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $configPath = is_readable(THREATPULSE_DB_READ_CONFIG)
        ? THREATPULSE_DB_READ_CONFIG
        : THREATPULSE_DB_SHARED_CONFIG;

    $pdo = threatpulse_db_connect($configPath);

    return $pdo;
}

/**
 * Read/write connection, used only by publish.php.
 */
function threatpulse_db_write(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $configPath = is_readable(THREATPULSE_DB_WRITE_CONFIG)
        ? THREATPULSE_DB_WRITE_CONFIG
        : THREATPULSE_DB_SHARED_CONFIG;

    $pdo = threatpulse_db_connect($configPath);

    return $pdo;
}
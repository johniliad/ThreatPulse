<?php

/**
 * ThreatPulse database configuration diagnostic.
 *
 * Run it over SSH — it must NOT be placed in the web root:
 *
 *   php deployment/check-db-config.php
 *   php deployment/check-db-config.php /path/to/threatpulse-db-read-config.php
 *
 * It reports, per configuration file:
 *   1. whether the file exists, its mode and owner;
 *   2. whether it loads (a syntax error is shown with its line number);
 *   3. whether it returns an array with the required keys;
 *   4. whether the credentials actually connect;
 *   5. whether the least-privilege split holds, by attempting a harmless
 *      no-op DELETE (`WHERE 1 = 0`): the read user must be refused.
 *
 * It never prints a password.
 */

declare(strict_types=1);

const TP_REQUIRED_KEYS = ['host', 'port', 'database', 'charset', 'username', 'password'];

$paths = array_slice($argv, 1);

if ($paths === []) {
    $paths = [
        '/home/iliadis/threatpulse-secrets/threatpulse-db-read-config.php',
        '/home/iliadis/threatpulse-secrets/threatpulse-db-write-config.php',
        '/home/iliadis/threatpulse-secrets/threatpulse-db-config.php',
    ];
}

foreach ($paths as $path) {
    echo "=== {$path}\n";

    inspect($path);

    echo "\n";
}

function inspect(string $path): void
{
    if (!file_exists($path)) {
        echo "  MISSING: the file does not exist at this path.\n";

        return;
    }

    $mode = substr(sprintf('%o', @fileperms($path) ?: 0), -4);
    $owner = 'unknown';

    if (function_exists('posix_getpwuid')) {
        $ownerId = @fileowner($path);
        $owner = $ownerId === false
            ? 'unknown'
            : (posix_getpwuid($ownerId)['name'] ?? (string) $ownerId);
    }

    printf(
        "  exists: yes   mode: %s   owner: %s   size: %d bytes\n",
        $mode,
        $owner,
        filesize($path) ?: 0
    );

    printf("  readable by this process: %s\n", is_readable($path) ? 'yes' : 'NO');

    try {
        $config = require $path;
    } catch (Throwable $error) {
        echo '  LOAD FAILED: ' . get_class($error) . ': ' . $error->getMessage() . "\n";
        echo "  ^ this is the cause of the HTTP 500\n";

        return;
    }

    if (!is_array($config)) {
        echo '  LOAD FAILED: the file returned ' . gettype($config)
            . ", not an array. It is probably missing <?php or the return statement.\n";

        return;
    }

    echo '  keys present: ' . implode(', ', array_keys($config)) . "\n";

    $missing = array_diff(TP_REQUIRED_KEYS, array_keys($config));

    if ($missing !== []) {
        echo '  MISSING KEYS: ' . implode(', ', $missing) . "\n";

        return;
    }

    echo '  connecting as: ' . $config['username'] . "\n";

    try {
        $pdo = new PDO(
            sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                (string) $config['host'],
                (int) $config['port'],
                (string) $config['database'],
                (string) $config['charset']
            ),
            (string) $config['username'],
            (string) $config['password'],
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
    } catch (Throwable $error) {
        echo '  CONNECTION FAILED: ' . $error->getMessage() . "\n";

        return;
    }

    echo "  connection: OK\n";

    try {
        $count = $pdo->query('SELECT COUNT(*) FROM threats')->fetchColumn();
        echo "  SELECT works: yes ({$count} threats)\n";
    } catch (Throwable $error) {
        echo '  SELECT FAILED: ' . $error->getMessage() . "\n";
    }

    /*
     * A no-op DELETE. It changes no data, but it proves whether DELETE is
     * granted — which is exactly what the least-privilege split must prevent for
     * the read-only user.
     */
    try {
        $pdo->exec('DELETE FROM threats WHERE 1 = 0');
        echo "  DELETE permitted: YES  <-- the read user must NOT have DELETE\n";
    } catch (Throwable $error) {
        echo "  DELETE refused: yes (expected for the read user)\n";
    }
}

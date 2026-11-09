-- ============================================================================
-- ThreatPulse — least-privilege MySQL users
-- ============================================================================
--
-- WHY THIS EXISTS
--   Previously one MySQL account served both the public read endpoints and
--   publish.php. A flaw in any public read endpoint therefore carried write
--   privileges it never needed. These statements separate the two:
--
--     tp_read    SELECT only            — threats.php, threat.php, sources.php,
--                                         vulnerabilities.php, publications.php
--     tp_write   SELECT/INSERT/UPDATE   — publish.php only
--
--   Neither user needs DELETE, DROP, ALTER or CREATE. Nothing in the API
--   deletes rows or changes schema.
--
-- HOW TO RUN (cPanel)
--   1. cPanel → MySQL Databases → "Add New User" twice (cPanel normally refuses
--      CREATE USER from phpMyAdmin). Suggested names:
--          <cpaneluser>_tp_read
--          <cpaneluser>_tp_write
--      Use a long random password for each, and note them for step 4.
--
--   2. In the same screen, "Add User To Database" for each user and tick ALL
--      PRIVILEGES. This is only a starting point — step 3 narrows it.
--
--   3. Run the statements below in phpMyAdmin → SQL tab.
--
--   4. Create the two secrets files on the server (see the comment block at the
--      end of this file).
--
-- REPLACE THESE BEFORE RUNNING
--   iliadis_threatpulse   → your actual database name
--   tp_read               → your read-only MySQL user
--   tp_write              → your write MySQL user
--   localhost             → the host shown in cPanel for these users
--
-- ADDING A TABLE LATER
--   A new table needs a new GRANT. These users have privileges on named tables
--   only, so a table added after this file was applied is invisible to them, and
--   the failure looks like a missing table rather than a denied one:
--
--     publish.php  → logs "ThreatPulse attribution register not stored: ..." and
--                    reports attribution_stored: false in its response
--     attribution.php → reports stored: false
--
--   Both are the same signal a genuinely absent table produces, so check the PHP
--   error log: it names the real cause. "INSERT command denied" is this file;
--   "Base table or view not found" is the DDL.
--
--   Every table added to the schema needs its own two GRANT lines here — one for
--   tp_read (SELECT) and one for tp_write (SELECT, INSERT, UPDATE).
-- ============================================================================


-- ----------------------------------------------------------------------------
-- 1. Remove the blanket grant that cPanel's "add user to database" created.
--    Without this the users keep full privileges on the whole database.
-- ----------------------------------------------------------------------------

REVOKE ALL PRIVILEGES ON `iliadis_threatpulse`.* FROM 'tp_read'@'localhost';
REVOKE ALL PRIVILEGES ON `iliadis_threatpulse`.* FROM 'tp_write'@'localhost';


-- ----------------------------------------------------------------------------
-- 2. Read-only user — exactly the tables the public endpoints SELECT from.
-- ----------------------------------------------------------------------------

GRANT SELECT ON `iliadis_threatpulse`.`threats`                TO 'tp_read'@'localhost';
GRANT SELECT ON `iliadis_threatpulse`.`vulnerabilities`        TO 'tp_read'@'localhost';
GRANT SELECT ON `iliadis_threatpulse`.`threat_vulnerabilities` TO 'tp_read'@'localhost';
GRANT SELECT ON `iliadis_threatpulse`.`sources`                TO 'tp_read'@'localhost';
GRANT SELECT ON `iliadis_threatpulse`.`threat_sources`         TO 'tp_read'@'localhost';
GRANT SELECT ON `iliadis_threatpulse`.`publications`           TO 'tp_read'@'localhost';
GRANT SELECT ON `iliadis_threatpulse`.`publication_threats`    TO 'tp_read'@'localhost';
GRANT SELECT ON `iliadis_threatpulse`.`source_attribution`     TO 'tp_read'@'localhost';


-- ----------------------------------------------------------------------------
-- 3. Write user — publish.php only.
--    SELECT is required because publish.php looks up existing rows before
--    inserting; UPDATE is required because every insert uses
--    "ON DUPLICATE KEY UPDATE". DELETE is deliberately NOT granted.
-- ----------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE ON `iliadis_threatpulse`.`threats`                TO 'tp_write'@'localhost';
GRANT SELECT, INSERT, UPDATE ON `iliadis_threatpulse`.`vulnerabilities`        TO 'tp_write'@'localhost';
GRANT SELECT, INSERT, UPDATE ON `iliadis_threatpulse`.`threat_vulnerabilities` TO 'tp_write'@'localhost';
GRANT SELECT, INSERT, UPDATE ON `iliadis_threatpulse`.`sources`                TO 'tp_write'@'localhost';
GRANT SELECT, INSERT, UPDATE ON `iliadis_threatpulse`.`threat_sources`         TO 'tp_write'@'localhost';
GRANT SELECT, INSERT, UPDATE ON `iliadis_threatpulse`.`publications`           TO 'tp_write'@'localhost';
GRANT SELECT, INSERT, UPDATE ON `iliadis_threatpulse`.`publication_threats`    TO 'tp_write'@'localhost';
GRANT SELECT, INSERT, UPDATE ON `iliadis_threatpulse`.`source_attribution`     TO 'tp_write'@'localhost';

FLUSH PRIVILEGES;


-- ----------------------------------------------------------------------------
-- 4. Verify the grants.
-- ----------------------------------------------------------------------------

SHOW GRANTS FOR 'tp_read'@'localhost';
SHOW GRANTS FOR 'tp_write'@'localhost';


-- ----------------------------------------------------------------------------
-- 5. Test the split (run as each user, or check via phpMyAdmin).
-- ----------------------------------------------------------------------------
--
--   As tp_read:   SELECT COUNT(*) FROM threats;          -- must succeed
--                 INSERT INTO sources (source_key) VALUES ('x');  -- must FAIL
--                              with "INSERT command denied to user"
--
--   As tp_write:  SELECT COUNT(*) FROM threats;          -- must succeed
--                 DELETE FROM threats LIMIT 1;           -- must FAIL
--                              with "DELETE command denied to user"
--
-- If the INSERT or DELETE succeeds, the REVOKE in step 1 did not take effect
-- (usually because the host in the GRANT did not match the account's real host).
-- Run SELECT user, host FROM mysql.user WHERE user LIKE '%tp_%'; to confirm.


-- ============================================================================
-- 6. Secrets files
-- ============================================================================
--
-- The API reads its credentials from PHP files that return an array. Create
-- both files on the server, each mode 0600, owned by the account that serves
-- the site (never world-readable, never inside the web root):
--
--   /home/iliadis/threatpulse-secrets/threatpulse-db-read-config.php
--   /home/iliadis/threatpulse-secrets/threatpulse-db-write-config.php
--
-- threatpulse-db-read-config.php — used by every public read endpoint:
--
--   <?php
--   return [
--       'host'     => 'localhost',
--       'port'     => 3306,
--       'database' => 'iliadis_threatpulse',
--       'charset'  => 'utf8mb4',
--       'username' => 'tp_read',
--       'password' => '<the tp_read password>',
--   ];
--
-- threatpulse-db-write-config.php — used by publish.php only:
--
--   <?php
--   return [
--       'host'     => 'localhost',
--       'port'     => 3306,
--       'database' => 'iliadis_threatpulse',
--       'charset'  => 'utf8mb4',
--       'username' => 'tp_write',
--       'password' => '<the tp_write password>',
--   ];
--
-- Permissions:
--
--   chmod 0600 /home/iliadis/threatpulse-secrets/threatpulse-db-*-config.php
--
-- MIGRATION SAFETY
--   The API resolves connections in this order:
--     read  → threatpulse-db-read-config.php,  else threatpulse-db-config.php
--     write → threatpulse-db-write-config.php, else threatpulse-db-config.php
--   So the code can be deployed before these files exist: it keeps using the
--   existing shared configuration until each file appears. Nothing breaks if
--   you create the read file first and the write file later.
--
--   Once both files exist, the original threatpulse-db-config.php is unused by
--   the API and can be removed.
-- ============================================================================

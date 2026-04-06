# Pyro Scope

WordPress security monitoring plugin. Companion to Pyro Shield.

**This is NOT a full vulnerability scanner.** It performs pattern-based detection of known malicious code signatures and does not guarantee detection of all threats.

- **Stable tag:** 3.3
- **License:** GPLv2 or later
- **Contributors:** Ikkido-den (一揆堂田)

## Requirements

- PHP 8.1 or later
- WordPress 6.0 or later (tested up to 6.7)

## Features

### File Scanner

Scans PHP and JS files under ABSPATH for known malicious code patterns.

Detected signatures:

| Signature Name | Description |
|---|---|
| Variable Function Execution | Variable function calls to dangerous functions (passthru, shell_exec, system, exec, popen, proc_open) |
| Obfuscated Eval | Concatenation-based obfuscation in eval/assert/preg_replace |
| Advanced Obfuscation | eval/assert wrapping gzuncompress, gzinflate, base64_decode, str_rot13 |
| File Upload Webshell | move_uploaded_file using $_FILES |
| Remote Code Execution | include/require using $_GET (both statement and function-call form) |
| Create Function Webshell | Usage of create_function() |
| Eval Base64 Decode | Standalone eval(base64_decode(...)) calls |
| User Input Include | include/require using $_REQUEST or $_POST (both statement and function-call form) |
| User Input Eval | eval() using $_REQUEST or $_POST |
| PHP File Write | file_put_contents writing to .php files |
| PHP file in uploads directory | Any .php file located inside wp-content/uploads/ |

### Database Scanner

Scans published posts, wp_options, and approved comments for:

| Pattern Name | Description |
|---|---|
| Malicious Script | `<script>` tag injection |
| Obfuscated Code | eval, base64_decode, gzinflate, str_rot13 function calls |
| Malicious Iframe | `<iframe>` tag injection |

### Whitelist

Paths can be excluded from the file scan (e.g., Pyro Shield's plugin directory) to prevent false positives between companion plugins.

### Auto Scan

Weekly automatic scans via WP-Cron. Manual scans can also be triggered from the admin screen. Scan results are saved as JSON and the latest results are always displayed in the admin panel.

### Core File Integrity Check

Compares local WordPress core files against official checksums from the WordPress.org API. Reports modified or deleted core files. Files under wp-content/ are excluded from this check.

### Plugin Vulnerability Check

Compares installed plugin versions against the latest versions available on WordPress.org. Reports plugins that are not up to date. This is a version comparison only; it does not check CVE databases or known vulnerability feeds.

## Error Handling

- If the file scanner encounters an error during directory traversal (e.g., symbolic link loops, permission errors), the error message is recorded in the scan log and the scan is marked as incomplete via the `scan_incomplete` flag in the scan result data.
- Errors are never silently suppressed. All caught exceptions during file scanning are logged.
- Scan results are written to disk using `LOCK_EX` to prevent data corruption from concurrent writes.

## Scan Result Storage

- Scan results are stored as JSON at `wp-content/uploads/pyro-scope-log/pyro-scope-scan.json`.
- The log directory is protected by an `index.php` silence file and a `.htaccess` deny rule (Apache only).
- Last scan timestamp is stored in `pyro_scope_last_scan_timestamp` (wp_options, autoload: no).
- Plugin vulnerability check results are cached as transients (`pyro_scope_vuln_*`) with a 12-hour TTL.

## Limitations

- Pattern-based detection only. Obfuscation techniques not covered by the defined signatures will not be detected.
- The file scanner skips files larger than 2 MB (2,097,152 bytes). Malicious code in files exceeding this limit will not be detected. This threshold prevents memory exhaustion on constrained hosting environments.
- The database scanner skips option values larger than 100,000 bytes.
- Core integrity check depends on WordPress.org API availability and only covers core files (not plugins or themes).
- Plugin vulnerability check only compares version numbers against WordPress.org. Plugins not hosted on WordPress.org are not checked.
- The file scanner only inspects files with `.php` or `.js` extensions.
- Multisite environments are not explicitly supported. Each site must activate the plugin individually.
- Automatic scans run weekly via WP-Cron. WP-Cron depends on site traffic and is not a reliable scheduler.

## Security Considerations

- Scan results may contain file paths and database content. The log directory is protected against HTTP access on Apache via `.htaccess`. Nginx environments require manual configuration to deny access to `wp-content/uploads/pyro-scope-log/`.
- The AJAX scan endpoint requires `manage_options` capability and nonce verification.
- This plugin does not modify or delete any detected files. It is detection and reporting only.
- This plugin does not communicate with any external service other than the WordPress.org API.
- Scan log lines in the admin UI are rendered as text nodes (`document.createTextNode`), not as HTML. This prevents interpretation of any HTML or script content that may appear in log messages (e.g., from exception messages containing file paths or user-influenced data).
- Files larger than 2 MB are skipped without notification. An attacker could embed malicious code in a file exceeding this threshold to evade detection. This is an accepted trade-off to prevent memory exhaustion.

## Assumptions

- WordPress is installed in the standard directory structure with `wp-content/uploads/` as the uploads directory.
- The `ABSPATH` constant accurately reflects the WordPress root directory.
- The WordPress.org API is the authoritative source for core file checksums and plugin version information.
- File system permissions allow the plugin to read files under ABSPATH and write to the uploads directory.
- The `.htaccess` deny rule is only effective on Apache with `AllowOverride` enabled.
- PHP and JS files containing malicious signatures are assumed to be smaller than 2 MB. Files exceeding this size are not scanned.

## Non-Goals

- This plugin does not perform runtime behavior analysis or sandboxing.
- This plugin does not provide malware removal or file quarantine.
- This plugin does not scan theme files for vulnerabilities.
- This plugin does not integrate with CVE databases or vulnerability advisory feeds.
- This plugin does not provide real-time file system monitoring (inotify or similar).
- This plugin does not replace professional security auditing or penetration testing.
- This plugin does not provide user authentication, login protection, or brute-force prevention (delegated to Pyro Shield).
- This plugin does not provide WAF functionality (delegated to Pyro Shield).

## Pyro Shield Integration

Pyro Scope is designed as a companion to Pyro Shield.

- Login protection and WAF functionality are delegated to Pyro Shield and are not included in Pyro Scope.
- Adding Pyro Shield's plugin directory to the whitelist prevents false positives between the two plugins.

## FAQ

**Can I use Pyro Scope without Pyro Shield?**
Yes. Pyro Scope works standalone. However, for login protection and advanced defense features, using it together with Pyro Shield is recommended.

**Can I change the scan frequency?**
In the current version, automatic scans are fixed to weekly. You can run a manual scan at any time using the "Run manual scan now" button in the admin screen.

**Are detected files automatically deleted?**
No. Pyro Scope only detects and reports. File deletion or remediation must be performed manually by the administrator.

**Is multisite supported?**
The current version targets single-site installations. In multisite environments, the plugin must be activated individually on each site by the network administrator.

## Module Configuration

Each feature can be toggled independently via the `pyro_scope_options` option:

- `enable_scanner` — File scan and DB scan (default: ON)
- `enable_integrity` — Core file integrity check (default: ON)
- `enable_vuln` — Plugin vulnerability check (default: ON)
- `whitelist_paths` — Array of paths excluded from file scan (default: `['wp-content/plugins/pyro-shield']`)

## Installation

1. Upload the `pyro-scope` folder to `wp-content/plugins/`.
2. Activate the plugin from the WordPress admin Plugins page.
3. Access "Pyro Scope" from the admin menu to run scans and view results.

## Tests

This plugin includes a small PHPUnit test suite under `tests/`. The tests use a minimal WordPress stub bootstrap, so a full WordPress test environment or database is not required.

1. Install development dependencies:

```
composer install
```

2. Run the full test suite from the plugin root:

```
./vendor/bin/phpunit
```

3. Optional: run a single test file:

```
./vendor/bin/phpunit tests/PyroScopeTest.php
```

`phpunit.xml.dist` is loaded automatically, so no extra options are required for the default test run.

### Nginx Configuration

Add the following to deny HTTP access to the scan log directory:

```
location ~* /wp-content/uploads/pyro-scope-log/ {
    deny all;
    return 403;
}
```

## Upgrade Notice

- **3.3:** Breaking change — Plugin renamed from Pyre Scope to Pyro Scope. All identifiers, file names, and log paths updated. Settings from 3.2 are not migrated.
- **3.2:** Code quality improvements. No breaking changes.
- **3.1:** Breaking change — Simple WAF feature removed. Use Pyro Shield for WAF functionality.
- **3.0:** Breaking change — All internal identifiers renamed from `pyreopsis` to `pyro_scope`. Settings from previous versions are not migrated. Re-check your settings after upgrading.
- **2.8:** Contains security fixes (AJAX permission check, PHP 8.1+ compatibility, information leak prevention). Immediate update recommended for all users.

## Changelog

### 3.3

- **Breaking:** Renamed plugin from Pyre Scope to Pyro Scope. All internal identifiers updated (`pyre_scope_*` → `pyro_scope_*`, `pyre-scope-*` → `pyro-scope-*`, `PyreScopeAjax` → `PyroScopeAjax`). Plugin file renamed from `pyre-scope.php` to `pyro-scope.php`. Asset files renamed accordingly.
- **Breaking:** Renamed log directory from `fspo-log` to `pyro-scope-log` and log file from `fspo-scan.json` to `pyro-scope-scan.json`.
- **Breaking:** Renamed companion plugin references from Pyre Shield to Pyro Shield. Default whitelist path updated from `wp-content/plugins/pyre-shield` to `wp-content/plugins/pyro-shield`.

### 3.2

- Removed unused `scan_schedule` option from defaults (was defined but never referenced)
- Removed unreachable `return` statement after `wp_send_json_error()` in AJAX handler
- Refactored `file_scan()` to return a structured result array instead of using pass-by-reference for error reporting
- Deferred log directory initialization to first use (`get_log_file_path()`), eliminating unnecessary file I/O on frontend and non-scan requests
- Added `whitelist_paths` to Module Configuration documentation

### 3.1

- **Breaking:** Removed Simple WAF feature entirely (delegated to Pyro Shield). Removed `run_waf()`, `waf_check_value()`, `enable_waf` option, and all associated hooks and patterns.

### 3.0

- **Breaking:** Renamed all internal identifiers from `pyreopsis` to `pyre_scope` (subsequently renamed to `pyro_scope` in 3.3).
- **Breaking:** Removed phantom filter hook documentation (`pyreopsis_allow_login_protection`, `pyreopsis_is_login_endpoint`) — no implementation existed.
- Removed obsolete option keys from uninstall cleanup.

### 2.9.1

- Fixed stored XSS risk in admin JS log rendering; log lines are now inserted as text nodes instead of HTML
- Extended `include/require` detection signatures to match both function-call form (`include(...)`) and statement form (`include ...`)
- Added 2 MB file size limit to file scanner; files exceeding 2,097,152 bytes are skipped to prevent memory exhaustion

### 2.9

- Added file scanner signature: `eval(base64_decode(...))` standalone detection
- Added file scanner signature: `include/require/eval` using `$_REQUEST` or `$_POST`
- Added file scanner signature: `file_put_contents` writing `.php` files
- Added file scanner rule: flag any `.php` file inside `wp-content/uploads/` as suspicious
- Fixed silent error suppression in file scanner catch block; errors are now logged and scan is marked incomplete
- Added `LOCK_EX` to scan result file writing to prevent concurrent write corruption

### 2.8

- Added `current_user_can('manage_options')` permission check to AJAX scan handler
- Fixed global timezone pollution from `date_default_timezone_set()` (replaced with `wp_date()`)
- Fixed missing vulnerability check results in HTML output
- Fixed `$wpdb->get_results()` null return TypeError on PHP 8.0+
- Fixed asset file path references
- Unified plugin name to Pyro Scope
- Added PHP 8.1 type declarations to all properties
- Changed `catch (Exception)` to `catch (\Throwable)`
- Improved DB scan to query `option_value` directly
- Added `.htaccess` to log directory
- Set `update_option` autoload to `false` for scan timestamp
- Added `JSON_UNESCAPED_UNICODE` to JSON encoding
- Added strict comparison to `in_array` calls
- Replaced `strpos` with `str_starts_with`
- Changed activation/deactivation hooks to static closures
- Added type-safe guard for `whitelist_paths`
- Applied `urlencode()` to `check_vuln` URL
- Added transient cache cleanup on uninstall

### 2.7

- Initial release

## Developer Notes

The default signatures are conservatively tuned. For production environments, integrating an auto-update mechanism that fetches signed signature packs from a trusted feed is recommended.

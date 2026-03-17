<?php
/*
Plugin Name: Pyro Scope
Description: Pyro Shield専用補完プラグイン（スキャン・脆弱性・整合性チェック）
Version: 3.3
Author: Ikkido-den (一揆堂田)
Requires PHP: 8.1
Requires at least: 6.0
*/

if (!defined('ABSPATH')) {
    exit; // Direct access not allowed.
}

// [M2] activation/deactivationフックを静的クロージャに変更（グローバル関数汚染の回避）
register_activation_hook(__FILE__, static function (): void {
    if (!wp_next_scheduled('pyro_scope_weekly_scan_event')) {
        wp_schedule_event(time(), 'weekly', 'pyro_scope_weekly_scan_event');
    }
});

register_deactivation_hook(__FILE__, static function (): void {
    wp_clear_scheduled_hook('pyro_scope_weekly_scan_event');
});

final class Pyro_Scope
{
    // [H2] PHP 8.1準拠の型宣言を全プロパティに追加
    private static ?self $instance = null;
    private const PLUGIN_VERSION = '3.3';
    private string $option_key = 'pyro_scope_options';
    /** @var array<string, mixed> */
    private array $options;
    private ?string $log_file_path = null;

    private function __construct()
    {
        $this->load_options();
        $this->add_hooks();
    }

    /**
     * ログディレクトリを遅延初期化し、ログファイルパスを返す。
     * 管理画面・スキャン実行時のみ呼ばれるため、フロントエンドリクエストでのファイルI/Oを回避する。
     */
    private function get_log_file_path(): string
    {
        if ($this->log_file_path !== null) {
            return $this->log_file_path;
        }

        $upload_dir = wp_upload_dir();
        $log_dir = $upload_dir['basedir'] . '/pyro-scope-log';

        if (!file_exists($log_dir)) {
            wp_mkdir_p($log_dir);
        }
        if (!file_exists($log_dir . '/index.php')) {
            file_put_contents($log_dir . '/index.php', '<?php // Silence is golden.');
        }
        // [M3] .htaccess によるHTTPアクセス防止（Apache環境）
        $htaccess_path = $log_dir . '/.htaccess';
        if (!file_exists($htaccess_path)) {
            file_put_contents($htaccess_path, "Deny from all\n");
        }

        $this->log_file_path = $log_dir . '/pyro-scope-scan.json';

        return $this->log_file_path;
    }

    public static function get_instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    // [M1] get_optionを1回に統合。falseをセンチネルとして存在判定
    private function load_options(): void
    {
        $defaults = [
            'enable_scanner'   => 1,
            'enable_integrity' => 1,
            'enable_vuln'      => 1,
            'whitelist_paths'  => ['wp-content/plugins/pyro-shield'],
        ];

        /** @var array<string, mixed>|false $saved */
        $saved = get_option($this->option_key, false);

        if ($saved === false) {
            add_option($this->option_key, $defaults, '', 'yes');
            $this->options = $defaults;
        } else {
            // 保存済み値にデフォルトをマージ（将来のキー追加に対応）
            $this->options = array_merge($defaults, (array) $saved);
        }
    }

    private function add_hooks(): void
    {
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('wp_ajax_pyro_scope_run_scan', [$this, 'ajax_run_scan']);
        add_action('pyro_scope_weekly_scan_event', [$this, 'run_scheduled_scan']);
    }

    public function admin_menu(): void
    {
        add_menu_page(
            'Pyro Scope',
            'Pyro Scope',
            'manage_options',
            'pyro-scope',
            [$this, 'settings_page'],
            'dashicons-shield'
        );
    }

    public function enqueue_scripts(string $hook): void
    {
        if ('toplevel_page_pyro-scope' !== $hook) {
            return;
        }
        wp_enqueue_style(
            'pyro-scope-admin-style',
            plugin_dir_url(__FILE__) . 'assets/css/pyro-scope-admin.css',
            [],
            self::PLUGIN_VERSION
        );
        wp_enqueue_script(
            'pyro-scope-admin-script',
            plugin_dir_url(__FILE__) . 'assets/js/pyro-scope-admin.js',
            ['jquery'],
            self::PLUGIN_VERSION,
            true
        );
        wp_localize_script(
            'pyro-scope-admin-script',
            'PyroScopeAjax',
            [
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce'    => wp_create_nonce('pyro_scope_scan_nonce'),
            ]
        );
    }

    public function settings_page(): void
    {
        ?>
        <div class="wrap">
            <h1>Pyro Scope</h1>
            <p style="font-size:1.1em; background:#fff; padding:10px; border-left: 4px solid #72aee6;">
                <?php
                $last_scan_timestamp = get_option('pyro_scope_last_scan_timestamp');
                if ($last_scan_timestamp) {
                    // [C2] wp_date()はWordPressの管理画面タイムゾーン設定を自動的に使用する。
                    $formatted_date = wp_date(
                        get_option('date_format') . ' H:i:s',
                        (int) $last_scan_timestamp
                    );
                    // wp_date()はフォーマット失敗時にfalseを返す
                    echo '<strong>最終スキャン実行日時:</strong> ' . esc_html((string) $formatted_date);
                } else {
                    echo 'まだスキャンは実行されていません。';
                }
                ?>
            </p>

            <button id="pyro-scope-run-scan" class="button button-primary">Run manual scan now</button>
            <div id="pyro-scope-progress-container" style="margin-top:10px; width:100%; background:#eee; height:20px; border-radius:3px; display:none;">
                <div id="pyro-scope-progress-bar" style="width:0%; height:100%; background:#0a0; transition: width 0.1s;"></div>
            </div>
            <pre id="pyro-scope-scan-log" style="margin-top:10px; background:#f5f5f5; padding:10px; height:200px; overflow:auto; border:1px solid #ccc;"></pre>

            <div id="pyro-scope-results-container">
                <?php
                $log_path = $this->get_log_file_path();
                if (file_exists($log_path) && is_readable($log_path)) {
                    $json_data = file_get_contents($log_path);
                    if ($json_data !== false) {
                        $last_results = json_decode($json_data, true);
                        if (is_array($last_results) && isset($last_results['scan_data'])) {
                            // generate_results_html は内部で全値をesc_html済み
                            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                            echo $this->generate_results_html($last_results['scan_data']);
                        }
                    }
                }
                ?>
            </div>
        </div>
        <?php
    }

    // [C1] nonce検証に加えて権限チェックを追加
    public function ajax_run_scan(): void
    {
        check_ajax_referer('pyro_scope_scan_nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.'], 403);
        }

        $scan_data   = $this->execute_scan();
        $html_output = $this->generate_results_html($scan_data);
        wp_send_json_success(['log' => $scan_data['log'], 'html' => $html_output]);
    }

    public function run_scheduled_scan(): void
    {
        $this->execute_scan();
    }

    /**
     * @return array{log: list<string>, files: array<string, string>, db: array<string, string>, integrity: list<string>, vuln: list<string>, scan_incomplete?: bool}
     */
    private function execute_scan(): array
    {
        $scan_data = ['log' => [], 'files' => [], 'db' => [], 'integrity' => [], 'vuln' => []];

        if (!empty($this->options['enable_integrity'])) {
            $scan_data['log'][]     = 'Checking file integrity against WordPress.org...';
            $scan_data['integrity'] = $this->check_integrity();
            $scan_data['log'][]     = count($scan_data['integrity']) . ' integrity issues found.';
        }
        if (!empty($this->options['enable_scanner'])) {
            $scan_data['log'][] = 'Starting file scan...';
            $file_result         = $this->file_scan();
            $scan_data['files']  = $file_result['findings'];
            if (isset($file_result['error'])) {
                $scan_data['log'][]          = 'File scan error: ' . $file_result['error'];
                $scan_data['scan_incomplete'] = true;
            }
            $scan_data['log'][] = count($scan_data['files']) . ' suspicious files found.';

            $scan_data['log'][] = 'Starting DB scan...';
            $scan_data['db']    = $this->db_scan();
            $scan_data['log'][] = count($scan_data['db']) . ' suspicious DB entries found.';
        }
        if (!empty($this->options['enable_vuln'])) {
            $scan_data['log'][] = 'Checking plugin vulnerabilities...';
            $scan_data['vuln']  = $this->check_vuln();
            $scan_data['log'][] = count($scan_data['vuln']) . ' outdated plugins detected.';
        }

        $scan_timestamp = time();

        $log_data_structure = [
            'scan_timestamp' => $scan_timestamp,
            'scan_data'      => $scan_data,
        ];

        // [M5] JSON_UNESCAPED_UNICODE追加（日本語の可読性向上）
        // [v2.9] LOCK_EXを追加（並行書き込み時のデータ破損防止）
        file_put_contents(
            $this->get_log_file_path(),
            (string) json_encode(
                $log_data_structure,
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            ),
            LOCK_EX
        );

        // [H7] autoload=falseを指定（管理画面でのみ必要な値）
        update_option('pyro_scope_last_scan_timestamp', $scan_timestamp, false);

        return $scan_data;
    }

    /**
     * スキャン結果をHTMLとして生成する（内部で全動的値をesc_html済み）
     *
     * @param array<string, mixed> $results
     * @return string エスケープ済みHTML
     */
    private function generate_results_html(array $results): string
    {
        $html = '';

        // === 整合性チェック結果 ===
        $integrity_issues = $results['integrity'] ?? [];
        $integrity_count  = count($integrity_issues);
        $first_issue      = $integrity_issues[0] ?? '';

        if (is_string($first_issue) && str_starts_with($first_issue, 'Error:')) {
            $html .= '<div class="pyro-scope-notice error">';
            $html .= '<h3>Integrity Check Failed</h3>';
            $html .= '<p>' . esc_html($first_issue) . '</p>';
            $html .= '</div>';
        } elseif ($integrity_count > 0) {
            $html .= '<div class="pyro-scope-notice warning">';
            $html .= '<h3>' . esc_html((string) $integrity_count) . '件のコアファイルの整合性に関する問題が検出されました 危険</h3>';
            $html .= '<p>以下のWordPressコアファイルが、公式のファイルと異なります。改ざんの可能性が非常に高いです。</p>';
            $html .= '<ul style="list-style:disc; margin-left:20px;">';
            foreach ($integrity_issues as $issue) {
                $html .= '<li><code>' . esc_html((string) $issue) . '</code></li>';
            }
            $html .= '</ul></div>';
        } else {
            $html .= '<div class="pyro-scope-notice info">';
            $html .= '<h3>コアファイルの整合性は正常です ✅</h3>';
            $html .= '<p>WordPressコアファイルは、WordPress.orgの公式ファイルと一致しています。</p>';
            $html .= '</div>';
        }

        // === 不審ファイル検出結果 ===
        $files = $results['files'] ?? [];
        if (!empty($files)) {
            $html .= '<h2>不審なファイルの検出結果 (' . (int) count($files) . '件)</h2>';
            $html .= '<table class="pyro-scope-results-table">';
            $html .= '<thead><tr><th>ファイルパス</th><th>原因 (検出シグネチャ)</th></tr></thead><tbody>';
            foreach ($files as $file_path => $cause) {
                $html .= '<tr>';
                $html .= '<td><code>' . esc_html(str_replace(ABSPATH, '', (string) $file_path)) . '</code></td>';
                $html .= '<td>' . esc_html((string) $cause) . '</td>';
                $html .= '</tr>';
            }
            $html .= '</tbody></table>';
        }

        // === 不審DBエントリ検出結果 ===
        $db_entries = $results['db'] ?? [];
        if (!empty($db_entries)) {
            $html .= '<h2>不審なDBエントリの検出結果 (' . (int) count($db_entries) . '件)</h2>';
            $html .= '<table class="pyro-scope-results-table">';
            $html .= '<thead><tr><th>場所</th><th>原因 (検出パターン)</th></tr></thead><tbody>';
            foreach ($db_entries as $entry_location => $cause) {
                $html .= '<tr>';
                $html .= '<td>' . esc_html((string) $entry_location) . '</td>';
                $html .= '<td>' . esc_html((string) $cause) . '</td>';
                $html .= '</tr>';
            }
            $html .= '</tbody></table>';
        }

        // === 脆弱性チェック（バージョン未更新プラグイン）結果 ===
        $vuln_entries = $results['vuln'] ?? [];
        if (!empty($vuln_entries)) {
            $html .= '<div class="pyro-scope-notice warning">';
            $html .= '<h3>' . (int) count($vuln_entries) . '件のプラグインが最新版ではありません</h3>';
            $html .= '<p>以下のプラグインに更新があります。セキュリティ修正を含む可能性があるため、早急な更新を推奨します。</p>';
            $html .= '<ul style="list-style:disc; margin-left:20px;">';
            foreach ($vuln_entries as $vuln) {
                $html .= '<li>' . esc_html((string) $vuln) . '</li>';
            }
            $html .= '</ul></div>';
        }

        return $html;
    }

    /**
     * WordPress.org APIと照合してコアファイルの整合性をチェック
     *
     * @return list<string>
     */
    private function check_integrity(): array
    {
        global $wp_version;
        $diffs = [];

        $url      = 'https://api.wordpress.org/core/checksums/1.0/?version=' . urlencode($wp_version) . '&locale=en_US';
        $response = wp_remote_get($url, ['timeout' => 20]);

        if (is_wp_error($response) || 200 !== wp_remote_retrieve_response_code($response)) {
            return ['Error: Could not retrieve official checksums from WordPress.org API.'];
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($data) || !isset($data['checksums']) || !is_array($data['checksums'])) {
            return ['Error: Invalid checksum data received from API.'];
        }

        $official_checksums = array_filter(
            $data['checksums'],
            static function (string $file): bool {
                return !str_starts_with($file, 'wp-content/');
            },
            ARRAY_FILTER_USE_KEY
        );

        $local_files = [];
        foreach (array_keys($official_checksums) as $file_path) {
            $full_path = ABSPATH . $file_path;
            if (file_exists($full_path) && is_readable($full_path)) {
                $local_files[$file_path] = md5_file($full_path);
            }
        }

        foreach ($official_checksums as $file => $checksum) {
            if (!isset($local_files[$file])) {
                $diffs[] = 'File Deleted: ' . $file;
            } elseif ($local_files[$file] !== $checksum) {
                $diffs[] = 'File Modified: ' . $file;
            }
        }

        return $diffs;
    }

    /**
     * ファイルシステムをスキャンして不審なコードパターンを検出
     *
     * @return array{findings: array<string, string>, error?: string}
     */
    private function file_scan(): array
    {
        $root = ABSPATH;

        // [M6] whitelist_pathsが配列でない場合のガード
        $whitelist_raw = is_array($this->options['whitelist_paths'] ?? null)
            ? $this->options['whitelist_paths']
            : [];
        $whitelist = array_map(static function (string $p): string {
            return wp_normalize_path(ABSPATH . trim($p));
        }, $whitelist_raw);

        $findings   = [];
        $signatures = [
            'Variable Function Execution' => '/\$[a-zA-Z0-9_]+\s*\(\s*[`\'"](pass(thru)?|shell_exec|system|exec|popen|proc_open)/i',
            'Obfuscated Eval'             => '/(eval|assert|preg_replace)\s*\(\s*(\'|")\s*\.\s*(\'|")\s*\.\s*/i',
            'Advanced Obfuscation'        => '/(eval|assert)\s*\(\s*(gzuncompress|gzinflate|base64_decode|str_rot13)\s*\(/i',
            'File Upload Webshell'        => '/move_uploaded_file\s*\(\s*\$_FILES\s*\[\s*[\'"].*?[\'"]\s*\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]/i',
            'Remote Code Execution'       => '/(include|require)(_once)?\s*[\s(]\s*\$_GET\s*\[/i',
            'Create Function Webshell'    => '/create_function\s*\(/i',
            'Eval Base64 Decode'          => '/\beval\s*\(\s*base64_decode\s*\(/i',
            'User Input Include'          => '/(include|require)(_once)?\s*[\s(]\s*\$_(REQUEST|POST)\s*\[/i',
            'User Input Eval'             => '/\beval\s*\(\s*\$_(REQUEST|POST)\s*\[/i',
            'PHP File Write'              => '/file_put_contents\s*\([^)]*\.php/i',
        ];

        $uploads_dir = wp_normalize_path(ABSPATH . 'wp-content/uploads/');

        $result = ['findings' => []];

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($root, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $file) {
                if (!$file->isFile() || !$file->isReadable()) {
                    continue;
                }

                $path = wp_normalize_path($file->getPathname());
                if (isset($findings[$path])) {
                    continue;
                }

                foreach ($whitelist as $w) {
                    if (str_starts_with($path, $w)) {
                        continue 2;
                    }
                }

                $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                if (!in_array($ext, ['php', 'js'], true)) {
                    continue;
                }

                // Flag any .php file inside wp-content/uploads/ as suspicious
                if ($ext === 'php' && str_starts_with($path, $uploads_dir)) {
                    $findings[$path] = 'PHP file in uploads directory';
                    continue;
                }

                // [v2.9.1] 2MB超のファイルはスキップ（メモリ枯渇防止）
                if ($file->getSize() > 2097152) {
                    continue;
                }

                $content = file_get_contents($path);
                if ($content === false) {
                    continue;
                }

                foreach ($signatures as $cause => $pattern) {
                    if (preg_match($pattern, $content)) {
                        $findings[$path] = $cause;
                        continue 2;
                    }
                }
            }
        } catch (\Throwable $e) {
            $result['error'] = $e->getMessage();
        }

        $result['findings'] = $findings;

        return $result;
    }

    /**
     * データベース内の公開コンテンツを不審パターンでスキャン
     *
     * @return array<string, string>
     */
    private function db_scan(): array
    {
        global $wpdb;
        $findings           = [];
        $suspicious_patterns = [
            'Malicious Script'  => '/<script\b/i',
            'Obfuscated Code'   => '/(eval|base64_decode|gzinflate|str_rot13)\s*\(/i',
            'Malicious Iframe'  => '/<iframe\b/i',
        ];

        // --- 投稿コンテンツのスキャン ---
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $posts = $wpdb->get_results(
            "SELECT ID, post_content FROM `{$wpdb->posts}` WHERE `post_status` = 'publish'"
        );
        if (is_array($posts)) {
            foreach ($posts as $post) {
                $location = 'Post ID: ' . $post->ID;
                foreach ($suspicious_patterns as $cause => $pattern) {
                    if (preg_match($pattern, $post->post_content)) {
                        $findings[$location] = $cause;
                        break;
                    }
                }
            }
        }

        // --- オプションテーブルのスキャン ---
        $skip_options = ['rewrite_rules', 'active_plugins', 'cron'];
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $options = $wpdb->get_results(
            "SELECT option_name, option_value FROM `{$wpdb->options}`"
        );
        if (is_array($options)) {
            foreach ($options as $option) {
                if (in_array($option->option_name, $skip_options, true)) {
                    continue;
                }

                $value_str = (string) $option->option_value;

                // 巨大な値はスキップ（パフォーマンス保護）
                if (strlen($value_str) > 100000) {
                    continue;
                }

                $location = 'Option: ' . $option->option_name;
                foreach ($suspicious_patterns as $cause => $pattern) {
                    if (preg_match($pattern, $value_str)) {
                        $findings[$location] = $cause;
                        break;
                    }
                }
            }
        }

        // --- コメントのスキャン ---
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $comments = $wpdb->get_results(
            "SELECT comment_ID, comment_content FROM `{$wpdb->comments}` WHERE `comment_approved` = '1'"
        );
        if (is_array($comments)) {
            foreach ($comments as $comment) {
                $location = 'Comment ID: ' . $comment->comment_ID;
                foreach ($suspicious_patterns as $cause => $pattern) {
                    if (preg_match($pattern, $comment->comment_content)) {
                        $findings[$location] = $cause;
                        break;
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * WordPress.org APIでプラグインのバージョンチェック
     *
     * @return list<string>
     */
    private function check_vuln(): array
    {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $all_plugins = get_plugins();
        $findings    = [];

        foreach ($all_plugins as $path => $meta) {
            $slug = dirname($path);
            if ($slug === '' || $slug === '.') {
                continue;
            }

            $cache_key = 'pyro_scope_vuln_' . md5($slug);
            if (get_transient($cache_key) !== false) {
                continue;
            }

            $response = wp_remote_get(
                'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . urlencode($slug),
                ['timeout' => 10]
            );

            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                set_transient($cache_key, 'error', 2 * HOUR_IN_SECONDS);
                continue;
            }

            $data = json_decode(wp_remote_retrieve_body($response));
            if (is_object($data) && !empty($data->version) && version_compare($meta['Version'], $data->version, '<')) {
                $findings[] = $meta['Name'] . " (Installed: {$meta['Version']}, Latest: {$data->version})";
            }
            set_transient($cache_key, 'checked', 12 * HOUR_IN_SECONDS);
        }

        return $findings;
    }
}

Pyro_Scope::get_instance();

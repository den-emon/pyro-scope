<?php
/**
 * Minimal PHPUnit coverage for Pyro Scope without database-backed WordPress tests.
 */

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PyroScopeTest extends TestCase
{
    private Pyro_Scope $plugin;

    /** @var list<string> */
    private array $created_paths = [];

    protected function setUp(): void
    {
        parent::setUp();

        pyro_scope_test_reset_wordpress_state();
        $this->reset_singleton();
        $this->plugin = Pyro_Scope::get_instance();
    }

    protected function tearDown(): void
    {
        foreach (array_reverse($this->created_paths) as $path) {
            pyro_scope_test_remove_path($path);
        }

        $this->created_paths = [];
        parent::tearDown();
    }

    public function test_get_instance_initializes_defaults_and_hooks(): void
    {
        $expected = [
            'enable_scanner'   => 1,
            'enable_integrity' => 1,
            'enable_vuln'      => 1,
            'whitelist_paths'  => ['wp-content/plugins/pyro-shield'],
        ];

        // Singleton 初期化時にデフォルト設定と主要フックが登録される。
        $this->assertSame($expected, get_option('pyro_scope_options'));
        $this->assertSame(10, has_action('admin_menu', [$this->plugin, 'admin_menu']));
        $this->assertSame(10, has_action('admin_enqueue_scripts', [$this->plugin, 'enqueue_scripts']));
        $this->assertSame(10, has_action('wp_ajax_pyro_scope_run_scan', [$this->plugin, 'ajax_run_scan']));
        $this->assertSame(10, has_action('pyro_scope_weekly_scan_event', [$this->plugin, 'run_scheduled_scan']));
    }

    public function test_enqueue_scripts_only_enqueues_assets_on_plugin_screen(): void
    {
        // 対象外の管理画面では何も積まない。
        $this->plugin->enqueue_scripts('dashboard_page_dummy');
        $this->assertFalse(wp_style_is('pyro-scope-admin-style'));
        $this->assertFalse(wp_script_is('pyro-scope-admin-script'));

        // プラグイン画面では CSS / JS とローカライズデータを積む。
        $this->plugin->enqueue_scripts('toplevel_page_pyro-scope');

        $this->assertTrue(wp_style_is('pyro-scope-admin-style'));
        $this->assertTrue(wp_script_is('pyro-scope-admin-script'));
        $this->assertSame(
            'PyroScopeAjax',
            $GLOBALS['pyro_scope_test_wp']['localized_scripts']['pyro-scope-admin-script']['object_name']
        );
        $this->assertSame(
            'http://example.org/wp-admin/admin-ajax.php',
            $GLOBALS['pyro_scope_test_wp']['localized_scripts']['pyro-scope-admin-script']['data']['ajax_url']
        );
    }

    public function test_generate_results_html_renders_scan_sections(): void
    {
        $results = [
            'integrity' => ['File Modified: wp-includes/load.php'],
            'files'     => [ABSPATH . 'wp-content/mu-plugins/malicious.php' => 'Eval Base64 Decode'],
            'db'        => ['Option: suspicious_option' => 'Malicious Script'],
            'vuln'      => ['Fixture Plugin (Installed: 1.0.0, Latest: 2.0.0)'],
        ];

        // テンプレートの主要セクションが描画されることだけを最小確認する。
        $html = $this->call_private_method('generate_results_html', $results);

        $this->assertStringContainsString('コアファイルの整合性に関する問題', $html);
        $this->assertStringContainsString('wp-content/mu-plugins/malicious.php', $html);
        $this->assertStringContainsString('Option: suspicious_option', $html);
        $this->assertStringContainsString('Fixture Plugin (Installed: 1.0.0, Latest: 2.0.0)', $html);
    }

    public function test_file_scan_flags_uploads_php_and_skips_whitelisted_paths(): void
    {
        $uploads_file = ABSPATH . 'wp-content/uploads/pyro-scope-tests/suspicious.php';
        $scan_target = ABSPATH . 'wp-content/mu-plugins/scan-target/malicious.php';
        $ignored_file = ABSPATH . 'wp-content/mu-plugins/whitelist/ignored.php';

        $this->create_file($uploads_file, "<?php\necho 'ok';\n");
        $this->create_file($scan_target, "<?php\neval(base64_decode('ZWNobyAiaGVsbG8iOw=='));\n");
        $this->create_file($ignored_file, "<?php\neval(base64_decode('ZWNobyAiaWdub3JlZCI7'));\n");

        $this->set_private_property(
            'options',
            [
                'enable_scanner'   => 1,
                'enable_integrity' => 1,
                'enable_vuln'      => 1,
                'whitelist_paths'  => ['wp-content/mu-plugins/whitelist'],
            ]
        );

        // uploads 配下と非ホワイトリストの危険シグネチャのみ検出する。
        $result = $this->call_private_method('file_scan');

        $this->assertSame(
            'PHP file in uploads directory',
            $result['findings'][wp_normalize_path($uploads_file)]
        );
        $this->assertSame(
            'Advanced Obfuscation',
            $result['findings'][wp_normalize_path($scan_target)]
        );
        $this->assertArrayNotHasKey(wp_normalize_path($ignored_file), $result['findings']);
    }

    public function test_check_integrity_returns_error_when_remote_request_fails(): void
    {
        global $wp_version;

        $wp_version = '6.7';
        $GLOBALS['pyro_scope_test_wp']['remote_get'] = static fn (): WP_Error => new WP_Error(
            'http_error',
            'HTTP request failed.'
        );

        // 外部通信が失敗した場合は例外ではなくエラー配列を返す。
        $this->assertSame(
            ['Error: Could not retrieve official checksums from WordPress.org API.'],
            $this->call_private_method('check_integrity')
        );
    }

    public function test_check_vuln_uses_stubbed_update_transient(): void
    {
        $GLOBALS['pyro_scope_test_wp']['plugins'] = [
            'fixture-plugin/fixture.php' => [
                'Name'    => 'Fixture Plugin',
                'Version' => '1.0.0',
            ],
        ];
        $GLOBALS['pyro_scope_test_wp']['site_transients']['update_plugins'] = (object) [
            'response' => [
                'fixture-plugin/fixture.php' => (object) ['new_version' => '9.9.9'],
            ],
        ];

        // WordPress の transient をスタブすれば脆弱性チェックも DB 不要で確認できる。
        $findings = $this->call_private_method('check_vuln');

        $this->assertSame(
            ['Fixture Plugin (Installed: 1.0.0, Latest: 9.9.9)'],
            $findings
        );
    }

    private function reset_singleton(): void
    {
        $reflection = new ReflectionClass(Pyro_Scope::class);
        $property = $reflection->getProperty('instance');
        $property->setValue(null, null);
    }

    private function call_private_method(string $method, mixed ...$args): mixed
    {
        $callback = Closure::bind(
            fn (mixed ...$call_args): mixed => $this->{$method}(...$call_args),
            $this->plugin,
            Pyro_Scope::class
        );

        return $callback(...$args);
    }

    private function set_private_property(string $property, mixed $value): void
    {
        $writer = Closure::bind(
            function (mixed $new_value) use ($property): void {
                $this->{$property} = $new_value;
            },
            $this->plugin,
            Pyro_Scope::class
        );

        $writer($value);
    }

    private function create_file(string $path, string $contents): void
    {
        $directory = dirname($path);
        if (!is_dir($directory)) {
            wp_mkdir_p($directory);
            $this->created_paths[] = $directory;
        }

        file_put_contents($path, $contents);
        $this->created_paths[] = $path;
    }
}

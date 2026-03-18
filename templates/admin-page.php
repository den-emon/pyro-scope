<?php
/**
 * Admin page template.
 *
 * Included from Pyro_Scope::settings_page().
 * Available variables: $settings_saved (bool), $scan_results_html (string), $options (array)
 *
 * @var bool                  $settings_saved
 * @var string                $scan_results_html
 * @var array<string, mixed>  $options
 */

if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap">
    <h1>Pyro Scope</h1>
    <?php if ($settings_saved) : ?>
        <div class="notice notice-success is-dismissible"><p>設定を保存しました。</p></div>
    <?php endif; ?>

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
        // generate_results_html は内部で全値をesc_html済み
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo $scan_results_html;
        ?>
    </div>

    <hr>
    <h2>設定</h2>
    <form method="post">
        <?php wp_nonce_field('pyro_scope_settings_nonce'); ?>
        <table class="form-table">
            <tr>
                <th scope="row">ファイル &amp; DBスキャン</th>
                <td>
                    <label>
                        <input type="checkbox" name="enable_scanner" value="1" <?php checked(!empty($options['enable_scanner'])); ?>>
                        有効
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row">コアファイル整合性チェック</th>
                <td>
                    <label>
                        <input type="checkbox" name="enable_integrity" value="1" <?php checked(!empty($options['enable_integrity'])); ?>>
                        有効
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row">プラグイン脆弱性チェック</th>
                <td>
                    <label>
                        <input type="checkbox" name="enable_vuln" value="1" <?php checked(!empty($options['enable_vuln'])); ?>>
                        有効
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row">ホワイトリストパス</th>
                <td>
                    <textarea name="whitelist_paths" rows="5" cols="60" class="large-text"><?php
                        $paths = is_array($options['whitelist_paths'] ?? null) ? $options['whitelist_paths'] : [];
                        echo esc_textarea(implode("\n", $paths));
                    ?></textarea>
                    <p class="description">スキャン除外パス（ABSPATHからの相対パス、1行に1つ）</p>
                </td>
            </tr>
        </table>
        <p class="submit">
            <input type="submit" name="pyro_scope_save_settings" class="button button-primary" value="設定を保存">
        </p>
    </form>
</div>

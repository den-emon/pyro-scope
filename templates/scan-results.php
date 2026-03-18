<?php
/**
 * Scan results template.
 *
 * Called via output buffering from Pyro_Scope::generate_results_html().
 * Available variables: $results (array)
 *
 * @var array<string, mixed> $results
 */

if (!defined('ABSPATH')) {
    exit;
}

// === 整合性チェック結果 ===
$integrity_issues = $results['integrity'] ?? [];
$integrity_count  = count($integrity_issues);
$first_issue      = $integrity_issues[0] ?? '';

if (is_string($first_issue) && str_starts_with($first_issue, 'Error:')) : ?>
    <div class="pyro-scope-notice error">
        <h3>Integrity Check Failed</h3>
        <p><?php echo esc_html($first_issue); ?></p>
    </div>
<?php elseif ($integrity_count > 0) : ?>
    <div class="pyro-scope-notice warning">
        <h3><?php echo esc_html((string) $integrity_count); ?>件のコアファイルの整合性に関する問題が検出されました 危険</h3>
        <p>以下のWordPressコアファイルが、公式のファイルと異なります。改ざんの可能性が非常に高いです。</p>
        <ul style="list-style:disc; margin-left:20px;">
            <?php foreach ($integrity_issues as $issue) : ?>
                <li><code><?php echo esc_html((string) $issue); ?></code></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php else : ?>
    <div class="pyro-scope-notice info">
        <h3>コアファイルの整合性は正常です ✅</h3>
        <p>WordPressコアファイルは、WordPress.orgの公式ファイルと一致しています。</p>
    </div>
<?php endif; ?>

<?php
// === 不審ファイル検出結果 ===
$files = $results['files'] ?? [];
if (!empty($files)) : ?>
    <h2>不審なファイルの検出結果 (<?php echo (int) count($files); ?>件)</h2>
    <table class="pyro-scope-results-table">
        <thead><tr><th>ファイルパス</th><th>原因 (検出シグネチャ)</th></tr></thead>
        <tbody>
            <?php foreach ($files as $file_path => $cause) : ?>
                <tr>
                    <td><code><?php echo esc_html(str_replace(ABSPATH, '', (string) $file_path)); ?></code></td>
                    <td><?php echo esc_html((string) $cause); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
<?php endif; ?>

<?php
// === 不審DBエントリ検出結果 ===
$db_entries = $results['db'] ?? [];
if (!empty($db_entries)) : ?>
    <h2>不審なDBエントリの検出結果 (<?php echo (int) count($db_entries); ?>件)</h2>
    <table class="pyro-scope-results-table">
        <thead><tr><th>場所</th><th>原因 (検出パターン)</th></tr></thead>
        <tbody>
            <?php foreach ($db_entries as $entry_location => $cause) : ?>
                <tr>
                    <td><?php echo esc_html((string) $entry_location); ?></td>
                    <td><?php echo esc_html((string) $cause); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
<?php endif; ?>

<?php
// === 脆弱性チェック（バージョン未更新プラグイン）結果 ===
$vuln_entries = $results['vuln'] ?? [];
if (!empty($vuln_entries)) : ?>
    <div class="pyro-scope-notice warning">
        <h3><?php echo (int) count($vuln_entries); ?>件のプラグインが最新版ではありません</h3>
        <p>以下のプラグインに更新があります。セキュリティ修正を含む可能性があるため、早急な更新を推奨します。</p>
        <ul style="list-style:disc; margin-left:20px;">
            <?php foreach ($vuln_entries as $vuln) : ?>
                <li><?php echo esc_html((string) $vuln); ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<?php
/**
 * Pyro Scope Uninstall
 *
 * Fired when the plugin is deleted.
 *
 * @package   Pyro_Scope
 */
// [FIXED] パッケージ名を Pyro_Scope に変更

// WordPressから呼び出されていない場合は、直接のアクセスを禁止
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// === データベースのクリーンアップ ===

$option_keys = [
    'pyro_scope_options',
    'pyro_scope_last_scan_timestamp',
];

foreach ($option_keys as $key) {
    delete_option($key);
}

// [L9] === Transientキャッシュのクリーンアップ ===
// check_vuln() が生成する pyro_scope_vuln_* transient を一括削除
global $wpdb;
$like_transient = $wpdb->esc_like('_transient_pyro_scope_vuln_') . '%';
$like_timeout   = $wpdb->esc_like('_transient_timeout_pyro_scope_vuln_') . '%';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
    $wpdb->prepare(
        "DELETE FROM `{$wpdb->options}` WHERE `option_name` LIKE %s OR `option_name` LIKE %s",
        $like_transient,
        $like_timeout
    )
);

// === ファイルのクリーンアップ ===

// 1. アップロードディレクトリのパスを取得
$upload_dir   = wp_upload_dir();
$log_dir_path = $upload_dir['basedir'] . '/pyro-scope-log';

// [L9] 2. SPLイテレータでディレクトリを再帰削除（グローバル関数定義を回避）
if (is_dir($log_dir_path)) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($log_dir_path, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir()) {
            @rmdir($item->getPathname());
        } else {
            @unlink($item->getPathname());
        }
    }
    @rmdir($log_dir_path);
}

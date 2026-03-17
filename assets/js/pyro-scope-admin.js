jQuery(document).ready(function($) {
    'use strict'; // [L8]

    // [FIXED] セレクタ・ローカライズオブジェクト名・AJAXアクション名を pyro-scope / PyroScopeAjax に変更
    // スキャンボタンがクリックされたときの処理
    $('#pyro-scope-run-scan').on('click', function() {
        // 各UI要素を定数として定義
        const scanButton = $(this);
        const log = $('#pyro-scope-scan-log');
        const progressBar = $('#pyro-scope-progress-bar');
        const progressContainer = $('#pyro-scope-progress-container');

        // --- スキャン開始時のUI初期化 ---
        scanButton.prop('disabled', true);
        log.text('Scan initialized...');
        $('#pyro-scope-results-container').html(''); // 前回のリザルトをクリア
        progressContainer.show();
        progressBar.css('width', '0%').css('background-color', '#0a0');

        // --- Ajaxリクエストの実行 ---
        $.ajax({
            // wp_localize_scriptでPHPから渡されたオブジェクトを使用
            url: PyroScopeAjax.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'pyro_scope_run_scan',
                _ajax_nonce: PyroScopeAjax.nonce // セキュリティトークン
            },
            success: function(resp) {
                if (resp.success) {
                    // 成功した場合、レスポンス内のHTMLを結果表示エリアに描画
                    $('#pyro-scope-results-container').html(resp.data.html);

                    const lines = resp.data.log;
                    const total = lines.length;
                    log.text('');

                    // ログが空の場合のエッジケース対応
                    if (total === 0) {
                        log[0].appendChild(document.createTextNode('--- Scan Complete (no log entries) ---\n'));
                        scanButton.prop('disabled', false);
                        return;
                    }

                    lines.forEach(function(line, i) {
                        setTimeout(function() {
                            // [v2.9.1] createTextNodeでHTML解釈を防止（XSS対策）
                            log[0].appendChild(document.createTextNode(line + '\n'));
                            progressBar.css('width', Math.round((i + 1) / total * 100) + '%');
                            log.scrollTop(log[0].scrollHeight);

                            if (i + 1 === total) {
                                log[0].appendChild(document.createTextNode('--- Scan Complete ---\n'));
                                log.scrollTop(log[0].scrollHeight);
                                scanButton.prop('disabled', false); // ボタンを再度有効化
                            }
                        }, i * 100);
                    });
                } else {
                    // サーバーからエラーが返された場合
                    const errorMessage = (resp.data && resp.data.message) ? resp.data.message : 'An unknown error occurred on the server.';
                    log.text('Scan failed: ' + errorMessage);
                    progressBar.css('width', '100%').css('background-color', '#d9534f');
                    scanButton.prop('disabled', false);
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                // 通信自体が失敗した場合
                log.text('Communication error: ' + textStatus + ' - ' + errorThrown);
                progressBar.css('width', '100%').css('background-color', '#d9534f');
                scanButton.prop('disabled', false);
            }
        });
    });
});

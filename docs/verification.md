# 再現可能な検証

公開資料には実運用のURL・AWSリソース識別子・利用者情報・ジョブID・ログを記載しない。

1. `make bootstrap`でロック済み依存をインストールする。
2. `make test check`でPython/Reactのテスト、型、lint、ビルド、依存方向を検査する。
3. `make generate`後、OpenAPIと生成クライアントに差分がないことを確認する。
4. `make package synth`と`scripts/check_infra.py`でLambdaパッケージとローカル構成を検査する。
5. `make local-up local-deploy`、`make dev-web`の後、`E2E_REPORTS=1 PLAYWRIGHT_CHANNEL=chrome pnpm --filter @security-testing/web test:e2e reports.e2e.ts --workers=1`で新規fixtureレコードだけを使う統合検証を実行する。

直近の機能検証はPython112件、React38件が成功。統合検証では認証付きの履歴PDFバイナリー取得、攻撃分析、AI工事中、モバイル説明、作成した検証対象と履歴の削除を確認した。
日本語フォントを埋め込んだ表形式PDF全7ページを表示確認した。追加診断のLocalStack統合検証で、手動DNS/TCP確認・PDF取得・接続テンプレート・ロール設定保存・390px画面で横はみ出しがないことを確認した。

追加診断の統合検証は `E2E_ADVANCED=1 PLAYWRIGHT_CHANNEL=chrome pnpm --filter @security-testing/web test:e2e advanced.e2e.ts --workers=1`。2つのケースを続ける場合は、テスト内でホスト待機の時間を確保します。個別に実行する場合は`--grep`を使用します。新しく作成したfixtureレコードを使い、DNS/TCP確認・履歴PDF・AWS接続準備・スマートフォン表示を検査します。ダミーの接続ロールは実行しません。実AWS情報取得とは区別します。

限定Web検証も実Chrome/LocalStackで実応答を確認済みです。CORS・OPTIONS・TRACEの結果と、IPA表を開いた390px表示を検証しています。

診断の入口は5種類の常時表示カードです。種類別の保存結果・履歴・検査範囲を表示し、別種類の結果混在を拒否します。実測ポート状態・HTTPメソッド/応答・AWS対象/CVEを結果に表示します。LocalStack/実Chromeの2ケースでネットワーク・限定HTTP検証・履歴PDF・AWS接続準備・種類切り替え・390px表示を検証済みです。AWSホスト/クラウドの実アカウント収集は未実施で、単体テストとサンプルPDFで確認しています。

チェックボックスはテキスト入力用CSSから分離し、18pxの選択欄と文字を2列で配置。5種類すべての検査項目・ポート・権限確認について、1440px/390px/360pxで寸法、先頭行の中心、間隔、44px以上のタップ範囲、横はみ出しを実Chromeで検証しました。通常Web診断からの履歴PDF・説明・作成レコード削除の統合検証も成功しています。

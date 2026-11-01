# 再現可能な検証

公開資料には実運用のURL・AWSリソース識別子・利用者情報・ジョブID・ログを記載しない。

1. `make bootstrap`でロック済み依存をインストールする。
2. `make test check`でPython/Reactのテスト、型、lint、ビルド、依存方向を検査する。
3. `make generate`後、OpenAPIと生成クライアントに差分がないことを確認する。
4. `make package synth`と`scripts/check_infra.py`でLambdaパッケージとローカル構成を検査する。
5. `make local-up local-deploy`、`make dev-web`の後、`E2E_REPORTS=1 PLAYWRIGHT_CHANNEL=chrome pnpm --filter @security-testing/web test:e2e reports.e2e.ts --workers=1`で新規fixtureレコードだけを使う統合検証を実行する。

直近の機能検証はPython76件、React29件が成功。統合検証では認証付きの履歴PDFバイナリー取得、攻撃分析、AI工事中、モバイル説明、作成した検証対象と履歴の削除を確認した。
日本語フォントを埋め込んだPDF全8ページを表示確認した。

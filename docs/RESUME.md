# ローカル開発の再開

1. Docker互換の実行環境を起動する。
2. 既存の`.env`を保持して`make local-up`を実行する。
3. 必要な場合は`make local-deploy`でLocalStackへ反映する。
4. `make dev-web`で開発画面を起動し、http://localhost:5173 を開く。
5. 制御下のfixtureで確認する。対象は`http://fixture.security-testing.test/`。

認証トークンをログ・Git・PRへ転載しない。既存サーバーの二重起動は避ける。
ローカルの停止は`make local-down`。LocalStackの永続化は未設定のためコンテナの削除・再作成に注意する。
実装と確認状況は`docs/status.md`、AWSへの一般的な配信手順は`docs/aws-deployment.md`を参照する。
実環境の接続先や設定はGit管理外の情報を使用する。
